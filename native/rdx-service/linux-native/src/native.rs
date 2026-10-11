// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux-only descriptor, `SG_IO`, and retained-volume implementation.

mod block_authority;
mod btrfs;
use block_authority::RetainedBlockAuthority;
mod file_test;
mod formatting;
mod udisks;
mod unmount;
mod volume_label;
#[cfg(test)]
pub(crate) use formatting::retained_fd_namespace_runtime_contract;

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::ptr;

use crate::block::{
    BlockBinding, BlockNodeProof, BlockTopology, OpenedBlockProof, resolve_block_node,
    retained_block_authority_is_current, retained_volume_handle_count,
};
use crate::identity::{
    DeviceBinding, DeviceNumber, OpenedDeviceProof, SysfsInstanceProof, SysfsRoots,
    block_topology_for, candidate_instance_is_stable, device_number_from_linux_dev_t,
    enumerate_candidates_at, resolve_binding,
};
use crate::mountinfo::{MountRecord, canonical_mounts_for_devices, parse_mountinfo};
use crate::readiness::{
    DeviceAccess, Readiness, UdevRuleState, configured_group_gid, inspect_udev_rules,
    polkit_policy_is_narrow, process_has_group,
};
use crate::sg::{
    DataDirection, ScsiRequest, SgIoHeader, media_identity_material_from_vpd,
    media_identity_request, sg_open_requirements,
};
use crate::{
    Completion, FileTestOutcome, HostFilesystem, HostOperationOutcome, MAX_SYSFS_ATTRIBUTE_BYTES,
    NativeError, ResourceCloser, ResourceGuard, ScsiGenericCandidate,
};

const SG_IO: libc::c_ulong = 0x2285;
const SG_INTERFACE_ID: i32 = b'S' as i32;
const SG_DXFER_NONE: i32 = -1;
const SG_DXFER_TO_DEV: i32 = -2;
const SG_DXFER_FROM_DEV: i32 = -3;
const MAX_PRECALL_EINTR_ATTEMPTS: usize = 8;
const MAX_READINESS_FILE_BYTES: usize = 1024 * 1024;
const MAX_MOUNTINFO_BYTES: usize = 4 * 1024 * 1024;
const OPENRDX_RULE_NAME: &str = "70-openrdx.rules";
const OPENRDX_POLICY_PATH: &str = "/usr/share/polkit-1/actions/org.openrdx.hardware.policy";
struct FdCloser;

impl ResourceCloser<libc::c_int> for FdCloser {
    /// Closes one owned Linux descriptor without retrying an ambiguous close.
    fn close(resource: libc::c_int) {
        // SAFETY: `resource` is owned by exactly one guard and is closed once.
        let _ = unsafe { libc::close(resource) };
    }
}

type OwnedFd = ResourceGuard<libc::c_int, FdCloser>;

/// Retained exact sysfs instance acquired during candidate enumeration.
pub(crate) struct RetainedSysfsInstance {
    fd: OwnedFd,
    proof: SysfsInstanceProof,
}

/// Exact retained sg descriptor plus immutable sysfs binding.
pub(crate) struct NativeDevice {
    fd: OwnedFd,
    sysfs_instance: RetainedSysfsInstance,
    binding: DeviceBinding,
    roots: SysfsRoots,
    format_selection: Option<(HostFilesystem, u64)>,
}

impl NativeDevice {
    /// Opens an exclusive SG lease while preserving exact enumeration authority.
    pub(crate) fn open(candidate: &ScsiGenericCandidate) -> Result<Self, NativeError> {
        let (binding, retained) = candidate.native_parts()?;
        let roots = SysfsRoots::native()?;
        let before =
            resolve_binding(&roots, binding.sg_index()).map_err(|_| NativeError::DeviceRemoved)?;
        let retained_now = sysfs_instance_proof(&fstat_owned(&retained.fd)?);
        let node = CString::new(format!("/dev/sg{}", binding.sg_index()))
            .map_err(|_| NativeError::InvalidRequest)?;
        let fd = open_owned(&node, sg_open_flags())?;
        let stat = fstat_owned(&fd)?;
        let opened = OpenedDeviceProof::new(
            file_type(stat.st_mode) == libc::S_IFCHR,
            device_number(stat.st_rdev),
        );
        let after =
            resolve_binding(&roots, binding.sg_index()).map_err(|_| NativeError::DeviceRemoved)?;
        // This final path handle is the promotion linearization point: a
        // same-path/same-dev_t recreation after SG open has a different inode.
        let current_instance = open_sysfs_instance(&roots, &binding)?;
        let current_proof = sysfs_instance_proof(&fstat_owned(&current_instance)?);
        if !candidate_instance_is_stable(
            &binding,
            &before,
            retained.proof,
            retained_now,
            current_proof,
            opened,
            &after,
        ) {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(Self {
            fd,
            // Keep this independently opened directory in the operation lease;
            // its inode was proven equal to the retained enumeration authority.
            sysfs_instance: RetainedSysfsInstance {
                fd: current_instance,
                proof: current_proof,
            },
            binding,
            roots,
            format_selection: None,
        })
    }

    /// Invokes one already-bounded synchronous semantic SCSI request.
    pub(crate) fn execute(&mut self, request: ScsiRequest) -> Completion {
        if request.needs_cartridge_readiness() {
            let failure = crate::media_presence::require_cartridge_ready(|| {
                let probe = crate::ScsiOperation::test_unit_ready()
                    .with_timeout_ms(3_000)
                    .expect("fixed read-only deadline")
                    .into_request()
                    .expect("closed no-data request");
                self.execute_request(probe)
            });
            if let Some(completion) = failure {
                return completion;
            }
        }
        self.execute_request(request)
    }

    /// Runs only the already-validated bounded ioctl; readiness probes cannot recurse.
    fn execute_request(&mut self, mut request: ScsiRequest) -> Completion {
        let direction = request.direction();
        let mut cdb = request.cdb().to_vec().into_boxed_slice();
        let mut sense = vec![0_u8; request.sense_capacity()];
        let Ok(command_length) = u8::try_from(cdb.len()) else {
            return Completion::NotAttempted(NativeError::InvalidRequest);
        };
        let Ok(transfer_length) = u32::try_from(request.data().len()) else {
            return Completion::NotAttempted(NativeError::ResourceLimit);
        };
        let dxferp = if request.data_mut().is_empty() {
            ptr::null_mut()
        } else {
            request.data_mut().as_mut_ptr().cast()
        };
        let mut header = SgIoHeader {
            interface_id: SG_INTERFACE_ID,
            dxfer_direction: sg_direction(direction),
            cmd_len: command_length,
            max_sense_len: u8::try_from(sense.len()).expect("bounded sense capacity"),
            iovec_count: 0,
            dxfer_len: transfer_length,
            dxferp,
            cmdp: cdb.as_mut_ptr(),
            sensep: sense.as_mut_ptr(),
            timeout: request.timeout_ms(),
            flags: 0,
            pack_id: 0,
            user_ptr: ptr::null_mut(),
            status: 0,
            masked_status: 0,
            message_status: 0,
            sense_len_written: 0,
            host_status: 0,
            driver_status: 0,
            residual: 0,
            duration: 0,
            info: 0,
        };
        // SAFETY: the fd is a revalidated owned sg descriptor; header pointers
        // refer to live uniquely owned buffers for this synchronous call.
        let result = unsafe { libc::ioctl(self.fd.copied(), SG_IO, &mut header) };
        if result < 0 {
            // Linux may orphan an already queued SG request when the wait is
            // interrupted, so even EINTR is attempted and is never retried.
            return Completion::AttemptedError(last_native_error());
        }
        let sense_reported_length = usize::from(header.sense_len_written);
        sense.truncate(sense_reported_length.min(sense.len()));
        let data = if direction == DataDirection::FromDevice {
            request.take_data()
        } else {
            Vec::new()
        };
        Completion::Device {
            status: header.status,
            masked_status: header.masked_status,
            message_status: header.message_status,
            host_status: header.host_status,
            driver_status: header.driver_status,
            info: header.info,
            residual: header.residual,
            data,
            sense_reported_length,
            sense,
        }
    }

    /// Actively queries two cartridge-specific VPD pages through the retained SG fd.
    pub(crate) fn media_identity_material(&mut self) -> Result<Vec<u8>, NativeError> {
        self.revalidate_sg_authority()?;
        let c0 = self.execute(media_identity_request(0xC0)?);
        self.revalidate_sg_authority()?;
        let c2 = self.execute(media_identity_request(0xC2)?);
        self.revalidate_sg_authority()?;
        media_identity_material_from_vpd(
            completion_data(c0)?.as_slice(),
            completion_data(c2)?.as_slice(),
        )
    }

    /// Opens exact block and mount descriptors while retaining this sg lease.
    pub(crate) fn pin_volumes(&mut self) -> Result<NativeVolumeLeases, NativeError> {
        self.revalidate_sg_authority()?;
        let topology = block_topology_for(&self.roots, &self.binding)?;
        let blocks = topology.bindings();
        retained_volume_handle_count(topology.nodes(), 0)?;
        let mut block_authorities = Vec::with_capacity(topology.nodes().len());
        for node in topology.nodes() {
            block_authorities.push(RetainedBlockAuthority::open(&self.roots, node)?);
        }

        let mountinfo_before =
            read_bounded(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
        let records_before = parse_mountinfo(&mountinfo_before)?;
        let device_numbers = blocks
            .iter()
            .map(BlockBinding::device_number)
            .collect::<BTreeSet<_>>();
        let (selected_mounts, mount_bindings) =
            btrfs::selected_mounts(&records_before, &device_numbers)?;
        let mount_handle_count = selected_mounts
            .len()
            .checked_mul(3)
            .ok_or(NativeError::ResourceLimit)?;
        retained_volume_handle_count(topology.nodes(), mount_handle_count)?;
        let mut mount_fds = Vec::with_capacity(selected_mounts.len());
        for mount in &selected_mounts {
            let directory = btrfs::open_record_mount(mount)?;
            let tree = open_exact_mount_tree(mount.mount_point())?;
            let restore = open_mount_restore_authority(mount.mount_point(), &directory)?;
            mount_fds.push(RetainedMount {
                directory,
                tree,
                mount_id: mount.mount_id(),
                restore,
            });
        }

        let mountinfo_after = read_bounded(Path::new("/proc/self/mountinfo"), MAX_MOUNTINFO_BYTES)?;
        let records_after = parse_mountinfo(&mountinfo_after)?;
        let (selected_mounts_after, mount_bindings_after) =
            btrfs::selected_mounts(&records_after, &device_numbers)?;
        if selected_mounts_after != selected_mounts
            || mount_bindings_after != mount_bindings
            || block_topology_for(&self.roots, &self.binding)? != topology
        {
            return Err(NativeError::DeviceRemoved);
        }
        for authority in &block_authorities {
            authority.revalidate(&self.roots)?;
        }
        self.revalidate_sg_authority()?;
        Ok(NativeVolumeLeases {
            _block_authorities: block_authorities,
            _mount_fds: mount_fds,
            _topology: topology,
            _mount_snapshot: selected_mounts,
            _mount_bindings: mount_bindings,
        })
    }

    /// Revalidates the retained enumeration inode, current class binding, and
    /// exact SG descriptor together before or after a complete pin attempt.
    fn revalidate_sg_authority(&self) -> Result<(), NativeError> {
        let before = resolve_binding(&self.roots, self.binding.sg_index())
            .map_err(|_| NativeError::DeviceRemoved)?;
        let retained_now = sysfs_instance_proof(&fstat_owned(&self.sysfs_instance.fd)?);
        let sg_stat = fstat_owned(&self.fd)?;
        let opened = OpenedDeviceProof::new(
            file_type(sg_stat.st_mode) == libc::S_IFCHR,
            device_number(sg_stat.st_rdev),
        );
        let current_instance = open_sysfs_instance(&self.roots, &self.binding)?;
        let current_proof = sysfs_instance_proof(&fstat_owned(&current_instance)?);
        let after = resolve_binding(&self.roots, self.binding.sg_index())
            .map_err(|_| NativeError::DeviceRemoved)?;
        if !candidate_instance_is_stable(
            &self.binding,
            &before,
            self.sysfs_instance.proof,
            retained_now,
            current_proof,
            opened,
            &after,
        ) {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(())
    }
}

/// Reads one bounded unsigned sysfs decimal attribute.
fn read_decimal(path: &Path) -> Result<u64, NativeError> {
    let bytes = read_bounded(path, MAX_SYSFS_ATTRIBUTE_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| NativeError::EnumerationFailed)?;
    text.trim()
        .parse::<u64>()
        .map_err(|_| NativeError::EnumerationFailed)
}

/// Owned block and mount leases with no descriptor or path getters.
pub(crate) struct NativeVolumeLeases {
    _block_authorities: Vec<RetainedBlockAuthority>,
    _mount_fds: Vec<RetainedMount>,
    _topology: BlockTopology,
    _mount_snapshot: Vec<MountRecord>,
    _mount_bindings: std::collections::BTreeMap<u64, DeviceNumber>,
}

/// Exact kernel mount authority retained independently of its pathname.
struct RetainedMount {
    directory: OwnedFd,
    tree: OwnedFd,
    mount_id: u64,
    restore: MountRestoreAuthority,
}

/// Parent-fd and leaf authority for independently checking one retained mount.
struct MountRestoreAuthority {
    parent: OwnedFd,
    leaf: CString,
    mount_point: Vec<u8>,
}

impl NativeVolumeLeases {
    /// Returns the count of exact retained block descriptors.
    pub(crate) fn block_count(&self) -> usize {
        self._block_authorities.len()
    }

    /// Returns the count of exact retained mount descriptors.
    pub(crate) fn mount_count(&self) -> usize {
        self._mount_fds.len()
    }

    /// Rejects root and boot mounts from destructive mutation eligibility.
    pub(crate) fn mutation_topology_safe(&self) -> bool {
        !self._mount_snapshot.iter().any(|mount| {
            let point = mount.mount_point();
            point == b"/"
                || point == b"/boot"
                || point == b"/boot/efi"
                || point == b"/usr"
                || point == b"/var"
        })
    }

    /// Returns exact writable, free-byte, and capacity facts for one mounted volume.
    pub(crate) fn mounted_facts(&self) -> Result<(bool, u64, u64), NativeError> {
        if self._mount_fds.len() != 1 || self._mount_snapshot.len() != 1 {
            return Err(NativeError::EvidenceIncomplete);
        }
        let mut storage = MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: the retained exact mount descriptor is live and storage is writable.
        if unsafe { libc::fstatvfs(self._mount_fds[0].directory.copied(), storage.as_mut_ptr()) }
            != 0
        {
            return Err(last_native_error());
        }
        // SAFETY: successful fstatvfs initialized the complete structure.
        let facts = unsafe { storage.assume_init() };
        let fragment = facts.f_frsize;
        let free = facts
            .f_bavail
            .checked_mul(fragment)
            .ok_or(NativeError::ResourceLimit)?;
        let capacity = facts
            .f_blocks
            .checked_mul(fragment)
            .ok_or(NativeError::ResourceLimit)?;
        Ok((self._mount_snapshot[0].is_writable(), free, capacity))
    }

    /// Returns the sole exact kernel-reported mounted filesystem type.
    pub(crate) fn mounted_filesystem_type(&self) -> Result<&[u8], NativeError> {
        let [mount] = self._mount_snapshot.as_slice() else {
            return Err(NativeError::EvidenceIncomplete);
        };
        Ok(mount.filesystem_type())
    }

    /// Returns exact whole-device write protection and byte capacity from sysfs.
    pub(crate) fn media_facts(&self) -> Result<(bool, u64), NativeError> {
        let whole = self
            ._block_authorities
            .iter()
            .filter(|authority| authority.node.partition.is_none())
            .collect::<Vec<_>>();
        let [whole] = whole.as_slice() else {
            return Err(NativeError::EvidenceIncomplete);
        };
        let roots = SysfsRoots::native()?;
        whole.revalidate(&roots)?;
        let sysfs = roots.devices_root().join(whole.node.relative_path());
        let sectors = read_decimal(&sysfs.join("size"))?;
        let read_only = read_decimal(&sysfs.join("ro"))?;
        let capacity = sectors.checked_mul(512).ok_or(NativeError::ResourceLimit)?;
        if capacity == 0 || read_only > 1 {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok((read_only == 0, capacity))
    }

    /// Returns the exact kernel-reported start and size of the sole partition.
    pub(crate) fn sole_partition_extent(&self) -> Result<(u64, u64), NativeError> {
        let partitions = self
            ._block_authorities
            .iter()
            .filter(|authority| authority.node.partition.is_some())
            .collect::<Vec<_>>();
        let [partition] = partitions.as_slice() else {
            return Err(NativeError::EvidenceIncomplete);
        };
        let roots = SysfsRoots::native()?;
        partition.revalidate(&roots)?;
        let sysfs = roots.devices_root().join(partition.node.relative_path());
        Ok((
            read_decimal(&sysfs.join("start"))?,
            read_decimal(&sysfs.join("size"))?,
        ))
    }

    /// Returns one sole retained block authority after exact revalidation.
    fn exact_block_authority(
        &self,
        partition: Option<u32>,
    ) -> Result<&RetainedBlockAuthority, NativeError> {
        let roots = SysfsRoots::native()?;
        let matching = self
            ._block_authorities
            .iter()
            .filter(|authority| authority.node.partition == partition)
            .collect::<Vec<_>>();
        let [authority] = matching.as_slice() else {
            return Err(NativeError::EvidenceIncomplete);
        };
        authority.revalidate(&roots)?;
        Ok(authority)
    }
}

/// Returns successful data only for a complete good SG data-in response.
fn completion_data(completion: Completion) -> Result<Vec<u8>, NativeError> {
    match completion {
        Completion::NotAttempted(error) | Completion::AttemptedError(error) => Err(error),
        Completion::Device { sense, .. } if sense_reports_no_media(&sense) => {
            Err(NativeError::NoMedia)
        }
        Completion::Device {
            status,
            masked_status,
            message_status,
            host_status,
            driver_status,
            info,
            residual,
            mut data,
            ..
        } if status == 0
            && masked_status == 0
            && message_status == 0
            && host_status == 0
            && driver_status == 0
            && info & 1 == 0
            && residual >= 0
            && usize::try_from(residual).is_ok_and(|residual| residual <= data.len()) =>
        {
            data.truncate(data.len() - usize::try_from(residual).expect("checked residual"));
            Ok(data)
        }
        Completion::Device { .. } => Err(NativeError::EvidenceIncomplete),
    }
}

/// Recognizes only fixed or descriptor sense for NOT READY / MEDIUM NOT PRESENT.
fn sense_reports_no_media(sense: &[u8]) -> bool {
    match sense.first().map(|byte| byte & 0x7F) {
        Some(0x70 | 0x71) if sense.len() >= 14 => sense[2] & 0x0F == 0x02 && sense[12] == 0x3A,
        Some(0x72 | 0x73) if sense.len() >= 4 => sense[1] & 0x0F == 0x02 && sense[2] == 0x3A,
        _ => false,
    }
}

/// Probes standard Linux resources without manufacturing readiness evidence.
pub(crate) fn probe_readiness() -> Readiness {
    let roots = SysfsRoots::native();
    let sysfs_available = roots.is_ok();
    let candidates = roots
        .as_ref()
        .ok()
        .and_then(|roots| retained_candidates_at(roots).ok())
        .unwrap_or_default();
    let device_access = if candidates.is_empty() {
        DeviceAccess::NoCandidate
    } else if candidates
        .into_iter()
        .any(|candidate| NativeDevice::open(&candidate).is_ok())
    {
        DeviceAccess::ReadWrite
    } else {
        DeviceAccess::Denied
    };

    let udev_rules_installed = installed_udev_rule_is_constrained();
    let group_snapshot = read_bounded(Path::new("/etc/group"), MAX_READINESS_FILE_BYTES).ok();
    let group_gid = group_snapshot.as_deref().and_then(configured_group_gid);
    let status = read_bounded(Path::new("/proc/self/status"), MAX_READINESS_FILE_BYTES).ok();
    let current_ipc_group_member = group_gid.is_some_and(|gid| {
        status
            .as_deref()
            .is_some_and(|contents| process_has_group(contents, gid))
            || effective_uid() == 0
    });
    let polkit_policy_installed =
        read_bounded(Path::new(OPENRDX_POLICY_PATH), MAX_READINESS_FILE_BYTES)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .is_some_and(|policy| polkit_policy_is_narrow(&policy));
    Readiness::new(
        sysfs_available,
        udev_rules_installed,
        group_gid.is_some(),
        current_ipc_group_member,
        device_access,
        polkit_policy_installed,
    )
}

/// Enumerates only bounded scsi-generic candidates from standard sysfs.
pub(crate) fn enumerate_scsi_generic_candidates() -> Result<Vec<ScsiGenericCandidate>, NativeError>
{
    let roots = SysfsRoots::native()?;
    retained_candidates_at(&roots)
}

/// Enumerates and retains every exact candidate under one already-proven root.
fn retained_candidates_at(roots: &SysfsRoots) -> Result<Vec<ScsiGenericCandidate>, NativeError> {
    let mut candidates = enumerate_candidates_at(roots)?;
    for candidate in &mut candidates {
        retain_sysfs_instance(candidate, roots)?;
    }
    Ok(candidates)
}

/// Opens and attaches the exact sysfs instance before a candidate escapes.
fn retain_sysfs_instance(
    candidate: &mut ScsiGenericCandidate,
    roots: &SysfsRoots,
) -> Result<(), NativeError> {
    let binding = candidate.native_binding()?;
    let before =
        resolve_binding(roots, binding.sg_index()).map_err(|_| NativeError::DeviceRemoved)?;
    let fd = open_sysfs_instance(roots, &binding)?;
    let proof = sysfs_instance_proof(&fstat_owned(&fd)?);
    let after =
        resolve_binding(roots, binding.sg_index()).map_err(|_| NativeError::DeviceRemoved)?;
    if !proof.is_directory() || before != binding || after != binding {
        return Err(NativeError::DeviceRemoved);
    }
    candidate.retain(RetainedSysfsInstance { fd, proof });
    Ok(())
}

/// Converts one internal semantic direction to Linux SG v3.
const fn sg_direction(direction: DataDirection) -> i32 {
    match direction {
        DataDirection::None => SG_DXFER_NONE,
        DataDirection::FromDevice => SG_DXFER_FROM_DEV,
        DataDirection::ToDevice => SG_DXFER_TO_DEV,
    }
}

/// Opens one private CString with bounded EINTR retries before device dispatch.
fn open_owned(path: &CString, flags: libc::c_int) -> Result<OwnedFd, NativeError> {
    for attempt in 0..MAX_PRECALL_EINTR_ATTEMPTS {
        // SAFETY: `path` is NUL-terminated and the flags require no variadic mode.
        let fd = unsafe { libc::open(path.as_ptr(), flags) };
        if fd >= 0 {
            return Ok(OwnedFd::new(fd));
        }
        let error = last_native_error();
        if error != NativeError::Interrupted || attempt + 1 == MAX_PRECALL_EINTR_ATTEMPTS {
            return Err(error);
        }
    }
    Err(NativeError::Interrupted)
}

/// Opens one slash-free child relative to retained directory authority.
fn openat_owned(
    parent: &OwnedFd,
    leaf: &CString,
    flags: libc::c_int,
) -> Result<OwnedFd, NativeError> {
    for attempt in 0..MAX_PRECALL_EINTR_ATTEMPTS {
        // SAFETY: parent is an owned directory fd, leaf is NUL-terminated and
        // slash-free, and these flags require no variadic mode argument.
        let fd = unsafe { libc::openat(parent.copied(), leaf.as_ptr(), flags) };
        if fd >= 0 {
            return Ok(OwnedFd::new(fd));
        }
        let error = last_native_error();
        if error != NativeError::Interrupted || attempt + 1 == MAX_PRECALL_EINTR_ATTEMPTS {
            return Err(error);
        }
    }
    Err(NativeError::Interrupted)
}

/// Translates the portable exact policy into the only accepted SG open flags.
fn sg_open_flags() -> libc::c_int {
    let requirements = sg_open_requirements();
    let mut flags = 0;
    if requirements.read_write() {
        flags |= libc::O_RDWR;
    }
    if requirements.exclusive() {
        flags |= libc::O_EXCL;
    }
    if requirements.nonblocking() {
        flags |= libc::O_NONBLOCK;
    }
    if requirements.close_on_exec() {
        flags |= libc::O_CLOEXEC;
    }
    if requirements.no_follow() {
        flags |= libc::O_NOFOLLOW;
    }
    flags
}

/// Copies descriptor metadata while the ownership guard remains live.
fn fstat_owned(fd: &OwnedFd) -> Result<libc::stat, NativeError> {
    for attempt in 0..MAX_PRECALL_EINTR_ATTEMPTS {
        let mut storage = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: storage is valid for one `stat`; success initializes every field.
        let result = unsafe { libc::fstat(fd.copied(), storage.as_mut_ptr()) };
        if result == 0 {
            // SAFETY: the successful `fstat` above initialized the complete structure.
            return Ok(unsafe { storage.assume_init() });
        }
        let error = last_native_error();
        if error != NativeError::Interrupted || attempt + 1 == MAX_PRECALL_EINTR_ATTEMPTS {
            return Err(error);
        }
    }
    Err(NativeError::Interrupted)
}

/// Opens the canonical sysfs device directory as non-reopenable authority.
fn open_sysfs_instance(
    roots: &SysfsRoots,
    binding: &DeviceBinding,
) -> Result<OwnedFd, NativeError> {
    open_sysfs_relative(roots, binding.relative_devpath())
}

/// Opens one already-proven canonical path relative to `/sys/devices`.
fn open_sysfs_relative(roots: &SysfsRoots, relative: &Path) -> Result<OwnedFd, NativeError> {
    let path = roots.devices_root().join(relative);
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| NativeError::EnumerationFailed)?;
    open_owned(
        &path,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )
}

/// Converts one open sysfs directory stat into a pointer-free identity proof.
fn sysfs_instance_proof(stat: &libc::stat) -> SysfsInstanceProof {
    SysfsInstanceProof::new(
        file_type(stat.st_mode) == libc::S_IFDIR,
        stat.st_dev,
        stat.st_ino,
    )
}

/// Pins block-node identity without invoking sd_open or preventing media removal.
fn open_exact_block(name: &str, expected: DeviceNumber) -> Result<OwnedFd, NativeError> {
    let path = CString::new(format!("/dev/{name}")).map_err(|_| NativeError::EnumerationFailed)?;
    let fd = open_owned(
        &path,
        // O_RDONLY invokes sd_open, which prevents removable-media eject until
        // its last block opener closes. Identity needs only fstat; O_PATH keeps
        // the exact inode without acquiring the kernel's media-removal lock.
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    let stat = fstat_owned(&fd)?;
    if file_type(stat.st_mode) != libc::S_IFBLK || device_number(stat.st_rdev) != expected {
        return Err(NativeError::DeviceRemoved);
    }
    Ok(fd)
}

/// Opens one mountinfo path and proves its filesystem device number exactly.
fn open_exact_mount(path: &[u8], expected: DeviceNumber) -> Result<OwnedFd, NativeError> {
    let path = CString::new(path).map_err(|_| NativeError::EnumerationFailed)?;
    let fd = open_owned(&path, libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)?;
    let stat = fstat_owned(&fd)?;
    if file_type(stat.st_mode) == libc::S_IFLNK || device_number(stat.st_dev) != expected {
        return Err(NativeError::DeviceRemoved);
    }
    Ok(fd)
}

/// Opens the exact mount object itself, without cloning it or retaining only a
/// pathname lookup result, for independent mount-object identity checks.
fn open_exact_mount_tree(path: &[u8]) -> Result<OwnedFd, NativeError> {
    let path = CString::new(path).map_err(|_| NativeError::EnumerationFailed)?;
    // SAFETY: path is the exact bounded mountinfo path and open_tree receives
    // only close-on-exec, deliberately omitting OPEN_TREE_CLONE.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(last_native_error());
    }
    let raw = libc::c_int::try_from(raw).map_err(|_| NativeError::Other)?;
    Ok(OwnedFd::new(raw))
}

/// Retains the original mountpoint parent and leaf for fd-relative identity checks.
fn open_mount_restore_authority(
    path: &[u8],
    mounted_directory: &OwnedFd,
) -> Result<MountRestoreAuthority, NativeError> {
    let separator = path
        .iter()
        .rposition(|byte| *byte == b'/')
        .ok_or(NativeError::EnumerationFailed)?;
    let leaf = path
        .get(separator + 1..)
        .filter(|leaf| !leaf.is_empty() && !leaf.contains(&b'/'))
        .ok_or(NativeError::EnumerationFailed)?;
    let parent = if separator == 0 {
        b"/".as_slice()
    } else {
        &path[..separator]
    };
    let parent = CString::new(parent).map_err(|_| NativeError::EnumerationFailed)?;
    let parent = open_owned(
        &parent,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    let leaf = CString::new(leaf).map_err(|_| NativeError::EnumerationFailed)?;
    let child = openat_owned(
        &parent,
        &leaf,
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    )?;
    let expected = fstat_owned(mounted_directory)?;
    let observed = fstat_owned(&child)?;
    if expected.st_dev != observed.st_dev
        || expected.st_ino != observed.st_ino
        || file_type(expected.st_mode) != file_type(observed.st_mode)
    {
        return Err(NativeError::DeviceRemoved);
    }
    Ok(MountRestoreAuthority {
        parent,
        leaf,
        mount_point: path.to_vec(),
    })
}

/// Converts Linux `dev_t` to a checked pointer-free major/minor pair.
fn device_number(raw: libc::dev_t) -> DeviceNumber {
    device_number_from_linux_dev_t(raw)
}

/// Extracts only the POSIX file-type bits.
const fn file_type(mode: libc::mode_t) -> libc::mode_t {
    mode & libc::S_IFMT
}

/// Reads at most one bounded file plus a sentinel byte.
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, NativeError> {
    use std::io::Read;

    let file = fs::File::open(path).map_err(|_| NativeError::EnumerationFailed)?;
    let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
    file.take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| NativeError::EnumerationFailed)?;
    if bytes.len() > maximum {
        return Err(NativeError::ResourceLimit);
    }
    Ok(bytes)
}

/// Returns true only for an installed exact-name constrained rules file.
fn installed_udev_rule_is_constrained() -> bool {
    let directories = [
        Path::new("/etc/udev/rules.d"),
        Path::new("/usr/lib/udev/rules.d"),
    ];
    let mut found = false;
    for directory in directories {
        let path = directory.join(OPENRDX_RULE_NAME);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return false,
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return false;
        }
        let Ok(bytes) = read_bounded(&path, MAX_READINESS_FILE_BYTES) else {
            return false;
        };
        let Ok(contents) = String::from_utf8(bytes) else {
            return false;
        };
        if inspect_udev_rules(&contents) != UdevRuleState::Constrained {
            return false;
        }
        found = true;
    }
    found
}

/// Reads the current effective UID for conservative service authorization.
fn effective_uid() -> libc::uid_t {
    // SAFETY: `geteuid` takes no pointers and has no preconditions.
    unsafe { libc::geteuid() }
}

/// Proves the current endpoint process is running as the root service account.
pub(crate) fn current_process_is_privileged_service() -> bool {
    effective_uid() == 0
}

/// Sanitizes the thread-local errno without retaining native text.
fn last_native_error() -> NativeError {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => NativeError::AccessDenied,
        Some(libc::EBUSY | libc::EAGAIN) => NativeError::Busy,
        Some(libc::EINTR) => NativeError::Interrupted,
        Some(libc::ETIMEDOUT) => NativeError::TimedOut,
        Some(libc::ENODEV | libc::ENXIO | libc::ENOENT) => NativeError::DeviceRemoved,
        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM) => NativeError::ResourceLimit,
        Some(_) | None => NativeError::Other,
    }
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;

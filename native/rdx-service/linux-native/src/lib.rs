#![deny(unsafe_op_in_unsafe_fn)]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#![deny(missing_docs)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

//! Safe package-private ownership boundary around OpenRDX Linux APIs.
//!
//! The parent service remains `forbid(unsafe_code)`. This crate owns Linux
//! descriptors and ioctl pointers, exposes no raw descriptor or device path,
//! and accepts only closed semantic operations.

#[cfg(any(target_os = "linux", test))]
use std::marker::PhantomData;

const MAX_CANDIDATES: usize = 128;
const MAX_SYSFS_ATTRIBUTE_BYTES: usize = 256;

mod block;
mod filesystem;
pub use filesystem::HostFilesystem;
mod endpoint;
mod host_unmount;
mod identity;
mod media_presence;
mod mountinfo;
mod ownership;
mod readiness;
mod sg;
mod volume_label;

#[cfg(target_os = "linux")]
mod native;

pub use endpoint::{
    ManagerEndpointConnection, SystemdEndpointContract, SystemdManagerEndpointListener,
    accept_systemd_manager_endpoint, activate_systemd_manager_endpoint, systemd_endpoint_contract,
};
pub use identity::ScsiGenericCandidate;
pub use ownership::{
    HardwareOwnershipGuard, HardwareOwnershipNamespace, hardware_ownership_contract,
    initialize_hardware_ownership_namespace, try_acquire_hardware_ownership,
};
pub use readiness::{DeviceAccess, Readiness};
pub use sg::{Completion, ScsiOperation, SgOpenRequirements, sg_open_requirements};

/// Returns whether this Linux process has the root service-account authority
/// required after accepting the fixed systemd socket.
#[must_use]
pub fn current_process_is_privileged_service() -> bool {
    #[cfg(target_os = "linux")]
    {
        native::current_process_is_privileged_service()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(all(test, unix))]
use block::{OpenedBlockProof, retained_block_authority_is_current, retained_volume_handle_count};
#[cfg(all(test, unix))]
use identity::{
    DeviceBinding, DeviceNumber, OpenedDeviceProof, SysfsInstanceProof, SysfsRoots,
    binding_is_stable, block_bindings_for, block_topology_for, candidate_instance_is_stable,
    decode_recipe, device_number_from_linux_dev_t, enumerate_candidates_at,
    retained_sysfs_instance_is_current,
};
#[cfg(all(test, unix))]
use mountinfo::{
    MAX_MOUNTINFO_LINE_BYTES, canonical_mounts_for_devices, mounts_for_devices, parse_mountinfo,
};
#[cfg(all(test, unix))]
use readiness::{
    UdevRuleState, configured_group_gid, inspect_udev_rules, polkit_policy_is_narrow,
    process_has_group,
};
#[cfg(all(test, unix))]
use sg::{DataDirection, MAX_SENSE_LENGTH, SgIoHeader, media_identity_material_from_vpd};

/// Sanitized companion-boundary failure with no errno text or path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeError {
    /// The current host is not Linux.
    UnsupportedPlatform,
    /// A bounded request or private recipe was malformed.
    InvalidRequest,
    /// The current process lacks required access.
    AccessDenied,
    /// Sharing, locking, or device state prevented the operation.
    Busy,
    /// A signal interrupted an already invoked synchronous operation.
    Interrupted,
    /// The bounded operation timed out.
    TimedOut,
    /// Hotplug removed or replaced the selected OS instance.
    DeviceRemoved,
    /// The retained exact RDX dock authoritatively reports no cartridge.
    NoMedia,
    /// Sysfs, block, mount, or readiness enumeration failed safely.
    EnumerationFailed,
    /// Exact topology evidence is layered, aggregate, or otherwise incomplete.
    EvidenceIncomplete,
    /// A required fixed host partitioning or filesystem tool is unavailable.
    DependencyMissing,
    /// A bounded allocation or enumeration limit was exceeded.
    ResourceLimit,
    /// Another sanitized native failure occurred.
    Other,
}

/// Certainty-preserving outcome of one closed Linux host mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOperationOutcome {
    /// Complete validation failed before a mutating syscall or SG dispatch.
    NotAttempted(NativeError),
    /// The kernel or device definitely rejected the invoked request.
    DefinitelyRejected(NativeError),
    /// A mutating call was invoked but completion cannot be proven.
    CompletionUnknown(NativeError),
    /// The complete closed operation succeeded.
    Succeeded,
}

/// Closed mounted-volume file test with independent cleanup evidence.
pub struct FileTestOutcome {
    operation: Result<Vec<u8>, NativeError>,
    operation_certainty: HostOperationOutcome,
    cleanup: HostOperationOutcome,
}

impl FileTestOutcome {
    /// Moves exact readback or failure plus cleanup certainty to the safe parent.
    pub fn into_parts(
        self,
    ) -> (
        Result<Vec<u8>, NativeError>,
        HostOperationOutcome,
        HostOperationOutcome,
    ) {
        (self.operation, self.operation_certainty, self.cleanup)
    }
}

impl std::fmt::Debug for FileTestOutcome {
    /// Redacts file bytes and reports only length plus cleanup certainty.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileTestOutcome")
            .field(
                "readback_length",
                &self.operation.as_ref().map_or(0, Vec::len),
            )
            .field("operation_certainty", &self.operation_certainty)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}

/// Releases one opaque resource value without exposing it outside this crate.
#[cfg(any(target_os = "linux", test))]
trait ResourceCloser<T> {
    /// Releases the exact resource once ownership ends.
    fn close(resource: T);
}

/// Non-cloneable ownership guard shared by real and injected native resources.
#[cfg(any(target_os = "linux", test))]
struct ResourceGuard<T, C: ResourceCloser<T>> {
    resource: Option<T>,
    closer: PhantomData<C>,
}

#[cfg(any(target_os = "linux", test))]
impl<T, C: ResourceCloser<T>> ResourceGuard<T, C> {
    /// Takes exclusive ownership of one resource value.
    fn new(resource: T) -> Self {
        Self {
            resource: Some(resource),
            closer: PhantomData,
        }
    }

    /// Copies an opaque scalar for one bounded native call.
    fn copied(&self) -> T
    where
        T: Copy,
    {
        self.resource.expect("live resource guard")
    }
}

#[cfg(any(target_os = "linux", test))]
impl<T, C: ResourceCloser<T>> Drop for ResourceGuard<T, C> {
    /// Releases a still-owned resource exactly once.
    fn drop(&mut self) {
        if let Some(resource) = self.resource.take() {
            C::close(resource);
        }
    }
}

/// Probes native Linux sysfs, access, group, policy, and service readiness.
#[must_use]
pub fn probe_readiness() -> Readiness {
    #[cfg(target_os = "linux")]
    {
        native::probe_readiness()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Readiness::unavailable()
    }
}

/// Enumerates bounded scsi-generic candidates without claiming RDX identity.
///
/// # Errors
///
/// Returns a sanitized enumeration failure. On non-Linux hosts this always
/// returns [`NativeError::UnsupportedPlatform`].
pub fn enumerate_scsi_generic_candidates() -> Result<Vec<ScsiGenericCandidate>, NativeError> {
    #[cfg(target_os = "linux")]
    {
        native::enumerate_scsi_generic_candidates()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Exact scsi-generic device lease whose descriptor and recipe never escape.
pub struct LinuxDevice {
    #[cfg(target_os = "linux")]
    inner: native::NativeDevice,
}

impl LinuxDevice {
    /// Atomically promotes one retained enumerated candidate into an SG lease.
    ///
    /// # Errors
    ///
    /// Returns a sanitized access, hotplug, busy, or recipe failure. Caller-
    /// supplied recipes or `/dev` paths are never accepted.
    pub fn open(candidate: ScsiGenericCandidate) -> Result<Self, NativeError> {
        Self::reopen(&candidate)
    }

    /// Opens a new exclusive lease from retained enumeration authority.
    ///
    /// Each open verifies the original sysfs instance, current device number,
    /// and opened SG descriptor. The recipe remains available after discovery;
    /// the live device lease itself is never shared or cloned.
    ///
    /// # Errors
    ///
    /// Returns a sanitized access, hotplug, busy, or incomplete-authority error.
    pub fn reopen(candidate: &ScsiGenericCandidate) -> Result<Self, NativeError> {
        #[cfg(target_os = "linux")]
        {
            native::NativeDevice::open(candidate).map(|inner| Self { inner })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = candidate;
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Executes one closed bounded operation synchronously through this lease.
    #[must_use]
    pub fn execute(&mut self, operation: ScsiOperation) -> Completion {
        #[cfg(target_os = "linux")]
        {
            match operation.into_request() {
                Ok(request) => self.inner.execute(request),
                Err(error) => Completion::NotAttempted(error),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = operation;
            Completion::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Pins exact block and mounted-volume descriptors beneath this device.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed topology or descriptor error without publishing a path.
    pub fn pin_volumes(&mut self) -> Result<VolumeLeaseSet<'_>, NativeError> {
        #[cfg(target_os = "linux")]
        {
            let media_identity_material = self.inner.media_identity_material()?;
            let leases = self.inner.pin_volumes()?;
            let block_count = leases.block_count();
            let mount_count = leases.mount_count();
            let mounted_facts = leases.mounted_facts().ok();
            let media_facts = leases.media_facts().ok();
            let mutation_topology_safe = leases.mutation_topology_safe();
            Ok(VolumeLeaseSet {
                block_count,
                mount_count,
                mounted_facts,
                media_facts,
                media_identity_material: Some(media_identity_material),
                mutation_topology_safe,
                _leases: leases,
                _device: self,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Requests physical media eject without first unmounting host filesystems.
    #[must_use]
    pub fn force_eject(&mut self) -> HostOperationOutcome {
        completion_to_host_outcome(self.execute(ScsiOperation::eject_media()))
    }

    /// Checks fixed partitioning and filesystem tools before any host mutation.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::DependencyMissing`] when the exact required tools
    /// are unavailable or a stale device authority cannot be revalidated.
    pub fn preflight_format(&mut self, filesystem: HostFilesystem) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.preflight_format(filesystem)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = filesystem;
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Replaces the exact whole-disk layout with one MBR partition.
    #[must_use]
    pub fn create_single_partition(&mut self, mbr_signature: u32) -> HostOperationOutcome {
        #[cfg(target_os = "linux")]
        {
            self.inner.create_single_partition(mbr_signature)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = mbr_signature;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Formats the exact newly discovered sole partition with a supported filesystem.
    #[must_use]
    pub fn format_partition(&mut self, filesystem: HostFilesystem) -> HostOperationOutcome {
        #[cfg(target_os = "linux")]
        {
            self.inner.format_partition(filesystem)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = filesystem;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Waits for authoritative absence of the exact cartridge after eject dispatch.
    ///
    /// # Errors
    ///
    /// Returns a sanitized timeout or stale-authority error when absence is unproven.
    pub fn verify_eject_departure(&mut self) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.verify_eject_departure()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }

    /// Waits for authoritative rediscovery of one exact formatted cartridge volume.
    ///
    /// # Errors
    ///
    /// Returns a sanitized timeout, topology, filesystem, or identity failure.
    pub fn verify_format_rediscovery(
        &mut self,
        filesystem: HostFilesystem,
        previous_capacity: u64,
    ) -> Result<(), NativeError> {
        #[cfg(target_os = "linux")]
        {
            self.inner
                .verify_format_rediscovery(filesystem, previous_capacity)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (filesystem, previous_capacity);
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl std::fmt::Debug for LinuxDevice {
    /// Redacts the descriptor, device node, and sysfs recipe.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LinuxDevice(<private>)")
    }
}

/// Opaque retained block and mount leases tied to one exact sg device.
pub struct VolumeLeaseSet<'device> {
    block_count: usize,
    mount_count: usize,
    mounted_facts: Option<(bool, u64, u64)>,
    media_facts: Option<(bool, u64)>,
    media_identity_material: Option<Vec<u8>>,
    mutation_topology_safe: bool,
    #[cfg(target_os = "linux")]
    _leases: native::NativeVolumeLeases,
    _device: &'device mut LinuxDevice,
}

impl VolumeLeaseSet<'_> {
    /// Returns the number of exact retained block descriptors.
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.block_count
    }

    /// Returns the number of exact retained mounted-path descriptors.
    #[must_use]
    pub const fn mount_count(&self) -> usize {
        self.mount_count
    }

    /// Returns exact writable, free-byte, and capacity facts for one mounted volume.
    #[must_use]
    pub const fn mounted_facts(&self) -> Option<(bool, u64, u64)> {
        self.mounted_facts
    }

    /// Returns exact whole-block writable and byte-capacity facts when proven.
    #[must_use]
    pub const fn media_facts(&self) -> Option<(bool, u64)> {
        self.media_facts
    }

    /// Returns actively queried cartridge VPD identity material.
    #[must_use]
    pub fn media_identity_material(&self) -> Option<&[u8]> {
        self.media_identity_material.as_deref()
    }

    /// Reports whether no exact selected mount is a boot or root filesystem.
    #[must_use]
    pub const fn mutation_topology_safe(&self) -> bool {
        self.mutation_topology_safe
    }

    /// Safely unmounts every exact retained mount and then ejects through SG_IO.
    #[must_use]
    pub fn safe_eject(self) -> HostOperationOutcome {
        self.safe_eject_observed(&mut || true)
    }

    /// Safely unmounts every exact retained mount and then ejects through SG_IO.
    /// The closed callback publishes the physical-eject stage only after the
    /// complete retained unmount succeeds.
    #[must_use]
    #[allow(
        unused_mut,
        reason = "only the Linux target mutates its retained leases"
    )]
    pub fn safe_eject_observed(
        mut self,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> HostOperationOutcome {
        #[cfg(target_os = "linux")]
        {
            let unmount = self._leases.unmount_all();
            if unmount != HostOperationOutcome::Succeeded {
                return unmount;
            }
            if !after_unmount() {
                return HostOperationOutcome::CompletionUnknown(NativeError::Interrupted);
            }
            completion_to_host_outcome(self._device.execute(ScsiOperation::eject_media()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = after_unmount;
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Unmounts every exact retained mount for a subsequent layout mutation.
    #[must_use]
    #[allow(
        unused_mut,
        reason = "only the Linux target mutates its retained leases"
    )]
    pub fn unmount_all(mut self) -> HostOperationOutcome {
        #[cfg(target_os = "linux")]
        {
            self._leases.unmount_all()
        }
        #[cfg(not(target_os = "linux"))]
        {
            HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
        }
    }

    /// Runs exact create-new/no-follow/write/fsync/reopen/read/unlink semantics.
    #[must_use]
    #[allow(
        unused_mut,
        reason = "only the Linux target mutates its retained leases"
    )]
    pub fn write_read_file(mut self, filename: &str, bytes: &[u8]) -> FileTestOutcome {
        #[cfg(target_os = "linux")]
        {
            self._leases.write_read_file(filename, bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (filename, bytes);
            FileTestOutcome {
                operation: Err(NativeError::UnsupportedPlatform),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::UnsupportedPlatform,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform),
            }
        }
    }
}

/// Converts one exact SG completion into host-mutation certainty.
fn completion_to_host_outcome(completion: Completion) -> HostOperationOutcome {
    match completion {
        Completion::NotAttempted(error) => HostOperationOutcome::NotAttempted(error),
        Completion::AttemptedError(error) => HostOperationOutcome::CompletionUnknown(error),
        Completion::Device {
            status,
            masked_status,
            message_status,
            host_status,
            driver_status,
            info,
            residual,
            ..
        } if status == 0
            && masked_status == 0
            && message_status == 0
            && host_status == 0
            && driver_status == 0
            && info & 1 == 0
            && residual == 0 =>
        {
            HostOperationOutcome::Succeeded
        }
        Completion::Device { .. } => HostOperationOutcome::DefinitelyRejected(NativeError::Other),
    }
}

impl std::fmt::Debug for VolumeLeaseSet<'_> {
    /// Formats only lease counts while redacting descriptors and paths.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VolumeLeaseSet")
            .field("block_count", &self.block_count)
            .field("mount_count", &self.mount_count)
            .field("handles", &"<private>")
            .finish()
    }
}

#[cfg(all(test, unix))]
mod tests;

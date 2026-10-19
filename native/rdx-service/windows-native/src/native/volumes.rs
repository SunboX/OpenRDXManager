// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact disk-to-volume mapping with retained opaque volume handles.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::OpenOptionsExt;

use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_FILES, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    DeleteVolumeMountPointW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetDiskFreeSpaceExW,
    GetVolumeInformationByHandleW, GetVolumeInformationW, GetVolumePathNamesForVolumeNameW,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, SetVolumeMountPointW,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    DISK_EXTENT, FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME, VOLUME_DISK_EXTENTS,
};
use windows::core::PCWSTR;

use super::super::{
    FileTestOutcome, HostFilesystem, HostOperationOutcome, NativeError, ResourceCloser,
    ResourceGuard, VolumeExtent, VolumeInventory, VolumeMembership, VolumeRecord, VolumeTopology,
    bounded_returned_length, classify_volume_probe, mount_paths_from_multi_sz,
    query_volume_topology, volume_extent_buffer_length, volume_extents_from_bytes,
};
use super::{
    KernelHandle, kernel_handle, map_windows_error, open_path, storage_device_identity,
    win32_error_code,
};

const MAX_VOLUME_NAME_UNITS: usize = 1_024;
use crate::volume_access::VolumeAccess;
#[cfg(test)]
mod metadata_tests;
const MAX_VOLUMES: usize = 256;
const MAX_VOLUME_EXTENT_BYTES: usize = 65_536;
const MAX_VOLUME_EXTENT_RESIZES: usize = 8;
const MAX_VOLUME_PATH_UNITS: usize = 32_768;

enum VolumeControl {
    Lock,
    Dismount,
}

impl VolumeControl {
    /// Returns only the two control codes admitted by the semantic boundary.
    const fn code(self) -> u32 {
        match self {
            Self::Lock => FSCTL_LOCK_VOLUME,
            Self::Dismount => FSCTL_DISMOUNT_VOLUME,
        }
    }
}

struct VolumeFindCloser;

impl ResourceCloser<isize> for VolumeFindCloser {
    /// Closes one volume-enumeration cursor exactly once.
    fn close(resource: isize) {
        // SAFETY: ResourceGuard owns the FindFirstVolumeW cursor exactly once.
        let _ = unsafe { FindVolumeClose(HANDLE(resource as *mut c_void)) };
    }
}

type VolumeFindHandle = ResourceGuard<isize, VolumeFindCloser>;

/// One authorized volume handle with no retained path or caller-visible identity.
pub(crate) struct NativeVolumeLease {
    handle: KernelHandle,
    record: VolumeRecord,
    access: VolumeAccess,
}

impl NativeVolumeLease {
    /// Returns fresh private extent evidence for the generated-layout continuation.
    pub(super) fn format_topology(&self) -> Result<crate::VolumeTopology, NativeError> {
        self.revalidate()?;
        volume_topology(kernel_handle(&self.handle))
    }

    /// Rechecks the complete pinned topology and mount association after enumeration.
    pub(super) fn revalidate(&self) -> Result<(), NativeError> {
        self.record.revalidate(
            &volume_topology(kernel_handle(&self.handle))?,
            &volume_mount_paths(self.record.key())?,
        )
    }

    /// Locks this retained volume handle for exclusive safe dismount preparation.
    pub(super) fn lock(&self) -> Result<(), NativeError> {
        self.access.require_mutation()?;
        no_data_volume_control(kernel_handle(&self.handle), VolumeControl::Lock)
    }

    /// Dismounts this already-locked retained volume through the same handle.
    pub(super) fn dismount(&self) -> Result<(), NativeError> {
        self.access.require_mutation()?;
        no_data_volume_control(kernel_handle(&self.handle), VolumeControl::Dismount)
    }

    /// Runs exact volume-GUID-relative file I/O without using a drive-letter path.
    pub(super) fn write_read_file(&self, filename: &str, bytes: &[u8]) -> FileTestOutcome {
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 || !valid_test_filename(filename) {
            return FileTestOutcome {
                operation: Err(NativeError::InvalidRequest),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::InvalidRequest,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::InvalidRequest),
            };
        }
        if let Err(error) = self
            .access
            .require_mutation()
            .and_then(|()| self.revalidate())
        {
            return FileTestOutcome {
                operation: Err(error),
                operation_certainty: HostOperationOutcome::NotAttempted(error),
                cleanup: HostOperationOutcome::NotAttempted(error),
            };
        }
        let path = match exact_file_path(self.record.key(), filename) {
            Ok(path) => path,
            Err(error) => {
                return FileTestOutcome {
                    operation: Err(error),
                    operation_certainty: HostOperationOutcome::NotAttempted(error),
                    cleanup: HostOperationOutcome::NotAttempted(error),
                };
            }
        };
        let mut created = false;
        let operation = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags((FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH).0)
                .open(&path)
                .map_err(map_file_error)?;
            created = true;
            self.revalidate()?;
            file.write_all(bytes).map_err(map_file_error)?;
            file.sync_all().map_err(map_file_error)?;
            drop(file);
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
                .open(&path)
                .map_err(map_file_error)?;
            let mut readback = vec![0_u8; bytes.len()];
            file.read_exact(&mut readback).map_err(map_file_error)?;
            let mut trailing = [0_u8; 1];
            if file.read(&mut trailing).map_err(map_file_error)? != 0 {
                return Err(NativeError::Other);
            }
            Ok(readback)
        })();
        let cleanup = if !created {
            HostOperationOutcome::Succeeded
        } else if self.revalidate().is_err() {
            HostOperationOutcome::CompletionUnknown(NativeError::DeviceRemoved)
        } else if std::fs::remove_file(&path).is_ok() && self.revalidate().is_ok() {
            HostOperationOutcome::Succeeded
        } else {
            HostOperationOutcome::CompletionUnknown(NativeError::Other)
        };
        let operation_certainty = if operation.is_ok() {
            HostOperationOutcome::Succeeded
        } else {
            HostOperationOutcome::CompletionUnknown(
                operation.as_ref().expect_err("failed operation").to_owned(),
            )
        };
        FileTestOutcome {
            operation,
            operation_certainty,
            cleanup,
        }
    }

    /// Returns filesystem space, or absence of a recognized filesystem on RAW media.
    pub(super) fn mounted_facts(&self) -> Result<Option<(u64, u64)>, NativeError> {
        self.revalidate()?;
        let mut available = 0_u64;
        let mut total = 0_u64;
        let mut label = [0_u16; 128];
        let mut filesystem = [0_u16; 64];
        let mut serial = 0_u32;
        let mut maximum_component = 0_u32;
        let mut flags = 0_u32;
        // Opening a RAW volume for retained read/write access can make path-based
        // information and space queries fail with ERROR_INVALID_PARAMETER. Query
        // this same handle instead: its explicit RAW name proves absent space
        // facts without treating generic failures as filesystem evidence.
        // SAFETY: the retained handle and all bounded output storage remain live.
        let information = unsafe {
            GetVolumeInformationByHandleW(
                kernel_handle(&self.handle),
                Some(&mut label),
                Some(&raw mut serial),
                Some(&raw mut maximum_component),
                Some(&raw mut flags),
                Some(&mut filesystem),
            )
        }
        .map_err(|error| error.code().0 as u32)
        .and_then(|()| {
            let end = filesystem
                .iter()
                .position(|unit| *unit == 0)
                .ok_or(0x8007_000d_u32)?;
            String::from_utf16(&filesystem[..end]).map_err(|_| 0x8007_000d_u32)
        });
        // SAFETY: record key is the exact NUL-terminated volume GUID root and all
        // outputs are valid writable u64 storage for this synchronous query.
        // Zero-access DASD handles can return ERROR_INVALID_FUNCTION on mounted
        // NTFS. Query the same pinned GUID root in that case, then require its
        // positive filesystem evidence before classifying free-space results.
        let information = crate::filesystem_facts::filesystem_information(information, || {
            filesystem.fill(0);
            // SAFETY: the retained GUID root and bounded output buffers remain live.
            unsafe {
                GetVolumeInformationW(
                    PCWSTR(self.record.key().as_ptr()),
                    None,
                    None,
                    None,
                    None,
                    Some(&mut filesystem),
                )
            }
            .map_err(|error| error.code().0 as u32)?;
            let end = filesystem
                .iter()
                .position(|unit| *unit == 0)
                .ok_or(0x8007_000d_u32)?;
            String::from_utf16(&filesystem[..end]).map_err(|_| 0x8007_000d_u32)
        });
        let facts = crate::filesystem_facts::query_volume_space(
            information.as_deref().map_err(|code| *code),
            || {
                unsafe {
                    GetDiskFreeSpaceExW(
                        PCWSTR(self.record.key().as_ptr()),
                        Some(&raw mut available),
                        Some(&raw mut total),
                        None,
                    )
                }
                .map(|()| (available, total))
                .map_err(|error| error.code().0 as u32)
            },
        )
        .map_err(|code| super::map_windows_error(windows::core::HRESULT(code as i32).into()))?;
        // RAW is a filesystem observation, not permission to skip identity or
        // topology checks on the same retained volume after the native query.
        self.revalidate()?;
        Ok(facts)
    }

    /// Formats this exact retained volume and returns its pre-format identity.
    /// VDS can remount it and change its mount associations. The parent must
    /// drop old leases and prove fresh GUID/topology/media identity afterward.
    pub(super) fn format(&self, filesystem: HostFilesystem) -> Result<VolumeRecord, NativeError> {
        self.access.require_mutation()?;
        self.revalidate()?;
        super::vds::format_volume(self.record.key(), filesystem)?;
        Ok(self.record.clone())
    }

    /// Compares fresh identity against one confirmed format's immutable proof.
    /// The parent must also revalidate this lease's fresh mount snapshot.
    pub(super) fn revalidate_after_format(
        &self,
        expected: &VolumeRecord,
    ) -> Result<(), NativeError> {
        expected.revalidate_after_format(&self.record)
    }

    /// Reports whether one absolute host path lies under any exact mount path.
    pub(super) fn contains_host_path(&self, path: &[u16]) -> bool {
        self.record.mount_paths().iter().any(|mount| {
            path.len() >= mount.len()
                && path[..mount.len()].iter().zip(mount).all(|(left, right)| {
                    left == right
                        || (char::from_u32(u32::from(*left)).is_some_and(|left| {
                            char::from_u32(u32::from(*right))
                                .is_some_and(|right| left.eq_ignore_ascii_case(&right))
                        }))
                })
        })
    }

    /// Returns whether this exact volume currently owns one drive-root mount.
    pub(crate) fn has_drive_letter(&self, letter: char) -> bool {
        self.record.drive_letters().contains(&letter)
    }

    /// Applies one unused drive root to this exact retained volume GUID.
    pub(crate) fn set_drive_letter(&self, letter: char) -> crate::HostOperationOutcome {
        if let Err(error) = self.access.require_mutation() {
            return crate::HostOperationOutcome::NotAttempted(error);
        }
        if let Err(error) = self.revalidate() {
            return crate::HostOperationOutcome::NotAttempted(error);
        }
        let root = [letter as u16, ':' as u16, '\\' as u16, 0];
        // SAFETY: root and retained volume key are exact NUL-terminated strings.
        if let Err(error) = unsafe {
            SetVolumeMountPointW(PCWSTR(root.as_ptr()), PCWSTR(self.record.key().as_ptr()))
        }
        .map_err(super::map_windows_error)
        {
            return crate::HostOperationOutcome::CompletionUnknown(error);
        }
        let current = match volume_mount_paths(self.record.key()) {
            Ok(current) => current,
            Err(error) => return crate::HostOperationOutcome::CompletionUnknown(error),
        };
        if current.iter().any(|path| path.as_slice() == &root[..3]) {
            crate::HostOperationOutcome::Succeeded
        } else {
            crate::HostOperationOutcome::CompletionUnknown(NativeError::DeviceRemoved)
        }
    }

    /// Deletes only the requested drive root after proving this exact volume owns it.
    pub(crate) fn reset_drive_letter(&self, letter: char) -> Result<(), NativeError> {
        self.access.require_mutation()?;
        if !self.has_drive_letter(letter) {
            return Err(NativeError::InvalidRequest);
        }
        let root = [letter as u16, ':' as u16, '\\' as u16, 0];
        // SAFETY: root is one exact NUL-terminated drive root proven on this volume.
        unsafe { DeleteVolumeMountPointW(PCWSTR(root.as_ptr())) }
            .map_err(super::map_windows_error)?;
        let current = volume_mount_paths(self.record.key())?;
        if current.iter().any(|path| path.as_slice() == &root[..3]) {
            Err(NativeError::DeviceRemoved)
        } else {
            Ok(())
        }
    }

    /// Returns a private UTF-16 copy of the exact retained volume GUID key.
    pub(crate) fn volume_key(&self) -> &[u16] {
        self.record.key()
    }

    /// Proves the exact current filesystem type reported for this volume GUID.
    pub(crate) fn filesystem_matches(
        &self,
        filesystem: HostFilesystem,
    ) -> Result<bool, NativeError> {
        self.revalidate()?;
        let mut name = [0_u16; 64];
        // SAFETY: retained key is NUL-terminated and name is bounded writable storage.
        unsafe {
            GetVolumeInformationW(
                PCWSTR(self.record.key().as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut name),
            )
        }
        .map_err(super::map_windows_error)?;
        let end = name
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(NativeError::Other)?;
        let observed = String::from_utf16(&name[..end]).map_err(|_| NativeError::Other)?;
        Ok(match filesystem {
            HostFilesystem::Ntfs => observed.eq_ignore_ascii_case("NTFS"),
            HostFilesystem::ExFat => observed.eq_ignore_ascii_case("exFAT"),
        })
    }
}

/// Accepts only the parent service's random app-owned basename.
fn valid_test_filename(filename: &str) -> bool {
    let prefix = ".openrdx-write-read-";
    let suffix = ".tmp";
    filename.len() == prefix.len() + 32 + suffix.len()
        && filename.starts_with(prefix)
        && filename.ends_with(suffix)
        && filename[prefix.len()..filename.len() - suffix.len()]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Builds one internal volume-GUID path plus validated basename.
fn exact_file_path(volume: &[u16], filename: &str) -> Result<OsString, NativeError> {
    if volume.len() < 2 || volume.last() != Some(&0) || volume[volume.len() - 2] != b'\\' as u16 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let mut path = OsString::from_wide(&volume[..volume.len() - 1]);
    path.push(filename);
    Ok(path)
}

/// Sanitizes one std filesystem error without retaining a path or message.
fn map_file_error(error: std::io::Error) -> NativeError {
    match error.raw_os_error().map(|code| code as u32) {
        Some(code) if code == windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 => {
            NativeError::AccessDenied
        }
        Some(code) if code == windows::Win32::Foundation::ERROR_WRITE_PROTECT.0 => {
            NativeError::ReadOnly
        }
        Some(code)
            if code == windows::Win32::Foundation::ERROR_DEVICE_REMOVED.0
                || code == windows::Win32::Foundation::ERROR_DEVICE_NOT_CONNECTED.0 =>
        {
            NativeError::DeviceRemoved
        }
        _ => NativeError::Other,
    }
}

/// One complete scan plus target handles retained from that same enumeration.
pub(super) struct ScannedVolumes {
    pub(super) drive_letters: Vec<char>,
    pub(super) mount_path_count: usize,
    pub(super) inventory: VolumeInventory,
    pub(super) leases: Vec<NativeVolumeLease>,
}

/// Enumerates and pins only volumes proven to belong exclusively to one retained disk.
pub(super) fn pin_disk_volumes(disk_number: u32) -> Result<ScannedVolumes, NativeError> {
    scan_disk_volumes(disk_number, VolumeAccess::Mutation)
}

/// Retains metadata-only handles for complete, non-mutating cartridge discovery.
pub(super) fn pin_disk_volume_metadata(disk_number: u32) -> Result<ScannedVolumes, NativeError> {
    scan_disk_volumes(disk_number, VolumeAccess::Metadata)
}

/// Revalidates every topology and retains only exact target volumes at fixed access.
fn scan_disk_volumes(
    disk_number: u32,
    access: VolumeAccess,
) -> Result<ScannedVolumes, NativeError> {
    let mut buffer = vec![0_u16; MAX_VOLUME_NAME_UNITS];
    // SAFETY: buffer is writable and sized for a bounded volume name.
    let cursor = unsafe { FindFirstVolumeW(&mut buffer) }.map_err(map_windows_error)?;
    let cursor = VolumeFindHandle::new(cursor.0 as isize);
    let mut leases = Vec::new();
    let mut records = Vec::new();
    let mut drive_letters = BTreeSet::new();
    let mut mount_path_count = 0_usize;
    let mut candidate_count = 0_usize;
    loop {
        candidate_count = candidate_count
            .checked_add(1)
            .ok_or(NativeError::ResourceLimit)?;
        if candidate_count > MAX_VOLUMES {
            return Err(NativeError::ResourceLimit);
        }
        let name = nul_terminated_copy(&buffer)?;
        let (record, lease) = inspect_volume(&name, disk_number, access)?;
        if let Some(lease) = lease {
            drive_letters.extend(record.drive_letters().iter().copied());
            mount_path_count = mount_path_count
                .checked_add(record.mount_paths().len())
                .ok_or(NativeError::ResourceLimit)?;
            leases.push(lease);
            if leases.len() > MAX_VOLUMES {
                return Err(NativeError::ResourceLimit);
            }
        }
        records.push(record);
        buffer.fill(0);
        // SAFETY: cursor remains live and buffer is writable for the next name.
        if let Err(error) = unsafe { FindNextVolumeW(volume_find_handle(&cursor), &mut buffer) } {
            if win32_error_code(&error) == Some(ERROR_NO_MORE_FILES) {
                break;
            }
            return Err(map_windows_error(error));
        }
    }
    Ok(ScannedVolumes {
        drive_letters: drive_letters.into_iter().collect(),
        mount_path_count,
        inventory: VolumeInventory::new(records)?,
        leases,
    })
}

/// Fully inspects one enumerated volume and upgrades target access before retention.
fn inspect_volume(
    volume_name: &[u16],
    disk_number: u32,
    access: VolumeAccess,
) -> Result<(VolumeRecord, Option<NativeVolumeLease>), NativeError> {
    let open_name = open_volume_name(volume_name)?;
    let inspection = open_path(&open_name, 0)?;
    let topology = volume_topology(kernel_handle(&inspection))?;
    let target = match classify_volume_probe(Ok(topology.clone()), disk_number)? {
        VolumeMembership::Unrelated => false,
        VolumeMembership::Target(_) => true,
    };
    let mount_paths = volume_mount_paths(volume_name)?;
    let record =
        VolumeRecord::new_with_mount_paths(volume_name.to_vec(), topology, mount_paths, target)?;
    if !target {
        return Ok((record, None));
    }

    // Metadata queries retain the zero-access handle already bound to this
    // topology. Mutation leases still require a separate successful raw open.
    let retained = match access {
        VolumeAccess::Metadata => inspection,
        VolumeAccess::Mutation => open_path(&open_name, access.desired_access())?,
    };
    record.revalidate(
        &volume_topology(kernel_handle(&retained))?,
        &volume_mount_paths(volume_name)?,
    )?;
    Ok((
        record.clone(),
        Some(NativeVolumeLease {
            handle: retained,
            record,
            access,
        }),
    ))
}

/// Converts a volume GUID path to the exact no-trailing-slash CreateFile name.
fn open_volume_name(volume_name: &[u16]) -> Result<Vec<u16>, NativeError> {
    let mut open_name = volume_name.to_vec();
    if open_name.len() < 2 || open_name.last() != Some(&0) {
        return Err(NativeError::EnumerationFailed);
    }
    open_name.pop();
    if open_name.last() == Some(&92_u16) {
        open_name.pop();
    }
    if open_name.is_empty() {
        return Err(NativeError::EnumerationFailed);
    }
    open_name.push(0);
    Ok(open_name)
}

/// Reads every bounded physical-disk extent from one already-open volume.
fn volume_disk_extents(volume: HANDLE) -> Result<Vec<VolumeExtent>, NativeError> {
    let extent_offset = offset_of!(VOLUME_DISK_EXTENTS, Extents);
    let extent_stride = size_of::<DISK_EXTENT>();
    let mut capacity =
        volume_extent_buffer_length(1, extent_offset, extent_stride, MAX_VOLUME_EXTENT_BYTES)?;
    for _ in 0..MAX_VOLUME_EXTENT_RESIZES {
        let words = capacity.div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let mut returned = 0_u32;
        // SAFETY: aligned storage is writable for the exact bounded capacity.
        let result = unsafe {
            DeviceIoControl(
                volume,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None,
                0,
                Some(storage.as_mut_ptr().cast()),
                u32::try_from(capacity).map_err(|_| NativeError::ResourceLimit)?,
                Some(&mut returned),
                None,
            )
        };
        if let Err(error) = result {
            if win32_error_code(&error) != Some(ERROR_MORE_DATA) {
                return Err(map_windows_error(error));
            }
            let first_word = storage[0].to_le_bytes();
            let count = u32::from_le_bytes(
                first_word[..size_of::<u32>()]
                    .try_into()
                    .map_err(|_| NativeError::EnumerationFailed)?,
            );
            let required = volume_extent_buffer_length(
                count,
                extent_offset,
                extent_stride,
                MAX_VOLUME_EXTENT_BYTES,
            )?;
            if required <= capacity {
                return Err(NativeError::EnumerationFailed);
            }
            capacity = required;
            continue;
        }

        let returned = bounded_returned_length(returned, capacity, size_of::<u32>())?;
        // SAFETY: returned is bounded by the live aligned allocation passed to DeviceIoControl.
        let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned) };
        return volume_extents_from_bytes(
            bytes,
            extent_offset,
            extent_stride,
            offset_of!(DISK_EXTENT, DiskNumber),
            offset_of!(DISK_EXTENT, StartingOffset),
            offset_of!(DISK_EXTENT, ExtentLength),
        );
    }
    Err(NativeError::ResourceLimit)
}

/// Captures every identity field and ordered extent from one live volume handle.
pub(super) fn volume_topology(volume: HANDLE) -> Result<VolumeTopology, NativeError> {
    query_volume_topology(storage_device_identity(volume), || {
        volume_disk_extents(volume)
    })
}

/// Reads and normalizes only root drive-letter mount paths for one volume.
/// Reads and retains every exact drive-root or folder mount path for one volume.
fn volume_mount_paths(volume_name: &[u16]) -> Result<Vec<Vec<u16>>, NativeError> {
    mount_paths_from_multi_sz(&volume_mount_paths_buffer(volume_name)?)
}

/// Reads one bounded raw mount-path MULTI_SZ for exact parsing.
fn volume_mount_paths_buffer(volume_name: &[u16]) -> Result<Vec<u16>, NativeError> {
    let mut required = 0_u32;
    // SAFETY: volume_name is NUL-terminated and first call requests required size only.
    let first = unsafe {
        GetVolumePathNamesForVolumeNameW(PCWSTR(volume_name.as_ptr()), None, &mut required)
    };
    if let Err(error) = first
        && !matches!(
            win32_error_code(&error),
            Some(ERROR_MORE_DATA) | Some(ERROR_INSUFFICIENT_BUFFER)
        )
    {
        return Err(map_windows_error(error));
    }
    let required = required as usize;
    if required == 0 {
        return Ok(Vec::new());
    }
    if required > MAX_VOLUME_PATH_UNITS {
        return Err(NativeError::ResourceLimit);
    }
    let mut buffer = vec![0_u16; required];
    let mut returned = required as u32;
    // SAFETY: volume name and output slice are valid for this synchronous query.
    unsafe {
        GetVolumePathNamesForVolumeNameW(
            PCWSTR(volume_name.as_ptr()),
            Some(&mut buffer),
            &mut returned,
        )
    }
    .map_err(map_windows_error)?;
    let returned = returned as usize;
    if returned == 0 || returned > buffer.len() {
        return Err(NativeError::EnumerationFailed);
    }
    buffer.truncate(returned);
    Ok(buffer)
}

/// Issues one closed no-buffer volume control through an already-pinned handle.
fn no_data_volume_control(volume: HANDLE, control: VolumeControl) -> Result<(), NativeError> {
    let mut returned = 0_u32;
    // SAFETY: volume is a retained direct-access handle; the closed control code
    // requires no input/output buffers and the byte count is valid writable storage.
    unsafe {
        DeviceIoControl(
            volume,
            control.code(),
            None,
            0,
            None,
            0,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error)
}

/// Copies one NUL-terminated string from a fixed native output buffer.
fn nul_terminated_copy(buffer: &[u16]) -> Result<Vec<u16>, NativeError> {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(NativeError::EnumerationFailed)?;
    if end == 0 {
        return Err(NativeError::EnumerationFailed);
    }
    Ok(buffer[..=end].to_vec())
}

/// Reconstructs a private volume-enumeration HANDLE for one bounded call.
fn volume_find_handle(handle: &VolumeFindHandle) -> HANDLE {
    HANDLE(handle.copied() as *mut c_void)
}

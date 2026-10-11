// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact physical-disk layout, mounted-volume facts, and filesystem operations.

use super::*;
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows::Win32::System::Com::CoCreateGuid;
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ, RegCloseKey,
    RegOpenKeyExW, RegQueryValueExW,
};

impl NativeDevice {
    /// Returns exact disk write protection, mounted state, free bytes, and capacity.
    pub(crate) fn volume_facts(&self) -> Result<(bool, bool, u64, u64, bool), NativeError> {
        self.revalidate_exact()?;
        // Windows can enumerate a zero-length placeholder volume for an empty
        // RDX bay. Prove no-media on the retained disk before inspecting volumes;
        // a cartridge that is present still needs every original topology check.
        let Some(_) = crate::media::verified_media_capacity(
            disk_capacity(kernel_handle(&self.handle)),
            || self.revalidate_exact(),
        )?
        else {
            return Ok((false, false, 0, 0, true));
        };
        let scanned = volumes::pin_disk_volumes(self.identity.disk_number())?;
        self.revalidate_volume_leases(&scanned.leases)?;
        // Retain the original post-pinning capacity read for present cartridges;
        // the early query only decides whether volume inspection is applicable.
        let capacity = disk_capacity(kernel_handle(&self.handle))?;
        let writable = disk_is_writable(kernel_handle(&self.handle))?;
        let protected_paths = windows_protected_host_paths()?;
        let topology_safe = !disk_has_protected_partition_roles(kernel_handle(&self.handle))?
            && !scanned.leases.iter().any(|lease| {
                protected_paths
                    .iter()
                    .any(|path| lease.contains_host_path(path))
            });
        let (mounted, free_bytes) = match scanned.leases.as_slice() {
            [] if scanned.mount_path_count == 0 => (false, 0),
            [_lease] if scanned.mount_path_count == 0 => (false, 0),
            [lease] if scanned.mount_path_count > 0 => match lease.mounted_facts()? {
                Some((free, _)) => (true, free),
                None => (false, 0),
            },
            _ => return Err(NativeError::EvidenceIncomplete),
        };
        self.revalidate_volume_leases(&scanned.leases)?;
        Ok((writable, mounted, free_bytes, capacity, topology_safe))
    }

    /// Runs exact volume-GUID file I/O for one sole mounted target volume.
    pub(crate) fn write_read_file(&self, filename: &str, bytes: &[u8]) -> FileTestOutcome {
        let scanned = match self.pin_volumes() {
            Ok((_drive_letters, mount_path_count, _inventory, leases)) => {
                (mount_path_count, leases)
            }
            Err(error) => {
                return FileTestOutcome {
                    operation: Err(error),
                    operation_certainty: HostOperationOutcome::NotAttempted(error),
                    cleanup: HostOperationOutcome::NotAttempted(error),
                };
            }
        };
        let (1, [lease]) = (scanned.0, scanned.1.as_slice()) else {
            return FileTestOutcome {
                operation: Err(NativeError::EvidenceIncomplete),
                operation_certainty: HostOperationOutcome::NotAttempted(
                    NativeError::EvidenceIncomplete,
                ),
                cleanup: HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete),
            };
        };
        lease.write_read_file(filename, bytes)
    }

    /// Proves VDS and the exact current disk authority before host mutation.
    pub(crate) fn preflight_format(&self, _filesystem: HostFilesystem) -> Result<(), NativeError> {
        self.revalidate_exact()?;
        vds::preflight()?;
        let (writable, _, _, capacity, topology_safe) = self.format_volume_facts()?;
        if !writable {
            return Err(NativeError::ReadOnly);
        }
        let _ = partition_style_for_capacity(capacity)?;
        if !topology_safe {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    }

    /// Applies one capacity-safe MBR or GPT basic-data partition through exact disk IOCTLs.
    pub(crate) fn create_single_partition(&self, signature: u32) -> HostOperationOutcome {
        if let Err(error) = self.clear_created_layout() {
            return HostOperationOutcome::NotAttempted(error);
        }
        if signature == 0 {
            return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
        }
        if let Err(error) = self.revalidate_exact() {
            return HostOperationOutcome::NotAttempted(error);
        }
        match self.format_volume_facts() {
            Ok((true, _, _, _, true)) => {}
            Ok(_) => return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete),
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        }
        let scanned = match volumes::pin_disk_volumes(self.identity.disk_number()) {
            Ok(scanned) => scanned,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        if let Err(error) = self.revalidate_volume_leases(&scanned.leases) {
            return HostOperationOutcome::NotAttempted(error);
        }
        let capacity = match disk_capacity(kernel_handle(&self.handle)) {
            Ok(capacity) => capacity,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let style = match partition_style_for_capacity(capacity) {
            Ok(style) => style,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let alignment = 1024_u64 * 1024;
        let Ok(starting_offset) = i64::try_from(alignment) else {
            return HostOperationOutcome::NotAttempted(NativeError::ResourceLimit);
        };
        let reserved_tail = if style == DiskLayoutStyle::Gpt {
            alignment
        } else {
            0
        };
        let partition_bytes = capacity
            .saturating_sub(alignment)
            .saturating_sub(reserved_tail)
            / alignment
            * alignment;
        let Ok(partition_length) = i64::try_from(partition_bytes) else {
            return HostOperationOutcome::NotAttempted(NativeError::ResourceLimit);
        };
        if partition_length <= 0 {
            return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
        }
        let prepared = match style {
            DiskLayoutStyle::Mbr => {
                let sectors = partition_bytes / 512;
                if sectors == 0 || sectors > u64::from(u32::MAX) {
                    return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
                }
                (
                    CREATE_DISK {
                        PartitionStyle: PARTITION_STYLE_MBR,
                        Anonymous: CREATE_DISK_0 {
                            Mbr: CREATE_DISK_MBR {
                                Signature: signature,
                            },
                        },
                    },
                    DRIVE_LAYOUT_INFORMATION_EX {
                        PartitionStyle: PARTITION_STYLE_MBR.0 as u32,
                        PartitionCount: 1,
                        Anonymous: DRIVE_LAYOUT_INFORMATION_EX_0 {
                            Mbr: DRIVE_LAYOUT_INFORMATION_MBR {
                                Signature: signature,
                                CheckSum: 0,
                            },
                        },
                        PartitionEntry: [PARTITION_INFORMATION_EX {
                            PartitionStyle: PARTITION_STYLE_MBR,
                            StartingOffset: starting_offset,
                            PartitionLength: partition_length,
                            PartitionNumber: 1,
                            RewritePartition: true,
                            IsServicePartition: false,
                            Anonymous: PARTITION_INFORMATION_EX_0 {
                                Mbr: PARTITION_INFORMATION_MBR {
                                    PartitionType: PARTITION_IFS as u8,
                                    BootIndicator: false,
                                    RecognizedPartition: true,
                                    HiddenSectors: u32::try_from(alignment / 512).unwrap_or(0),
                                    PartitionId: windows::core::GUID::zeroed(),
                                },
                            },
                        }],
                    },
                )
            }
            DiskLayoutStyle::Gpt => {
                // SAFETY: CoCreateGuid initializes and returns one value without
                // retaining caller storage or mutating disk state.
                let disk_id = match unsafe { CoCreateGuid() } {
                    Ok(id) => id,
                    Err(error) => {
                        return HostOperationOutcome::NotAttempted(map_windows_error(error));
                    }
                };
                // SAFETY: the second call creates the distinct partition identity
                // before any disk IOCTL can be dispatched.
                let partition_id = match unsafe { CoCreateGuid() } {
                    Ok(id) => id,
                    Err(error) => {
                        return HostOperationOutcome::NotAttempted(map_windows_error(error));
                    }
                };
                if disk_id == windows::core::GUID::zeroed()
                    || partition_id == windows::core::GUID::zeroed()
                    || disk_id == partition_id
                {
                    return HostOperationOutcome::NotAttempted(NativeError::EvidenceIncomplete);
                }
                let mut name = [0_u16; 36];
                for (target, value) in name.iter_mut().zip("OpenRDX".encode_utf16()) {
                    *target = value;
                }
                (
                    CREATE_DISK {
                        PartitionStyle: PARTITION_STYLE_GPT,
                        Anonymous: CREATE_DISK_0 {
                            Gpt: CREATE_DISK_GPT {
                                DiskId: disk_id,
                                MaxPartitionCount: MAX_DISK_PARTITIONS as u32,
                            },
                        },
                    },
                    DRIVE_LAYOUT_INFORMATION_EX {
                        PartitionStyle: PARTITION_STYLE_GPT.0 as u32,
                        PartitionCount: 1,
                        Anonymous: DRIVE_LAYOUT_INFORMATION_EX_0 {
                            Gpt: DRIVE_LAYOUT_INFORMATION_GPT {
                                DiskId: disk_id,
                                StartingUsableOffset: starting_offset,
                                UsableLength: partition_length,
                                MaxPartitionCount: MAX_DISK_PARTITIONS as u32,
                            },
                        },
                        PartitionEntry: [PARTITION_INFORMATION_EX {
                            PartitionStyle: PARTITION_STYLE_GPT,
                            StartingOffset: starting_offset,
                            PartitionLength: partition_length,
                            PartitionNumber: 1,
                            RewritePartition: true,
                            IsServicePartition: false,
                            Anonymous: PARTITION_INFORMATION_EX_0 {
                                Gpt: PARTITION_INFORMATION_GPT {
                                    PartitionType: MICROSOFT_BASIC_DATA,
                                    PartitionId: partition_id,
                                    Attributes: GPT_ATTRIBUTES(0),
                                    Name: name,
                                },
                            },
                        }],
                    },
                )
            }
        };
        let (create, layout) = prepared;
        let medium = match self.media_identity_material() {
            Ok(medium) => medium,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        // Dismount does not remove Windows mount-point associations. Reacquire
        // and retain every exclusive volume lock here, immediately across the
        // layout write, instead of treating a remaining drive letter as busy.
        // The earlier host-level dismount released its handles on return.
        super::mutations::execute_locked_layout(self, &scanned.leases, &scanned.inventory, || {
            match disk_capacity(kernel_handle(&self.handle)) {
                Ok(current) if current == capacity => {}
                Ok(_) => return HostOperationOutcome::NotAttempted(NativeError::DeviceRemoved),
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            }
            if let Err(error) =
                disk_control_input(kernel_handle(&self.handle), IOCTL_DISK_CREATE_DISK, &create)
            {
                return HostOperationOutcome::CompletionUnknown(error);
            }
            if let Err(error) = disk_control_input(
                kernel_handle(&self.handle),
                IOCTL_DISK_SET_DRIVE_LAYOUT_EX,
                &layout,
            ) {
                return HostOperationOutcome::CompletionUnknown(error);
            }
            if let Err(error) =
                disk_control_no_data(kernel_handle(&self.handle), IOCTL_DISK_UPDATE_PROPERTIES)
            {
                return HostOperationOutcome::CompletionUnknown(error);
            }
            match self
                .revalidate_exact()
                .and_then(|()| self.remember_created_layout(&layout, capacity, medium))
            {
                Ok(()) => HostOperationOutcome::Succeeded,
                Err(error) => HostOperationOutcome::CompletionUnknown(error),
            }
        })
    }

    /// Waits for authoritative no-media evidence on the retained physical device.
    pub(crate) fn verify_eject_departure(&self) -> Result<(), NativeError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match self.media_identity_material() {
                Err(NativeError::DeviceRemoved | NativeError::NoMedia) => return Ok(()),
                Err(error) => return Err(error),
                Ok(_) if std::time::Instant::now() >= deadline => {
                    return Err(NativeError::TimedOut);
                }
                Ok(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Proves one newly mounted exact volume, filesystem, and unchanged capacity.
    pub(crate) fn verify_format_rediscovery(
        &self,
        filesystem: HostFilesystem,
        previous_capacity: u64,
    ) -> Result<(), NativeError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            self.revalidate_exact()?;
            match volumes::pin_disk_volumes(self.identity.disk_number()) {
                Ok(scanned)
                    if scanned.leases.len() == 1
                        && scanned.mount_path_count > 0
                        && disk_capacity(kernel_handle(&self.handle))? == previous_capacity
                        && scanned.leases[0].filesystem_matches(filesystem)? =>
                {
                    return Ok(());
                }
                Ok(_) | Err(NativeError::DeviceRemoved | NativeError::EnumerationFailed)
                    if std::time::Instant::now() < deadline => {}
                Ok(_) => return Err(NativeError::TimedOut),
                Err(error) => return Err(error),
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Reads a bounded complete partition layout from the exact retained disk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DiskLayoutStamp {
    Mbr(u32),
    Gpt(windows::core::GUID),
    Raw,
}

/// Reads a bounded complete partition layout with its immutable disk identity.
pub(super) fn disk_layout(
    handle: HANDLE,
) -> Result<(DiskLayoutStamp, Vec<PARTITION_INFORMATION_EX>), NativeError> {
    let entry_offset = offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
    let stride = size_of::<PARTITION_INFORMATION_EX>();
    let byte_capacity = entry_offset
        .checked_add(
            MAX_DISK_PARTITIONS
                .checked_mul(stride)
                .ok_or(NativeError::ResourceLimit)?,
        )
        .ok_or(NativeError::ResourceLimit)?;
    let word_count = byte_capacity.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; word_count];
    let mut returned = 0_u32;
    // SAFETY: storage is aligned writable output for the bounded layout size.
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
            None,
            0,
            Some(storage.as_mut_ptr().cast()),
            u32::try_from(byte_capacity).map_err(|_| NativeError::ResourceLimit)?,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error)?;
    if returned as usize > byte_capacity {
        return Err(NativeError::EvidenceIncomplete);
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned as usize) };
    if bytes.len() < entry_offset {
        return Err(NativeError::EvidenceIncomplete);
    }
    // SAFETY: initialized backing storage holds the full struct; the returned
    // bytes prove the fixed header, even when no flexible entry was returned.
    let layout =
        unsafe { std::ptr::read_unaligned(storage.as_ptr().cast::<DRIVE_LAYOUT_INFORMATION_EX>()) };
    // Storage is fully initialized; the returned header proves its fields, not
    // the flexible first entry. Never read a full struct from a short byte slice.
    let stamp = layout_stamp(&layout)?;
    let count = layout.PartitionCount as usize;
    let required = entry_offset
        .checked_add(
            count
                .checked_mul(stride)
                .ok_or(NativeError::ResourceLimit)?,
        )
        .ok_or(NativeError::ResourceLimit)?;
    if count > MAX_DISK_PARTITIONS || required > bytes.len() {
        return Err(NativeError::EvidenceIncomplete);
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        // SAFETY: required proves every complete aligned-or-unaligned entry byte range.
        let entry = unsafe {
            std::ptr::read_unaligned(
                bytes
                    .as_ptr()
                    .add(entry_offset + index * stride)
                    .cast::<PARTITION_INFORMATION_EX>(),
            )
        };
        entries.push(entry);
    }
    Ok((stamp, entries))
}

/// Reads only the union member selected by the native header discriminant.
pub(super) fn layout_stamp(
    layout: &DRIVE_LAYOUT_INFORMATION_EX,
) -> Result<DiskLayoutStamp, NativeError> {
    if layout.PartitionStyle == PARTITION_STYLE_GPT.0 as u32 {
        // SAFETY: the checked discriminant selects GPT.
        Ok(DiskLayoutStamp::Gpt(unsafe { layout.Anonymous.Gpt.DiskId }))
    } else if layout.PartitionStyle == PARTITION_STYLE_MBR.0 as u32 {
        // SAFETY: the checked discriminant selects MBR.
        Ok(DiskLayoutStamp::Mbr(unsafe {
            layout.Anonymous.Mbr.Signature
        }))
    } else if layout.PartitionStyle == PARTITION_STYLE_RAW.0 as u32 {
        Ok(DiskLayoutStamp::Raw)
    } else {
        Err(NativeError::EvidenceIncomplete)
    }
}

/// Rejects boot, EFI, recovery, service, and platform-required partition roles.
fn disk_has_protected_partition_roles(handle: HANDLE) -> Result<bool, NativeError> {
    let (_, entries) = disk_layout(handle)?;
    for entry in entries {
        if entry.PartitionLength <= 0 || entry.PartitionNumber == 0 {
            continue;
        }
        if entry.IsServicePartition {
            return Ok(true);
        }
        if entry.PartitionStyle == PARTITION_STYLE_MBR {
            // SAFETY: the discriminant above selects the MBR union member.
            let mbr = unsafe { entry.Anonymous.Mbr };
            if mbr.BootIndicator
                || matches!(
                    u32::from(mbr.PartitionType),
                    PARTITION_SYSTEM | PARTITION_MSFT_RECOVERY | PARTITION_WINDOWS_SYSTEM
                )
            {
                return Ok(true);
            }
        } else if entry.PartitionStyle == PARTITION_STYLE_GPT {
            // SAFETY: the discriminant above selects the GPT union member.
            let gpt = unsafe { entry.Anonymous.Gpt };
            const EFI_SYSTEM: windows::core::GUID =
                windows::core::GUID::from_u128(0xC12A7328_F81F_11D2_BA4B_00A0C93EC93B);
            const MICROSOFT_RESERVED: windows::core::GUID =
                windows::core::GUID::from_u128(0xE3C9E316_0B5C_4DB8_817D_F92DF00215AE);
            const MICROSOFT_RECOVERY: windows::core::GUID =
                windows::core::GUID::from_u128(0xDE94BBA4_06D1_4D40_A16A_BFD50179D6AC);
            if matches!(
                gpt.PartitionType,
                EFI_SYSTEM | MICROSOFT_RESERVED | MICROSOFT_RECOVERY
            ) || gpt.Attributes.0 & GPT_ATTRIBUTE_PLATFORM_REQUIRED.0 != 0
                || gpt.Attributes.0 & GPT_ATTRIBUTE_LEGACY_BIOS_BOOTABLE != 0
            {
                return Ok(true);
            }
        } else {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    Ok(false)
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: this guard owns one successful RegOpenKeyExW result.
        let _ = unsafe { RegCloseKey(self.0) };
    }
}

/// Collects OS, pagefile, and crash-dump host paths from authoritative settings.
pub(super) fn windows_protected_host_paths() -> Result<Vec<Vec<u16>>, NativeError> {
    let system = windows_system_path()?;
    let mut paths = vec![system.clone()];
    let paging_key =
        open_registry_key(r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")?;
    let (kind, units) = query_registry_units(&paging_key, "PagingFiles")?;
    if kind != REG_MULTI_SZ {
        return Err(NativeError::EvidenceIncomplete);
    }
    for entry in split_multi_sz(&units)? {
        let path = entry
            .iter()
            .position(|unit| *unit == ' ' as u16)
            .map_or(entry.as_slice(), |end| &entry[..end]);
        if let Some(path) = expand_fixed_system_path(path, &system) {
            paths.push(path);
        }
    }
    let crash_key = open_registry_key(r"SYSTEM\CurrentControlSet\Control\CrashControl")?;
    for name in ["DumpFile", "MinidumpDir", "DedicatedDumpFile"] {
        match query_registry_units_optional(&crash_key, name)? {
            Some((kind, units)) if kind == REG_SZ || kind == REG_EXPAND_SZ => {
                let end = units
                    .iter()
                    .position(|unit| *unit == 0)
                    .unwrap_or(units.len());
                if let Some(path) = expand_fixed_system_path(&units[..end], &system) {
                    paths.push(path);
                }
            }
            Some(_) => return Err(NativeError::EvidenceIncomplete),
            None => {}
        }
    }
    paths.sort_unstable();
    paths.dedup();
    Ok(paths)
}

/// Opens one fixed HKLM system policy key read-only.
fn open_registry_key(path: &str) -> Result<RegistryKey, NativeError> {
    let path = wide_null(OsStr::new(path));
    let mut key = HKEY::default();
    // SAFETY: path is fixed NUL-terminated text and output storage is writable.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            None,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(RegistryKey(key))
}

/// Reads one bounded registry string value with its exact declared type.
fn query_registry_units(
    key: &RegistryKey,
    name: &str,
) -> Result<(windows::Win32::System::Registry::REG_VALUE_TYPE, Vec<u16>), NativeError> {
    query_registry_units_optional(key, name)?.ok_or(NativeError::EvidenceIncomplete)
}

/// Reads an optional bounded registry string value without environment expansion.
fn query_registry_units_optional(
    key: &RegistryKey,
    name: &str,
) -> Result<Option<(windows::Win32::System::Registry::REG_VALUE_TYPE, Vec<u16>)>, NativeError> {
    let name = wide_null(OsStr::new(name));
    let mut kind = Default::default();
    let mut length = 0_u32;
    // SAFETY: key/name are live and type/length are writable sizing storage.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut length),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS || length == 0 || length > 32_768 || length % 2 != 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let mut bytes = vec![0_u8; length as usize];
    // SAFETY: bytes has the exact bounded writable capacity returned above.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PCWSTR(name.as_ptr()),
            None,
            Some(&mut kind),
            Some(bytes.as_mut_ptr()),
            Some(&mut length),
        )
    };
    if status != ERROR_SUCCESS || length as usize > bytes.len() {
        return Err(NativeError::EvidenceIncomplete);
    }
    bytes.truncate(length as usize);
    let units = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(Some((kind, units)))
}

/// Splits a strict double-NUL-terminated registry MULTI_SZ.
fn split_multi_sz(units: &[u16]) -> Result<Vec<Vec<u16>>, NativeError> {
    if units.len() < 2 || units[units.len() - 2..] != [0, 0] {
        return Err(NativeError::EvidenceIncomplete);
    }
    let mut values = Vec::new();
    let mut start = 0_usize;
    while start < units.len() - 1 {
        let length = units[start..]
            .iter()
            .position(|unit| *unit == 0)
            .ok_or(NativeError::EvidenceIncomplete)?;
        if length == 0 {
            break;
        }
        values.push(units[start..start + length].to_vec());
        start += length + 1;
    }
    Ok(values)
}

/// Expands only exact SystemRoot/SystemDrive prefixes or accepts a drive path.
fn expand_fixed_system_path(path: &[u16], system: &[u16]) -> Option<Vec<u16>> {
    let text = String::from_utf16(path).ok()?;
    if text.len() >= 3
        && text.as_bytes()[0].is_ascii_alphabetic()
        && &text.as_bytes()[1..3] == b":\\"
    {
        return Some(path.to_vec());
    }
    let system_text = String::from_utf16(system).ok()?;
    let upper = text.to_ascii_uppercase();
    if let Some(suffix) = upper.strip_prefix("%SYSTEMROOT%") {
        return Some(format!("{system_text}{suffix}").encode_utf16().collect());
    }
    if let Some(suffix) = upper.strip_prefix("%SYSTEMDRIVE%") {
        let drive = system_text.get(..2)?;
        return Some(format!("{drive}{suffix}").encode_utf16().collect());
    }
    None
}

/// Returns the uppercase drive hosting the current Windows directory.
fn windows_system_path() -> Result<Vec<u16>, NativeError> {
    let mut buffer = [0_u16; 512];
    // SAFETY: buffer is valid writable UTF-16 storage for this bounded query.
    let length = unsafe { GetWindowsDirectoryW(Some(&mut buffer)) } as usize;
    if length < 3 || length >= buffer.len() || buffer[1] != b':' as u16 {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(buffer[..length].to_vec())
}

/// Issues one exact typed disk-control input request.
fn disk_control_input<T>(handle: HANDLE, code: u32, input: &T) -> Result<(), NativeError> {
    let mut returned = 0_u32;
    // SAFETY: input is an initialized fixed-layout Win32 structure and the
    // retained exact physical handle stays live for this synchronous call.
    unsafe {
        DeviceIoControl(
            handle,
            code,
            Some((input as *const T).cast::<c_void>()),
            size_of::<T>() as u32,
            None,
            0,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error)?;
    if returned == 0 {
        Ok(())
    } else {
        Err(NativeError::Other)
    }
}

/// Issues one exact no-buffer disk-control request.
fn disk_control_no_data(handle: HANDLE, code: u32) -> Result<(), NativeError> {
    let mut returned = 0_u32;
    // SAFETY: retained exact physical handle stays live for this synchronous call.
    unsafe { DeviceIoControl(handle, code, None, 0, None, 0, Some(&mut returned), None) }
        .map_err(map_windows_error)?;
    if returned == 0 {
        Ok(())
    } else {
        Err(NativeError::Other)
    }
}

/// Queries exact physical-disk write protection through the retained handle.
fn disk_is_writable(handle: HANDLE) -> Result<bool, NativeError> {
    let mut returned = 0_u32;
    // SAFETY: retained exact disk handle is live and the no-buffer query is synchronous.
    match unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_IS_WRITABLE,
            None,
            0,
            None,
            0,
            Some(&mut returned),
            None,
        )
    } {
        Ok(()) if returned == 0 => Ok(true),
        Ok(()) => Err(NativeError::Other),
        Err(error) if win32_error_code(&error) == Some(ERROR_WRITE_PROTECT) => Ok(false),
        Err(error) => Err(map_windows_error(error)),
    }
}

/// Queries exact byte capacity through the retained physical-disk handle.
pub(super) fn disk_capacity(handle: HANDLE) -> Result<u64, NativeError> {
    let mut geometry = DISK_GEOMETRY_EX::default();
    let mut returned = 0_u32;
    // SAFETY: geometry is exact initialized writable storage for this synchronous query.
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            None,
            0,
            Some((&raw mut geometry).cast()),
            size_of::<DISK_GEOMETRY_EX>() as u32,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error)?;
    if (returned as usize) < offset_of!(DISK_GEOMETRY_EX, Data) || geometry.DiskSize <= 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    u64::try_from(geometry.DiskSize).map_err(|_| NativeError::ResourceLimit)
}

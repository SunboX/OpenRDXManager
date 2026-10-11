// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only VDS disk-role evidence for the narrowly supported Mac data layout.

use super::*;
use windows::Win32::Storage::VirtualDiskService::{
    IVdsDisk, VDS_DISK_PROP, VDS_DS_ONLINE, VDS_PST_GPT,
};

// Do not infer safety from IsBoot=false alone: the EFI system disk can differ
// from the Windows volume's disk. VDS owns these active role flags. Allow only
// inert style/firmware-visibility/Refs-support flags; unknown flags fail closed.
const INERT_FLAGS: u32 = 0x10 | 0x1000 | 0x10000;

/// Proves exactly one matching online, non-system disk in the complete VDS graph.
pub(super) fn require_inactive_disk(
    number: u32,
    capacity: u64,
    id: windows::core::GUID,
) -> Result<(), NativeError> {
    if capacity == 0 || id == windows::core::GUID::zeroed() {
        return Err(NativeError::InvalidRequest);
    }
    let _apartment = ComApartment::initialize()?;
    let service = load_service()?;
    wait_service_ready_bounded(&service)?;
    // SAFETY: initialized COM service and the documented software-provider flag.
    let providers = unsafe { service.QueryProviders(VDS_QUERY_SOFTWARE_PROVIDERS.0 as u32) }
        .map_err(map_windows_error)?;
    let mut inspected = 0;
    let mut matches = 0;
    while let Some(provider) = next_object(&providers)? {
        inspected = bounded_increment(inspected)?;
        let provider: IVdsSwProvider = provider.cast().map_err(map_windows_error)?;
        // SAFETY: the cast owns a live provider interface in this apartment.
        let packs = unsafe { provider.QueryPacks() }.map_err(map_windows_error)?;
        while let Some(pack) = next_object(&packs)? {
            inspected = bounded_increment(inspected)?;
            let pack: IVdsPack = pack.cast().map_err(map_windows_error)?;
            // SAFETY: the cast owns a live pack interface in this apartment.
            let disks = unsafe { pack.QueryDisks() }.map_err(map_windows_error)?;
            inspect_disks(&disks, number, capacity, id, &mut inspected, &mut matches)?;
        }
    }
    // SAFETY: the live service returns an owned read-only enumeration.
    let disks = unsafe { service.QueryUnallocatedDisks() }.map_err(map_windows_error)?;
    inspect_disks(&disks, number, capacity, id, &mut inspected, &mut matches)?;
    if matches == 1 {
        Ok(())
    } else {
        Err(NativeError::EvidenceIncomplete)
    }
}

/// Reads every bounded disk object, matching disk number, capacity and GPT identity.
fn inspect_disks(
    enumerator: &IEnumVdsObject,
    number: u32,
    capacity: u64,
    id: windows::core::GUID,
    inspected: &mut usize,
    matches: &mut usize,
) -> Result<(), NativeError> {
    while let Some(object) = next_object(enumerator)? {
        *inspected = bounded_increment(*inspected)?;
        let disk: IVdsDisk = object.cast().map_err(map_windows_error)?;
        let mut properties = DiskProperties(VDS_DISK_PROP::default());
        // SAFETY: the owned COM object initializes the exact guarded output.
        unsafe { disk.GetProperties(&mut properties.0) }.map_err(map_windows_error)?;
        let name = copy_disk_name(properties.0.pwszName)?;
        if !disk_name_matches(&name, number) {
            continue;
        }
        *matches += 1;
        if *matches != 1 || !inactive_properties(&properties.0, capacity, id) {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    Ok(())
}

/// Requires the same GPT identity/capacity and authoritative inactive Windows roles.
fn inactive_properties(properties: &VDS_DISK_PROP, capacity: u64, id: windows::core::GUID) -> bool {
    if properties.PartitionStyle != VDS_PST_GPT || properties.ullSize != capacity {
        return false;
    }
    // SAFETY: the checked GPT discriminant selects the disk GUID member.
    (unsafe { properties.Anonymous.DiskGuid == id })
        && inactive_flags(properties.status == VDS_DS_ONLINE, properties.ulFlags)
}

/// Accepts only the OS physical-disk name, never an arbitrary path or prefix match.
fn disk_name_matches(name: &str, number: u32) -> bool {
    name.eq_ignore_ascii_case(&format!(r"\\?\PhysicalDrive{number}"))
        || name.eq_ignore_ascii_case(&format!(r"\\.\PhysicalDrive{number}"))
}

/// Requires positive online evidence and rejects every active or unknown flag.
const fn inactive_flags(online: bool, flags: u32) -> bool {
    online && flags & !INERT_FLAGS == 0
}

/// Copies a bounded native name; its allocation remains owned by DiskProperties.
fn copy_disk_name(name: PWSTR) -> Result<String, NativeError> {
    if name.is_null() {
        return Err(NativeError::EvidenceIncomplete);
    }
    for length in 0..256 {
        // SAFETY: successful VDS GetProperties promises a NUL-terminated string.
        if unsafe { *name.as_ptr().add(length) } == 0 {
            // SAFETY: every unit up to this terminator was read above; the
            // properties guard retains the allocation while this slice is used.
            let units = unsafe { std::slice::from_raw_parts(name.as_ptr(), length) };
            return String::from_utf16(units).map_err(|_| NativeError::EvidenceIncomplete);
        }
    }
    Err(NativeError::ResourceLimit)
}

/// Owns all five task-memory strings returned by IVdsDisk::GetProperties.
struct DiskProperties(VDS_DISK_PROP);

impl Drop for DiskProperties {
    /// Releases each transferred native allocation exactly once.
    fn drop(&mut self) {
        for pointer in [
            self.0.pwszDiskAddress,
            self.0.pwszName,
            self.0.pwszFriendlyName,
            self.0.pwszAdaptorName,
            self.0.pwszDevicePath,
        ] {
            if !pointer.is_null() {
                // SAFETY: GetProperties transfers these individual COM allocations.
                unsafe { CoTaskMemFree(Some(pointer.as_ptr().cast())) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matching the device number alone cannot admit a stale/replaced or system disk.
    #[test]
    fn properties_require_the_same_gpt_identity_capacity_and_active_role_proof() {
        use windows::Win32::Storage::VirtualDiskService::{
            VDS_DISK_PROP_0, VDS_DS_UNKNOWN, VDS_PST_MBR,
        };
        let id = windows::core::GUID::from_u128(77);
        let mut properties = VDS_DISK_PROP {
            PartitionStyle: VDS_PST_GPT,
            ullSize: 3000,
            status: VDS_DS_ONLINE,
            Anonymous: VDS_DISK_PROP_0 { DiskGuid: id },
            ..Default::default()
        };
        assert!(inactive_properties(&properties, 3000, id));
        assert!(!inactive_properties(&properties, 3001, id));
        assert!(!inactive_properties(
            &properties,
            3000,
            windows::core::GUID::from_u128(78)
        ));
        properties.status = VDS_DS_UNKNOWN;
        assert!(!inactive_properties(&properties, 3000, id));
        properties.status = VDS_DS_ONLINE;
        properties.ulFlags = 0x80;
        assert!(!inactive_properties(&properties, 3000, id));
        properties.ulFlags = 0;
        properties.PartitionStyle = VDS_PST_MBR;
        assert!(!inactive_properties(&properties, 3000, id));
    }

    /// Even one protected or unknown bit rejects a removable Mac-looking disk.
    #[test]
    fn active_windows_roles_and_unknown_evidence_are_rejected() {
        assert!(inactive_flags(true, 0));
        assert!(inactive_flags(true, INERT_FLAGS));
        assert!(!inactive_flags(false, 0));
        for bit in 0..32 {
            let flag = 1 << bit;
            if flag & INERT_FLAGS == 0 {
                assert!(!inactive_flags(true, flag));
            }
        }
    }

    /// A neighboring or suffix-injected disk name cannot authorize the selected disk.
    #[test]
    fn native_disk_matching_is_exact() {
        assert!(disk_name_matches(r"\\?\PhysicalDrive1", 1));
        assert!(disk_name_matches(r"\\.\physicaldrive1", 1));
        for name in [
            r"\\?\PhysicalDrive10",
            r"\\?\PhysicalDrive1\suffix",
            "PhysicalDrive1",
            "",
        ] {
            assert!(!disk_name_matches(name, 1));
        }
    }
}

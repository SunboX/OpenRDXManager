// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Format-only admission for inactive EFI plus Apple data cartridges.

use super::*;

const EFI: windows::core::GUID =
    windows::core::GUID::from_u128(0xc12a7328_f81f_11d2_ba4b_00a0c93ec93b);
const HFS: windows::core::GUID =
    windows::core::GUID::from_u128(0x48465300_0000_11aa_aa11_00306543ecac);
const APFS: windows::core::GUID =
    windows::core::GUID::from_u128(0x7c3457ef_0000_11aa_aa11_00306543ecac);

/// Immutable, complete identity of the narrowly supported Mac cartridge layout.
#[derive(Debug, Eq, PartialEq)]
struct MacLayoutIdentity {
    disk_id: windows::core::GUID,
    partitions: [(windows::core::GUID, windows::core::GUID, i64, i64); 2],
}

/// Recognizes only two ordered, non-overlapping GPT entries with no protected flags.
fn mac_layout_identity(
    disk_id: windows::core::GUID,
    entries: &[PARTITION_INFORMATION_EX],
    capacity: u64,
) -> Option<MacLayoutIdentity> {
    if disk_id == windows::core::GUID::zeroed() || entries.len() != 2 {
        return None;
    }
    let mut partitions = [(
        windows::core::GUID::zeroed(),
        windows::core::GUID::zeroed(),
        0,
        0,
    ); 2];
    let mut previous_end = 0_u64;
    for (index, entry) in entries.iter().enumerate() {
        if entry.PartitionStyle != PARTITION_STYLE_GPT
            || entry.IsServicePartition
            || entry.PartitionNumber != index as u32 + 1
        {
            return None;
        }
        // SAFETY: the explicit GPT discriminant selects this union member.
        let gpt = unsafe { entry.Anonymous.Gpt };
        let offset = u64::try_from(entry.StartingOffset).ok()?;
        let length = u64::try_from(entry.PartitionLength).ok()?;
        let end = offset.checked_add(length)?;
        // Disk Utility starts its ESP at LBA 40, not the Windows 1 MiB boundary.
        // Reserve the GPT headers while validating sector alignment and bounds.
        if offset < 34 * 512
            || offset < previous_end
            || length == 0
            || offset % 512 != 0
            || length % 512 != 0
            || end > capacity.saturating_sub(34 * 512)
            || gpt.Attributes.0 != 0
            || gpt.PartitionId == windows::core::GUID::zeroed()
        {
            return None;
        }
        if index == 0 {
            // Apple Disk Utility commonly creates a 200 MiB unused ESP. Keep
            // this exception bounded; arbitrary boot/system layouts stay denied.
            if gpt.PartitionType != EFI
                || !(100 * 1024 * 1024..=512 * 1024 * 1024).contains(&length)
            {
                return None;
            }
        } else if ![HFS, APFS].contains(&gpt.PartitionType) || length <= 512 * 1024 * 1024 {
            return None;
        }
        partitions[index] = (
            gpt.PartitionType,
            gpt.PartitionId,
            entry.StartingOffset,
            entry.PartitionLength,
        );
        previous_end = end;
    }
    if partitions[0].1 == partitions[1].1 {
        return None;
    }
    Some(MacLayoutIdentity {
        disk_id,
        partitions,
    })
}

impl NativeDevice {
    /// Extends only format facts after complete layout, native role and medium proof.
    pub(crate) fn format_volume_facts(&self) -> Result<(bool, bool, u64, u64, bool), NativeError> {
        let facts = self.volume_facts()?;
        if facts.4 || facts.3 == 0 {
            return Ok(facts);
        }
        let (stamp, entries) = layout::disk_layout(kernel_handle(&self.handle))?;
        let layout::DiskLayoutStamp::Gpt(disk_id) = stamp else {
            return Ok(facts);
        };
        let Some(expected) = mac_layout_identity(disk_id, &entries, facts.3) else {
            return Ok(facts);
        };
        let medium = self.media_identity_material()?;
        let scanned = volumes::pin_disk_volumes(self.identity.disk_number())?;
        self.revalidate_volume_leases(&scanned.leases)?;
        let paths = layout::windows_protected_host_paths()?;
        if scanned
            .leases
            .iter()
            .any(|lease| paths.iter().any(|path| lease.contains_host_path(path)))
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        vds::require_inactive_mac_disk(self.identity.disk_number(), facts.3, disk_id)?;
        self.revalidate_exact()?;
        self.revalidate_volume_leases(&scanned.leases)?;
        // Host roles can change while the bounded VDS worker is running.
        let paths = layout::windows_protected_host_paths()?;
        if scanned
            .leases
            .iter()
            .any(|lease| paths.iter().any(|path| lease.contains_host_path(path)))
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        let current = self.volume_facts()?;
        let (current_stamp, current_entries) = layout::disk_layout(kernel_handle(&self.handle))?;
        let layout::DiskLayoutStamp::Gpt(current_id) = current_stamp else {
            return Err(NativeError::DeviceRemoved);
        };
        if current.3 != facts.3
            || current.0 != facts.0
            || self.media_identity_material()? != medium
            || mac_layout_identity(current_id, &current_entries, current.3).as_ref()
                != Some(&expected)
        {
            return Err(NativeError::DeviceRemoved);
        }
        // The EFI filesystem is not the cartridge's data volume. Formatting
        // replaces the whole confirmed layout; rename/write-read still use the
        // unchanged ordinary volume_facts() and reject this topology.
        Ok((current.0, false, 0, current.3, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the exact GPT shape observed on the connected HFS cartridge.
    fn fixture(
        data_type: windows::core::GUID,
    ) -> (windows::core::GUID, Vec<PARTITION_INFORMATION_EX>, u64) {
        let entry = |number, offset, length, kind| PARTITION_INFORMATION_EX {
            PartitionStyle: PARTITION_STYLE_GPT,
            PartitionNumber: number,
            StartingOffset: offset,
            PartitionLength: length,
            Anonymous: PARTITION_INFORMATION_EX_0 {
                Gpt: PARTITION_INFORMATION_GPT {
                    PartitionType: kind,
                    PartitionId: windows::core::GUID::from_u128(number as u128),
                    ..Default::default()
                },
            },
            ..Default::default()
        };
        (
            windows::core::GUID::from_u128(77),
            vec![
                entry(1, 20_480, 209_715_200, EFI),
                entry(2, 209_735_680, 3_000_244_813_824, data_type),
            ],
            3_000_588_787_712,
        )
    }

    /// HFS and APFS data layouts are candidates, not authority without native role proof.
    #[test]
    fn known_mac_data_layouts_are_recognized() {
        for kind in [HFS, APFS] {
            let (id, entries, capacity) = fixture(kind);
            assert!(mac_layout_identity(id, &entries, capacity).is_some());
        }
    }

    /// Arbitrary EFI, Windows, service, boot-flagged and malformed layouts stay denied.
    #[test]
    fn protected_or_incomplete_layouts_are_not_mac_data() {
        for case in 0..12 {
            let (mut id, mut entries, mut capacity) = fixture(HFS);
            match case {
                0 => id = windows::core::GUID::zeroed(),
                1 => entries.pop().map(|_| ()).unwrap(),
                2 => entries.push(entries[1]),
                3 => entries[0].IsServicePartition = true,
                4 => entries[1].PartitionStyle = PARTITION_STYLE_MBR,
                5 => entries[1].StartingOffset = 1024 * 1024,
                6 => entries[1].PartitionLength = -1,
                7 => capacity = 1024 * 1024,
                8 => entries[0].Anonymous.Gpt.Attributes = GPT_ATTRIBUTE_PLATFORM_REQUIRED,
                9 => {
                    entries[1].Anonymous.Gpt.Attributes =
                        GPT_ATTRIBUTES(GPT_ATTRIBUTE_LEGACY_BIOS_BOOTABLE)
                }
                10 => entries[1].Anonymous.Gpt.PartitionType = MICROSOFT_BASIC_DATA,
                11 => entries[1].Anonymous.Gpt.PartitionId = windows::core::GUID::from_u128(1),
                _ => unreachable!(),
            }
            assert!(
                mac_layout_identity(id, &entries, capacity).is_none(),
                "case {case}"
            );
        }
    }
}

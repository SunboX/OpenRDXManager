// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Builds the exact generated partition identity without any device access.
fn fixture(gpt: bool) -> CreatedLayout {
    CreatedLayout {
        stamp: if gpt {
            layout::DiskLayoutStamp::Gpt(windows::core::GUID::from_u128(77))
        } else {
            layout::DiskLayoutStamp::Mbr(77)
        },
        partition: PARTITION_INFORMATION_EX {
            PartitionStyle: if gpt {
                PARTITION_STYLE_GPT
            } else {
                PARTITION_STYLE_MBR
            },
            StartingOffset: 1_048_576,
            PartitionLength: 320_000_000_000,
            PartitionNumber: 1,
            Anonymous: if gpt {
                PARTITION_INFORMATION_EX_0 {
                    Gpt: PARTITION_INFORMATION_GPT {
                        PartitionType: MICROSOFT_BASIC_DATA,
                        PartitionId: windows::core::GUID::from_u128(88),
                        ..Default::default()
                    },
                }
            } else {
                PARTITION_INFORMATION_EX_0 {
                    Mbr: PARTITION_INFORMATION_MBR {
                        PartitionType: PARTITION_IFS as u8,
                        HiddenSectors: 2048,
                        ..Default::default()
                    },
                }
            },
            ..Default::default()
        },
        medium: vec![1],
        capacity: 320_002_097_152,
    }
}

/// MBR and GPT continue only onto their exact generated data partition.
#[test]
fn created_layout_requires_the_generated_partition_identity() {
    for gpt in [true, false] {
        let proof = fixture(gpt);
        assert!(proof.matches(proof.stamp, &[proof.partition]));
        for case in 0..9 {
            let mut entry = proof.partition;
            let mut stamp = proof.stamp;
            match case {
                0 => stamp = layout::DiskLayoutStamp::Raw,
                1 => entry.StartingOffset += 512,
                2 => entry.PartitionLength -= 512,
                3 => entry.PartitionNumber = 2,
                4 => entry.IsServicePartition = true,
                5 => entry.PartitionStyle = PARTITION_STYLE_RAW,
                6 if gpt => entry.Anonymous.Gpt.PartitionId = windows::core::GUID::from_u128(99),
                6 => entry.Anonymous.Mbr.HiddenSectors = 2049,
                7 if gpt => entry.Anonymous.Gpt.Attributes = GPT_ATTRIBUTE_PLATFORM_REQUIRED,
                7 => entry.Anonymous.Mbr.BootIndicator = true,
                8 if gpt => entry.Anonymous.Gpt.PartitionType = windows::core::GUID::zeroed(),
                8 => entry.Anonymous.Mbr.PartitionType = 0,
                _ => unreachable!(),
            }
            assert!(!proof.matches(stamp, &[entry]), "gpt={gpt} case={case}");
        }
        assert!(!proof.matches(proof.stamp, &[]));
        assert!(!proof.matches(proof.stamp, &[proof.partition, proof.partition]));
    }
}

/// An old EFI volume or a multi-disk extent cannot consume the new layout proof.
#[test]
fn created_layout_rejects_stale_or_foreign_volume_extents() {
    let proof = fixture(true);
    let mut topology = crate::VolumeTopology {
        storage: crate::StorageDeviceIdentity {
            device_type: 7,
            device_number: 1,
            partition_number: 1,
        },
        extents: vec![crate::VolumeExtent {
            disk_number: 1,
            starting_offset: proof.partition.StartingOffset,
            extent_length: proof.partition.PartitionLength,
        }],
    };
    assert!(proof.matches_volume(&topology, 1));
    topology.extents[0].extent_length = 209_715_200;
    assert!(!proof.matches_volume(&topology, 1));
    topology.extents[0].extent_length = proof.partition.PartitionLength;
    topology.storage.partition_number = 2;
    assert!(!proof.matches_volume(&topology, 1));
    topology.storage.partition_number = 1;
    assert!(!proof.matches_volume(&topology, 0));
    topology.extents.push(topology.extents[0]);
    assert!(!proof.matches_volume(&topology, 1));
}

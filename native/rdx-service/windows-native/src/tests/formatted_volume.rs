// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Confirmed format may change mounts, never the exact physical volume identity.

use super::{NativeError, StorageDeviceIdentity, VolumeExtent, VolumeRecord, VolumeTopology};

/// Provides one synthetic basic-data volume whose original RAW mount is absent.
fn topology() -> VolumeTopology {
    VolumeTopology {
        storage: StorageDeviceIdentity {
            device_type: 7,
            device_number: 2,
            partition_number: 1,
        },
        extents: vec![VolumeExtent {
            disk_number: 2,
            starting_offset: 1_048_576,
            extent_length: 3_000_000_000_000,
        }],
    }
}

/// Builds bounded opaque synthetic identity evidence without host paths.
fn record(key: u16, topology: VolumeTopology, letters: Vec<char>, target: bool) -> VolumeRecord {
    VolumeRecord::new(vec![key, 0], topology, letters, target).unwrap()
}

/// VDS's newly assigned drive letter is expected only after confirmed format.
#[test]
fn confirmed_format_accepts_mount_arrival_on_the_same_exact_volume() {
    let old = record(1, topology(), vec![], true);
    let new = record(1, topology(), vec!['F'], true);
    assert_eq!(old.revalidate_after_format(&new), Ok(()));
    // General-purpose pre-write validation keeps its original strict rule.
    assert_eq!(
        old.revalidate(&topology(), &[vec!['F' as u16, ':' as u16, '\\' as u16]]),
        Err(NativeError::DeviceRemoved)
    );
}

/// Reassignment or removal of a mount does not alter physical post-format proof.
#[test]
fn post_format_identity_accepts_mount_reassignment_and_departure() {
    let old = record(1, topology(), vec!['F'], true);
    for letters in [vec![], vec!['G']] {
        assert_eq!(
            old.revalidate_after_format(&record(1, topology(), letters, true)),
            Ok(())
        );
    }
}

/// A different GUID cannot be adopted even on the same disk and extent.
#[test]
fn post_format_identity_rejects_guid_replacement() {
    let old = record(1, topology(), vec![], true);
    assert_eq!(
        old.revalidate_after_format(&record(2, topology(), vec!['F'], true)),
        Err(NativeError::DeviceRemoved)
    );
}

/// Every storage identity field remains bound across filesystem remount.
#[test]
fn post_format_identity_rejects_storage_identity_changes() {
    let old = record(1, topology(), vec![], true);
    let mut changed_type = topology();
    changed_type.storage.device_type = 2;
    let mut changed_disk = topology();
    changed_disk.storage.device_number = 3;
    let mut changed_partition = topology();
    changed_partition.storage.partition_number = 2;
    for changed in [changed_type, changed_disk, changed_partition] {
        assert_eq!(
            old.revalidate_after_format(&record(1, changed, vec!['F'], true)),
            Err(NativeError::DeviceRemoved)
        );
    }
}

/// A shifted, resized, spanned or retargeted extent never becomes safe remount.
#[test]
fn post_format_identity_rejects_extent_changes() {
    let old = record(1, topology(), vec![], true);
    let mut shifted = topology();
    shifted.extents[0].starting_offset += 512;
    let mut resized = topology();
    resized.extents[0].extent_length -= 512;
    let mut retargeted = topology();
    retargeted.extents[0].disk_number = 3;
    let mut spanned = topology();
    spanned.extents.push(spanned.extents[0]);
    for changed in [shifted, resized, retargeted, spanned] {
        assert_eq!(
            old.revalidate_after_format(&record(1, changed, vec!['F'], true)),
            Err(NativeError::DeviceRemoved)
        );
    }
}

/// Only previously and freshly qualified target volumes can authorize readback.
#[test]
fn unrelated_volume_cannot_authorize_post_format_readback() {
    for (old_target, new_target) in [(false, true), (true, false), (false, false)] {
        let old = record(1, topology(), vec![], old_target);
        let new = record(1, topology(), vec!['F'], new_target);
        assert_eq!(
            old.revalidate_after_format(&new),
            Err(NativeError::DeviceRemoved)
        );
    }
}

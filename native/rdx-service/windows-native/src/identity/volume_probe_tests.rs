// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host-free regression coverage for optical volumes beside a mounted RDX disk.

use super::{
    FILE_DEVICE_CD_ROM, FILE_DEVICE_DISK, NativeError, StorageDeviceIdentity, VolumeExtent,
    VolumeMembership, VolumeTopology, classify_volume_probe, query_volume_topology,
};
use crate::{VolumeInventory, VolumeRecord};

/// Builds an exact kernel-style identity without any hardware or device path.
fn storage(device_type: u32, device_number: u32) -> StorageDeviceIdentity {
    StorageDeviceIdentity {
        device_type,
        device_number,
        partition_number: 1,
    }
}

/// Builds one positive simple-disk extent for a controlled disk number.
fn extent(disk_number: u32) -> VolumeExtent {
    VolumeExtent {
        disk_number,
        starting_offset: 1_048_576,
        extent_length: 320_067_338_240,
    }
}

/// An empty virtual DVD never receives disk IOCTLs or aliases a same-numbered disk.
#[test]
fn optical_volume_bypasses_disk_query_only_after_positive_type_proof() {
    let topology = query_volume_topology(Ok(storage(FILE_DEVICE_CD_ROM, 0)), || {
        panic!("disk-only query must not be sent to an optical volume")
    })
    .unwrap();
    assert!(topology.extents.is_empty());
    assert_eq!(
        classify_volume_probe(Ok(topology), 0),
        Ok(VolumeMembership::Unrelated)
    );
}

/// A real RDX disk still requires its exact successfully queried extent.
#[test]
fn disk_volumes_still_require_complete_matching_extents() {
    let topology =
        query_volume_topology(Ok(storage(FILE_DEVICE_DISK, 1)), || Ok(vec![extent(1)])).unwrap();
    assert_eq!(
        classify_volume_probe(Ok(topology.clone()), 1),
        Ok(VolumeMembership::Target(topology.clone()))
    );
    assert_eq!(
        classify_volume_probe(Ok(topology), 0),
        Ok(VolumeMembership::Unrelated)
    );
    for extents in [vec![], vec![extent(2)], vec![extent(1), extent(2)]] {
        let topology =
            query_volume_topology(Ok(storage(FILE_DEVICE_DISK, 1)), || Ok(extents)).unwrap();
        assert_eq!(
            classify_volume_probe(Ok(topology), 1),
            Err(NativeError::EnumerationFailed)
        );
    }
}

/// Query errors on actual disks cannot become a successful unrelated-volume result.
#[test]
fn disk_extent_failures_propagate_for_target_and_unrelated_disks() {
    for number in [0, 1] {
        for error in [
            NativeError::AccessDenied,
            NativeError::DeviceRemoved,
            NativeError::Other,
        ] {
            let topology =
                query_volume_topology(Ok(storage(FILE_DEVICE_DISK, number)), || Err(error));
            assert_eq!(classify_volume_probe(topology, 1), Err(error));
        }
    }
}

/// Failed identity and unsupported types cannot authorize skipping an inspection.
#[test]
fn unverified_or_unknown_storage_types_fail_closed() {
    for identity in [
        Err(NativeError::AccessDenied),
        Ok(storage(0, 0)),
        Ok(storage(0x8000, 1)),
    ] {
        let expected = identity
            .as_ref()
            .err()
            .copied()
            .unwrap_or(NativeError::EnumerationFailed);
        assert_eq!(
            query_volume_topology(identity, || panic!("unproven disk type")),
            Err(expected)
        );
    }
    assert_eq!(
        classify_volume_probe(
            Ok(VolumeTopology {
                storage: storage(FILE_DEVICE_CD_ROM, 1),
                extents: vec![extent(1)]
            }),
            1
        ),
        Err(NativeError::EnumerationFailed)
    );
}

/// Optical identities and letters remain in the complete transaction inventory.
#[test]
fn optical_records_preserve_collision_and_change_detection() {
    let optical = query_volume_topology(Ok(storage(FILE_DEVICE_CD_ROM, 0)), || {
        panic!("optical extent query")
    })
    .unwrap();
    let disk =
        query_volume_topology(Ok(storage(FILE_DEVICE_DISK, 1)), || Ok(vec![extent(1)])).unwrap();
    let disk_record = VolumeRecord::new(vec![2], disk, vec!['E'], true).unwrap();
    let optical_record = VolumeRecord::new(vec![1], optical.clone(), vec!['D'], false).unwrap();
    let inventory =
        VolumeInventory::new(vec![disk_record.clone(), optical_record.clone()]).unwrap();
    assert_eq!(
        inventory,
        VolumeInventory::new(vec![optical_record, disk_record.clone()]).unwrap()
    );
    let collision = VolumeRecord::new(vec![1], optical.clone(), vec!['E'], false).unwrap();
    assert_eq!(
        VolumeInventory::new(vec![disk_record.clone(), collision]),
        Err(NativeError::EnumerationFailed)
    );
    let remounted = VolumeRecord::new(vec![1], optical, vec!['F'], false).unwrap();
    assert_ne!(
        inventory,
        VolumeInventory::new(vec![disk_record, remounted]).unwrap()
    );
}

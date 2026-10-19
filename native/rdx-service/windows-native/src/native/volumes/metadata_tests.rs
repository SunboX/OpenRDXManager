// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metadata authority must fail before touching any native mutation boundary.
use super::*;
use crate::StorageDeviceIdentity;

/// Uses an invalid synthetic handle and key so no real disk or mount can be touched.
fn metadata_lease() -> NativeVolumeLease {
    NativeVolumeLease {
        handle: KernelHandle::new(0),
        record: VolumeRecord::new(
            vec![1, 0],
            VolumeTopology {
                storage: StorageDeviceIdentity {
                    device_type: 7,
                    device_number: 2,
                    partition_number: 1,
                },
                extents: vec![VolumeExtent {
                    disk_number: 2,
                    starting_offset: 1_048_576,
                    extent_length: 8_388_608,
                }],
            },
            vec!['X'],
            true,
        )
        .unwrap(),
        access: VolumeAccess::Metadata,
    }
}

/// Exercises production mutators and distinguishes admission denial from native errors.
#[test]
fn metadata_leases_refuse_every_host_mutation_before_native_dispatch() {
    let lease = metadata_lease();
    assert_eq!(lease.lock(), Err(NativeError::AccessDenied));
    assert_eq!(lease.dismount(), Err(NativeError::AccessDenied));
    assert_eq!(
        lease.format(HostFilesystem::Ntfs),
        Err(NativeError::AccessDenied)
    );
    assert_eq!(
        lease.set_drive_letter('Y'),
        HostOperationOutcome::NotAttempted(NativeError::AccessDenied)
    );
    assert_eq!(
        lease.reset_drive_letter('X'),
        Err(NativeError::AccessDenied)
    );
    let (operation, certainty, cleanup) = lease
        .write_read_file(
            ".openrdx-write-read-00000000000000000000000000000000.tmp",
            &[1],
        )
        .into_parts();
    assert_eq!(operation, Err(NativeError::AccessDenied));
    assert_eq!(
        certainty,
        HostOperationOutcome::NotAttempted(NativeError::AccessDenied)
    );
    assert_eq!(
        cleanup,
        HostOperationOutcome::NotAttempted(NativeError::AccessDenied)
    );
}

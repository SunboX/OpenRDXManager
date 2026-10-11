#![cfg(windows)]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::ffi::OsStr;

use rdx_windows_native::{NativeError, WindowsDevice, enumerate_disk_candidates, probe_readiness};

/// Native readiness fields remain truthful without requiring an RDX device.
#[test]
fn native_readiness_is_internally_consistent_without_rdx() {
    let readiness = probe_readiness();

    assert!(!readiness.service_running() || readiness.service_installed());
}

/// SetupAPI enumeration returns only bounded/redacted candidates or a stable error.
#[test]
fn setupapi_enumeration_is_bounded_and_redacted_without_rdx() {
    match enumerate_disk_candidates() {
        Ok(candidates) => {
            assert!(candidates.len() <= 128);
            for candidate in candidates {
                let debug = format!("{candidate:?}");
                let (_, instance_id) = candidate.into_parts();
                assert!(!instance_id.is_empty());
                assert!(!debug.contains(&instance_id));
                assert!(debug.contains("<private>"));
            }
        }
        Err(error) => assert!(matches!(
            error,
            NativeError::AccessDenied
                | NativeError::Busy
                | NativeError::DeviceRemoved
                | NativeError::EnumerationFailed
                | NativeError::ResourceLimit
                | NativeError::Other
        )),
    }
}

/// Caller-authored physical-drive paths fail before any native device call.
#[test]
fn caller_physical_drive_path_is_not_an_open_authority() {
    assert!(matches!(
        WindowsDevice::open(OsStr::new(r"\\.\PhysicalDrive0")),
        Err(NativeError::InvalidRequest)
    ));
}

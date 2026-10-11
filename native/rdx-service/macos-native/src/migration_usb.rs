// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only registry observation of the exact post-migration USB application.

use crate::NativeError;

/// Observes the selected OpenRDX USB parent without opening a device or transport.
///
/// Returns its registry entry ID as an enumeration epoch only for the unique
/// `1A5A:0005` application at the selected location with the exact twelve-digit
/// serial. Unrelated docks on other ports are allowed. A normal PID0005/0006 RDX
/// parent with the saved serial on another port always rejects, including while
/// the selected port is absent or in ROM. This permits a read-only collision
/// check immediately before an explicitly selected ROM setup.
/// No parent, or the TI `0451:926B` ROM loader at that location, returns `None`
/// only when that collision check passes. Callers must observe a subsequent
/// disappearance/epoch change before treating an operator power cycle as complete.
/// The epoch is not device proof
/// or a verified firmware version and should stay out of ordinary diagnostics.
///
/// # Errors
/// Rejects malformed inputs, foreign/mismatched identity, ambiguous parents or
/// incomplete registry evidence. This never claims, resets, or sends USB/SCSI IO.
pub fn observe_migration_usb(location_id: u32, serial: &str) -> Result<Option<u64>, NativeError> {
    if location_id == 0 || serial.len() != 12 || !serial.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NativeError::InvalidRequest);
    }
    #[cfg(target_os = "macos")]
    {
        let mut epoch = 0;
        // SAFETY: the exact twelve input bytes and distinct output remain alive
        // for a synchronous registry-property read; no raw device owner escapes.
        let status = unsafe {
            rdx_macos_observe_migration_usb(
                location_id,
                serial.as_ptr(),
                serial.len() as u32,
                &mut epoch,
            )
        };
        crate::status_result(status)?;
        Ok((epoch != 0).then_some(epoch))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn rdx_macos_observe_migration_usb(
        location_id: u32,
        serial: *const u8,
        length: u32,
        epoch: *mut u64,
    ) -> u32;
    #[cfg(all(test, feature = "test-hooks"))]
    fn rdx_macos_test_migration_usb_observation_contract() -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Malformed selection cannot reach the native observer at all.
    #[test]
    fn migration_usb_rejects_invalid_selection_before_io() {
        for (location, serial) in [
            (0, "001234567890"),
            (1, ""),
            (1, "01234567890"),
            (1, "0012345678900"),
            (1, "00123456789a"),
            (1, "00123456789\n"),
        ] {
            assert_eq!(
                observe_migration_usb(location, serial),
                Err(NativeError::InvalidRequest)
            );
        }
    }

    /// Literal native snapshots exercise absence, ROM, epochs and hostile identities.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn migration_usb_observation_is_exact_and_read_only() {
        // SAFETY: the hook passes only local facts to the production selector.
        assert!(unsafe { rdx_macos_test_migration_usb_observation_contract() });
    }
}

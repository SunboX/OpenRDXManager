// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact serial-specific Windows drive-letter preference operations.

use crate::model::DriveLetter;

use super::volume::{HostOperationFailure, HostOperations};

/// Sets one collision-free preference for the exact selected dock serial.
///
/// # Errors
///
/// Rejects stale bindings, unsupported platforms, collisions,
/// or any native preference-write failure.
pub fn set_drive_letter(
    host: &mut impl HostOperations,
    letter: DriveLetter,
) -> Result<(), HostOperationFailure> {
    let binding = host.binding();
    let facts = host
        .revalidate(&binding)
        .map_err(|failure| HostOperationFailure::from_primitive("preflight", failure))?;
    if facts.media_present {
        return Err(HostOperationFailure::preflight(
            "preflight",
            super::volume::HostPrimitiveError::MediaPresent,
        ));
    }
    host.set_drive_letter_exact(&binding, letter.get())
        .map_err(|failure| HostOperationFailure::from_primitive("drive-letter", failure))
}

/// Removes only this application's current exact-serial preference.
///
/// # Errors
///
/// Rejects stale bindings, foreign/currently changed mappings,
/// unsupported platforms, or native removal failure.
pub fn reset_drive_letter(host: &mut impl HostOperations) -> Result<(), HostOperationFailure> {
    let binding = host.binding();
    let facts = host
        .revalidate(&binding)
        .map_err(|failure| HostOperationFailure::from_primitive("preflight", failure))?;
    if facts.media_present {
        return Err(HostOperationFailure::preflight(
            "preflight",
            super::volume::HostPrimitiveError::MediaPresent,
        ));
    }
    host.reset_drive_letter_exact(&binding)
        .map_err(|failure| HostOperationFailure::from_primitive("drive-letter", failure))
}

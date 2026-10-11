// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable policy for an authoritative Windows media-arrival letter change.

#[cfg(any(windows, test))]
use crate::HostOperationOutcome;
use crate::NativeError;

const FIRST_ASSIGNABLE_LETTER: char = 'D';
const LAST_ASSIGNABLE_LETTER: char = 'Z';
const MAX_APP_PREFERENCES: usize = 256;

/// Closed action selected from one exact target volume and the host letter namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArrivalDriveLetterPlan {
    /// No target volume exists yet; retain the preference for a later arrival scan.
    WaitForVolume,
    /// The exact selected volume already owns only the preferred letter.
    AlreadyApplied,
    /// The exact selected volume owns one old automatic letter that may be replaced.
    ReplaceSelectedLetter(char),
    /// The preferred letter belongs to another volume or app preference.
    TargetCollision,
}

/// Selects one fail-closed arrival action from authoritative bounded facts.
///
/// # Errors
///
/// Returns [`NativeError::EvidenceIncomplete`] for multiple target volumes,
/// non-drive-root mount paths, or multiple letters on the selected volume.
pub fn plan_arrival_drive_letter(
    target_volume_count: usize,
    target_mount_path_count: usize,
    selected_letters: &[char],
    preferred: char,
    target_reserved_elsewhere: bool,
) -> Result<ArrivalDriveLetterPlan, NativeError> {
    if !preferred.is_ascii_uppercase() || preferred < 'D' {
        return Err(NativeError::InvalidRequest);
    }
    if target_volume_count == 0 {
        return if target_mount_path_count == 0 && selected_letters.is_empty() {
            Ok(ArrivalDriveLetterPlan::WaitForVolume)
        } else {
            Err(NativeError::EvidenceIncomplete)
        };
    }
    if target_volume_count != 1
        || target_mount_path_count != selected_letters.len()
        || selected_letters.len() > 1
        || selected_letters
            .iter()
            .any(|letter| !letter.is_ascii_uppercase())
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    if target_reserved_elsewhere {
        return Ok(ArrivalDriveLetterPlan::TargetCollision);
    }
    match selected_letters {
        [] => Ok(ArrivalDriveLetterPlan::ReplaceSelectedLetter('\0')),
        [current] if *current == preferred => Ok(ArrivalDriveLetterPlan::AlreadyApplied),
        [current] => Ok(ArrivalDriveLetterPlan::ReplaceSelectedLetter(*current)),
        _ => Err(NativeError::EvidenceIncomplete),
    }
}

/// Derives the renderer-safe Windows letter list from authoritative host facts.
///
/// `occupied_mask` is the exact bitmap returned by `GetLogicalDrives` and
/// `reserved_letters` contains only preferences read under the fixed
/// application-owned registry root. System letters A-C are never returned.
///
/// # Errors
///
/// Returns [`NativeError::InvalidRequest`] for a malformed reservation and
/// [`NativeError::ResourceLimit`] when the fixed registry enumeration bound is
/// exceeded.
pub fn available_drive_letters_from_state(
    occupied_mask: u32,
    reserved_letters: &[char],
) -> Result<Vec<char>, NativeError> {
    if reserved_letters.len() > MAX_APP_PREFERENCES {
        return Err(NativeError::ResourceLimit);
    }
    if reserved_letters.iter().any(|letter| {
        !letter.is_ascii_uppercase()
            || *letter < FIRST_ASSIGNABLE_LETTER
            || *letter > LAST_ASSIGNABLE_LETTER
    }) {
        return Err(NativeError::InvalidRequest);
    }

    Ok((FIRST_ASSIGNABLE_LETTER..=LAST_ASSIGNABLE_LETTER)
        .filter(|letter| {
            let bit = 1_u32 << (*letter as u32 - 'A' as u32);
            occupied_mask & bit == 0 && !reserved_letters.contains(letter)
        })
        .collect())
}

/// Preserves mutation ambiguity when post-mount preference binding fails before its own write.
#[cfg(any(windows, test))]
pub(crate) const fn arrival_binding_outcome(
    plan: ArrivalDriveLetterPlan,
    outcome: HostOperationOutcome,
) -> HostOperationOutcome {
    match (plan, outcome) {
        (
            ArrivalDriveLetterPlan::ReplaceSelectedLetter(_),
            HostOperationOutcome::NotAttempted(error),
        ) => HostOperationOutcome::CompletionUnknown(error),
        (_, outcome) => outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mount mutation cannot be downgraded by a later pre-write registry failure.
    #[test]
    fn post_mount_binding_failure_remains_completion_unknown() {
        assert_eq!(
            arrival_binding_outcome(
                ArrivalDriveLetterPlan::ReplaceSelectedLetter('E'),
                HostOperationOutcome::NotAttempted(NativeError::AccessDenied),
            ),
            HostOperationOutcome::CompletionUnknown(NativeError::AccessDenied)
        );
        assert_eq!(
            arrival_binding_outcome(
                ArrivalDriveLetterPlan::AlreadyApplied,
                HostOperationOutcome::NotAttempted(NativeError::AccessDenied),
            ),
            HostOperationOutcome::NotAttempted(NativeError::AccessDenied)
        );
    }
}

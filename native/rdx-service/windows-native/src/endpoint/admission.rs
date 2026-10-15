// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Post-identification admission order; no caller token may reach hardware work.

use crate::NativeError;

/// Completes client identification before evaluating independent daemon authority.
/// Reversion runs even when identification fails; either failure denies admission.
pub(super) fn finish_authentication(
    identified: Result<(), NativeError>,
    revert: impl FnOnce() -> Result<(), NativeError>,
    running_authority: impl FnOnce() -> Result<(), NativeError>,
) -> Result<(), NativeError> {
    revert()?;
    identified?;
    running_authority()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A failed reversion must never return an admitted connection or query as the client.
    #[test]
    fn failed_revert_denies_admission_before_running_authority() {
        let evaluated = Cell::new(false);
        let result = finish_authentication(
            Ok(()),
            || Err(NativeError::AccessDenied),
            || {
                evaluated.set(true);
                Ok(())
            },
        );
        assert_eq!(result, Err(NativeError::AccessDenied));
        assert!(!evaluated.get());
    }

    /// A failed peer identity must still revert and must never query or admit work.
    #[test]
    fn rejected_identity_reverts_without_evaluating_running_authority() {
        let reverted = Cell::new(false);
        let result = finish_authentication(
            Err(NativeError::AccessDenied),
            || {
                reverted.set(true);
                Ok(())
            },
            || panic!("unidentified peer cannot reach authority or hardware"),
        );
        assert_eq!(result, Err(NativeError::AccessDenied));
        assert!(reverted.get());
    }

    /// Independent running evidence remains required after a correct peer and reversion.
    #[test]
    fn missing_running_proof_denies_an_identified_client() {
        let reverted = Cell::new(false);
        let result = finish_authentication(
            Ok(()),
            || {
                reverted.set(true);
                Ok(())
            },
            || {
                assert!(reverted.get());
                Err(NativeError::AccessDenied)
            },
        );
        assert_eq!(result, Err(NativeError::AccessDenied));
    }

    /// Only successful identification, checked reversion and running proof return admission.
    #[test]
    fn admitted_client_is_verified_only_after_reversion() {
        let reverted = Cell::new(false);
        let result = finish_authentication(
            Ok(()),
            || {
                reverted.set(true);
                Ok(())
            },
            || {
                assert!(reverted.get());
                Ok(())
            },
        );
        assert_eq!(result, Ok(()));
    }
}

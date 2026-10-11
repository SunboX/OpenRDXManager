// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pending and terminal results of the nonblocking VDS status API.

/// Recognizes pending on either documented HRESULT channel before completion.
///
/// A failing QueryStatus leaves its output unavailable; never use that output
/// to claim success. All non-pending query errors remain failures.
pub(super) fn query_is_pending(
    query_result: Result<(), u32>,
    operation_result: u32,
) -> Result<bool, u32> {
    const PENDING: u32 = 0x8004_2409;
    match query_result {
        Err(PENDING) => Ok(true),
        Err(error) => Err(error),
        Ok(()) => Ok(operation_result == PENDING),
    }
}

#[cfg(test)]
mod tests {
    use super::query_is_pending;

    /// A pending method HRESULT must not abort the still-running format.
    #[test]
    fn method_pending_ignores_unavailable_output() {
        for output in [0, 0x8004_2409, 0x8000_4005] {
            assert_eq!(query_is_pending(Err(0x8004_2409), output), Ok(true));
        }
    }

    /// Both documented forms keep polling until the operation has finished.
    #[test]
    fn both_pending_forms_precede_terminal_completion() {
        let sequence = [(Err(0x8004_2409), 0), (Ok(()), 0x8004_2409), (Ok(()), 0)];
        let decisions: Vec<_> = sequence
            .into_iter()
            .map(|(query, operation)| query_is_pending(query, operation))
            .collect();
        assert_eq!(decisions, [Ok(true), Ok(true), Ok(false)]);
    }

    /// Genuine query failures cannot be hidden by a success or pending output.
    #[test]
    fn query_errors_preserve_failure() {
        for error in [0x8007_0005, 0x8000_4005, 0x8007_0057] {
            for output in [0, 0x8004_2409] {
                assert_eq!(query_is_pending(Err(error), output), Err(error));
            }
        }
    }

    /// Terminal operation failure stops polling for the caller to propagate it.
    #[test]
    fn terminal_operation_error_is_not_pending() {
        assert_eq!(query_is_pending(Ok(()), 0x8004_242b), Ok(false));
    }
}

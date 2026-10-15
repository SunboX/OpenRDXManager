// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recovery retains supplied connection authority or mints direct authority before any attempt.

use super::{RecoveryError, ServiceExecutionContext};

/// Selected by fixed recovery entrypoints only, never by a caller mode or request field.
pub(super) enum ContextAuthority {
    Direct,
    Service(ServiceExecutionContext),
}

/// Obtains complete direct authority after the caller acquired the existing native ownership lease.
pub(super) fn mint_direct_context() -> Result<ServiceExecutionContext, RecoveryError> {
    let factory = rdx_macos_native::MacDirectWorkerFactory::for_current_privileged_process()
        .map_err(|_| RecoveryError::PrivilegeRequired)?;
    Ok(ServiceExecutionContext::privileged_direct_cli(true)
        .with_macos_direct_worker_factory(factory))
}

/// Resolves authority before entering any mutable recovery or readback continuation.
pub(super) fn with_recovery_context<R>(
    authority: ContextAuthority,
    mint: impl FnOnce() -> Result<ServiceExecutionContext, RecoveryError>,
    attempt: impl FnOnce(ServiceExecutionContext) -> Result<R, RecoveryError>,
) -> Result<R, RecoveryError> {
    let context = match authority {
        ContextAuthority::Direct => mint()?,
        ContextAuthority::Service(context) => context,
    };
    attempt(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// An actual ordinary native mint refusal must stop before entering even a synthetic attempt.
    #[test]
    fn direct_recovery_native_mint_refusal_precedes_every_attempt() {
        assert!(!rdx_macos_native::current_process_is_privileged_service());
        let mut entered = 0;
        let result = with_recovery_context(ContextAuthority::Direct, mint_direct_context, |_| {
            entered += 1;
            Ok(())
        });
        assert_eq!(result, Err(RecoveryError::PrivilegeRequired));
        assert_eq!(
            entered, 0,
            "no mutable continuation after missing native capability"
        );
    }

    /// Private non-authorizing contexts exercise the consumed selector; they cannot mint a worker.
    #[test]
    fn direct_recovery_selects_mint_once_before_attempt_and_preserves_context() {
        let calls = RefCell::new(Vec::new());
        let context = ServiceExecutionContext::privileged_direct_cli(true).with_backup_owner(502);
        with_recovery_context(
            ContextAuthority::Direct,
            || {
                calls.borrow_mut().push("native-mint");
                Ok(context.duplicate_for_runtime())
            },
            |selected| {
                calls.borrow_mut().push("attempt");
                assert_eq!(selected, context);
                assert!(
                    selected.macos_direct_worker_factory().is_none(),
                    "fixture is non-authorizing"
                );
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.into_inner(), ["native-mint", "attempt"]);
    }

    /// Accepted service recovery keeps the original context and never attempts native direct minting.
    #[test]
    fn service_recovery_preserves_supplied_context_without_direct_remint() {
        let context =
            ServiceExecutionContext::authenticated_platform_endpoint(true).with_backup_owner(502);
        let expected = context.duplicate_for_runtime();
        with_recovery_context(
            ContextAuthority::Service(context),
            || panic!("no direct service fallback"),
            |selected| {
                assert_eq!(selected, expected);
                assert!(selected.endpoint_authenticated());
                assert!(!selected.direct_process_authorized());
                Ok(())
            },
        )
        .unwrap();
    }
}

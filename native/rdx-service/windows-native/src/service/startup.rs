// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Startup sequencing shared by the native SCM callback and portable regressions.

use super::WindowsServiceLifecycle;
use crate::NativeError;

/// Retains the first endpoint before publishing RUNNING; a stop never admits work.
///
/// The caller supplies only native publication and endpoint creation boundaries.
/// Any failure drops the endpoint and leaves STOPPED publication to the caller.
pub(super) fn start_endpoint<L>(
    lifecycle: &WindowsServiceLifecycle,
    mut publish: impl FnMut() -> Result<(), NativeError>,
    bind: impl FnOnce() -> Result<L, NativeError>,
) -> Result<Option<L>, NativeError> {
    publish()?;
    if lifecycle.stop_requested() {
        return Ok(None);
    }
    let listener = match bind() {
        Ok(listener) => listener,
        Err(NativeError::Cancelled) if lifecycle.stop_requested() => return Ok(None),
        Err(error) => return Err(error),
    };
    if lifecycle.stop_requested() {
        return Ok(None);
    }
    lifecycle.mark_endpoint_bound()?;
    match lifecycle.mark_running() {
        Ok(()) => {}
        Err(NativeError::AccessDenied) if lifecycle.stop_requested() => return Ok(None),
        Err(error) => return Err(error),
    }
    publish()?;
    if lifecycle.stop_requested() {
        return Ok(None);
    }
    Ok(Some(listener))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceIdentityEvidence, ServiceRuntimeEvidence, WindowsServiceState};

    /// Native current-token/configuration proofs do not depend on an invalid pending PID.
    fn pending_service_evidence() -> ServiceIdentityEvidence {
        let pending = ServiceRuntimeEvidence {
            running: false,
            process_id: 0,
            own_process: true,
        };
        ServiceIdentityEvidence {
            installed: true,
            current_pid: 42,
            status_before: pending,
            status_after: pending,
            config_stable: true,
            demand_start: true,
            binary_matches: true,
            token_local_service: true,
        }
    }

    /// A running-only gate here deadlocks real SCM startup before its first pipe exists.
    #[test]
    fn registered_startup_binds_before_running_without_trusting_pending_pid() {
        let lifecycle = WindowsServiceLifecycle::new(8).unwrap();
        let mut published = Vec::new();
        let result = start_endpoint(
            &lifecycle,
            || {
                published.push(lifecycle.snapshot().state());
                Ok(())
            },
            || {
                assert_eq!(
                    lifecycle.snapshot().state(),
                    WindowsServiceState::StartPending
                );
                if !pending_service_evidence().startup_authorized() {
                    return Err(NativeError::AccessDenied);
                }
                Ok(23)
            },
        );
        assert_eq!(result, Ok(Some(23)));
        assert_eq!(
            published,
            [
                WindowsServiceState::StartPending,
                WindowsServiceState::Running
            ]
        );
        assert!(lifecycle.begin_connection().is_ok());
    }

    /// A native bind cancelled by STOP retires cleanly without RUNNING or admission.
    #[test]
    fn stop_during_authority_proof_retires_without_running() {
        let lifecycle = WindowsServiceLifecycle::new(8).unwrap();
        let mut published = Vec::new();
        let result = start_endpoint::<u8>(
            &lifecycle,
            || {
                published.push(lifecycle.snapshot().state());
                Ok(())
            },
            || {
                lifecycle.request_stop();
                Err(NativeError::Cancelled)
            },
        );
        assert_eq!(result, Ok(None));
        assert_eq!(published, [WindowsServiceState::StartPending]);
        assert_eq!(
            lifecycle.begin_connection().unwrap_err(),
            NativeError::AccessDenied
        );
    }

    /// Missing native authority facts cannot be turned into RUNNING or hardware admission.
    #[test]
    fn incomplete_startup_proof_never_opens_connection_admission() {
        let base = pending_service_evidence();
        let mut rejected = [base; 6];
        rejected[0].installed = false;
        rejected[1].current_pid = 0;
        rejected[2].config_stable = false;
        rejected[3].demand_start = false;
        rejected[4].binary_matches = false;
        // Native collection sets this only for both primary LocalService user
        // and the exact enabled, non-deny-only OpenRDX service SID.
        rejected[5].token_local_service = false;
        for facts in rejected {
            let lifecycle = WindowsServiceLifecycle::new(8).unwrap();
            let mut published = Vec::new();
            let result = start_endpoint::<u8>(
                &lifecycle,
                || {
                    published.push(lifecycle.snapshot().state());
                    Ok(())
                },
                || {
                    if facts.startup_authorized() {
                        Ok(23)
                    } else {
                        Err(NativeError::AccessDenied)
                    }
                },
            );
            assert_eq!(result, Err(NativeError::AccessDenied));
            assert_eq!(published, [WindowsServiceState::StartPending]);
            assert!(lifecycle.begin_connection().is_err());
        }
    }

    /// A startup proof never changes ordinary running-only process authorization.
    #[test]
    fn startup_proof_cannot_authorize_general_readiness() {
        let service = pending_service_evidence();
        assert!(service.startup_authorized());
        let readiness = crate::Readiness::from_authority(
            true,
            crate::AuthorityEvidence {
                service,
                process_elevated: false,
                exact_device_access: false,
            },
        );
        assert!(!readiness.service_running());
        assert!(!readiness.current_process_authorized());
    }

    /// Failed trust verification or a competing namespace owner leaves startup closed.
    #[test]
    fn failed_native_bind_preserves_pending_state_without_admission() {
        for error in [NativeError::AccessDenied, NativeError::Other] {
            let lifecycle = WindowsServiceLifecycle::new(8).unwrap();
            let result = start_endpoint::<u8>(&lifecycle, || Ok(()), || Err(error));
            assert_eq!(result, Err(error));
            assert_eq!(
                lifecycle.snapshot().state(),
                WindowsServiceState::StartPending
            );
            assert!(lifecycle.begin_connection().is_err());
        }
    }

    /// A failed SCM status publication cannot create an endpoint.
    #[test]
    fn failed_start_pending_publication_never_calls_native_bind() {
        let lifecycle = WindowsServiceLifecycle::new(8).unwrap();
        let result = start_endpoint::<u8>(
            &lifecycle,
            || Err(NativeError::Other),
            || panic!("no SCM publication, no startup capability"),
        );
        assert_eq!(result, Err(NativeError::Other));
        assert!(lifecycle.begin_connection().is_err());
    }

    /// The first endpoint and its trust resources are released on stop or publication failure.
    #[test]
    fn retained_endpoint_drops_when_startup_cannot_finish() {
        use std::cell::Cell;
        struct Endpoint<'a>(&'a Cell<u32>);
        impl Drop for Endpoint<'_> {
            /// Observes ownership release of a successfully created native boundary.
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        for stop_after_bind in [false, true] {
            let dropped = Cell::new(0);
            let lifecycle = WindowsServiceLifecycle::new(8).unwrap();
            let mut publication_count = 0;
            let result = start_endpoint(
                &lifecycle,
                || {
                    publication_count += 1;
                    if publication_count == 2 {
                        Err(NativeError::Other)
                    } else {
                        Ok(())
                    }
                },
                || {
                    if stop_after_bind {
                        lifecycle.request_stop();
                    }
                    Ok(Endpoint(&dropped))
                },
            );
            assert!(result.is_err() || matches!(result, Ok(None)));
            assert_eq!(dropped.get(), 1);
        }
    }
}

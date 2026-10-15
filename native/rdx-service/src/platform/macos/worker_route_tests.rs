// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::sync::{Arc, Mutex};

/// Test-only state cannot mint the production native capability or invoke native IO.
#[derive(Clone)]
struct Factory {
    state: Arc<Mutex<State>>,
    pinned: (u32, u32),
}
struct State {
    active: bool,
    observed: (u32, u32),
    identities: Vec<u64>,
}

impl WorkerFactory for Factory {
    type Identity = u64;
    type Worker = u64;
    /// Models fresh per-spawn refusal; actual native proof is covered separately, not fabricated here.
    fn spawn(&self, identity: &u64) -> Result<u64, NativeError> {
        let mut state = self.state.lock().unwrap();
        if !state.active || state.observed != self.pinned {
            state.active = false;
            return Err(NativeError::AccessDenied);
        }
        state.identities.push(*identity);
        Ok(*identity)
    }
}

/// Produces one closed dispatch fixture with independent connection/session and runtime generation.
fn fixture() -> Factory {
    Factory {
        state: Arc::new(Mutex::new(State {
            active: true,
            observed: (7, 9),
            identities: Vec::new(),
        })),
        pinned: (7, 9),
    }
}

/// Initial, handle, migration/reacquire and recovery clones must all dispatch the same retained factory.
#[test]
fn retained_worker_route_initial_rematch_and_recovery_use_one_factory() {
    let factory = fixture();
    let backend = WorkerRoute::select(true, false, Some(factory.clone()), None);
    let handle = backend.clone();
    let recovery = backend.clone();
    for (route, identity) in [
        (&backend, 10),
        (&handle, 10),
        (&handle, 10),
        (&recovery, 10),
    ] {
        assert_eq!(route.dispatch(&identity), Ok(10));
    }
    assert_eq!(factory.state.lock().unwrap().identities, [10, 10, 10, 10]);
}

/// A revoked connection or changed peer-session/runtime generation cannot revive cached recipes.
#[test]
fn retained_worker_route_refusal_never_falls_back_to_direct_capture() {
    for changed in [None, Some((8, 9)), Some((7, 10))] {
        let factory = fixture();
        let route = WorkerRoute::select(true, false, Some(factory.clone()), None);
        assert_eq!(route.dispatch(&42), Ok(42));
        {
            let mut state = factory.state.lock().unwrap();
            if let Some(observed) = changed {
                state.observed = observed;
            } else {
                state.active = false;
            }
        }
        let retained = route.clone();
        assert_eq!(retained.dispatch(&42), Err(NativeError::AccessDenied));
        factory.state.lock().unwrap().observed = factory.pinned;
        assert_eq!(route.dispatch(&42), Err(NativeError::AccessDenied));
        assert_eq!(factory.state.lock().unwrap().identities, [42]);
    }
}

/// A new connection's usable route cannot revive older clones even when synthetic UID/session match.
#[test]
fn retained_worker_route_new_connection_cannot_revive_revoked_recovery_clone() {
    let old = fixture();
    let route = WorkerRoute::select(true, false, Some(old.clone()), None);
    let recovery = route.clone();
    old.state.lock().unwrap().active = false;
    let replacement = WorkerRoute::select(true, false, Some(fixture()), None);
    assert_eq!(replacement.dispatch(&42), Ok(42));
    assert_eq!(recovery.dispatch(&42), Err(NativeError::AccessDenied));
}

/// Actual backend construction consumes trusted context; backup owner and endpoint flags grant no route.
#[cfg(target_os = "macos")]
#[test]
fn retained_worker_route_backend_context_never_uses_backup_owner_as_authority() {
    use crate::platform::macos::MacOsBackend;
    use crate::service::ServiceExecutionContext;
    for context in [
        ServiceExecutionContext::authenticated_platform_endpoint(true),
        ServiceExecutionContext::authenticated_platform_endpoint(true).with_backup_owner(502),
        ServiceExecutionContext::development_stdio(),
    ] {
        let expected_backup_owner = context.backup_owner();
        let backend = MacOsBackend::native_with_context(context);
        assert!(matches!(backend.worker_route, WorkerRoute::Denied));
        assert_eq!(backend.backup_owner, expected_backup_owner);
    }
    let backend =
        MacOsBackend::native_with_context(ServiceExecutionContext::privileged_direct_cli(true));
    assert!(matches!(backend.worker_route, WorkerRoute::Denied));
}

/// Endpoint flags/backup ownership alone never create GUI authority or select a raw fallback.
#[test]
fn retained_worker_route_requires_factory_for_endpoint_and_explicit_direct_mode() {
    for route in [
        WorkerRoute::<Factory>::select(true, true, None, Some(fixture())),
        WorkerRoute::select(true, false, None, None),
        WorkerRoute::select(false, false, None, Some(fixture())),
    ] {
        assert_eq!(route.dispatch(&1), Err(NativeError::AccessDenied));
    }
    let missing = WorkerRoute::<Factory>::select(false, true, None, None);
    assert_eq!(missing.dispatch(&1), Err(NativeError::AccessDenied));
    let direct = fixture();
    let route = WorkerRoute::<Factory>::select(false, true, None, Some(direct.clone()));
    assert_eq!(route.dispatch(&1), Ok(1));
    direct.state.lock().unwrap().active = false;
    assert_eq!(route.dispatch(&1), Err(NativeError::AccessDenied));
}

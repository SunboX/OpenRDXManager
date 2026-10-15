// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Quick connection-lifetime admission; this never performs native or device validation.

use super::ServiceExecutionContext;

/// Shared revocation only; the unique native lease remains in the endpoint entrypoint.
#[derive(Clone, Default)]
pub(super) struct SessionAdmission {
    #[cfg(target_os = "macos")]
    factory: Option<rdx_macos_native::MacWorkerFactory>,
    #[cfg(all(test, unix))]
    fixture: Option<std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>>,
}

impl SessionAdmission {
    /// Borrows native authority only from the trusted context, never request or backup fields.
    pub(super) fn from_context(context: &ServiceExecutionContext) -> Self {
        #[cfg(target_os = "macos")]
        {
            Self {
                factory: context.macos_worker_factory().cloned(),
                #[cfg(all(test, unix))]
                fixture: None,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = context;
            Self::default()
        }
    }

    /// Checks admission without querying filesystem, Security.framework, sockets or devices.
    pub(super) fn is_active(&self) -> bool {
        #[cfg(target_os = "macos")]
        if let Some(factory) = &self.factory {
            return factory.ensure_active().is_ok();
        }
        #[cfg(all(test, unix))]
        if let Some(state) = &self.fixture {
            return *state.0.lock().unwrap();
        }
        true
    }

    /// Permanently refuses new work; existing operation deadlines/cancellation/cleanup stay unchanged.
    pub(super) fn revoke(&self) {
        #[cfg(target_os = "macos")]
        if let Some(factory) = &self.factory {
            factory.revoke();
        }
        #[cfg(all(test, unix))]
        if let Some(state) = &self.fixture {
            *state.0.lock().unwrap() = false;
            state.1.notify_all();
        }
    }

    /// Declared after runtime/recovery owners, this guard drops first on every return or unwind.
    pub(super) fn disconnect_guard(&self) -> SessionRevokeGuard {
        SessionRevokeGuard {
            admission: self.clone(),
        }
    }

    /// Isolated runtime-only state cannot mint a native factory or authenticate any peer.
    #[cfg(all(test, unix))]
    pub(super) fn fixture() -> Self {
        Self {
            fixture: Some(std::sync::Arc::new((
                std::sync::Mutex::new(true),
                std::sync::Condvar::new(),
            ))),
            #[cfg(target_os = "macos")]
            factory: None,
        }
    }

    /// Waits for the actual terminal transition with a bounded condition-variable wait.
    #[cfg(all(test, unix))]
    pub(super) fn wait_revoked(&self) -> bool {
        let state = self.fixture.as_ref().unwrap();
        let (active, _) = state
            .1
            .wait_timeout_while(
                state.0.lock().unwrap(),
                std::time::Duration::from_secs(2),
                |active| *active,
            )
            .unwrap();
        !*active
    }
}

/// Inner runtime guard; it grants no permission and can only revoke.
pub(super) struct SessionRevokeGuard {
    admission: SessionAdmission,
}

impl Drop for SessionRevokeGuard {
    /// Revokes before recovery joins even after reader/writer/parse failures or panics.
    fn drop(&mut self) {
        self.admission.revoke();
    }
}

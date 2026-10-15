// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One retained worker authority shared by initial capture, rematch and recovery backends.

use rdx_macos_native::NativeError;

/// Private injectable dispatch boundary; generic test factories cannot become a native capability.
pub(super) trait WorkerFactory: Clone {
    /// Exact candidate identity consumed by this factory, never a supplied device path.
    type Identity;
    /// Capture-owning worker returned only after the factory's complete initialization gate.
    type Worker;
    /// Creates a new worker; production repeats native full peer/session/generation proof and ACK.
    fn spawn(&self, identity: &Self::Identity) -> Result<Self::Worker, NativeError>;
}

/// Only an opaque native Manager factory selects GUI launch; explicit process mode is temporary.
#[derive(Clone)]
pub(super) enum WorkerRoute<F> {
    Manager(F),
    LegacyDirect,
    Denied,
}

impl<F: WorkerFactory> WorkerRoute<F> {
    /// Selects authority without manufacturing a GUI capability from booleans or backup ownership.
    fn select(endpoint: bool, direct: bool, factory: Option<F>) -> Self {
        if endpoint {
            factory.map_or(Self::Denied, Self::Manager)
        } else if direct {
            Self::LegacyDirect
        } else {
            Self::Denied
        }
    }

    /// Dispatches one new worker; a GUI refusal must never invoke the temporary direct route.
    fn dispatch(
        &self,
        identity: &F::Identity,
        direct: impl FnOnce(&F::Identity) -> Result<F::Worker, NativeError>,
    ) -> Result<F::Worker, NativeError> {
        match self {
            Self::Manager(factory) => factory.spawn(identity),
            Self::LegacyDirect => direct(identity),
            Self::Denied => Err(NativeError::AccessDenied),
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) type MacWorkerRoute = WorkerRoute<rdx_macos_native::MacWorkerFactory>;

#[cfg(target_os = "macos")]
impl WorkerFactory for rdx_macos_native::MacWorkerFactory {
    type Identity = rdx_macos_native::MacRematchIdentity;
    type Worker = rdx_macos_native::MacScsiWorkerLease;
    /// Native capability performs fresh exact peer/session/generation validation and child preflight.
    fn spawn(&self, identity: &Self::Identity) -> Result<Self::Worker, NativeError> {
        rdx_macos_native::MacWorkerFactory::spawn(self, identity)
    }
}

#[cfg(target_os = "macos")]
impl MacWorkerRoute {
    /// Retains only the original connection capability; backup-owner values never select authority.
    pub(super) fn from_context(context: &crate::service::ServiceExecutionContext) -> Self {
        Self::select(
            context.endpoint_authenticated(),
            context.direct_process_authorized(),
            context.macos_worker_factory().cloned(),
        )
    }

    /// Central new-worker entry; temporary direct mode remains explicit until reviewed Task 5.
    pub(super) fn spawn(
        &self,
        identity: &rdx_macos_native::MacRematchIdentity,
    ) -> Result<rdx_macos_native::MacScsiWorkerLease, NativeError> {
        // The Denied branch also clears stale evidence, without native probing or a raw fallback.
        let _ = rdx_macos_native::take_last_worker_startup_failure();
        self.dispatch(identity, rdx_macos_native::MacScsiWorkerLease::spawn)
    }
}

#[cfg(test)]
#[path = "worker_route_tests.rs"]
mod tests;

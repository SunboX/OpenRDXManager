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

/// Both launch routes require opaque native authority; flags never become a capture capability.
#[derive(Clone)]
pub(super) enum WorkerRoute<F> {
    Manager(F),
    Direct(F),
    Denied,
}

impl<F: WorkerFactory> WorkerRoute<F> {
    /// Selects authority without manufacturing a GUI capability from booleans or backup ownership.
    fn select(endpoint: bool, direct: bool, factory: Option<F>, process: Option<F>) -> Self {
        if endpoint {
            factory.map_or(Self::Denied, Self::Manager)
        } else if direct {
            process.map_or(Self::Denied, Self::Direct)
        } else {
            Self::Denied
        }
    }

    /// Dispatches only the retained native capability; neither route has a raw capture fallback.
    fn dispatch(&self, identity: &F::Identity) -> Result<F::Worker, NativeError> {
        match self {
            Self::Manager(factory) | Self::Direct(factory) => factory.spawn(identity),
            Self::Denied => Err(NativeError::AccessDenied),
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) type MacWorkerRoute = WorkerRoute<MacWorkerAuthority>;

/// One retained native capability; public context flags cannot construct either variant's payload.
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub(super) enum MacWorkerAuthority {
    Manager(rdx_macos_native::MacWorkerFactory),
    Direct(rdx_macos_native::MacDirectWorkerFactory),
}

#[cfg(target_os = "macos")]
impl WorkerFactory for MacWorkerAuthority {
    type Identity = rdx_macos_native::MacRematchIdentity;
    type Worker = rdx_macos_native::MacScsiWorkerLease;
    /// Both native factories perform full route-specific proof before capture under one deadline.
    fn spawn(&self, identity: &Self::Identity) -> Result<Self::Worker, NativeError> {
        match self {
            Self::Manager(factory) => factory.spawn(identity),
            Self::Direct(factory) => factory.spawn(identity),
        }
    }
}

#[cfg(target_os = "macos")]
impl MacWorkerRoute {
    /// Retains only the original connection capability; backup-owner values never select authority.
    pub(super) fn from_context(context: &crate::service::ServiceExecutionContext) -> Self {
        Self::select(
            context.endpoint_authenticated(),
            context.direct_process_authorized(),
            context
                .macos_worker_factory()
                .cloned()
                .map(MacWorkerAuthority::Manager),
            context
                .macos_direct_worker_factory()
                .cloned()
                .map(MacWorkerAuthority::Direct),
        )
    }

    /// Central new-worker entry requires one native-minted route with no missing-GUI fallback.
    pub(super) fn spawn(
        &self,
        identity: &rdx_macos_native::MacRematchIdentity,
    ) -> Result<rdx_macos_native::MacScsiWorkerLease, NativeError> {
        // The Denied branch also clears stale evidence, without native probing or a raw fallback.
        let _ = rdx_macos_native::take_last_worker_startup_failure();
        self.dispatch(identity)
    }
}

#[cfg(test)]
#[path = "worker_route_tests.rs"]
mod tests;

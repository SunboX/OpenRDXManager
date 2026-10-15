// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native-minted direct authority never selects or impersonates a Manager GUI session.

use crate::{NativeError, worker_context::DirectBaseline};
use std::{fmt, path::PathBuf, sync::Arc, time::Instant};

/// Immutable actual native caller identity, shared only by handles minted in that process.
struct DirectState {
    baseline: DirectBaseline,
    executable: PathBuf,
}

/// Opaque privileged direct-process capability; flags, storage ownership and IPC cannot mint it.
#[derive(Clone)]
pub struct MacDirectWorkerFactory {
    state: Arc<DirectState>,
}

impl MacDirectWorkerFactory {
    /// Mints only after actual native privilege and public self-audit checks in this current process.
    /// # Errors
    /// Refuses non-root/inconsistent process metadata and unavailable executable identity.
    pub fn for_current_privileged_process() -> Result<Self, NativeError> {
        let baseline = DirectBaseline::capture()?;
        let executable = std::env::current_exe().map_err(|_| NativeError::TransportUnavailable)?;
        Ok(Self {
            state: Arc::new(DirectState {
                baseline,
                executable,
            }),
        })
    }

    /// Rechecks the actual caller baseline without GUI policy or any device access.
    fn revalidate(&self) -> Result<(), NativeError> {
        self.state.baseline.revalidate()?;
        if std::env::current_exe().map_err(|_| NativeError::TransportUnavailable)?
            != self.state.executable
        {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }

    /// Starts the fixed current executable directly; actual child proof and ACK precede INIT/IOKit.
    /// # Errors
    /// Preserves existing Busy, bounded transport, context, capture and exact-candidate failures.
    pub fn spawn(
        &self,
        identity: &crate::MacRematchIdentity,
    ) -> Result<crate::MacScsiWorkerLease, NativeError> {
        use crate::scsi_worker_startup as diagnostic;
        use std::sync::atomic::Ordering;
        diagnostic::reset();
        let deadline = Instant::now() + crate::scsi_worker::INIT_TIMEOUT;
        if crate::scsi_worker::UNREAPED_WORKER.load(Ordering::Acquire) {
            diagnostic::parent_failure("process-spawn", NativeError::Busy);
            return Err(NativeError::Busy);
        }
        self.revalidate()
            .inspect_err(|error| diagnostic::parent_failure("context-peer", *error))?;
        if Instant::now() >= deadline {
            return Err(NativeError::TimedOut);
        }
        let process = crate::worker_process::spawn_direct()
            .inspect_err(|error| diagnostic::parent_failure("process-spawn", *error))?;
        let expected = self.state.baseline.expectation(process.child.id())?;
        crate::MacScsiWorkerLease::initialize_context_process(
            process,
            &expected,
            identity,
            deadline,
            |worker| {
                self.revalidate()?;
                // One nonblocking write uses the original deadline; direct authority has no peer lease.
                worker.acknowledge_context(deadline)
            },
        )
    }
}

impl fmt::Debug for MacDirectWorkerFactory {
    /// Never exposes private credentials, audit metadata, process identity or executable path.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacDirectWorkerFactory(<private>)")
    }
}
impl PartialEq for MacDirectWorkerFactory {
    /// Equality means shared native-minted process authority, never a matching claimed UID.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}
impl Eq for MacDirectWorkerFactory {}

#[cfg(test)]
mod tests {
    use super::*;
    /// Actual ordinary process cannot gain direct authority from CLI flags or a requested route.
    #[test]
    fn direct_factory_rejects_actual_unprivileged_current_process() {
        assert!(
            !crate::current_process_is_privileged_service(),
            "fixture requires ordinary test invocation"
        );
        assert!(matches!(
            MacDirectWorkerFactory::for_current_privileged_process(),
            Err(NativeError::AccessDenied)
        ));
    }
}

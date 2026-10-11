// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-owned, bounded, explicitly selected recovery and fresh operator consent.

mod native;
mod routes;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rsa::rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde_json::{Value, json};

use super::recovery::{
    RecoveryError, RecoveryObserver, RecoveryOutcome, RecoverySelection, RecoveryStage,
};
use super::{ServiceExecutionContext, ServiceProtocolError, action_failure};

const TARGET_LIFETIME: Duration = Duration::from_secs(300);
const MAX_TARGETS: usize = 16;
const MAX_BUNDLES: usize = 128;
const MAX_RECOVERY_DURATION: Duration = Duration::from_secs(30 * 60);
const RELEASE_TIMEOUT: Duration = Duration::from_secs(30);

/// Exact renderer-safe saved unit facts, never an artifact path or raw record.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Bundle {
    bundle_id: String,
    serial: String,
    source_version: &'static str,
    target_version: &'static str,
    recovery_needed: bool,
}

/// Internal native token with only a human-readable physical route in public output.
struct Target {
    native_token: String,
    label: String,
}

/// Injectable controller boundary; only production bindings can touch native IO.
trait Driver: Send + Sync {
    /// Checks process/endpoint authority independently of descriptor claims.
    fn authorize(&self) -> Result<(), RecoveryError>;
    /// Reads existing evidence and current USB enumeration without provisioning.
    fn inventory(&self) -> Result<(Vec<Target>, Vec<Bundle>), RecoveryError>;
    /// Executes one bounded, non-retrying recovery under inherited global ownership.
    fn recover(
        &self,
        selection: &RecoverySelection,
        observer: &mut dyn RecoveryObserver,
    ) -> Result<RecoveryOutcome, RecoveryError>;
}

/// One fresh list token, consumed before a dedicated worker is admitted.
struct SelectionEntry {
    native_token: String,
    expires: Instant,
}

/// Fixed public status retained across renderer reloads within this native generation.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    state: &'static str,
    revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    awaiting_acknowledgment: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// Shared progress and fresh single-use acknowledgment, containing no native handle.
struct Shared {
    status: Status,
    connected: bool,
    deadline: Option<Instant>,
    gate_seen: bool,
    acknowledgment_pending: bool,
}

impl Shared {
    /// Rejects a lost client or exhausted lifetime before the next dependent native call.
    fn ensure_connected(&self) -> Result<(), RecoveryError> {
        if !self.connected
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(RecoveryError::ObserverUnavailable);
        }
        Ok(())
    }

    /// Commits a terminal only after the controller and its native owners have returned.
    fn complete(&mut self, result: Result<RecoveryOutcome, RecoveryError>) {
        let result = self.ensure_connected().and(result).and_then(|outcome| {
            if self.status.stage == Some(RecoveryStage::VerifyingFinalRelease.code()) {
                Ok(outcome)
            } else {
                Err(RecoveryError::ObserverUnavailable)
            }
        });
        self.status.revision += 1;
        self.status.awaiting_acknowledgment = Some(false);
        self.acknowledgment_pending = false;
        match result {
            Ok(RecoveryOutcome::FinalReleaseVerified) => self.status.state = "succeeded",
            Err(error) => {
                self.status.state = "failed";
                self.status.reason = Some(error.code());
            }
        }
    }
}

/// One service-generation recovery controller with no automatic resume or retry.
pub(super) struct RecoverySession {
    driver: Arc<dyn Driver>,
    shared: Arc<Mutex<Shared>>,
    selections: BTreeMap<String, SelectionEntry>,
    bundle_ids: BTreeSet<String>,
    worker: Option<JoinHandle<()>>,
    release: Option<mpsc::SyncSender<()>>,
}

impl RecoverySession {
    /// Constructs production bindings from startup evidence, never a backend descriptor.
    pub(super) fn native(context: ServiceExecutionContext) -> Self {
        Self::with_driver(Arc::new(native::NativeDriver { context }))
    }

    /// Creates an idle bounded session around a production or deterministic test driver.
    fn with_driver(driver: Arc<dyn Driver>) -> Self {
        Self {
            driver,
            shared: Arc::new(Mutex::new(Shared {
                status: Status {
                    state: "idle",
                    revision: 0,
                    attempt_id: None,
                    stage: None,
                    awaiting_acknowledgment: None,
                    reason: None,
                },
                connected: true,
                deadline: None,
                gate_seen: false,
                acknowledgment_pending: false,
            })),
            selections: BTreeMap::new(),
            bundle_ids: BTreeSet::new(),
            worker: None,
            release: None,
        }
    }

    /// Retains admission until the dedicated thread has returned and dropped all captures.
    pub(super) fn is_active(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    /// Returns retained fixed progress without enumeration, IO or selection invalidation.
    fn status(&self) -> Value {
        match self.shared.lock() {
            Ok(shared) => json!({"ok": true, "status": shared.status}),
            Err(_) => action_failure(RecoveryError::ObserverUnavailable.code()),
        }
    }

    /// Rotates all choices on every read-only inventory, with a five-minute lifetime.
    fn list(&mut self) -> Value {
        self.selections.clear();
        self.bundle_ids.clear();
        let inventory = self
            .driver
            .authorize()
            .and_then(|()| self.driver.inventory());
        let (targets, bundles) = match inventory {
            Ok(inventory) => inventory,
            Err(error) => return action_failure(error.code()),
        };
        if targets.len() > MAX_TARGETS || bundles.len() > MAX_BUNDLES {
            return action_failure(RecoveryError::StorageUnavailable.code());
        }
        let mut public_targets = Vec::new();
        for target in targets {
            let token = match nonce("recovery-target:") {
                Ok(token) => token,
                Err(error) => return action_failure(error.code()),
            };
            public_targets.push(json!({"token": token, "label": target.label}));
            self.selections.insert(
                token,
                SelectionEntry {
                    native_token: target.native_token,
                    expires: Instant::now() + TARGET_LIFETIME,
                },
            );
        }
        self.bundle_ids
            .extend(bundles.iter().map(|bundle| bundle.bundle_id.clone()));
        match self.shared.lock() {
            Ok(shared) => {
                json!({"ok": true, "targets": public_targets, "bundles": bundles, "status": shared.status})
            }
            Err(_) => action_failure(RecoveryError::ObserverUnavailable.code()),
        }
    }

    /// Admits one acknowledged service-issued selection, with mutation held until flush.
    fn start(&mut self, bundle_id: String, token: String, acknowledged: bool) -> Value {
        if self.is_active() {
            return action_failure("recovery-in-progress");
        }
        if let Err(error) = self.driver.authorize() {
            return action_failure(error.code());
        }
        if !acknowledged {
            return action_failure("recovery-acknowledgment-required");
        }
        if !self.bundle_ids.contains(&bundle_id) {
            return action_failure("recovery-bundle-unavailable");
        }
        let Some(selected) = self.selections.remove(&token) else {
            return action_failure("recovery-selection-stale");
        };
        if Instant::now() >= selected.expires {
            return action_failure("recovery-selection-stale");
        }
        self.selections.clear();
        self.bundle_ids.clear();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let attempt_id = match nonce("recovery:") {
            Ok(token) => token,
            Err(error) => return action_failure(error.code()),
        };
        let initial_status;
        {
            let Ok(mut shared) = self.shared.lock() else {
                return action_failure(RecoveryError::ObserverUnavailable.code());
            };
            if !shared.connected {
                return action_failure(RecoveryError::ObserverUnavailable.code());
            }
            // A new explicit attempt gets a new deadline; an expired prior
            // attempt must not masquerade as a permanently disconnected client.
            shared.status = Status {
                state: "running",
                revision: shared.status.revision + 1,
                attempt_id: Some(attempt_id),
                stage: Some(RecoveryStage::Preparing.code()),
                awaiting_acknowledgment: Some(false),
                reason: None,
            };
            shared.deadline = Some(Instant::now() + MAX_RECOVERY_DURATION);
            shared.gate_seen = false;
            shared.acknowledgment_pending = false;
            initial_status = shared.status.clone();
        }
        let selection = RecoverySelection {
            bundle_id,
            target_token: selected.native_token,
        };
        let driver = Arc::clone(&self.driver);
        let shared = Arc::clone(&self.shared);
        let (release, admission) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("openrdx-recovery".to_owned())
            .spawn(move || {
                let mut observer = SessionObserver {
                    shared: Arc::clone(&shared),
                };
                let result = catch_unwind(AssertUnwindSafe(|| {
                    admission
                        .recv_timeout(RELEASE_TIMEOUT)
                        .map_err(|_| RecoveryError::ObserverUnavailable)?;
                    observer.ensure_connected()?;
                    driver.recover(&selection, &mut observer)
                }))
                .unwrap_or(Err(RecoveryError::RomOperationUnknown));
                if let Ok(mut shared) = shared.lock() {
                    shared.complete(result);
                }
            });
        match worker {
            Ok(worker) => {
                self.worker = Some(worker);
                self.release = Some(release);
                json!({"ok": true, "status": initial_status})
            }
            Err(_) => {
                if let Ok(mut shared) = self.shared.lock() {
                    shared.complete(Err(RecoveryError::ObserverUnavailable));
                }
                action_failure(RecoveryError::ObserverUnavailable.code())
            }
        }
    }

    /// Opens the one worker release gate only after its acceptance response is flushed.
    pub(super) fn release_prepared(&mut self) -> Result<(), ServiceProtocolError> {
        if let Some(release) = self.release.take() {
            release
                .send(())
                .map_err(|_| ServiceProtocolError::BackendContract)?;
        }
        Ok(())
    }

    /// Consumes only the exact currently armed attempt and publishes the consumed state.
    fn acknowledge(&mut self, attempt_id: &str, acknowledged: bool) -> Value {
        let Ok(mut shared) = self.shared.lock() else {
            return action_failure(RecoveryError::ObserverUnavailable.code());
        };
        if !acknowledged {
            return action_failure("recovery-acknowledgment-required");
        }
        if shared.ensure_connected().is_err()
            || shared.status.state != "running"
            || shared.status.attempt_id.as_deref() != Some(attempt_id)
        {
            return action_failure("recovery-attempt-not-found");
        }
        if shared.status.stage != Some(RecoveryStage::AwaitingPowerCycle.code())
            || shared.status.awaiting_acknowledgment != Some(true)
        {
            return action_failure("recovery-not-continuable");
        }
        shared.status.awaiting_acknowledgment = Some(false);
        shared.status.revision += 1;
        shared.acknowledgment_pending = true;
        json!({"ok": true, "status": shared.status})
    }
}

impl Drop for RecoverySession {
    /// Stops at the next observer checkpoint and retains ownership until native cleanup ends.
    fn drop(&mut self) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.connected = false;
        }
        self.release = None;
        if let Some(worker) = self.worker.take() {
            // Native ROM/SCSI operations and all controller waits have finite
            // deadlines. Joining, rather than detaching a capture, keeps the
            // enclosing service-generation global hardware owner alive.
            let _ = worker.join();
        }
    }
}

/// Nonblocking observer over the service's fixed progress/acknowledgment state.
struct SessionObserver {
    shared: Arc<Mutex<Shared>>,
}

impl RecoveryObserver for SessionObserver {
    /// Publishes progress before mutation and arms exactly one new power-cycle reply.
    fn reached(&mut self, stage: RecoveryStage) -> Result<(), RecoveryError> {
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| RecoveryError::ObserverUnavailable)?;
        shared.ensure_connected()?;
        if stage == RecoveryStage::AwaitingPowerCycle {
            if shared.gate_seen {
                return Err(RecoveryError::ObserverUnavailable);
            }
            shared.gate_seen = true;
            shared.acknowledgment_pending = false;
        }
        shared.status.stage = Some(stage.code());
        shared.status.awaiting_acknowledgment = Some(stage == RecoveryStage::AwaitingPowerCycle);
        shared.status.revision += 1;
        Ok(())
    }

    /// Returns one accepted fresh UI reply exactly once, independently of USB enumeration.
    fn operator_acknowledged(&mut self) -> Result<bool, RecoveryError> {
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| RecoveryError::ObserverUnavailable)?;
        shared.ensure_connected()?;
        if shared.status.stage != Some(RecoveryStage::AwaitingPowerCycle.code())
            || !shared.gate_seen
        {
            return Err(RecoveryError::OperatorAcknowledgmentRequired);
        }
        Ok(std::mem::take(&mut shared.acknowledgment_pending))
    }

    /// Stops dependent transport steps promptly after loss of the owning IPC connection.
    fn ensure_connected(&mut self) -> Result<(), RecoveryError> {
        self.shared
            .lock()
            .map_err(|_| RecoveryError::ObserverUnavailable)?
            .ensure_connected()
    }
}

/// Uses operating-system randomness for an unguessable, path-free service capability.
fn nonce(prefix: &str) -> Result<String, RecoveryError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| RecoveryError::ObserverUnavailable)?;
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("{prefix}{suffix}"))
}

/// Recognizes only the fixed recovery vocabulary; unknown names remain ordinary rejections.
pub(super) fn is_recovery_method(method: &str) -> bool {
    matches!(
        method,
        "recovery-list" | "recovery-start" | "recovery-status" | "recovery-continue"
    )
}

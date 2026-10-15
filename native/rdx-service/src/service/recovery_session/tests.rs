// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic recovery admission, wire, lifetime, and connection-loss coverage.

use super::super::{
    ActiveOperation, ServiceBackend, ServiceDescriptor, ServiceEventSink, ServicePlatform,
    ServiceRejection, ServiceRuntime, service_rejection,
};
use super::*;
use crate::model::{DeviceSnapshot, OperationId, OperationRequest};
use std::sync::atomic::{AtomicUsize, Ordering};

const BUNDLE: &str = "migration-1-1";

/// Commands advance only the injected controller and never reach hardware.
enum Command {
    Stage(RecoveryStage),
    Poll,
    Succeed,
    Fail,
    Panic,
    WaitDisconnect,
}
#[derive(Debug, PartialEq)]
enum Report {
    Started,
    Stage,
    Acknowledged(bool),
    Waiting,
}

/// Counts read-only inventory and explicitly released recovery calls independently.
struct FakeDriver {
    authorized: bool,
    inventories: AtomicUsize,
    writes: AtomicUsize,
    commands: Mutex<mpsc::Receiver<Command>>,
    reports: mpsc::SyncSender<Report>,
}

impl Driver for FakeDriver {
    /// Supplies deterministic authority without a fabricated service descriptor.
    fn authorize(&self) -> Result<(), RecoveryError> {
        if self.authorized {
            Ok(())
        } else {
            Err(RecoveryError::PrivilegeRequired)
        }
    }

    /// Returns one known original profile and an epoch token, with no writes.
    fn inventory(&self) -> Result<(Vec<Target>, Vec<Bundle>), RecoveryError> {
        self.inventories.fetch_add(1, Ordering::SeqCst);
        Ok((
            vec![Target {
                native_token: "private-native-token".to_owned(),
                label: "USB port 1".to_owned(),
            }],
            vec![Bundle {
                bundle_id: BUNDLE.to_owned(),
                serial: "007820746632".to_owned(),
                source_version: "2.83",
                target_version: "1.07",
                recovery_needed: true,
            }],
        ))
    }

    /// Advances only when the test sends a bounded deterministic command.
    fn recover(
        &self,
        selection: &RecoverySelection,
        observer: &mut dyn RecoveryObserver,
    ) -> Result<RecoveryOutcome, RecoveryError> {
        assert_eq!(selection.bundle_id, BUNDLE);
        assert_eq!(selection.target_token, "private-native-token");
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.reports.send(Report::Started).unwrap();
        let commands = self.commands.lock().unwrap();
        loop {
            match commands.recv_timeout(Duration::from_secs(2)).unwrap() {
                Command::Stage(stage) => {
                    observer.reached(stage)?;
                    self.reports.send(Report::Stage).unwrap();
                }
                Command::Poll => {
                    let acknowledged = observer.operator_acknowledged()?;
                    self.reports
                        .send(Report::Acknowledged(acknowledged))
                        .unwrap();
                }
                Command::Succeed => return Ok(RecoveryOutcome::FinalReleaseVerified),
                Command::Fail => return Err(RecoveryError::RomOperationUnknown),
                Command::Panic => panic!("injected sanitized controller panic"),
                Command::WaitDisconnect => {
                    self.reports.send(Report::Waiting).unwrap();
                    let deadline = Instant::now() + Duration::from_secs(2);
                    loop {
                        observer.ensure_connected()?;
                        assert!(Instant::now() < deadline);
                        thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
    }
}

/// Owns exact bounded test commands and observable non-hardware effects.
struct Harness {
    driver: Arc<FakeDriver>,
    commands: mpsc::SyncSender<Command>,
    reports: mpsc::Receiver<Report>,
}

impl Harness {
    /// Creates a separately authorized controller and a fresh service session.
    fn new(authorized: bool) -> (Self, RecoverySession) {
        let (commands, command_receiver) = mpsc::sync_channel(8);
        let (reports, report_receiver) = mpsc::sync_channel(8);
        let driver = Arc::new(FakeDriver {
            authorized,
            inventories: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            commands: Mutex::new(command_receiver),
            reports,
        });
        let session = RecoverySession::with_driver(driver.clone());
        (
            Self {
                driver,
                commands,
                reports: report_receiver,
            },
            session,
        )
    }

    /// Confirms a worker observation within a short deterministic test bound.
    fn expect(&self, report: Report) {
        assert_eq!(
            self.reports.recv_timeout(Duration::from_secs(2)).unwrap(),
            report
        );
    }

    /// Simulates native progress only after admission has been released.
    fn stage(&self, stage: RecoveryStage) {
        self.commands.send(Command::Stage(stage)).unwrap();
        self.expect(Report::Stage);
    }

    /// Finishes the worker and joins it before assertions about terminal state.
    fn finish(&self, session: &mut RecoverySession, command: Command) {
        self.commands.send(command).unwrap();
        session.worker.take().unwrap().join().unwrap();
    }
}

/// Reads one current opaque target capability from a successful public list.
fn target(session: &mut RecoverySession) -> String {
    let result = session.list();
    assert_eq!(result["ok"], true);
    result["targets"][0]["token"].as_str().unwrap().to_owned()
}

/// Starts and causally releases one selected recovery, returning its attempt owner.
fn start(harness: &Harness, session: &mut RecoverySession) -> String {
    let token = target(session);
    let result = session.start(BUNDLE.to_owned(), token, true);
    assert_eq!(result["status"]["state"], "running");
    assert!(matches!(
        harness.reports.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_eq!(harness.driver.writes.load(Ordering::SeqCst), 0);
    session.release_prepared().unwrap();
    harness.expect(Report::Started);
    result["status"]["attemptId"].as_str().unwrap().to_owned()
}

/// Enumeration never writes; tokens rotate, expire, and cannot be forged from native facts.
#[test]
fn list_is_read_only_and_selection_capabilities_are_fresh_and_bounded() {
    let (harness, mut session) = Harness::new(true);
    let previous = target(&mut session);
    let current = target(&mut session);
    assert_ne!(current, previous);
    assert_eq!(
        session.start(BUNDLE.to_owned(), previous, true)["reason"],
        "recovery-selection-stale"
    );
    assert_eq!(
        session.start(BUNDLE.to_owned(), "private-native-token".to_owned(), true)["reason"],
        "recovery-selection-stale"
    );
    session.selections.get_mut(&current).unwrap().expires = Instant::now();
    assert_eq!(
        session.start(BUNDLE.to_owned(), current, true)["reason"],
        "recovery-selection-stale"
    );
    assert_eq!(harness.driver.writes.load(Ordering::SeqCst), 0);
    assert_eq!(harness.driver.inventories.load(Ordering::SeqCst), 2);
    assert_eq!(
        session.status(),
        json!({"ok": true, "status": {"state": "idle", "revision": 0}})
    );
}

/// Neither an unknown profile nor a false/missing acknowledgment grants authority.
#[test]
fn start_requires_current_profile_and_explicit_association_acknowledgment() {
    let (harness, mut session) = Harness::new(true);
    let token = target(&mut session);
    assert_eq!(
        session.start("../../elsewhere".to_owned(), token.clone(), true)["reason"],
        "recovery-bundle-unavailable"
    );
    assert_eq!(
        session.start(BUNDLE.to_owned(), token, false)["reason"],
        "recovery-acknowledgment-required"
    );
    assert_eq!(harness.driver.writes.load(Ordering::SeqCst), 0);
}

/// Only the active fresh power-cycle gate accepts one exact owner acknowledgment.
#[test]
fn acknowledgment_is_fresh_exact_single_use_and_survives_status_polling() {
    let (harness, mut session) = Harness::new(true);
    let attempt = start(&harness, &mut session);
    assert_eq!(
        session.acknowledge(&attempt, true)["reason"],
        "recovery-not-continuable"
    );
    harness.stage(RecoveryStage::AwaitingPowerCycle);
    assert_eq!(
        session.acknowledge("recovery:foreign", true)["reason"],
        "recovery-attempt-not-found"
    );
    assert_eq!(
        session.acknowledge(&attempt, false)["reason"],
        "recovery-acknowledgment-required"
    );
    let prompt = session.status();
    assert_eq!(prompt["status"]["awaitingAcknowledgment"], true);
    let accepted = session.acknowledge(&attempt, true);
    assert_eq!(accepted["status"]["awaitingAcknowledgment"], false);
    assert!(
        accepted["status"]["revision"].as_u64().unwrap()
            > prompt["status"]["revision"].as_u64().unwrap()
    );
    assert_eq!(session.status(), accepted);
    assert_eq!(
        session.acknowledge(&attempt, true)["reason"],
        "recovery-not-continuable"
    );
    harness.commands.send(Command::Poll).unwrap();
    harness.expect(Report::Acknowledged(true));
    harness.commands.send(Command::Poll).unwrap();
    harness.expect(Report::Acknowledged(false));
    harness.stage(RecoveryStage::VerifyingFinalRelease);
    harness.finish(&mut session, Command::Succeed);
    assert_eq!(session.status()["status"]["state"], "succeeded");
    assert_eq!(session.status()["status"]["awaitingAcknowledgment"], false);
}

/// A consumed target never authorizes an automatic second attempt after failure or panic.
#[test]
fn overlap_failure_and_panic_never_retry_or_manufacture_success() {
    for command in [Command::Fail, Command::Panic] {
        let (harness, mut session) = Harness::new(true);
        start(&harness, &mut session);
        assert_eq!(
            session.start(BUNDLE.to_owned(), "ignored".to_owned(), true)["reason"],
            "recovery-in-progress"
        );
        harness.finish(&mut session, command);
        let result = session.status();
        assert_eq!(result["status"]["state"], "failed");
        assert_eq!(result["status"]["reason"], "recovery-rom-operation-unknown");
        assert_eq!(harness.driver.writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            session.start(BUNDLE.to_owned(), "ignored".to_owned(), true)["reason"],
            "recovery-bundle-unavailable"
        );
    }
}

/// Losing the response stream before acceptance flush cannot dispatch a native call.
#[test]
fn disconnect_before_release_joins_without_dispatching() {
    let (harness, mut session) = Harness::new(true);
    let token = target(&mut session);
    assert_eq!(session.start(BUNDLE.to_owned(), token, true)["ok"], true);
    let shared = Arc::clone(&session.shared);
    drop(session);
    assert_eq!(harness.driver.writes.load(Ordering::SeqCst), 0);
    assert_eq!(shared.lock().unwrap().status.state, "failed");
}

/// Loss after native start prevents further steps and joins before releasing the owner.
#[test]
fn disconnect_during_attempt_joins_worker_and_retains_failure() {
    let (harness, mut session) = Harness::new(true);
    start(&harness, &mut session);
    harness.commands.send(Command::WaitDisconnect).unwrap();
    harness.expect(Report::Waiting);
    let shared = Arc::clone(&session.shared);
    drop(session);
    let shared = shared.lock().unwrap();
    assert_eq!(shared.status.state, "failed");
    assert_eq!(
        shared.status.reason,
        Some(RecoveryError::ObserverUnavailable.code())
    );
}

/// Polls never enumerate or rotate a still-valid selection; the observer lifetime is finite.
#[test]
fn status_is_side_effect_free_and_deadline_prevents_further_steps() {
    let (harness, mut session) = Harness::new(true);
    let token = target(&mut session);
    assert_eq!(session.status()["status"]["state"], "idle");
    assert!(session.selections.contains_key(&token));
    assert_eq!(harness.driver.inventories.load(Ordering::SeqCst), 1);
    let mut observer = SessionObserver {
        shared: Arc::clone(&session.shared),
    };
    session.shared.lock().unwrap().deadline = Some(Instant::now());
    assert_eq!(
        observer.ensure_connected(),
        Err(RecoveryError::ObserverUnavailable)
    );
    assert_eq!(
        observer.reached(RecoveryStage::SettingUpRom),
        Err(RecoveryError::ObserverUnavailable)
    );
}

/// A fabricated native descriptor has no relationship to independently verified authority.
#[test]
fn native_descriptor_and_unprivileged_context_do_not_grant_recovery() {
    let session = RecoverySession::native(ServiceExecutionContext::development_stdio());
    assert_eq!(
        session.driver.authorize(),
        Err(RecoveryError::PrivilegeRequired)
    );
    let mut forged_descriptor = runtime(session);
    assert_eq!(
        forged_descriptor.descriptor.mode,
        super::super::ServiceMode::Native
    );
    assert_eq!(
        forged_descriptor
            .handle_recovery_request("recovery-list", json!({}))
            .unwrap()["reason"],
        "recovery-privilege-required"
    );
    assert_eq!(forged_descriptor.backend.calls, 0);
    let (harness, mut injected) = Harness::new(false);
    assert_eq!(injected.list()["reason"], "recovery-privilege-required");
    assert_eq!(harness.driver.inventories.load(Ordering::SeqCst), 0);
}

/// Counts ordinary backend calls so recovery exclusion covers every wire route.
struct Backend {
    busy: bool,
    calls: usize,
}

impl ServiceBackend for Backend {
    /// Supplies a deliberately native-looking descriptor with no authority value.
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::native_available(ServicePlatform::Darwin, "test").unwrap()
    }
    /// Simulates the independent preparation/cleanup reservation.
    fn require_recovery_idle(&mut self) -> Result<(), ServiceRejection> {
        if self.busy {
            Err(service_rejection("operation-in-progress"))
        } else {
            Ok(())
        }
    }
    /// Counts a public inventory request without hardware.
    fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        self.calls += 1;
        Ok(vec![])
    }
    /// Counts an ordinary scan request without hardware.
    fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
        self.calls += 1;
        Ok(vec![])
    }
    /// Counts ordinary operation admission without hardware.
    fn start_operation(
        &mut self,
        _: OperationId,
        _: OperationRequest,
        _: ServiceEventSink,
    ) -> Result<(), ServiceRejection> {
        self.calls += 1;
        Ok(())
    }
    /// Counts ordinary cancellation without hardware.
    fn cancel_operation(&mut self, _: &OperationId) -> Result<(), ServiceRejection> {
        self.calls += 1;
        Ok(())
    }
    /// Counts shutdown requests without terminating a process.
    fn shutdown(&mut self) -> Result<(), ServiceRejection> {
        self.calls += 1;
        Ok(())
    }
}

/// Creates a fake native descriptor while controlling recovery authority separately.
fn runtime(session: RecoverySession) -> ServiceRuntime<Backend> {
    let sink = ServiceEventSink::new(
        mpsc::sync_channel(64).0,
        super::super::crash::CrashAdmission::new(),
    );
    let mut runtime = ServiceRuntime::new(
        Backend {
            busy: false,
            calls: 0,
        },
        sink,
    );
    runtime.recovery = session;
    runtime
}

/// Every ordinary route remains excluded even if a caller bypasses renderer/main guards.
#[test]
fn active_recovery_excludes_all_ordinary_requests_and_shutdown() {
    let (harness, mut session) = Harness::new(true);
    start(&harness, &mut session);
    let mut runtime = runtime(session);
    for method in [
        "devices-list",
        "devices-scan",
        "operation-start",
        "operation-cancel",
        "operation-continue",
        "operation-confirmation-issue",
        "firmware-registration-begin",
        "firmware-registration-chunk",
        "firmware-registration-commit",
        "firmware-registration-abort",
        "service-shutdown",
    ] {
        let (responses, stop) = runtime
            .handle_request("request:1".to_owned(), method, json!({}))
            .unwrap();
        assert_eq!(
            responses[0]["result"]["reason"], "recovery-in-progress",
            "{method}"
        );
        assert!(!stop);
    }
    assert_eq!(runtime.backend.calls, 0);
    harness.finish(&mut runtime.recovery, Command::Fail);
}

/// Queued preparation and a terminal-but-not-cleaned worker both keep recovery excluded.
#[test]
fn existing_runtime_operation_and_worker_reservation_exclude_recovery() {
    let (_harness, session) = Harness::new(true);
    let mut runtime = runtime(session);
    let payload = json!({"bundleId": BUNDLE, "targetToken": "forged", "acknowledged": true});
    runtime.backend.busy = true;
    assert_eq!(
        runtime
            .handle_recovery_request("recovery-start", payload.clone())
            .unwrap()["reason"],
        "operation-in-progress"
    );
    runtime.backend.busy = false;
    let request = OperationRequest::StatusRefresh {
        device_id: crate::model::DeviceId::new("rdx:test").unwrap(),
        device_revision: crate::model::DiscoveryRevision::new(1).unwrap(),
    };
    runtime.active =
        Some(ActiveOperation::new(OperationId::new("op:test").unwrap(), &request).unwrap());
    assert_eq!(
        runtime
            .handle_recovery_request("recovery-start", payload)
            .unwrap()["reason"],
        "operation-in-progress"
    );
}

/// Wire payloads deny hidden fields, missing acknowledgments, and arbitrary gate names.
#[test]
fn recovery_payloads_are_strict_and_only_the_power_cycle_stage_is_accepted() {
    let (_harness, session) = Harness::new(true);
    let mut runtime = runtime(session);
    for (method, payload) in [
        ("recovery-list", json!({"path": "/tmp"})),
        ("recovery-status", json!({"extra": true})),
        (
            "recovery-start",
            json!({"bundleId": BUNDLE, "targetToken": "forged"}),
        ),
        (
            "recovery-start",
            json!({"bundleId": BUNDLE, "targetToken": "forged", "acknowledged": true, "locationId": 1}),
        ),
        (
            "recovery-continue",
            json!({"attemptId": "recovery:1", "stage": "recovery-setting-up-rom", "acknowledged": true}),
        ),
        (
            "recovery-continue",
            json!({"attemptId": "recovery:1", "stage": "recovery-awaiting-power-cycle", "acknowledged": true, "extra": true}),
        ),
    ] {
        assert_eq!(
            runtime.handle_recovery_request(method, payload),
            Err(ServiceProtocolError::ProtocolViolation)
        );
    }
    assert_eq!(runtime.backend.calls, 0);
}

/// A broken writer models lost acceptance without ever touching a native adapter.
struct BrokenWriter;
impl std::io::Write for BrokenWriter {
    /// Fails before any acceptance bytes become visible to a caller.
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    /// Does not manufacture a successful frame flush.
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

/// Failed start-frame publication leaves the worker held until disconnect teardown.
#[test]
fn service_writer_failure_does_not_release_recovery_mutation() {
    let (harness, mut session) = Harness::new(true);
    let token = target(&mut session);
    let mut runtime = runtime(session);
    runtime.handshaken = true;
    let (input, input_receiver) = mpsc::sync_channel(2);
    input.send(super::super::runtime_loop::InputSignal::Message(json!({
        "type": "request", "protocolVersion": 1, "requestId": "request:1", "method": "recovery-start",
        "payload": {"bundleId": BUNDLE, "targetToken": token, "acknowledged": true}
    }))).unwrap();
    let (_events, event_receiver) = mpsc::sync_channel(2);
    let crashes = super::super::crash::CrashAdmission::new();
    assert_eq!(
        super::super::runtime_loop::service_loop(
            &mut runtime,
            &input_receiver,
            &event_receiver,
            &crashes,
            &mut BrokenWriter,
            &super::super::session_admission::SessionAdmission::default()
        ),
        Err(ServiceProtocolError::Io)
    );
    drop(runtime);
    assert_eq!(harness.driver.writes.load(Ordering::SeqCst), 0);
}

/// Writer failure, protocol return and unwind revoke before an actual held recovery join completes.
#[cfg(unix)]
#[test]
fn session_admission_revokes_before_recovery_join_on_error_and_unwind() {
    use super::super::session_admission::SessionAdmission;
    for mode in 0..5 {
        let (_harness, session) = Harness::new(true);
        let mut runtime = runtime(session);
        let (entered, waiting) = mpsc::sync_channel(0);
        let (release, resume) = mpsc::sync_channel(0);
        runtime.recovery.worker = Some(thread::spawn(move || {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(4)).unwrap();
        }));
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        let admission = SessionAdmission::fixture();
        let observer = admission.clone();
        let (done, completed) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let (input, input_receiver) = mpsc::sync_channel(1);
            use super::super::runtime_loop::InputSignal;
            input
                .send(match mode {
                    1 => InputSignal::Message(json!({"unexpected":"invalid"})),
                    3 => InputSignal::End,
                    4 => InputSignal::Failure(ServiceProtocolError::InvalidFrameLength),
                    _ => InputSignal::Message(
                        json!({"type":"handshake-request","protocolVersion":1}),
                    ),
                })
                .unwrap();
            let (_events, event_receiver) = mpsc::sync_channel(1);
            let crashes = super::super::crash::CrashAdmission::new();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::super::runtime_loop::service_loop(
                    &mut runtime,
                    &input_receiver,
                    &event_receiver,
                    &crashes,
                    &mut ExitWriter { panic: mode == 2 },
                    &admission,
                )
            }));
            // This really enters RecoverySession::drop and joins the held worker.
            drop(runtime);
            done.send(outcome).unwrap();
        });
        let revoked = observer.wait_revoked();
        let still_joining = matches!(completed.try_recv(), Err(mpsc::TryRecvError::Empty));
        // Release before assertions so a failing regression cannot strand its fixture thread.
        release.send(()).unwrap();
        let outcome = completed.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        assert!(revoked, "mode {mode} did not revoke before recovery join");
        assert!(still_joining);
        match mode {
            0 => assert_eq!(outcome.unwrap(), Err(ServiceProtocolError::Io)),
            1 => assert_eq!(outcome.unwrap(), Err(ServiceProtocolError::MalformedFrame)),
            3 => assert_eq!(outcome.unwrap(), Ok(super::super::ServiceExit::EndOfInput)),
            4 => assert_eq!(
                outcome.unwrap(),
                Err(ServiceProtocolError::InvalidFrameLength)
            ),
            _ => assert!(outcome.is_err()),
        }
    }
}

/// Fails only inside the framed writer, preserving the actual error/unwind path.
#[cfg(unix)]
struct ExitWriter {
    panic: bool,
}

#[cfg(unix)]
impl std::io::Write for ExitWriter {
    /// Supplies either a real writer error or an intentional test unwind.
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        assert!(!self.panic, "injected writer unwind");
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    /// Never claims publication succeeded after a failed write.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

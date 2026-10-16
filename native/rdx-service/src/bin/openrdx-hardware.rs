// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Long-lived bounded privileged service used by Electron main.

#[path = "openrdx-hardware/recovery_cli.rs"]
mod recovery_cli;
#[path = "openrdx-hardware/recovery_status.rs"]
mod recovery_status;
#[cfg(any(windows, test))]
#[path = "openrdx-hardware/windows_session.rs"]
mod windows_session;

use std::ffi::OsStr;
use std::io;
#[cfg(any(windows, test))]
use std::io::{ErrorKind, Read};
use std::process::ExitCode;
#[cfg(any(windows, test))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
#[cfg(any(windows, test))]
use std::time::Instant;

#[cfg(unix)]
use rdx_service::endpoint::HandshakeDeadlineReader;
#[cfg(target_os = "macos")]
use rdx_service::endpoint::embedded_macos_manager_designated_requirement;
#[cfg(target_os = "linux")]
use rdx_service::platform::linux::LinuxBackend;
#[cfg(target_os = "macos")]
use rdx_service::platform::macos::MacOsBackend;
#[cfg(windows)]
use rdx_service::platform::windows::WindowsBackend;
use rdx_service::service::{
    HardwareServiceBackend, SERVICE_PROTOCOL_VERSION, ServiceExecutionContext, ServicePlatform,
    install_process_panic_redaction, run_framed_service_with_context,
};

const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(any(windows, test))]
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[cfg(target_os = "macos")]
type NativeBackend = MacOsBackend;
#[cfg(target_os = "linux")]
type NativeBackend = LinuxBackend;
#[cfg(windows)]
type NativeBackend = WindowsBackend;

/// Runs one accepted session inside an owner or refuses only a busy session.
fn run_owned_service_session<G, T, E, A, B, F>(
    acquire: A,
    is_busy: B,
    execute: F,
) -> Result<Option<T>, E>
where
    A: FnOnce() -> Result<G, E>,
    B: FnOnce(&E) -> bool,
    F: FnOnce() -> Result<T, E>,
{
    let _ownership = match acquire() {
        Ok(ownership) => ownership,
        Err(error) if is_busy(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    execute().map(Some)
}

/// Classifies only the native macOS lock-contention outcome as session-local.
#[cfg(any(target_os = "macos", test))]
fn macos_ownership_is_busy(error: &rdx_macos_native::NativeError) -> bool {
    *error == rdx_macos_native::NativeError::Busy
}

/// Classifies only the native Linux lock-contention outcome as session-local.
#[cfg(any(target_os = "linux", test))]
fn linux_ownership_is_busy(error: &rdx_linux_native::NativeError) -> bool {
    *error == rdx_linux_native::NativeError::Busy
}

/// Classifies only the native Windows lock-contention outcome as session-local.
#[cfg(any(windows, test))]
fn windows_ownership_is_busy(error: &rdx_windows_native::NativeError) -> bool {
    *error == rdx_windows_native::NativeError::Busy
}

/// Selects the current platform's registry-owning production hardware backend.
fn readiness_backend(
    platform: ServicePlatform,
    context: ServiceExecutionContext,
) -> HardwareServiceBackend<NativeBackend> {
    #[cfg(target_os = "macos")]
    {
        HardwareServiceBackend::new(platform, MacOsBackend::native_with_context(context))
    }
    #[cfg(target_os = "linux")]
    {
        HardwareServiceBackend::new(platform, LinuxBackend::native_with_context(context))
    }
    #[cfg(windows)]
    {
        HardwareServiceBackend::new(platform, WindowsBackend::native_with_context(context))
    }
}

/// Proves development-helper authority from the current native process only.
fn current_process_is_authorized() -> bool {
    #[cfg(target_os = "macos")]
    {
        rdx_macos_native::current_process_is_privileged_service()
    }
    #[cfg(target_os = "linux")]
    {
        rdx_linux_native::current_process_is_privileged_service()
    }
    #[cfg(windows)]
    {
        rdx_windows_native::current_process_is_elevated()
    }
}

/// Runs development IPC under the same native owner required by recovery.
fn run_stdio_session(platform: ServicePlatform) -> Result<(), ()> {
    let context =
        ServiceExecutionContext::privileged_development_stdio(current_process_is_authorized());
    #[cfg(target_os = "macos")]
    let context = if context.direct_process_authorized() {
        context.with_macos_direct_worker_factory(
            rdx_macos_native::MacDirectWorkerFactory::for_current_privileged_process()
                .map_err(|_| ())?,
        )
    } else {
        context
    };
    // sudo itself supplies SUDO_UID for this debug-only inherited-pipe launch.
    let context = if let Some(owner) = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    {
        context.with_backup_owner(owner)
    } else {
        context
    };
    #[cfg(target_os = "macos")]
    let _ownership = if context.hardware_authorized() {
        // These guards must outlive the framed runtime and its joined recovery
        // worker, just as the authenticated endpoint's whole-session owner does.
        let namespace =
            rdx_macos_native::initialize_hardware_ownership_namespace().map_err(|_| ())?;
        let ownership = rdx_macos_native::try_acquire_hardware_ownership().map_err(|_| ())?;
        Some((namespace, ownership))
    } else {
        None
    };
    run_framed_service_with_context(
        readiness_backend(platform, context.duplicate_for_runtime()),
        io::stdin(),
        io::stdout(),
        context,
    )
    .map(|_| ())
    .map_err(|_| ())
}

/// Accepts only the fixed main-owned service invocation contract.
fn service_mode() -> Option<&'static str> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return None;
    }
    if arguments[0] != OsStr::new("--service-mode")
        || arguments[2] != OsStr::new("--protocol-version")
        || arguments[3] != OsStr::new(&SERVICE_PROTOCOL_VERSION.to_string())
    {
        return None;
    }
    let platform_endpoint_mode = if cfg!(target_os = "macos") {
        OsStr::new("launchd-socket")
    } else if cfg!(target_os = "linux") {
        OsStr::new("systemd-socket")
    } else if cfg!(windows) {
        OsStr::new("named-pipe")
    } else {
        OsStr::new("")
    };
    if arguments[1] == OsStr::new("stdio") && cfg!(debug_assertions) {
        Some("stdio")
    } else if !platform_endpoint_mode.is_empty() && arguments[1] == platform_endpoint_mode {
        Some("platform-endpoint")
    } else {
        None
    }
}

/// Runs one authenticated production endpoint for the current platform.
#[cfg(target_os = "macos")]
fn run_platform_endpoint(platform: ServicePlatform) -> Result<(), ()> {
    use rdx_macos_native::log_endpoint_phase;
    log_endpoint_phase("startup", None);
    let _namespace =
        rdx_macos_native::initialize_hardware_ownership_namespace().map_err(|error| {
            log_endpoint_phase("ownership-namespace", Some(error));
        })?;
    log_endpoint_phase("ownership-namespace", None);
    let requirement = embedded_macos_manager_designated_requirement().map_err(|_| {
        log_endpoint_phase(
            "embedded-trust-requirement",
            Some(rdx_macos_native::NativeError::AccessDenied),
        );
    })?;
    log_endpoint_phase("embedded-trust-requirement", None);
    let listener =
        rdx_macos_native::activate_launchd_manager_endpoint(&requirement).map_err(|error| {
            log_endpoint_phase("launchd-activation", Some(error));
        })?;
    log_endpoint_phase("launchd-activation", None);
    for _ in 0..rdx_macos_native::launchd_endpoint_contract().max_connections {
        let mut connection = match listener.accept() {
            Ok(connection) => {
                log_endpoint_phase("authenticated-accept", None);
                connection
            }
            Err(error) => {
                log_endpoint_phase("authenticated-accept", Some(error));
                return classify_macos_endpoint_failure(error).map_err(|_| ());
            }
        };
        let worker_session = connection.begin_worker_session().map_err(|_| ())?;
        let reader = connection.try_clone().map_err(|_| ())?;
        let reader =
            HandshakeDeadlineReader::new(reader, FIRST_FRAME_TIMEOUT, |reader, timeout| {
                reader.set_read_timeout(timeout)
            })
            .map_err(|_| ())?;
        let context = ServiceExecutionContext::authenticated_platform_endpoint(
            rdx_macos_native::current_process_is_privileged_service(),
        );
        let context = context
            .with_backup_owner(connection.user_id())
            .with_macos_worker_factory(worker_session.factory());
        let outcome = run_owned_service_session(
            rdx_macos_native::try_acquire_hardware_ownership,
            macos_ownership_is_busy,
            || {
                run_framed_service_with_context(
                    readiness_backend(platform, context.duplicate_for_runtime()),
                    reader,
                    connection,
                    context,
                )
                .map_err(|_| rdx_macos_native::NativeError::Other)
            },
        )
        .map_err(|_| ())?;
        if outcome.is_none() {
            continue;
        }
    }
    Ok(())
}

/// Retire only an ordinary empty-listener timeout; launchd retains activation.
#[cfg(any(target_os = "macos", test))]
fn classify_macos_endpoint_failure(
    error: rdx_macos_native::NativeError,
) -> Result<(), rdx_macos_native::NativeError> {
    if error == rdx_macos_native::NativeError::TimedOut {
        Ok(())
    } else {
        Err(error)
    }
}

/// Runs one authenticated systemd socket connection on Linux.
#[cfg(target_os = "linux")]
fn run_platform_endpoint(platform: ServicePlatform) -> Result<(), ()> {
    let _namespace = rdx_linux_native::initialize_hardware_ownership_namespace().map_err(|_| ())?;
    let listener = rdx_linux_native::activate_systemd_manager_endpoint().map_err(|_| ())?;
    for _ in 0..rdx_linux_native::systemd_endpoint_contract().max_connections {
        let connection = match listener.accept() {
            Ok(connection) => connection,
            Err(error) => match classify_linux_endpoint_failure(error).map_err(|_| ())? {
                LinuxAcceptDisposition::RetireCleanly => return Ok(()),
            },
        };
        let reader = connection.try_clone().map_err(|_| ())?;
        let reader =
            HandshakeDeadlineReader::new(reader, FIRST_FRAME_TIMEOUT, |reader, timeout| {
                reader.set_read_timeout(timeout)
            })
            .map_err(|_| ())?;
        let context = ServiceExecutionContext::authenticated_platform_endpoint(
            rdx_linux_native::current_process_is_privileged_service(),
        );
        let outcome = run_owned_service_session(
            rdx_linux_native::try_acquire_hardware_ownership,
            linux_ownership_is_busy,
            || {
                run_framed_service_with_context(
                    readiness_backend(platform, context.duplicate_for_runtime()),
                    reader,
                    connection,
                    context,
                )
                .map_err(|_| rdx_linux_native::NativeError::Other)
            },
        )
        .map_err(|_| ())?;
        if outcome.is_none() {
            continue;
        }
    }
    Ok(())
}

/// Clean non-session outcomes from one bounded Linux socket-activation poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(target_os = "linux", test))]
enum LinuxAcceptDisposition {
    /// No manager connected; systemd retains the socket for future activation.
    RetireCleanly,
}

/// Treats only ordinary Linux idle timeout as successful socket retirement.
#[cfg(any(target_os = "linux", test))]
fn classify_linux_endpoint_failure(
    error: rdx_linux_native::NativeError,
) -> Result<LinuxAcceptDisposition, rdx_linux_native::NativeError> {
    if error == rdx_linux_native::NativeError::TimedOut {
        Ok(LinuxAcceptDisposition::RetireCleanly)
    } else {
        Err(error)
    }
}

/// Runs one authenticated protected named-pipe connection on Windows.
#[cfg(windows)]
fn run_platform_endpoint(_platform: ServicePlatform) -> Result<(), ()> {
    rdx_windows_native::run_windows_service_dispatcher(run_windows_service_generation)
        .map_err(|_| ())
}

/// Runs sequential authenticated pipe sessions inside the real SCM callback.
#[cfg(windows)]
fn run_windows_service_generation(
    lifecycle: rdx_windows_native::WindowsServiceLifecycle,
    mut listener: rdx_windows_native::NamedPipeManagerEndpointListener,
) -> Result<(), rdx_windows_native::NativeError> {
    let _namespace = rdx_windows_native::initialize_hardware_ownership_namespace()?;
    loop {
        if lifecycle.stop_requested() {
            return Ok(());
        }
        let admission = lifecycle.begin_connection()?;
        let connection = match listener.accept_until(|| lifecycle.stop_requested()) {
            Ok(connection) => connection,
            Err(error) => {
                drop(admission);
                match classify_windows_endpoint_failure(error, lifecycle.stop_requested())? {
                    WindowsAcceptDisposition::Idle => continue,
                    WindowsAcceptDisposition::Stop => return Ok(()),
                }
            }
        };
        if lifecycle.stop_requested() {
            drop(connection);
            drop(admission);
            return Ok(());
        }
        let reader = StopAwareReader::new(
            connection.try_clone()?,
            |reader, timeout| reader.set_read_timeout(timeout),
            {
                let lifecycle = lifecycle.clone();
                move || lifecycle.stop_requested()
            },
        );
        let stop_evidence = reader.stop_evidence();
        let framed_result = run_owned_service_session(
            rdx_windows_native::try_acquire_hardware_ownership,
            windows_ownership_is_busy,
            || {
                let context = ServiceExecutionContext::authenticated_platform_endpoint(true);
                let (backend, reader, connection) = windows_session::prepare_session(
                    || readiness_backend(ServicePlatform::Win32, context),
                    reader,
                    connection,
                    |reader, timeout| reader.set_read_timeout(timeout),
                    || lifecycle.stop_requested(),
                    Instant::now,
                )
                .map_err(|_| rdx_windows_native::NativeError::Other)?;
                run_framed_service_with_context(backend, reader, connection, context)
                    .map_err(|_| rdx_windows_native::NativeError::Other)
            },
        );
        match framed_result {
            Ok(None) => {
                drop(admission);
                continue;
            }
            Err(_) if !stop_evidence.load(Ordering::Acquire) && !lifecycle.stop_requested() => {
                return Err(rdx_windows_native::NativeError::Other);
            }
            // Both clean ServiceExit outcomes release this connection's admission.
            Ok(Some(_)) | Err(_) => {}
        }
        drop(admission);
        if stop_evidence.load(Ordering::Acquire) || lifecycle.stop_requested() {
            return Ok(());
        }
    }
}

/// Nonterminal outcomes from one bounded Windows accept poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(windows, test))]
enum WindowsAcceptDisposition {
    /// No manager connected during this bounded idle interval.
    Idle,
    /// SCM STOP/SHUTDOWN was independently observed.
    Stop,
}

/// Classifies idle polling separately from explicit lifecycle stop and errors.
#[cfg(any(windows, test))]
fn classify_windows_endpoint_failure(
    error: rdx_windows_native::NativeError,
    lifecycle_stop_observed: bool,
) -> Result<WindowsAcceptDisposition, rdx_windows_native::NativeError> {
    if error == rdx_windows_native::NativeError::Cancelled && lifecycle_stop_observed {
        Ok(WindowsAcceptDisposition::Stop)
    } else if error == rdx_windows_native::NativeError::TimedOut && !lifecycle_stop_observed {
        Ok(WindowsAcceptDisposition::Idle)
    } else {
        Err(error)
    }
}

/// Polling reader that turns STOP/SHUTDOWN into bounded framed-service EOF.
#[cfg(any(windows, test))]
struct StopAwareReader<R, F, S, N = fn() -> Instant> {
    inner: R,
    set_native_timeout: F,
    stop_requested: S,
    now: N,
    deadline: Option<Instant>,
    stop_observed: Arc<AtomicBool>,
}

#[cfg(any(windows, test))]
impl<R, F, S> StopAwareReader<R, F, S, fn() -> Instant>
where
    F: FnMut(&mut R, Option<Duration>) -> io::Result<()>,
    S: Fn() -> bool,
{
    /// Creates one polling reader without arming a transport timeout yet.
    fn new(inner: R, set_native_timeout: F, stop_requested: S) -> Self {
        Self::with_clock(inner, set_native_timeout, stop_requested, Instant::now)
    }
}

#[cfg(any(windows, test))]
impl<R, F, S, N> StopAwareReader<R, F, S, N>
where
    F: FnMut(&mut R, Option<Duration>) -> io::Result<()>,
    S: Fn() -> bool,
    N: Fn() -> Instant,
{
    /// Creates one polling reader with an explicit monotonic clock for deterministic tests.
    fn with_clock(inner: R, set_native_timeout: F, stop_requested: S, now: N) -> Self {
        Self {
            inner,
            set_native_timeout,
            stop_requested,
            now,
            deadline: None,
            stop_observed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Applies one absolute caller deadline while retaining bounded stop polls.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.deadline = timeout
            .map(|duration| {
                (self.now)()
                    .checked_add(duration)
                    .ok_or(io::ErrorKind::InvalidInput)
            })
            .transpose()?;
        self.arm_native_poll()
    }

    /// Arms one native poll no longer than the caller's remaining deadline.
    fn arm_native_poll(&mut self) -> io::Result<()> {
        let timeout = match self.deadline {
            Some(deadline) => deadline
                .checked_duration_since((self.now)())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?
                .min(STOP_POLL_INTERVAL),
            None => STOP_POLL_INTERVAL,
        };
        (self.set_native_timeout)(&mut self.inner, Some(timeout))
    }

    /// Returns the owned transport after endpoint processing or a test probe.
    #[cfg(test)]
    fn into_inner(self) -> R {
        self.inner
    }

    /// Shares durable evidence that this reader emitted lifecycle stop EOF.
    #[cfg(windows)]
    fn stop_evidence(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop_observed)
    }

    /// Reports whether this reader emitted lifecycle stop EOF.
    #[cfg(test)]
    fn stopped(&self) -> bool {
        self.stop_observed.load(Ordering::Acquire)
    }
}

#[cfg(any(windows, test))]
impl<R, F, S, N> Read for StopAwareReader<R, F, S, N>
where
    R: Read,
    F: FnMut(&mut R, Option<Duration>) -> io::Result<()>,
    S: Fn() -> bool,
    N: Fn() -> Instant,
{
    /// Reads until bytes arrive or the SCM atomically closes admission.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            if (self.stop_requested)() {
                self.stop_observed.store(true, Ordering::Release);
                return Ok(0);
            }
            self.arm_native_poll()?;
            match self.inner.read(buffer) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    if (self.stop_requested)() {
                        self.stop_observed.store(true, Ordering::Release);
                        return Ok(0);
                    }
                    if self
                        .deadline
                        .is_some_and(|deadline| (self.now)() >= deadline)
                    {
                        return Err(ErrorKind::TimedOut.into());
                    }
                    continue;
                }
                result => return result,
            }
        }
    }
}

/// Reports endpoint support as unavailable on unsupported compile targets.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn run_platform_endpoint(_platform: ServicePlatform) -> Result<(), ()> {
    Err(())
}

/// Runs the no-device service without writing non-protocol data to stdout.
fn main() -> ExitCode {
    install_process_panic_redaction();
    // This offline branch must precede every worker, backend, and endpoint owner.
    if let Some(exit) = recovery_status::run_if_requested(std::env::args_os().skip(1)) {
        return exit;
    }
    // Only an explicit administrator recovery invocation enters this one-shot path.
    if let Some(exit) = recovery_cli::run_if_requested(std::env::args_os().skip(1)) {
        return exit;
    }
    #[cfg(target_os = "macos")]
    {
        let mut arguments = std::env::args_os().skip(1);
        if arguments.next().as_deref() == Some(OsStr::new("--openrdx-internal-macos-scsi-worker"))
            && arguments.next().is_none()
        {
            if !current_process_is_authorized() {
                eprintln!("openrdx-hardware: internal worker authority unavailable");
                return ExitCode::from(3);
            }
            return match rdx_macos_native::run_scsi_worker_stdio() {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("openrdx-hardware: internal worker failure");
                    ExitCode::from(3)
                }
            };
        }
    }
    #[cfg(windows)]
    {
        let mut arguments = std::env::args_os().skip(1);
        if arguments.next().as_deref() == Some(OsStr::new("--openrdx-internal-vds-worker"))
            && arguments.next().is_none()
        {
            return ExitCode::from(rdx_windows_native::run_internal_vds_worker());
        }
    }
    let Some(mode) = service_mode() else {
        eprintln!("openrdx-hardware: invalid service arguments");
        return ExitCode::from(2);
    };
    let platform = match ServicePlatform::current() {
        Ok(platform) => platform,
        Err(_) => {
            eprintln!("openrdx-hardware: unsupported platform");
            return ExitCode::from(3);
        }
    };
    let result = if mode == "stdio" {
        run_stdio_session(platform)
    } else {
        run_platform_endpoint(platform)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("openrdx-hardware: service protocol failure");
            ExitCode::from(3)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LinuxAcceptDisposition, StopAwareReader, WindowsAcceptDisposition,
        classify_linux_endpoint_failure, classify_macos_endpoint_failure,
        classify_windows_endpoint_failure,
    };
    use rdx_windows_native::NativeError;
    use std::cell::Cell;
    use std::io::{self, Cursor, ErrorKind, Read};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct DropEvidence(Rc<Cell<bool>>);

    impl Drop for DropEvidence {
        /// Records the exact end of one injected ownership lifetime.
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    /// Backend execution remains inside the exact acquired ownership lifetime.
    #[test]
    fn owned_generation_retains_guard_through_execution() {
        let dropped = Rc::new(Cell::new(false));
        let observed = Rc::clone(&dropped);

        let result = super::run_owned_service_session(
            || Ok(DropEvidence(Rc::clone(&dropped))),
            |_: &()| false,
            || {
                assert!(!observed.get());
                Ok(7_u8)
            },
        );

        assert_eq!(result, Ok(Some(7)));
        assert!(dropped.get());
    }

    /// Both framed session exit reasons survive the owned Windows session boundary.
    #[test]
    fn owned_generation_preserves_framed_service_exit() {
        use rdx_service::service::ServiceExit;

        for outcome in [ServiceExit::EndOfInput, ServiceExit::ShutdownRequested] {
            let dropped = Rc::new(Cell::new(false));
            let result = super::run_owned_service_session(
                || Ok(DropEvidence(Rc::clone(&dropped))),
                |_: &()| false,
                || {
                    assert!(!dropped.get());
                    Ok(outcome)
                },
            );

            assert_eq!(result, Ok(Some(outcome)));
            assert!(dropped.get());
        }
    }

    /// Failed ownership never constructs or executes an unrelated backend.
    #[test]
    fn owned_generation_rejects_before_execution() {
        let executed = Cell::new(false);

        let result = super::run_owned_service_session::<(), _, _, _, _, _>(
            || Err(()),
            |_: &()| false,
            || {
                executed.set(true);
                Ok(7_u8)
            },
        );

        assert_eq!(result, Err(()));
        assert!(!executed.get());
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OwnershipError {
        Busy,
        Fatal,
    }

    /// Busy ownership rejects one session while a later session remains executable.
    #[test]
    fn busy_ownership_refuses_only_the_contended_session() {
        let executed = Cell::new(0_u8);
        let acquisitions = Cell::new(0_u8);

        let busy = super::run_owned_service_session::<(), _, _, _, _, _>(
            || {
                acquisitions.set(acquisitions.get() + 1);
                Err(OwnershipError::Busy)
            },
            |error| *error == OwnershipError::Busy,
            || {
                executed.set(executed.get() + 1);
                Ok(7_u8)
            },
        );
        let next = super::run_owned_service_session(
            || {
                acquisitions.set(acquisitions.get() + 1);
                Ok(())
            },
            |error: &OwnershipError| *error == OwnershipError::Busy,
            || {
                executed.set(executed.get() + 1);
                Ok(7_u8)
            },
        );

        assert_eq!(busy, Ok(None));
        assert_eq!(next, Ok(Some(7)));
        assert_eq!(acquisitions.get(), 2);
        assert_eq!(executed.get(), 1);
    }

    /// Non-busy ownership failures still retire the service generation.
    #[test]
    fn fatal_ownership_failure_still_retires_generation() {
        let executed = Cell::new(false);

        let result = super::run_owned_service_session::<(), u8, _, _, _, _>(
            || Err(OwnershipError::Fatal),
            |error| *error == OwnershipError::Busy,
            || {
                executed.set(true);
                Ok(7_u8)
            },
        );

        assert_eq!(result, Err(OwnershipError::Fatal));
        assert!(!executed.get());
    }

    /// Every supported native Busy value selects the same session-local refusal.
    #[test]
    fn native_busy_classification_is_cross_platform_and_exact() {
        assert!(super::macos_ownership_is_busy(
            &rdx_macos_native::NativeError::Busy
        ));
        assert!(super::linux_ownership_is_busy(
            &rdx_linux_native::NativeError::Busy
        ));
        assert!(super::windows_ownership_is_busy(
            &rdx_windows_native::NativeError::Busy
        ));
        assert!(!super::macos_ownership_is_busy(
            &rdx_macos_native::NativeError::AccessDenied
        ));
        assert!(!super::linux_ownership_is_busy(
            &rdx_linux_native::NativeError::AccessDenied
        ));
        assert!(!super::windows_ownership_is_busy(
            &rdx_windows_native::NativeError::AccessDenied
        ));
    }

    #[derive(Debug, Default)]
    struct ImmediateTimeoutReader {
        reads: usize,
        timeout_updates: Vec<Option<Duration>>,
    }

    impl Read for ImmediateTimeoutReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            Err(ErrorKind::TimedOut.into())
        }
    }

    #[test]
    fn stop_polling_preserves_the_absolute_handshake_deadline() {
        let fixture = ImmediateTimeoutReader::default();
        let clock_reads = Cell::new(0_u8);
        let origin = Instant::now();
        let mut reader = StopAwareReader::with_clock(
            fixture,
            |fixture, timeout| {
                fixture.timeout_updates.push(timeout);
                Ok(())
            },
            || false,
            || {
                let read = clock_reads.get();
                clock_reads.set(read + 1);
                if read < 3 {
                    origin
                } else {
                    origin + Duration::from_millis(2)
                }
            },
        );
        reader
            .set_read_timeout(Some(Duration::from_millis(2)))
            .unwrap();

        let error = reader.read(&mut [0_u8; 1]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::TimedOut);
        let fixture = reader.into_inner();
        assert!(fixture.reads > 0);
        assert!(
            fixture
                .timeout_updates
                .iter()
                .all(|timeout| timeout.is_some())
        );
    }

    #[test]
    fn stop_during_accept_is_clean_only_for_the_explicit_cancel_signal() {
        assert_eq!(
            classify_windows_endpoint_failure(NativeError::Cancelled, true),
            Ok(WindowsAcceptDisposition::Stop)
        );
        assert_eq!(
            classify_windows_endpoint_failure(NativeError::TimedOut, true),
            Err(NativeError::TimedOut)
        );
        assert_eq!(
            classify_windows_endpoint_failure(NativeError::Other, true),
            Err(NativeError::Other)
        );
    }

    #[test]
    fn idle_accept_timeout_keeps_service_admission_open() {
        assert_eq!(
            classify_windows_endpoint_failure(NativeError::TimedOut, false),
            Ok(WindowsAcceptDisposition::Idle)
        );
        assert_eq!(
            classify_windows_endpoint_failure(NativeError::Other, false),
            Err(NativeError::Other)
        );
    }

    #[test]
    fn macos_idle_accept_timeout_is_the_only_clean_listener_retirement() {
        use rdx_macos_native::NativeError;
        assert_eq!(
            classify_macos_endpoint_failure(NativeError::TimedOut),
            Ok(())
        );
        for error in [
            NativeError::Other,
            NativeError::AccessDenied,
            NativeError::TransportUnavailable,
        ] {
            assert_eq!(classify_macos_endpoint_failure(error), Err(error));
        }
    }

    #[test]
    fn linux_idle_accept_timeout_retires_socket_activated_service_cleanly() {
        assert_eq!(
            classify_linux_endpoint_failure(rdx_linux_native::NativeError::TimedOut),
            Ok(LinuxAcceptDisposition::RetireCleanly)
        );
        assert_eq!(
            classify_linux_endpoint_failure(rdx_linux_native::NativeError::Other),
            Err(rdx_linux_native::NativeError::Other)
        );
    }

    #[derive(Debug)]
    struct PartialThenTimeoutReader {
        bytes: Cursor<Vec<u8>>,
        stop: Rc<Cell<bool>>,
    }

    impl Read for PartialThenTimeoutReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.bytes.position() < self.bytes.get_ref().len() as u64 {
                let count = self.bytes.read(buffer)?;
                self.stop.set(true);
                return Ok(count);
            }
            Err(ErrorKind::TimedOut.into())
        }
    }

    #[test]
    fn stop_during_partial_frame_becomes_explicit_clean_eof() {
        let stop = Rc::new(Cell::new(false));
        let fixture = PartialThenTimeoutReader {
            bytes: Cursor::new(vec![0, 0]),
            stop: Rc::clone(&stop),
        };
        let mut reader =
            StopAwareReader::new(fixture, |_fixture, _timeout| Ok(()), move || stop.get());
        let mut prefix = [0_u8; 4];

        assert_eq!(reader.read(&mut prefix).unwrap(), 2);
        assert_eq!(reader.read(&mut prefix[2..]).unwrap(), 0);
        assert!(reader.stopped());
    }
}

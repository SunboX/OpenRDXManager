// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable Windows service lifecycle and target-gated SCM dispatcher.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::NativeError;
use crate::endpoint::NamedPipeManagerEndpointListener;

#[cfg(any(windows, test))]
pub(crate) mod diagnostics;
#[cfg(any(windows, test))]
mod startup;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
#[cfg(windows)]
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};

const MAX_SERVICE_CONNECTIONS: u32 = 8;
#[cfg(windows)]
const SERVICE_NAME: &str = "OpenRDXHardwareService";

/// Endpoint-creation capability minted only in the private registered SCM callback.
#[cfg(windows)]
pub(crate) struct RegisteredServiceStartup {
    trust: Arc<crate::local_trust::windows::RuntimeLease>,
}

#[cfg(windows)]
impl RegisteredServiceStartup {
    /// Verifies native startup facts after handler registration and status publication.
    fn verify(lifecycle: &WindowsServiceLifecycle) -> Result<Self, NativeError> {
        if lifecycle.snapshot().state() != WindowsServiceState::StartPending {
            return Err(NativeError::AccessDenied);
        }
        let trust = Arc::new(crate::native::verify_service_startup()?);
        // Ordinary Managers must inspect this verified service's identity. Grant
        // only query rights on our live objects, never the token's default DACL.
        diagnostics::record(
            diagnostics::Stage::ServiceQueryAccess,
            crate::service_identity_access::prepare_current_service_identity_queries(),
        )?;
        if lifecycle.stop_requested() {
            return Err(NativeError::Cancelled);
        }
        Ok(Self { trust })
    }

    /// Transfers retained runtime protection into the sole authoritative listener.
    pub(crate) fn into_runtime(self) -> Arc<crate::local_trust::windows::RuntimeLease> {
        self.trust
    }
}

/// Main-owned work executed only inside the registered SCM service callback.
pub type WindowsServiceRunner =
    fn(WindowsServiceLifecycle, NamedPipeManagerEndpointListener) -> Result<(), NativeError>;

#[cfg(windows)]
static SERVICE_RUNNER: Mutex<Option<WindowsServiceRunner>> = Mutex::new(None);
#[cfg(windows)]
static SERVICE_RESULT: Mutex<Option<Result<(), NativeError>>> = Mutex::new(None);

/// SCM-visible lifecycle states published by the hardware service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsServiceState {
    /// The control handler is registered and initialization is bounded.
    StartPending,
    /// The service accepts STOP/SHUTDOWN and may admit manager connections.
    Running,
    /// Admission is closed while existing owned work drains.
    StopPending,
    /// All connection ownership is released and the process may exit.
    Stopped,
}

#[derive(Debug)]
struct LifecycleInner {
    state: WindowsServiceState,
    active_connections: u32,
    endpoint_bound: bool,
    served_connections: u32,
    max_concurrent_connections: u32,
    win32_exit_code: u32,
}

/// Thread-safe admission and drain state shared with the SCM control handler.
#[derive(Clone, Debug)]
pub struct WindowsServiceLifecycle {
    inner: Arc<Mutex<LifecycleInner>>,
}

impl WindowsServiceLifecycle {
    /// Creates one bounded service generation in `START_PENDING`.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::InvalidRequest`] unless the concurrent connection
    /// budget is between one and the declared eight-instance endpoint limit.
    pub fn new(max_concurrent_connections: u32) -> Result<Self, NativeError> {
        if !(1..=MAX_SERVICE_CONNECTIONS).contains(&max_concurrent_connections) {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(LifecycleInner {
                state: WindowsServiceState::StartPending,
                active_connections: 0,
                endpoint_bound: false,
                served_connections: 0,
                max_concurrent_connections,
                win32_exit_code: 0,
            })),
        })
    }

    /// Records retention of the authoritative first protected pipe instance.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::AccessDenied`] unless startup is still pending and
    /// this is the first endpoint-bound transition.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn mark_endpoint_bound(&self) -> Result<(), NativeError> {
        let mut inner = self.lock();
        if inner.state != WindowsServiceState::StartPending || inner.endpoint_bound {
            return Err(NativeError::AccessDenied);
        }
        inner.endpoint_bound = true;
        Ok(())
    }

    /// Opens connection admission only after the first pipe instance is retained.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::AccessDenied`] unless this is the single valid
    /// `START_PENDING` to `RUNNING` transition.
    pub fn mark_running(&self) -> Result<(), NativeError> {
        let mut inner = self.lock();
        if inner.state != WindowsServiceState::StartPending || !inner.endpoint_bound {
            return Err(NativeError::AccessDenied);
        }
        inner.state = WindowsServiceState::Running;
        Ok(())
    }

    /// Atomically closes admission for the first STOP or SHUTDOWN request.
    ///
    /// Returns `true` only for the transition that first enters
    /// `STOP_PENDING`; repeated controls are idempotent.
    pub fn request_stop(&self) -> bool {
        let mut inner = self.lock();
        if matches!(
            inner.state,
            WindowsServiceState::StartPending | WindowsServiceState::Running
        ) {
            inner.state = WindowsServiceState::StopPending;
            true
        } else {
            false
        }
    }

    /// Acquires one RAII connection-admission lease before native accept.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::AccessDenied`] after STOP/SHUTDOWN and
    /// [`NativeError::ResourceLimit`] while all concurrent pipe instances are
    /// owned. Completed sequential sessions never retire the service.
    pub fn begin_connection(&self) -> Result<WindowsServiceConnection, NativeError> {
        let mut inner = self.lock();
        if inner.state != WindowsServiceState::Running {
            return Err(NativeError::AccessDenied);
        }
        if inner.active_connections >= inner.max_concurrent_connections {
            return Err(NativeError::ResourceLimit);
        }
        inner.active_connections += 1;
        inner.served_connections = inner.served_connections.saturating_add(1);
        Ok(WindowsServiceConnection {
            lifecycle: self.clone(),
        })
    }

    /// Reports whether STOP/SHUTDOWN has atomically closed admission.
    #[must_use]
    pub fn stop_requested(&self) -> bool {
        matches!(
            self.lock().state,
            WindowsServiceState::StopPending | WindowsServiceState::Stopped
        )
    }

    /// Transitions to `STOPPED` only after every connection lease drains.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::Busy`] while any accepted/accepting connection is
    /// still owned, or [`NativeError::AccessDenied`] after a duplicate finish.
    pub fn finish(&self, win32_exit_code: u32) -> Result<(), NativeError> {
        let mut inner = self.lock();
        if inner.active_connections != 0 {
            return Err(NativeError::Busy);
        }
        if inner.state == WindowsServiceState::Stopped {
            return Err(NativeError::AccessDenied);
        }
        inner.state = WindowsServiceState::Stopped;
        inner.win32_exit_code = win32_exit_code;
        Ok(())
    }

    /// Copies one pointer-free state snapshot for status publication/testing.
    #[must_use]
    pub fn snapshot(&self) -> WindowsServiceSnapshot {
        let inner = self.lock();
        WindowsServiceSnapshot {
            state: inner.state,
            active_connections: inner.active_connections,
            served_connections: inner.served_connections,
            win32_exit_code: inner.win32_exit_code,
        }
    }

    /// Acquires the non-panicking internal lifecycle lock.
    fn lock(&self) -> MutexGuard<'_, LifecycleInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One active/accepting service connection released exactly once on drop.
#[derive(Debug)]
pub struct WindowsServiceConnection {
    lifecycle: WindowsServiceLifecycle,
}

impl Drop for WindowsServiceConnection {
    /// Releases one exact active connection count on every exit path.
    fn drop(&mut self) {
        let mut inner = self.lifecycle.lock();
        debug_assert!(inner.active_connections > 0);
        inner.active_connections = inner.active_connections.saturating_sub(1);
    }
}

/// Pointer-free copy of SCM lifecycle evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsServiceSnapshot {
    state: WindowsServiceState,
    active_connections: u32,
    served_connections: u32,
    win32_exit_code: u32,
}

impl WindowsServiceSnapshot {
    /// Returns the exact SCM lifecycle state.
    #[must_use]
    pub const fn state(self) -> WindowsServiceState {
        self.state
    }

    /// Returns whether STOP and SHUTDOWN controls are currently accepted.
    #[must_use]
    pub const fn accepts_stop_or_shutdown(self) -> bool {
        matches!(self.state, WindowsServiceState::Running)
    }

    /// Returns the currently retained connection-ownership count.
    #[must_use]
    pub const fn active_connections(self) -> u32 {
        self.active_connections
    }

    /// Returns connection attempts admitted in this bounded generation.
    #[must_use]
    pub const fn served_connections(self) -> u32 {
        self.served_connections
    }

    /// Returns the final Win32 exit code, zero until stopped successfully.
    #[must_use]
    pub const fn win32_exit_code(self) -> u32 {
        self.win32_exit_code
    }
}

/// Enters the real Windows SCM dispatcher and runs one bounded service generation.
///
/// The dispatcher registers STOP/SHUTDOWN handling, publishes
/// `START_PENDING`, `RUNNING`, `STOP_PENDING`, and `STOPPED`, and does not call
/// `runner` outside the SCM-owned service callback.
///
/// # Errors
///
/// Returns a sanitized dispatch, registration, status-publication, lifecycle,
/// or runner failure. On non-Windows targets it returns `UnsupportedPlatform`.
pub fn run_windows_service_dispatcher(runner: WindowsServiceRunner) -> Result<(), NativeError> {
    #[cfg(windows)]
    {
        {
            let mut slot = SERVICE_RUNNER
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if slot.is_some() {
                return Err(NativeError::Busy);
            }
            *slot = Some(runner);
        }
        *SERVICE_RESULT
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;

        let mut service_name = wide_null(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(service_name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];
        // SAFETY: the table is NUL-terminated, its name storage remains live for
        // the blocking dispatcher call, and the callback has the required ABI.
        let dispatched = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        *SERVICE_RUNNER
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        dispatched.map_err(|_| NativeError::AccessDenied)?;
        SERVICE_RESULT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or(Err(NativeError::Other))
    }
    #[cfg(not(windows))]
    {
        let _ = runner;
        Err(NativeError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
struct ServiceControlContext {
    lifecycle: WindowsServiceLifecycle,
    reporter: Mutex<ServiceStatusReporter>,
}

#[cfg(windows)]
struct ServiceStatusReporter {
    handle: isize,
    checkpoint: u32,
    failure_code: u32,
}

#[cfg(windows)]
impl ServiceStatusReporter {
    /// Publishes one exact state snapshot to the SCM.
    fn publish(&mut self, snapshot: WindowsServiceSnapshot) -> Result<(), NativeError> {
        let (state, controls, wait_hint) = match snapshot.state() {
            WindowsServiceState::StartPending => (SERVICE_START_PENDING, 0, 10_000),
            WindowsServiceState::Running => (
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                0,
            ),
            WindowsServiceState::StopPending => (SERVICE_STOP_PENDING, 0, 12_000),
            WindowsServiceState::Stopped => (SERVICE_STOPPED, 0, 0),
        };
        self.checkpoint = if matches!(
            snapshot.state(),
            WindowsServiceState::StartPending | WindowsServiceState::StopPending
        ) {
            self.checkpoint.saturating_add(1)
        } else {
            0
        };
        let (win32_exit, specific_exit) =
            diagnostics::status_exit_codes(snapshot.win32_exit_code(), self.failure_code);
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls,
            dwWin32ExitCode: win32_exit,
            dwServiceSpecificExitCode: specific_exit,
            dwCheckPoint: self.checkpoint,
            dwWaitHint: wait_hint,
        };
        // SAFETY: the SCM supplied this nonzero status handle and status points
        // to initialized storage for the duration of the synchronous call.
        unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(self.handle as *mut c_void), &status) }
            .map_err(|_| NativeError::Other)
    }
}

#[cfg(windows)]
impl ServiceControlContext {
    /// Publishes the lifecycle's current pointer-free snapshot.
    fn publish(&self) -> Result<(), NativeError> {
        self.reporter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .publish(self.lifecycle.snapshot())
    }
}

#[cfg(windows)]
unsafe extern "system" fn service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    if context.is_null() {
        return ERROR_CALL_NOT_IMPLEMENTED.0;
    }
    if control != SERVICE_CONTROL_STOP && control != SERVICE_CONTROL_SHUTDOWN {
        return ERROR_CALL_NOT_IMPLEMENTED.0;
    }
    // SAFETY: service_main registers the Arc-owned context pointer and retains
    // that Arc until after STOPPED is published and the callback returns.
    let control_context = unsafe { &*context.cast::<ServiceControlContext>() };
    control_context.lifecycle.request_stop();
    match control_context.publish() {
        Ok(()) => NO_ERROR.0,
        Err(_) => ERROR_SERVICE_SPECIFIC_ERROR.0,
    }
}

#[cfg(windows)]
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let result = run_registered_service();
    *SERVICE_RESULT
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(result);
}

#[cfg(windows)]
fn run_registered_service() -> Result<(), NativeError> {
    diagnostics::begin_attempt();
    let runner = SERVICE_RUNNER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .ok_or(NativeError::Other)?;
    let lifecycle = WindowsServiceLifecycle::new(MAX_SERVICE_CONNECTIONS)?;
    let service_name = wide_null(SERVICE_NAME);
    let control = Arc::new(ServiceControlContext {
        lifecycle: lifecycle.clone(),
        reporter: Mutex::new(ServiceStatusReporter {
            handle: 0,
            checkpoint: 0,
            failure_code: 1,
        }),
    });
    // SAFETY: the service name is NUL-terminated, the handler has the required
    // ABI, and the Arc keeps the context alive through final status publication.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            PCWSTR(service_name.as_ptr()),
            Some(service_control_handler),
            Some(Arc::as_ptr(&control).cast()),
        )
    }
    .map_err(|_| NativeError::AccessDenied)?;
    control
        .reporter
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .handle = handle.0 as isize;
    let run_result = (|| {
        let listener = startup::start_endpoint(
            &lifecycle,
            || control.publish(),
            || {
                NamedPipeManagerEndpointListener::bind(RegisteredServiceStartup::verify(
                    &lifecycle,
                )?)
            },
        )?;
        match listener {
            Some(listener) => runner(lifecycle.clone(), listener),
            None => Ok(()),
        }
    })();
    if let Err(error) = run_result {
        control
            .reporter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .failure_code = diagnostics::failure_code(error);
    }
    lifecycle.request_stop();
    let pending_result = control.publish();
    let exit_code = if run_result.is_ok() {
        NO_ERROR.0
    } else {
        ERROR_SERVICE_SPECIFIC_ERROR.0
    };
    let finish_result = lifecycle.finish(exit_code);
    let stopped_result = finish_result.and_then(|()| control.publish());
    run_result.and(pending_result).and(stopped_result)
}

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

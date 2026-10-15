// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Only this private CPAsUser factory creates debug ownership; event handles are separate OS leases.
use super::modules::Modules;
use super::protocol::{Continue, Event, EventPolicy, Exception, Exit, HandleLedger, Kind, Module};
use super::*;
use std::mem::ManuallyDrop;
use std::os::windows::io::FromRawHandle;
use windows::Win32::Foundation::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    ERROR_SEM_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
use windows::Win32::System::Diagnostics::Debug::*;
use windows::Win32::System::Threading::DEBUG_ONLY_THIS_PROCESS;

/// Owns only a file handle returned in an event; one explicit close attempt even on failure.
struct EventFile(HANDLE);
impl EventFile {
    /// Closing cannot grant successful protocol or hide a primary SDK error.
    fn close(&mut self) -> Result<(), NativeError> {
        let handle = std::mem::take(&mut self.0);
        if !handle.is_invalid() {
            // SAFETY: only the returned event file belongs to this guard; process/thread leases never enter it.
            unsafe { CloseHandle(handle) }.map_err(map_native_error)?;
        }
        Ok(())
    }
}
impl Drop for EventFile {
    /// Every early return still attempts this event file's close exactly once.
    fn drop(&mut self) {
        let _ = self.close();
    }
}
/// Dedicated duplicates remain owned after Windows automatically closes debug-event handles.
pub(super) struct DebugOwnedChild {
    held: Option<OwnedChild>,
    originals: [HANDLE; 2],
    ledger: HandleLedger,
    policy: EventPolicy,
    modules: Modules,
    files_closed: bool,
    end: Instant,
    creator: std::thread::ThreadId,
    pid: u32,
    initial: u32,
    emit_events: bool,
    natural: Option<Exit>,
    image_identity: FileIdentity,
    image_digest: [u8; 32],
    proof: Option<TokenState>,
    reproduced: bool,
    changed: bool,
}
impl DebugOwnedChild {
    /// Fixed sibling constructor; only DEBUG_ONLY_THIS_PROCESS differs from ordinary creation.
    pub(super) fn create(
        fixture: &Fixture,
        derived: &MinimalDerivedToken,
        deadline: &Deadline,
    ) -> Result<Self, NativeError> {
        let modules = Modules::new();
        let application = wide_null(fixture.executable.as_os_str());
        let directory = wide_null(fixture.root.as_os_str());
        let mut desktop = wide_null(OsStr::new(r"winsta0\default"));
        let environment: Vec<u16> = "SystemRoot=C:\\Windows\0WINDIR=C:\\Windows\0\0"
            .encode_utf16()
            .collect();
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: exact fixed staged image and live private buffers; no inherited handles or caller options.
        unsafe {
            CreateProcessAsUserW(
                Some(derived.launch_token().0),
                PCWSTR(application.as_ptr()),
                None,
                None,
                None,
                false,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | DEBUG_ONLY_THIS_PROCESS,
                Some(environment.as_ptr().cast()),
                PCWSTR(directory.as_ptr()),
                &startup,
                &mut info,
            )
        }
        .map_err(map_native_error)?;
        // Retain the trusted returned handles immediately, before duplication or any PID validation.
        let mut owned = Self {
            held: Some(OwnedChild {
                process: OwnedHandle(info.hProcess),
                thread: OwnedHandle(info.hThread),
                reaped: false,
            }),
            originals: [HANDLE::default(); 2],
            ledger: HandleLedger::new(info.hProcess.0 as usize, info.hThread.0 as usize),
            policy: EventPolicy::new(info.dwProcessId, info.dwThreadId),
            modules,
            files_closed: true,
            end: deadline.0,
            creator: std::thread::current().id(),
            pid: info.dwProcessId,
            initial: info.dwThreadId,
            emit_events: false,
            natural: None,
            reproduced: false,
            changed: false,
            image_identity: FileIdentity {
                volume: fixture.identity.volume,
                index_high: fixture.identity.index_high,
                index_low: fixture.identity.index_low,
            },
            image_digest: fixture.digest,
            proof: None,
        };
        owned.duplicate_held()?;
        // PID values authorize only this returned connection, never discovery or attachment.
        if owned.pid == 0 || owned.initial == 0 || owned.pid == std::process::id() {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(owned)
    }
    /// Moves original PI closure to the ledger while replacing each proof/reap handle with its owned duplicate.
    fn duplicate_held(&mut self) -> Result<(), NativeError> {
        let child = self.held.as_mut().ok_or(NativeError::Other)?;
        for (index, handle) in [&mut child.process, &mut child.thread]
            .into_iter()
            .enumerate()
        {
            let mut duplicate = HANDLE::default();
            // SAFETY: duplicate only this owned returned handle, preserving rights and forbidding inheritance.
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle.0,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            }
            .map_err(map_native_error)?;
            self.originals[index] = std::mem::replace(&mut handle.0, duplicate);
        }
        Ok(())
    }
    /// Borrows only the factory-held owned duplicate, never an event handle or PID-opened object.
    pub(super) fn child(&self) -> Result<&OwnedChild, NativeError> {
        self.held.as_ref().ok_or(NativeError::Other)
    }
    /// Captures full actual primary state after the protected image/medium/current-console proof.
    pub(super) fn capture_proof(
        &mut self,
        fixture: &Fixture,
        source: &SourceContext,
        derived: &MinimalDerivedToken,
    ) -> Result<(), NativeError> {
        source.unchanged()?;
        derived.unchanged(source)?;
        prove_child_quiet(
            self.child()?,
            fixture,
            &source.state.snapshot,
            &source.console,
            source.session,
        )?;
        let actual = context::read_child(self.child()?)?;
        if actual.snapshot != derived.observed()?.snapshot {
            return Err(NativeError::AccessDenied);
        }
        self.proof = Some(actual);
        Ok(())
    }
    /// Complete state checks finish BEFORE the inseparable final quiet proof and one ResumeThread.
    pub(super) fn prove_and_resume(
        &mut self,
        fixture: &Fixture,
        source: &SourceContext,
        derived: &MinimalDerivedToken,
    ) -> Result<(), NativeError> {
        source.unchanged()?;
        derived.unchanged(source)?;
        let actual = context::read_child(self.child()?)?;
        actual.require_same(self.proof.as_ref().ok_or(NativeError::EvidenceIncomplete)?)?;
        if actual.snapshot != derived.observed()?.snapshot {
            return Err(NativeError::AccessDenied);
        }
        Deadline(self.end).require_launch()?;
        prove_child_quiet(
            self.child()?,
            fixture,
            &source.state.snapshot,
            &source.console,
            source.session,
        )?;
        self.child()?.resume()
    }
    /// Requires the actual event image handle to identify the pinned fixture, without adopting its ownership.
    fn prove_event_image(&self, file: HANDLE) -> Result<(), NativeError> {
        if file.is_invalid() {
            return Err(NativeError::EvidenceIncomplete);
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: live event file handle, exact SDK output.
        unsafe { GetFileInformationByHandle(file, &mut info) }.map_err(map_native_error)?;
        if info.dwVolumeSerialNumber != self.image_identity.volume
            || info.nFileIndexHigh != self.image_identity.index_high
            || info.nFileIndexLow != self.image_identity.index_low
        {
            return Err(NativeError::AccessDenied);
        }
        // SAFETY: temporary borrowed File view; ManuallyDrop leaves the single event guard in charge of closure.
        let mut borrowed = ManuallyDrop::new(unsafe { File::from_raw_handle(file.0) });
        if fixture::hash(&mut borrowed)? != self.image_digest {
            return Err(NativeError::AccessDenied);
        }
        Ok(())
    }
    /// Decodes only the active SDK union member; an event-file guard exists before every fallible observation.
    fn consume(&mut self, event: DEBUG_EVENT) -> Result<(), NativeError> {
        // SAFETY: SDK event code determines exactly which returned union member contains an owned file.
        let file = unsafe {
            match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => event.u.CreateProcessInfo.hFile,
                LOAD_DLL_DEBUG_EVENT => event.u.LoadDll.hFile,
                _ => HANDLE::default(),
            }
        };
        let mut file = EventFile(file);
        let decoded = (|| {
            if event.dwProcessId != self.pid {
                self.policy.continuation_failed();
                return Err(NativeError::EvidenceIncomplete);
            }
            // SAFETY: every branch reads only the union field for this exact documented SDK event code.
            let kind = unsafe {
                match event.dwDebugEventCode {
                    CREATE_PROCESS_DEBUG_EVENT => {
                        let created = event.u.CreateProcessInfo;
                        self.ledger
                            .event_process(
                                event.dwThreadId,
                                created.hProcess.0 as usize,
                                created.hThread.0 as usize,
                            )
                            .map_err(|_| NativeError::EvidenceIncomplete)?;
                        self.prove_event_image(file.0)?;
                        self.modules.load(
                            self.child()?.process.0,
                            file.0,
                            created.lpBaseOfImage as usize,
                            true,
                        );
                        Kind::CreateProcess
                    }
                    CREATE_THREAD_DEBUG_EVENT => {
                        self.ledger
                            .event_thread(event.dwThreadId, event.u.CreateThread.hThread.0 as usize)
                            .map_err(|_| NativeError::EvidenceIncomplete)?;
                        Kind::CreateThread
                    }
                    EXIT_THREAD_DEBUG_EVENT => Kind::ExitThread,
                    LOAD_DLL_DEBUG_EVENT => {
                        let loaded = event.u.LoadDll;
                        let base = loaded.lpBaseOfDll as usize;
                        let module =
                            self.modules
                                .load(self.child()?.process.0, file.0, base, false);
                        Kind::Load { module, base }
                    }
                    UNLOAD_DLL_DEBUG_EVENT => {
                        let base = event.u.UnloadDll.lpBaseOfDll as usize;
                        self.modules.unload(base);
                        Kind::Unload { base }
                    }
                    EXCEPTION_DEBUG_EVENT => {
                        let exception = event.u.Exception;
                        let (module, mapped) = self.modules.exception(
                            self.child()?.process.0,
                            exception.ExceptionRecord.ExceptionAddress,
                        );
                        Kind::Exception {
                            class: Exception::from_code(
                                exception.ExceptionRecord.ExceptionCode.0 as u32,
                            ),
                            first: exception.dwFirstChance != 0,
                            module,
                            mapped,
                        }
                    }
                    EXIT_PROCESS_DEBUG_EVENT => Kind::ExitProcess {
                        class: Exit::from_code(event.u.ExitProcess.dwExitCode),
                    },
                    OUTPUT_DEBUG_STRING_EVENT => Kind::DebugString,
                    RIP_EVENT => Kind::Rip,
                    _ => {
                        self.policy.continuation_failed();
                        return Err(NativeError::EvidenceIncomplete);
                    }
                }
            };
            let decision = self
                .policy
                .observe(Event {
                    pid: event.dwProcessId,
                    tid: event.dwThreadId,
                    kind,
                })
                .map_err(|_| NativeError::EvidenceIncomplete)?;
            let status = match decision {
                Continue::Handled => DBG_CONTINUE,
                Continue::NotHandled => DBG_EXCEPTION_NOT_HANDLED,
            };
            // SAFETY: only a policy-admitted event from this owned creation can be continued.
            let result = unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) }
                .map_err(map_native_error);
            if self.emit_events {
                self.emit(kind, result.is_ok());
            }
            let thread_lease = if matches!(kind, Kind::ExitThread) {
                self.ledger.thread_exit(event.dwThreadId, result.is_ok())
            } else {
                Ok(())
            };
            if let Err(error) = result {
                self.policy.continuation_failed();
                return Err(error);
            }
            self.policy
                .continued()
                .map_err(|_| NativeError::EvidenceIncomplete)?;
            thread_lease.map_err(|_| NativeError::EvidenceIncomplete)?;
            if let Kind::ExitProcess { class } = kind {
                self.natural = Some(class);
                self.ledger.continued_process_exit();
            }
            Ok(())
        })();
        let close = file.close();
        self.files_closed &= close.is_ok();
        match decoded {
            Err(error) => {
                self.policy.continuation_failed();
                Err(error)
            }
            Ok(()) => close,
        }
    }
    /// Formats only compiled categories; IDs, module bases and addresses never enter output.
    fn emit(&self, kind: Kind, continued: bool) {
        let (name, module, exception, first) = match kind {
            Kind::CreateProcess => ("create-process", Module::None, Exception::None, false),
            Kind::CreateThread => ("create-thread", Module::None, Exception::None, false),
            Kind::ExitThread => ("exit-thread", Module::None, Exception::None, false),
            Kind::Load { module, .. } => ("load", module, Exception::None, false),
            Kind::Unload { .. } => ("unload", Module::None, Exception::None, false),
            Kind::Exception {
                class,
                first,
                module,
                ..
            } => ("exception", module, class, first),
            Kind::ExitProcess { .. } => ("exit-process", Module::None, Exception::None, false),
            Kind::DebugString => ("debug-string", Module::None, Exception::None, false),
            Kind::Rip => ("rip", Module::None, Exception::None, false),
        };
        output::event(
            self.policy.slot(),
            name,
            module.label(),
            exception.label(),
            first,
            continued,
        );
    }
    /// One finite creator-thread wait; timeout differs from another API failure and never advances policy.
    fn poll(&mut self, milliseconds: u32) -> Result<bool, NativeError> {
        if self.creator != std::thread::current().id() {
            return Err(NativeError::Busy);
        }
        if !self.policy.can_wait() {
            return Err(NativeError::Busy);
        }
        let mut event = DEBUG_EVENT::default();
        // SAFETY: this method executes synchronously on the same creator thread; no APC or helper handoff.
        match unsafe { WaitForDebugEventEx(&mut event, milliseconds) } {
            Ok(()) => {
                self.consume(event)?;
                Ok(true)
            }
            Err(error)
                if error.code() == windows::core::HRESULT::from_win32(ERROR_SEM_TIMEOUT.0) =>
            {
                Ok(false)
            }
            Err(error) => Err(map_native_error(error)),
        }
    }
    /// Bounded natural observations; cleanup never repairs or changes the original primary result.
    pub(super) fn run_events(&mut self, deadline: &Deadline) -> Result<(), NativeError> {
        self.emit_events = true;
        let observation_end = Instant::now() + Duration::from_millis(10_000);
        let mut window = protocol::ObservationWindow::new();
        let primary = (|| {
            while !self.policy.exit_continued() {
                let now = Instant::now();
                let remaining = deadline.remaining();
                if window.expired(now >= observation_end, remaining, self.policy.can_wait()) {
                    // Drain an already queued exit first; timeout alone must not misclassify a natural failure.
                    match self.poll(0) {
                        Ok(queued) => match window
                            .expiry_poll(queued, output::failed())
                            .map_err(|_| NativeError::Other)?
                        {
                            protocol::ExpiryPoll::Continue => continue,
                            protocol::ExpiryPoll::Survived => {
                                self.changed = true;
                                return Err(NativeError::TimedOut);
                            }
                        },
                        Err(error) => {
                            window.interrupt();
                            return Err(error);
                        }
                    }
                }
                // Do not round a positive final fractional millisecond down into an early timeout.
                let observation_remaining = observation_end
                    .saturating_duration_since(now)
                    .as_millis()
                    .max(1);
                let budget = match protocol::event_wait_budget(remaining, observation_remaining) {
                    Some(budget) => budget,
                    None => {
                        window.interrupt();
                        return Err(NativeError::TimedOut);
                    }
                };
                if let Err(error) = self.poll(budget) {
                    window.interrupt();
                    return Err(error);
                }
                window
                    .poll_output(output::failed())
                    .map_err(|_| NativeError::Other)?;
            }
            // OS exit-event handles may already be closed; only the dedicated owned duplicate is waited.
            let observed = self.held.as_mut().ok_or(NativeError::Other)?.wait(
                protocol::event_wait_budget(deadline.remaining(), 100)
                    .ok_or(NativeError::TimedOut)?,
            )?;
            self.reproduced = self.policy.reproduced() && observed == Some(0xc000_0142);
            self.changed = self.natural.is_some_and(|exit| exit != Exit::DllInitFailed);
            if !self.reproduced {
                return Err(NativeError::EvidenceIncomplete);
            }
            Ok(())
        })();
        // If waiting failed but the event protocol is still usable, drain within its SAME cap while active.
        if primary.is_err() {
            let _ = self.reap(deadline);
        }
        self.emit_events = false;
        output::facts(
            "debug-events",
            &[
                ("event-protocol", self.policy.exit_continued()),
                ("exit-continued", self.policy.exit_continued()),
                ("held-exit-match", self.reproduced),
                ("files-closed", self.files_closed),
            ],
        );
        primary
    }
    /// Terminates only the dedicated factory-held child; exit continuation must precede successful reap.
    pub(super) fn reap(&mut self, deadline: &Deadline) -> Result<(), NativeError> {
        if self.creator != std::thread::current().id() {
            return Err(NativeError::Busy);
        }
        if self.held.is_none() {
            return Ok(());
        }
        let end = Instant::now() + Duration::from_millis(3_000);
        if !self.policy.exit_continued() {
            // SAFETY: only this trusted returned child's retained duplicate is supplied, never a PID-opened process.
            unsafe { TerminateProcess(self.child()?.process.0, 19) }.map_err(map_native_error)?;
            while !self.policy.exit_continued() {
                let budget = deadline
                    .remaining()
                    .min(end.saturating_duration_since(Instant::now()).as_millis())
                    .min(100) as u32;
                if budget == 0 {
                    return Err(NativeError::TimedOut);
                }
                self.poll(budget)?;
            }
        }
        let remaining = deadline
            .remaining()
            .min(end.saturating_duration_since(Instant::now()).as_millis())
            as u32;
        if remaining == 0 {
            return Err(NativeError::TimedOut);
        }
        let child = self.held.as_mut().ok_or(NativeError::Other)?;
        if child.wait(remaining)?.is_none() {
            return Err(NativeError::Busy);
        }
        if !self.policy.exit_continued() {
            return Err(NativeError::Busy);
        }
        self.close_originals()?;
        self.held.take();
        Ok(())
    }
    /// Automatic event leases are never closed again; dedicated duplicates remain normal owned guards.
    fn close_originals(&mut self) -> Result<(), NativeError> {
        let mut first = None;
        for handle in &mut self.originals {
            let old = std::mem::take(handle);
            if self.ledger.caller_closes(old.0 as usize) {
                // SAFETY: exact original PI handle not leased to Windows; duplicate guard owns a different handle.
                if let Err(error) = unsafe { CloseHandle(old) } {
                    first.get_or_insert(map_native_error(error));
                }
            }
        }
        let ledger = &self.ledger;
        if let Some(child) = self.held.as_mut() {
            for handle in [&mut child.process, &mut child.thread] {
                // A duplication error may leave an original in the held guard; disarm it if OS already closed it.
                if !ledger.caller_closes(handle.0.0 as usize)
                    && ledger.is_original(handle.0.0 as usize)
                {
                    handle.0 = HANDLE::default();
                }
            }
        }
        first.map_or(Ok(()), Err)
    }
    /// Closed observations are independent from whether the overall native test returns success.
    pub(super) fn reproduction(&self) -> (bool, bool) {
        (self.reproduced, self.changed)
    }
}
impl Drop for DebugOwnedChild {
    /// Creation rejection still attempts same-thread drain/reap within the original global deadline.
    fn drop(&mut self) {
        self.emit_events = false;
        if self.held.is_some() && self.reap(&Deadline(self.end)).is_err() {
            // Unresolved event/PI/dedicated handles remain retained; State also retains all fixture pins.
            if let Some(child) = self.held.take() {
                std::mem::forget(child);
            }
        }
    }
}

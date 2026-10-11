// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fair bounded scheduling for framed input, backend events, and crash control.

use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Instant;

use serde_json::Value;

use super::crash::CrashAdmission;
use super::events::ServiceOperationSignal;
use super::framing::{read_frame, write_frame};
use super::{
    EVENT_POLL_INTERVAL, MAX_BACKEND_EVENT_BATCH, MAX_PENDING_SERVICE_EVENTS,
    MAX_PENDING_SERVICE_REQUESTS, ServiceBackend, ServiceEventSink, ServiceExecutionContext,
    ServiceExit, ServiceProtocolError, ServiceRuntime,
};

/// One complete input message or terminal reader observation.
pub(super) enum InputSignal {
    /// One decoded bounded JSON request.
    Message(Value),
    /// Clean end of the framed input stream.
    End,
    /// Terminal framing or input failure.
    Failure(ServiceProtocolError),
}

/// Reads complete bounded frames until EOF or the first protocol failure.
pub(super) fn read_loop<R: Read>(reader: &mut R, sender: SyncSender<InputSignal>) {
    loop {
        let signal = match read_frame(reader) {
            Ok(Some(value)) => InputSignal::Message(value),
            Ok(None) => InputSignal::End,
            Err(error) => InputSignal::Failure(error),
        };
        let terminal = !matches!(signal, InputSignal::Message(_));
        if sender.send(signal).is_err() || terminal {
            return;
        }
    }
}

/// Prioritizes a bounded backend-event quantum before the next input message.
pub(super) fn service_loop<B: ServiceBackend, W: Write>(
    runtime: &mut ServiceRuntime<B>,
    input: &Receiver<InputSignal>,
    events: &Receiver<Box<ServiceOperationSignal>>,
    crashes: &CrashAdmission,
    writer: &mut W,
) -> Result<ServiceExit, ServiceProtocolError> {
    let _disconnect_guard = crashes.disconnect_guard();
    loop {
        drain_backend_signals(runtime, events, crashes, writer)?;
        check_active_deadline(runtime)?;
        match input.recv_timeout(EVENT_POLL_INTERVAL) {
            Ok(InputSignal::Message(value)) => {
                let (messages, stop) = runtime.handle_message(value)?;
                for message in messages {
                    write_frame(writer, &message)?;
                }
                // A prepared native job is released only after every immediate
                // response from the admitting request has reached the framed writer.
                runtime.release_prepared_operation()?;
                runtime.recovery.release_prepared()?;
                if stop {
                    crashes.close()?;
                    return Ok(ServiceExit::ShutdownRequested);
                }
            }
            Ok(InputSignal::End) => {
                drain_backend_signals(runtime, events, crashes, writer)?;
                check_active_deadline(runtime)?;
                crashes.close()?;
                return Ok(ServiceExit::EndOfInput);
            }
            Ok(InputSignal::Failure(error)) => return Err(error),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                drain_backend_signals(runtime, events, crashes, writer)?;
                check_active_deadline(runtime)?;
                crashes.close()?;
                return Ok(ServiceExit::EndOfInput);
            }
        }
    }
}

/// Handles one fixed event quantum before honoring the reserved crash signal.
pub(super) fn drain_backend_signals<B: ServiceBackend, W: Write>(
    runtime: &mut ServiceRuntime<B>,
    events: &Receiver<Box<ServiceOperationSignal>>,
    crashes: &CrashAdmission,
    writer: &mut W,
) -> Result<(), ServiceProtocolError> {
    for _ in 0..MAX_BACKEND_EVENT_BATCH {
        let Ok(signal) = events.try_recv() else {
            break;
        };
        if let Some(report) = signal.inventory_update {
            write_frame(writer, &runtime.install_operation_inventory(report)?)?;
        }
        write_frame(
            writer,
            &runtime.handle_event_at_publication(
                signal.event,
                Some(signal.publication_sequence),
                Instant::now(),
            )?,
        )?;
    }
    crashes.observe()
}

/// Applies the absolute lifetime bound even when no backend event arrives.
fn check_active_deadline<B>(runtime: &ServiceRuntime<B>) -> Result<(), ServiceProtocolError> {
    runtime
        .active
        .as_ref()
        .map_or(Ok(()), |active| active.check_deadline(Instant::now()))
}

/// Runs a bounded framed generation without granting recovery authority.
///
/// Descriptor claims never substitute for trusted entrypoint process/endpoint
/// evidence. Existing test and custom backend callers therefore default closed.
/// # Errors
/// Returns an error for stream, strict protocol, or backend contract failures.
pub fn run_framed_service<B, R, W>(
    backend: B,
    reader: R,
    writer: W,
) -> Result<ServiceExit, ServiceProtocolError>
where
    B: ServiceBackend,
    R: Read + Send + 'static,
    W: Write,
{
    run_framed_service_with_context(
        backend,
        reader,
        writer,
        ServiceExecutionContext::development_stdio(),
    )
}

/// Runs one framed generation with trusted service startup authority.
///
/// The entrypoint must retain its global hardware owner until this returns.
/// Recovery teardown signals observer disconnection and joins its bounded native
/// calls before returning, so a capture cannot outlive the session owner. Native
/// transport calls have finite deadlines; this does not force-interrupt a USB
/// call or issue cleanup commands when the client disappears.
/// # Errors
/// Returns an error for stream, strict protocol, or backend contract failures.
pub fn run_framed_service_with_context<B, R, W>(
    backend: B,
    mut reader: R,
    mut writer: W,
    context: ServiceExecutionContext,
) -> Result<ServiceExit, ServiceProtocolError>
where
    B: ServiceBackend,
    R: Read + Send + 'static,
    W: Write,
{
    let (input_sender, input_receiver) =
        mpsc::sync_channel::<InputSignal>(MAX_PENDING_SERVICE_REQUESTS);
    let (event_sender, event_receiver) =
        mpsc::sync_channel::<Box<ServiceOperationSignal>>(MAX_PENDING_SERVICE_EVENTS);
    let crashes = CrashAdmission::new();
    let event_sink = ServiceEventSink::new(event_sender, crashes.clone());
    let mut runtime = ServiceRuntime::new_with_context(backend, event_sink, context);
    // Detach only the stream reader. Recovery's dedicated worker is always joined.
    let _reader = thread::spawn(move || read_loop(&mut reader, input_sender));
    service_loop(
        &mut runtime,
        &input_receiver,
        &event_receiver,
        &crashes,
        &mut writer,
    )
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit one-shot recovery CLI; ordinary service/status modes never enter it.

use rdx_service::service::recovery::{
    self, RecoveryError, RecoveryObserver, RecoveryOutcome, RecoveryStage,
};
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::process::ExitCode;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

/// Routes only this exact flag and one bundle identifier, before normal startup.
pub(super) fn run_if_requested(arguments: impl IntoIterator<Item = OsString>) -> Option<ExitCode> {
    let selected = select(arguments)?;
    Some(ExitCode::from(run(
        selected,
        io::stdin().is_terminal(),
        &mut io::stdout().lock(),
        recovery::recover_existing,
    )))
}

/// Rejects extra image, port, path or command parameters before recovery is invoked.
fn select(arguments: impl IntoIterator<Item = OsString>) -> Option<Result<String, RecoveryError>> {
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some(OsStr::new("--recover-migration")) {
        return None;
    }
    Some(match (arguments.next(), arguments.next()) {
        (Some(bundle), None) => bundle
            .into_string()
            .map_err(|_| RecoveryError::InvalidArguments),
        _ => Err(RecoveryError::InvalidArguments),
    })
}

/// A terminal is mandatory: a pipe cannot supply the explicit operator reply.
fn run(
    selected: Result<String, RecoveryError>,
    terminal: bool,
    output: &mut dyn Write,
    execute: impl FnOnce(&str, &mut dyn RecoveryObserver) -> Result<RecoveryOutcome, RecoveryError>,
) -> u8 {
    let result = match selected {
        Err(error) => Err(error),
        Ok(_) if !terminal => Err(RecoveryError::OperatorAcknowledgmentRequired),
        Ok(bundle) => {
            let mut observer = CliObserver {
                output,
                pending: None,
                acknowledgment_consumed: false,
                flush_input: discard_queued_input,
                start_input: begin_input,
            };
            execute(&bundle, &mut observer)
        }
    };
    let (value, code) = match result {
        Ok(RecoveryOutcome::FinalReleaseVerified) => (
            serde_json::json!({
                "ok": true, "code": "recovery-final-release-verified", "releaseVersion": "1.07",
                "recordsVerified": true
            }),
            0,
        ),
        Err(error) => (
            serde_json::json!({"ok": false, "code": error.code(),
            "completed": false, "automaticRetry": false}),
            3,
        ),
    };
    if write_json(output, &value).is_err() {
        3
    } else {
        code
    }
}

/// Flushes only fixed progress or result objects before the controller can continue.
fn write_json(output: &mut dyn Write, value: &serde_json::Value) -> Result<(), RecoveryError> {
    serde_json::to_writer(&mut *output, value).map_err(|_| RecoveryError::ObserverUnavailable)?;
    output
        .write_all(b"\n")
        .and_then(|()| output.flush())
        .map_err(|_| RecoveryError::ObserverUnavailable)
}

/// One separately armed prompt, with a background bounded read and nonblocking polls.
struct CliObserver<'output> {
    output: &'output mut dyn Write,
    pending: Option<Receiver<Result<(), RecoveryError>>>,
    acknowledgment_consumed: bool,
    flush_input: fn() -> Result<(), RecoveryError>,
    start_input: fn() -> Receiver<Result<(), RecoveryError>>,
}

impl RecoveryObserver for CliObserver<'_> {
    /// Arms reading only after the newly published prompt has been flushed.
    fn reached(&mut self, stage: RecoveryStage) -> Result<(), RecoveryError> {
        if stage == RecoveryStage::AwaitingPowerCycle {
            if self.pending.is_some() || self.acknowledgment_consumed {
                return Err(RecoveryError::OperatorAcknowledgmentRequired);
            }
            (self.flush_input)()?;
            write_json(
                self.output,
                &serde_json::json!({"stage": stage.code(),
                "instruction": "Disconnect and reconnect USB at the original captured port with J7 open. Then type POWER CYCLED and press Return. Do not change ports or insert a cartridge."}),
            )?;
            self.pending = Some((self.start_input)());
            Ok(())
        } else {
            write_json(self.output, &serde_json::json!({"stage": stage.code()}))
        }
    }

    /// EOF, invalid lines and channel failures cannot be interpreted as acknowledgment.
    fn operator_acknowledged(&mut self) -> Result<bool, RecoveryError> {
        if self.acknowledgment_consumed {
            return Err(RecoveryError::OperatorAcknowledgmentRequired);
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(RecoveryError::OperatorAcknowledgmentRequired)?;
        match pending.try_recv() {
            Ok(Ok(())) => {
                self.acknowledgment_consumed = true;
                self.pending = None;
                Ok(true)
            }
            Ok(Err(error)) => Err(error),
            Err(TryRecvError::Empty) => Ok(false),
            Err(TryRecvError::Disconnected) => Err(RecoveryError::OperatorAcknowledgmentRequired),
        }
    }
}

/// Discards pre-prompt terminal bytes once; failure leaves acknowledgment unarmed.
fn discard_queued_input() -> Result<(), RecoveryError> {
    #[cfg(target_os = "macos")]
    {
        rdx_macos_native::discard_recovery_terminal_input()
            .map_err(|_| RecoveryError::OperatorAcknowledgmentRequired)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(RecoveryError::UnsupportedPlatform)
    }
}

/// Starts only one bounded stdin line read; the controller independently times out.
fn begin_input() -> Receiver<Result<(), RecoveryError>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(read_acknowledgment(io::stdin()));
    });
    receiver
}

/// Accepts only the exact requested literal followed by a terminal newline.
fn read_acknowledgment(input: impl Read) -> Result<(), RecoveryError> {
    let mut line = Vec::new();
    io::BufReader::new(input)
        .take(33)
        .read_until(b'\n', &mut line)
        .map_err(|_| RecoveryError::OperatorAcknowledgmentRequired)?;
    if line == b"POWER CYCLED\n" || line == b"POWER CYCLED\r\n" {
        Ok(())
    } else {
        Err(RecoveryError::OperatorAcknowledgmentRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extra arguments and nonterminal input reject without invoking hardware code.
    #[test]
    fn invalid_invocation_never_enters_recovery() {
        let parsed =
            select(["--recover-migration", "migration-1-0", "--port"].map(OsString::from)).unwrap();
        assert!(parsed.is_err());
        assert_eq!(
            run(parsed, true, &mut Vec::new(), |_, _| panic!(
                "must not execute"
            )),
            3
        );
        assert_eq!(
            run(
                Ok("migration-1-0".into()),
                false,
                &mut Vec::new(),
                |_, _| panic!("must not execute")
            ),
            3
        );
        assert!(select([OsString::from("--service-mode")]).is_none());
    }

    /// Empty, partial, excessive, or approximate replies never satisfy the gate.
    #[test]
    fn operator_line_requires_the_literal_and_newline() {
        for value in [
            b"".as_slice(),
            b"POWER CYCLED",
            b"yes\n",
            b" POWER CYCLED\n",
            &[b'X'; 100],
        ] {
            assert!(read_acknowledgment(value).is_err());
        }
        assert!(read_acknowledgment(b"POWER CYCLED\n".as_slice()).is_ok());
        assert!(read_acknowledgment(b"POWER CYCLED\r\n".as_slice()).is_ok());
    }

    /// A fake reply is still consumed only once after the prompt has been armed.
    #[test]
    fn acknowledgment_is_separately_armed_and_single_use() {
        fn input() -> Receiver<Result<(), RecoveryError>> {
            let (sender, receiver) = mpsc::sync_channel(1);
            sender.send(Ok(())).unwrap();
            receiver
        }
        let mut output = Vec::new();
        let mut observer = CliObserver {
            output: &mut output,
            pending: None,
            acknowledgment_consumed: false,
            flush_input: || Ok(()),
            start_input: input,
        };
        assert!(observer.operator_acknowledged().is_err());
        observer.reached(RecoveryStage::AwaitingPowerCycle).unwrap();
        assert_eq!(observer.operator_acknowledged(), Ok(true));
        assert!(observer.operator_acknowledged().is_err());
    }

    /// A failed input flush cannot publish a prompt or start accepting queued input.
    #[test]
    fn failed_flush_keeps_acknowledgment_unarmed() {
        let mut output = Vec::new();
        let mut observer = CliObserver {
            output: &mut output,
            pending: None,
            acknowledgment_consumed: false,
            flush_input: || Err(RecoveryError::OperatorAcknowledgmentRequired),
            start_input: || panic!("must not read input"),
        };
        assert!(observer.reached(RecoveryStage::AwaitingPowerCycle).is_err());
        assert!(observer.pending.is_none());
        assert!(output.is_empty());
    }

    /// Failures never serialize the bundle identifier or claim completed installation.
    #[test]
    fn result_is_fixed_and_sanitized() {
        let mut output = Vec::new();
        assert_eq!(
            run(
                Ok("migration-dead-beef".into()),
                true,
                &mut output,
                |_, _| Err(RecoveryError::FinalUpdateUnknown)
            ),
            3
        );
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("migration-dead-beef"));
        assert!(text.contains("\"completed\":false"));
        assert!(text.contains("\"automaticRetry\":false"));
    }
}

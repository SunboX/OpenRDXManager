// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed eight-row, test-only object DACL matrix; completion is not ordinary child authorization.
use super::*;
#[path = "matrix_protocol.rs"]
mod matrix_protocol;
#[path = "owned_derived_token.rs"]
mod owned_derived_token;
use super::process_dacl_control::process_descriptor::{Components, ObjectRole};
use super::process_dacl_control::{Objects, PrivateDescriptor};
use matrix_protocol::Row;
use owned_derived_token::{FreshDerivedToken, SourceGuard};
use std::time::{Duration, Instant};
use windows::Win32::Security::{SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS};
use windows::Win32::System::Threading::{PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS};

/// Native work ends below the external 120-second capture deadline; reaping reserve precedes every launch.
struct Deadline(Instant);
impl Deadline {
    /// Starts once before any source/fixture work, never reset per row.
    fn start() -> Self {
        Self(Instant::now() + Duration::from_secs(90))
    }
    /// Reserves execution plus explicit, final and existing RAII bounded owned-handle reaping.
    fn launch(&self) -> Result<(), NativeError> {
        if matrix_protocol::launch_budget(
            self.0.saturating_duration_since(Instant::now()).as_millis(),
        ) {
            Ok(())
        } else {
            Err(NativeError::TimedOut)
        }
    }
}

/// One live child maximum; positive root belongs only to a row whose Wait image remains alive.
#[derive(Default)]
struct State {
    child: Option<OwnedChild>,
    positive: Option<Fixture>,
}
impl State {
    /// Reaps only retained creation handles, preserving ownership on unresolved cleanup.
    fn reap(&mut self) -> Result<(), NativeError> {
        if let Some(child) = &mut self.child {
            child.terminate_and_reap()?;
        }
        drop(self.child.take());
        Ok(())
    }
    /// Cleans both owned resources; no positive root is released while an owned child remains unresolved.
    fn cleanup(&mut self) -> Result<(), NativeError> {
        self.reap()?;
        if let Some(fixture) = &mut self.positive {
            fixture.cleanup()?;
        }
        drop(self.positive.take());
        Ok(())
    }
    /// Borrows only this state's exclusively owned created child, never a looked-up process.
    fn child(&self) -> Result<&OwnedChild, NativeError> {
        self.child.as_ref().ok_or(NativeError::Other)
    }
    /// Bounds a wait on the exclusive current child, preserving its private exact exit code.
    fn wait(&mut self, milliseconds: u32) -> Result<Option<u32>, NativeError> {
        self.child
            .as_mut()
            .ok_or(NativeError::Other)?
            .wait(milliseconds)
    }
}

/// Only compiled roles/phases/keys and booleans enter the compact matrix transcript.
fn facts(row: &'static str, phase: &'static str, values: &[(&'static str, bool)]) {
    println!(
        "openrdx-token-object-dacl-matrix row={row} phase={phase} {}",
        values
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
}
/// Closed ordered transition pairs retain original failure separately from subsequent cleanup.
fn checkpoint<T>(
    row: &'static str,
    phase: &'static str,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    println!("openrdx-token-object-dacl-matrix-stage row={row} phase={phase} status=begin");
    let result = operation();
    match &result {
        Ok(_) => {
            println!("openrdx-token-object-dacl-matrix-stage row={row} phase={phase} status=ok")
        }
        Err(error) => println!(
            "openrdx-token-object-dacl-matrix-stage row={row} phase={phase} status=failed reason={error:?}"
        ),
    }
    result
}
/// Reports the exact private exit only as a fixed category; alive means the bounded wait timed out.
fn wait(
    row: &'static str,
    phase: &'static str,
    state: &mut State,
    milliseconds: u32,
) -> Result<Option<u32>, NativeError> {
    let result = state.wait(milliseconds)?;
    let category = result.map(exit_status::category).unwrap_or("alive");
    println!("openrdx-token-object-dacl-matrix-exit row={row} phase={phase} category={category}");
    Ok(result)
}
/// Aliases only the established closed shared fixture vocabulary.
use super::exit_status;

/// Measures source immutability with API-query success separated from private exact comparison.
fn source_check(
    row: &'static str,
    phase: &'static str,
    source: &SourceGuard,
) -> Result<(), NativeError> {
    let observed = source.observations();
    let same = observed
        .as_ref()
        .is_ok_and(|values| values.iter().all(|value| *value));
    facts(
        row,
        phase,
        &[
            ("source-query-ok", observed.is_ok()),
            ("source-unchanged", same),
        ],
    );
    let values = observed.as_ref().copied().unwrap_or([false; 3]);
    facts(
        row,
        phase,
        &[
            ("source-properties-unchanged", values[0]),
            ("source-default-dacl-unchanged", values[1]),
            ("source-object-unchanged", values[2]),
        ],
    );
    observed?;
    if same {
        Ok(())
    } else {
        Err(NativeError::AccessDenied)
    }
}
/// Constructs correctly sized, noninheriting attributes over privately owned aligned descriptor bytes.
fn attributes(descriptor: &PrivateDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.pointer().0,
        bInheritHandle: false.into(),
    }
}

/// Expected readback contains precisely old components plus each compiled user ACE, with original denials intact.
struct Expected {
    process: PrivateDescriptor,
    thread: PrivateDescriptor,
    token: Components,
}
impl Expected {
    /// Builds masks only from the closed role enum, validated against actual SDK constants at setup.
    fn build(baseline: &Objects, row: Row, user: &OwnedSid) -> Result<Self, NativeError> {
        let [process, thread, token] = row.objects();
        let build = |original: &Components, enabled, role| {
            if enabled {
                original
                    .with_user_allow(user.bytes(), role)
                    .map_err(|_| NativeError::Other)
            } else {
                Ok(original.clone())
            }
        };
        let process = build(&baseline.process.components, process, ObjectRole::Process)?;
        let thread = build(&baseline.thread.components, thread, ObjectRole::Thread)?;
        Ok(Self {
            process: PrivateDescriptor::from_bytes(
                &process.bytes().map_err(|_| NativeError::Other)?,
            )?,
            thread: PrivateDescriptor::from_bytes(
                &thread.bytes().map_err(|_| NativeError::Other)?,
            )?,
            token: build(&baseline.token.components, token, ObjectRole::Token)?,
        })
    }
    /// Requires all canonical components exact; absence of token grant propagation forbids Resume.
    fn readback(
        &self,
        row: &'static str,
        phase: &'static str,
        child: &OwnedChild,
    ) -> Result<(), NativeError> {
        let observed = Objects::read(child);
        facts(row, phase, &[("query-ok", observed.is_ok())]);
        let observed = observed?;
        let process = observed.process.components == self.process.components;
        let thread = observed.thread.components == self.thread.components;
        let token = observed.token.components == self.token;
        for (kind, kept) in [
            (
                [
                    "process-owner-preserved",
                    "process-group-preserved",
                    "process-label-preserved",
                    "process-control-preserved",
                ],
                observed
                    .process
                    .components
                    .preservation(&self.process.components),
            ),
            (
                [
                    "thread-owner-preserved",
                    "thread-group-preserved",
                    "thread-label-preserved",
                    "thread-control-preserved",
                ],
                observed
                    .thread
                    .components
                    .preservation(&self.thread.components),
            ),
            (
                [
                    "token-owner-preserved",
                    "token-group-preserved",
                    "token-label-preserved",
                    "token-control-preserved",
                ],
                observed.token.components.preservation(&self.token),
            ),
        ] {
            facts(
                row,
                phase,
                &[
                    (kind[0], kept[0]),
                    (kind[1], kept[1]),
                    (kind[2], kept[2]),
                    (kind[3], kept[3]),
                ],
            );
        }
        facts(
            row,
            phase,
            &[
                ("exact", process && thread && token),
                ("process-exact", process),
                ("thread-exact", thread),
                ("token-exact", token),
                ("token-propagated", token),
            ],
        );
        if process && thread && token {
            Ok(())
        } else {
            Err(NativeError::EvidenceIncomplete)
        }
    }
    /// Supplies only the selected private process/thread attributes; unselected objects remain NULL.
    fn create(
        &self,
        row: Row,
        fixture: &Fixture,
        token: &FreshDerivedToken,
    ) -> Result<OwnedChild, NativeError> {
        let process = attributes(&self.process);
        let thread = attributes(&self.thread);
        let [p, t, _] = row.objects();
        OwnedChild::create_with_object_security(
            fixture,
            token.launch_token(),
            p.then_some(&process),
            t.then_some(&thread),
        )
    }
}

/// Revalidates source, all token reductions and exact protected image/consoles immediately before Resume.
fn resume(
    row: &'static str,
    phase: &'static str,
    state: &State,
    fixture: &Fixture,
    source: &SourceGuard,
    token: &FreshDerivedToken,
    changed: bool,
) -> Result<(), NativeError> {
    source_check(row, phase, source)?;
    token.unchanged(changed, source)?;
    let proof = prove_child_quiet(
        state.child()?,
        fixture,
        &source.snapshot,
        &source.console,
        source.session,
    );
    facts(row, phase, &[("child-proof", proof.is_ok())]);
    proof?;
    state.child()?.resume()
}

/// Executes one independent baseline/treatment pair, and a positive PE only after the Wait PE survives 100ms.
fn experiment(
    row: Row,
    state: &mut State,
    fixture: &Fixture,
    source: &SourceGuard,
    deadline: &Deadline,
) -> Result<bool, NativeError> {
    let name = row.name();
    let mut token = checkpoint(name, "derive", || {
        let token = FreshDerivedToken::create(source, row);
        facts(
            name,
            "derive",
            &[("query-ok", token.is_ok()), ("exact", token.is_ok())],
        );
        token
    })?;
    state.child = Some(checkpoint(name, "reference-create", || {
        deadline.launch()?;
        OwnedChild::create(fixture, token.launch_token())
    })?);
    let baseline = checkpoint(name, "reference-read", || {
        let objects = Objects::read(state.child()?);
        facts(
            name,
            "reference-read",
            &[("query-ok", objects.is_ok()), ("exact", objects.is_ok())],
        );
        objects
    })?;
    checkpoint(name, "reference-resume", || {
        deadline.launch()?;
        resume(
            name,
            "reference-resume",
            state,
            fixture,
            source,
            &token,
            false,
        )
    })?;
    checkpoint(name, "reference-wait", || {
        if wait(name, "reference-wait", state, 100)? != Some(0xC000_0142) {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    })?;
    checkpoint(name, "reference-reap", || {
        let result = state.reap();
        facts(name, "reference-reap", &[("owned-cleanup", result.is_ok())]);
        result
    })?;
    let expected = checkpoint(name, "intervention", || {
        let expected = Expected::build(&baseline, row, &source.user)?;
        if row.objects()[2] {
            token.add_object_user_allow(source)?;
        }
        let kept = token.preservation(row.objects()[2], source);
        facts(name, "intervention", &[("query-ok", kept.is_ok())]);
        let kept = kept?;
        facts(
            name,
            "intervention",
            &[
                ("owner-preserved", kept[0]),
                ("group-preserved", kept[1]),
                ("label-preserved", kept[2]),
                ("control-preserved", kept[3]),
                ("exact", kept[4]),
                ("properties-unchanged", kept[5]),
                ("default-dacl-unchanged", kept[6]),
            ],
        );
        if !kept.into_iter().all(|value| value) {
            return Err(NativeError::AccessDenied);
        }
        Ok(expected)
    })?;
    state.child = Some(checkpoint(name, "create", || {
        deadline.launch()?;
        expected.create(row, fixture, &token)
    })?);
    checkpoint(name, "read", || {
        expected.readback(name, "read", state.child()?)
    })?;
    checkpoint(name, "resume", || {
        deadline.launch()?;
        resume(
            name,
            "resume",
            state,
            fixture,
            source,
            &token,
            row.objects()[2],
        )
    })?;
    let startup = checkpoint(name, "wait", || match wait(name, "wait", state, 100)? {
        None => Ok(true),
        Some(0xC000_0142) => Ok(false),
        Some(_) => Err(NativeError::EvidenceIncomplete),
    })?;
    checkpoint(name, "reap", || {
        let result = state.reap();
        facts(name, "reap", &[("owned-cleanup", result.is_ok())]);
        result
    })?;
    if startup {
        state.child = Some(checkpoint(name, "positive-create", || {
            deadline.launch()?;
            state.positive = Some(Fixture::create(&source.user, Variant::Proof)?);
            let positive = state.positive.as_ref().ok_or(NativeError::Other)?;
            expected.create(row, positive, &token)
        })?);
        checkpoint(name, "positive-read", || {
            expected.readback(name, "positive-read", state.child()?)
        })?;
        checkpoint(name, "positive-resume", || {
            deadline.launch()?;
            resume(
                name,
                "positive-resume",
                state,
                state.positive.as_ref().ok_or(NativeError::Other)?,
                source,
                &token,
                row.objects()[2],
            )
        })?;
        checkpoint(name, "positive-wait", || {
            if wait(name, "positive-wait", state, 10_000)? != Some(0) {
                return Err(NativeError::EvidenceIncomplete);
            }
            Ok(())
        })?;
        checkpoint(name, "positive-reap", || {
            let result = state.reap();
            facts(name, "positive-reap", &[("owned-cleanup", result.is_ok())]);
            result
        })?;
    }
    token.unchanged(row.objects()[2], source)?;
    Ok(startup)
}

/// Runs all independent controls unless source preservation, unresolved cleanup or global reserve forbids launch.
fn observe_matrix() -> Result<(), NativeError> {
    let deadline = Deadline::start();
    let source = checkpoint("matrix", "setup", || {
        if PROCESS_ALL_ACCESS.0 != 0x001f_ffff
            || THREAD_ALL_ACCESS.0 != 0x001f_ffff
            || TOKEN_ALL_ACCESS.0 != 0x000f_01ff
        {
            return Err(NativeError::UnsupportedPlatform);
        }
        let source = SourceGuard::capture();
        facts("matrix", "setup", &[("verified", source.is_ok())]);
        source
    })?;
    let mut fixture = checkpoint("matrix", "fixture", || {
        let result = Fixture::create(&source.user, Variant::Wait);
        facts("matrix", "fixture", &[("verified", result.is_ok())]);
        result
    })?;
    let mut state = State::default();
    let mut first_error = None;
    let mut any_startup = false;
    for (index, row) in Row::ALL.into_iter().enumerate() {
        let primary = experiment(row, &mut state, &fixture, &source, &deadline);
        let cleanup = checkpoint(row.name(), "cleanup", || {
            let result = state.cleanup();
            facts(row.name(), "cleanup", &[("owned-cleanup", result.is_ok())]);
            result
        });
        let unchanged = checkpoint(row.name(), "source-check", || {
            source_check(row.name(), "source-check", &source)
        });
        let may_continue = cleanup.is_ok() && unchanged.is_ok() && deadline.launch().is_ok();
        let startup = primary.as_ref().is_ok_and(|value| *value);
        let complete = primary.is_ok() && cleanup.is_ok() && unchanged.is_ok();
        checkpoint(row.name(), "complete", || {
            facts(
                row.name(),
                "complete",
                &[
                    ("experiment-complete", complete),
                    ("startup-proof", startup && complete),
                ],
            );
            Ok(())
        })?;
        if complete {
            any_startup |= startup;
        }
        let combined = primary.map(|_| ()).and(cleanup).and(unchanged);
        if let Err(error) = combined {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        if !may_continue && index + 1 < Row::ALL.len() {
            if first_error.is_none() {
                first_error = Some(NativeError::TimedOut);
            }
            break;
        }
    }
    let cleanup = checkpoint("matrix", "cleanup", || {
        let child = state.cleanup();
        let fixture_result = if child.is_ok() {
            fixture.cleanup()
        } else {
            Err(NativeError::Other)
        };
        facts(
            "matrix",
            "cleanup",
            &[("owned-cleanup", child.is_ok() && fixture_result.is_ok())],
        );
        child.and(fixture_result)
    });
    let unchanged = checkpoint("matrix", "source-check", || {
        source_check("matrix", "source-check", &source)
    });
    let complete = first_error.is_none() && cleanup.is_ok() && unchanged.is_ok();
    checkpoint("matrix", "complete", || {
        facts(
            "matrix",
            "complete",
            &[
                ("experiment-complete", complete),
                ("any-startup-proof", any_startup),
            ],
        );
        Ok(())
    })?;
    if let Some(error) = first_error {
        return Err(error);
    }
    cleanup.and(unchanged)
}

/// Explicit disposable experiment only; no successful row clears the independent ordinary-child gate.
#[test]
#[ignore = "requires administrator on a disposable Windows verifier"]
fn native_object_dacl_matrix() {
    assert!(observe_matrix().is_ok(), "object-dacl-matrix-failed");
}

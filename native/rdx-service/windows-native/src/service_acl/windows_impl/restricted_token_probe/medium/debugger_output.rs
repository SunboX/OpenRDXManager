// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed standalone control transcript; only static keys/booleans and closed error/exit tokens.
use std::cell::Cell;
use std::io::Write;
thread_local! {static FAILED:Cell<bool>=const{Cell::new(false)};static BYTES:Cell<usize>=const{Cell::new(0)};}
/// Starts a single bounded transcript; phase resets never reset this global byte budget.
pub(super) fn start() {
    FAILED.with(|v| v.set(false));
    BYTES.with(|v| v.set(0));
}
/// Resets the per-phase IO outcome without retaining arbitrary writer errors.
pub(super) fn clear_failure() {
    FAILED.with(|failed| failed.set(false));
}
/// Checks only the fixed IO-failure bit after ALL native cleanup operations still execute.
pub(super) fn failed() -> bool {
    FAILED.with(Cell::get)
}
/// Writes only reconstructed static fields; failed IO never panics or hides a primary native error.
fn emit(value: std::fmt::Arguments<'_>) {
    let line = format!("{value}\n");
    let admitted = BYTES.with(|total| {
        let next = total.get().saturating_add(line.len());
        if next > 61_440 {
            false
        } else {
            total.set(next);
            true
        }
    });
    if !admitted || std::io::stdout().lock().write_all(line.as_bytes()).is_err() {
        FAILED.with(|v| v.set(true));
    }
}

/// Fixed begin/terminal marker; only the fieldless NativeError enum may be formatted.
pub(super) fn stage(
    phase: &'static str,
    status: &'static str,
    reason: Option<&super::NativeError>,
) {
    assert!(PHASES.contains(&phase), "debugger-output-phase");
    match reason {
        Some(error) => emit(format_args!(
            "openrdx-token-debugger-stage phase={phase} status={status} reason={error:?}"
        )),
        None => emit(format_args!(
            "openrdx-token-debugger-stage phase={phase} status={status}"
        )),
    }
}
/// Exact complete ordered phase set; failures may skip only to safe cleanup.
pub(super) const PHASES: &[&str] = &[
    "setup",
    "fixture",
    "baseline-create",
    "baseline-proof",
    "baseline-resume",
    "baseline-wait",
    "baseline-reap",
    "debug-create",
    "debug-proof",
    "debug-resume",
    "debug-events",
    "debug-reap",
    "fixture-cleanup",
    "source-check",
    "derived-check",
    "complete",
];
/// Compiled facts are shared by native formatter and actual host transcript tests.
pub(super) fn keys(phase: &str) -> &'static [&'static str] {
    match phase {
        "setup" => &["verified", "source-minimal", "derived-medium"],
        "fixture" => &["protected"],
        "baseline-create" => &["created", "creation-uncertain"],
        "baseline-proof" => &[
            "image",
            "properties",
            "console",
            "source-preserved",
            "derived-preserved",
        ],
        "baseline-resume" => &["fresh"],
        "baseline-wait" => &["dll-init-failed"],
        "baseline-reap" => &["verified", "deferred"],
        "debug-create" => &["created", "creation-uncertain"],
        "debug-proof" => &[
            "image",
            "properties",
            "console",
            "source-preserved",
            "derived-preserved",
        ],
        "debug-resume" => &["fresh"],
        "debug-events" => &[
            "event-protocol",
            "exit-continued",
            "held-exit-match",
            "files-closed",
        ],
        "debug-reap" => &["verified", "deferred"],
        "fixture-cleanup" => &["verified", "deferred"],
        "source-check" => &[
            "query-ok",
            "properties",
            "default-dacl",
            "object-descriptor",
            "instance-known",
            "instance-equal",
        ],
        "derived-check" => &[
            "query-ok",
            "properties",
            "default-dacl",
            "object-descriptor",
            "instance-known",
            "instance-equal",
        ],
        "complete" => &[
            "experiment-complete",
            "reproduced",
            "debugger-changed-behavior",
            "startup-proof",
        ],
        _ => panic!("debugger-output-phase"),
    }
}
/// Emits only static known boolean facts, never arbitrary SDK text.
pub(super) fn facts(phase: &'static str, values: &[(&'static str, bool)]) {
    assert!(
        PHASES.contains(&phase) && values.iter().all(|(key, _)| keys(phase).contains(key)),
        "debugger-output-schema"
    );
    emit(format_args!(
        "openrdx-token-debugger-control phase={phase} {}",
        values
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    ));
}
/// A fixed slot and compiled categories contain no process/thread/module identifiers.
pub(super) fn event(
    slot: usize,
    kind: &'static str,
    module: &'static str,
    exception: &'static str,
    first: bool,
    continued: bool,
) {
    assert!(
        slot < 128
            && [
                "create-process",
                "create-thread",
                "exit-thread",
                "load",
                "unload",
                "exception",
                "exit-process",
                "debug-string",
                "rip"
            ]
            .contains(&kind),
        "debugger-output-event"
    );
    assert!(
        [
            "none",
            "fixture",
            "ntdll",
            "kernel32",
            "kernelbase",
            "advapi32",
            "ucrt",
            "vcruntime",
            "other",
            "unknown"
        ]
        .contains(&module),
        "debugger-output-module"
    );
    assert!(
        [
            "none",
            "breakpoint",
            "access-denied",
            "access-violation",
            "in-page-error",
            "dll-init-failed",
            "other"
        ]
        .contains(&exception),
        "debugger-output-exception"
    );
    emit(format_args!(
        "openrdx-token-debugger-event slot=e{slot:03} kind={kind} module={module} exception={exception} first={first} continued={continued}"
    ));
}

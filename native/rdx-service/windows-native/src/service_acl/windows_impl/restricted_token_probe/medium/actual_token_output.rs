// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed standalone control transcript; only static keys/booleans and closed error/exit tokens.
use std::cell::Cell;
use std::io::Write;
thread_local! {static FAILED:Cell<bool>=const{Cell::new(false)};}
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
    if writeln!(std::io::stdout().lock(), "{value}").is_err() {
        FAILED.with(|failed| failed.set(true));
    }
}
/// Fixed begin/terminal marker; only the fieldless NativeError enum may be formatted.
pub(super) fn stage(
    phase: &'static str,
    status: &'static str,
    reason: Option<&super::NativeError>,
) {
    assert!(PHASES.contains(&phase), "actual-token-output-phase");
    match reason {
        Some(error) => emit(format_args!(
            "openrdx-token-actual-control-stage phase={phase} status={status} reason={error:?}"
        )),
        None => emit(format_args!(
            "openrdx-token-actual-control-stage phase={phase} status={status}"
        )),
    }
}
/// Successful native execution must include every one of these ordered phases.
pub(super) const PHASES: &[&str] = &[
    "setup",
    "derive",
    "fixtures",
    "baseline-create",
    "baseline-proof",
    "baseline-resume",
    "baseline-wait",
    "baseline-reap",
    "treatment-create",
    "treatment-observe",
    "treatment-write",
    "treatment-readback",
    "treatment-resume",
    "treatment-wait",
    "treatment-reap",
    "positive-create",
    "positive-observe",
    "positive-write",
    "positive-readback",
    "positive-resume",
    "positive-wait",
    "positive-reap",
    "child-cleanup",
    "proof-cleanup",
    "wait-cleanup",
    "source-check",
    "derived-check",
    "complete",
];
/// Fixed per-observation admission properties, required true in both treatment/positive subjects.
pub(super) const OBSERVE_KEYS: &[&str] = &[
    "fresh-proof",
    "full-properties-known",
    "full-properties-equal",
    "identities-known",
    "actual-source-distinct",
    "actual-derived-distinct",
    "write-handle-same-instance",
    "prewrite-state-exact",
    "source-unchanged",
    "derived-unchanged",
];
/// Exact isolated intervention; partial/unknown observations can never authorize resume.
pub(super) const READBACK_KEYS: &[&str] = &[
    "query-ok",
    "token-dacl-exact",
    "one-addition",
    "old-aces-retained",
    "denials-equal",
    "owner-preserved",
    "group-preserved",
    "label-preserved",
    "control-preserved",
    "same-instance",
    "full-properties-equal",
    "default-dacl-equal",
    "process-exact",
    "thread-exact",
    "source-unchanged",
    "derived-unchanged",
];
/// Compiled schema is consumed by native formatting and by the host transcript driver.
pub(super) fn keys(phase: &str) -> &'static [&'static str] {
    match phase {
        "setup" => &["verified"],
        "derive" => &[
            "reduced-proved",
            "source-handle-exact",
            "source-minimal-rights",
        ],
        "fixtures" => &["protected"],
        "baseline-create" | "treatment-create" | "positive-create" => {
            &["created", "creation-uncertain"]
        }
        "baseline-proof" => &[
            "query-ok",
            "image-proved",
            "properties-equal",
            "grant-absent",
            "identity-known",
            "actual-source-distinct",
            "actual-derived-distinct",
            "source-unchanged",
            "derived-unchanged",
        ],
        "baseline-resume" => &["fresh-proof"],
        "baseline-wait" => &["dll-init-failed"],
        "baseline-reap" | "treatment-reap" | "positive-reap" => &["verified"],
        "treatment-observe" | "positive-observe" => OBSERVE_KEYS,
        "treatment-write" | "positive-write" => &["epoch-fresh", "write-succeeded"],
        "treatment-readback" | "positive-readback" => READBACK_KEYS,
        "treatment-resume" | "positive-resume" => &["fresh-proof", "resumed"],
        "treatment-wait" => &["timeout-alive"],
        "positive-wait" => &["exit-zero"],
        "child-cleanup" | "proof-cleanup" | "wait-cleanup" => &["verified", "deferred"],
        "source-check" | "derived-check" => &[
            "query-ok",
            "properties-equal",
            "default-dacl-equal",
            "descriptor-equal",
            "instance-known",
            "instance-equal",
            "logon-equal",
            "modified-equal",
        ],
        "complete" => &["experiment-complete", "startup-proof"],
        _ => panic!("actual-token-output-phase"),
    }
}
/// Private writer holds no SDK objects and never forwards arbitrary strings.
pub(super) fn facts(phase: &'static str, values: &[(&'static str, bool)]) {
    assert!(
        PHASES.contains(&phase) && values.iter().all(|(key, _)| keys(phase).contains(key)),
        "actual-token-output-schema"
    );
    emit(format_args!(
        "openrdx-token-actual-control phase={phase} {}",
        values
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    ));
}
/// Only an existing fixed category is supplied by the retained owned process wait.
pub(super) fn exit(phase: &'static str, category: &'static str) {
    emit(format_args!(
        "openrdx-token-actual-control-exit phase={phase} category={category}"
    ));
}

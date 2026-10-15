// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed Task Two formatter only; the separate Task Three execution/parser gate is not implemented.

/// Compiled lifecycle phases; names never originate from source/child metadata.
pub(super) const PHASES: &[&str] = &[
    "donor-proof",
    "duplicate",
    "copy-proof",
    "fixtures",
    "wait-create",
    "wait-proof",
    "wait-resume",
    "wait-observe",
    "wait-reap",
    "proof-create",
    "proof-proof",
    "proof-resume",
    "proof-exit",
    "proof-reap",
    "child-cleanup",
    "wait-cleanup",
    "proof-cleanup",
    "caller-check",
    "donor-check",
    "copy-check",
    "complete",
];
/// Boolean-only field vocabulary; Task Three will separately impose per-phase completion requirements.
pub(super) const KEYS: &[&str] = &[
    "query-ok",
    "available",
    "enrolled",
    "image",
    "ordinary-medium",
    "mapped-generation-known",
    "caller-user-equal",
    "copy-distinct",
    "properties-equal",
    "default-dacl-equal",
    "descriptor-equal",
    "protected",
    "caller-owned",
    "created",
    "creation-uncertain",
    "fresh",
    "timeout-alive",
    "exit-zero",
    "verified",
    "deferred",
    "experiment-complete",
    "startup-proof",
    "instance-known",
    "instance-equal",
    "console-current",
    "user-equal",
    "session-equal",
    "elevation-equal",
    "integrity-equal",
    "ui-access-equal",
    "sandbox-inert-equal",
    "primary-equal",
    "elevation-type-equal",
    "groups-equal",
    "privileges-equal",
    "no-enabled-admins",
    "donor-properties-equal",
];
const REASONS: &[&str] = &[
    "UnsupportedPlatform",
    "InvalidRequest",
    "AccessDenied",
    "Busy",
    "ReadOnly",
    "Cancelled",
    "TimedOut",
    "DeviceRemoved",
    "NoMedia",
    "EnumerationFailed",
    "EvidenceIncomplete",
    "ResourceLimit",
    "Other",
];
const EXITS: &[&str] = &[
    "alive",
    "success",
    "self-token-open",
    "self-process-session",
    "self-console-session",
    "self-token-session",
    "self-elevation",
    "self-ui-access",
    "self-sandbox-inert",
    "self-primary",
    "self-integrity",
    "status-dll-not-found",
    "status-dll-init-failed",
    "status-invalid-image-format",
    "unknown",
];

/// Reconstructs only known phase/status and fieldless NativeError names.
pub(super) fn stage(phase: &str, status: &str, reason: Option<&str>) -> Result<String, ()> {
    if !PHASES.contains(&phase)
        || !matches!(status, "begin" | "ok" | "failed")
        || if status == "failed" {
            reason.is_none_or(|r| !REASONS.contains(&r))
        } else {
            reason.is_some()
        }
    {
        return Err(());
    }
    Ok(format!(
        "openrdx-manager-source-stage phase={phase} status={status}{}\n",
        reason.map(|r| format!(" reason={r}")).unwrap_or_default()
    ))
}
/// Rejects unknown/duplicate fields before reconstructing static keys and boolean values.
pub(super) fn facts(phase: &str, values: &[(&str, bool)]) -> Result<String, ()> {
    if !PHASES.contains(&phase)
        || values.is_empty()
        || values.len() > KEYS.len()
        || values.iter().enumerate().any(|(index, (key, _))| {
            !KEYS.contains(key) || values[..index].iter().any(|(previous, _)| previous == key)
        })
    {
        return Err(());
    }
    Ok(format!(
        "openrdx-manager-source phase={phase} {}\n",
        values
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    ))
}
/// Classifies fixed owned-child exit observations only, never forwarding a raw status.
pub(super) fn exit(phase: &str, category: &str) -> Result<String, ()> {
    if !matches!(phase, "wait-observe" | "proof-exit") || !EXITS.contains(&category) {
        return Err(());
    }
    Ok(format!(
        "openrdx-manager-source-exit phase={phase} category={category}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Only the closed phase/status/error vocabulary can reach native stdout.
    #[test]
    fn stage_schema_rejects_private_or_contradictory_tokens() {
        assert!(stage("wait-create", "begin", None).is_ok());
        for reason in REASONS {
            assert!(stage("wait-create", "failed", Some(reason)).is_ok());
        }
        for (phase, status, reason) in [
            ("private-path", "begin", None),
            ("wait-create", "private", None),
            ("wait-create", "ok", Some("Other")),
            ("wait-create", "failed", None),
            ("wait-create", "failed", Some("S-1-5-private")),
        ] {
            assert!(stage(phase, status, reason).is_err());
        }
    }
    /// Unknown/duplicate fields never leak, while a known false caller equality remains observational.
    #[test]
    fn facts_are_unique_closed_booleans_without_identity_values() {
        assert!(facts("donor-proof", &[("caller-user-equal", false)]).is_ok());
        for values in [
            vec![("private-SID", true)],
            vec![("query-ok", true), ("query-ok", false)],
            vec![],
        ] {
            assert!(facts("donor-proof", &values).is_err());
        }
        assert!(facts("private-path", &[("query-ok", true)]).is_err());
    }
    /// Exit classes belong only to fixed observation phases; unknown raw status is never emitted.
    #[test]
    fn exit_categories_cannot_carry_raw_status_or_orphan_phase() {
        assert!(exit("wait-observe", "alive").is_ok());
        assert!(exit("proof-exit", "success").is_ok());
        for (phase, category) in [
            ("wait-create", "alive"),
            ("proof-exit", "0xc0000142"),
            ("private", "unknown"),
        ] {
            assert!(exit(phase, category).is_err());
        }
    }
    /// Actual formatter worst-size booleans/terminal/exit branches retain both existing reserves.
    #[test]
    fn all_success_and_failure_branches_fit_original_capture_bound() {
        for failed in [false, true] {
            let mut transcript = String::new();
            for phase in PHASES {
                transcript += &stage(phase, "begin", None).unwrap();
                transcript += &facts(
                    phase,
                    &KEYS.iter().map(|key| (*key, false)).collect::<Vec<_>>(),
                )
                .unwrap();
                if matches!(*phase, "wait-observe" | "proof-exit") {
                    transcript += &exit(phase, "status-invalid-image-format").unwrap();
                }
                transcript += &stage(
                    phase,
                    if failed { "failed" } else { "ok" },
                    failed.then_some("UnsupportedPlatform"),
                )
                .unwrap();
            }
            // Task One's closed acquisition/copy trace is bounded to24KiB by its fixed call graph;
            // after acquisition Task Two exclusively uses silent preservation methods.
            let bytes = transcript.replace('\n', "\r\n").len() + 24 * 1024 + 4096;
            assert!(bytes < 65536);
        }
    }
}

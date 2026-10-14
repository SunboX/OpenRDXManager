// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only private object lineage and ACL-profile observations; never actual-child security setters.
use super::process_dacl_control::process_descriptor::token_acl_profile;
use super::token_statistics::Statistics;
use super::*;
use windows::Win32::Security::TOKEN_READ_CONTROL;

/// Emits only compiled boolean keys, within fixed matrix phases; no private SDK identifiers/ACL bytes.
fn emit(row: &'static str, phase: &'static str, values: &[(&'static str, bool)]) {
    matrix_output::record(matrix_output::Prefix::Lineage, row, phase, values);
}
/// Initial source metadata was captured by the query-only observer before any WRITE_DAC handle opening.
pub(super) fn initial(source: &SourceGuard) {
    let (initial, _) = source.statistics();
    emit(
        "matrix",
        "setup",
        &[
            ("source-initial-query-ok", initial.query_ok),
            ("source-initial-layout-valid", initial.layout_valid),
        ],
    );
}
/// Same held source is read after all rows; ModifiedId equality is observational, not an immutability promise.
pub(super) fn final_source(source: &SourceGuard) {
    let (initial, current) = source.statistics();
    let equal = initial.compare(current);
    emit(
        "matrix",
        "source-check",
        &[
            ("source-final-query-ok", current.query_ok),
            ("source-final-layout-valid", current.layout_valid),
            ("source-stable-known", equal[0]),
            ("source-stable-id-equal", equal[1]),
            ("source-stable-logon-equal", equal[2]),
            ("source-stable-modified-equal", equal[3]),
        ],
    );
}
/// Formats pairwise equality only after both exact private SDK layouts are known.
fn pair(row: &'static str, left: Statistics, right: Statistics, keys: [&'static str; 4]) {
    let equal = left.compare(right);
    emit(
        row,
        "read",
        &[
            (keys[0], equal[0]),
            (keys[1], equal[1]),
            (keys[2], equal[2]),
            (keys[3], equal[3]),
        ],
    );
}
/// Read-only scope is mechanically bound to the retained created child and the already-pinned Wait image.
pub(super) struct Context<'a> {
    pub(super) row: Row,
    pub(super) child: &'a OwnedChild,
    pub(super) fixture: &'a Fixture,
    pub(super) source: &'a SourceGuard,
    pub(super) derived: &'a FreshDerivedToken,
    pub(super) baseline: &'a Components,
    pub(super) expected: &'a Components,
}
/// Checks fresh image/medium/current-console and complete derived equality before any metadata/profile interpretation.
/// Optional query/encoding unavailability cannot override the original exact guard's error.
pub(super) fn observe(context: Context<'_>) -> Result<(), NativeError> {
    let Context {
        row,
        child,
        fixture,
        source,
        derived,
        baseline,
        expected,
    } = context;
    let name = row.name();
    let proof = source
        .unchanged()
        .and(derived.unchanged(true, source))
        .and_then(|()| {
            prove_child_quiet(
                child,
                fixture,
                &source.snapshot,
                &source.console,
                source.session,
            )
        });
    emit(name, "read", &[("fresh-proof", proof.is_ok())]);
    proof?;
    let mut raw = HANDLE::default();
    // OpenProcessToken checks requested TOKEN OBJECT rights. QUERY|READ_CONTROL only, no WRITE_DAC/DUPLICATE.
    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
    // SAFETY: exact factory-owned retained suspended process, not a PID or borrowed/source process.
    let opened =
        unsafe { OpenProcessToken(child.process.0, TOKEN_QUERY | TOKEN_READ_CONTROL, &mut raw) }
            .map_err(map_native_error);
    let actual = opened.as_ref().ok().map(|_| OwnedHandle(raw));
    emit(name, "read", &[("actual-open-ok", opened.is_ok())]);
    opened?;
    let actual = actual.ok_or(NativeError::Other)?;
    let actual_properties = SourceSnapshot::read(&actual);
    let derived_properties = SourceSnapshot::read(derived.launch_token());
    let known = actual_properties.is_ok() && derived_properties.is_ok();
    let equal = actual_properties
        .as_ref()
        .ok()
        .zip(derived_properties.as_ref().ok())
        .is_some_and(|(a, d)| a == d);
    emit(
        name,
        "read",
        &[
            ("full-properties-known", known),
            ("full-properties-equal", equal),
        ],
    );
    actual_properties?;
    derived_properties?;
    if !equal {
        return Err(NativeError::AccessDenied);
    }
    let (source_initial, source_current) = source.statistics();
    let (derived_initial, derived_current) = derived.statistics();
    let actual_stats = Statistics::read(&actual);
    emit(
        name,
        "read",
        &[
            ("source-query-ok", source_current.query_ok),
            ("source-layout-valid", source_current.layout_valid),
            ("derived-query-ok", derived_current.query_ok),
            ("derived-layout-valid", derived_current.layout_valid),
            ("actual-query-ok", actual_stats.query_ok),
            ("actual-layout-valid", actual_stats.layout_valid),
            ("source-initial-query-ok", source_initial.query_ok),
            ("source-initial-layout-valid", source_initial.layout_valid),
            ("derived-initial-query-ok", derived_initial.query_ok),
            ("derived-initial-layout-valid", derived_initial.layout_valid),
        ],
    );
    pair(
        name,
        source_initial,
        source_current,
        [
            "source-stable-known",
            "source-stable-id-equal",
            "source-stable-logon-equal",
            "source-stable-modified-equal",
        ],
    );
    pair(
        name,
        derived_initial,
        derived_current,
        [
            "derived-stable-known",
            "derived-stable-id-equal",
            "derived-stable-logon-equal",
            "derived-stable-modified-equal",
        ],
    );
    pair(
        name,
        source_current,
        derived_current,
        [
            "source-derived-known",
            "source-derived-id-equal",
            "source-derived-logon-equal",
            "source-derived-modified-equal",
        ],
    );
    pair(
        name,
        source_current,
        actual_stats,
        [
            "source-actual-known",
            "source-actual-id-equal",
            "source-actual-logon-equal",
            "source-actual-modified-equal",
        ],
    );
    pair(
        name,
        derived_current,
        actual_stats,
        [
            "derived-actual-known",
            "derived-actual-id-equal",
            "derived-actual-logon-equal",
            "derived-actual-modified-equal",
        ],
    );
    let descriptor = PrivateDescriptor::read(actual.0);
    emit(name, "read", &[("descriptor-query-ok", descriptor.is_ok())]);
    let profile = descriptor.ok().and_then(|value| {
        token_acl_profile::observe(&value.components, baseline, expected, source.user.bytes()).ok()
    });
    emit(name, "read", &[("profile-valid", profile.is_some())]);
    if let Some(profile) = profile {
        for (keys, values) in [
            (
                [
                    "baseline-grant-absent",
                    "baseline-grant-single",
                    "baseline-grant-duplicate",
                ],
                profile.grants[0],
            ),
            (
                [
                    "expected-grant-absent",
                    "expected-grant-single",
                    "expected-grant-duplicate",
                ],
                profile.grants[1],
            ),
            (
                [
                    "actual-grant-absent",
                    "actual-grant-single",
                    "actual-grant-duplicate",
                ],
                profile.grants[2],
            ),
        ] {
            emit(
                name,
                "read",
                &[
                    (keys[0], values[0]),
                    (keys[1], values[1]),
                    (keys[2], values[2]),
                ],
            );
        }
        for (keys, values) in [
            (
                [
                    "baseline-acl-bytes-equal",
                    "baseline-ace-sequence-equal",
                    "baseline-header-equal",
                    "baseline-padding-equal",
                ],
                profile.comparison[0],
            ),
            (
                [
                    "expected-acl-bytes-equal",
                    "expected-ace-sequence-equal",
                    "expected-header-equal",
                    "expected-padding-equal",
                ],
                profile.comparison[1],
            ),
        ] {
            emit(
                name,
                "read",
                &[
                    (keys[0], values[0]),
                    (keys[1], values[1]),
                    (keys[2], values[2]),
                    (keys[3], values[3]),
                ],
            );
        }
        emit(
            name,
            "read",
            &[
                ("old-aces-retained", profile.old_aces),
                ("denials-equal", profile.denials),
                ("one-addition", profile.one_addition),
                ("owner-preserved", profile.preserved[0]),
                ("group-preserved", profile.preserved[1]),
                ("label-preserved", profile.preserved[2]),
                ("control-preserved", profile.preserved[3]),
            ],
        );
    }
    Ok(())
}

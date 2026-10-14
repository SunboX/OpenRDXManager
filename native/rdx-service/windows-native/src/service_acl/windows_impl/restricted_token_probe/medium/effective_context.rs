// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Effective-context layers remain read-only observations, never loader or authorization proof.
use super::*;
use std::os::windows::io::AsRawHandle;
use windows::Win32::Foundation::ERROR_NOT_SUPPORTED;
use windows::Win32::Security::{
    GENERIC_MAPPING, GetKernelObjectSecurity, IsWellKnownSid, LABEL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, WinBuiltinUsersSid,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};

/// Successful LABEL query and valid bounded parse are separate facts; unknown never infers a level.
#[derive(Default)]
struct LabelObservation {
    query_ok: bool,
    unsupported: bool,
    parsed: bool,
    facts: mandatory_label::LabelFacts,
}

/// Queries LABEL only through existing retained READ_CONTROL handles, including token/file objects.
/// LABEL requires READ_CONTROL, unlike full SACL; no security privilege is requested/enabled.
/// https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information
fn label(handle: Option<HANDLE>) -> LabelObservation {
    let Some(handle) = handle else {
        return LabelObservation::default();
    };
    let mut needed = 0;
    // SAFETY: retained borrowed kernel handle; fixed LABEL-only sizing query.
    let sizing = unsafe {
        GetKernelObjectSecurity(handle, LABEL_SECURITY_INFORMATION.0, None, 0, &mut needed)
    };
    // SDK Result captures the failed API's thread-local error immediately; only fixed unsupported escapes.
    if !is_error(&sizing, ERROR_INSUFFICIENT_BUFFER) {
        return LabelObservation {
            unsupported: is_error(&sizing, ERROR_NOT_SUPPORTED),
            ..Default::default()
        };
    }
    if !(20..=MAX_PROBE_BYTES).contains(&(needed as usize)) {
        return LabelObservation::default();
    }
    let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let capacity = storage.len() * size_of::<usize>();
    // SAFETY: aligned bounded initialized caller storage; original held handle, LABEL only.
    let result = unsafe {
        GetKernelObjectSecurity(
            handle,
            LABEL_SECURITY_INFORMATION.0,
            Some(PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast())),
            capacity as u32,
            &mut needed,
        )
    };
    if result.is_err() {
        return LabelObservation {
            unsupported: is_error(&result, ERROR_NOT_SUPPORTED),
            ..Default::default()
        };
    }
    let mut observed = LabelObservation {
        query_ok: true,
        ..Default::default()
    };
    if !(20..=capacity).contains(&(needed as usize)) {
        return observed;
    }
    // SAFETY: successful bounded returned bytes are initialized; pure parser validates every ACE/SID extent.
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), needed as usize) };
    if let Some(facts) = mandatory_label::parse(bytes) {
        observed.parsed = true;
        observed.facts = facts;
    }
    observed
}

/// Builds fixed booleans; valid absent label alone supplies implicit-medium observations.
fn label_fields(fields: &mut Vec<String>, subject: &str, handle: Option<HANDLE>) {
    let observed = label(handle);
    let facts = &observed.facts;
    for (key, value) in [
        ("query-ok", observed.query_ok),
        ("query-unsupported", observed.unsupported),
        ("parse-valid", observed.parsed),
        ("present", facts.present),
        ("single", facts.single),
        ("known", facts.known),
        ("implicit-medium", facts.implicit_medium),
        ("low", facts.low),
        ("medium", facts.medium),
        ("high", facts.high),
        ("system", facts.system),
        ("policy-known", facts.policy_known),
        ("no-write-up", facts.no_write_up),
        ("no-read-up", facts.no_read_up),
        ("no-execute-up", facts.no_execute_up),
    ] {
        fields.push(format!("{subject}-label-{key}={value}"));
    }
}

/// Checks exact retained file/directory DACLs with documented SDK file generic rights.
fn fixture_fields(
    fields: &mut Vec<String>,
    fixture: &Fixture,
    source: &OwnedHandle,
    derived: &OwnedHandle,
    actual: Option<&OwnedHandle>,
) {
    let pins = fixture.retained_payload();
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    for (object, file) in [
        ("root", pins.map(|pins| pins.0)),
        ("image", pins.map(|pins| pins.1)),
    ] {
        // File remains owned/pinned by Fixture; raw handle is borrowed and never closed here.
        let handle = file.map(|file| HANDLE(file.as_raw_handle()));
        let descriptor = handle.and_then(|handle| object_context::descriptor(handle).ok());
        fields.push(format!(
            "fixture-{object}-descriptor-query-ok={}",
            descriptor.is_some()
        ));
        label_fields(fields, &format!("fixture-{object}"), handle);
        for (subject, token) in [
            ("source", Some(source)),
            ("derived", Some(derived)),
            ("actual", actual),
        ] {
            for (access, desired) in [
                ("read", FILE_GENERIC_READ.0),
                ("execute", FILE_GENERIC_EXECUTE.0),
            ] {
                let result = descriptor.as_ref().zip(token).map(|(descriptor, token)| {
                    desktop_context::dacl_access(descriptor, token, desired, &mapping)
                });
                fields.push(format!(
                    "{subject}-fixture-{object}-{access}-query-ok={}",
                    result.as_ref().is_some_and(|result| result.is_ok())
                ));
                fields.push(format!(
                    "{subject}-fixture-{object}-{access}-allowed={}",
                    result
                        .as_ref()
                        .is_some_and(|result| result.as_ref().is_ok_and(|value| *value))
                ));
            }
        }
    }
}

/// Queries private group identities, returning Users enabled and exactly-one enabled logon SID only.
fn principals(token: &OwnedHandle) -> Result<(bool, bool, bool), NativeError> {
    let buffer = TokenBuffer::read(token, TokenGroups)?;
    let groups = buffer
        .entries::<SID_AND_ATTRIBUTES>(offset_of!(TOKEN_GROUPS, Groups), buffer.header::<u32>()?)?;
    let mut users = false;
    let mut user_groups = 0;
    let mut logons = 0;
    let mut logon_enabled = false;
    for group in groups {
        let sid = buffer.sid(group.Sid)?;
        let enabled =
            group.Attributes & GROUP_ENABLED != 0 && group.Attributes & GROUP_DENY_ONLY == 0;
        // SAFETY: privately bounded copied SID, fixed well-known classifier; no identity output.
        if unsafe { IsWellKnownSid(sid.pointer(), WinBuiltinUsersSid).as_bool() } {
            user_groups += 1;
            users = enabled;
        }
        if group.Attributes & 0xc000_0000 == 0xc000_0000 {
            logons += 1;
            logon_enabled = enabled;
        }
    }
    // Ambiguous duplicate identities cannot establish an enabled/deny-only observation.
    if user_groups > 1 || logons > 1 {
        return Err(NativeError::Other);
    }
    Ok((users, logons == 1, logons == 1 && logon_enabled))
}

/// Unavailable handles cannot accidentally become implicit-medium or access-level evidence.
#[test]
fn missing_label_handle_remains_unknown() {
    let observed = label(None);
    assert!(!observed.query_ok && !observed.unsupported && !observed.parsed);
    assert!(!observed.facts.known && !observed.facts.implicit_medium && !observed.facts.medium);
}

/// Reads actual child and derived snapshots freshly at observation; never substitutes precreation facts.
fn token_fields(
    fields: &mut Vec<String>,
    source: &OwnedHandle,
    derived: &OwnedHandle,
    actual: Option<&OwnedHandle>,
) {
    let actual_snapshot = actual.map(SourceSnapshot::read);
    let derived_snapshot = SourceSnapshot::read(derived);
    fields.push(format!(
        "actual-snapshot-query-ok={}",
        actual_snapshot
            .as_ref()
            .is_some_and(|result| result.is_ok())
    ));
    fields.push(format!(
        "derived-fresh-snapshot-query-ok={}",
        derived_snapshot.is_ok()
    ));
    let snapshots = actual_snapshot
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .zip(derived_snapshot.as_ref().ok());
    let comparisons = snapshots
        .map(|(actual, derived)| {
            [
                actual.user == derived.user,
                actual.session == derived.session,
                actual.elevation == derived.elevation,
                actual.integrity == derived.integrity,
                actual.ui_access == derived.ui_access,
                actual.sandbox_inert == derived.sandbox_inert,
                actual.token_type == derived.token_type,
                actual.elevation_type == derived.elevation_type,
                actual.groups == derived.groups,
                actual.privileges == derived.privileges,
            ]
        })
        .unwrap_or([false; 10]);
    for (key, matches) in [
        "user",
        "session",
        "elevation",
        "integrity",
        "ui-access",
        "sandbox-inert",
        "type",
        "elevation-type",
        "groups",
        "privileges",
    ]
    .iter()
    .zip(comparisons)
    {
        fields.push(format!("actual-derived-{key}-match={matches}"));
    }
    fields.push(format!(
        "actual-derived-snapshot-match={}",
        snapshots.is_some_and(|(actual, derived)| actual == derived)
    ));
    for (subject, token) in [
        ("source", Some(source)),
        ("derived", Some(derived)),
        ("actual", actual),
    ] {
        let result = token.map(principals);
        let values = result.as_ref().and_then(|result| result.as_ref().ok());
        for (key, value) in [
            ("principals-query-ok", values.is_some()),
            (
                "builtin-users-enabled",
                values.is_some_and(|values| values.0),
            ),
            ("logon-single", values.is_some_and(|values| values.1)),
            ("logon-enabled", values.is_some_and(|values| values.2)),
        ] {
            fields.push(format!("{subject}-{key}={value}"));
        }
    }
}

/// Observes only the exact owned suspended child and held fixture pins; no launch/ACL/token adjustment.
pub(super) fn observe(
    source: &OwnedHandle,
    derived: &OwnedHandle,
    actual: Option<&OwnedHandle>,
    child: &OwnedChild,
    fixture: &Fixture,
) {
    let mut fields = Vec::new();
    for (subject, handle) in [
        ("child-process", Some(child.process.0)),
        ("child-thread", Some(child.thread.0)),
        ("child-token", actual.map(|token| token.0)),
    ] {
        label_fields(&mut fields, subject, handle);
    }
    fixture_fields(&mut fields, fixture, source, derived, actual);
    token_fields(&mut fields, source, derived, actual);
    println!("openrdx-token-effective-context {}", fields.join(" "));
}

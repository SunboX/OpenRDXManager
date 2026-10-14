// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only LABEL-only and token-policy facts; never loader or access authorization.
use super::super::mandatory_label;
use super::*;
use mandatory_label::LabelFacts;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Security::TokenMandatoryPolicy;

/// LABEL-only reads need existing READ_CONTROL; no security privilege is requested.
/// https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information
const LABEL_SECURITY_INFORMATION: u32 = 0x10;

/// Successful querying and valid parsing are independent, closed observations.
#[derive(Default)]
struct Observation {
    query_ok: bool,
    unsupported: bool,
    parsed: bool,
    facts: LabelFacts,
}

/// Reads only a borrowed fixed user-object handle into bounded aligned caller storage.
fn label(object: Option<HANDLE>) -> Observation {
    let Some(object) = object else {
        return Observation::default();
    };
    let mut needed = 0;
    // SAFETY: borrowed valid owned-by-caller station/desktop, LABEL-only sizing query.
    let sizing = unsafe {
        GetUserObjectSecurity(
            object,
            &LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    // SAFETY: immediate thread-local error query is used only for fixed unsupported classification.
    let error = if sizing == 0 {
        unsafe { GetLastError().0 }
    } else {
        0
    };
    // Only ERROR_NOT_SUPPORTED establishes unsupported. Invalid parameter and
    // other failures remain unknown; ERROR_INSUFFICIENT_BUFFER is normal sizing.
    if sizing == 0 && error != 122 {
        return Observation {
            unsupported: error == 50,
            ..Default::default()
        };
    }
    if !(20..=MAX_PROBE_BYTES).contains(&(needed as usize)) {
        return Observation::default();
    }
    let mut storage = vec![0_usize; (needed as usize).div_ceil(size_of::<usize>())];
    let capacity = storage.len() * size_of::<usize>();
    // GetUserObjectSecurity returns self-relative storage, including on SE_WINDOW_OBJECT targets.
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getuserobjectsecurity
    // SAFETY: aligned bounded initialized storage, original fixed object, LABEL-only request.
    if unsafe {
        GetUserObjectSecurity(
            object,
            &LABEL_SECURITY_INFORMATION,
            storage.as_mut_ptr().cast(),
            capacity as u32,
            &mut needed,
        )
    } == 0
    {
        // SAFETY: immediate thread-local error query; no raw value is emitted.
        return Observation {
            unsupported: unsafe { GetLastError().0 } == 50,
            ..Default::default()
        };
    }
    let mut observation = Observation {
        query_ok: true,
        ..Default::default()
    };
    if !(20..=capacity).contains(&(needed as usize)) {
        return observation;
    }
    // SAFETY: successful API initialized exactly the bounded returned byte count.
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), needed as usize) };
    if let Some(facts) = mandatory_label::parse(bytes) {
        observation.parsed = true;
        observation.facts = facts;
    }
    observation
}

/// Builds fixed boolean fields without raw SIDs, labels, names or error values.
fn label_fields(subject: &'static str, observation: &Observation) -> Vec<String> {
    let facts = &observation.facts;
    let fields = [
        ("query-ok", observation.query_ok),
        ("query-unsupported", observation.unsupported),
        ("parse-valid", observation.parsed),
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
    ];
    fields
        .iter()
        .map(|(key, value)| format!("{subject}-label-{key}={value}"))
        .collect()
}

/// Builds token-policy booleans only after exact API/scalar size validation, without adjustment.
fn policy_fields(subject: &'static str, token: &OwnedHandle) -> Vec<String> {
    let policy = scalar(token, TokenMandatoryPolicy);
    let fields = [
        ("query-ok", policy.is_ok()),
        ("known", policy.as_ref().is_ok_and(|value| value & !3 == 0)),
        ("off", policy.as_ref().is_ok_and(|value| *value == 0)),
        (
            "no-write-up",
            policy.as_ref().is_ok_and(|value| value & 1 != 0),
        ),
        (
            "new-process-min",
            policy.as_ref().is_ok_and(|value| value & 2 != 0),
        ),
    ];
    fields
        .iter()
        .map(|(key, value)| format!("{subject}-policy-{key}={value}"))
        .collect()
}

/// Observes existing owned fixed user objects via borrowed handles; no ownership or launch change.
pub(super) fn observe(
    station: Option<HANDLE>,
    desktop: Option<HANDLE>,
    source: &OwnedHandle,
    derived: &OwnedHandle,
) {
    let station = label(station);
    let desktop = label(desktop);
    let mut facts = label_fields("station", &station);
    facts.extend(label_fields("desktop", &desktop));
    facts.extend(policy_fields("source", source));
    facts.extend(policy_fields("derived", derived));
    println!("openrdx-token-mandatory-context {}", facts.join(" "));
}

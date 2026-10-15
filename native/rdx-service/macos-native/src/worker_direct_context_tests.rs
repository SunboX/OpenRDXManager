// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Synthetic metadata tests direct policy only, and cannot mint a production factory.
fn root_fixture() -> WorkerContext {
    WorkerContext {
        version: 1,
        size: 72,
        uid: 0,
        euid: 0,
        gid: 20,
        egid: 20,
        pid: 123,
        ppid: 1,
        auid: u32::MAX,
        audit_euid: 0,
        audit_egid: 20,
        audit_ruid: 0,
        audit_rgid: 20,
        audit_pid: 123,
        asid: 100_013,
        pid_version: 9,
        session: 100_013,
        attributes: 1,
    }
}

/// Direct policy accepts a genuine anonymous root or graphical audit baseline without asuser policy.
#[test]
fn direct_baseline_accepts_anonymous_and_gui_root_without_session_rewrite() {
    assert!(DirectBaseline::from_observed(root_fixture()).is_ok());
    let mut gui = root_fixture();
    gui.auid = 502;
    gui.asid = 100_014;
    gui.session = 100_014;
    gui.attributes = 0x6030;
    assert!(DirectBaseline::from_observed(gui).is_ok());
}

/// A boolean/process claim cannot stand in for actual root, audit, PID and valid-session observations.
#[test]
fn direct_baseline_rejects_unprivileged_and_inconsistent_native_observations() {
    for field in [
        "uid",
        "euid",
        "audit_ruid",
        "audit_euid",
        "audit_rgid",
        "audit_egid",
        "audit_pid",
        "pid_version",
        "session",
        "asid",
        "version",
        "size",
    ] {
        let mut invalid = root_fixture();
        match field {
            "uid" => invalid.uid = 502,
            "euid" => invalid.euid = 502,
            "audit_ruid" => invalid.audit_ruid = 502,
            "audit_euid" => invalid.audit_euid = 502,
            "audit_rgid" => invalid.audit_rgid += 1,
            "audit_egid" => invalid.audit_egid += 1,
            "audit_pid" => invalid.audit_pid += 1,
            "pid_version" => invalid.pid_version = 0,
            "session" => invalid.session += 1,
            "asid" => {
                invalid.asid = 0;
                invalid.session = 0;
            }
            "version" => invalid.version += 1,
            _ => invalid.size -= 1,
        }
        assert!(DirectBaseline::from_observed(invalid).is_err(), "{field}");
    }
    assert!(
        DirectBaseline::from_observed(WorkerContext::current().unwrap()).is_err(),
        "ordinary process must not acquire direct root authority"
    );
}

/// Exact actual-child proof must retain all credentials, audit provenance and unchanged session bits.
#[test]
fn direct_child_proof_rejects_pid_parent_credential_audit_and_session_drift() {
    let parent = root_fixture();
    let expected = DirectBaseline::from_observed(parent)
        .unwrap()
        .expectation(1234)
        .unwrap();
    let mut child = parent;
    child.pid = 1234;
    child.audit_pid = 1234;
    child.ppid = parent.pid;
    child.pid_version = 10;
    assert_eq!(expected.verify(&child, 1234), Ok(()));
    assert_eq!(
        expected.verify(&child, 1235),
        Err(NativeError::AccessDenied)
    );
    let encoded = child.encode();
    for word in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17] {
        let mut changed = encoded.clone();
        let value = u32::from_le_bytes(changed[word * 4..word * 4 + 4].try_into().unwrap());
        changed[word * 4..word * 4 + 4].copy_from_slice(&value.wrapping_add(1).to_le_bytes());
        let observed = WorkerContext::decode(&changed);
        assert!(
            observed.is_err() || expected.verify(&observed.unwrap(), 1234).is_err(),
            "word {word}"
        );
    }
    child.pid_version = 0;
    assert_eq!(
        expected.verify(&child, 1234),
        Err(NativeError::AccessDenied)
    );
    let request = expected.encode();
    assert_eq!(
        DirectExpectation::decode(&request).unwrap().encode(),
        request
    );
    for len in [
        0,
        1,
        DIRECT_EXPECTATION_BYTES - 1,
        DIRECT_EXPECTATION_BYTES + 1,
    ] {
        assert!(DirectExpectation::decode(&vec![0; len]).is_err());
    }
    let mut wrong = request.clone();
    wrong[8] = 1;
    assert!(DirectExpectation::decode(&wrong).is_err());
    assert!(
        WorkerExpectation::decode(&request).is_err(),
        "no GUI/direct wire collision"
    );
}

/// Fresh same-process revalidation is byte-exact across all private native baseline observations.
#[test]
fn direct_baseline_stale_snapshot_never_revalidates_as_actual_current_process() {
    let baseline = DirectBaseline::from_observed(root_fixture()).unwrap();
    assert_eq!(baseline.revalidate(), Err(NativeError::AccessDenied));
    for pid in [0, 123, u32::MAX] {
        assert!(baseline.expectation(pid).is_err());
    }
}

/// Each new spawn and final ACK consumes a complete fresh snapshot, never a UID-only comparison.
#[test]
fn direct_baseline_revalidation_rejects_every_changed_native_word() {
    let parent = root_fixture();
    let baseline = DirectBaseline::from_observed(parent).unwrap();
    assert_eq!(baseline.revalidate_observed(parent), Ok(()));
    let bytes = parent.encode();
    for word in 2..18 {
        let mut changed = bytes.clone();
        let value = u32::from_le_bytes(changed[word * 4..word * 4 + 4].try_into().unwrap());
        changed[word * 4..word * 4 + 4].copy_from_slice(&value.wrapping_add(1).to_le_bytes());
        assert_eq!(
            baseline.revalidate_observed(WorkerContext::decode(&changed).unwrap()),
            Err(NativeError::AccessDenied),
            "word {word}"
        );
    }
}

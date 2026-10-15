// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Synthetic metadata exercises policy only; it is not root, session or installed-worker proof.
fn fixture() -> (WorkerExpectation, WorkerContext) {
    (
        WorkerExpectation {
            uid: 502,
            asid: 100_014,
            pid: 1234,
            ppid: 123,
            gid: 20,
            egid: 20,
        },
        WorkerContext {
            version: 1,
            size: 72,
            uid: 0,
            euid: 0,
            gid: 20,
            egid: 20,
            pid: 1234,
            ppid: 123,
            auid: 502,
            audit_euid: 0,
            audit_egid: 20,
            audit_ruid: 0,
            audit_rgid: 20,
            audit_pid: 1234,
            asid: 100_014,
            pid_version: 9,
            session: 100_014,
            attributes: 0x6030,
        },
    )
}

/// Actual observed additional session bits must not reject a valid exact peer session.
#[test]
fn context_allows_known_gui_bits_with_additional_session_attributes() {
    let (expected, observed) = fixture();
    assert_eq!(std::mem::size_of::<WorkerContext>(), 72);
    assert_eq!(verify_child_context(&expected, &observed, 1234), Ok(()));
}

/// PID from an untrusted pipe cannot replace the actual retained process identity or its parent.
#[test]
fn context_rejects_wrong_owned_pid_parent_and_pid_generation() {
    let (expected, observed) = fixture();
    assert_eq!(
        verify_child_context(&expected, &observed, 1235),
        Err(NativeError::AccessDenied)
    );
    for field in ["pid", "audit_pid", "ppid", "pid_version"] {
        let mut altered = observed;
        match field {
            "pid" => altered.pid += 1,
            "audit_pid" => altered.audit_pid += 1,
            "ppid" => altered.ppid += 1,
            _ => altered.pid_version = 0,
        }
        assert_eq!(
            verify_child_context(&expected, &altered, 1234),
            Err(NativeError::AccessDenied),
            "{field}"
        );
    }
}

/// Both ordinary and audit credentials must preserve actual root and the service's GID tuple.
#[test]
fn context_rejects_root_loss_and_every_gid_drift() {
    let (expected, observed) = fixture();
    for field in [
        "uid",
        "euid",
        "gid",
        "egid",
        "audit_euid",
        "audit_egid",
        "audit_ruid",
        "audit_rgid",
    ] {
        let mut altered = observed;
        match field {
            "uid" => altered.uid = 502,
            "euid" => altered.euid = 502,
            "gid" => altered.gid = 0,
            "egid" => altered.egid = 0,
            "audit_euid" => altered.audit_euid = 502,
            "audit_egid" => altered.audit_egid = 0,
            "audit_ruid" => altered.audit_ruid = 502,
            _ => altered.audit_rgid = 0,
        }
        assert_eq!(
            verify_child_context(&expected, &altered, 1234),
            Err(NativeError::AccessDenied),
            "{field}"
        );
    }
}

/// Same-UID sessions and root/remote/non-graphical sessions are not the retained peer generation.
#[test]
fn context_rejects_wrong_audit_session_and_ineligible_session_bits() {
    let (expected, observed) = fixture();
    for field in ["auid", "asid", "session", "root", "remote", "nongraphical"] {
        let mut altered = observed;
        match field {
            "auid" => altered.auid += 1,
            "asid" => altered.asid += 1,
            "session" => altered.session += 1,
            "root" => altered.attributes |= 1,
            "remote" => altered.attributes |= 0x1000,
            _ => altered.attributes &= !0x10,
        }
        assert_eq!(
            verify_child_context(&expected, &altered, 1234),
            Err(NativeError::AccessDenied),
            "{field}"
        );
    }
}

/// A malformed version/length never reaches policy, even when the remaining metadata matches.
#[test]
fn context_rejects_unknown_record_layout() {
    let (expected, observed) = fixture();
    let mut altered = observed;
    altered.version = 2;
    assert_eq!(
        verify_child_context(&expected, &altered, 1234),
        Err(NativeError::AccessDenied)
    );
    altered = observed;
    altered.size -= 4;
    assert_eq!(
        verify_child_context(&expected, &altered, 1234),
        Err(NativeError::AccessDenied)
    );
}

/// Real self-only public APIs must agree with this retained ordinary test process, without GUI assumptions.
#[test]
fn current_context_is_actual_process_public_audit_metadata() {
    let actual = WorkerContext::current().unwrap();
    assert_eq!(actual.pid, std::process::id());
    assert_eq!(actual.audit_pid, std::process::id());
    // SAFETY: public credential getters take no arguments and transfer no ownership.
    unsafe {
        assert_eq!(actual.uid, libc::getuid());
        assert_eq!(actual.euid, libc::geteuid());
        assert_eq!(actual.gid, libc::getgid());
        assert_eq!(actual.egid, libc::getegid());
        assert_eq!(actual.ppid, libc::getppid() as u32);
    }
    assert_eq!(actual.audit_euid, actual.euid);
    assert_eq!(actual.audit_ruid, actual.uid);
    assert_eq!(actual.audit_rgid, actual.gid);
    assert_eq!(actual.audit_egid, actual.egid);
    assert!(actual.pid_version > 0);
    assert_eq!(actual.asid, actual.session);
    let encoded = actual.encode();
    assert_eq!(WorkerContext::decode(&encoded).unwrap().encode(), encoded);
}

/// Private records reject partial/trailing bytes, unknown request mode and stale expectation metadata.
#[test]
fn context_fixed_wire_records_reject_length_mode_and_expectation_drift() {
    let (expected, observed) = fixture();
    let encoded = expected.encode();
    assert_eq!(
        WorkerExpectation::decode(&encoded).unwrap().encode(),
        encoded
    );
    for length in [0, 1, EXPECTATION_BYTES - 1, EXPECTATION_BYTES + 1] {
        assert!(WorkerExpectation::decode(&vec![0; length]).is_err());
    }
    for length in [0, 1, CONTEXT_BYTES - 1, CONTEXT_BYTES + 1] {
        assert!(WorkerContext::decode(&vec![0; length]).is_err());
    }
    let mut malformed = encoded;
    malformed[8] = 2;
    assert!(WorkerExpectation::decode(&malformed).is_err());
    for invalid in [0, u32::MAX - 1, u32::MAX] {
        let mut altered = expected;
        altered.uid = invalid;
        assert_eq!(
            verify_child_context(&altered, &observed, 1234),
            Err(NativeError::AccessDenied)
        );
        altered = expected;
        altered.asid = invalid;
        assert_eq!(
            verify_child_context(&altered, &observed, 1234),
            Err(NativeError::AccessDenied)
        );
    }
}

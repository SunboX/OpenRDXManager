// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Builds metadata only; this fixture never authenticates a Manager or grants authority.
fn record() -> crate::ffi::PeerSessionRecord {
    crate::ffi::PeerSessionRecord {
        version: 1,
        size: std::mem::size_of::<crate::ffi::PeerSessionRecord>() as u32,
        audit_token: [502, 502, 20, 502, 20, 123, 100_014, 7],
    }
}

/// The separate record rejects incompatible headers without changing ABI four.
#[test]
fn peer_session_header_rejects_wrong_version_and_size() {
    assert!(PeerSession::from_record(record()).is_ok());
    let mut wrong = record();
    wrong.version = 4;
    assert!(PeerSession::from_record(wrong).is_err());
    wrong = record();
    wrong.size -= 1;
    assert!(PeerSession::from_record(wrong).is_err());
    assert_eq!(crate::ffi::ABI_VERSION, 4);
}

/// Header validity cannot turn absent, conflicting, or reserved kernel metadata into proof.
#[test]
fn peer_session_record_rejects_ineligible_identity_fields() {
    for (field, value) in [
        (0, 0),
        (0, u32::MAX),
        (0, 501),
        (1, 0),
        (3, 0),
        (5, 0),
        (5, u32::MAX),
        (6, 0),
        (6, u32::MAX),
        (6, u32::MAX - 1),
        (7, 0),
    ] {
        let mut invalid = record();
        invalid.audit_token[field] = value;
        assert!(
            PeerSession::from_record(invalid).is_err(),
            "field {field}, value {value}"
        );
    }
}

/// Production masks require only documented bits and exact retained identities.
#[test]
fn peer_session_session_bits_and_identity_must_match() {
    let record = record();
    let matches = |uid, asid, attributes, console| {
        // SAFETY: the initialized fixture is metadata only and remains live for this pure predicate.
        unsafe {
            crate::ffi::rdx_macos_peer_session_metadata_matches(
                &record, uid, asid, attributes, console,
            )
        }
    };
    assert!(matches(502, 100_014, 0x10, 502));
    assert!(matches(502, 100_014, 0x6030, 502));
    assert!(matches(502, 100_014, 0x8000_0010, 502));
    for attributes in [0, 0x20, 0x11, 0x1010, 0x1011] {
        assert!(!matches(502, 100_014, attributes, 502));
    }
    assert!(!matches(501, 100_014, 0x10, 502));
    assert!(!matches(502, 100_015, 0x10, 502));
    assert!(!matches(502, 100_014, 0x10, 501));
}

/// Every token word matters, including PID version, audit session and group credentials.
#[test]
fn peer_session_exact_token_compares_all_eight_words() {
    let original = record();
    // SAFETY: both records are fully initialized metadata; this comparison grants no capability.
    assert!(unsafe { crate::ffi::rdx_macos_peer_session_same_token(&original, &original) });
    for index in 0..8 {
        let mut changed = original;
        changed.audit_token[index] += 1;
        // SAFETY: the changed fixture is a complete record and cannot enter production admission.
        assert!(!unsafe { crate::ffi::rdx_macos_peer_session_same_token(&original, &changed) });
    }
}

/// Caller-side version/size checking and failures transfer neither a descriptor nor evidence.
#[test]
fn peer_session_native_accept_rejects_wrong_output_header_and_invalid_listener() {
    let requirement = std::ffi::CString::new(
        "identifier \"com.openrdx.manager\" and cdhash H\"0123456789abcdef0123456789abcdef01234567\""
    ).unwrap();
    for (version, size) in [(0, 40), (1, 39), (4, 40)] {
        let mut output = record();
        output.version = version;
        output.size = size;
        let mut socket = 19;
        // SAFETY: all scalar/record outputs and the C string are initialized and live.
        let status = unsafe {
            crate::ffi::rdx_macos_accept_launchd_manager_with_session(
                0,
                requirement.as_ptr(),
                &mut socket,
                &mut output,
            )
        };
        assert_eq!(status, crate::ffi::STATUS_INVALID_ARGUMENT);
        assert_eq!(socket, -1);
    }
    let mut socket = -1;
    let mut uid = 99;
    // SAFETY: the invalid listener is rejected before use; this exercises the preserved UID API.
    let status = unsafe {
        crate::ffi::rdx_macos_accept_launchd_manager_from_listener(
            -1,
            requirement.as_ptr(),
            &mut socket,
            &mut uid,
        )
    };
    assert_eq!(status, crate::ffi::STATUS_INVALID_ARGUMENT);
    assert_eq!(socket, -1);
    assert_eq!(uid, 0);
}

/// A real ordinary socket and a fabricated metadata tuple never prove installed Manager identity.
#[test]
fn peer_session_real_socket_cannot_bypass_full_live_code_and_path_proof() {
    use std::os::fd::AsRawFd;
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let requirement = std::ffi::CString::new(
        "identifier \"com.openrdx.manager\" and cdhash H\"0123456789abcdef0123456789abcdef01234567\""
    ).unwrap();
    let session = PeerSession::from_record(record()).unwrap();
    assert_eq!(
        session.revalidate(socket.as_raw_fd(), &requirement),
        Err(crate::NativeError::AccessDenied)
    );
}

/// Native and Rust records share the complete token width without changing old ABI records.
#[test]
fn peer_session_record_layout_and_uid_are_bounded() {
    assert_eq!(std::mem::size_of::<crate::ffi::PeerSessionRecord>(), 40);
    assert_eq!(std::mem::align_of::<crate::ffi::PeerSessionRecord>(), 4);
    assert_eq!(PeerSession::from_record(record()).unwrap().user_id(), 502);
    assert!(PeerSession::from_record(PeerSession::output_record()).is_err());
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Only internal state transitions are exercised; these fixtures cannot satisfy native revalidation.
#[test]
fn worker_factory_owner_is_one_shot_across_connection_clones() {
    let state = fixture();
    let owner = state.begin().unwrap();
    assert!(owner.factory().ensure_active().is_ok());
    assert!(state.begin().is_err());
    assert!(Arc::clone(&state).begin().is_err());
}

/// Shared handles cannot extend authority beyond the unique connection owner.
#[test]
fn worker_factory_owner_drop_revokes_every_existing_clone() {
    let state = fixture();
    let owner = state.begin().unwrap();
    let factory = owner.factory();
    let copy = factory.clone();
    drop(owner);
    assert_eq!(factory.ensure_active(), Err(NativeError::AccessDenied));
    assert_eq!(copy.ensure_active(), Err(NativeError::AccessDenied));
    assert!(state.begin().is_err());
}

/// Native validation can stall without preventing another thread from revoking the connection.
#[test]
fn worker_factory_revocation_during_validation_is_not_blocked_by_native_work() {
    use std::{sync::mpsc, thread, time::Duration};
    let state = fixture();
    let owner = state.begin().unwrap();
    let factory = owner.factory();
    let validator = factory.clone();
    let (entered, ready) = mpsc::sync_channel(0);
    let (release, resume) = mpsc::sync_channel(0);
    let worker = thread::spawn(move || {
        validator.revalidate_with(|_| {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(())
        })
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.revoke();
    assert_eq!(factory.ensure_active(), Err(NativeError::AccessDenied));
    release.send(()).unwrap();
    assert_eq!(worker.join().unwrap(), Err(NativeError::AccessDenied));
}

/// Identical UID metadata on a later connection cannot revive an earlier revoked factory.
#[test]
fn worker_factory_connection_identity_is_not_uid_equality() {
    let first = fixture().begin().unwrap();
    let second = fixture().begin().unwrap();
    assert_ne!(first.factory(), second.factory());
    assert_eq!(first.factory(), first.factory());
    first.revoke();
    assert!(second.factory().ensure_active().is_ok());
    assert_eq!(
        format!("{:?}", second.factory()),
        "MacWorkerFactory(<private>)"
    );
}

/// Observing invalid live/generation evidence permanently retires that connection's capability.
#[test]
fn worker_factory_failed_validation_cannot_revive_when_evidence_returns() {
    let owner = fixture().begin().unwrap();
    let factory = owner.factory();
    assert_eq!(
        factory.revalidate_with(|_| Err(NativeError::EvidenceIncomplete)),
        Err(NativeError::EvidenceIncomplete)
    );
    assert_eq!(factory.ensure_active(), Err(NativeError::AccessDenied));
    assert_eq!(
        factory.revalidate_with(|_| Ok(())),
        Err(NativeError::AccessDenied)
    );
}

/// Revocation observed during expensive proof must prevent the later ACK under the short gate.
#[test]
fn worker_factory_final_ack_refuses_revoke_after_proof_and_expired_deadline() {
    use std::time::{Duration, Instant};
    let owner = fixture().begin().unwrap();
    let factory = owner.factory();
    let mut acknowledgements = 0;
    assert_eq!(
        factory.admit_worker_with(
            Instant::now() + Duration::from_secs(1),
            || {
                owner.revoke();
                Ok(())
            },
            || {
                acknowledgements += 1;
                Ok(())
            }
        ),
        Err(NativeError::AccessDenied)
    );
    assert_eq!(acknowledgements, 0);
    let owner = fixture().begin().unwrap();
    assert_eq!(
        owner.factory().admit_worker_with(
            Instant::now(),
            || Ok(()),
            || {
                acknowledgements += 1;
                Ok(())
            }
        ),
        Err(NativeError::TimedOut)
    );
    assert_eq!(acknowledgements, 0);
}

/// A fresh verifier stalled between proof and ACK cannot block EOF revocation or later admit the child.
#[test]
fn worker_factory_final_ack_validation_does_not_hold_revocation_gate() {
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    let owner = fixture().begin().unwrap();
    let factory = owner.factory();
    let (entered, ready) = mpsc::sync_channel(0);
    let (release, resume) = mpsc::sync_channel(0);
    let thread = thread::spawn(move || {
        factory.admit_worker_with(
            Instant::now() + Duration::from_secs(2),
            || {
                entered.send(()).unwrap();
                resume.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(())
            },
            || panic!("revoked validation cannot ACK"),
        )
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.revoke();
    assert_eq!(
        owner.factory().ensure_active(),
        Err(NativeError::AccessDenied)
    );
    release.send(()).unwrap();
    assert_eq!(thread.join().unwrap(), Err(NativeError::AccessDenied));
}

/// Test-only accepted metadata never authenticates an installed Manager or privileged service.
pub(super) fn fixture() -> Arc<PeerSessionState> {
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let record = crate::ffi::PeerSessionRecord {
        version: 1,
        size: 40,
        audit_token: [502, 502, 20, 502, 20, 123, 100_014, 7],
    };
    Arc::new(PeerSessionState::new(
        stream,
        crate::peer_session::PeerSession::from_record(record).unwrap(),
        std::ffi::CString::new("private-test-requirement").unwrap(),
        crate::runtime_generation::RuntimeGeneration::fixture(),
    ))
}

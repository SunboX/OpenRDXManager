// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed-role reverse metadata permissions, reconnect and concurrency regressions.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Synthetic service-shaped SID, never a configurable runtime policy identity.
pub(super) fn service_sid() -> FixedServiceSid {
    FixedServiceSid([
        1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0,
        0, 0,
    ])
}

/// Complete synthetic descriptor shared with the existing preservation regressions.
fn baseline() -> Descriptor {
    Descriptor::parse(&super::tests::descriptor_bytes()).unwrap()
}

/// Windows may leave cbSid at its input capacity after returning a valid 32-byte service SID.
#[test]
fn successful_fixed_sid_lookup_may_retain_bounded_input_capacity() {
    assert!(fixed_service_lookup_capacity_valid(68, 68));
    assert!(fixed_service_lookup_capacity_valid(32, 68));
    for (reported, allocated) in [(0, 68), (31, 68), (69, 68), (32, 31), (32, 69)] {
        assert!(!fixed_service_lookup_capacity_valid(reported, allocated));
    }
}

/// Role proof rejects copies, aliases, malformed paths, Node and unpinned images before a grant.
#[test]
fn manager_role_requires_fixed_path_and_all_current_and_pinned_file_identities() {
    let expected = [7, 8, 9];
    let path: Vec<u16> = MANAGER_IMAGE.encode_utf16().collect();
    assert!(manager_identity_matches(
        &path, expected, expected, expected, true
    ));
    assert!(manager_identity_matches(
        &MANAGER_IMAGE
            .to_ascii_lowercase()
            .encode_utf16()
            .collect::<Vec<_>>(),
        expected,
        expected,
        expected,
        true
    ));
    for bad in [
        r"C:\portable\OpenRDXManager.exe",
        r"C:\Program Files\OpenRDXManager\node.exe",
        r"C:\Program Files\OpenRDXManager\..\OpenRDXManager.exe",
        "",
        "C:\\Program Files\\OpenRDXManager\\OpenRDXManager.exe\0",
    ] {
        assert!(!manager_identity_matches(
            &bad.encode_utf16().collect::<Vec<_>>(),
            expected,
            expected,
            expected,
            true
        ));
    }
    assert!(!manager_identity_matches(
        &path,
        [7, 8, 10],
        expected,
        expected,
        true
    ));
    assert!(!manager_identity_matches(
        &path,
        expected,
        [7, 8, 10],
        expected,
        true
    ));
    assert!(!manager_identity_matches(
        &path, expected, expected, expected, false
    ));
}

/// Exact existing ACEs require no further append; BU rights cannot satisfy this role.
#[test]
fn manager_query_grant_is_fixed_service_only_and_idempotent() {
    let original = baseline();
    let sid = service_sid();
    let granted = original.with_manager_query_access(&sid).unwrap();
    assert!(granted != original);
    assert!(granted.with_manager_query_access(&sid).unwrap() == granted);
    assert!(granted != original.with_query_access(Object::Process).unwrap());
    let mut expected = super::tests::descriptor_bytes();
    let mut ace = vec![0, 0, 40, 0, 0, 16, 0, 0];
    ace.extend(sid.0);
    expected.splice(120..120, ace);
    expected[74..76].copy_from_slice(&108_u16.to_le_bytes());
    expected[76..78].copy_from_slice(&4_u16.to_le_bytes());
    assert!(granted == Descriptor::parse(&expected).unwrap());
    for (offset, value) in [(121, 2), (124, 0x10), (125, 0x14)] {
        let mut changed = expected.clone();
        changed[offset] = value;
        let changed = Descriptor::parse(&changed).unwrap();
        assert!(changed.with_manager_query_access(&sid).unwrap() != changed);
    }
}

/// Thread-safe process fixture refuses every primary-token access.
struct ManagerObjects {
    process: Mutex<Descriptor>,
    writes: AtomicUsize,
    reads: AtomicUsize,
    fail_read: usize,
    fail_write: bool,
    corrupt_readback: bool,
}

impl ManagerObjects {
    /// Creates a private current-process fixture with no failure injection enabled.
    fn new(process: Descriptor) -> Self {
        Self {
            process: Mutex::new(process),
            writes: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            fail_read: 0,
            fail_write: false,
            corrupt_readback: false,
        }
    }
}

impl CurrentObjects for ManagerObjects {
    /// Returns process state only, exposing accidental token access as a test failure.
    fn read(&self, object: Object) -> Result<Descriptor, NativeError> {
        assert_eq!(object, Object::Process);
        let read = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if read == self.fail_read {
            return Err(NativeError::Other);
        }
        if self.corrupt_readback && self.writes.load(Ordering::SeqCst) > 0 {
            return Ok(baseline());
        }
        Ok(self.process.lock().unwrap().clone())
    }
    /// Counts process mutations only; no fixture can grant token permissions.
    fn set_dacl(&self, object: Object, descriptor: &Descriptor) -> Result<(), NativeError> {
        assert_eq!(object, Object::Process);
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.fail_write {
            return Err(NativeError::Other);
        }
        *self.process.lock().unwrap() = descriptor.clone();
        Ok(())
    }
}

/// Concurrent reconnect workers share serialization and never grow the process DACL.
#[test]
fn reconnect_and_concurrent_manager_preparations_write_once() {
    let objects = Arc::new(ManagerObjects::new(baseline()));
    let expected = baseline()
        .with_manager_query_access(&service_sid())
        .unwrap();
    let mut workers = Vec::new();
    for _ in 0..16 {
        let objects = Arc::clone(&objects);
        workers.push(std::thread::spawn(move || {
            for _ in 0..8 {
                grant_manager_query_access(objects.as_ref(), &service_sid()).unwrap();
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(objects.writes.load(Ordering::SeqCst), 1);
    assert!(*objects.process.lock().unwrap() == expected);
}

/// Existing exact grants write nothing; failed queries/setters/readback never return readiness.
#[test]
fn manager_preparation_skips_exact_grants_and_fails_closed_at_native_boundaries() {
    let sid = service_sid();
    let mut objects = ManagerObjects::new(baseline().with_manager_query_access(&sid).unwrap());
    objects.fail_write = true;
    assert_eq!(grant_manager_query_access(&objects, &sid), Ok(()));
    assert_eq!(objects.writes.load(Ordering::SeqCst), 0);
    for fail_read in [1, 2] {
        let mut objects = ManagerObjects::new(baseline());
        objects.fail_read = fail_read;
        assert_eq!(
            grant_manager_query_access(&objects, &sid),
            Err(NativeError::Other)
        );
        if fail_read == 1 {
            assert_eq!(objects.writes.load(Ordering::SeqCst), 0);
        }
    }
    let mut objects = ManagerObjects::new(baseline());
    objects.fail_write = true;
    assert_eq!(
        grant_manager_query_access(&objects, &sid),
        Err(NativeError::Other)
    );
    let mut objects = ManagerObjects::new(baseline());
    objects.corrupt_readback = true;
    assert_eq!(
        grant_manager_query_access(&objects, &sid),
        Err(NativeError::AccessDenied)
    );
}

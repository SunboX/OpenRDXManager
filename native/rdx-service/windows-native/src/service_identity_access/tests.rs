// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable security-policy and fail-closed startup regressions.

use super::*;
use std::cell::{Cell, RefCell};

/// Builds one synthetic SID, distinct from the fixed query trustee.
fn sid(id: u8) -> Vec<u8> {
    vec![1, 1, 0, 0, 0, 0, 0, 5, id, 0, 0, 0]
}

/// Builds a self-relative descriptor with deny/allow/inherited ACEs and a system label.
pub(super) fn descriptor_bytes() -> Vec<u8> {
    let mut bytes = vec![
        1, 0, 0x14, 0x90, 20, 0, 0, 0, 32, 0, 0, 0, 44, 0, 0, 0, 72, 0, 0, 0,
    ];
    bytes.extend(sid(19));
    bytes.extend(sid(19));
    bytes.extend([2, 0, 28, 0, 1, 0, 0, 0, 0x11, 0, 20, 0, 1, 0, 0, 0]);
    bytes.extend([1, 1, 0, 0, 0, 0, 0, 16, 0, 64, 0, 0]);
    bytes.extend([2, 0, 68, 0, 3, 0, 0, 0]);
    for (kind, flags, mask) in [(1, 0, 2_u32), (0, 0, 0x1fffff), (0, 0x10, 0x1400)] {
        bytes.extend([kind, flags, 20, 0]);
        bytes.extend(mask.to_le_bytes());
        bytes.extend(sid(9));
    }
    bytes
}

/// Only fixed trustee, concrete query mask and noninheriting ALLOW may be added.
#[test]
fn exact_query_grants_preserve_every_previous_component_and_ace() {
    let bytes = descriptor_bytes();
    let original = Descriptor::parse(&bytes).unwrap();
    for object in [Object::Process, Object::PrimaryToken] {
        let granted = original.with_query_access(object).unwrap();
        // Compare through expected serialized evidence, including all original ACE bytes.
        let mut expected = bytes.clone();
        let mut ace = vec![0, 0, 24, 0];
        ace.extend(object.query_mask().to_le_bytes());
        ace.extend([1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0]);
        expected.splice(120..120, ace);
        expected[74..76].copy_from_slice(&92_u16.to_le_bytes());
        expected[76..78].copy_from_slice(&4_u16.to_le_bytes());
        assert!(granted == Descriptor::parse(&expected).unwrap());
        assert!(original == Descriptor::parse(&bytes).unwrap());
    }
}

/// Null, overlapping, unbounded and unsupported descriptors never produce a plan.
#[test]
fn malformed_security_evidence_fails_closed() {
    let bytes = descriptor_bytes();
    for length in 0..bytes.len() {
        assert!(Descriptor::parse(&bytes[..length]).is_err());
    }
    for (index, value) in [
        (0, 2),
        (2, 0x10),
        (4, 0),
        (8, 20),
        (16, 0),
        (80, 9),
        (81, 0x80),
        (83, 0xff),
    ] {
        let mut bad = bytes.clone();
        bad[index] = value;
        assert!(Descriptor::parse(&bad).is_err());
    }
}

/// Kernel ACL capacity may differ; only identical complete ACE bytes may compare equal.
#[test]
fn acl_capacity_padding_cannot_hide_additional_grants() {
    let bytes = descriptor_bytes();
    let original = Descriptor::parse(&bytes).unwrap();
    let mut padded = bytes.clone();
    padded.extend([0; 8]);
    padded[74..76].copy_from_slice(&76_u16.to_le_bytes());
    assert!(Descriptor::parse(&padded).unwrap() == original);
    padded[140] = 1;
    assert!(Descriptor::parse(&padded).is_err());
    let mut additional = bytes.clone();
    additional.extend(&bytes[100..120]);
    additional[74..76].copy_from_slice(&88_u16.to_le_bytes());
    additional[76..78].copy_from_slice(&4_u16.to_le_bytes());
    assert!(Descriptor::parse(&additional).unwrap() != original);
}

/// Query masks exclude memory, injection, duplication, mutation and security-control rights.
#[test]
fn query_masks_never_authorize_process_or_token_mutation() {
    assert_eq!(Object::Process.query_mask(), 0x1000);
    assert_eq!(Object::PrimaryToken.query_mask(), 8);
    let security_writes = 0x0004_0000 | 0x0008_0000 | 0x0100_0000;
    assert_eq!(
        Object::Process.query_mask() & (0x1 | 0x2 | 0x8 | 0x10 | 0x20 | 0x40 | security_writes),
        0
    );
    assert_eq!(
        Object::PrimaryToken.query_mask()
            & (0x1 | 0x2 | 0x4 | 0x20 | 0x40 | 0x80 | 0x100 | security_writes),
        0
    );
}

/// Owns synthetic object descriptors; no test changes the host process/token security.
struct Objects {
    process: RefCell<Descriptor>,
    token: RefCell<Descriptor>,
    reads: Cell<usize>,
    writes: Cell<usize>,
    fail_read: usize,
    fail_write: usize,
    corrupt_readback: bool,
}

impl Objects {
    /// Creates a pristine private fixture with independently injected failures.
    fn new() -> Self {
        let descriptor = Descriptor::parse(&descriptor_bytes()).unwrap();
        Self {
            process: RefCell::new(descriptor.clone()),
            token: RefCell::new(descriptor),
            reads: Cell::new(0),
            writes: Cell::new(0),
            fail_read: 0,
            fail_write: 0,
            corrupt_readback: false,
        }
    }
}

impl CurrentObjects for Objects {
    /// Fails a selected query or returns a changed preserved component after a write.
    fn read(&self, object: Object) -> Result<Descriptor, NativeError> {
        self.reads.set(self.reads.get() + 1);
        if self.reads.get() == self.fail_read {
            return Err(NativeError::Other);
        }
        let mut descriptor = match object {
            Object::Process => self.process.borrow().clone(),
            Object::PrimaryToken => self.token.borrow().clone(),
        };
        if self.corrupt_readback && self.writes.get() > 0 {
            let mut bytes = descriptor_bytes();
            bytes[28] ^= 1;
            descriptor = Descriptor::parse(&bytes)?;
        }
        Ok(descriptor)
    }

    /// Records only the closed object role and expected whole descriptor fixture.
    fn set_dacl(&self, object: Object, descriptor: &Descriptor) -> Result<(), NativeError> {
        self.writes.set(self.writes.get() + 1);
        if self.writes.get() == self.fail_write {
            return Err(NativeError::Other);
        }
        match object {
            Object::Process => *self.process.borrow_mut() = descriptor.clone(),
            Object::PrimaryToken => *self.token.borrow_mut() = descriptor.clone(),
        }
        Ok(())
    }
}

/// Both objects are preflighted and exact readback is mandatory; errors cannot open startup.
#[test]
fn native_boundaries_fail_closed_before_identity_access_is_ready() {
    let objects = Objects::new();
    assert_eq!(grant_query_access(&objects), Ok(()));
    assert_eq!(objects.reads.get(), 4);
    assert_eq!(objects.writes.get(), 2);
    for fail_read in 1..=4 {
        let mut objects = Objects::new();
        objects.fail_read = fail_read;
        assert!(grant_query_access(&objects).is_err());
        if fail_read <= 2 {
            assert_eq!(objects.writes.get(), 0);
        }
    }
    for fail_write in 1..=2 {
        let mut objects = Objects::new();
        objects.fail_write = fail_write;
        assert!(grant_query_access(&objects).is_err());
    }
    let mut objects = Objects::new();
    objects.corrupt_readback = true;
    assert_eq!(grant_query_access(&objects), Err(NativeError::AccessDenied));
    assert_eq!(objects.writes.get(), 1);
}

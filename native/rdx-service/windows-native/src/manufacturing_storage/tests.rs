// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows filesystem tests use disposable current-user data, never production records.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Owns only a uniquely created test directory and removes it after all leases drop.
struct Temporary(PathBuf);
impl Temporary {
    /// Creates a fresh directory; a collision fails instead of reusing existing data.
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "openrdx-store-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    /// Opens the production implementation with a test-only current-user policy.
    fn store(&self) -> ManufacturingStore {
        ManufacturingStore::open_at(&self.0.join("backups"), Policy::current_user().unwrap())
            .unwrap()
    }
}
impl Drop for Temporary {
    /// Deletes only the exact unique directory created by this fixture.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Real Win32 short-name spelling must not defeat retained ancestry or private readback.
#[test]
fn round_trips_backup_through_win32_short_name_ancestors() {
    let temporary = Temporary::new();
    let path = wide(&temporary.0);
    let mut buffer = vec![0u16; 32768];
    // SAFETY: existing disposable directory, terminated input and bounded writable output.
    let length = unsafe { GetShortPathNameW(PCWSTR(path.as_ptr()), Some(&mut buffer)) } as usize;
    assert!(length > 0 && length < buffer.len());
    let short = PathBuf::from(String::from_utf16(&buffer[..length]).unwrap());
    let store = ManufacturingStore::open_for_test(&short.join("backups")).unwrap();
    store
        .persist("record-1-0", &[0x42; 256], None, b"{}")
        .unwrap();
    drop(store);
    let reopened = temporary.store();
    assert_eq!(
        reopened.read("record-1-0", BackupFile::Record).unwrap(),
        [0x42; 256]
    );
    assert_eq!(
        reopened.read("record-1-0", BackupFile::Manifest).unwrap(),
        b"{}"
    );
}

/// Exact record/sector/manifest bytes survive a complete independent reopen.
#[test]
fn persistent_bundle_round_trips_and_refuses_overwrite() {
    let temporary = Temporary::new();
    let record = [0x42; 256];
    let sector = [0x42; 4096];
    let store = temporary.store();
    store
        .persist(
            "record-123-0",
            &record,
            Some(&sector),
            b"{\"schemaVersion\":1}",
        )
        .unwrap();
    assert!(
        store
            .persist("record-123-0", &[0; 256], None, b"{}")
            .is_err()
    );
    drop(store);
    let store = temporary.store();
    assert_eq!(store.names().unwrap(), vec!["record-123-0"]);
    assert_eq!(
        store.read("record-123-0", BackupFile::Record).unwrap(),
        record
    );
    assert_eq!(
        store.read("record-123-0", BackupFile::Sector).unwrap(),
        sector
    );
    assert_eq!(
        store.read("record-123-0", BackupFile::Manifest).unwrap(),
        b"{\"schemaVersion\":1}"
    );
}

/// Path-like IDs, alternate streams and incomplete files never become recovery data.
#[test]
fn rejects_invalid_ids_and_incomplete_records() {
    let temporary = Temporary::new();
    let store = temporary.store();
    for id in [
        "../record-1-0",
        "record-01-0",
        "record-1-0:stream",
        "record-A-0",
        "record-1-0\\leaf",
    ] {
        assert!(store.persist(id, &[0; 256], None, b"{}").is_err());
        assert!(store.read(id, BackupFile::Record).is_err());
    }
    store.persist("record-1-0", &[0; 256], None, b"{}").unwrap();
    assert!(store.read("record-1-0", BackupFile::Sector).is_err());
    assert!(
        store
            .persist("record-2-0", &[0; 256], Some(&[1; 4096]), b"{}")
            .is_err()
    );
}

/// Extra hardlinks are rejected on read even when the pathname and contents match.
#[test]
fn rejects_multiply_linked_backup_files() {
    let temporary = Temporary::new();
    let store = temporary.store();
    store.persist("record-1-0", &[0; 256], None, b"{}").unwrap();
    drop(store);
    std::fs::hard_link(
        temporary.0.join("backups/record-1-0/manufacturing.bin"),
        temporary.0.join("alias.bin"),
    )
    .unwrap();
    let store = temporary.store();
    assert!(store.read("record-1-0", BackupFile::Record).is_err());
}

/// An ordinary inherited directory must not be adopted or have its ACL repaired.
#[test]
fn rejects_existing_non_private_store() {
    let temporary = Temporary::new();
    let path = temporary.0.join("backups");
    std::fs::create_dir(&path).unwrap();
    assert!(ManufacturingStore::open_at(&path, Policy::current_user().unwrap()).is_err());
}

/// The retained directory cannot be renamed during an authorized storage operation.
#[test]
fn pins_storage_ancestry_against_replacement() {
    let temporary = Temporary::new();
    let store = temporary.store();
    assert!(std::fs::rename(temporary.0.join("backups"), temporary.0.join("replaced")).is_err());
    drop(store);
    std::fs::rename(temporary.0.join("backups"), temporary.0.join("replaced")).unwrap();
}

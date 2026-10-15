// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Privileged NTFS fixtures: unique owned paths only, never installed backup data.
use super::*;
use std::collections::BTreeMap;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::*;
use windows::core::PWSTR;

const PARENT: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;LS)(A;OICI;GRGX;;;BU)";
const LEGACY: &str = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;LS)(A;;FA;;;BA)";
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Owns an atomically created private root before any fallible child setup.
struct Fixture(PathBuf);
impl Fixture {
    /// Creates an isolated private ancestor and canonical runtime-policy data parent.
    fn new() -> Self {
        let root = Path::new(r"C:\Program Files").join(format!(
            "openrdx-storage-install-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let attributes = Policy::production().unwrap();
        unsafe { CreateDirectoryW(PCWSTR(wide(&root).as_ptr()), Some(&attributes.attributes())) }
            .unwrap();
        let fixture = Self(root);
        with_descriptor(PARENT, |sd| {
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            unsafe {
                CreateDirectoryW(
                    PCWSTR(wide(&fixture.0.join("data")).as_ptr()),
                    Some(&attributes),
                )
            }
            .unwrap();
        });
        fixture
    }
    /// Supplies only this fixture's private leaf to the unchanged store implementation.
    fn store(&self) -> ManufacturingStore {
        ManufacturingStore::open_at(
            &self.0.join("data/manufacturing-backups"),
            Policy::production().unwrap(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    /// Deletes only the root successfully created by this fixture, after leases close.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Retains an API-allocated descriptor across one synchronous fixture operation.
fn with_descriptor(text: &str, action: impl FnOnce(PSECURITY_DESCRIPTOR)) {
    struct Allocation(PSECURITY_DESCRIPTOR);
    impl Drop for Allocation {
        /// Releases only the descriptor returned by the conversion API.
        fn drop(&mut self) {
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }
    let text: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(text.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .unwrap();
    let owned = Allocation(sd);
    action(owned.0);
}

/// Reads full owner/group/DACL text from the same no-follow fixture handle.
fn descriptor(path: &Path) -> String {
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .unwrap();
    let fields =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            fields,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
    }
    .ok()
    .unwrap();
    let mut text = PWSTR::null();
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            fields,
            &mut text,
            None,
        )
    };
    let _ = unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    converted.unwrap();
    let result = unsafe { text.to_string() };
    let _ = unsafe { LocalFree(Some(HLOCAL(text.0.cast()))) };
    result.unwrap()
}

/// Snapshots only fixture-owned descendants, including descriptors and exact file bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (String, Vec<u8>)> {
    let mut paths = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = paths.pop() {
        let bytes = if path.is_dir() {
            paths.extend(
                std::fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path()),
            );
            Vec::new()
        } else {
            std::fs::read(&path).unwrap()
        };
        result.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            (descriptor(&path), bytes),
        );
    }
    result
}

/// Missing storage is privately provisioned; its retained ancestry permits sibling publication.
#[test]
fn provisions_private_leaf_and_retains_it_through_sibling_publication() {
    let fixture = Fixture::new();
    let store = fixture.store();
    store
        .persist("record-123-0", &[0x42; 256], None, b"{}")
        .unwrap();
    let trust = fixture.0.join("data/LocalTrust");
    std::fs::create_dir(&trust).unwrap();
    std::fs::write(trust.join("history.tmp"), b"fixture intent").unwrap();
    std::fs::rename(trust.join("history.tmp"), trust.join("history.json")).unwrap();
    let before = snapshot(&fixture.0.join("data/manufacturing-backups"));
    drop(store);
    let reopened = fixture.store();
    assert_eq!(
        reopened.read("record-123-0", BackupFile::Record).unwrap(),
        [0x42; 256]
    );
    assert_eq!(
        snapshot(&fixture.0.join("data/manufacturing-backups")),
        before
    );
}

/// An equivalent existing private leaf is accepted without rewriting any fixture descriptor or byte.
#[test]
fn preserves_existing_private_backup_tree_with_legacy_ace_order() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let mut sector = [0x73; 4096];
    sector[..256].copy_from_slice(&[0x42; 256]);
    store
        .persist("record-123-0", &[0x42; 256], Some(&sector), b"{}")
        .unwrap();
    drop(store);
    let backup = fixture.0.join("data/manufacturing-backups");
    with_descriptor(LEGACY, |sd| {
        assert!(
            unsafe {
                SetFileSecurityW(
                    PCWSTR(wide(&backup).as_ptr()),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    sd,
                )
            }
            .as_bool()
        );
    });
    let before = snapshot(&backup);
    let store = fixture.store();
    assert_eq!(
        store.read("record-123-0", BackupFile::Record).unwrap(),
        [0x42; 256]
    );
    assert_eq!(
        store.read("record-123-0", BackupFile::Sector).unwrap(),
        sector
    );
    assert_eq!(snapshot(&backup), before);
}

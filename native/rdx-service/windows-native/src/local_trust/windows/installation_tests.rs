// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production runtime preparation exercised only on disposable protected trees.
use super::*;
use sha2::{Digest, Sha256};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    child: Option<Child>,
}
impl Drop for Fixture {
    /// Stops only the test's own copied process, then deletes its exact private tree.
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Windows may release the copied image mapping shortly after process exit.
        // Retry only this owned fixture; never alter its protection or other paths.
        for _ in 0..40 {
            match std::fs::remove_dir_all(&self.root) {
                Ok(()) => return,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        if !std::thread::panicking() {
            panic!("owned runtime fixture cleanup failed");
        }
    }
}
/// Gives the mapped-executable fixture a harmless test-only waiting process.
#[test]
fn mapped_fixture_child() {
    if std::env::var_os("OPENRDX_MAPPED_FIXTURE_CHILD").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(20));
    }
}
/// Protects, pins and hashes a final NSIS-like tree while its own copied image is mapped.
#[test]
fn native_runtime_preparation_preserves_complete_mapped_payload() {
    let root = Path::new(LOCAL_RUNTIME_ROOT)
        .parent()
        .unwrap()
        .join(format!(
            "openrdx-runtime-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    create_protected_directory(&root).unwrap();
    let mut fixture = Fixture { root, child: None };
    let manifest = fixture.root.join("resources/local-trust/runtime.json");
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    let image = fixture.root.join("OpenRDXManager.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &image).unwrap();
    let inventory = RuntimeInventory {
        schema_version: 1,
        platform: "windows".into(),
        files: vec![rdx_local_trust::RuntimeFile {
            path: "OpenRDXManager.exe".into(),
            size: std::fs::metadata(&image).unwrap().len(),
            sha256: format!("{:x}", Sha256::digest(std::fs::read(&image).unwrap())),
        }],
        links: vec![],
        manager_cd_hash: "".into(),
        helper_cd_hash: "".into(),
    };
    std::fs::write(&manifest, serde_json::to_vec(&inventory).unwrap()).unwrap();
    std::fs::write(
        fixture.root.join("uninstallerIcon.ico"),
        b"fixed-administrator-icon",
    )
    .unwrap();
    let test_name = format!(
        "{}::mapped_fixture_child",
        module_path!().split_once("::").unwrap().1
    );
    fixture.child = Some(
        Command::new(&image)
            .args(["--exact", &test_name])
            .env("OPENRDX_MAPPED_FIXTURE_CHILD", "1")
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        fixture
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
    );
    let (pins, bytes) = prepare_runtime_files(&fixture.root, &test_administrator_sid())
        .expect("complete installed files must prepare with mapped image");
    let enrolled = parse_inventory(&bytes, "windows").unwrap();
    assert!(
        enrolled
            .files
            .iter()
            .any(|file| file.path == "uninstallerIcon.ico")
    );
    verify_runtime(&fixture.root, &enrolled).unwrap();
    drop(pins);
}

/// Refuses a foreign write lease instead of relaxing immutable runtime sharing.
#[test]
fn native_runtime_preparation_refuses_existing_writer() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = Path::new(LOCAL_RUNTIME_ROOT)
        .parent()
        .unwrap()
        .join(format!(
            "openrdx-runtime-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    create_protected_directory(&root).unwrap();
    let fixture = Fixture { root, child: None };
    let path = fixture.root.join("retained-writer.bin");
    std::fs::write(&path, b"fixture").unwrap();
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(1 | 2)
        .open(&path)
        .unwrap();
    assert!(matches!(
        prepare_runtime_files(&fixture.root, &test_administrator_sid()),
        Err(NativeError::AccessDenied)
    ));
    drop(writer);
}
/// Copies an explicit test-only payload without accepting reparses or modifying it.
fn copy_payload(
    source: &Path,
    destination: &Path,
    root: &Path,
    files: &mut Vec<rdx_local_trust::RuntimeFile>,
) {
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        assert!(!kind.is_symlink());
        let path = destination.join(entry.file_name());
        if kind.is_dir() {
            std::fs::create_dir(&path).unwrap();
            copy_payload(&entry.path(), &path, root, files);
        } else {
            assert!(kind.is_file());
            std::fs::copy(entry.path(), &path).unwrap();
            let mut file = File::open(&path).unwrap();
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 65536];
            loop {
                let size = file.read(&mut buffer).unwrap();
                if size == 0 {
                    break;
                }
                hasher.update(&buffer[..size]);
            }
            files.push(rdx_local_trust::RuntimeFile {
                path: path
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                size: file.metadata().unwrap().len(),
                sha256: format!("{:x}", hasher.finalize()),
            });
        }
    }
}
/// Exercises an explicitly supplied historical packaged tree with fresh fixture inventory.
/// This opt-in test cannot redirect the production fixed installation root.
#[test]
#[ignore = "requires an explicitly extracted Windows payload fixture"]
fn native_runtime_preparation_accepts_packaged_payload_shape() {
    let source = PathBuf::from(
        std::env::var_os("OPENRDX_PACKAGED_FIXTURE").expect("explicit test fixture required"),
    );
    let root = Path::new(LOCAL_RUNTIME_ROOT)
        .parent()
        .unwrap()
        .join(format!(
            "openrdx-runtime-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    create_protected_directory(&root).unwrap();
    let fixture = Fixture { root, child: None };
    let mut files = Vec::new();
    copy_payload(&source, &fixture.root, &fixture.root, &mut files);
    eprintln!("packaged-payload-fixture files={}", files.len());
    let inventory = RuntimeInventory {
        schema_version: 1,
        platform: "windows".into(),
        files,
        links: vec![],
        manager_cd_hash: String::new(),
        helper_cd_hash: String::new(),
    };
    let manifest = fixture.root.join("resources/local-trust/runtime.json");
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    std::fs::write(&manifest, serde_json::to_vec(&inventory).unwrap()).unwrap();
    std::fs::write(fixture.root.join("uninstallerIcon.ico"), b"fixture-icon").unwrap();
    let (pins, bytes) = prepare_runtime_files(&fixture.root, &test_administrator_sid())
        .expect("packaged shape must prepare");
    verify_runtime(&fixture.root, &parse_inventory(&bytes, "windows").unwrap()).unwrap();
    drop(pins);
}

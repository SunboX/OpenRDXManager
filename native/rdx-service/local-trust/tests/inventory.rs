// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_local_trust::{MAX_INVENTORY_BYTES, parse_inventory, verify_enrollment, verify_runtime};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;

/// Build an inventory of one real file with the correct digest.
fn inventory(platform: &str, path: &str, bytes: &[u8]) -> Value {
    json!({"schemaVersion":1,"platform":platform,"files":[{"path":path,"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes))}],"links":[],"managerCdHash":if platform == "macos" {"a".repeat(40)} else {String::new()},"helperCdHash":if platform == "macos" {"b".repeat(40)} else {String::new()}})
}

/// Encode test JSON without bypassing the parser's schema validation.
fn parse(value: &Value, platform: &str) -> rdx_local_trust::RuntimeInventory {
    parse_inventory(&serde_json::to_vec(value).unwrap(), platform).unwrap()
}

#[test]
/// A real digest admits a file and rejects same-size content replacement.
fn verifies_real_content_then_rejects_tampering() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("app.asar"), b"sealed").unwrap();
    let policy = parse(&inventory("macos", "app.asar", b"sealed"), "macos");
    verify_runtime(root.path(), &policy).unwrap();
    fs::write(root.path().join("app.asar"), b"broken").unwrap();
    assert!(verify_runtime(root.path(), &policy).is_err());
}

#[test]
/// Complete runtime verification rejects length mismatches and added code.
fn rejects_wrong_size_and_unlisted_content() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("app.asar"), b"sealed").unwrap();
    let mut value = inventory("macos", "app.asar", b"sealed");
    value["files"][0]["size"] = json!(7);
    assert!(verify_runtime(root.path(), &parse(&value, "macos")).is_err());
    value["files"][0]["size"] = json!(6);
    fs::write(root.path().join("extra.js"), b"execute me").unwrap();
    assert!(verify_runtime(root.path(), &parse(&value, "macos")).is_err());
}

#[test]
/// Portable path rules deny traversal, aliases and duplicate file records.
fn rejects_duplicate_traversal_and_noncanonical_paths() {
    for path in [
        "../outside",
        "/app",
        "a/../app",
        "a/./app",
        "a//app",
        "a\\app",
        "C:app",
        "a\0app",
        "a/",
        ".",
        "",
    ] {
        assert!(
            parse_inventory(
                &serde_json::to_vec(&inventory("windows", path, b"a")).unwrap(),
                "windows"
            )
            .is_err(),
            "accepted {path:?}"
        );
    }
    let mut value = inventory("windows", "app.exe", b"a");
    let duplicate = value["files"][0].clone();
    value["files"].as_array_mut().unwrap().push(duplicate);
    assert!(parse_inventory(&serde_json::to_vec(&value).unwrap(), "windows").is_err());
}

#[test]
/// Schema, platform and bounds validation remain fail closed.
fn rejects_unknown_fields_versions_platform_and_invalid_hashes() {
    for (field, value) in [
        ("unexpected", json!(true)),
        ("schemaVersion", json!(2)),
        ("platform", json!("linux")),
        ("managerCdHash", json!("a".repeat(40))),
        ("files", json!([])),
    ] {
        let mut policy = inventory("windows", "app.exe", b"a");
        policy[field] = value;
        assert!(parse_inventory(&serde_json::to_vec(&policy).unwrap(), "windows").is_err());
    }
    let mut policy = inventory("macos", "app", b"a");
    policy["files"][0]["sha256"] = json!("A".repeat(64));
    assert!(parse_inventory(&serde_json::to_vec(&policy).unwrap(), "macos").is_err());
    assert!(
        parse_inventory(
            &serde_json::to_vec(&inventory("windows", "app", b"a")).unwrap(),
            "macos"
        )
        .is_err()
    );
    assert!(parse_inventory(&vec![b' '; MAX_INVENTORY_BYTES + 1], "macos").is_err());
    assert!(parse_inventory(br#"{"schemaVersion":1,"schemaVersion":1}"#, "macos").is_err());
}

#[test]
/// A user-selected temporary path cannot become endpoint enrollment policy.
fn rejects_enrollment_at_caller_selected_path() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("runtime.json");
    fs::write(
        &path,
        serde_json::to_vec(&inventory("macos", "app", b"a")).unwrap(),
    )
    .unwrap();
    assert!(verify_enrollment(&path, "macos").is_err());
}

#[cfg(unix)]
#[test]
/// Installer pending reads preserve production ownership rules.
fn protected_pending_inventory_rejects_user_owned_content() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("pending-runtime.json");
    fs::write(
        &path,
        serde_json::to_vec(&inventory("macos", "app", b"a")).unwrap(),
    )
    .unwrap();
    assert!(rdx_local_trust::read_protected_inventory(&path, "macos").is_err());
}

#[cfg(unix)]
#[test]
/// Setup directories must have the same protected ancestor and ACL policy.
fn protected_setup_directory_rejects_user_owned_location() {
    let root = tempfile::tempdir().unwrap();
    assert!(rdx_local_trust::verify_protected_directory(root.path()).is_err());
}

#[cfg(unix)]
#[test]
/// An open setup lease cannot hide unsafe permissions from the descriptor check.
fn protected_descriptor_rejects_writable_held_file() {
    use std::os::unix::fs::PermissionsExt;
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o666))
        .unwrap();
    assert!(rdx_local_trust::verify_protected_descriptor(file.as_file()).is_err());
}

#[cfg(unix)]
#[test]
/// ACL-only inspection accepts a default temporary file without claiming ownership.
fn descriptor_acl_inspection_accepts_a_default_real_file() {
    let file = tempfile::NamedTempFile::new().unwrap();
    rdx_local_trust::verify_descriptor_acl(file.as_file()).unwrap();
}

#[cfg(unix)]
#[test]
/// Framework aliases work only with exact pinned internal targets.
fn accepts_only_declared_framework_links_with_pinned_literal_targets() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let dir = "Contents/Frameworks/Test.framework";
    fs::create_dir_all(root.path().join(dir).join("Versions/A")).unwrap();
    fs::write(root.path().join(dir).join("Versions/A/Test"), b"sealed").unwrap();
    symlink("A", root.path().join(dir).join("Versions/Current")).unwrap();
    symlink("Versions/Current/Test", root.path().join(dir).join("Test")).unwrap();
    let mut value = inventory("macos", &format!("{dir}/Versions/A/Test"), b"sealed");
    value["links"] = json!([{"path":format!("{dir}/Versions/Current"),"target":"A"},{"path":format!("{dir}/Test"),"target":"Versions/Current/Test"}]);
    verify_runtime(root.path(), &parse(&value, "macos")).unwrap();
    fs::remove_file(root.path().join(dir).join("Test")).unwrap();
    symlink("/etc/passwd", root.path().join(dir).join("Test")).unwrap();
    assert!(verify_runtime(root.path(), &parse(&value, "macos")).is_err());
    value["links"][1]["target"] = json!("../../../../../../etc/passwd");
    assert!(parse_inventory(&serde_json::to_vec(&value).unwrap(), "macos").is_err());
    value["platform"] = json!("windows");
    assert!(parse_inventory(&serde_json::to_vec(&value).unwrap(), "windows").is_err());
}

#[cfg(unix)]
#[test]
/// Multiple names and undeclared redirects cannot authorize runtime content.
fn rejects_undeclared_symlinks_and_hardlinks() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("app"), b"sealed").unwrap();
    let value = inventory("macos", "app", b"sealed");
    fs::hard_link(root.path().join("app"), root.path().join("copy")).unwrap();
    assert!(verify_runtime(root.path(), &parse(&value, "macos")).is_err());
    fs::remove_file(root.path().join("copy")).unwrap();
    symlink("app", root.path().join("link")).unwrap();
    assert!(verify_runtime(root.path(), &parse(&value, "macos")).is_err());
}

#[test]
/// Nested records also reject unknown fields and platform aliases.
fn rejects_unknown_nested_fields_and_case_aliased_windows_records() {
    let mut value = inventory("windows", "Manager.exe", b"a");
    value["files"][0]["execute"] = json!(true);
    assert!(parse_inventory(&serde_json::to_vec(&value).unwrap(), "windows").is_err());
    value["files"][0].as_object_mut().unwrap().remove("execute");
    let mut duplicate = value["files"][0].clone();
    duplicate["path"] = json!("manager.exe");
    value["files"].as_array_mut().unwrap().push(duplicate);
    assert!(parse_inventory(&serde_json::to_vec(&value).unwrap(), "windows").is_err());
}

#[test]
/// The Windows self-inventory/uninstaller exception cannot hide extra code.
fn windows_allows_only_exact_installer_exclusions() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("Manager.exe"), b"sealed").unwrap();
    fs::create_dir_all(root.path().join("resources/local-trust")).unwrap();
    fs::write(
        root.path().join("resources/local-trust/runtime.json"),
        b"embedded inventory",
    )
    .unwrap();
    fs::write(
        root.path().join("Uninstall OpenRDXManager.exe"),
        b"NSIS uninstall",
    )
    .unwrap();
    fs::write(root.path().join("uninstallerIcon.ico"), b"NSIS icon").unwrap();
    let policy = parse(&inventory("windows", "Manager.exe", b"sealed"), "windows");
    verify_runtime(root.path(), &policy).unwrap();
    fs::write(root.path().join("Uninstall other.exe"), b"extra").unwrap();
    assert!(verify_runtime(root.path(), &policy).is_err());
}

#[test]
/// Native installer serialization preserves the strict wire schema.
fn parsed_inventory_serializes_with_the_same_canonical_field_names() {
    let value = inventory("windows", "Manager.exe", b"sealed");
    let parsed = parse(&value, "windows");
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
}

#[cfg(unix)]
#[test]
/// A declared link loop is not a bounded route to inventoried content.
fn rejects_declared_framework_link_cycles() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let framework = "Contents/Frameworks/Test.framework";
    fs::create_dir_all(root.path().join(framework)).unwrap();
    fs::write(root.path().join("app"), b"sealed").unwrap();
    symlink("B", root.path().join(framework).join("A")).unwrap();
    symlink("A", root.path().join(framework).join("B")).unwrap();
    let mut value = inventory("macos", "app", b"sealed");
    value["links"] = json!([{"path":format!("{framework}/A"),"target":"B"},{"path":format!("{framework}/B"),"target":"A"}]);
    assert!(verify_runtime(root.path(), &parse(&value, "macos")).is_err());
}

#[test]
/// Installer preflight includes retained ancestors and bounded process headroom.
fn runtime_handle_requirement_counts_unique_parent_directories() {
    let flat = parse(&inventory("macos", "app", b"sealed"), "macos");
    let nested = parse(
        &inventory("macos", "Contents/Resources/app.asar", b"sealed"),
        "macos",
    );
    let flat_count = rdx_local_trust::runtime_handle_requirement(&flat).unwrap();
    let nested_count = rdx_local_trust::runtime_handle_requirement(&nested).unwrap();
    assert!(flat_count >= 129);
    assert_eq!(nested_count, flat_count + 2);
}

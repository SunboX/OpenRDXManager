// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native filesystem policy, secret redaction, and opt-in disposable-image proof.
use rdx_service::model::{Filesystem, FormatPassphrase, OperationRequest};

#[test]
fn format_password_is_bounded_redacted_and_not_required_for_plain_requests() {
    let passphrase: FormatPassphrase =
        serde_json::from_str("\"temporary example password\"").unwrap();
    assert_eq!(format!("{passphrase:?}"), "[REDACTED]");
    for value in ["\"\"", "\"line\\nbreak\"", "\"nul\\u0000byte\""] {
        assert!(serde_json::from_str::<FormatPassphrase>(value).is_err());
    }
    let request: OperationRequest = serde_json::from_str(r#"{"kind":"format","deviceId":"rdx:example","deviceRevision":1,"filesystem":"apfs-encrypted","passphrase":"temporary example password","confirmationToken":"confirm:example"}"#).unwrap();
    assert!(!format!("{request:?}").contains("temporary example"));
    assert_eq!(
        Filesystem::ApfsCaseSensitiveEncrypted.macos_selector(),
        Some(14)
    );
    assert!(Filesystem::ApfsCaseSensitiveEncrypted.encrypted());
    assert_eq!(Filesystem::Ntfs.macos_selector(), None);
}

/// Creates a disposable image, runs the actual native pipeline, and always detaches.
#[cfg(target_os = "macos")]
fn exercise_image(selector: u32, size: &str) {
    use std::process::Command;
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("format-proof.sparseimage");
    let created = Command::new("/usr/bin/hdiutil")
        .args([
            "create", "-size", size, "-layout", "NONE", "-type", "SPARSE", "-o",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(created.status.success(), "image creation failed");
    let attached = Command::new("/usr/bin/hdiutil")
        .args(["attach", "-nomount"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(attached.status.success(), "image attachment failed");
    let output = String::from_utf8(attached.stdout).unwrap();
    let device = output.split_whitespace().next().unwrap();
    let bsd = device.strip_prefix("/dev/").unwrap();
    let password = matches!(selector, 13 | 14).then_some("temporary disk image password");
    let result = rdx_macos_native::system_format_virtual_disk_for_test(bsd, selector, password);
    let mut detached = Command::new("/usr/bin/hdiutil")
        .args(["detach", device])
        .output()
        .unwrap();
    if !detached.status.success() {
        detached = Command::new("/usr/bin/hdiutil")
            .args(["detach", "-force", device])
            .output()
            .unwrap();
    }
    assert!(detached.status.success(), "image detach failed");
    assert!(
        result,
        "native formatting/readback failed for selector {selector}"
    );
}

#[test]
#[cfg(target_os = "macos")]
#[ignore = "creates disposable virtual disk images; run explicitly for native formatter verification"]
fn all_native_formats_verify_on_disposable_disk_images() {
    let requested = std::env::var("OPENRDX_FORMAT_TEST_SELECTOR")
        .ok()
        .map(|value| value.parse::<u32>().unwrap());
    for selector in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14] {
        if requested.is_some_and(|value| value != selector) {
            continue;
        }
        eprintln!("Verifying native filesystem selector {selector}");
        exercise_image(selector, if selector == 4 { "8m" } else { "512m" });
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fs;
use std::path::Path;
use std::process::Command;

/// Builds the downstream probe manifest with a TOML-safe serialized path.
fn fixture_probe_manifest(crate_root: &Path) -> String {
    let dependency_path = serde_json::to_string(crate_root.to_string_lossy().as_ref())
        .expect("fixture dependency path serializes as a TOML-compatible string");
    format!(
        "[package]\nname = \"fixture-feature-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nrdx-service = {{ path = {dependency_path}, default-features = false }}\n"
    )
}

/// Proves Windows dependency paths remain valid quoted TOML strings.
#[test]
fn fixture_manifest_escapes_windows_dependency_paths() {
    let manifest =
        fixture_probe_manifest(Path::new(r"C:\workspace\OpenRDXManager\native\rdx-service"));

    assert!(manifest.contains(r#"path = "C:\\workspace\\OpenRDXManager\\native\\rdx-service""#));
}

/// Proves deterministic adapter construction is absent from the safe default API.
#[test]
fn fixture_construction_requires_the_explicit_feature() {
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let project = tempfile::tempdir().unwrap();
    fs::create_dir(project.path().join("src")).unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        fixture_probe_manifest(crate_root),
    )
    .unwrap();
    fs::write(
        project.path().join("src/main.rs"),
        "use rdx_service::host::FixtureDevice;\nfn main() { let _ = core::mem::size_of::<FixtureDevice>(); }\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline", "--quiet"])
        .current_dir(project.path())
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "FixtureDevice unexpectedly exists without the fixtures feature"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unresolved import `rdx_service::host::FixtureDevice`"),
        "compiler failure was not the gated fixture symbol: {stderr}"
    );
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One primary compiler rejection, independent of diagnostic decoration.
pub struct Rejection<'a> {
    pub code: Option<&'a str>,
    pub line: u64,
    pub message_parts: &'a [&'a str],
}

/// Locates metadata from a successful locked Cargo library check, not a glob
/// that might select an old or differently featured build.
fn checked_library() -> PathBuf {
    let output = Command::new(std::env::var_os("CARGO").expect("Cargo test runner"))
        .args([
            "check",
            "--offline",
            "--locked",
            "--all-features",
            "--lib",
            "--message-format=json",
            "--manifest-path",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .output()
        .expect("run library check");
    assert!(
        output.status.success(),
        "library check must succeed before negative tests: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut artifacts = Vec::new();
    for line in output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: Value = serde_json::from_slice(line).expect("Cargo JSON");
        if message["reason"] == "compiler-artifact" && message["target"]["name"] == "rdx_service" {
            for file in message["filenames"].as_array().expect("artifact filenames") {
                let path = PathBuf::from(file.as_str().expect("artifact path"));
                if path
                    .extension()
                    .is_some_and(|extension| extension == "rmeta")
                {
                    artifacts.push(path);
                }
            }
        }
    }
    assert_eq!(artifacts.len(), 1, "exact current library metadata");
    artifacts.remove(0)
}

/// Type-checks only: no generated fixture executable or device command can run.
fn compile(source: &Path, library: &Path, destination: &Path) -> std::process::Output {
    Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args([
            "--edition=2024",
            "--crate-type=bin",
            "--emit=metadata",
            "--error-format=json",
            "--extern",
        ])
        .arg(format!("rdx_service={}", library.display()))
        .arg("-L")
        .arg(format!(
            "dependency={}",
            library.parent().expect("metadata directory").display()
        ))
        .arg("-o")
        .arg(destination)
        .arg(source)
        .output()
        .expect("run fixture compiler")
}

/// Proves allowed type access first, then demands each exact forbidden operation
/// fail for its intended primary error, not a missing tool, dependency or typo.
pub fn check_cases(cases: &[(&str, &[Rejection<'_>])]) {
    let library = checked_library();
    let temporary = tempfile::tempdir().expect("isolated compiler outputs");
    let control = temporary.path().join("allowed.rs");
    std::fs::write(&control, "use rdx_service::host::DeviceSession; fn main() { let _ = std::mem::size_of::<DeviceSession>(); }\n").expect("write positive control");
    let allowed = compile(&control, &library, &temporary.path().join("allowed.rmeta"));
    assert!(
        allowed.status.success(),
        "positive API control must compile: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    for (name, expected) in cases {
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/ui")
            .join(name);
        let output = compile(&source, &library, &temporary.path().join("rejected.rmeta"));
        assert_eq!(
            output.status.code(),
            Some(1),
            "{name} must be a compiler rejection"
        );
        let diagnostics: Vec<Value> = output
            .stderr
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("rustc JSON diagnostic"))
            .filter(|message: &Value| {
                message["level"] == "error"
                    && !message["spans"].as_array().expect("spans").is_empty()
            })
            .collect();
        assert_eq!(
            diagnostics.len(),
            expected.len(),
            "{name}: unexpected primary errors: {diagnostics:?}"
        );
        for (diagnostic, rejection) in diagnostics.iter().zip(*expected) {
            assert_eq!(
                diagnostic["code"]["code"].as_str(),
                rejection.code,
                "{name}"
            );
            let message = diagnostic["message"].as_str().expect("diagnostic message");
            for part in rejection.message_parts {
                assert!(message.contains(part), "{name}: wrong rejection: {message}");
            }
            assert!(
                diagnostic["spans"]
                    .as_array()
                    .expect("spans")
                    .iter()
                    .any(|span| {
                        span["is_primary"] == true
                            && span["line_start"].as_u64() == Some(rejection.line)
                            && span["file_name"]
                                .as_str()
                                .is_some_and(|file| Path::new(file) == source)
                    }),
                "{name}: rejection must identify the forbidden expression"
            );
        }
    }
}

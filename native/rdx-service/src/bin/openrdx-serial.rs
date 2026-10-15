#![forbid(unsafe_code)]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit-target macOS serial inspection, durable preparation, and guarded application.

#[path = "../serial_cli/mod.rs"]
mod serial_cli;

/// Routes the private capture worker or the closed user-facing command grammar.
fn main() {
    #[cfg(target_os = "macos")]
    if std::env::args_os().skip(1).collect::<Vec<_>>() == ["--openrdx-internal-macos-scsi-worker"] {
        let result = rdx_macos_native::run_serial_scsi_worker_stdio();
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }
    let result = serial_cli::run(std::env::args_os().skip(1));
    let (value, exit) = match result {
        Ok(value) => (value, 0),
        Err(error) => (serde_json::json!({"status": "error", "code": error}), 1),
    };
    println!("{value}");
    std::process::exit(exit);
}

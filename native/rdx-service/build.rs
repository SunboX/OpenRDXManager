// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keep offline integration-test executables out of Windows installer detection.

/// Adds an explicit, non-elevating UAC manifest only to Windows MSVC test targets.
/// Production executables retain their existing privilege and packaging policy.
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        // Names such as compatibility_setup must not trigger installer heuristics.
        println!("cargo::rustc-link-arg-tests=/MANIFEST:EMBED");
        println!("cargo::rustc-link-arg-tests=/MANIFESTUAC:level='asInvoker' uiAccess='false'");
    }
}

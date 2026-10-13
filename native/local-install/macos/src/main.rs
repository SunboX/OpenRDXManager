// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Administrator-only fixed installation entrypoint, with no caller paths.

#[cfg(target_os = "macos")]
mod install;
#[cfg(target_os = "macos")]
mod package_source;
#[cfg(target_os = "macos")]
mod supervisor_roles;
#[cfg(target_os = "macos")]
mod supervisor_spawn;
#[cfg(target_os = "macos")]
mod transaction;

/// Validate command arity before applying the fixed native administrator policy.
fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(target_os = "macos")]
    let result = if arguments.first().map(String::as_str) == Some("--internal-supervisor") {
        supervisor_roles::run(&arguments)
    } else {
        openrdx_macos_local_install::parse_action(&arguments).and_then(run)
    };
    #[cfg(not(target_os = "macos"))]
    let result = openrdx_macos_local_install::parse_action(&arguments).and_then(run);
    if let Err(error) = result {
        eprintln!("OpenRDXManager setup refused: {error}");
        std::process::exit(1);
    }
}

/// Dispatch only the compiled macOS actions; every action requires effective root.
#[cfg(target_os = "macos")]
fn run(action: &str) -> Result<(), String> {
    // No renderer or environment value can substitute for native administrator approval.
    if unsafe { libc::geteuid() } != 0 {
        return Err("run the OpenRDXManager package installer with administrator approval".into());
    }
    match action {
        "prepare" => transaction::prepare(),
        "install" => install::commit(),
        "verify" => transaction::verify(),
        "repair" => transaction::repair(),
        "remove" => transaction::remove(),
        _ => unreachable!("validated fixed action"),
    }
}

/// Never substitute a portable platform implementation for macOS root policy.
#[cfg(not(target_os = "macos"))]
fn run(_: &str) -> Result<(), String> {
    Err("this installer is supported only on macOS".into())
}

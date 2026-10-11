// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Elevated installer entrypoint for the fixed OpenRDX service DACL.

use std::process::ExitCode;

use rdx_windows_native::{
    ManagerServiceAccessOutcome, apply_manager_service_access,
    parse_manager_service_access_arguments,
};

/// Parses the exact argument contract and applies one sanitized operation.
fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let Ok(command) = parse_manager_service_access_arguments(&borrowed) else {
        eprintln!("openrdx-service-acl: invalid arguments");
        return ExitCode::from(2);
    };
    match apply_manager_service_access(command) {
        Ok(
            ManagerServiceAccessOutcome::AlreadyExact
            | ManagerServiceAccessOutcome::Changed
            | ManagerServiceAccessOutcome::Verified
            | ManagerServiceAccessOutcome::Removed,
        ) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("openrdx-service-acl: service access operation failed");
            ExitCode::from(3)
        }
    }
}

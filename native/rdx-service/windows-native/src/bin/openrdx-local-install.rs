// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Elevated fixed installation entrypoint; exposes no trust-policy arguments.
use std::process::ExitCode;
/// Applies only parsed native install actions and emits a bounded repair instruction.
fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let borrowed: Vec<_> = arguments.iter().map(String::as_str).collect();
    let Ok(command) = rdx_windows_native::parse_local_install_arguments(&borrowed) else {
        eprintln!("OpenRDX setup: invalid fixed action or missing live Manager PID");
        return ExitCode::from(2);
    };
    match rdx_windows_native::apply_local_install(command) {
        Ok(()) => {
            use rdx_windows_native::LocalInstallAction;
            let evidence = match command.action() {
                LocalInstallAction::Prepare => {
                    "admission=revoked runtime=owned quiescence=verified"
                }
                LocalInstallAction::Install | LocalInstallAction::Repair => {
                    "trust=local runtime=protected-and-hash-verified service=LocalService service-sid=unrestricted device-access=unverified"
                }
                LocalInstallAction::Verify => {
                    "trust=local runtime=protected-and-hash-verified service=LocalService service-sid=unrestricted device-access=unverified"
                }
                LocalInstallAction::Remove => {
                    "service=removed enrollment=revoked journal=preserved"
                }
            };
            println!("OpenRDX setup verified: {evidence}");
            ExitCode::SUCCESS
        }
        Err(rdx_windows_native::NativeError::Busy) => {
            eprintln!(
                "OpenRDX setup: service is active; close Manager, wait for hardware operations to finish, then retry setup"
            );
            ExitCode::from(4)
        }
        Err(_) => {
            eprintln!(
                "OpenRDX setup incomplete: launch installed Manager as the active console user, then rerun the elevated installer Repair action"
            );
            ExitCode::from(3)
        }
    }
}

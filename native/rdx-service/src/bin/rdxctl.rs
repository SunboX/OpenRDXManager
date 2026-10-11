#![forbid(unsafe_code)]
// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#![deny(missing_docs)]

//! Bounded high-level command-line companion for OpenRDXManager.

use std::io;
use std::process::ExitCode;

use rdx_service::service::cli;

/// Runs the strict CLI without placing raw paths or device commands on its boundary.
fn main() -> ExitCode {
    let standard_output = io::stdout();
    let standard_error = io::stderr();
    let mut output = standard_output.lock();
    let mut diagnostics = standard_error.lock();
    let exit = cli::run(std::env::args_os().skip(1), &mut output, &mut diagnostics);
    ExitCode::from(exit.as_u8())
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit-target, read-only vendor-0283 snapshot research command.

/// Runs the closed collector without exposing device fields to process output.
fn main() {
    rdx_service::factory_snapshot::run_cli_and_exit(std::env::args_os().skip(1));
}

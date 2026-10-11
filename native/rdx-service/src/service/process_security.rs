// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-owned panic diagnostics for the supervised native executable.

use std::io::{self, Write};

const FATAL_DIAGNOSTIC: &[u8] = b"openrdx-hardware: fatal native service failure\n";

/// Installs one process-wide panic hook which never formats attacker-controlled payloads.
///
/// The native executable must call this once at the start of `main`, before it
/// starts threads or invokes an adapter. The executable owns the whole process,
/// so the hook intentionally replaces and does not chain any prior hook: a
/// chained hook could print the panic payload, source path, or adapter internals.
pub fn install_process_panic_redaction() {
    std::panic::set_hook(Box::new(|_| {
        let mut stderr = io::stderr().lock();
        let _ = stderr.write_all(FATAL_DIAGNOSTIC);
    }));
}

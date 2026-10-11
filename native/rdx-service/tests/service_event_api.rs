// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Proves raw caller-authored service events are not a downstream API.
#[test]
fn service_event_terminals_require_native_proof() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/service_event_raw_publish.rs");
}

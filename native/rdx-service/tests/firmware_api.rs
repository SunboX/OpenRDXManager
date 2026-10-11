// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Proves that validated-but-unauthorized images cannot expose transfer data
/// and that callers cannot manufacture transfer chunks themselves.
#[test]
fn transfer_api_requires_an_authorized_image() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/firmware_image_*.rs");
    cases.compile_fail("tests/ui/firmware_installable_fields.rs");
    cases.compile_fail("tests/ui/firmware_chunk_fields.rs");
}

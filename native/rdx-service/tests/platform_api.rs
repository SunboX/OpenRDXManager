// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Proves platform locator and resolution capabilities cannot be copied or serialized.
#[test]
fn platform_registry_api_keeps_private_bindings_linear() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/candidate_device_clone.rs");
    cases.compile_fail("tests/ui/candidate_device_locator.rs");
    cases.compile_fail("tests/ui/candidate_device_serialize.rs");
    cases.compile_fail("tests/ui/candidate_lease_clone.rs");
    cases.compile_fail("tests/ui/candidate_lease_serialize.rs");
    cases.compile_fail("tests/ui/device_lease_clone.rs");
    cases.compile_fail("tests/ui/device_lease_serialize.rs");
    cases.compile_fail("tests/ui/resolved_device_clone.rs");
    cases.compile_fail("tests/ui/resolved_device_lease.rs");
    cases.compile_fail("tests/ui/resolved_device_serialize.rs");
    cases.compile_fail("tests/ui/windows_backend_from_readiness.rs");
    cases.compile_fail("tests/ui/windows_readiness_construct.rs");
    cases.compile_fail("tests/ui/windows_volume_lease_clone.rs");
    cases.compile_fail("tests/ui/windows_validated_volume_lease_clone.rs");
    cases.compile_fail("tests/ui/windows_volume_validation_only.rs");
    cases.compile_fail("tests/ui/windows_completion_command_mismatch.rs");
}

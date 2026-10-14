// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared fixed test-only exit vocabulary; never contains identities or arbitrary status text.

/// Argument-free child's closed self-check failures, encoded as fixed exit bytes.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum SelfCheckFailure {
    /// Opening its own query token failed.
    TokenOpen = 32,
    /// Reading its own process session failed.
    ProcessSession = 33,
    /// Active-console/process-session comparison failed.
    ConsoleSession = 34,
    /// Own token/session read or comparison failed.
    TokenSession = 35,
    /// Own elevation read or nonzero-elevation refusal failed.
    Elevation = 36,
    /// Own UIAccess read or zero comparison failed.
    UiAccess = 37,
    /// Own SandboxInert read or zero comparison failed.
    SandboxInert = 38,
    /// Own token type read or primary comparison failed.
    Primary = 39,
    /// Own bounded mandatory label read or exact-medium comparison failed.
    Integrity = 40,
}

/// Classifies only owned-child exit status into a fixed public token; raw status stays private.
#[allow(dead_code)] // Used by the parent proof; the argument-free fixture only emits fixed bytes.
pub fn category(code: u32) -> &'static str {
    match code {
        0 => "success",
        32 => "self-token-open",
        33 => "self-process-session",
        34 => "self-console-session",
        35 => "self-token-session",
        36 => "self-elevation",
        37 => "self-ui-access",
        38 => "self-sandbox-inert",
        39 => "self-primary",
        40 => "self-integrity",
        // Exact NTSTATUS names, not a guess about the failing DLL or its cause.
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
        0xC000_0135 => "status-dll-not-found",
        0xC000_0142 => "status-dll-init-failed",
        0xC000_007B => "status-invalid-image-format",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fixture failure maps to its exact distinct category without status/identity output.
    #[test]
    fn self_check_categories_are_exact() {
        for (failure, expected) in [
            (SelfCheckFailure::TokenOpen, "self-token-open"),
            (SelfCheckFailure::ProcessSession, "self-process-session"),
            (SelfCheckFailure::ConsoleSession, "self-console-session"),
            (SelfCheckFailure::TokenSession, "self-token-session"),
            (SelfCheckFailure::Elevation, "self-elevation"),
            (SelfCheckFailure::UiAccess, "self-ui-access"),
            (SelfCheckFailure::SandboxInert, "self-sandbox-inert"),
            (SelfCheckFailure::Primary, "self-primary"),
            (SelfCheckFailure::Integrity, "self-integrity"),
        ] {
            assert!(category(failure as u32) == expected);
            assert!(category(failure as u32) != "success");
        }
    }

    /// Known loader statuses and unknown values never become fixture success.
    #[test]
    fn status_categories_are_bounded() {
        assert!(category(0) == "success");
        assert!(category(0xC000_0135) == "status-dll-not-found");
        assert!(category(0xC000_0142) == "status-dll-init-failed");
        assert!(category(0xC000_007B) == "status-invalid-image-format");
        for code in [1, 17, 19, 31, 41, 259, 0xC000_0005, u32::MAX] {
            assert!(category(code) == "unknown");
        }
    }
}

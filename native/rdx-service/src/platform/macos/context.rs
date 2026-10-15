// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit macOS direct-process authority mapping.

use crate::service::ServiceExecutionContext;

use super::MacOsReadinessFacts;

/// Applies one explicit execution context without changing endpoint facts.
pub(super) const fn apply(
    mut facts: MacOsReadinessFacts,
    context: &ServiceExecutionContext,
) -> MacOsReadinessFacts {
    facts.direct_process_authorized = context.direct_process_authorized();
    facts
}

#[cfg(test)]
mod tests {
    use crate::platform::PlatformBackend;
    use crate::service::ServiceExecutionContext;

    use super::super::{
        MacOsBackend, MacOsReadinessFacts, MacOsReadinessIssue, evaluate_macos_readiness,
    };

    /// Direct root authority remains separate from service enablement and endpoint facts.
    #[test]
    fn privileged_direct_context_does_not_manufacture_service_endpoint_evidence() {
        let context = ServiceExecutionContext::privileged_direct_cli(true);
        let facts = super::apply(
            MacOsReadinessFacts::new(true, true, false, false, false),
            &context,
        );
        let report = evaluate_macos_readiness(facts);
        let backend = MacOsBackend::from_readiness(facts, true);

        assert!(!facts.service_metadata_present);
        assert!(!facts.service_enabled);
        assert!(!facts.current_process_authorized);
        assert!(!context.endpoint_authenticated());
        assert_eq!(report.issue(), MacOsReadinessIssue::ReadyHardwareUnverified);
        assert!(PlatformBackend::capabilities(&backend).transport_available());
    }
}

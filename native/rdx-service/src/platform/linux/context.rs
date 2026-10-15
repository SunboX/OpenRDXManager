// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit Linux direct-process authority mapping.

use crate::service::ServiceExecutionContext;

use super::LinuxReadinessFacts;

/// Applies one explicit execution context without changing endpoint facts.
pub(super) const fn apply(
    mut facts: LinuxReadinessFacts,
    context: &ServiceExecutionContext,
) -> LinuxReadinessFacts {
    facts.direct_process_authorized = context.direct_process_authorized();
    facts
}

#[cfg(test)]
mod tests {
    use crate::platform::PlatformBackend;
    use crate::service::ServiceExecutionContext;

    use super::super::{
        DeviceAccessEvidence, LinuxBackend, LinuxReadinessFacts, LinuxReadinessIssue,
    };

    /// Direct root authority remains separate from every service and IPC fact.
    #[test]
    fn privileged_direct_context_does_not_manufacture_service_endpoint_evidence() {
        let context = ServiceExecutionContext::privileged_direct_cli(true);
        let facts = super::apply(
            LinuxReadinessFacts::new(
                true,
                true,
                false,
                false,
                DeviceAccessEvidence::NoCandidate,
                false,
                false,
                false,
                false,
            ),
            &context,
        );
        let backend = LinuxBackend::from_readiness(facts, true);

        assert!(!facts.service_installed);
        assert!(!facts.service_running);
        assert!(!facts.current_process_authorized);
        assert!(!context.endpoint_authenticated());
        assert_eq!(
            backend.readiness_issue(),
            LinuxReadinessIssue::ReadyHardwareUnverified
        );
        assert!(PlatformBackend::capabilities(&backend).transport_available());
    }
}

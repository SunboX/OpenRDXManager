// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit Windows service-entrypoint and direct-process authority mapping.

use crate::service::ServiceExecutionContext;

use super::WindowsReadiness;

/// Applies separately proven process authority to one native readiness snapshot.
pub(super) const fn apply(
    mut readiness: WindowsReadiness,
    context: ServiceExecutionContext,
) -> WindowsReadiness {
    readiness.current_process_authorized |= context.hardware_authorized();
    readiness
}

#[cfg(test)]
mod tests {
    use crate::platform::PlatformBackend;
    use crate::service::ServiceExecutionContext;

    use super::super::{WindowsBackend, WindowsReadiness};

    /// A privileged direct CLI supplies process authority without claiming an endpoint.
    #[test]
    fn privileged_direct_context_reaches_transport_without_endpoint_authentication() {
        let context = ServiceExecutionContext::privileged_direct_cli(true);
        let backend = WindowsBackend::from_test_readiness(
            super::apply(WindowsReadiness::new(true, true, true, false), context),
            true,
        );

        assert!(!context.endpoint_authenticated());
        assert!(PlatformBackend::capabilities(&backend).transport_available());
        assert!(PlatformBackend::capabilities(&backend).privileged());
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trusted service-startup endpoint and process authority.

/// Trusted process and endpoint authority threaded into native readiness.
///
/// This value is constructed by the service entrypoint after it has selected
/// development stdio or accepted the fixed authenticated platform endpoint. It
/// never reads environment variables and carries no user-controlled path.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(not(target_os = "macos"), derive(Copy))]
pub struct ServiceExecutionContext {
    endpoint_authenticated: bool,
    development_ipc: bool,
    direct_cli: bool,
    process_authorized: bool,
    backup_owner: Option<u32>,
    #[cfg(target_os = "macos")]
    macos_worker_factory: Option<rdx_macos_native::MacWorkerFactory>,
    #[cfg(target_os = "macos")]
    macos_direct_worker_factory: Option<rdx_macos_native::MacDirectWorkerFactory>,
}

impl ServiceExecutionContext {
    /// Duplicates the shared context without cloning Copy-only non-macOS values.
    #[must_use]
    pub fn duplicate_for_runtime(&self) -> Self {
        #[cfg(target_os = "macos")]
        {
            self.clone()
        }
        #[cfg(not(target_os = "macos"))]
        {
            *self
        }
    }

    /// Attaches opaque native connection authority only to an authorized endpoint context.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn with_macos_worker_factory(
        mut self,
        factory: rdx_macos_native::MacWorkerFactory,
    ) -> Self {
        if self.endpoint_authenticated && self.process_authorized {
            self.macos_worker_factory = Some(factory);
        }
        self
    }

    /// Borrows existing native authority; flags and backup ownership never manufacture it.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn macos_worker_factory(&self) -> Option<&rdx_macos_native::MacWorkerFactory> {
        self.macos_worker_factory.as_ref()
    }

    /// Retains existing native direct authority only for explicitly selected process-authorized modes.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn with_macos_direct_worker_factory(
        mut self,
        factory: rdx_macos_native::MacDirectWorkerFactory,
    ) -> Self {
        if !self.endpoint_authenticated && self.direct_process_authorized() {
            self.macos_direct_worker_factory = Some(factory);
        }
        self
    }

    /// Borrows direct authority; flags, endpoint payloads and backup ownership cannot manufacture it.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn macos_direct_worker_factory(&self) -> Option<&rdx_macos_native::MacDirectWorkerFactory> {
        self.macos_direct_worker_factory.as_ref()
    }

    /// Creates the unprivileged development-stdio execution context.
    #[must_use]
    pub const fn development_stdio() -> Self {
        Self {
            endpoint_authenticated: false,
            development_ipc: false,
            direct_cli: false,
            process_authorized: false,
            backup_owner: None,
            #[cfg(target_os = "macos")]
            macos_worker_factory: None,
            #[cfg(target_os = "macos")]
            macos_direct_worker_factory: None,
        }
    }

    /// Creates authority for the debug-only inherited stdio service.
    ///
    /// `process_authorized` must come from the native root/elevation probe. The
    /// release service does not accept stdio mode, and the inherited pipes are
    /// owned exclusively by the unprivileged Electron parent and this child.
    #[must_use]
    pub const fn privileged_development_stdio(process_authorized: bool) -> Self {
        Self {
            endpoint_authenticated: false,
            development_ipc: true,
            direct_cli: false,
            process_authorized,
            backup_owner: None,
            #[cfg(target_os = "macos")]
            macos_worker_factory: None,
            #[cfg(target_os = "macos")]
            macos_direct_worker_factory: None,
        }
    }

    /// Creates context for an already accepted fixed privileged endpoint.
    ///
    /// `process_authorized` must come from the native service-account check,
    /// not command-line or environment input.
    #[must_use]
    pub const fn authenticated_platform_endpoint(process_authorized: bool) -> Self {
        Self {
            endpoint_authenticated: true,
            development_ipc: false,
            direct_cli: false,
            process_authorized,
            backup_owner: None,
            #[cfg(target_os = "macos")]
            macos_worker_factory: None,
            #[cfg(target_os = "macos")]
            macos_direct_worker_factory: None,
        }
    }

    /// Creates authority for an administrator-invoked CLI using the shared
    /// process-global hardware ownership boundary.
    ///
    /// This context deliberately does not claim an authenticated IPC endpoint.
    /// `process_authorized` must come from the native root/elevation probe,
    /// never from arguments or environment input. Exact candidate access is
    /// still revalidated independently by the platform backend.
    #[must_use]
    pub const fn privileged_direct_cli(process_authorized: bool) -> Self {
        Self {
            endpoint_authenticated: false,
            development_ipc: false,
            direct_cli: true,
            process_authorized,
            backup_owner: None,
            #[cfg(target_os = "macos")]
            macos_worker_factory: None,
            #[cfg(target_os = "macos")]
            macos_direct_worker_factory: None,
        }
    }

    /// Associates private backup storage with the authenticated desktop user.
    #[must_use]
    pub const fn with_backup_owner(mut self, user_id: u32) -> Self {
        if self.process_authorized && user_id != 0 {
            self.backup_owner = Some(user_id);
        }
        self
    }

    /// Returns the accepted desktop owner; an absent owner prevents manufacturing storage.
    #[must_use]
    pub const fn backup_owner(&self) -> Option<u32> {
        self.backup_owner
    }

    /// Returns whether startup accepted the fixed privileged endpoint.
    #[must_use]
    pub const fn endpoint_authenticated(&self) -> bool {
        self.endpoint_authenticated
    }

    /// Returns whether native process-account evidence authorized this service.
    #[must_use]
    pub const fn process_authorized(&self) -> bool {
        self.process_authorized
    }

    /// Returns whether this is the explicit privileged direct-CLI route.
    #[must_use]
    pub const fn direct_cli_authorized(&self) -> bool {
        self.direct_cli && self.process_authorized
    }

    /// Returns whether direct process evidence authorizes CLI or private development IPC.
    #[must_use]
    pub const fn direct_process_authorized(&self) -> bool {
        (self.direct_cli || self.development_ipc) && self.process_authorized
    }

    /// Returns whether a service endpoint or direct CLI has complete native
    /// process authority for hardware access.
    #[must_use]
    pub const fn hardware_authorized(&self) -> bool {
        self.process_authorized
            && (self.endpoint_authenticated || self.direct_cli || self.development_ipc)
    }
}

#[cfg(test)]
mod tests {
    use super::ServiceExecutionContext;

    /// Direct CLI authority cannot masquerade as an authenticated IPC peer.
    #[test]
    fn privileged_direct_cli_separates_process_and_endpoint_authority() {
        let context = ServiceExecutionContext::privileged_direct_cli(true);

        assert!(!context.endpoint_authenticated());
        assert!(context.process_authorized());
        assert!(context.direct_cli_authorized());
        assert!(context.hardware_authorized());
    }

    /// An unprivileged direct CLI never gains hardware authority from its mode.
    #[test]
    fn unprivileged_direct_cli_fails_closed() {
        let context = ServiceExecutionContext::privileged_direct_cli(false);

        assert!(!context.endpoint_authenticated());
        assert!(!context.process_authorized());
        assert!(!context.direct_cli_authorized());
        assert!(!context.hardware_authorized());
    }

    /// Development IPC gains hardware authority only from native process evidence.
    #[test]
    fn privileged_development_stdio_requires_process_authority() {
        let privileged = ServiceExecutionContext::privileged_development_stdio(true);
        let unprivileged = ServiceExecutionContext::privileged_development_stdio(false);

        assert!(!privileged.endpoint_authenticated());
        assert!(!privileged.direct_cli_authorized());
        assert!(privileged.direct_process_authorized());
        assert!(privileged.hardware_authorized());
        assert!(!unprivileged.direct_process_authorized());
        assert!(!unprivileged.hardware_authorized());
    }

    /// Flags, direct CLI and backup storage ownership cannot mint native GUI-session authority.
    #[cfg(target_os = "macos")]
    #[test]
    fn context_flags_and_backup_owner_do_not_create_worker_factory() {
        for context in [
            ServiceExecutionContext::authenticated_platform_endpoint(true).with_backup_owner(502),
            ServiceExecutionContext::privileged_direct_cli(true).with_backup_owner(502),
            ServiceExecutionContext::privileged_development_stdio(true),
        ] {
            assert!(context.macos_worker_factory().is_none());
            assert!(context.macos_direct_worker_factory().is_none());
            assert_eq!(context, context.duplicate_for_runtime());
        }
    }
}

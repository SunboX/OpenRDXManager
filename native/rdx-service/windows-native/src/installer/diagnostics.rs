// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed, public installer diagnostics; no paths, principals or device data.
use crate::NativeError;

/// Fixed provisioning checkpoints; neither field can contain external material.
#[derive(Clone, Copy)]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) enum InstallStage {
    /// Sanitized fresh-root checkpoint.
    FreshRoot,
    /// Sanitized incoming-source checkpoint.
    IncomingSource,
    /// Sanitized empty-root checkpoint.
    EmptyRoot,
    /// Sanitized existing-data checkpoint.
    ExistingData,
    /// Sanitized create-data checkpoint.
    CreateData,
    /// Sanitized revoke-enrollment checkpoint.
    RevokeEnrollment,
    /// Sanitized persist-intent checkpoint.
    PersistIntent,
    /// Sanitized create-runtime checkpoint.
    CreateRuntime,
    /// Sanitized service-configuration checkpoint.
    ServiceConfiguration,
    /// Sanitized service-owner checkpoint.
    ServiceOwner,
    /// Sanitized service-quiescence checkpoint.
    ServiceQuiescence,
    /// Sanitized service-sid checkpoint.
    ServiceSid,
    /// Sanitized installed-runtime checkpoint.
    InstalledRuntime,
    /// Sanitized installed runtime ancestors checkpoint.
    RuntimeAncestors,
    /// Sanitized installed runtime open checkpoint.
    RuntimeOpen,
    /// Sanitized installed runtime protection checkpoint.
    RuntimeProtection,
    /// Sanitized installed runtime pinning checkpoint.
    RuntimePinning,
    /// Sanitized installed runtime manifest checkpoint.
    RuntimeManifest,
    /// Sanitized installed runtime inventory checkpoint.
    RuntimeInventory,
    /// Sanitized installed runtime artifacts checkpoint.
    RuntimeArtifacts,
    /// Sanitized installed runtime history checkpoint.
    RuntimeHistory,
    /// Sanitized manager-access checkpoint.
    ManagerAccess,
    /// Sanitized manager runtime checkpoint.
    ManagerRuntime,
    /// Sanitized manager process checkpoint.
    ManagerProcess,
    /// Sanitized manager user checkpoint.
    ManagerUser,
    /// Sanitized manager configuration checkpoint.
    ManagerConfiguration,
    /// Sanitized manager dacl checkpoint.
    ManagerDacl,
    /// Sanitized manager registry checkpoint.
    ManagerRegistry,
    /// Sanitized manager revalidation checkpoint.
    ManagerRevalidation,
    /// Sanitized manager user elevation checkpoint.
    ManagerUserElevation,
    /// Sanitized manager elevation output-size checkpoint.
    ManagerUserElevationSize,
    /// Sanitized manager user session checkpoint.
    ManagerUserSession,
    /// Sanitized manager user principal checkpoint.
    ManagerUserPrincipal,
    /// Sanitized manager user kernel-query checkpoint.
    ManagerUserQuery,
    /// Sanitized device-access checkpoint.
    DeviceAccess,
    /// Sanitized commit-enrollment checkpoint.
    CommitEnrollment,
    /// Sanitized verify-enrollment checkpoint.
    VerifyEnrollment,
}
impl InstallStage {
    /// Returns the fixed diagnostic token consumed by NSIS.
    fn name(self) -> &'static str {
        match self {
            Self::FreshRoot => "fresh-root",
            Self::IncomingSource => "incoming-source",
            Self::EmptyRoot => "empty-root",
            Self::ExistingData => "existing-data",
            Self::CreateData => "create-data",
            Self::RevokeEnrollment => "revoke-enrollment",
            Self::PersistIntent => "persist-intent",
            Self::CreateRuntime => "create-runtime",
            Self::ServiceConfiguration => "service-configuration",
            Self::ServiceOwner => "service-owner",
            Self::ServiceQuiescence => "service-quiescence",
            Self::ServiceSid => "service-sid",
            Self::InstalledRuntime => "installed-runtime",
            Self::RuntimeAncestors => "runtime-ancestors",
            Self::RuntimeOpen => "runtime-open",
            Self::RuntimeProtection => "runtime-protection",
            Self::RuntimePinning => "runtime-pinning",
            Self::RuntimeManifest => "runtime-manifest",
            Self::RuntimeInventory => "runtime-inventory",
            Self::RuntimeArtifacts => "runtime-artifacts",
            Self::RuntimeHistory => "runtime-history",
            Self::ManagerAccess => "manager-access",
            Self::ManagerRuntime => "manager-runtime",
            Self::ManagerProcess => "manager-process",
            Self::ManagerUser => "manager-user",
            Self::ManagerConfiguration => "manager-configuration",
            Self::ManagerDacl => "manager-dacl",
            Self::ManagerRegistry => "manager-registry",
            Self::ManagerRevalidation => "manager-revalidation",
            Self::ManagerUserElevation => "manager-user-elevation",
            Self::ManagerUserElevationSize => "manager-user-elevation-size",
            Self::ManagerUserSession => "manager-user-session",
            Self::ManagerUserPrincipal => "manager-user-principal",
            Self::ManagerUserQuery => "manager-user-query",
            Self::DeviceAccess => "device-access",
            Self::CommitEnrollment => "commit-enrollment",
            Self::VerifyEnrollment => "verify-enrollment",
        }
    }
}
/// Formats only a closed checkpoint and a fieldless sanitized native error.
fn failure(stage: InstallStage, error: NativeError) -> String {
    format!(
        "OpenRDX native failure: phase={} reason={error:?}",
        stage.name()
    )
}
/// Logs a bounded public denial and returns the original policy result unchanged.
pub(crate) fn diagnostic<T>(
    stage: InstallStage,
    result: Result<T, NativeError>,
) -> Result<T, NativeError> {
    if let Err(error) = &result {
        eprintln!("{}", failure(stage, *error));
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Proves the new size denial cannot be mistaken for a nonzero elevation value.
    #[test]
    fn manager_elevation_denials_are_distinct_and_preserve_access_denied() {
        for (stage, expected) in [
            (
                InstallStage::ManagerUserElevationSize,
                "manager-user-elevation-size",
            ),
            (InstallStage::ManagerUserElevation, "manager-user-elevation"),
        ] {
            assert_eq!(
                failure(stage, NativeError::AccessDenied),
                format!("OpenRDX native failure: phase={expected} reason=AccessDenied")
            );
            assert_eq!(
                diagnostic::<()>(stage, Err(NativeError::AccessDenied)),
                Err(NativeError::AccessDenied)
            );
        }
    }
    /// Confirms diagnostics cannot incorporate an external path, SID or payload.
    #[test]
    fn diagnostics_have_closed_public_fields_and_preserve_results() {
        assert_eq!(
            failure(InstallStage::IncomingSource, NativeError::AccessDenied),
            "OpenRDX native failure: phase=incoming-source reason=AccessDenied"
        );
        for stage in [
            InstallStage::RuntimeAncestors,
            InstallStage::RuntimeOpen,
            InstallStage::RuntimeProtection,
            InstallStage::RuntimePinning,
            InstallStage::RuntimeManifest,
            InstallStage::RuntimeInventory,
            InstallStage::RuntimeArtifacts,
            InstallStage::RuntimeHistory,
        ] {
            let message = failure(stage, NativeError::AccessDenied);
            assert!(message.starts_with("OpenRDX native failure: phase=runtime-"));
            assert!(message.ends_with(" reason=AccessDenied"));
            assert!(message.len() < 100);
            assert_eq!(
                diagnostic::<()>(stage, Err(NativeError::AccessDenied)),
                Err(NativeError::AccessDenied)
            );
        }
        for stage in [
            InstallStage::ManagerRuntime,
            InstallStage::ManagerProcess,
            InstallStage::ManagerUser,
            InstallStage::ManagerConfiguration,
            InstallStage::ManagerDacl,
            InstallStage::ManagerRegistry,
            InstallStage::ManagerRevalidation,
            InstallStage::ManagerUserElevation,
            InstallStage::ManagerUserElevationSize,
            InstallStage::ManagerUserSession,
            InstallStage::ManagerUserPrincipal,
            InstallStage::ManagerUserQuery,
        ] {
            let message = failure(stage, NativeError::AccessDenied);
            assert!(message.starts_with("OpenRDX native failure: phase=manager-"));
            assert!(message.ends_with(" reason=AccessDenied"));
            assert!(message.len() < 100);
            assert_eq!(
                diagnostic::<()>(stage, Err(NativeError::AccessDenied)),
                Err(NativeError::AccessDenied)
            );
        }
        assert_eq!(diagnostic(InstallStage::InstalledRuntime, Ok(7)), Ok(7));
        assert_eq!(
            diagnostic::<()>(InstallStage::ManagerAccess, Err(NativeError::Busy)),
            Err(NativeError::Busy)
        );
    }
}

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
    /// Sanitized manager-access checkpoint.
    ManagerAccess,
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
            Self::ManagerAccess => "manager-access",
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
    /// Confirms diagnostics cannot incorporate an external path, SID or payload.
    #[test]
    fn diagnostics_have_closed_public_fields_and_preserve_results() {
        assert_eq!(
            failure(InstallStage::IncomingSource, NativeError::AccessDenied),
            "OpenRDX native failure: phase=incoming-source reason=AccessDenied"
        );
        assert_eq!(diagnostic(InstallStage::InstalledRuntime, Ok(7)), Ok(7));
        assert_eq!(
            diagnostic::<()>(InstallStage::ManagerAccess, Err(NativeError::Busy)),
            Err(NativeError::Busy)
        );
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed high-level RDX cartridge security operation admission.

use std::error::Error;
use std::fmt::{Display, Formatter};

use zeroize::{Zeroize, Zeroizing};

/// Every documented mutating security operation exposed by the application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityMutator {
    /// Authenticate one credential for the current media insertion.
    EnableAccess,
    /// Close the current authenticated session.
    DisableAccess,
    /// Add one named credential and permission descriptor.
    CreateCredential,
    /// Replace one credential through the documented temporary-slot transaction.
    ChangeCredential,
    /// Remove one credential or the protection-owning master credential.
    DeleteCredential,
    /// Erase protection configuration under the stored passwordless-reset policy.
    ResetProtection,
    /// Configure Basic password protection.
    ConfigureBasic,
    /// Configure compatible AES-256-XTS protection.
    ConfigureAes,
    /// Remove Basic password protection.
    RemoveBasic,
    /// Remove AES protection and reinitialize media.
    RemoveAes,
    /// Add a SATA III drive-generated automatic credential to the cartridge.
    AddAutomaticAssociation,
    /// Delete drive- or cartridge-side automatic authentication state.
    DeleteAutomaticAssociation,
    /// Delete the drive-held credential shared by every paired cartridge.
    DeleteDriveAutomaticCredential,
}

include!("security_evidence_generated.rs");

/// Bundled security evidence decisions generated from immutable supplied artifacts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecurityEvidenceRegistry;

impl SecurityEvidenceRegistry {
    /// Returns the bundled fail-closed evidence registry.
    #[must_use]
    pub const fn bundled() -> Self {
        Self
    }

    /// Returns the exact unresolved boundary for one mutator.
    #[must_use]
    pub fn incomplete_reason(self, operation: SecurityMutator) -> &'static str {
        for (candidate, reason) in GENERATED_SECURITY_EVIDENCE_ENTRIES {
            if *candidate == operation {
                return reason;
            }
        }
        unreachable!("generated registry covers every SecurityMutator")
    }

    /// Returns every generated operation/reason pair for native/renderer drift checks.
    #[must_use]
    pub const fn entries(self) -> &'static [(SecurityMutator, &'static str)] {
        GENERATED_SECURITY_EVIDENCE_ENTRIES
    }
}

/// Structured fail-closed result for a blocked high-level security operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityOperationError {
    /// No complete selector/descriptor/transaction fixture authorizes this mutation.
    EvidenceIncomplete {
        /// Requested high-level operation.
        operation: SecurityMutator,
        /// Stable redacted evidence boundary shared with the renderer.
        reason: &'static str,
    },
}

impl Display for SecurityOperationError {
    /// Formats only the operation and stable evidence reason.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EvidenceIncomplete { operation, reason } => {
                write!(formatter, "{operation:?} is evidence-incomplete: {reason}")
            }
        }
    }
}

impl Error for SecurityOperationError {}

/// Applies the generated evidence gate before any native security transport exists.
///
/// An optional transient credential is zeroized for every terminal result,
/// including this evidence rejection. Because no supplied fixture proves a full
/// mutating transaction, this function cannot construct or dispatch a command.
///
/// # Errors
///
/// Always returns [`SecurityOperationError::EvidenceIncomplete`] for the bundled
/// evidence registry.
pub fn execute_security_mutator(
    evidence: &SecurityEvidenceRegistry,
    operation: SecurityMutator,
    credential: Option<&mut Zeroizing<Vec<u8>>>,
) -> Result<(), SecurityOperationError> {
    let reason = evidence.incomplete_reason(operation);
    if let Some(secret) = credential {
        secret.zeroize();
    }
    Err(SecurityOperationError::EvidenceIncomplete { operation, reason })
}

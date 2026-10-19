// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Separates volume observation from authority to mutate an enrolled volume.
use crate::NativeError;

/// Exact access retained by a service-owned volume lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VolumeAccess {
    /// Query topology and filesystem metadata without raw read/write rights.
    Metadata,
    /// Retain the original read/write access required for host mutations.
    Mutation,
}

impl VolumeAccess {
    /// Returns the fixed CreateFile access mask for this lease purpose.
    pub(crate) const fn desired_access(self) -> u32 {
        match self {
            Self::Metadata => 0,
            Self::Mutation => 0xc000_0000,
        }
    }

    /// Refuses mutation before any host API when this is an observation lease.
    pub(crate) fn require_mutation(self) -> Result<(), NativeError> {
        if self == Self::Mutation {
            Ok(())
        } else {
            Err(NativeError::AccessDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// New cartridges remain observable without inheriting raw volume write rights.
    #[test]
    fn metadata_never_requests_or_authorizes_raw_volume_mutation() {
        assert_eq!(VolumeAccess::Metadata.desired_access(), 0);
        assert_eq!(
            VolumeAccess::Metadata.require_mutation(),
            Err(NativeError::AccessDenied)
        );
        assert_eq!(VolumeAccess::Mutation.desired_access(), 0xc000_0000);
        assert_eq!(VolumeAccess::Mutation.require_mutation(), Ok(()));
    }
}

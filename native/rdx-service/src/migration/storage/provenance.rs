// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Flat recovery-copy provenance and independent writable attempt creation.

use super::*;

impl RecoveryStore {
    /// Rechecks a schema-one origin and identical artifacts without recursive copies.
    pub(super) fn verify_origin(
        &self,
        receipt: &Receipt,
        artifacts: &Artifacts,
    ) -> Result<(), MigrationError> {
        let name = receipt
            .source_bundle
            .as_deref()
            .ok_or(MigrationError::StorageUnavailable)?;
        let hash = receipt
            .source_receipt_sha256
            .as_deref()
            .ok_or(MigrationError::StorageUnavailable)?;
        let (source, original, _) = loader::load_original(&self.root, name)?;
        if digest(&source.receipt) != hash || artifacts.inventory() != original.inventory() {
            return Err(MigrationError::StorageUnavailable);
        }
        Ok(())
    }

    /// Copies existing artifacts verbatim, retaining the original receipt and journal.
    pub(in crate::migration) fn create_recovery(
        &self,
    ) -> Result<(Self, Artifacts), MigrationError> {
        if Receipt::parse(&self.receipt, &self.name)?.schema_version != 1 {
            return Err(MigrationError::StorageUnavailable);
        }
        let original = self.reopen()?;
        let source_hash = digest(&self.receipt);
        let (mut store, copied) =
            Self::create_inner(&self.root, original, Some((&self.name, &source_hash)))?;
        if copied.inventory() != self.reopen()?.inventory() {
            return Err(MigrationError::StorageUnavailable);
        }
        store.append(MigrationEvent::RecoveryResumed)?;
        let independently_reopened = store.reopen()?;
        Ok((store, independently_reopened))
    }
}

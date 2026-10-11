// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UI-safe original inventory with validated flat recovery-attempt status aggregation.

use super::*;
use crate::migration::{
    MigrationRecoveryInventoryEntry, MigrationRecoverySummary, PreparedMigration,
};
use std::collections::BTreeMap;

/// Orders generated creation identifiers numerically without exposing paths or hashes.
fn creation_order(name: &str) -> Result<(u128, u64), MigrationError> {
    let (timestamp, sequence) = name
        .strip_prefix("migration-")
        .and_then(|value| value.split_once('-'))
        .ok_or(MigrationError::StorageUnavailable)?;
    Ok((
        u128::from_str_radix(timestamp, 16).map_err(storage_error)?,
        u64::from_str_radix(sequence, 16).map_err(storage_error)?,
    ))
}

/// Tracks only validated saved state; live hardware authority is deliberately absent.
struct Attempt {
    origin: Option<String>,
    order: (u128, u64),
    last: MigrationEvent,
    serial: String,
}

/// Validates every artifact before extracting the single allowed private-to-UI field.
fn inspect(root: &Path, name: &str, release: &str) -> Result<Attempt, MigrationError> {
    let (store, artifacts, events) = loader::load(root, name)?;
    let receipt = Receipt::parse(&store.receipt, name)?;
    let prepared = PreparedMigration::from_store(store, artifacts, release)?;
    Ok(Attempt {
        origin: receipt.source_bundle,
        order: creation_order(name)?,
        last: *events.last().ok_or(MigrationError::StorageUnavailable)?,
        serial: prepared.capture().usb.serial.clone(),
    })
}

/// Lists original summaries and fixed per-bundle failures within existing inventory bounds.
pub(in crate::migration) fn inventory(
    root: &Path,
    release: &str,
) -> Result<Vec<MigrationRecoveryInventoryEntry>, MigrationError> {
    let mut originals = BTreeMap::new();
    let mut copies = Vec::new();
    let mut failures = BTreeMap::new();
    for name in loader::bundle_ids(root)? {
        match inspect(root, &name, release) {
            Ok(attempt) if attempt.origin.is_none() => {
                originals.insert(name, attempt);
            }
            Ok(attempt) => copies.push(attempt),
            Err(_) => {
                failures.insert(
                    name.clone(),
                    MigrationRecoveryInventoryEntry::Unavailable {
                        bundle_id: name,
                        reason: MigrationError::StorageUnavailable.code(),
                    },
                );
            }
        }
    }
    for copy in copies {
        if let Some(original) = copy
            .origin
            .as_ref()
            .and_then(|name| originals.get_mut(name))
            && copy.order > original.order
        {
            original.order = copy.order;
            original.last = copy.last;
        }
    }
    for (name, original) in originals {
        let completed = original.last == MigrationEvent::FinalUpdateVerified;
        failures.insert(
            name.clone(),
            MigrationRecoveryInventoryEntry::Available(MigrationRecoverySummary {
                bundle_id: name,
                display_label: format!("RDX {}", original.serial),
                serial: original.serial,
                source_version: "2.83",
                target_version: "1.07",
                last_state: original.last,
                completed,
                recovery_needed: !completed,
            }),
        );
    }
    Ok(failures.into_values().collect())
}

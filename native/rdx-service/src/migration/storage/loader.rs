// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only cold recovery validation; no provisioning, repair, or device access.

use super::*;
use crate::migration::{MigrationRecoveryStatus, PreparedMigration};
use std::collections::BTreeSet;

const MAX_BUNDLES: usize = 64;
const MAX_ROOT_ENTRIES: usize = MAX_BUNDLES * 3;

/// Parses every complete canonical line and its hash of the full previous prefix.
fn journal_events(journal: &[u8], receipt: &[u8]) -> Result<Vec<MigrationEvent>, MigrationError> {
    if journal.is_empty() || journal.len() > MAX_JOURNAL || journal.last() != Some(&b'\n') {
        return Err(MigrationError::StorageUnavailable);
    }
    let mut events = Vec::new();
    let mut offset = 0;
    for line in journal.split_inclusive(|byte| *byte == b'\n') {
        if events.len() >= MAX_EVENTS {
            return Err(MigrationError::StorageUnavailable);
        }
        let entry: JournalEntry = serde_json::from_slice(line).map_err(storage_error)?;
        if (events.is_empty() && entry.event != MigrationEvent::Prepared)
            || (!events.is_empty() && entry.event == MigrationEvent::Prepared)
            || line != journal_line(events.len(), entry.event, receipt, &journal[..offset])?
        {
            return Err(MigrationError::StorageUnavailable);
        }
        events.push(entry.event);
        offset += line.len();
    }
    Ok(events)
}

/// Cold-loads a canonical chain, then reopens every receipt-bound immutable artifact.
pub(in crate::migration) fn load(
    root: &Path,
    name: &str,
) -> Result<(RecoveryStore, Artifacts, Vec<MigrationEvent>), MigrationError> {
    load_checked(root, name, false)
}

/// Rejects nested provenance before following any origin, making validation bounded.
pub(super) fn load_original(
    root: &Path,
    name: &str,
) -> Result<(RecoveryStore, Artifacts, Vec<MigrationEvent>), MigrationError> {
    load_checked(root, name, true)
}

/// Validates cold metadata before constructing the read-only store owner.
fn load_checked(
    root: &Path,
    name: &str,
    original_only: bool,
) -> Result<(RecoveryStore, Artifacts, Vec<MigrationEvent>), MigrationError> {
    if !valid_bundle_id(name) {
        return Err(MigrationError::StorageUnavailable);
    }
    let parent = open_directory(root, true)?;
    let receipt = read_file(&parent, &format!("{name}.receipt.json"), MAX_METADATA)?;
    let parsed = Receipt::parse(&receipt, name)?;
    if original_only && parsed.schema_version != 1 {
        return Err(MigrationError::StorageUnavailable);
    }
    let journal = read_file(&parent, &format!("{name}.journal.jsonl"), MAX_JOURNAL)?;
    let events = journal_events(&journal, &receipt)?;
    let resumed: Vec<_> = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| (*event == MigrationEvent::RecoveryResumed).then_some(index))
        .collect();
    if (parsed.schema_version == 1 && !resumed.is_empty())
        || (parsed.schema_version == 2 && resumed != [1])
    {
        return Err(MigrationError::StorageUnavailable);
    }
    let store = RecoveryStore {
        root: root.to_path_buf(),
        name: name.to_owned(),
        directory: root.join(name),
        receipt,
        journal,
        events: events.len(),
        // A resumed hardware attempt requires a separately designed journal.
        failed: true,
    };
    let artifacts = store.reopen()?;
    Ok((store, artifacts, events))
}

/// Finds a bounded union of bundle directories, receipts and journals, including partial sets.
pub(super) fn bundle_ids(root: &Path) -> Result<BTreeSet<String>, MigrationError> {
    let parent = open_directory(root, true)?;
    let mut names = BTreeSet::new();
    let mut count = 0;
    for entry in fs::Dir::read_from(&parent).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        count += 1;
        if count > MAX_ROOT_ENTRIES {
            return Err(MigrationError::StorageUnavailable);
        }
        let name = std::str::from_utf8(bytes).map_err(storage_error)?;
        let name = name
            .strip_suffix(".receipt.json")
            .or_else(|| name.strip_suffix(".journal.jsonl"))
            .unwrap_or(name);
        if !valid_bundle_id(name) {
            return Err(MigrationError::StorageUnavailable);
        }
        names.insert(name.to_owned());
        if names.len() > MAX_BUNDLES {
            return Err(MigrationError::StorageUnavailable);
        }
    }
    Ok(names)
}

/// Reports only fully validated events; any incomplete/tampered bundle remains untouched.
pub(in crate::migration) fn status(
    root: &Path,
    release_digest: &str,
) -> Result<Vec<MigrationRecoveryStatus>, MigrationError> {
    bundle_ids(root)?
        .into_iter()
        .map(|name| {
            let validated = load(root, &name).and_then(|(store, artifacts, events)| {
                PreparedMigration::from_store(store, artifacts, release_digest)?;
                Ok(events)
            });
            Ok(MigrationRecoveryStatus {
                bundle_id: name,
                integrity: validated.is_ok(),
                events: validated.unwrap_or_default(),
            })
        })
        .collect()
}

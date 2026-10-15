// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bootstrap-only recognition; this policy never authenticates a runtime.
use super::RuntimeAclEvidence;
use crate::NativeError;

/// Distinguishes the privileged container from its service-owned private leaf.
#[derive(Clone, Copy)]
pub(super) enum StorageRole {
    Parent,
    Backup,
}

/// Recognizes only a complete private storage descriptor for installer migration.
pub(super) fn validate_private_storage_acl(
    evidence: &RuntimeAclEvidence,
    role: StorageRole,
) -> Result<(), NativeError> {
    let owner_allowed = matches!(evidence.owner.as_str(), "S-1-5-18" | "S-1-5-32-544")
        || matches!(role, StorageRole::Backup) && evidence.owner == "S-1-5-19";
    let trustees = ["S-1-5-18", "S-1-5-32-544", "S-1-5-19"];
    if !owner_allowed
        || !evidence.protected
        || evidence.reparse
        || !evidence.directory
        || evidence.entries.len() != trustees.len()
        || trustees.iter().any(|sid| {
            evidence
                .entries
                .iter()
                .filter(|ace| ace.sid == *sid)
                .count()
                != 1
        })
        || evidence
            .entries
            .iter()
            .any(|ace| !ace.allowed || ace.flags != 0 || ace.mask != 0x001f01ff)
    {
        return Err(NativeError::AccessDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_trust::{RuntimeAce, validate_runtime_acl};

    /// Models the observed protected container, including its noncanonical ACE order.
    fn legacy() -> RuntimeAclEvidence {
        RuntimeAclEvidence {
            owner: "S-1-5-32-544".into(),
            protected: true,
            reparse: false,
            directory: true,
            links: 1,
            entries: ["S-1-5-18", "S-1-5-19", "S-1-5-32-544"]
                .into_iter()
                .map(|sid| RuntimeAce {
                    sid: sid.into(),
                    mask: 0x001f01ff,
                    flags: 0,
                    allowed: true,
                })
                .collect(),
        }
    }

    /// Exact private storage can be migrated but cannot authenticate the app.
    #[test]
    fn recognizes_private_parent_without_relaxing_runtime_policy() {
        let mut descriptor = legacy();
        for _ in 0..3 {
            assert!(validate_private_storage_acl(&descriptor, StorageRole::Parent).is_ok());
            assert!(validate_runtime_acl(&descriptor).is_err());
            descriptor.entries.rotate_left(1);
        }
    }

    /// Service ownership is valid for the private backup leaf, never its trust parent.
    #[test]
    fn local_service_owner_is_confined_to_the_existing_backup_leaf() {
        let mut descriptor = legacy();
        descriptor.owner = "S-1-5-19".into();
        assert!(validate_private_storage_acl(&descriptor, StorageRole::Backup).is_ok());
        assert!(validate_private_storage_acl(&descriptor, StorageRole::Parent).is_err());
    }

    /// Every unknown owner, permission, inheritance, object type and extra ACE fails closed.
    #[test]
    fn rejects_modified_or_incomplete_private_storage_descriptors() {
        let original = legacy();
        let mut rejected = Vec::new();
        let mut value = original.clone();
        value.owner = "S-1-5-32-545".into();
        rejected.push(value);
        let mut value = original.clone();
        value.protected = false;
        rejected.push(value);
        let mut value = original.clone();
        value.reparse = true;
        rejected.push(value);
        let mut value = original.clone();
        value.directory = false;
        rejected.push(value);
        for index in 0..3 {
            let mut value = original.clone();
            value.entries[index].sid = "S-1-5-32-545".into();
            rejected.push(value);
            let mut value = original.clone();
            value.entries[index].mask = 0x001200a9;
            rejected.push(value);
            let mut value = original.clone();
            value.entries[index].flags = 3;
            rejected.push(value);
            let mut value = original.clone();
            value.entries[index].allowed = false;
            rejected.push(value);
        }
        let mut value = original.clone();
        value.entries.pop();
        rejected.push(value);
        let mut value = original.clone();
        value.entries.push(original.entries[0].clone());
        rejected.push(value);
        let mut value = original.clone();
        value.entries[1] = value.entries[0].clone();
        rejected.push(value);
        for descriptor in rejected {
            assert!(validate_private_storage_acl(&descriptor, StorageRole::Parent).is_err());
            assert!(validate_private_storage_acl(&descriptor, StorageRole::Backup).is_err());
        }
    }
}

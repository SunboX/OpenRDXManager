// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cleanup ordering after the root caller has established fixed-target ownership.

/// One compiled removal operation, never a caller-selected pathname.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovalStep {
    Revoke,
    App,
    Helper,
    Daemon,
    Pending,
    Cli,
    History,
}

/// Apply owned cleanup, propagating the first failure to the root caller.
pub fn remove_owned_payload(
    mut apply: impl FnMut(RemovalStep) -> Result<(), String>,
) -> Result<(), String> {
    for step in [
        RemovalStep::Revoke,
        RemovalStep::App,
        RemovalStep::Helper,
        RemovalStep::Daemon,
        RemovalStep::Pending,
        RemovalStep::Cli,
        RemovalStep::History,
    ] {
        apply(step)?;
    }
    Ok(())
}

/// Archive the latest strict record, or retain valid history when current is malformed.
/// The root caller must prove protection of these fixed paths and descriptors,
/// and strict policy validity before invoking this filesystem-only operation.
/// It never establishes enrollment or IPC authority and does not change owners.
pub fn revoke_owned_enrollment(
    current: &std::fs::File,
    current_path: &std::path::Path,
    history_path: &std::path::Path,
    current_valid: bool,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let held = current.metadata().map_err(|error| error.to_string())?;
    let named = std::fs::symlink_metadata(current_path).map_err(|error| error.to_string())?;
    if !held.is_file()
        || held.nlink() != 1
        || held.mode() & 0o7022 != 0
        || !named.is_file()
        || held.dev() != named.dev()
        || held.ino() != named.ino()
    {
        return Err("ownership enrollment namespace changed before revocation".into());
    }
    if current_valid {
        // Change only the retained inode, then durably replace older history.
        current
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .and_then(|()| current.sync_all())
            .map_err(|error| error.to_string())?;
        std::fs::rename(current_path, history_path).map_err(|error| error.to_string())?;
        let archived =
            std::fs::symlink_metadata(history_path).map_err(|error| error.to_string())?;
        if !archived.is_file()
            || archived.nlink() != 1
            || archived.mode() & 0o7777 != 0o600
            || held.dev() != archived.dev()
            || held.ino() != archived.ino()
            || held.uid() != archived.uid()
            || held.gid() != archived.gid()
        {
            return Err("ownership history namespace changed after revocation".into());
        }
    } else {
        // The caller already proved strict protected history; do not overwrite it.
        std::fs::remove_file(current_path).map_err(|error| error.to_string())?;
    }
    std::fs::File::open(
        current_path
            .parent()
            .ok_or("ownership record has no parent")?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    /// Produce distinct strict historical policies, including changed framework aliases.
    fn policy(target: &str) -> String {
        format!(
            r#"{{"schemaVersion":1,"platform":"macos","files":[{{"path":"Contents/Info.plist","size":1,"sha256":"{}"}}],"links":[{{"path":"Contents/Frameworks/Test.framework/Versions/Current","target":"{}"}}],"managerCdHash":"{}","helperCdHash":"{}"}}"#,
            "a".repeat(64),
            target,
            "b".repeat(40),
            "c".repeat(40)
        )
    }

    /// Every payload failure preserves latest ownership and the CLI for a real-file retry.
    #[test]
    fn failed_app_cleanup_keeps_latest_history_and_cli_until_retry() {
        for failing_step in [
            RemovalStep::App,
            RemovalStep::Helper,
            RemovalStep::Daemon,
            RemovalStep::Pending,
            RemovalStep::Cli,
        ] {
            for current_valid in [true, false] {
                let temporary = tempfile::tempdir().unwrap();
                let root = temporary.path();
                fs::create_dir(root.join("app")).unwrap();
                let latest = policy("B");
                let previous = policy("A");
                rdx_local_trust::parse_inventory(latest.as_bytes(), "macos").unwrap();
                rdx_local_trust::parse_inventory(previous.as_bytes(), "macos").unwrap();
                let current_bytes = if current_valid { &latest } else { "malformed" };
                for (name, bytes) in [
                    ("current", current_bytes),
                    ("history", &previous),
                    ("helper", "helper"),
                    ("daemon", "daemon"),
                    ("cli", "cli"),
                    ("pending", "pending"),
                ] {
                    fs::write(root.join(name), bytes).unwrap();
                    fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                fs::set_permissions(root.join("current"), fs::Permissions::from_mode(0o644))
                    .unwrap();
                let mut fail_once = true;
                let mut apply = |step| -> Result<(), String> {
                    if step == RemovalStep::Revoke {
                        if root.join("current").exists() {
                            let current = fs::File::open(root.join("current")).unwrap();
                            let valid = rdx_local_trust::parse_inventory(
                                &fs::read(root.join("current")).unwrap(),
                                "macos",
                            )
                            .is_ok();
                            if !valid {
                                rdx_local_trust::parse_inventory(
                                    &fs::read(root.join("history")).unwrap(),
                                    "macos",
                                )
                                .unwrap();
                            }
                            revoke_owned_enrollment(
                                &current,
                                &root.join("current"),
                                &root.join("history"),
                                valid,
                            )?;
                        }
                        return Ok(());
                    }
                    if step == failing_step && fail_once {
                        fail_once = false;
                        return Err("injected payload cleanup failure".into());
                    }
                    let path = root.join(match step {
                        RemovalStep::App => "app",
                        RemovalStep::Helper => "helper",
                        RemovalStep::Daemon => "daemon",
                        RemovalStep::Pending => "pending",
                        RemovalStep::Cli => "cli",
                        RemovalStep::History => "history",
                        RemovalStep::Revoke => unreachable!(),
                    });
                    let result = if step == RemovalStep::App {
                        fs::remove_dir_all(path)
                    } else {
                        fs::remove_file(path)
                    };
                    match result {
                        Ok(()) => Ok(()),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(error) => Err(error.to_string()),
                    }
                };
                assert_eq!(
                    remove_owned_payload(&mut apply),
                    Err("injected payload cleanup failure".into())
                );
                assert!(!root.join("current").exists());
                let retained = fs::read(root.join("history")).unwrap();
                assert_eq!(
                    retained,
                    if current_valid {
                        latest.as_bytes()
                    } else {
                        previous.as_bytes()
                    }
                );
                let record = rdx_local_trust::parse_inventory(&retained, "macos").unwrap();
                assert_eq!(
                    record.links[0].target,
                    if current_valid { "B" } else { "A" }
                );
                assert_eq!(
                    fs::symlink_metadata(root.join("history")).unwrap().mode() & 0o7777,
                    0o600
                );
                assert!(root.join("cli").is_file());
                remove_owned_payload(&mut apply).unwrap();
                assert_eq!(fs::read_dir(root).unwrap().count(), 0);
            }
        }
    }

    /// A replaced namespace or hardlinked policy cannot overwrite recovery history.
    #[test]
    fn revocation_rejects_replaced_or_multilink_current_inode() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::write(root.join("current"), "current").unwrap();
        fs::set_permissions(root.join("current"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(root.join("history"), "history").unwrap();
        let held = fs::File::open(root.join("current")).unwrap();
        fs::rename(root.join("current"), root.join("retained")).unwrap();
        fs::write(root.join("current"), "replacement").unwrap();
        assert!(
            revoke_owned_enrollment(&held, &root.join("current"), &root.join("history"), true)
                .is_err()
        );
        assert_eq!(fs::read(root.join("history")).unwrap(), b"history");
        fs::remove_file(root.join("current")).unwrap();
        fs::rename(root.join("retained"), root.join("current")).unwrap();
        fs::hard_link(root.join("current"), root.join("alias")).unwrap();
        assert!(
            revoke_owned_enrollment(&held, &root.join("current"), &root.join("history"), true)
                .is_err()
        );
        assert_eq!(fs::read(root.join("history")).unwrap(), b"history");
    }
}

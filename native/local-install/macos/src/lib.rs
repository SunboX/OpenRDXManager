// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed, administrator-only installation policy.

pub mod removal;

/// Parse one fixed action, rejecting arbitrary arguments.
pub fn parse_action(arguments: &[String]) -> Result<&'static str, String> {
    match arguments {
        [action] => match action.as_str() {
            "prepare" => Ok("prepare"),
            "install" => Ok("install"),
            "verify" => Ok("verify"),
            "repair" => Ok("repair"),
            "remove" => Ok("remove"),
            _ => Err("expected prepare, install, verify, repair or remove".into()),
        },
        _ => Err(
            "exactly one fixed action is required; paths, SIDs and requirements are forbidden"
                .into(),
        ),
    }
}
/// Validate the exact retained namespace inode evidence.
pub fn validate_lock_evidence(
    regular: bool,
    uid: u32,
    links: u64,
    mode: u32,
) -> Result<(), String> {
    if !regular || uid != 0 || links != 1 || mode & 0o7777 != 0o600 {
        return Err("foreign or unsafe hardware ownership file".into());
    }
    Ok(())
}
/// Require preparation and complete generation verification before publication.
pub fn commit_allowed(prepared: bool, verified: bool) -> bool {
    prepared && verified
}

/// Require exact top-level launchd path/program evidence before owned bootout.
pub fn registration_is_owned(evidence: &str) -> bool {
    let paths: Vec<&str> = evidence
        .lines()
        .filter_map(|line| line.strip_prefix("\tpath = "))
        .collect();
    let programs: Vec<&str> = evidence
        .lines()
        .filter_map(|line| line.strip_prefix("\tprogram = "))
        .collect();
    evidence.starts_with("system/com.openrdx.hardware = {\n")
        && paths == ["/Library/LaunchDaemons/com.openrdx.hardware.plist"]
        && programs == ["/Library/PrivilegedHelperTools/openrdx-hardware"]
}

/// Separate administrator replacement authority from runtime authentication.
/// A damaged content hash does not authorize IPC and need not block owned repair.
pub fn replacement_authorized(record: bool, tree: bool, setup: bool, registration: bool) -> bool {
    record && tree && setup && registration
}

/// Authorize root-protected package source ancestors, with one fixed sticky temp exception.
pub fn package_directory_allowed(
    path: &std::path::Path,
    uid: u32,
    gid: u32,
    mode: u32,
    immediate: bool,
) -> bool {
    if uid != 0 || mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR) {
        return false;
    }
    if mode & 0o7022 == 0 {
        return true;
    }
    !immediate
        && path == std::path::Path::new("/private/tmp")
        && gid == 0
        && mode & 0o7777 == 0o1777
}

/// Publish public hashes by changing ONLY an already verified retained candidate inode.
/// The root caller must first prove owner, ACL, namespace and content protection;
/// this helper never accepts a pathname or grants write permission to other users.
pub fn make_verified_enrollment_readable(
    file: &std::fs::File,
    verified: bool,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !verified {
        return Err("unverified enrollment must remain private".into());
    }
    let original = file.metadata().map_err(|error| error.to_string())?;
    if !original.is_file()
        || original.nlink() != 1
        || !matches!(original.mode() & 0o7777, 0o600 | 0o644)
    {
        return Err("enrollment candidate is not a private regular inode".into());
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|error| error.to_string())?;
    let published = file.metadata().map_err(|error| error.to_string())?;
    if published.nlink() != 1
        || published.mode() & 0o7777 != 0o644
        || published.uid() != original.uid()
        || published.gid() != original.gid()
        || published.dev() != original.dev()
        || published.ino() != original.ino()
    {
        return Err("enrollment publication metadata changed unexpectedly".into());
    }
    Ok(())
}

/// Take the kernel nonblocking exclusive lease on an already validated inode.
pub fn acquire_file_lock(file: &std::fs::File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("hardware operation or installer is active; allow it to finish, quit Manager, then retry the package installer".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A coincident label does not make a legacy/user-owned registration removable.
    #[test]
    fn registered_label_requires_exact_system_daemon_and_program() {
        let owned = "system/com.openrdx.hardware = {\n\tpath = /Library/LaunchDaemons/com.openrdx.hardware.plist\n\tprogram = /Library/PrivilegedHelperTools/openrdx-hardware\n}";
        assert!(registration_is_owned(owned));
        assert!(!registration_is_owned(&owned.replace(
            "/Library/PrivilegedHelperTools/openrdx-hardware",
            "/tmp/openrdx-hardware"
        )));
        assert!(!registration_is_owned(&owned.replace(
            "/Library/LaunchDaemons/com.openrdx.hardware.plist",
            "(submitted by smd.554)"
        )));
        assert!(!registration_is_owned(&format!(
            "{owned}\n\tprogram = /tmp/foreign"
        )));
        assert!(!registration_is_owned(
            "system/com.openrdx.hardware = {\n\tprogram identifier = Contents/Library/LaunchServices/openrdx-hardware (mode: 2)\n}"
        ));
    }

    /// A retained duplicate preserves kernel ownership when the parent handle closes.
    #[test]
    fn retained_description_blocks_new_generation_until_release() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path())
            .unwrap();
        acquire_file_lock(&file).unwrap();
        let retained = file.try_clone().unwrap();
        drop(file);
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path())
            .unwrap();
        assert!(acquire_file_lock(&contender).is_err());
        drop(retained);
        assert!(acquire_file_lock(&contender).is_ok());
    }

    /// Repair requires historical ownership and complete current protection even if hashes differ.
    #[test]
    fn repair_authority_never_accepts_foreign_or_unprotected_targets() {
        assert!(replacement_authorized(true, true, true, true));
        for evidence in [
            (false, true, true, true),
            (true, false, true, true),
            (true, true, false, true),
            (true, true, true, false),
        ] {
            assert!(!replacement_authorized(
                evidence.0, evidence.1, evidence.2, evidence.3
            ));
        }
    }

    /// Sticky temp protects root children, never a writable package script directory itself.
    #[test]
    fn package_sources_reject_writable_immediate_foreign_and_symlink_directories() {
        use std::path::Path;
        let directory = u32::from(libc::S_IFDIR);
        assert!(package_directory_allowed(
            Path::new("/Library/InstallerSandboxes/pkg/Scripts"),
            0,
            0,
            directory | 0o700,
            true
        ));
        assert!(package_directory_allowed(
            Path::new("/private/tmp"),
            0,
            0,
            directory | 0o1777,
            false
        ));
        assert!(!package_directory_allowed(
            Path::new("/private/tmp"),
            0,
            0,
            directory | 0o1777,
            true
        ));
        assert!(!package_directory_allowed(
            Path::new("/tmp/attacker"),
            501,
            20,
            directory | 0o755,
            true
        ));
        assert!(!package_directory_allowed(
            Path::new("/private/tmp/attacker"),
            0,
            0,
            directory | 0o777,
            true
        ));
        assert!(!package_directory_allowed(
            Path::new("/private/other"),
            0,
            0,
            directory | 0o1777,
            false
        ));
        assert!(!package_directory_allowed(
            Path::new("/private/tmp"),
            0,
            20,
            directory | 0o1777,
            false
        ));
        assert!(!package_directory_allowed(
            Path::new("/private/tmp/pkg"),
            0,
            0,
            u32::from(libc::S_IFLNK) | 0o755,
            true
        ));
    }

    /// Public read permission is added only after verification and never grants write access.
    #[test]
    fn enrollment_publication_makes_verified_retained_file_publicly_readable() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let candidate = tempfile::NamedTempFile::new().unwrap();
        candidate
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let original = candidate.as_file().metadata().unwrap();
        assert!(make_verified_enrollment_readable(candidate.as_file(), false).is_err());
        assert_eq!(
            candidate.as_file().metadata().unwrap().mode() & 0o7777,
            0o600
        );
        make_verified_enrollment_readable(candidate.as_file(), true).unwrap();
        let published = candidate.as_file().metadata().unwrap();
        assert_eq!(published.mode() & 0o7777, 0o644);
        assert_eq!(
            (
                published.uid(),
                published.gid(),
                published.dev(),
                published.ino()
            ),
            (
                original.uid(),
                original.gid(),
                original.dev(),
                original.ino()
            )
        );
    }

    /// Alias inodes cannot gain publication permissions, even after claimed verification.
    #[test]
    fn enrollment_publication_rejects_hardlink_and_preserves_private_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pending.json");
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, directory.path().join("alias.json")).unwrap();
        let file = std::fs::File::open(path).unwrap();
        assert!(make_verified_enrollment_readable(&file, true).is_err());
        assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);
    }

    /// Only five fixed actions may cross the elevated command boundary.
    #[test]
    fn actions_reject_paths_requirements_and_extra_arguments() {
        for action in ["prepare", "install", "verify", "repair", "remove"] {
            assert!(parse_action(&[action.to_owned()]).is_ok());
        }
        for args in [
            vec![],
            vec!["enroll".into()],
            vec!["install".into(), "/tmp/app".into()],
            vec!["verify --path=/tmp/app".into()],
        ] {
            assert!(parse_action(&args).is_err());
        }
    }

    /// Mutable or aliased lock inodes cannot serialize the installation.
    #[test]
    fn lock_evidence_requires_root_single_link_private_regular_file() {
        assert!(validate_lock_evidence(true, 0, 1, 0o600).is_ok());
        for evidence in [
            (false, 0, 1, 0o600),
            (true, 501, 1, 0o600),
            (true, 0, 2, 0o600),
            (true, 0, 1, 0o660),
            (true, 0, 1, 0o4600),
        ] {
            assert!(
                validate_lock_evidence(evidence.0, evidence.1, evidence.2, evidence.3).is_err()
            );
        }
    }

    /// A fixed transaction must quiesce under the retained lease, then publish.
    #[test]
    fn commit_requires_prepared_transaction_and_verified_generation() {
        assert!(commit_allowed(true, true));
        assert!(!commit_allowed(false, true));
        assert!(!commit_allowed(true, false));
    }
}

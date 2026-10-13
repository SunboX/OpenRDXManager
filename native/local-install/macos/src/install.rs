// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verification and atomic enrollment at compiled, administrator-owned locations.

use rdx_local_trust::{
    RuntimeInventory, read_protected_inventory, verify_enrollment, verify_protected_file,
    verify_protected_runtime,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::Duration,
};

pub(super) const APP: &str = "/Applications/OpenRDXManager.app";
pub(super) const TRUST: &str = "/Library/Application Support/OpenRDXManager/LocalTrust";
pub(super) const ENROLLMENT: &str =
    "/Library/Application Support/OpenRDXManager/LocalTrust/runtime.json";
pub(super) const PENDING: &str =
    "/Library/Application Support/OpenRDXManager/LocalTrust/pending-runtime.json";
pub(super) const PREVIOUS: &str =
    "/Library/Application Support/OpenRDXManager/LocalTrust/previous-runtime.json";
pub(super) const HELPER: &str = "/Library/PrivilegedHelperTools/openrdx-hardware";
pub(super) const CLI: &str =
    "/Library/Application Support/OpenRDXManager/LocalTrust/openrdx-local-install";
pub(super) const DAEMON: &str = "/Library/LaunchDaemons/com.openrdx.hardware.plist";
pub(super) const DAEMON_BYTES: &[u8] =
    include_bytes!("../../../../resources/installer/macos/com.openrdx.hardware.plist");
const HELPER_ENTRY: &str = "Contents/Library/LaunchServices/openrdx-hardware";
const CLI_ENTRY: &str = "Contents/Resources/native/macos/openrdx-local-install";

/// Verify the fixed enrolled app, separately staged helper, setup tool and daemon.
pub(super) fn verify_installed() -> Result<RuntimeInventory, String> {
    let inventory =
        verify_enrollment(Path::new(ENROLLMENT), "macos").map_err(|error| error.to_string())?;
    verify_generation(&inventory)?;
    Ok(inventory)
}

/// Prove administrator replacement/removal authority without authenticating damaged code.
/// A protected historical enrollment identifies our fixed targets; every existing
/// object must retain root/no-write/no-ACL/no-link protection. Hashes and seals
/// remain mandatory for committing enrollment and admitting service sessions.
pub(super) fn verify_owned_targets(owned_registration: bool) -> Result<RuntimeInventory, String> {
    for path in [CLI, HELPER, DAEMON, ENROLLMENT, PREVIOUS, PENDING] {
        verify_owned_file_if_present(path)?;
    }
    let mut record = verify_enrollment(Path::new(ENROLLMENT), "macos")
        .or_else(|_| read_protected_inventory(Path::new(PREVIOUS), "macos"))
        .map_err(
            |_| "no protected strict historical ownership record; foreign replacement is refused",
        )?;
    if let Ok(pending) = read_protected_inventory(Path::new(PENDING), "macos") {
        // A partial newer payload may have changed framework aliases. Authorize
        // only literal links pinned by one of the protected known generations.
        for link in pending.links {
            if fs::read_link(Path::new(APP).join(&link.path))
                .is_ok_and(|target| target.as_os_str() == std::ffi::OsStr::new(&link.target))
            {
                record.files.retain(|file| file.path != link.path);
                record.links.retain(|old| old.path != link.path);
                record.links.push(link);
            }
        }
    }
    provision_verifier_capacity(&record)?;
    if Path::new(APP).exists() {
        rdx_local_trust::verify_protected_tree_ownership(Path::new(APP), &record)
            .map_err(|error| error.to_string())?;
    } else if fs::symlink_metadata(APP).is_ok() {
        return Err("foreign application link occupies the fixed app path".into());
    }
    if !openrdx_macos_local_install::replacement_authorized(true, true, true, owned_registration) {
        return Err("fixed service registration is not owned by local installation".into());
    }
    Ok(record)
}

/// Validate an existing fixed setup object for replacement without trusting its bytes.
fn verify_owned_file_if_present(path: &str) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let parent = Path::new(path)
        .parent()
        .ok_or("fixed setup path has no parent")?;
    rdx_local_trust::verify_protected_directory(parent).map_err(|error| error.to_string())?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| error.to_string())?;
    rdx_local_trust::verify_protected_descriptor(&file).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err("owned setup file was replaced".into());
    }
    Ok(())
}

/// Retain package enrollment protection while reading, then verify the whole runtime.
fn verify_pending() -> Result<RuntimeInventory, String> {
    let inventory =
        read_protected_inventory(Path::new(PENDING), "macos").map_err(|error| error.to_string())?;
    verify_generation(&inventory)?;
    Ok(inventory)
}

/// Ensure all privileged executable inputs agree with the package's exact generation.
fn verify_generation(inventory: &RuntimeInventory) -> Result<(), String> {
    provision_verifier_capacity(inventory)?;
    verify_protected_runtime(Path::new(APP), inventory).map_err(|error| error.to_string())?;
    for (entry, path) in [(HELPER_ENTRY, HELPER), (CLI_ENTRY, CLI)] {
        let file = inventory
            .files
            .iter()
            .find(|file| file.path == entry)
            .ok_or("required privileged executable is absent from runtime inventory")?;
        verify_protected_file(Path::new(path), &file.sha256, file.size)
            .map_err(|error| error.to_string())?;
    }
    verify_daemon()?;
    verify_code(APP, "com.openrdx.manager", &inventory.manager_cd_hash)?;
    verify_code(HELPER, "com.openrdx.hardware", &inventory.helper_cd_hash)?;
    let output = fixed_command(
        "/usr/libexec/PlistBuddy",
        &[
            "-c",
            "Print :OpenRDXInstallationMode",
            "/Applications/OpenRDXManager.app/Contents/Info.plist",
        ],
    )?;
    if output.trim() != "local" {
        return Err("installed application has no explicit local installation mode".into());
    }
    Ok(())
}

/// Raise only this root setup process's descriptor limit, never system-wide limits.
/// A package exceeding the daemon's fixed 8,192-descriptor budget is refused.
fn provision_verifier_capacity(inventory: &RuntimeInventory) -> Result<(), String> {
    let required = rdx_local_trust::runtime_handle_requirement(inventory)
        .map_err(|error| error.to_string())? as libc::rlim_t;
    if required > 8192 {
        return Err("runtime exceeds the fixed local-service verifier descriptor budget".into());
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err("cannot inspect setup process descriptor budget".into());
    }
    if required > limit.rlim_max {
        return Err("setup hard descriptor limit cannot verify this runtime".into());
    }
    let capacity = limit.rlim_max.min(8192);
    if capacity > limit.rlim_cur {
        // Ownership-only repair may inspect additional regular files left by a
        // partial newer payload, while admission still pins the exact inventory.
        limit.rlim_cur = capacity;
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err("cannot provision setup process verifier capacity".into());
        }
    }
    Ok(())
}

/// Require the exact fixed launchd configuration, protected independently of app files.
pub(super) fn verify_daemon() -> Result<(), String> {
    verify_protected_file(
        Path::new(DAEMON),
        &format!("{:x}", Sha256::digest(DAEMON_BYTES)),
        DAEMON_BYTES.len() as u64,
    )
    .map_err(|error| error.to_string())
}

/// Validate the sealed executable and its exact generated identifier/CodeDirectory hash.
fn verify_code(path: &str, identifier: &str, hash: &str) -> Result<(), String> {
    fixed_command(
        "/usr/bin/codesign",
        &["--verify", "--strict", "--all-architectures", path],
    )?;
    let output = fixed_command("/usr/bin/codesign", &["--display", "--verbose=4", path])?;
    if !output
        .lines()
        .any(|line| line == format!("Identifier={identifier}"))
        || !output.lines().any(|line| line == format!("CDHash={hash}"))
    {
        return Err("installed code seal does not match enrolled identity".into());
    }
    Ok(())
}

/// Execute a compiled system tool with fixed arguments and no inherited tool environment.
pub(super) fn fixed_command(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("LANG", "C")
        .output()
        .map_err(|error| format!("required system setup tool {program} is unavailable: {error}"))?;
    if output.stdout.len().saturating_add(output.stderr.len()) > 65536 {
        return Err("system setup evidence exceeded its bound".into());
    }
    if !output.status.success() {
        let status = output
            .status
            .code()
            .map(|code| format!("exit={code}"))
            .unwrap_or_else(|| output.status.to_string());
        // Diagnostic output is never identity evidence. Bound it and preserve
        // UTF-8 boundaries before passing it over the supervisor's private frame.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut end = stderr.len().min(1024);
        while !stderr.is_char_boundary(end) {
            end -= 1;
        }
        return Err(format!(
            "{program} rejected fixed setup action ({status}): {}{}; run the package installer to repair",
            &stderr[..end],
            if end < stderr.len() {
                " [truncated]"
            } else {
                ""
            }
        ));
    }
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    String::from_utf8(bytes).map_err(|_| "system setup evidence was not UTF-8".into())
}

/// Connect to the retained root supervisor before committing any new enrollment.
/// Failure leaves the daemon stopped; only a complete verified generation is published.
pub(super) fn commit() -> Result<(), String> {
    let mut channel = super::transaction::connect_supervisor()?;
    channel
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|error| error.to_string())?;
    // Retain the exact candidate inode through verification, publication mode
    // change and rename. A pathname-only chmod could select a replacement.
    let candidate = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(PENDING)
        .map_err(|error| error.to_string())?;
    rdx_local_trust::verify_protected_descriptor(&candidate).map_err(|error| error.to_string())?;
    let verification = verify_pending();
    let verified = verification.is_ok();
    if !openrdx_macos_local_install::commit_allowed(true, verified) {
        let cause = verification
            .err()
            .unwrap_or_else(|| "transaction was not prepared".into());
        return Err(format!(
            "pending generation failed complete protection/content/code verification: {cause}; access remains disabled"
        ));
    }
    assert_candidate_namespace(&candidate, PENDING)?;
    openrdx_macos_local_install::make_verified_enrollment_readable(&candidate, verified)?;
    rdx_local_trust::verify_protected_descriptor(&candidate).map_err(|error| error.to_string())?;
    assert_candidate_namespace(&candidate, PENDING)?;
    candidate.sync_all().map_err(|error| error.to_string())?;
    fs::rename(PENDING, ENROLLMENT).map_err(|error| error.to_string())?;
    assert_candidate_namespace(&candidate, ENROLLMENT)?;
    fs::File::open(TRUST)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    verify_installed()?;
    channel.write_all(b"C").map_err(|error| error.to_string())?;
    super::transaction::read_registration_result(&mut channel)
}

/// Ensure publication still names the exact root-protected retained candidate inode.
fn assert_candidate_namespace(candidate: &fs::File, path: &str) -> Result<(), String> {
    let held = candidate.metadata().map_err(|error| error.to_string())?;
    let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !named.is_file()
        || named.uid() != 0
        || named.nlink() != 1
        || held.dev() != named.dev()
        || held.ino() != named.ino()
        || held.mode() != named.mode()
    {
        return Err("verified enrollment candidate was replaced before publication".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real fixed-tool failure must retain both exit status and bounded stderr evidence.
    #[test]
    fn fixed_tool_failure_reports_exit_status_and_stderr() {
        let error = fixed_command(
            "/bin/sh",
            &["-c", "printf 'bootstrap fixture rejected' >&2; exit 7"],
        )
        .unwrap_err();
        assert!(error.contains("exit=7"), "{error}");
        assert!(error.contains("bootstrap fixture rejected"), "{error}");
    }

    /// Oversized stderr is truncated for diagnostics or refused at the full evidence bound.
    #[test]
    fn fixed_tool_failure_bounds_stderr_and_evidence() {
        let error =
            fixed_command("/bin/sh", &["-c", "printf '%01025d' 1 >&2; exit 7"]).unwrap_err();
        assert!(error.contains("exit=7"), "{error}");
        assert!(error.contains("[truncated]"), "{error}");
        assert!(error.len() < 1200);
        let excessive =
            fixed_command("/bin/sh", &["-c", "printf '%066000d' 1 >&2; exit 7"]).unwrap_err();
        assert_eq!(excessive, "system setup evidence exceeded its bound");
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained installation and hardware leases spanning both Installer script phases.

use super::install::{self, APP, CLI, DAEMON, ENROLLMENT, HELPER, PENDING, PREVIOUS, TRUST};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    thread,
    time::{Duration, Instant},
};

const HARDWARE_LOCK: &str = "/private/var/run/openrdx-hardware.lock";
const INSTALL_LOCK: &str = "/private/var/run/openrdx-local-install.lock";
const SUPERVISOR: &str = "/private/var/run/openrdx-local-install.sock";
const LABEL: &str = "system/com.openrdx.hardware";
const MAX_TRANSACTION: Duration = Duration::from_secs(600);
const MAX_PREPARATION_ERROR_BYTES: usize = 1024;

/// Own one validated kernel flock; releasing the handle releases this exact lease.
struct Lease(File);

impl Lease {
    /// Retain and lock a root-private single-link inode without a check/release gap.
    fn acquire(path: &str) -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| error.to_string())?;
        rdx_local_trust::verify_protected_descriptor(&file).map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        openrdx_macos_local_install::validate_lock_evidence(
            metadata.is_file(),
            metadata.uid(),
            metadata.nlink(),
            metadata.mode(),
        )?;
        openrdx_macos_local_install::acquire_file_lock(&file)?;
        let lease = Self(file);
        lease.recheck(path)?;
        Ok(lease)
    }

    /// Reject namespace replacement while the lease remains retained.
    fn recheck(&self, path: &str) -> Result<(), String> {
        rdx_local_trust::verify_protected_descriptor(&self.0).map_err(|error| {
            // A failed ACL/metadata syscall after fork needs the retained fd and
            // a fresh diagnostic snapshot; neither becomes authorization proof.
            let snapshot = self.0.metadata().map(|metadata| {
                (metadata.mode(), metadata.uid(), metadata.gid(), metadata.nlink())
            });
            format!("retained lease protection failed (fd={}, mode/uid/gid/links={snapshot:?}): {error}", self.0.as_raw_fd())
        })?;
        let opened = self.0.metadata().map_err(|error| format!("cannot inspect retained lease fd={}: {error}", self.0.as_raw_fd()))?;
        let named = fs::symlink_metadata(path).map_err(|error| format!("cannot inspect lease namespace {path}: {error}"))?;
        openrdx_macos_local_install::validate_lock_evidence(
            named.is_file(),
            named.uid(),
            named.nlink(),
            named.mode(),
        ).map_err(|error| format!("named lease protection failed at {path}: {error}"))?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err("installation ownership namespace was replaced".into());
        }
        Ok(())
    }
}

/// Determine whether the fixed launchd label currently exists, never trusting output text.
fn registered() -> Result<bool, String> {
    let output = std::process::Command::new("/bin/launchctl")
        .args(["print", LABEL])
        .env_clear()
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(true);
    }
    // launchctl uses 113 when the exact service is absent. Other failures are not absence.
    if output.status.code() == Some(113) {
        return Ok(false);
    }
    Err("cannot establish existing launchd registration; setup is disabled".into())
}

/// Refuse any preexisting files/registration without complete owned local-generation proof.
fn verify_previous_ownership() -> Result<bool, String> {
    let mut existing = false;
    for path in [APP, HELPER, CLI, DAEMON, ENROLLMENT, PREVIOUS, PENDING] {
        match fs::symlink_metadata(path) {
            Ok(_) => existing = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let loaded = registered()?;
    if existing {
        let owned_registration = if loaded {
            let evidence = install::fixed_command("/bin/launchctl", &["print", LABEL])?;
            openrdx_macos_local_install::registration_is_owned(&evidence)
        } else {
            true
        };
        install::verify_owned_targets(owned_registration)?;
    } else if loaded {
        return Err("another or legacy signed registration occupies com.openrdx.hardware; unregister it using its original app before installing local mode".into());
    }
    Ok(loaded)
}

/// Disable the exact verified local registration only while exclusive mutation ownership is held.
fn quiesce(loaded: bool) -> Result<(), String> {
    if loaded {
        install::fixed_command("/bin/launchctl", &["bootout", LABEL])?;
    }
    if registered()? {
        return Err("launchd registration did not stop; payload replacement is refused".into());
    }
    Ok(())
}

/// Create only fixed setup directories; never repair foreign ownership or broad permissions.
fn ensure_trust_directories() -> Result<(), String> {
    for path in ["/Library/Application Support/OpenRDXManager", TRUST] {
        if !Path::new(path).exists() {
            let parent = Path::new(path)
                .parent()
                .ok_or("fixed setup directory has no parent")?;
            rdx_local_trust::verify_protected_directory(parent)
                .map_err(|error| error.to_string())?;
            fs::DirBuilder::new()
                .mode(0o755)
                .create(path)
                .map_err(|error| error.to_string())?;
            // Set readable traversal only on the directory just created by this
            // root transaction; caller umask cannot make enrollment unreadable.
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .map_err(|error| error.to_string())?;
        }
        rdx_local_trust::verify_protected_directory(Path::new(path))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Remove only a stale root-owned socket after exclusive setup ownership is established.
fn clear_socket() -> Result<(), String> {
    match fs::symlink_metadata(SUPERVISOR) {
        Ok(metadata) => {
            use std::os::unix::fs::FileTypeExt;
            if !metadata.file_type().is_socket()
                || metadata.uid() != 0
                || metadata.mode() & 0o7777 != 0o600
            {
                return Err("foreign setup transaction socket".into());
            }
            fs::remove_file(SUPERVISOR).map_err(|error| error.to_string())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

/// Keep both leases in a detached root supervisor; return only after it confirms bootout.
/// Preinstall failure never triggers privileged payload replacement. The child times out
/// after ten minutes with the daemon stopped and enrollment revoked, requiring repair.
pub(super) fn prepare() -> Result<(), String> {
    let _standard_descriptors = reserve_missing_standard_descriptors()?;
    let setup = Lease::acquire(INSTALL_LOCK)?;
    let hardware = Lease::acquire(HARDWARE_LOCK)?;
    let package_record = super::package_source::read_package_record()?;
    let loaded = verify_previous_ownership()?;
    ensure_trust_directories()?;
    if !Path::new(ENROLLMENT).exists() && !Path::new(PREVIOUS).exists() {
        // Fresh first installs need durable ownership proof before Installer can
        // leave a partial payload. This incoming policy is NEVER enrollment.
        let mut previous = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(PREVIOUS)
            .map_err(|error| error.to_string())?;
        previous
            .write_all(&package_record)
            .and_then(|()| previous.sync_all())
            .map_err(|error| error.to_string())?;
        rdx_local_trust::verify_protected_descriptor(&previous)
            .map_err(|error| error.to_string())?;
        File::open(TRUST)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
    }
    clear_socket()?;
    let listener = UnixListener::bind(SUPERVISOR).map_err(|error| error.to_string())?;
    fs::set_permissions(SUPERVISOR, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let (mut parent, mut child) = UnixStream::pair().map_err(|error| error.to_string())?;
    parent
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    // The entrypoint is single-threaded, so this fork has no inherited Rust mutex users.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        clear_socket()?;
        return Err("cannot retain installation supervisor".into());
    }
    if pid == 0 {
        drop(parent);
        let result = supervise(listener, &mut child, setup, hardware, loaded);
        if let Err(error) = &result {
            // Only the retained fork socket carries diagnostics. Installer's
            // inherited streams stay detached and cannot hold its pipes open.
            let _ = write_preparation_failure(&mut child, error);
        }
        // No child stack unwinding or parent stdout flushing after fork.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }
    drop(child);
    // Do not explicitly LOCK_UN here: forked descriptors share one flock owner.
    drop(listener);
    drop(setup);
    drop(hardware);
    read_preparation_result(&mut parent)
}

/// Retain only missing standard stream slots before opening leases or private sockets.
/// Present streams remain untouched; the single-threaded prepare entrypoint owns
/// these guards through fork so later dup2 detachment cannot replace a protocol fd.
fn reserve_missing_standard_descriptors() -> Result<Vec<File>, String> {
    let mut retained = Vec::new();
    for descriptor in [0, 1, 2] {
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0 {
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBADF) {
            return Err(format!("cannot inspect standard stream {descriptor}: {error}"));
        }
        let opened = unsafe {
            libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
        };
        if opened < 0 {
            return Err(format!("cannot reserve missing standard stream {descriptor}: {}", std::io::Error::last_os_error()));
        }
        let file = unsafe { File::from_raw_fd(opened) };
        // open chooses the lowest free descriptor. The entrypoint is single
        // threaded, so a different result means our reservation is unreliable.
        if opened != descriptor {
            return Err("standard stream namespace changed during reservation".into());
        }
        retained.push(file);
    }
    Ok(retained)
}

/// Await one private fork-channel response under the parent's existing timeout.
/// Any malformed or incomplete response refuses privileged payload replacement.
fn read_preparation_result(parent: &mut UnixStream) -> Result<(), String> {
    read_supervisor_result(parent, "quiescence", "replacement is refused")
}

/// Read the retained supervisor's registration result under the caller's timeout.
pub(super) fn read_registration_result(channel: &mut UnixStream) -> Result<(), String> {
    read_supervisor_result(channel, "registration", "privileged access remains disabled, rerun the package installer")
}

/// Decode one bounded private supervisor frame; only Y permits the fixed phase.
/// Invalid UTF-8, framing, lengths or transport remain failures with phase guidance.
fn read_supervisor_result(channel: &mut UnixStream, phase: &str, refusal: &str) -> Result<(), String> {
    let mut result = [0];
    channel
        .read_exact(&mut result)
        .map_err(|_| format!("setup supervisor did not confirm {phase}; {refusal}"))?;
    if result == [b'Y'] {
        return Ok(());
    }
    if result != [b'N'] {
        return Err(format!("setup supervisor refused {phase}; {refusal}"));
    }
    let mut length = [0_u8; 2];
    channel.read_exact(&mut length).map_err(|_| format!("setup supervisor {phase} failure detail is incomplete; {refusal}"))?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_PREPARATION_ERROR_BYTES {
        return Err(format!("setup supervisor {phase} failure detail exceeds its bound; {refusal}"));
    }
    let mut bytes = vec![0; length];
    channel.read_exact(&mut bytes).map_err(|_| format!("setup supervisor {phase} failure detail is incomplete; {refusal}"))?;
    let detail = String::from_utf8(bytes).map_err(|_| format!("setup supervisor {phase} failure detail is not UTF-8; {refusal}"))?;
    Err(format!("setup supervisor refused {phase}: {detail}; {refusal}"))
}

/// Send at most 1,024 UTF-8 bytes over a private supervisor channel, never Installer stdio.
/// Retains character boundaries and emits a fixed N/u16-length frame; write failure
/// cannot authorize preparation or registration and the caller closes the channel.
fn write_preparation_failure(child: &mut UnixStream, error: &str) -> Result<(), String> {
    let mut length = error.len().min(MAX_PREPARATION_ERROR_BYTES);
    while !error.is_char_boundary(length) {
        length -= 1;
    }
    child.write_all(b"N").map_err(|error| error.to_string())?;
    child.write_all(&(length as u16).to_be_bytes()).map_err(|error| error.to_string())?;
    child.write_all(&error.as_bytes()[..length]).map_err(|error| error.to_string())
}

/// Detach, stop only a verified idle generation, revoke it, and await a root commit.
fn supervise(
    listener: UnixListener,
    ready: &mut UnixStream,
    setup: Lease,
    hardware: Lease,
    loaded: bool,
) -> Result<(), String> {
    if unsafe { libc::setsid() } < 0 {
        return Err(format!("cannot detach setup supervisor: {}", std::io::Error::last_os_error()));
    }
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|error| format!("cannot open supervisor null streams: {error}"))?;
    for descriptor in [0, 1, 2] {
        if unsafe { libc::dup2(null.as_raw_fd(), descriptor) } < 0 {
            return Err(format!("cannot detach setup stream {descriptor}: {}", std::io::Error::last_os_error()));
        }
    }
    hardware.recheck(HARDWARE_LOCK).map_err(|error| format!("supervisor hardware lease recheck failed: {error}"))?;
    setup.recheck(INSTALL_LOCK).map_err(|error| format!("supervisor setup lease recheck failed: {error}"))?;
    quiesce(loaded).map_err(|error| format!("supervisor service quiescence failed: {error}"))?;
    revoke_enrollment().map_err(|error| format!("supervisor enrollment revocation failed: {error}"))?;
    ready.write_all(b"Y").map_err(|error| format!("supervisor readiness confirmation failed: {error}"))?;
    let deadline = Instant::now() + MAX_TRANSACTION;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut channel, _)) => {
                if !root_peer(&channel)? {
                    continue;
                }
                if !read_commit_message(&mut channel)? {
                    continue;
                }
                let result =
                    install::verify_installed().and_then(|_| hardware.recheck(HARDWARE_LOCK));
                if let Err(error) = result {
                    let _ = write_preparation_failure(&mut channel, &format!("new generation was not verified: {error}"));
                    clear_socket()?;
                    return Err("new generation was not verified".into());
                }
                // The old daemon is gone, the new generation is fully enrolled and
                // setup ownership remains retained through registration.
                drop(hardware);
                let result = bootstrap_owned_registration();
                match &result {
                    Ok(()) => { let _ = channel.write_all(b"Y"); }
                    Err(error) => { let _ = write_preparation_failure(&mut channel, error); }
                }
                clear_socket()?;
                drop(setup);
                return result;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(error) => {
                clear_socket()?;
                return Err(error.to_string());
            }
        }
    }
    clear_socket()?;
    Err("installer transaction expired; service remains stopped".into())
}

/// Bootstrap only while the fixed label remains absent, then prove exact ownership.
/// A concurrent foreign or legacy job is refused without bootout or BTM changes;
/// successful tool exit alone never confirms the newly installed registration.
fn bootstrap_owned_registration() -> Result<(), String> {
    if registered()? {
        let evidence = install::fixed_command("/bin/launchctl", &["print", LABEL])?;
        let reason = if openrdx_macos_local_install::registration_is_owned(&evidence) {
            "fixed local registration reappeared during installation"
        } else {
            "foreign or legacy signed registration reappeared during installation; unregister it using its original app"
        };
        return Err(reason.into());
    }
    install::fixed_command("/bin/launchctl", &["bootstrap", "system", DAEMON])?;
    if !registered()? {
        return Err("launchctl bootstrap returned success but the fixed daemon is absent".into());
    }
    let evidence = install::fixed_command("/bin/launchctl", &["print", LABEL])?;
    if !openrdx_macos_local_install::registration_is_owned(&evidence) {
        return Err("registration after bootstrap is foreign or changed; unregister the legacy service using its original app".into());
    }
    Ok(())
}

/// Await only the fixed commit byte under the existing verification timeout.
/// Missing, malformed or failed reads never authorize enrollment registration.
fn read_commit_message(channel: &mut UnixStream) -> Result<bool, String> {
    // Darwin's accepted stream inherits O_NONBLOCK from the polling listener.
    // Wait for the already authenticated root client's full runtime verification
    // before reading C; an immediate WouldBlock would close its live transaction.
    channel
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    channel
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|error| error.to_string())?;
    let mut message = [0];
    Ok(channel.read_exact(&mut message).is_ok() && message == [b'C'])
}

/// Prove kernel peer credentials on the retained transaction socket, never a pathname alone.
fn root_peer(channel: &UnixStream) -> Result<bool, String> {
    let mut uid = u32::MAX;
    let mut gid = u32::MAX;
    if unsafe { libc::getpeereid(channel.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err("setup peer credentials unavailable".into());
    }
    Ok(uid == 0)
}

/// Return a retained authenticated root supervisor connection to the new installer CLI.
pub(super) fn connect_supervisor() -> Result<UnixStream, String> {
    let metadata = fs::symlink_metadata(SUPERVISOR)
        .map_err(|_| "no prepared installer transaction; rerun the package installer")?;
    use std::os::unix::fs::FileTypeExt;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o600
    {
        return Err("foreign setup transaction socket".into());
    }
    let channel = UnixStream::connect(SUPERVISOR).map_err(|error| error.to_string())?;
    if !root_peer(&channel)? {
        return Err("setup supervisor is not root".into());
    }
    Ok(channel)
}

/// Verify complete enrollment/content/seals and the actual fixed launchd registration.
/// Socket activation may legitimately leave the helper idle; physical readiness is separate.
pub(super) fn verify() -> Result<(), String> {
    install::verify_installed()?;
    if !registered()? {
        return Err("verified daemon files are not registered; rerun the package installer or administrator Repair".into());
    }
    let evidence = install::fixed_command("/bin/launchctl", &["print", LABEL])?;
    if !openrdx_macos_local_install::registration_is_owned(&evidence) {
        return Err("registered launchd job is foreign or has changed".into());
    }
    Ok(())
}

/// Re-register only a currently verified complete owned generation, without replacing files.
pub(super) fn repair() -> Result<(), String> {
    let _setup = Lease::acquire(INSTALL_LOCK)?;
    let hardware = Lease::acquire(HARDWARE_LOCK)?;
    let loaded = verify_previous_ownership()?;
    if !Path::new(ENROLLMENT).exists() {
        return Err("enrollment is absent; rerun the package installer".into());
    }
    quiesce(loaded)?;
    install::verify_installed()?;
    hardware.recheck(HARDWARE_LOCK)?;
    drop(hardware);
    install::fixed_command("/bin/launchctl", &["bootstrap", "system", DAEMON]).map(|_| ())
}

/// Stop and remove only the complete verified owned setup, preserving all user data/backups.
pub(super) fn remove() -> Result<(), String> {
    let _setup = Lease::acquire(INSTALL_LOCK)?;
    let hardware = Lease::acquire(HARDWARE_LOCK)?;
    let loaded = verify_previous_ownership()?;
    quiesce(loaded)?;
    hardware.recheck(HARDWARE_LOCK)?;
    install::verify_owned_targets(true)?;
    use openrdx_macos_local_install::removal::{RemovalStep, remove_owned_payload};
    // Revoke admission first, preserving the latest policy until EVERY owned
    // payload cleanup succeeds. The CLI stays available through earlier errors.
    remove_owned_payload(|step| {
        let result = match step {
            RemovalStep::Revoke => return revoke_enrollment(),
            RemovalStep::App => fs::remove_dir_all(APP),
            RemovalStep::Helper => fs::remove_file(HELPER),
            RemovalStep::Daemon => fs::remove_file(DAEMON),
            RemovalStep::Pending => fs::remove_file(PENDING),
            RemovalStep::Cli => fs::remove_file(CLI),
            RemovalStep::History => fs::remove_file(PREVIOUS),
        };
        match result {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    })?;
    let _ = fs::remove_dir(TRUST); // Preserve any other artifacts, including backups.
    Ok(())
}

/// Revoke current IPC policy while retaining the newest strict ownership evidence.
/// Caller retains setup/hardware leases and has proved all fixed target protection.
fn revoke_enrollment() -> Result<(), String> {
    match fs::symlink_metadata(ENROLLMENT) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    }
    let historical = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(ENROLLMENT)
        .map_err(|error| format!("cannot retain current enrollment for revocation: {error}"))?;
    rdx_local_trust::verify_protected_descriptor(&historical).map_err(|error| format!("current enrollment protection check failed: {error}"))?;
    let current_valid = rdx_local_trust::verify_enrollment(Path::new(ENROLLMENT), "macos").is_ok();
    if !current_valid {
        // Malformed current metadata is never runtime authority. Valid historical
        // policy must survive so an administrator can retry owned cleanup.
        rdx_local_trust::read_protected_inventory(Path::new(PREVIOUS), "macos")
            .map_err(|error| format!("replacement historical enrollment check failed: {error}"))?;
    }
    openrdx_macos_local_install::removal::revoke_owned_enrollment(
        &historical,
        Path::new(ENROLLMENT),
        Path::new(PREVIOUS),
        current_valid,
    )?;
    if current_valid {
        rdx_local_trust::verify_protected_descriptor(&historical)
            .map_err(|error| format!("archived enrollment protection check failed: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exact foreign-label bootstrap failures must survive the private socket response.
    #[test]
    fn registration_response_preserves_foreign_job_failure() {
        let (mut client, mut supervisor) = UnixStream::pair().unwrap();
        let detail = "foreign or legacy signed registration reappeared during installation";
        write_preparation_failure(&mut supervisor, detail).unwrap();
        drop(supervisor);
        let error = read_registration_result(&mut client).unwrap_err();
        assert!(error.contains(detail), "{error}");
        assert!(error.contains("privileged access remains disabled"), "{error}");
    }

    /// Unknown, empty, truncated, oversized or malformed frames cannot confirm registration.
    #[test]
    fn registration_response_refuses_invalid_failure_frames() {
        for bytes in [
            vec![b'N', 4, 1],
            vec![b'N', 0, 1, 0xff],
            vec![b'N', 0, 3, b'x'],
            vec![b'N', 0],
            vec![b'N', 0, 0],
            vec![b'N'],
            vec![b'Z'],
            vec![],
        ] {
            let (mut client, mut supervisor) = UnixStream::pair().unwrap();
            supervisor.write_all(&bytes).unwrap();
            drop(supervisor);
            let error = read_registration_result(&mut client).unwrap_err();
            assert!(error.contains("registration"), "{error}");
            assert!(error.contains("privileged access remains disabled"), "{error}");
        }
    }

    /// Long Unicode diagnostics remain valid and bounded while registration stays refused.
    #[test]
    fn registration_response_bounds_overlong_utf8_diagnostics() {
        let (mut client, mut supervisor) = UnixStream::pair().unwrap();
        write_preparation_failure(&mut supervisor, &"α".repeat(1100)).unwrap();
        drop(supervisor);
        let error = read_registration_result(&mut client).unwrap_err();
        assert!(error.contains(&"α".repeat(512)), "{error}");
        assert!(!error.contains(&"α".repeat(513)), "{error}");
    }

    /// Registration keeps the single-byte Y success response without waiting for EOF.
    #[test]
    fn registration_response_keeps_single_byte_success() {
        let (mut client, mut supervisor) = UnixStream::pair().unwrap();
        client.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        supervisor.write_all(b"Y").unwrap();
        read_registration_result(&mut client).unwrap();
    }

    /// Missing Installer stdio must never place ownership/protocol handles below fd3.
    #[test]
    fn missing_standard_streams_cannot_become_lease_or_ready_handles() {
        for missing in ["1", "all"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "transaction::tests::stdio_reservation_isolated_child", "--nocapture"])
                .env("OPENRDX_TEST_MISSING_STDIO", missing)
                .output().unwrap();
            assert!(output.status.success(), "missing={missing}, status={}: {}", output.status, String::from_utf8_lossy(&output.stderr));
        }
    }

    /// Self-exec fixture closes only its own stdio and exercises real fd replacement.
    #[test]
    fn stdio_reservation_isolated_child() {
        let close_stderr = match std::env::var("OPENRDX_TEST_MISSING_STDIO").as_deref() {
            Ok("1") => false,
            Ok("all") => true,
            _ => return,
        };
        let directory = tempfile::tempdir().unwrap();
        let evidence_fd = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(evidence_fd >= 3);
        let mut evidence = unsafe { File::from_raw_fd(evidence_fd) };
        let existing_stderr = evidence.metadata().unwrap();
        unsafe { libc::close(0); libc::close(1); }
        if close_stderr {
            unsafe { libc::close(2); }
        }
        let _guards = reserve_missing_standard_descriptors().unwrap();
        let stderr_check_fd = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
        assert!(stderr_check_fd >= 3);
        let retained_stderr = unsafe { File::from_raw_fd(stderr_check_fd) }.metadata().unwrap();
        let present_stream_unchanged = close_stderr || (existing_stderr.dev() == retained_stderr.dev()
            && existing_stderr.ino() == retained_stderr.ino());
        let lease = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.path().join("lease")).unwrap();
        openrdx_macos_local_install::acquire_file_lock(&lease).unwrap();
        let original = lease.metadata().unwrap();
        let (mut ready_parent, mut ready_child) = UnixStream::pair().unwrap();
        let critical_fds_above_stdio = [lease.as_raw_fd(), ready_parent.as_raw_fd(), ready_child.as_raw_fd()]
            .iter().all(|descriptor| *descriptor >= 3);
        let null = File::options().read(true).write(true).open("/dev/null").unwrap();
        for descriptor in [0, 1, 2] {
            assert!(unsafe { libc::dup2(null.as_raw_fd(), descriptor) } >= 0);
        }
        let held = lease.metadata().unwrap();
        let lease_unchanged = held.is_file() && held.dev() == original.dev() && held.ino() == original.ino();
        ready_parent.set_read_timeout(Some(Duration::from_millis(50))).ok();
        let sent = ready_child.write_all(b"Y").is_ok();
        let mut ready = [0];
        let protocol_unchanged = sent && ready_parent.read_exact(&mut ready).is_ok() && ready == [b'Y'];
        writeln!(evidence, "lease_fd={}, above_stdio={critical_fds_above_stdio}, lease_unchanged={lease_unchanged}, protocol_unchanged={protocol_unchanged}, existing_stderr_unchanged={present_stream_unchanged}", lease.as_raw_fd()).unwrap();
        fs::remove_dir_all(directory.path()).unwrap();
        // Exit directly: this isolated fixture intentionally replaced standard
        // descriptor slots, so its test harness must not flush inherited streams.
        unsafe { libc::_exit(if critical_fds_above_stdio && lease_unchanged && protocol_unchanged && present_stream_unchanged { 0 } else { 1 }); }
    }

    /// Foreign files remain refused while the diagnostic identifies retained fd state.
    #[test]
    fn lease_recheck_reports_protected_descriptor_failure_with_metadata() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let file = tempfile::NamedTempFile::new().unwrap();
        let lease = Lease(file.as_file().try_clone().unwrap());
        let error = lease.recheck(file.path().to_str().unwrap()).unwrap_err();
        assert!(error.contains("retained lease protection failed"), "{error}");
        assert!(error.contains(&format!("fd={}", lease.0.as_raw_fd())), "{error}");
        assert!(error.contains("mode/uid/gid/links=Ok("), "{error}");
        assert!(error.contains("foreign-owned"), "{error}");
    }

    /// Darwin accepts inherit nonblocking mode; commit follows content verification.
    #[test]
    fn accepted_transaction_waits_for_commit_after_client_verification() {
        let directory = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(directory.path().join("transaction.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = UnixStream::connect(directory.path().join("transaction.sock")).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        let flags = unsafe { libc::fcntl(accepted.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::O_NONBLOCK, 0, "Darwin accepted socket must reproduce inherited nonblocking mode");
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            client.write_all(b"C").unwrap();
        });
        let admitted = read_commit_message(&mut accepted).unwrap();
        writer.join().unwrap();
        assert!(admitted, "commit was dropped before client verification completed");
    }

    /// Blocking the retained peer still rejects EOF and every non-commit byte.
    #[test]
    fn transaction_commit_read_refuses_closed_or_invalid_client() {
        for bytes in [b"".as_slice(), b"N", b"Y"] {
            let (mut supervisor, mut client) = UnixStream::pair().unwrap();
            supervisor.set_nonblocking(true).unwrap();
            client.write_all(bytes).unwrap();
            if bytes.is_empty() {
                drop(client);
                assert!(!matches!(read_commit_message(&mut supervisor), Ok(true)));
            } else {
                assert!(!read_commit_message(&mut supervisor).unwrap());
            }
        }
    }

    /// The private fork socket must preserve the root supervisor's failure cause.
    #[test]
    fn preparation_response_preserves_bounded_supervisor_failure() {
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        let detail = "daemon ownership changed before quiescence";
        child.write_all(b"N").unwrap();
        child.write_all(&(detail.len() as u16).to_be_bytes()).unwrap();
        child.write_all(detail.as_bytes()).unwrap();
        drop(child);
        let error = read_preparation_result(&mut parent).unwrap_err();
        assert!(error.contains(detail), "{error}");
    }

    /// The existing single-byte success response requires no EOF or extra frame.
    #[test]
    fn preparation_response_keeps_existing_single_byte_success() {
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        parent.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        child.write_all(b"Y").unwrap();
        read_preparation_result(&mut parent).unwrap();
    }

    /// Sender truncation preserves UTF-8 and the exact bounded wire length.
    #[test]
    fn preparation_failure_frame_truncates_at_utf8_boundary() {
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        let detail = format!("{}üextra", "x".repeat(1023));
        write_preparation_failure(&mut child, &detail).unwrap();
        drop(child);
        let mut bytes = Vec::new();
        parent.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes[0], b'N');
        let length = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        assert_eq!(length, 1023);
        assert_eq!(bytes.len(), length + 3);
        assert_eq!(String::from_utf8(bytes[3..].to_vec()).unwrap(), "x".repeat(1023));
    }

    /// Oversized, malformed, incomplete and unknown frames never admit replacement.
    #[test]
    fn preparation_response_refuses_invalid_failure_frames() {
        for bytes in [
            vec![b'N', 4, 1],
            vec![b'N', 0, 1, 0xff],
            vec![b'N', 0, 3, b'x'],
            vec![b'N', 0, 0],
            vec![b'Z'],
            vec![],
        ] {
            let (mut parent, mut child) = UnixStream::pair().unwrap();
            child.write_all(&bytes).unwrap();
            drop(child);
            let error = read_preparation_result(&mut parent).unwrap_err();
            assert!(error.contains("replacement is refused"), "{error}");
        }
    }
}

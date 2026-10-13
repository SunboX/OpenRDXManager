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

pub(super) const HARDWARE_LOCK: &str = "/private/var/run/openrdx-hardware.lock";
pub(super) const INSTALL_LOCK: &str = "/private/var/run/openrdx-local-install.lock";
pub(super) const SUPERVISOR: &str = "/private/var/run/openrdx-local-install.sock";
const LABEL: &str = "system/com.openrdx.hardware.local";
use openrdx_macos_local_install::namespace::{Registration, quiesce_plan, removal_plan};
const MAX_TRANSACTION: Duration = Duration::from_secs(600);
const MAX_PREPARATION_ERROR_BYTES: usize = 1024;

#[cfg(test)]
#[path = "postfork_tests.rs"]
mod postfork_tests;

/// Own one validated kernel flock; releasing the handle releases this exact lease.
pub(super) struct Lease(pub(super) File);

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

    /// Adopt the continuously inherited open-file description; never reopen/reacquire its path.
    pub(super) fn inherited(file: File, path: &str) -> Result<Self, String> {
        let lease = Self(file);
        lease.recheck(path)?;
        // Reassert ownership on this SAME open-file description. A substituted
        // descriptor cannot bypass a busy hardware writer's independent flock.
        openrdx_macos_local_install::acquire_file_lock(&lease.0)?;
        Ok(lease)
    }

    /// Reject namespace replacement while the lease remains retained.
    fn recheck(&self, path: &str) -> Result<(), String> {
        rdx_local_trust::verify_protected_descriptor(&self.0).map_err(|error| {
            // A failed ACL/metadata syscall needs the retained fd and
            // a fresh diagnostic snapshot; neither becomes authorization proof.
            let snapshot = self.0.metadata().map(|metadata| {
                (metadata.mode(), metadata.uid(), metadata.gid(), metadata.nlink())
            });
            format!("retained lease protection failed (fd={}, mode/uid/gid/links={snapshot:?}): {error}", self.0.as_raw_fd())
        })?;
        let opened = self.0.metadata().map_err(|error| {
            format!(
                "cannot inspect retained lease fd={}: {error}",
                self.0.as_raw_fd()
            )
        })?;
        let named = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect lease namespace {path}: {error}"))?;
        openrdx_macos_local_install::validate_lock_evidence(
            named.is_file(),
            named.uid(),
            named.nlink(),
            named.mode(),
        )
        .map_err(|error| format!("named lease protection failed at {path}: {error}"))?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err("installation ownership namespace was replaced".into());
        }
        Ok(())
    }
}

/// Determine whether the fixed launchd label currently exists, never trusting output text.
fn registered_at(registration: Registration) -> Result<bool, String> {
    let output = std::process::Command::new("/bin/launchctl")
        .args(["print", registration.label()])
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

/// Probe only one compiled job and retain its bounded system evidence.
fn registration_evidence(registration: Registration) -> Result<Option<String>, String> {
    if !registered_at(registration)? {
        return Ok(None);
    }
    install::fixed_command("/bin/launchctl", &["print", registration.label()]).map(Some)
}

/// Determine whether the dedicated local job exists; legacy jobs do not occupy it.
fn registered() -> Result<bool, String> {
    registered_at(Registration::Local)
}

/// Refuse foreign fixed targets/new labels, preserving separate legacy signed jobs.
pub(super) fn verify_previous_ownership() -> Result<Vec<Registration>, String> {
    let mut existing = false;
    for path in [APP, HELPER, CLI, DAEMON, ENROLLMENT, PREVIOUS, PENDING] {
        match fs::symlink_metadata(path) {
            Ok(_) => existing = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    // This ownership-only proof is mandatory before a previous local label can
    // be considered for migration. It never authenticates damaged runtime IPC.
    if existing {
        install::verify_owned_targets(true)?;
    }
    let local = registration_evidence(Registration::Local)?;
    let previous = registration_evidence(Registration::Previous)?;
    removal_plan(existing, local.as_deref(), previous.as_deref())
}

/// Stop exact-owned jobs under the shared hardware lease; never stop old foreign jobs.
fn quiesce(loaded: Vec<Registration>) -> Result<(), String> {
    if !loaded.is_empty() {
        install::verify_owned_targets(true)?;
    }
    quiesce_plan(&loaded, registration_evidence, |registration| {
        install::fixed_command("/bin/launchctl", &["bootout", registration.label()]).map(|_| ())
    })
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
    let source = super::package_source::retain_package_source()?;
    let _loaded = verify_previous_ownership()?;
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
            .write_all(source.bytes())
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
    let mut socket = super::supervisor_roles::SocketGuard::capture(Path::new(SUPERVISOR))?;
    socket.restrict_private()?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let (mut parent, child) = UnixStream::pair().map_err(|error| error.to_string())?;
    parent
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    let spawned = super::supervisor_spawn::spawn(
        &source,
        [
            setup.0.as_raw_fd(),
            hardware.0.as_raw_fd(),
            listener.as_raw_fd(),
            child.as_raw_fd(),
        ],
    )?;
    drop(child);
    // The owned child guard survives EVERY frame/root-peer/source/readiness failure.
    // Parent and child overlap the same kernel lease descriptions until verified Y.
    super::supervisor_spawn::confirm(spawned, || {
        if !root_peer(&parent)? {
            return Err("supervisor readiness peer is not root".into());
        }
        socket.send_frame(&mut parent)?;
        read_preparation_result(&mut parent)?;
        source.recheck()
    })?;
    socket.transferred();
    // No explicit LOCK_UN: closing parent copies preserves the child's leases.
    drop(listener);
    drop(setup);
    drop(hardware);
    Ok(())
}

/// Retain only missing standard stream slots before opening leases or private sockets.
/// Present streams remain untouched; the single-threaded prepare entrypoint owns
/// these guards through spawn so initial stream slots cannot become protocol fds.
fn reserve_missing_standard_descriptors() -> Result<Vec<File>, String> {
    let mut retained = Vec::new();
    for descriptor in [0, 1, 2] {
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0 {
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EBADF) {
            return Err(format!(
                "cannot inspect standard stream {descriptor}: {error}"
            ));
        }
        let opened = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if opened < 0 {
            return Err(format!(
                "cannot reserve missing standard stream {descriptor}: {}",
                std::io::Error::last_os_error()
            ));
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

/// Await one private fresh-executable response under the parent's existing timeout.
/// Any malformed or incomplete response refuses privileged payload replacement.
pub(super) fn read_preparation_result(parent: &mut UnixStream) -> Result<(), String> {
    read_supervisor_result(parent, "quiescence", "replacement is refused")
}

/// Read the retained supervisor's registration result under the caller's timeout.
pub(super) fn read_registration_result(channel: &mut UnixStream) -> Result<(), String> {
    read_supervisor_result(
        channel,
        "registration",
        "privileged access remains disabled, rerun the package installer",
    )
}

/// Decode one bounded private supervisor frame; only Y permits the fixed phase.
/// Invalid UTF-8, framing, lengths or transport remain failures with phase guidance.
fn read_supervisor_result(
    channel: &mut UnixStream,
    phase: &str,
    refusal: &str,
) -> Result<(), String> {
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
    channel
        .read_exact(&mut length)
        .map_err(|_| format!("setup supervisor {phase} failure detail is incomplete; {refusal}"))?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_PREPARATION_ERROR_BYTES {
        return Err(format!(
            "setup supervisor {phase} failure detail exceeds its bound; {refusal}"
        ));
    }
    let mut bytes = vec![0; length];
    channel
        .read_exact(&mut bytes)
        .map_err(|_| format!("setup supervisor {phase} failure detail is incomplete; {refusal}"))?;
    let detail = String::from_utf8(bytes)
        .map_err(|_| format!("setup supervisor {phase} failure detail is not UTF-8; {refusal}"))?;
    Err(format!(
        "setup supervisor refused {phase}: {detail}; {refusal}"
    ))
}

/// Send at most 1,024 UTF-8 bytes over a private supervisor channel, never Installer stdio.
/// Retains character boundaries and emits a fixed N/u16-length frame; write failure
/// cannot authorize preparation or registration and the caller closes the channel.
pub(super) fn write_preparation_failure(child: &mut UnixStream, error: &str) -> Result<(), String> {
    let mut length = error.len().min(MAX_PREPARATION_ERROR_BYTES);
    while !error.is_char_boundary(length) {
        length -= 1;
    }
    child.write_all(b"N").map_err(|error| error.to_string())?;
    child
        .write_all(&(length as u16).to_be_bytes())
        .map_err(|error| error.to_string())?;
    child
        .write_all(&error.as_bytes()[..length])
        .map_err(|error| error.to_string())
}

/// Detach, stop only a verified idle generation, revoke it, and await a root commit.
pub(super) fn supervise(
    listener: UnixListener,
    ready: &mut UnixStream,
    setup: Lease,
    hardware: Lease,
    loaded: Vec<Registration>,
    mut socket: super::supervisor_roles::SocketGuard,
    _source: super::package_source::PackageSource,
) -> Result<(), String> {
    hardware
        .recheck(HARDWARE_LOCK)
        .map_err(|error| format!("supervisor hardware lease recheck failed: {error}"))?;
    setup
        .recheck(INSTALL_LOCK)
        .map_err(|error| format!("supervisor setup lease recheck failed: {error}"))?;
    quiesce(loaded).map_err(|error| format!("supervisor service quiescence failed: {error}"))?;
    revoke_enrollment()
        .map_err(|error| format!("supervisor enrollment revocation failed: {error}"))?;
    ready
        .write_all(b"Y")
        .map_err(|error| format!("supervisor readiness confirmation failed: {error}"))?;
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
                    let _ = write_preparation_failure(
                        &mut channel,
                        &format!("new generation was not verified: {error}"),
                    );
                    socket.remove()?;
                    return Err("new generation was not verified".into());
                }
                // Owned previous local jobs are gone, the new generation is fully
                // enrolled and setup ownership remains held through registration.
                drop(hardware);
                let result = bootstrap_owned_registration();
                match &result {
                    Ok(()) => {
                        let _ = channel.write_all(b"Y");
                    }
                    Err(error) => {
                        let _ = write_preparation_failure(&mut channel, error);
                    }
                }
                socket.remove()?;
                drop(setup);
                return result;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(error) => {
                socket.remove()?;
                return Err(error.to_string());
            }
        }
    }
    socket.remove()?;
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
            "foreign registration occupies the dedicated local label during installation"
        };
        return Err(reason.into());
    }
    install::fixed_command("/bin/launchctl", &["bootstrap", "system", DAEMON])?;
    if !registered()? {
        return Err("launchctl bootstrap returned success but the fixed daemon is absent".into());
    }
    let evidence = install::fixed_command("/bin/launchctl", &["print", LABEL])?;
    if !openrdx_macos_local_install::registration_is_owned(&evidence) {
        return Err(
            "registration after bootstrap is foreign or changed at the dedicated local label"
                .into(),
        );
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
pub(super) fn root_peer(channel: &UnixStream) -> Result<bool, String> {
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
    rdx_local_trust::verify_protected_descriptor(&historical)
        .map_err(|error| format!("current enrollment protection check failed: {error}"))?;
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
#[path = "transaction_tests.rs"]
mod tests;

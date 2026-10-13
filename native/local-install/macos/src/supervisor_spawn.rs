// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Collision-safe fresh-executable supervisor transport and owned child cleanup.

use super::package_source::PackageSource;
use std::{
    ffi::{CString, OsStr},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub(super) const ROLES: [i32; 6] = [3, 4, 5, 6, 7, 8];
const STAGING_MIN: i32 = 32;
// Darwin sys/spawn.h: public POSIX_SPAWN_SETSID is absent from libc 0.2.190.
const DARWIN_SPAWN_SETSID: i16 = 0x0400;

/// Reject duplicate, negative or incomplete sources before any descriptor mapping.
fn validate_roles(sources: &[i32]) -> Result<(), String> {
    if sources.len() != ROLES.len()
        || sources.iter().any(|fd| *fd < 0)
        || sources
            .iter()
            .enumerate()
            .any(|(i, fd)| sources[..i].contains(fd))
    {
        return Err("invalid inherited descriptor roles".into());
    }
    Ok(())
}

/// Own only the kernel-returned child; every failure before verified readiness kills/reaps it.
pub(super) struct ChildGuard {
    pid: libc::pid_t,
    armed: bool,
}
impl ChildGuard {
    /// Transfer lifetime responsibility only after a fully checked Y readiness frame.
    pub(super) fn ready(&mut self) {
        self.armed = false;
    }
    /// Poll only this child; ECHILD never authorizes signaling a recycled PID.
    fn exited(&self) -> Result<bool, String> {
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == self.pid {
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            return Ok(false);
        }
        Err(error.to_string())
    }
    /// Bounded termination preserves the operation's original error at the caller.
    fn stop(&self) -> Result<(), String> {
        if self.exited()? {
            return Ok(());
        }
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if self.exited()? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("owned supervisor remains unreaped after bounded cleanup".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for ChildGuard {
    /// All early exits retain cleanup ownership; never target a caller-selected process.
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.stop() {
                eprintln!("secondary supervisor cleanup: {error}");
            }
        }
    }
}

/// Retain fully initialized native spawn actions and attributes for every return path.
struct SpawnPlan {
    actions: libc::posix_spawn_file_actions_t,
    attributes: libc::posix_spawnattr_t,
}
impl SpawnPlan {
    /// Use checked native API return values (these APIs return errno directly).
    fn new() -> Result<Self, String> {
        let mut actions = std::ptr::null_mut();
        checked(unsafe { libc::posix_spawn_file_actions_init(&mut actions) })?;
        let mut attributes = std::ptr::null_mut();
        if let Err(error) = checked(unsafe { libc::posix_spawnattr_init(&mut attributes) }) {
            unsafe {
                libc::posix_spawn_file_actions_destroy(&mut actions);
            }
            return Err(error);
        }
        Ok(Self {
            actions,
            attributes,
        })
    }
}
impl Drop for SpawnPlan {
    /// Destroy native construction state; spawned descriptors are independently owned.
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.actions);
            libc::posix_spawnattr_destroy(&mut self.attributes);
        }
    }
}
/// Preserve each native API's exact original error, without retries.
fn checked(code: i32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(code).to_string())
    }
}

/// Spawn only the retained package executable with the compiled private role.
pub(super) fn spawn(source: &PackageSource, descriptors: [i32; 4]) -> Result<ChildGuard, String> {
    source.recheck()?;
    let [cli, manifest] = source.files();
    let sources = [
        descriptors[0],
        descriptors[1],
        descriptors[2],
        descriptors[3],
        cli.as_raw_fd(),
        manifest.as_raw_fd(),
    ];
    spawn_image(
        source.executable(),
        &[OsStr::new("--internal-supervisor")],
        &sources,
    )
}

/// Build all descriptor/environment/signal actions in the parent, never in a raw fork child.
/// The production caller exclusively supplies its verified executable and fixed role set.
fn spawn_image(
    executable: &Path,
    arguments: &[&OsStr],
    sources: &[i32],
) -> Result<ChildGuard, String> {
    validate_roles(sources)?;
    let path =
        CString::new(executable.as_os_str().as_bytes()).map_err(|_| "invalid executable name")?;
    let mut argv = vec![path.clone()];
    for argument in arguments {
        argv.push(CString::new(argument.as_bytes()).map_err(|_| "invalid fixed spawn argument")?);
    }
    let mut argv_ptrs: Vec<_> = argv.iter().map(|value| value.as_ptr().cast_mut()).collect();
    argv_ptrs.push(std::ptr::null_mut());
    let environment = [c"LANG=C".as_ptr().cast_mut(), std::ptr::null_mut()];
    // Every source is duplicated ABOVE all destinations before dup2 file actions.
    // An original fd may equal any role without destroying another source.
    let mut staged = Vec::new();
    for source in sources {
        let fd = unsafe { libc::fcntl(*source, libc::F_DUPFD_CLOEXEC, STAGING_MIN) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        staged.push(unsafe { File::from_raw_fd(fd) });
    }
    let mut plan = SpawnPlan::new()?;
    for fd in [0, 1, 2] {
        checked(unsafe {
            libc::posix_spawn_file_actions_addopen(
                &mut plan.actions,
                fd,
                c"/dev/null".as_ptr(),
                libc::O_RDWR,
                0,
            )
        })?;
    }
    for (file, destination) in staged.iter().zip(ROLES) {
        checked(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut plan.actions, file.as_raw_fd(), destination)
        })?;
        checked(unsafe {
            libc::posix_spawn_file_actions_addclose(&mut plan.actions, file.as_raw_fd())
        })?;
    }
    let mut mask = unsafe { std::mem::zeroed() };
    let mut defaults = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigfillset(&mut defaults);
        libc::sigdelset(&mut defaults, libc::SIGKILL);
        libc::sigdelset(&mut defaults, libc::SIGSTOP);
    }
    checked(unsafe { libc::posix_spawnattr_setsigmask(&mut plan.attributes, &mask) })?;
    checked(unsafe { libc::posix_spawnattr_setsigdefault(&mut plan.attributes, &defaults) })?;
    checked(unsafe {
        libc::posix_spawnattr_setflags(
            &mut plan.attributes,
            (i32::from(DARWIN_SPAWN_SETSID)
                | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
                | libc::POSIX_SPAWN_SETSIGMASK
                | libc::POSIX_SPAWN_SETSIGDEF) as i16,
        )
    })?;
    let mut pid = 0;
    checked(unsafe {
        libc::posix_spawn(
            &mut pid,
            path.as_ptr(),
            &plan.actions,
            &plan.attributes,
            argv_ptrs.as_ptr(),
            environment.as_ptr(),
        )
    })?;
    if pid <= 0 {
        return Err("spawn did not return an owned supervisor".into());
    }
    Ok(ChildGuard { pid, armed: true })
}

/// Keep actual-child cleanup armed throughout every caller's peer/frame/source/Y check.
pub(super) fn confirm(
    mut child: ChildGuard,
    checks: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    checks()?;
    child.ready();
    Ok(())
}

#[cfg(test)]
#[path = "supervisor_spawn_tests.rs"]
mod tests;

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Explicitly gated diagnostic, excluded from the production CLI build.
//!
//! Proposed review-only package: no payload; root preinstall runs this binary
//! without arguments on the startup volume, then emits its bounded stderr into
//! Installer's log. The package does NOT call the production prepare/install.
//! Review the diagnostic before explicit privileged execution. Never ship
//! this target in the normal app/runtime inventory or LocalTrust directory.
//! Each readonly command has three seconds and 64 KiB of combined output.
//! Fork reads/reap share ten seconds; child-only SIGKILL cleanup adds at most one second.
//! Only existing fixed leases, readonly probes and a private disposable root
//! temp fixture are used. No enrollment/payload/launchd/device action is taken.

#[cfg(target_os = "macos")]
mod bounded_process;

#[cfg(target_os = "macos")]
mod diagnostic {
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::{
                fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
                net::UnixStream,
            },
        },
        path::Path,
        process::Command,
        time::{Duration, Instant},
    };

    const SETUP: &str = "/private/var/run/openrdx-local-install.lock";
    const HARDWARE: &str = "/private/var/run/openrdx-hardware.lock";
    const CURRENT: &str = "/Library/Application Support/OpenRDXManager/LocalTrust/runtime.json";
    const PREVIOUS: &str =
        "/Library/Application Support/OpenRDXManager/LocalTrust/previous-runtime.json";

    /// Retain the identity of the root-private directory created by this invocation.
    struct OwnedDirectory {
        path: std::path::PathBuf,
        original: fs::Metadata,
        held: Option<File>,
    }

    impl OwnedDirectory {
        /// Confirm the created directory's retained descriptor and named identity.
        fn recheck(&self) -> Result<(), String> {
            let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
            if !named.is_dir()
                || named.uid() != 0
                || named.mode() & 0o7777 != 0o700
                || named.dev() != self.original.dev()
                || named.ino() != self.original.ino()
            {
                return Err("temporary directory identity changed; cleanup refused".into());
            }
            if let Some(held) = &self.held {
                let metadata = held.metadata().map_err(|error| error.to_string())?;
                if !metadata.is_dir()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o7777 != 0o700
                    || metadata.dev() != self.original.dev()
                    || metadata.ino() != self.original.ino()
                {
                    return Err("retained temporary directory changed; cleanup refused".into());
                }
                rdx_local_trust::verify_descriptor_acl(held).map_err(|error| error.to_string())?;
            }
            Ok(())
        }
    }

    impl Drop for OwnedDirectory {
        /// Remove only this unchanged empty directory; preserve unknown entries on error.
        fn drop(&mut self) {
            let result = (|| -> Result<(), String> {
                self.recheck()?;
                fs::remove_dir(&self.path).map_err(|error| error.to_string())
            })();
            if let Err(error) = result {
                let _ = writeln!(std::io::stderr(), "secondary diagnostic cleanup: {error}");
            }
        }
    }

    /// A retained temporary inode plus its root-private parent; never follows cleanup paths.
    struct OwnedTemporary {
        file: File,
        file_path: std::path::PathBuf,
        directory: OwnedDirectory,
    }

    impl OwnedTemporary {
        /// Create only the private diagnostic namespace under the root sticky temp directory.
        fn create() -> Result<Self, String> {
            let path = std::path::PathBuf::from(format!(
                "/private/tmp/openrdx-postfork-diagnostic.{}",
                std::process::id()
            ));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|error| error.to_string())?;
            let original = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            let mut directory = OwnedDirectory {
                path,
                original,
                held: None,
            };
            directory.held = Some(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
                    .open(&directory.path)
                    .map_err(|error| error.to_string())?,
            );
            directory.recheck()?;
            let file_path = directory.path.join("lease");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&file_path)
                .map_err(|error| error.to_string())?;
            let temporary = Self {
                file,
                file_path,
                directory,
            };
            recheck(&temporary.file, &temporary.file_path)?;
            openrdx_macos_local_install::acquire_file_lock(&temporary.file)?;
            Ok(temporary)
        }
    }

    impl Drop for OwnedTemporary {
        /// Unlink only the unchanged retained inode; directory cleanup follows automatically.
        fn drop(&mut self) {
            let result = (|| -> Result<(), String> {
                self.directory.recheck()?;
                recheck(&self.file, &self.file_path)?;
                fs::remove_file(&self.file_path).map_err(|error| error.to_string())
            })();
            if let Err(error) = result {
                let _ = writeln!(std::io::stderr(), "secondary diagnostic cleanup: {error}");
            }
        }
    }

    /// Refuse unsafe fixed inodes; never create, unlock, unlink or replace a lease file.
    fn recheck(file: &File, path: &Path) -> Result<(), String> {
        rdx_local_trust::verify_protected_descriptor(file).map_err(|error| error.to_string())?;
        let held = file.metadata().map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        openrdx_macos_local_install::validate_lock_evidence(
            named.is_file(),
            named.uid(),
            named.nlink(),
            named.mode(),
        )?;
        if held.dev() != named.dev() || held.ino() != named.ino() {
            return Err("retained lease namespace changed".into());
        }
        Ok(())
    }

    /// Open and acquire ONLY an existing root-private fixed nonblocking lease.
    fn retain(path: &str) -> Result<File, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| error.to_string())?;
        recheck(&file, Path::new(path))?;
        openrdx_macos_local_install::acquire_file_lock(&file)?;
        recheck(&file, Path::new(path))?;
        Ok(file)
    }

    /// Exercise the same readonly launchctl probes without interpreting them as authority.
    fn readonly_prechecks() -> Result<(), String> {
        let record = rdx_local_trust::verify_enrollment(Path::new(CURRENT), "macos")
            .or_else(|_| rdx_local_trust::read_protected_inventory(Path::new(PREVIOUS), "macos"))
            .map_err(|error| error.to_string())?;
        let required = rdx_local_trust::protected_runtime_handle_requirement(
            Path::new("/Applications/OpenRDXManager.app"),
            &record,
        )
        .map_err(|error| error.to_string())? as libc::rlim_t;
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return Err("cannot inspect diagnostic descriptor capacity".into());
        }
        if required > limit.rlim_max || required > 8192 {
            return Err("diagnostic runtime exceeds its process descriptor budget".into());
        }
        if required > limit.rlim_cur {
            limit.rlim_cur = required;
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                return Err("cannot provision diagnostic-only descriptor capacity".into());
            }
        }
        rdx_local_trust::verify_protected_tree_ownership(
            Path::new("/Applications/OpenRDXManager.app"),
            &record,
        )
        .map_err(|error| error.to_string())?;
        eprintln!("readonly historical tree ownership passed");
        for label in [
            "system/com.openrdx.hardware.local",
            "system/com.openrdx.hardware",
        ] {
            let status = super::bounded_process::capture(
                Command::new("/bin/launchctl")
                    .args(["print", label])
                    .env_clear(),
                Instant::now() + Duration::from_secs(3),
                65536,
            )?;
            eprintln!("readonly {label} exit={:?}", status.code());
            if !status.success() && status.code() != Some(113) {
                return Err("readonly launchctl probe failed".into());
            }
        }
        Ok(())
    }

    /// Write bounded stage/metadata and the original shared-verifier syscall diagnostic.
    fn stage(output: &mut impl Write, name: &str, files: &[(&File, &Path)]) -> Result<(), String> {
        let mut first_failure = None;
        for (file, path) in files {
            let evidence = file.metadata().map(|metadata| {
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mode(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.nlink(),
                )
            });
            let result = recheck(file, path);
            writeln!(
                output,
                "{name} fd={} dev/ino/mode/uid/gid/links={evidence:?} verdict={result:?}",
                file.as_raw_fd()
            )
            .map_err(|error| error.to_string())?;
            if let Err(error) = result {
                first_failure.get_or_insert(error);
            }
        }
        first_failure.map_or(Ok(()), Err)
    }

    /// Perform one bounded detached fork, retaining both production leases throughout.
    pub(super) fn run() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 || std::env::args_os().count() != 1 {
            return Err("diagnostic requires root and accepts no arguments".into());
        }
        for fd in [0, 1, 2] {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                // This diagnostic refuses missing stdio rather than allocating
                // an unretained stream slot that could alias a critical handle.
                return Err("diagnostic requires all standard descriptors to be present".into());
            }
        }
        let setup = retain(SETUP)?;
        let hardware = retain(HARDWARE)?;
        readonly_prechecks()?;
        let temporary = OwnedTemporary::create()?;
        let files = [
            (&hardware, Path::new(HARDWARE)),
            (&setup, Path::new(SETUP)),
            (&temporary.file, temporary.file_path.as_path()),
        ];
        stage(&mut std::io::stderr(), "beforefork", &files)?;
        let (mut parent, mut child) = UnixStream::pair().map_err(|error| error.to_string())?;
        parent
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err("diagnostic fork failed".into());
        }
        if pid == 0 {
            drop(parent);
            let result = (|| -> Result<(), String> {
                stage(&mut child, "afterfork", &files)?;
                if unsafe { libc::setsid() } < 0 {
                    return Err("diagnostic setsid failed".into());
                }
                stage(&mut child, "aftersetsid", &files)?;
                let null = File::options()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .map_err(|error| error.to_string())?;
                for fd in [0, 1, 2] {
                    if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
                        return Err("diagnostic stream detachment failed".into());
                    }
                }
                stage(&mut child, "afterdup2", &files)
            })();
            let _ = writeln!(child, "result={result:?}");
            unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
        }
        drop(child);
        let mut evidence = Vec::new();
        let received = (|| -> Result<(), String> {
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("diagnostic read deadline expired".into());
                }
                parent
                    .set_read_timeout(Some(remaining))
                    .map_err(|error| error.to_string())?;
                let mut bytes = [0; 4096];
                let count = parent.read(&mut bytes).map_err(|error| error.to_string())?;
                if count == 0 {
                    return Ok(());
                }
                if evidence.len().saturating_add(count) > 16384 {
                    return Err("diagnostic evidence exceeds bound".into());
                }
                evidence.extend_from_slice(&bytes[..count]);
            }
        })();
        eprintln!("{}", String::from_utf8_lossy(&evidence));
        if let Err(error) = &received {
            eprintln!("diagnostic evidence read failed: {error}");
        }
        let reaped = if received.is_err() {
            super::bounded_process::stop_fork(pid)
        } else {
            super::bounded_process::reap_fork(pid, deadline)
        };
        let status = match reaped {
            Ok(status) => status,
            Err(error) => {
                if let Err(original) = received {
                    eprintln!("secondary diagnostic child cleanup: {error}");
                    return Err(original);
                }
                return Err(error);
            }
        };
        received?;
        recheck(&hardware, Path::new(HARDWARE))?;
        recheck(&setup, Path::new(SETUP))?;
        recheck(&temporary.file, &temporary.file_path)?;
        if status != 0 {
            return Err("postfork diagnostic failed; original stage evidence above; no setup changes were made".into());
        }
        Ok(())
    }
}

/// Dispatch only the separate platform diagnostic; never production installation actions.
fn main() {
    #[cfg(target_os = "macos")]
    let result = diagnostic::run();
    #[cfg(not(target_os = "macos"))]
    let result: Result<(), String> = Err("diagnostic requires macOS".into());
    if let Err(error) = result {
        eprintln!("OpenRDX postfork diagnostic refused: {error}");
        std::process::exit(1);
    }
}

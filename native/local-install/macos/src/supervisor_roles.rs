// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed private root entry and fresh verification of inherited supervisor roles.

use super::{
    package_source::{PackageSource, retain_package_source},
    supervisor_spawn::ROLES,
    transaction::{self, HARDWARE_LOCK, INSTALL_LOCK, Lease, SUPERVISOR},
};
use std::{
    fs::{self, File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};

const FRAME: &[u8; 4] = b"RDX1";

/// Private mode is fixed, administrator-only and never accepts descriptor/path arguments.
pub(super) fn validate_entry(arguments: &[String], uid: u32) -> Result<(), String> {
    if uid != 0 || arguments != ["--internal-supervisor"] {
        return Err("invalid administrator-only supervisor entry".into());
    }
    Ok(())
}

/// Keep one exact named socket until success transfers namespace cleanup to the child.
pub(super) struct SocketGuard {
    path: PathBuf,
    original: Metadata,
    armed: bool,
}
impl SocketGuard {
    /// Capture only the socket just created by this process; no generic deletion authority.
    pub(super) fn capture(path: &Path) -> Result<Self, String> {
        let original = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !original.file_type().is_socket() {
            return Err("supervisor namespace is not a socket".into());
        }
        Ok(Self {
            path: path.into(),
            original,
            armed: true,
        })
    }
    /// Restrict the socket just bound, retaining cleanup authority on its exact inode.
    pub(super) fn restrict_private(&mut self) -> Result<(), String> {
        self.recheck()?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        if !named.file_type().is_socket()
            || named.dev() != self.original.dev()
            || named.ino() != self.original.ino()
            || named.uid() != self.original.uid()
            || named.gid() != self.original.gid()
            || named.mode() & 0o7777 != 0o600
        {
            return Err("supervisor socket changed during private restriction".into());
        }
        self.original = named;
        Ok(())
    }

    /// Confirm exact retained inode, owner and type before every unlink.
    fn recheck(&self) -> Result<(), String> {
        let named = fs::symlink_metadata(&self.path).map_err(|error| error.to_string())?;
        if !named.file_type().is_socket()
            || named.dev() != self.original.dev()
            || named.ino() != self.original.ino()
            || named.uid() != self.original.uid()
            || named.gid() != self.original.gid()
        {
            return Err("owned supervisor socket namespace was replaced".into());
        }
        Ok(())
    }
    /// Explicit cleanup can report namespace failure without deleting replacements.
    pub(super) fn remove(&mut self) -> Result<(), String> {
        self.recheck()?;
        fs::remove_file(&self.path).map_err(|error| error.to_string())?;
        self.armed = false;
        Ok(())
    }
    /// Transfer cleanup responsibility only after verified readiness from this child.
    pub(super) fn transferred(&mut self) {
        self.armed = false;
    }
    /// Send a bounded version frame binding the child to our exact protected socket inode.
    pub(super) fn send_frame(&self, channel: &mut UnixStream) -> Result<(), String> {
        self.recheck()?;
        channel
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::from(FRAME.as_slice());
        bytes.extend(self.original.dev().to_be_bytes());
        bytes.extend(self.original.ino().to_be_bytes());
        channel.write_all(&bytes).map_err(|error| error.to_string())
    }
}
impl Drop for SocketGuard {
    /// Best effort exact-inode cleanup never masks the primary transaction failure.
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.remove() {
                eprintln!("secondary supervisor socket cleanup: {error}");
            }
        }
    }
}

/// Validate kernel socket roles rather than assuming a descriptor number proves its purpose.
fn socket_role(fd: i32, listening: bool) -> Result<(), String> {
    let mut kind = 0;
    let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut i32).cast(),
            &mut size,
        )
    } < 0
        || kind != libc::SOCK_STREAM
    {
        return Err("inherited role is not a stream socket".into());
    }
    if listening {
        // Darwin AF_UNIX rejects SO_ACCEPTCONN with ENOPROTOOPT. A strictly
        // nonblocking accept proves a live listener, without any service action.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || flags & libc::O_NONBLOCK == 0 {
            return Err("listener role must be nonblocking".into());
        }
        let accepted = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if accepted >= 0 {
            unsafe {
                libc::close(accepted);
            }
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(format!(
                    "inherited socket is not a listening stream: {error}"
                ));
            }
        }
    } else {
        let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getpeername(
                fd,
                (&mut address as *mut libc::sockaddr_storage).cast(),
                &mut size,
            )
        } < 0
        {
            return Err("readiness stream is not connected".into());
        }
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } < 0
        || address.ss_family as i32 != libc::AF_UNIX
    {
        return Err("inherited socket is not local AF_UNIX".into());
    }
    Ok(())
}

/// Reject missing/incompatible roles and restore CLOEXEC before any child subprocess.
pub(super) fn retain_roles() -> Result<Vec<File>, String> {
    let mut retained = Vec::new();
    for fd in ROLES {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err("inherited supervisor role unavailable".into());
        }
        retained.push(unsafe { File::from_raw_fd(fd) });
    }
    for (index, file) in retained.iter().enumerate() {
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if matches!(index, 0 | 1 | 4 | 5) {
            let expected = if index < 2 {
                libc::O_RDWR
            } else {
                libc::O_RDONLY
            };
            if !metadata.is_file() || flags < 0 || flags & libc::O_ACCMODE != expected {
                return Err("inherited file role has wrong type or access".into());
            }
        } else {
            socket_role(file.as_raw_fd(), index == 2)?;
        }
    }
    Ok(retained)
}

/// Decode only the fixed bounded frame; no paths, actions, trust roots or PIDs travel here.
pub(super) fn receive_frame(channel: &mut UnixStream) -> Result<(u64, u64), String> {
    channel
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    let mut bytes = [0; 20];
    channel
        .read_exact(&mut bytes)
        .map_err(|error| format!("supervisor launch frame incomplete: {error}"))?;
    if &bytes[..4] != FRAME {
        return Err("supervisor launch frame version refused".into());
    }
    Ok((
        u64::from_be_bytes(bytes[4..12].try_into().expect("fixed frame")),
        u64::from_be_bytes(bytes[12..20].try_into().expect("fixed frame")),
    ))
}

/// Fresh-image admission retains all inherited handles and proves every fixed role before actions.
fn admit(
    roles: Vec<File>,
    ready: &mut UnixStream,
) -> Result<(UnixListener, Lease, Lease, PackageSource, SocketGuard), String> {
    if !transaction::root_peer(ready)?
        || !ready
            .local_addr()
            .map_err(|error| error.to_string())?
            .is_unnamed()
        || !ready
            .peer_addr()
            .map_err(|error| error.to_string())?
            .is_unnamed()
    {
        return Err("supervisor readiness channel is not a private root peer".into());
    }
    let (dev, ino) = receive_frame(ready)?;
    let mut roles = roles.into_iter();
    let setup = Lease::inherited(roles.next().expect("fixed setup role"), INSTALL_LOCK)?;
    let hardware = Lease::inherited(roles.next().expect("fixed hardware role"), HARDWARE_LOCK)?;
    let listener = unsafe {
        UnixListener::from_raw_fd(roles.next().expect("fixed listener role").into_raw_fd())
    };
    let mut source = retain_package_source()?;
    let cli = roles.next().expect("fixed CLI role");
    let manifest = roles.next().expect("fixed inventory role");
    source.retain_inherited(cli, manifest)?;
    if listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .as_pathname()
        != Some(Path::new(SUPERVISOR))
    {
        return Err("supervisor listener has a foreign fixed namespace".into());
    }
    let socket = SocketGuard::capture(Path::new(SUPERVISOR))?;
    if socket.original.uid() != 0
        || socket.original.mode() & 0o7777 != 0o600
        || socket.original.dev() != dev
        || socket.original.ino() != ino
    {
        // Refused namespaces are never cleanup authority.
        let mut socket = socket;
        socket.transferred();
        return Err("supervisor listener namespace proof failed".into());
    }
    socket.recheck()?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    Ok((listener, setup, hardware, source, socket))
}

/// Exact private entry: all library/verifier work executes after posix_spawn's fresh exec.
pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    validate_entry(arguments, unsafe { libc::geteuid() })?;
    // Keep a verified private ready-channel description independently, so malformed
    // later roles still return their original refusal over this legitimate channel.
    socket_role(6, false)?;
    let copied = unsafe { libc::fcntl(6, libc::F_DUPFD_CLOEXEC, 32) };
    if copied < 0 {
        return Err("private readiness role unavailable".into());
    }
    let mut ready = unsafe { UnixStream::from_raw_fd(copied) };
    if !transaction::root_peer(&ready)?
        || !ready
            .local_addr()
            .map_err(|error| error.to_string())?
            .is_unnamed()
        || !ready
            .peer_addr()
            .map_err(|error| error.to_string())?
            .is_unnamed()
    {
        return Err("supervisor readiness channel is not a private root peer".into());
    }
    let retained = retain_roles().map(|mut roles| {
        drop(roles.remove(3));
        roles
    });
    let result = retained
        .and_then(|roles| admit(roles, &mut ready))
        .and_then(|(listener, setup, hardware, source, socket)| {
            let loaded = transaction::verify_previous_ownership()?;
            source.recheck()?;
            transaction::supervise(
                listener, &mut ready, setup, hardware, loaded, socket, source,
            )
        });
    if let Err(error) = &result {
        // Never send diagnostics to an unverified foreign peer.
        if transaction::root_peer(&ready).unwrap_or(false) {
            let _ = transaction::write_preparation_failure(&mut ready, error);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Private entry never accepts user authority, additional arguments or role selection.
    #[test]
    fn rejects_nonroot_and_caller_selected_private_arguments() {
        assert!(validate_entry(&["--internal-supervisor".into()], 0).is_ok());
        assert!(validate_entry(&["--internal-supervisor".into()], 502).is_err());
        assert!(validate_entry(&["--internal-supervisor".into(), "3".into()], 0).is_err());
        assert!(validate_entry(&["prepare".into()], 0).is_err());
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    /// Actual file/socket substitutions are refused before any transaction action.
    #[test]
    fn socket_roles_refuse_regular_datagram_connected_and_unlistened_substitutes() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(socket_role(file.as_raw_fd(), true).is_err());
        let datagram = std::os::unix::net::UnixDatagram::unbound().unwrap();
        assert!(socket_role(datagram.as_raw_fd(), false).is_err());
        let (stream, _peer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        assert!(socket_role(stream.as_raw_fd(), true).is_err());
        assert!(socket_role(stream.as_raw_fd(), false).is_ok());
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("listen")).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(socket_role(listener.as_raw_fd(), true).is_ok());
        assert!(socket_role(listener.as_raw_fd(), false).is_err());
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        let unlistened = unsafe { File::from_raw_fd(fd) };
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        assert!(socket_role(unlistened.as_raw_fd(), true).is_err());
    }

    /// Truncated and wrong-version launch frames preserve their original bounded denial.
    #[test]
    fn launch_frame_rejects_truncated_and_foreign_versions() {
        for bytes in [&b"RDX1"[..], &[0; 20][..]] {
            let (mut parent, mut child) = UnixStream::pair().unwrap();
            parent.write_all(bytes).unwrap();
            drop(parent);
            assert!(receive_frame(&mut child).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("socket");
        let _listener = UnixListener::bind(&path).unwrap();
        let guard = SocketGuard::capture(&path).unwrap();
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        guard.send_frame(&mut parent).unwrap();
        assert_eq!(
            receive_frame(&mut child).unwrap(),
            (guard.original.dev(), guard.original.ino())
        );
    }

    /// Failure cleanup removes only our captured socket, preserving substituted inodes.
    #[test]
    fn socket_cleanup_is_exact_and_preserves_replacements() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("socket");
        let first = UnixListener::bind(&path).unwrap();
        let guard = SocketGuard::capture(&path).unwrap();
        drop(guard);
        assert!(!path.exists());
        drop(first);
        let original = UnixListener::bind(&path).unwrap();
        let mut guard = SocketGuard::capture(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        assert!(guard.remove().is_err());
        drop(guard);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        drop(original);
        drop(replacement);
    }
}

use super::*;

/// A launch plan must not alias another source when mapping the fixed roles.
#[test]
fn rejects_duplicate_or_incomplete_descriptor_roles() {
    assert!(validate_roles(&[3, 4, 5, 6, 7, 8]).is_ok());
    assert!(validate_roles(&[3, 3, 5, 6, 7, 8]).is_err());
    assert!(validate_roles(&[3, 4, 5, 6, 7]).is_err());
    assert!(validate_roles(&[-1, 4, 5, 6, 7, 8]).is_err());
}

use std::{
    io::{Read, Write},
    os::{
        fd::IntoRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    process::Command,
};

/// Ordinary isolated transport fixture; no installed paths, registration or root mutation.
#[test]
fn fresh_exec_preserves_colliding_roles_and_kernel_lease() {
    run_fixture("continuity");
}

/// Every early peer/frame/Y failure retains actual kernel child cleanup ownership.
#[test]
fn failed_handoffs_reap_actual_child_and_preserve_original_error() {
    for case in ["peer", "frame", "readiness", "source"] {
        run_fixture(case);
    }
}

/// Invoke the fixture under one test thread so deliberate fd remaps affect no other test.
fn run_fixture(case: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "supervisor_spawn::tests::spawn_fixture",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("OPENRDX_SPAWN_FIXTURE", case)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{case}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Collision source fixture executes only in its explicitly isolated ordinary test process.
#[test]
fn spawn_fixture() {
    let Ok(case) = std::env::var("OPENRDX_SPAWN_FIXTURE") else {
        return;
    };
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "transport fixture refuses root"
    );
    let dir = tempfile::tempdir().unwrap();
    let open = |name: &str| {
        File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join(name))
            .unwrap()
    };
    let setup = open("setup");
    let hardware = open("hardware");
    openrdx_macos_local_install::acquire_file_lock(&setup).unwrap();
    openrdx_macos_local_install::acquire_file_lock(&hardware).unwrap();
    let listener = UnixListener::bind(dir.path().join("socket")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (parent_original, child) = UnixStream::pair().unwrap();
    let stock = File::open("/usr/bin/true").unwrap();
    let inventory = open("inventory");
    drop(inventory);
    let inventory = File::open(dir.path().join("inventory")).unwrap();
    let fd = unsafe { libc::fcntl(parent_original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 128) };
    assert!(fd >= 128);
    let mut parent = unsafe { UnixStream::from_raw_fd(fd) };
    drop(parent_original);
    parent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let files = [
        setup.as_raw_fd(),
        hardware.as_raw_fd(),
        listener.as_raw_fd(),
        child.as_raw_fd(),
        stock.as_raw_fd(),
        inventory.as_raw_fd(),
    ];
    let mut staged = Vec::new();
    let mut evidence = Vec::new();
    for original in files {
        let copied = unsafe { libc::fcntl(original, libc::F_DUPFD_CLOEXEC, 32) };
        assert!(copied >= 32);
        let copied = unsafe { File::from_raw_fd(copied) };
        let meta = copied.metadata().unwrap();
        evidence.extend(meta.dev().to_be_bytes());
        evidence.extend(meta.ino().to_be_bytes());
        staged.push(copied);
    }
    drop(setup);
    drop(hardware);
    drop(listener);
    drop(child);
    drop(stock);
    drop(inventory);
    // Reverse every destination pair: naïve sequential dup2 destroys later sources.
    let collision_sources = [4, 3, 6, 5, 8, 7];
    let mut mapped = Vec::new();
    for (file, fd) in staged.iter().zip(collision_sources) {
        assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), fd) }, fd);
        mapped.push(unsafe { File::from_raw_fd(fd) });
    }
    drop(staged);
    let leak = File::open("/usr/bin/true").unwrap();
    let leakfd = unsafe { libc::fcntl(leak.as_raw_fd(), libc::F_DUPFD, 200) };
    assert_eq!(leakfd, 200);
    let _leak = unsafe { File::from_raw_fd(leakfd) };
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
    }
    let mut mask = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
    }
    let child = spawn_image(
        &std::env::current_exe().unwrap(),
        &[
            OsStr::new("--exact"),
            OsStr::new("supervisor_spawn::tests::fresh_exec_child"),
            OsStr::new("--test-threads=1"),
        ],
        &collision_sources,
    )
    .unwrap();
    let pid = child.pid;
    drop(mapped); // Child now holds the only lease descriptions.
    let contender = File::options()
        .read(true)
        .write(true)
        .open(dir.path().join("hardware"))
        .unwrap();
    assert!(openrdx_macos_local_install::acquire_file_lock(&contender).is_err());
    parent.write_all(&evidence).unwrap();
    parent
        .write_all(match case.as_str() {
            "continuity" => b"Y",
            "frame" => b"F",
            _ => b"X",
        })
        .unwrap();
    let started = Instant::now();
    if case == "continuity" {
        super::confirm(child, || {
            super::super::transaction::read_preparation_result(&mut parent)
        })
        .unwrap();
        assert!(openrdx_macos_local_install::acquire_file_lock(&contender).is_err());
        parent.write_all(b"R").unwrap();
        let guard = ChildGuard { pid, armed: false };
        while !guard.exited().unwrap() {
            assert!(started.elapsed() < Duration::from_secs(1));
            thread::sleep(Duration::from_millis(5));
        }
    } else {
        let expected = match case.as_str() {
            "peer" => "supervisor readiness peer is not root",
            "frame" => "supervisor launch frame version refused",
            "source" => "package source replaced",
            _ => "setup supervisor refused quiescence; replacement is refused",
        };
        let error = super::confirm(child, || match case.as_str() {
            "peer" => {
                if super::super::transaction::root_peer(&parent)? {
                    Ok(())
                } else {
                    Err(expected.into())
                }
            }
            "frame" => super::super::supervisor_roles::receive_frame(&mut parent).map(|_| ()),
            "source" => Err(expected.into()),
            _ => super::super::transaction::read_preparation_result(&mut parent),
        })
        .unwrap_err();
        assert_eq!(error, expected);
        assert!(started.elapsed() < Duration::from_millis(500));
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        openrdx_macos_local_install::acquire_file_lock(&contender).unwrap();
    }
}

/// Real fresh-image worker checks inherited inodes, ACLs, environment, signal state and flock.
#[test]
fn fresh_exec_child() {
    if !std::env::args().any(|arg| arg == "supervisor_spawn::tests::fresh_exec_child") {
        return;
    }
    let cloned = unsafe { libc::fcntl(6, libc::F_DUPFD_CLOEXEC, 32) };
    assert!(cloned >= 32);
    let mut report = unsafe { UnixStream::from_raw_fd(cloned) };
    if let Err(panic) = std::panic::catch_unwind(fresh_exec_worker) {
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("worker panic");
        let _ = super::super::transaction::write_preparation_failure(&mut report, message);
        panic!("{message}");
    }
}

/// Exercise actual kernel transport in the child, forwarding the first test error privately.
fn fresh_exec_worker() {
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let mut roles = super::super::supervisor_roles::retain_roles().unwrap();
    let mut ready = unsafe { UnixStream::from_raw_fd(roles.remove(3).into_raw_fd()) };
    let mut evidence = [0; 96];
    ready.read_exact(&mut evidence).unwrap();
    for (index, fd) in ROLES.into_iter().enumerate() {
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        if fd == 6 {
            continue;
        }
        let file = roles.iter().find(|file| file.as_raw_fd() == fd).unwrap();
        let meta = file.metadata().unwrap();
        assert_eq!(
            meta.dev(),
            u64::from_be_bytes(evidence[index * 16..index * 16 + 8].try_into().unwrap())
        );
        assert_eq!(
            meta.ino(),
            u64::from_be_bytes(
                evidence[index * 16 + 8..index * 16 + 16]
                    .try_into()
                    .unwrap()
            )
        );
        if meta.is_file() {
            rdx_local_trust::verify_descriptor_acl(file).unwrap();
        }
    }
    assert_eq!(unsafe { libc::fcntl(200, libc::F_GETFD) }, -1);
    assert_eq!(
        std::env::vars().collect::<Vec<_>>(),
        vec![("LANG".into(), "C".into())]
    );
    let mut mask = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigprocmask(0, std::ptr::null(), &mut mask);
    }
    assert_eq!(unsafe { libc::sigismember(&mask, libc::SIGUSR1) }, 0);
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut action);
    }
    assert_eq!(action.sa_sigaction, libc::SIG_DFL);
    assert_eq!(unsafe { libc::getsid(0) }, unsafe { libc::getpid() });
    openrdx_macos_local_install::acquire_file_lock(&roles[0]).unwrap();
    openrdx_macos_local_install::acquire_file_lock(&roles[1]).unwrap();
    let null = File::open("/dev/null").unwrap().metadata().unwrap();
    for fd in [0, 1, 2] {
        let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 32) };
        assert!(copy >= 32);
        let stdio = unsafe { File::from_raw_fd(copy) }.metadata().unwrap();
        assert_eq!((stdio.dev(), stdio.ino()), (null.dev(), null.ino()));
    }
    let mut result = [0];
    ready.read_exact(&mut result).unwrap();
    if result == [b'F'] {
        ready.write_all(&[0; 20]).unwrap();
    } else {
        ready.write_all(&result).unwrap();
    }
    ready
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    ready.read_exact(&mut result).unwrap();
    assert_eq!(result, [b'R']);
}

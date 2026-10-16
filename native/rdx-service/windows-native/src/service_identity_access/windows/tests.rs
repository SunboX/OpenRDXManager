// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native mutations run only in a bounded isolated child with a distinct primary token.

use super::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_DEFAULT_DACL, TOKEN_STATISTICS, TokenDefaultDacl, TokenStatistics,
};
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

const CHILD: &str = "service_identity_access::windows::tests::owned_child_grants_query_only";
const PARENT_TOKEN: &str = "OPENRDX_IDENTITY_FIXTURE_PARENT_TOKEN";

/// Reads a fixed-size native token ID privately, never including user/service identities.
fn token_id(objects: &OwnObjects) -> (u32, i32) {
    let mut statistics = TOKEN_STATISTICS::default();
    let mut returned = 0;
    // SAFETY: statistics is aligned initialized storage of exactly the advertised length.
    unsafe {
        GetTokenInformation(
            objects
                .token
                .expect("fixture owns its primary-token handle"),
            TokenStatistics,
            Some((&raw mut statistics).cast()),
            std::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut returned,
        )
    }
    .unwrap();
    assert_eq!(returned as usize, std::mem::size_of::<TOKEN_STATISTICS>());
    (statistics.TokenId.LowPart, statistics.TokenId.HighPart)
}

/// Copies only bounded ACL bytes from TokenDefaultDacl, retaining aligned query storage.
fn default_dacl(objects: &OwnObjects) -> Vec<u8> {
    let mut needed = 0;
    // SAFETY: no buffer is supplied for the documented bounded-size query.
    assert!(
        unsafe {
            GetTokenInformation(
                objects
                    .token
                    .expect("fixture owns its primary-token handle"),
                TokenDefaultDacl,
                None,
                0,
                &mut needed,
            )
        }
        .is_err()
    );
    assert!((std::mem::size_of::<TOKEN_DEFAULT_DACL>()..=65_536).contains(&(needed as usize)));
    let mut storage = vec![0_usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let capacity = needed;
    // SAFETY: storage is suitably aligned and covers the advertised initialized capacity.
    unsafe {
        GetTokenInformation(
            objects
                .token
                .expect("fixture owns its primary-token handle"),
            TokenDefaultDacl,
            Some(storage.as_mut_ptr().cast()),
            capacity,
            &mut needed,
        )
    }
    .unwrap();
    assert!(needed <= capacity);
    // SAFETY: successful query initialized at least the fixed TOKEN_DEFAULT_DACL header.
    let pointer = unsafe { (*storage.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl };
    if pointer.is_null() {
        return Vec::new();
    }
    let begin = storage.as_ptr() as usize;
    let address = pointer as usize;
    assert!(address >= begin && address + std::mem::size_of::<ACL>() <= begin + needed as usize);
    // SAFETY: the fixed ACL header lies inside initialized aligned query storage.
    let length = unsafe { (*pointer).AclSize } as usize;
    assert!(length >= 8 && address + length <= begin + needed as usize);
    // SAFETY: complete ACL bytes are bounded by successful query storage retained above.
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) }.to_vec()
}

/// Runs the mutating fixture in another process, with a bounded wait and no shared test mutation.
#[test]
fn service_identity_query_access_native_owned_child() {
    assert_eq!(
        Object::Process.query_mask(),
        PROCESS_QUERY_LIMITED_INFORMATION.0
    );
    assert_eq!(Object::PrimaryToken.query_mask(), TOKEN_QUERY.0);
    let parent = OwnObjects::open().unwrap();
    let id = token_id(&parent);
    let before_process = parent.read(Object::Process).unwrap();
    let before_token = parent.read(Object::PrimaryToken).unwrap();
    let before_default = default_dacl(&parent);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            CHILD,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(PARENT_TOKEN, format!("{},{}", id.0, id.1))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "isolated identity-query fixture failed");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("isolated identity-query fixture exceeded its bounded wait");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(parent.read(Object::Process).unwrap() == before_process);
    assert!(parent.read(Object::PrimaryToken).unwrap() == before_token);
    assert!(
        default_dacl(&parent) == before_default,
        "parent default token DACL changed"
    );
}

/// Changes only this dedicated child's process/token objects after proving token separation.
#[test]
#[ignore = "invoked only by the bounded parent fixture with token-separation proof"]
fn owned_child_grants_query_only() {
    let parent = std::env::var(PARENT_TOKEN).expect("isolated parent fixture required");
    let objects = OwnObjects::open().unwrap();
    let id = token_id(&objects);
    assert!(
        parent != format!("{},{}", id.0, id.1),
        "refusing to mutate a shared primary token"
    );
    let before_default = default_dacl(&objects);
    let process = objects
        .read(Object::Process)
        .unwrap()
        .with_query_access(Object::Process)
        .unwrap();
    let token = objects
        .read(Object::PrimaryToken)
        .unwrap()
        .with_query_access(Object::PrimaryToken)
        .unwrap();
    grant_query_access(&objects).unwrap();
    assert!(objects.read(Object::Process).unwrap() == process);
    assert!(objects.read(Object::PrimaryToken).unwrap() == token);
    assert!(
        default_dacl(&objects) == before_default,
        "child default token DACL changed"
    );
    // Reverse admission is process-only, even though this test separately retains
    // a read/security handle for proving that token metadata stayed unchanged.
    let before_token = objects.read(Object::PrimaryToken).unwrap();
    // This isolated ACL fixture must also run before service installation in CI.
    // The installed account lookup is verified separately on the real installation.
    let sid = crate::service_identity_access::manager_tests::service_sid();
    let expected = objects
        .read(Object::Process)
        .unwrap()
        .with_manager_query_access(&sid)
        .unwrap();
    crate::service_identity_access::grant_manager_query_access(&OwnObjects::process_only(), &sid)
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let sid = &sid;
            scope.spawn(move || {
                for _ in 0..8 {
                    crate::service_identity_access::grant_manager_query_access(
                        &OwnObjects::process_only(),
                        sid,
                    )
                    .unwrap();
                }
            });
        }
    });
    assert!(objects.read(Object::Process).unwrap() == expected);
    assert!(objects.read(Object::PrimaryToken).unwrap() == before_token);
    assert!(
        default_dacl(&objects) == before_default,
        "reverse grant changed the default token DACL"
    );
}

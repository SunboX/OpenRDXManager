// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// The target translation contains exactly the five reviewed SG flags.
#[test]
fn sg_open_flag_translation_is_exact() {
    assert_eq!(
        sg_open_flags(),
        libc::O_RDWR | libc::O_EXCL | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
    );
}

/// Two independently enumerated authorities for one exact SG instance
/// demonstrate that reopening remains exclusive and does not consume recipes.
#[test]
#[ignore = "requires OPENRDX_TEST_SG_TOKEN and a dedicated Linux SG device"]
fn exclusive_sg_open_contention_reports_busy() {
    let token = std::env::var("OPENRDX_TEST_SG_TOKEN")
        .expect("set exact enumerated token, for example linux-sg-2");
    let first = enumerate_scsi_generic_candidates()
        .expect("first bounded enumeration")
        .into_iter()
        .find(|candidate| candidate.token() == token)
        .expect("selected first candidate");
    let second = enumerate_scsi_generic_candidates()
        .expect("second bounded enumeration")
        .into_iter()
        .find(|candidate| candidate.token() == token)
        .expect("selected second candidate");

    let lease = NativeDevice::open(&first).expect("first exclusive lease");
    assert!(matches!(NativeDevice::open(&first), Err(NativeError::Busy)));
    assert!(matches!(
        NativeDevice::open(&second),
        Err(NativeError::Busy)
    ));
    drop(lease);
    let _reopened = NativeDevice::open(&first).expect("same retained recipe after lease close");
}

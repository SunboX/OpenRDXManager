// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Namespace mount roots remain in the complete mount safety inventory.

use super::*;

/// A Snap namespace mount does not prevent exact RDX mounted-volume selection.
#[test]
fn mountinfo_keeps_nsfs_roots_without_hiding_rdx_mounts() {
    let records = parse_mountinfo(
        b"34 1 8:2 / / rw - ext4 /dev/sda2 rw\n\
          42 34 0:4 mnt:[4026532537] /run/snapd/ns/browser.mnt rw - nsfs nsfs rw\n\
          43 34 8:17 / /media/rdx rw - exfat /dev/sdb1 rw\n",
    )
    .expect("complete inventory with a kernel namespace root");
    assert_eq!(records.len(), 3, "namespace records must not be discarded");
    assert_eq!(records[1].root(), b"mnt:[4026532537]");
    let selected =
        canonical_mounts_for_devices(&records, &BTreeSet::from([DeviceNumber::new(8, 17)]))
            .expect("exact RDX mounted-volume set");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].mount_point(), b"/media/rdx");
}

/// Only exact kernel namespace roots in nsfs can bypass filesystem path syntax.
#[test]
fn mountinfo_rejects_malformed_or_misclassified_namespace_roots() {
    for (root, filesystem) in [
        ("mnt:[4026532537]", "exfat"),
        ("unknown:[4026532537]", "nsfs"),
        ("mnt:[0]", "nsfs"),
        ("mnt:[-1]", "nsfs"),
        ("mnt:[4026532537]suffix", "nsfs"),
        ("mnt:[4026532537", "nsfs"),
        ("mnt:[4026532537]:extra", "nsfs"),
        ("mnt:[18446744073709551616]", "nsfs"),
        ("../namespace", "nsfs"),
    ] {
        let line = format!("42 34 0:4 {root} /run/ns rw - {filesystem} nsfs rw\n");
        assert_eq!(
            parse_mountinfo(line.as_bytes()),
            Err(NativeError::EnumerationFailed)
        );
    }
    assert!(parse_mountinfo(b"42 34 0:4 mnt:[4026532537] ../ns rw - nsfs nsfs rw\n").is_err());
}

/// Namespace records still participate in stacked-mount ambiguity rejection.
#[test]
fn namespace_overlay_cannot_hide_a_selected_rdx_mount() {
    let records = parse_mountinfo(
        b"42 34 0:4 mnt:[4026532537] /media/rdx rw - nsfs nsfs rw\n\
          43 34 8:17 / /media/rdx rw - exfat /dev/sdb1 rw\n",
    )
    .expect("both records retained");
    assert_eq!(
        canonical_mounts_for_devices(&records, &BTreeSet::from([DeviceNumber::new(8, 17)])),
        Err(NativeError::EvidenceIncomplete),
    );
}

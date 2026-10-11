// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed Linux format selections at the service protocol boundary.
use rdx_service::model::{Filesystem, OperationRequest};
use rdx_service::operations::FileSystem;

/// Linux personalities round-trip without gaining a macOS formatter selector.
#[test]
fn linux_format_requests_are_closed_and_host_specific() {
    for selected in [
        Filesystem::Ext2,
        Filesystem::Ext3,
        Filesystem::Ext4,
        Filesystem::Xfs,
        Filesystem::Btrfs,
        Filesystem::F2fs,
    ] {
        assert_eq!(selected.macos_selector(), None);
        assert!(!selected.encrypted());
        assert_eq!(
            FileSystem::try_from(selected).unwrap(),
            FileSystem::Linux(selected)
        );
        let request = format!(
            r#"{{"kind":"format","deviceId":"rdx:example","deviceRevision":1,"filesystem":"{}","confirmationToken":"confirm:example"}}"#,
            selected.wire_name()
        );
        let parsed: OperationRequest = serde_json::from_str(&request).unwrap();
        let round_trip = serde_json::to_value(parsed).unwrap();
        assert_eq!(round_trip["filesystem"], selected.wire_name());
    }
    for value in ["zfs", "../../mkfs", "ext4 --force", "EXT4"] {
        assert!(serde_json::from_value::<Filesystem>(serde_json::json!(value)).is_err());
    }
}

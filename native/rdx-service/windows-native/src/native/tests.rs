// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::mem::{offset_of, size_of};

use windows::Win32::Devices::DeviceAndDriverInstallation::SP_DEVICE_INTERFACE_DETAIL_DATA_W;
use windows::Win32::Storage::IscsiDisc::{SCSI_PASS_THROUGH, SCSI_PASS_THROUGH_DIRECT};

use super::{BufferedControl, DirectControl};

/// Native Windows layouts match the documented pointer-width headers and offsets.
#[test]
fn native_spti_and_setupapi_layouts_are_exact() {
    let expected_header = if usize::BITS == 64 { 56 } else { 44 };
    let expected_detail = if usize::BITS == 64 { 8 } else { 6 };

    assert_eq!(size_of::<SCSI_PASS_THROUGH>(), expected_header);
    assert_eq!(size_of::<SCSI_PASS_THROUGH_DIRECT>(), expected_header);
    assert_eq!(offset_of!(DirectControl, sense), expected_header);
    assert_eq!(offset_of!(BufferedControl, sense), expected_header);
    assert_eq!(offset_of!(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath), 4);
    assert_eq!(
        size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>(),
        expected_detail
    );
}

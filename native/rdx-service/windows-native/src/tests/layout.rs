// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Capacity-boundary tests for closed Windows partition layout selection.

use crate::{
    DiskLayoutStyle, NativeError, canonical_volume_guid_paths_from_multi_sz,
    partition_style_for_capacity,
};

/// Proves the vendor large-cartridge boundary selects GPT without truncation.
#[test]
fn partition_style_changes_at_two_tib_without_capacity_truncation() {
    const TWO_TIB: u64 = 2 * 1024 * 1024 * 1024 * 1024;

    assert_eq!(
        partition_style_for_capacity(TWO_TIB - 1),
        Ok(DiskLayoutStyle::Mbr)
    );
    assert_eq!(
        partition_style_for_capacity(TWO_TIB),
        Ok(DiskLayoutStyle::Gpt)
    );
    assert_eq!(
        partition_style_for_capacity(TWO_TIB + 512),
        Ok(DiskLayoutStyle::Gpt)
    );
    assert_eq!(
        partition_style_for_capacity(2 * 1024 * 1024),
        Err(NativeError::EvidenceIncomplete)
    );
}

/// VDS path matching accepts only bounded, canonical exact volume GUIDs.
#[test]
fn vds_guid_pathname_matching_is_exact_and_bounded() {
    let first = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\";
    let sibling = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdee}\";
    let paths = first
        .encode_utf16()
        .chain([0])
        .chain(sibling.encode_utf16())
        .chain([0, 0])
        .collect::<Vec<_>>();

    assert_eq!(
        canonical_volume_guid_paths_from_multi_sz(&paths),
        Ok(vec![
            first.to_ascii_uppercase(),
            sibling.to_ascii_uppercase()
        ])
    );
    assert_eq!(
        canonical_volume_guid_paths_from_multi_sz(&paths[..paths.len() - 1]),
        Err(NativeError::EnumerationFailed)
    );
    let hostile = r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\suffix"
        .encode_utf16()
        .chain([0, 0])
        .collect::<Vec<_>>();
    assert_eq!(
        canonical_volume_guid_paths_from_multi_sz(&hostile),
        Err(NativeError::EnumerationFailed)
    );
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Distinguish an unformatted filesystem from failures to inspect a volume.

/// Queries free space only after Windows recognizes the exact volume filesystem.
///
/// A RAW partition remains present media. Access, topology, removal, and every
/// other failure keep their error instead of manufacturing free-space evidence.
/// In particular, an invalid-parameter free-space result alone never proves RAW.
pub(super) fn query_volume_space(
    information: Result<&str, u32>,
    query_space: impl FnOnce() -> Result<(u64, u64), u32>,
) -> Result<Option<(u64, u64)>, u32> {
    match information {
        Err(0x8007_03ed) => return Ok(None),
        Err(error) => return Err(error),
        Ok(name) if name.eq_ignore_ascii_case("RAW") => return Ok(None),
        Ok("") => return Err(0x8007_000d), // ERROR_INVALID_DATA
        Ok(_) => {}
    }
    classify_volume_space(query_space())
}

/// Preserves a later unrecognized-filesystem observation without hiding other errors.
fn classify_volume_space(result: Result<(u64, u64), u32>) -> Result<Option<(u64, u64)>, u32> {
    match result {
        Err(0x8007_03ed) => Ok(None), // HRESULT_FROM_WIN32(ERROR_UNRECOGNIZED_VOLUME)
        Ok(facts) => Ok(Some(facts)),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::query_volume_space;

    /// A newly partitioned RAW volume has no filesystem space facts.
    #[test]
    fn raw_volume_is_present_without_filesystem_facts() {
        for information in [Err(0x8007_03ed), Ok("RAW"), Ok("raw")] {
            assert_eq!(
                query_volume_space(information, || panic!("RAW space query must be skipped")),
                Ok(None)
            );
        }
    }

    /// Valid formatted-volume facts retain even a full filesystem's zero free space.
    #[test]
    fn formatted_volume_keeps_reported_space() {
        for facts in [(0, 3_000_000_000_000), (1234, 4096)] {
            for filesystem in ["NTFS", "exFAT", "ReFS"] {
                assert_eq!(
                    query_volume_space(Ok(filesystem), || Ok(facts)),
                    Ok(Some(facts))
                );
            }
        }
    }

    /// Access denial, removal, I/O, invalid input and unknown errors stay failures.
    #[test]
    fn other_errors_never_become_raw_media() {
        for error in [
            0x8007_0005,
            0x8007_048f,
            0x8007_001f,
            0x8007_0057,
            0x8000_4005,
        ] {
            assert_eq!(query_volume_space(Ok("NTFS"), || Err(error)), Err(error));
            assert_eq!(
                query_volume_space(Err(error), || panic!("failed filesystem query")),
                Err(error)
            );
        }
    }

    /// Filesystem loss between the two exact queries remains absent space facts.
    #[test]
    fn filesystem_loss_during_space_query_is_absent() {
        assert_eq!(
            query_volume_space(Ok("NTFS"), || Err(0x8007_03ed)),
            Ok(None)
        );
    }

    /// Missing filesystem names never become either mounted or RAW evidence.
    #[test]
    fn empty_filesystem_evidence_is_rejected() {
        assert_eq!(
            query_volume_space(Ok(""), || panic!("empty filesystem query")),
            Err(0x8007_000d)
        );
    }
}

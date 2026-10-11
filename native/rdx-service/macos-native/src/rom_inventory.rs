// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only TI ROM inventory and opaque enumeration identities.

use crate::NativeError;

#[cfg(any(target_os = "macos", test))]
const MAX_CANDIDATES: usize = 16;

/// One observed TI ROM USB parent, with no claimed per-unit identity.
///
/// The epoch and port prove continuity only until disconnect/re-enumeration.
/// Keep this private native value behind an application-owned selection token;
/// the ROM's generic serial is never used to associate a saved unit record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RomCandidate {
    registry_id: u64,
    location_id: u32,
}

impl RomCandidate {
    /// Returns the observed physical USB route; it may differ from the saved source route.
    #[must_use]
    pub const fn location_id(self) -> u32 {
        self.location_id
    }

    /// Returns the opaque registry epoch, which must change after re-enumeration.
    #[must_use]
    pub const fn registry_id(self) -> u64 {
        self.registry_id
    }

    /// Builds only the fixed native selection record from a previously observed candidate.
    #[cfg(target_os = "macos")]
    pub(crate) const fn record(self) -> CandidateRecord {
        CandidateRecord {
            registry_id: self.registry_id,
            location_id: self.location_id,
            reserved: 0,
        }
    }
}

impl std::fmt::Debug for RomCandidate {
    /// Redacts both location and enumeration epoch from generic diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RomCandidate(<private>)")
    }
}

/// Fixed-width FFI record; reserved bits make malformed native snapshots reject.
#[repr(C)]
#[derive(Clone, Copy, Default)]
#[cfg(any(target_os = "macos", test))]
pub(crate) struct CandidateRecord {
    registry_id: u64,
    location_id: u32,
    reserved: u32,
}

/// Returns up to sixteen ROM parents using read-only IORegistry enumeration.
///
/// This does not open a device/interface or send any USB request. Multiple ROM
/// parents remain separately selectable; there is no automatic first-device choice.
///
/// # Errors
/// Fails on incomplete enumeration, malformed/ambiguous identities or excessive
/// candidates. An empty successful list means no matching parent was observed.
pub fn enumerate_rom_candidates() -> Result<Vec<RomCandidate>, NativeError> {
    #[cfg(target_os = "macos")]
    {
        let mut records = [CandidateRecord::default(); MAX_CANDIDATES];
        let mut count = 0;
        // SAFETY: both outputs remain valid for this fixed-capacity, read-only call.
        let status = unsafe {
            rdx_macos_rom_enumerate(records.as_mut_ptr(), MAX_CANDIDATES as u32, &mut count)
        };
        if status != 0 {
            return Err(crate::status_error(status));
        }
        decode_inventory(&records, count as usize)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NativeError::UnsupportedPlatform)
    }
}

/// Validates the entire snapshot before exposing any sorted selection candidates.
#[cfg(any(target_os = "macos", test))]
fn decode_inventory(
    records: &[CandidateRecord],
    count: usize,
) -> Result<Vec<RomCandidate>, NativeError> {
    if count > MAX_CANDIDATES || count > records.len() {
        return Err(NativeError::ResourceLimit);
    }
    let mut candidates: Vec<RomCandidate> = Vec::with_capacity(count);
    for record in &records[..count] {
        if record.registry_id == 0
            || record.location_id == 0
            || record.reserved != 0
            || candidates.iter().any(|candidate| {
                candidate.registry_id == record.registry_id
                    || candidate.location_id == record.location_id
            })
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        candidates.push(RomCandidate {
            registry_id: record.registry_id,
            location_id: record.location_id,
        });
    }
    candidates.sort_unstable_by_key(|candidate| (candidate.location_id, candidate.registry_id));
    Ok(candidates)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn rdx_macos_rom_enumerate(output: *mut CandidateRecord, capacity: u32, count: *mut u32)
    -> u32;
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    /// Distinct ROMs remain selectable and their diagnostics do not expose physical identity.
    #[test]
    fn rom_inventory_preserves_multiple_selections_without_identity_claims() {
        let records = [
            CandidateRecord {
                registry_id: 22,
                location_id: 200,
                reserved: 0,
            },
            CandidateRecord {
                registry_id: 11,
                location_id: 100,
                reserved: 0,
            },
        ];
        let candidates = decode_inventory(&records, 2).unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            (candidates[0].registry_id(), candidates[0].location_id()),
            (11, 100)
        );
        assert_eq!(
            (candidates[1].registry_id(), candidates[1].location_id()),
            (22, 200)
        );
        assert_eq!(format!("{:?}", candidates[0]), "RomCandidate(<private>)");
        assert!(decode_inventory(&records, 0).unwrap().is_empty());
    }

    /// Native truncation, duplicate routes/epochs and malformed records fail all-or-nothing.
    #[test]
    fn rom_inventory_rejects_incomplete_or_ambiguous_snapshots() {
        let valid = CandidateRecord {
            registry_id: 11,
            location_id: 100,
            reserved: 0,
        };
        for invalid in [
            CandidateRecord {
                registry_id: 0,
                ..valid
            },
            CandidateRecord {
                location_id: 0,
                ..valid
            },
            CandidateRecord {
                reserved: 1,
                ..valid
            },
        ] {
            assert_eq!(
                decode_inventory(&[invalid], 1),
                Err(NativeError::EvidenceIncomplete)
            );
        }
        for duplicate in [
            valid,
            CandidateRecord {
                registry_id: 12,
                ..valid
            },
            CandidateRecord {
                location_id: 101,
                ..valid
            },
        ] {
            assert_eq!(
                decode_inventory(&[valid, duplicate], 2),
                Err(NativeError::EvidenceIncomplete)
            );
        }
        assert_eq!(
            decode_inventory(&[valid], 2),
            Err(NativeError::ResourceLimit)
        );
        assert_eq!(
            decode_inventory(&[valid; 17], 17),
            Err(NativeError::ResourceLimit)
        );
    }
}

#[cfg(all(test, target_os = "macos", feature = "test-hooks"))]
mod tests {
    unsafe extern "C" {
        fn rdx_macos_rom_inventory_test_contract() -> bool;
    }

    /// Multiple ROMs remain selectable while stale/ambiguous identities reject offline.
    #[test]
    fn rom_inventory_and_selected_epoch_contract() {
        // SAFETY: the hook uses only literal records and pure selection helpers.
        assert!(unsafe { rdx_macos_rom_inventory_test_contract() });
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact no-media classification before any present-cartridge volume inspection.

use super::NativeError;

/// Distinguishes authoritative no-media from failure to inspect a present cartridge.
///
/// Only the native no-media result can produce `None`, and only while the exact
/// retained dock is still present. Other errors, including disappearance, cannot
/// become an empty-bay snapshot. A positive capacity still requires the caller's
/// complete volume topology checks; zero capacity alone is not absence evidence.
pub(super) fn verified_media_capacity(
    capacity: Result<u64, NativeError>,
    revalidate: impl FnOnce() -> Result<(), NativeError>,
) -> Result<Option<u64>, NativeError> {
    match capacity {
        Err(NativeError::NoMedia) => {
            revalidate()?;
            Ok(None)
        }
        Ok(0) => Err(NativeError::EvidenceIncomplete),
        Ok(capacity) => Ok(Some(capacity)),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::verified_media_capacity;
    use crate::NativeError;
    use std::cell::Cell;

    /// An empty but still-present dock does not need a valid cartridge volume.
    #[test]
    fn no_media_requires_exact_dock_revalidation() {
        let revalidated = Cell::new(0);
        let result = verified_media_capacity(Err(NativeError::NoMedia), || {
            revalidated.set(revalidated.get() + 1);
            Ok(())
        });
        assert_eq!(result, Ok(None));
        assert_eq!(revalidated.get(), 1);
    }

    /// Removal or loss of authority during no-media observation remains a failure.
    #[test]
    fn no_media_rejects_failed_exact_revalidation() {
        for error in [
            NativeError::DeviceRemoved,
            NativeError::AccessDenied,
            NativeError::Other,
        ] {
            assert_eq!(
                verified_media_capacity(Err(NativeError::NoMedia), || Err(error)),
                Err(error)
            );
        }
    }

    /// Every non-media failure keeps its original meaning without manufacturing absence.
    #[test]
    fn capacity_errors_never_become_empty_bay_facts() {
        for error in [
            NativeError::AccessDenied,
            NativeError::DeviceRemoved,
            NativeError::EnumerationFailed,
            NativeError::EvidenceIncomplete,
            NativeError::Busy,
            NativeError::TimedOut,
            NativeError::Other,
        ] {
            assert_eq!(
                verified_media_capacity(Err(error), || panic!(
                    "non-media failure cannot be reclassified"
                )),
                Err(error)
            );
        }
    }

    /// A successful zero-sized geometry is inconclusive, not authoritative no-media.
    #[test]
    fn zero_capacity_is_not_absence_evidence() {
        assert_eq!(
            verified_media_capacity(Ok(0), || panic!("invalid capacity")),
            Err(NativeError::EvidenceIncomplete)
        );
    }

    /// Present cartridges retain their exact capacity for the unchanged topology checks.
    #[test]
    fn present_capacity_remains_available_for_full_volume_inspection() {
        for capacity in [1, 1_000_000_000, u64::MAX] {
            assert_eq!(
                verified_media_capacity(Ok(capacity), || panic!(
                    "present path has its own retained-volume checks"
                )),
                Ok(Some(capacity))
            );
        }
    }
}

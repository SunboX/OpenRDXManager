// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rename one mounted cartridge through its existing retained volume authority.
use super::volume::{HostOperationFailure, HostOperations, HostPrimitiveError, VolumeTopology};
use crate::model::VolumeLabel;

/// Renames the selected volume without changing its filesystem or contents.
/// Returns pre-dispatch failure for stale, missing, read-only, or unsafe targets.
pub fn set_volume_label(
    host: &mut impl HostOperations,
    label: &VolumeLabel,
) -> Result<(), HostOperationFailure> {
    let binding = host.binding();
    let facts = host
        .revalidate(&binding)
        .map_err(|failure| HostOperationFailure::from_primitive("preflight", failure))?;
    let failure = if !label.writable() {
        Some(HostPrimitiveError::Other)
    } else if !facts.media_present {
        Some(HostPrimitiveError::MediaMissing)
    } else if !facts.mounted {
        Some(HostPrimitiveError::NotMounted)
    } else if !facts.writable {
        Some(HostPrimitiveError::ReadOnly)
    } else if facts.topology != VolumeTopology::Simple {
        Some(HostPrimitiveError::UnsafeTopology)
    } else {
        None
    };
    if let Some(error) = failure {
        return Err(HostOperationFailure::preflight("preflight", error));
    }
    host.set_volume_label_exact(&binding, label)
        .map_err(|failure| HostOperationFailure::from_primitive("volume-label", failure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::fixtures::{FixtureHost, FixtureTopology};

    #[test]
    fn rename_and_clear_preserve_format_and_layout() {
        let mut host = FixtureHost::ready();
        for label in ["Backup", ""] {
            set_volume_label(&mut host, &VolumeLabel::new(label).unwrap()).unwrap();
            assert_eq!(host.current_volume_label(), Some(label));
        }
        assert_eq!(host.set_volume_label_count(), 2);
        assert_eq!(host.format_count(), 0);
        assert_eq!(host.layout_change_count(), 0);
        assert_eq!(host.unmount_count(), 0);
    }

    #[test]
    fn stale_read_only_missing_or_unsafe_media_never_reaches_rename() {
        let label = VolumeLabel::new("Backup").unwrap();
        for mut host in [
            FixtureHost::ready().with_media_swap_at_revalidation(1),
            FixtureHost::ready().with_media_swap_at_revalidation(2),
            FixtureHost::ready().read_only(),
            FixtureHost::ready().without_media(),
            FixtureHost::ready().with_topology(FixtureTopology::Shared),
        ] {
            assert!(set_volume_label(&mut host, &label).is_err());
            assert_eq!(host.set_volume_label_count(), 0);
        }
    }
}

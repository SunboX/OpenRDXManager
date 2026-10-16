// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Installer-only volume journal planning; grants no device or operation authority.
use crate::NativeError;
use std::collections::BTreeSet;

const MAX_POLICIES: usize = 256;

/// Exact prior and installed policy for one positively mapped volume instance.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
#[cfg_attr(windows, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(windows, serde(deny_unknown_fields, rename_all = "camelCase"))]
pub(crate) struct VolumePolicy {
    /// Exact SetupAPI instance identity.
    pub(crate) instance: String,
    /// Complete current storage topology captured under the verified parent dock.
    pub(crate) topology: String,
    /// Original instance property, preserving absence exactly.
    pub(crate) previous: Option<String>,
    /// Exact descriptor installed by this setup transaction.
    pub(crate) installed: String,
}

/// Read-only evidence collected before planning any journal or permission write.
pub(crate) struct VolumeObservation {
    /// Exact present SetupAPI instance identity.
    pub(crate) instance: String,
    /// Strictly verified current topology for the same parent dock.
    pub(crate) topology: String,
    /// Current instance security property, preserving absence exactly.
    pub(crate) current: Option<String>,
}

/// Defers only volume permission work for unavailable media; other errors survive.
pub(crate) fn volume_media_ready(result: Result<(), NativeError>) -> Result<bool, NativeError> {
    match result {
        Ok(()) => Ok(true),
        Err(NativeError::NoMedia) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Validates retained journal bounds and unique instance ownership before repair.
pub(crate) fn validate_volume_policies(policies: &[VolumePolicy]) -> Result<(), NativeError> {
    if policies.len() > MAX_POLICIES {
        return Err(NativeError::ResourceLimit);
    }
    let mut seen = BTreeSet::new();
    for policy in policies {
        if policy.instance.is_empty()
            || policy.instance.len() > 201
            || policy.topology.is_empty()
            || policy.topology.len() > 256
            || policy.installed.is_empty()
            || policy.installed.len() > 65536
            || policy.previous.as_ref().is_some_and(|v| v.len() > 65536)
            || !seen.insert(policy.instance.as_str())
        {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    Ok(())
}

/// Plans a complete replacement journal without writing permissions or storage.
/// The native callback constructs a new descriptor only for an unrecorded volume.
pub(crate) fn plan_volume_policies(
    previous: &[VolumePolicy],
    observed: &[VolumeObservation],
    mut build_installed: impl FnMut(usize) -> Result<String, NativeError>,
) -> Result<Vec<VolumePolicy>, NativeError> {
    validate_volume_policies(previous)?;
    if observed.len() > MAX_POLICIES {
        return Err(NativeError::ResourceLimit);
    }
    let mut seen = BTreeSet::new();
    let mut new_count = 0;
    // Validate the complete evidence set before constructing any new descriptor.
    for current in observed {
        if current.instance.is_empty()
            || current.instance.len() > 201
            || current.topology.is_empty()
            || current.topology.len() > 256
            || current.current.as_ref().is_some_and(|v| v.len() > 65536)
            || !seen.insert(current.instance.as_str())
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        if let Some(old) = previous.iter().find(|v| v.instance == current.instance) {
            if current.current.as_deref() != Some(old.installed.as_str())
                && current.current != old.previous
            {
                return Err(NativeError::AccessDenied);
            }
        } else {
            new_count += 1;
        }
    }
    if previous.len() + new_count > MAX_POLICIES {
        return Err(NativeError::ResourceLimit);
    }
    let mut planned = previous.to_vec();
    for (index, current) in observed.iter().enumerate() {
        if let Some(old) = planned.iter_mut().find(|v| v.instance == current.instance) {
            // The verified parent dock and exact current instance bind this new
            // geometry. Keep the original policy for eventual restoration.
            old.topology.clone_from(&current.topology);
        } else {
            planned.push(VolumePolicy {
                instance: current.instance.clone(),
                topology: current.topology.clone(),
                previous: current.current.clone(),
                installed: build_installed(index)?,
            });
        }
    }
    validate_volume_policies(&planned)?;
    Ok(planned)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a compact opaque policy fixture; these strings are never native ACLs.
    fn policy(instance: &str) -> VolumePolicy {
        VolumePolicy {
            instance: instance.to_owned(),
            topology: "old-geometry".to_owned(),
            previous: None,
            installed: "system-and-fixed-service".to_owned(),
        }
    }

    /// Builds one freshly observed target under an independently verified dock.
    fn observation(instance: &str, current: Option<&str>) -> VolumeObservation {
        VolumeObservation {
            instance: instance.to_owned(),
            topology: "new-geometry".to_owned(),
            current: current.map(str::to_owned),
        }
    }

    /// An empty/not-ready dock can be enrolled without admitting any volume.
    #[test]
    fn unavailable_media_defers_only_installer_volume_permissions() {
        assert_eq!(volume_media_ready(Err(NativeError::NoMedia)), Ok(false));
        assert_eq!(volume_media_ready(Ok(())), Ok(true));
        for error in [
            NativeError::AccessDenied,
            NativeError::Other,
            NativeError::DeviceRemoved,
        ] {
            assert_eq!(volume_media_ready(Err(error)), Err(error));
        }
    }

    /// Repair enrolls a newly available cartridge and retains disconnected records.
    #[test]
    fn repair_adds_new_volume_and_preserves_absent_records() {
        let old = policy("disconnected");
        let observed = [observation("new", Some("original-system-policy"))];
        let planned = plan_volume_policies(std::slice::from_ref(&old), &observed, |index| {
            assert_eq!(index, 0);
            Ok("new-fixed-service-policy".to_owned())
        })
        .unwrap();
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0], old);
        assert_eq!(planned[1].instance, "new");
        assert_eq!(planned[1].topology, "new-geometry");
        assert_eq!(
            planned[1].previous.as_deref(),
            Some("original-system-policy")
        );
        assert_eq!(planned[1].installed, "new-fixed-service-policy");
    }

    /// Geometry refresh never turns our installed grant into the original policy.
    #[test]
    fn same_instance_refresh_preserves_original_restoration_policy() {
        let mut old = policy("same");
        old.previous = Some("original".to_owned());
        let current = [observation("same", Some(&old.installed))];
        let planned = plan_volume_policies(std::slice::from_ref(&old), &current, |_| {
            panic!("existing policy must be reused")
        })
        .unwrap();
        assert_eq!(planned[0].topology, "new-geometry");
        assert_eq!(planned[0].previous, old.previous);
        assert_eq!(planned[0].installed, old.installed);
    }

    /// An interrupted write can resume from the exact absent original property.
    #[test]
    fn repair_accepts_exact_original_absence() {
        let old = policy("same");
        let current = [observation("same", None)];
        let planned = plan_volume_policies(&[old], &current, |_| panic!("reuse")).unwrap();
        assert_eq!(planned[0].previous, None);
        assert_eq!(planned[0].topology, "new-geometry");
    }

    /// Any administrator policy change rejects the entire plan before new grants.
    #[test]
    fn foreign_policy_rejects_before_any_new_descriptor_is_built() {
        let current = [
            observation("new", None),
            observation("same", Some("foreign")),
        ];
        assert_eq!(
            plan_volume_policies(&[policy("same")], &current, |_| panic!("no partial plan")),
            Err(NativeError::AccessDenied)
        );
    }

    /// Ambiguous retained or observed instance ownership cannot select a descriptor.
    #[test]
    fn duplicate_volume_instances_fail_closed() {
        let duplicate = vec![policy("same"), policy("same")];
        assert_eq!(
            validate_volume_policies(&duplicate),
            Err(NativeError::EvidenceIncomplete)
        );
        let current = [observation("same", None), observation("same", None)];
        assert_eq!(
            plan_volume_policies(&[], &current, |_| panic!("ambiguous")),
            Err(NativeError::EvidenceIncomplete)
        );
    }

    /// A missing cartridge preserves the entire protected journal without callbacks.
    #[test]
    fn no_observed_volume_preserves_restoration_records() {
        let old = vec![policy("absent")];
        assert_eq!(
            plan_volume_policies(&old, &[], |_| panic!("no observed volume")).unwrap(),
            old
        );
    }

    /// Combined retained/new records remain within the persisted journal bound.
    #[test]
    fn new_volume_cannot_exceed_retained_journal_capacity() {
        let previous = (0..256)
            .map(|n| policy(&format!("volume-{n}")))
            .collect::<Vec<_>>();
        assert_eq!(
            plan_volume_policies(&previous, &[observation("new", None)], |_| panic!(
                "over limit"
            )),
            Err(NativeError::ResourceLimit)
        );
    }

    /// Descriptor-construction failures propagate without producing a partial plan.
    #[test]
    fn new_descriptor_failure_survives_planning() {
        assert_eq!(
            plan_volume_policies(&[], &[observation("new", None)], |_| Err(
                NativeError::AccessDenied
            )),
            Err(NativeError::AccessDenied)
        );
    }
}

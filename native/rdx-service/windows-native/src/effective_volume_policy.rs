// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Write-ahead restoration evidence for a live, exact volume device DACL.
use crate::NativeError;

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(windows, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(windows, serde(deny_unknown_fields, rename_all = "camelCase"))]
pub(crate) struct EffectiveVolumePolicy {
    pub(crate) previous: String,
    pub(crate) installed: String,
}

impl EffectiveVolumePolicy {
    /// Bounds protected journal strings before any native descriptor parsing.
    pub(crate) fn validate(&self) -> Result<(), NativeError> {
        if [self.previous.as_str(), self.installed.as_str()]
            .iter()
            .any(|value| value.is_empty() || value.len() > 65536)
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(())
    }

    /// Preserves the first live descriptor across repair and refuses foreign changes.
    pub(crate) fn plan(
        previous: Option<&Self>,
        current: String,
        grant: impl FnOnce(&str) -> Result<String, NativeError>,
    ) -> Result<Self, NativeError> {
        if let Some(previous) = previous {
            previous.validate()?;
            if current != previous.previous && current != previous.installed {
                return Err(NativeError::AccessDenied);
            }
            return Ok(previous.clone());
        }
        let policy = Self {
            installed: grant(&current)?,
            previous: current,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Restores only our exact live descriptor; administrator changes are preserved.
    pub(crate) fn restore_target(&self, current: &str) -> Option<&str> {
        (current == self.installed).then_some(self.previous.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Initial and repeated repair retain the original live policy for removal.
    #[test]
    fn repair_preserves_original_and_accepts_interrupted_apply() {
        let initial =
            EffectiveVolumePolicy::plan(None, "original".into(), |_| Ok("grant".into())).unwrap();
        for current in ["original", "grant"] {
            let repaired = EffectiveVolumePolicy::plan(Some(&initial), current.into(), |_| {
                panic!("must reuse journal")
            })
            .unwrap();
            assert_eq!(repaired, initial);
        }
        assert_eq!(initial.restore_target("grant"), Some("original"));
        assert_eq!(initial.restore_target("administrator"), None);
    }

    /// A foreign live policy never becomes permission to overwrite or rebaseline it.
    #[test]
    fn repair_refuses_foreign_and_malformed_policies() {
        let initial = EffectiveVolumePolicy {
            previous: "original".into(),
            installed: "grant".into(),
        };
        assert_eq!(
            EffectiveVolumePolicy::plan(Some(&initial), "foreign".into(), |_| panic!("foreign")),
            Err(NativeError::AccessDenied)
        );
        assert_eq!(
            EffectiveVolumePolicy::plan(None, String::new(), |_| Ok("grant".into())),
            Err(NativeError::EvidenceIncomplete)
        );
        assert_eq!(
            EffectiveVolumePolicy::plan(None, "original".into(), |_| Err(
                NativeError::AccessDenied
            )),
            Err(NativeError::AccessDenied)
        );
    }
}

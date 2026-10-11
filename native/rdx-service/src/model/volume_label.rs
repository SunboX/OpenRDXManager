// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded path-free filesystem labels, including an explicitly unnamed volume.
use serde::{Deserialize, Deserializer, Serialize, de};

/// A display-safe volume label; filesystem-specific limits apply natively.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VolumeLabel(String);

impl VolumeLabel {
    /// Validates display text without accepting control characters or oversized UTF-16.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.encode_utf16().count() > 32 || value.chars().any(char::is_control) {
            return Err("invalid volume label");
        }
        Ok(Self(value))
    }

    /// Borrows the label solely for rendering or the retained native volume API.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Rejects filename metacharacters for the common NTFS/exFAT rename surface.
    pub fn writable(&self) -> bool {
        !self.0.chars().any(|c| "\\/:*?\"<>|".contains(c))
    }
}

impl<'de> Deserialize<'de> for VolumeLabel {
    /// Validates the cross-process label instead of trusting serde input.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn label_bounds_use_utf16_and_preserve_empty_and_unicode() {
        assert_eq!(VolumeLabel::new("").unwrap().as_str(), "");
        assert!(VolumeLabel::new("Sicherung ä").unwrap().writable());
        assert!(VolumeLabel::new("😀".repeat(17)).is_err());
        assert!(VolumeLabel::new("line\nname").is_err());
        assert!(!VolumeLabel::new("a/b").unwrap().writable());
    }
}

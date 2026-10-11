// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed filesystem selections and transient encrypted-format secrets.
use serde::{Deserialize, Deserializer, Serialize, de};
use zeroize::Zeroize;

/// Filesystem choice accepted by the high-level format request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Filesystem {
    /// Linux Ext2 filesystem.
    Ext2,
    /// Linux Ext3 filesystem.
    Ext3,
    /// Linux Ext4 filesystem.
    Ext4,
    /// Linux Xfs filesystem.
    Xfs,
    /// Linux Btrfs filesystem.
    Btrfs,
    /// Linux F2fs filesystem.
    F2fs,
    /// Windows NTFS.
    Ntfs,
    /// Cross-platform exFAT.
    Exfat,
    /// Native macOS fat format.
    Fat,
    /// Native macOS fat12 format.
    Fat12,
    /// Cross-platform FAT16, created on Linux or macOS.
    Fat16,
    /// Cross-platform FAT32, created on Linux or macOS.
    Fat32,
    /// Native macOS hfs format.
    Hfs,
    /// Native macOS hfs-case-sensitive format.
    HfsCaseSensitive,
    /// Native macOS hfs-journaled format.
    HfsJournaled,
    /// Native macOS hfs-case-sensitive-journaled format.
    HfsCaseSensitiveJournaled,
    /// Native macOS apfs format.
    Apfs,
    /// Native macOS apfs-case-sensitive format.
    ApfsCaseSensitive,
    /// Native macOS apfs-encrypted format.
    ApfsEncrypted,
    /// Native macOS apfs-case-sensitive-encrypted format.
    ApfsCaseSensitiveEncrypted,
}

impl Filesystem {
    /// Returns the public wire identifier, never a command argument.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
            Self::Xfs => "xfs",
            Self::Btrfs => "btrfs",
            Self::F2fs => "f2fs",
            Self::Ntfs => "ntfs",
            Self::Exfat => "exfat",
            Self::Fat => "fat",
            Self::Fat12 => "fat12",
            Self::Fat16 => "fat16",
            Self::Fat32 => "fat32",
            Self::Hfs => "hfs",
            Self::HfsCaseSensitive => "hfs-case-sensitive",
            Self::HfsJournaled => "hfs-journaled",
            Self::HfsCaseSensitiveJournaled => "hfs-case-sensitive-journaled",
            Self::Apfs => "apfs",
            Self::ApfsCaseSensitive => "apfs-case-sensitive",
            Self::ApfsEncrypted => "apfs-encrypted",
            Self::ApfsCaseSensitiveEncrypted => "apfs-case-sensitive-encrypted",
        }
    }
    /// Returns the closed native selector; NTFS has no macOS formatter.
    pub const fn macos_selector(self) -> Option<u32> {
        match self {
            Self::Ntfs
            | Self::Ext2
            | Self::Ext3
            | Self::Ext4
            | Self::Xfs
            | Self::Btrfs
            | Self::F2fs => None,
            Self::Exfat => Some(1),
            Self::Fat => Some(3),
            Self::Fat12 => Some(4),
            Self::Fat16 => Some(5),
            Self::Fat32 => Some(6),
            Self::Hfs => Some(7),
            Self::HfsCaseSensitive => Some(8),
            Self::HfsJournaled => Some(9),
            Self::HfsCaseSensitiveJournaled => Some(10),
            Self::Apfs => Some(11),
            Self::ApfsCaseSensitive => Some(12),
            Self::ApfsEncrypted => Some(13),
            Self::ApfsCaseSensitiveEncrypted => Some(14),
        }
    }
    /// Reports whether the format requires a transient password.
    pub const fn encrypted(self) -> bool {
        matches!(self, Self::ApfsEncrypted | Self::ApfsCaseSensitiveEncrypted)
    }
}

/// A transient format password, excluded from diagnostic formatting.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FormatPassphrase(String);
impl std::fmt::Debug for FormatPassphrase {
    /// Never reveals a password or its length in diagnostic output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl Drop for FormatPassphrase {
    /// Clears the owned password buffer on every completion and error path.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl FormatPassphrase {
    /// Borrows the password only for the native formatter's private stdin pipe.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for FormatPassphrase {
    /// Rejects empty, oversized, NUL, and multiline stdin payloads.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut value = String::deserialize(deserializer)?;
        if value.is_empty() || value.len() > 512 || value.bytes().any(|b| matches!(b, 0 | 10 | 13))
        {
            value.zeroize();
            return Err(de::Error::custom("invalid format passphrase"));
        }
        Ok(Self(value))
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed Linux formatter catalog shared by preflight, layout and readback.

use crate::NativeError;

/// Filesystem implementations admitted by the closed Linux formatter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFilesystem {
    /// Windows NTFS quick format.
    Ntfs,
    /// Cross-platform exFAT.
    ExFat,
    /// Linux ext2.
    Ext2,
    /// Linux ext3.
    Ext3,
    /// Linux ext4.
    Ext4,
    /// Linux XFS.
    Xfs,
    /// Single-device Linux Btrfs.
    Btrfs,
    /// Linux flash-friendly filesystem.
    F2fs,
    /// Cross-platform 16-bit FAT.
    Fat16,
    /// Cross-platform 32-bit FAT.
    Fat32,
}

impl HostFilesystem {
    /// Complete closed set used for exact on-disk personality recognition.
    pub(crate) const ALL: [Self; 10] = [
        Self::Ntfs,
        Self::ExFat,
        Self::Ext2,
        Self::Ext3,
        Self::Ext4,
        Self::Xfs,
        Self::Btrfs,
        Self::F2fs,
        Self::Fat16,
        Self::Fat32,
    ];

    /// Returns only fixed administrator-owned executable candidates, never PATH input.
    pub(crate) const fn tool_paths(self) -> &'static [&'static str] {
        match self {
            Self::Ntfs => &[
                "/usr/sbin/mkfs.ntfs",
                "/sbin/mkfs.ntfs",
                "/usr/bin/mkfs.ntfs",
            ],
            Self::ExFat => &[
                "/usr/sbin/mkfs.exfat",
                "/sbin/mkfs.exfat",
                "/usr/bin/mkfs.exfat",
            ],
            Self::Ext2 => &["/usr/sbin/mkfs.ext2", "/sbin/mkfs.ext2"],
            Self::Ext3 => &["/usr/sbin/mkfs.ext3", "/sbin/mkfs.ext3"],
            Self::Ext4 => &["/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"],
            Self::Xfs => &["/usr/sbin/mkfs.xfs", "/sbin/mkfs.xfs"],
            Self::Btrfs => &["/usr/sbin/mkfs.btrfs", "/sbin/mkfs.btrfs"],
            Self::F2fs => &["/usr/sbin/mkfs.f2fs", "/sbin/mkfs.f2fs"],
            Self::Fat16 | Self::Fat32 => &["/usr/sbin/mkfs.fat", "/sbin/mkfs.fat"],
        }
    }

    /// Builds fixed flags for the already-confirmed exact partition and label.
    pub(crate) const fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Ntfs => &["-F", "-Q", "-L", "OPENRDX"],
            Self::ExFat => &["-n", "OPENRDX"],
            Self::Ext2 | Self::Ext3 | Self::Ext4 => &["-F", "-q", "-L", "OPENRDX"],
            Self::Xfs | Self::Btrfs => &["-f", "-L", "OPENRDX"],
            Self::F2fs => &["-f", "-l", "OPENRDX"],
            Self::Fat16 => &["-F", "16", "-n", "OPENRDX"],
            Self::Fat32 => &["-F", "32", "-n", "OPENRDX"],
        }
    }

    /// Returns the DOS partition type belonging to the selected on-disk format.
    pub(crate) const fn mbr_type(self) -> &'static str {
        match self {
            Self::Ntfs | Self::ExFat => "7",
            Self::Fat16 => "e",
            Self::Fat32 => "c",
            _ => "83",
        }
    }

    /// Returns the GPT data personality independently of media capacity.
    pub(crate) const fn gpt_type(self) -> &'static str {
        match self {
            Self::Ntfs | Self::ExFat | Self::Fat16 | Self::Fat32 => {
                "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
            }
            _ => "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
        }
    }

    /// Checks conservative formatter bounds before any filesystem is unmounted.
    pub(crate) fn check_capacity(self, partition_bytes: u64) -> Result<(), NativeError> {
        let mib = 1024 * 1024;
        let (minimum, maximum) = match self {
            Self::Xfs => (300 * mib, u64::MAX),
            Self::Btrfs | Self::F2fs => (128 * mib, u64::MAX),
            Self::Fat16 => (4 * mib, 2 * 1024 * mib),
            Self::Fat32 => (32 * mib, 2 * 1024 * 1024 * mib),
            _ => (4 * mib, u64::MAX),
        };
        if !(minimum..=maximum).contains(&partition_bytes) {
            return Err(NativeError::InvalidRequest);
        }
        Ok(())
    }

    /// Matches uncached UDisks/blkid on-disk signatures, including FAT width.
    pub(crate) fn signature_matches(self, kind: &str, version: &str) -> bool {
        match self {
            Self::Ntfs => kind == "ntfs",
            Self::ExFat => kind == "exfat",
            Self::Ext2 => kind == "ext2",
            Self::Ext3 => kind == "ext3",
            Self::Ext4 => kind == "ext4",
            Self::Xfs => kind == "xfs",
            Self::Btrfs => kind == "btrfs",
            Self::F2fs => kind == "f2fs",
            Self::Fat16 => kind == "vfat" && version == "FAT16",
            Self::Fat32 => kind == "vfat" && version == "FAT32",
        }
    }

    /// Recognizes the kernel mount driver; ext4 can mount older ext personalities.
    pub(crate) fn mount_matches(self, kind: &[u8]) -> bool {
        match self {
            Self::Ntfs => matches!(kind, b"ntfs3" | b"ntfs" | b"fuseblk"),
            Self::ExFat => kind == b"exfat",
            Self::Ext2 => matches!(kind, b"ext2" | b"ext4"),
            Self::Ext3 => matches!(kind, b"ext3" | b"ext4"),
            Self::Ext4 => kind == b"ext4",
            Self::Xfs => kind == b"xfs",
            Self::Btrfs => kind == b"btrfs",
            Self::F2fs => kind == b"f2fs",
            Self::Fat16 | Self::Fat32 => kind == b"vfat",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux partition types differ from Windows types in both table schemes.
    #[test]
    fn layouts_and_signatures_preserve_selected_personality() {
        for fs in [
            HostFilesystem::Ext2,
            HostFilesystem::Ext3,
            HostFilesystem::Ext4,
            HostFilesystem::Xfs,
            HostFilesystem::Btrfs,
            HostFilesystem::F2fs,
        ] {
            assert_eq!(fs.mbr_type(), "83");
            assert_eq!(fs.gpt_type(), "0FC63DAF-8483-4772-8E79-3D69D8477DE4");
            assert!(!fs.signature_matches("ntfs", ""));
            assert!(fs.check_capacity(512 * 1024 * 1024).is_ok());
        }
        assert!(HostFilesystem::Ext3.mount_matches(b"ext4"));
        assert!(!HostFilesystem::Ext3.signature_matches("ext4", "1.0"));
        assert!(HostFilesystem::Fat16.signature_matches("vfat", "FAT16"));
        assert!(!HostFilesystem::Fat16.signature_matches("vfat", "FAT32"));
        assert!(HostFilesystem::Fat32.signature_matches("vfat", "FAT32"));
        assert_eq!(HostFilesystem::Fat16.mbr_type(), "e");
        assert_eq!(HostFilesystem::Fat32.mbr_type(), "c");
    }

    /// Impossible selections are rejected before unmount or partition writes.
    #[test]
    fn capacity_bounds_reject_small_xfs_and_oversized_fat() {
        assert!(
            HostFilesystem::Xfs
                .check_capacity(128 * 1024 * 1024)
                .is_err()
        );
        assert!(
            HostFilesystem::Btrfs
                .check_capacity(32 * 1024 * 1024)
                .is_err()
        );
        assert!(
            HostFilesystem::Fat16
                .check_capacity(3 * 1024 * 1024 * 1024)
                .is_err()
        );
        assert!(
            HostFilesystem::Fat32
                .check_capacity(3 * 1024_u64.pow(4))
                .is_err()
        );
    }
}

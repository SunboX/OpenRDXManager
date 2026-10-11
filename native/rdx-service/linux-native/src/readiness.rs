// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed udev, group, polkit, and device-resource readiness evidence.

/// Static safety state of one udev rules file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UdevRuleState {
    /// The file contains comments only and grants no access.
    InactiveTemplate,
    /// Every active rule is the exact root-only supported-device contract.
    Constrained,
    /// At least one active line is broad, malformed, or world-writable.
    Unsafe,
}

/// Exact access evidence for currently enumerated sg candidates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAccess {
    /// No sg candidate exists, so exact descriptor access is unproven.
    NoCandidate,
    /// A candidate exists but cannot be opened read/write.
    Denied,
    /// At least one exact candidate was opened read/write with safe flags.
    ReadWrite,
}

/// Sanitized Linux readiness evidence with no path or credential data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Readiness {
    sysfs_available: bool,
    udev_rules_installed: bool,
    ipc_group_configured: bool,
    current_ipc_group_member: bool,
    device_access: DeviceAccess,
    polkit_policy_installed: bool,
}

impl Readiness {
    /// Creates one complete private readiness record.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const fn new(
        sysfs_available: bool,
        udev_rules_installed: bool,
        ipc_group_configured: bool,
        current_ipc_group_member: bool,
        device_access: DeviceAccess,
        polkit_policy_installed: bool,
    ) -> Self {
        Self {
            sysfs_available,
            udev_rules_installed,
            ipc_group_configured,
            current_ipc_group_member,
            device_access,
            polkit_policy_installed,
        }
    }

    /// Returns a completely unavailable non-Linux result.
    #[cfg(not(target_os = "linux"))]
    pub(crate) const fn unavailable() -> Self {
        Self::new(false, false, false, false, DeviceAccess::NoCandidate, false)
    }

    /// Returns whether the standard scsi-generic sysfs class is available.
    #[must_use]
    pub const fn sysfs_available(self) -> bool {
        self.sysfs_available
    }

    /// Returns whether at least one installed udev rule is safely constrained.
    #[must_use]
    pub const fn udev_rules_installed(self) -> bool {
        self.udev_rules_installed
    }

    /// Returns whether the IPC-only `openrdx` socket group exists.
    #[must_use]
    pub const fn ipc_group_configured(self) -> bool {
        self.ipc_group_configured
    }

    /// Returns whether the current process inherited the IPC socket group or is root.
    #[must_use]
    pub const fn current_ipc_group_member(self) -> bool {
        self.current_ipc_group_member
    }

    /// Returns current exact descriptor access evidence.
    #[must_use]
    pub const fn device_access(self) -> DeviceAccess {
        self.device_access
    }

    /// Returns whether the narrow policy action is installed.
    #[must_use]
    pub const fn polkit_policy_installed(self) -> bool {
        self.polkit_policy_installed
    }
}

/// Inspects active udev lines and rejects every unconstrained sg grant.
pub(crate) fn inspect_udev_rules(contents: &str) -> UdevRuleState {
    let active = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();
    if active.is_empty() {
        return UdevRuleState::InactiveTemplate;
    }
    if active.iter().all(|line| constrained_udev_line(line)) {
        UdevRuleState::Constrained
    } else {
        UdevRuleState::Unsafe
    }
}

/// Requires the exact supported identity and root-only service ownership.
fn constrained_udev_line(line: &str) -> bool {
    let tokens = line.split(',').map(str::trim).collect::<Vec<_>>();
    tokens.len() == 7
        && tokens.contains(&"ACTION==\"add|change\"")
        && tokens.contains(&"SUBSYSTEM==\"scsi_generic\"")
        && tokens.contains(&"ATTRS{idVendor}==\"1a5a\"")
        && tokens.contains(&"ATTRS{idProduct}==\"0006\"")
        && tokens.contains(&"OWNER=\"root\"")
        && tokens.contains(&"GROUP=\"root\"")
        && tokens.contains(&"MODE=\"0600\"")
}

/// Extracts the exact `openrdx` group GID from a bounded `/etc/group` snapshot.
pub(crate) fn configured_group_gid(contents: &[u8]) -> Option<u32> {
    if contents.len() > 1024 * 1024 {
        return None;
    }
    let mut found = None;
    for line in contents.split(|byte| *byte == b'\n') {
        let fields = line.split(|byte| *byte == b':').collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != b"openrdx" {
            continue;
        }
        let gid = std::str::from_utf8(fields[2]).ok()?.parse().ok()?;
        if found.replace(gid).is_some() {
            return None;
        }
    }
    found
}

/// Checks the exact supplementary-group list from `/proc/self/status`.
pub(crate) fn process_has_group(status: &[u8], expected_gid: u32) -> bool {
    if status.len() > 1024 * 1024 {
        return false;
    }
    let Some(line) = status
        .split(|byte| *byte == b'\n')
        .find(|line| line.starts_with(b"Groups:"))
    else {
        return false;
    };
    let Ok(groups) = std::str::from_utf8(&line[b"Groups:".len()..]) else {
        return false;
    };
    let Ok(groups) = groups
        .split_ascii_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    groups.contains(&expected_gid)
}

/// Validates the one narrow packaged policy action and deny-by-default matrix.
pub(crate) fn polkit_policy_is_narrow(contents: &str) -> bool {
    contents == include_str!("../../resources/linux/org.openrdx.hardware.policy")
        && contents.matches("<action id=").count() == 1
        && contents.contains("<action id=\"org.openrdx.hardware.manage\">")
        && contents.contains("<allow_any>no</allow_any>")
        && contents.contains("<allow_inactive>no</allow_inactive>")
        && contents.contains("<allow_active>auth_admin</allow_active>")
        && !contents.contains("auth_admin_keep")
        && !contents.contains("<allow_any>yes</allow_any>")
}

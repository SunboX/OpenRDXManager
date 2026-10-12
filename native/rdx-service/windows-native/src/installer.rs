// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed native elevated-installer vocabulary, independent of Electron IPC.
use crate::NativeError;

/// Only fixed machine-wide setup operations are admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalInstallAction {
    /// Quiesce an owned existing service before installer file replacement.
    Prepare,
    /// Enroll and register a freshly installed protected runtime.
    Install,
    /// Verify the fixed installed enrollment without mutation.
    Verify,
    /// Administrator-approved renewal of the complete installed enrollment.
    Repair,
    /// Remove only owned service, enrollment and matching recorded permissions.
    Remove,
}
/// Parsed command has no caller-controlled root, service, SID or device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalInstallCommand {
    action: LocalInstallAction,
    manager_process_id: Option<u32>,
}
impl LocalInstallCommand {
    /// Returns the closed operation.
    pub const fn action(self) -> LocalInstallAction {
        self.action
    }
    /// Returns only a live Manager PID, subsequently verified from kernel evidence.
    pub const fn manager_process_id(self) -> Option<u32> {
        self.manager_process_id
    }
}
/// Parses the fixed installer command, rejecting all unspecified inputs.
///
/// # Errors
/// Install and Repair require a nonzero decimal Manager PID; no paths are accepted.
pub fn parse_local_install_arguments(
    arguments: &[&str],
) -> Result<LocalInstallCommand, NativeError> {
    if !matches!(arguments.len(), 2 | 4) || arguments[0] != "--action" {
        return Err(NativeError::InvalidRequest);
    }
    let action = match arguments[1] {
        "prepare" => LocalInstallAction::Prepare,
        "install" => LocalInstallAction::Install,
        "verify" => LocalInstallAction::Verify,
        "repair" => LocalInstallAction::Repair,
        "remove" => LocalInstallAction::Remove,
        _ => return Err(NativeError::InvalidRequest),
    };
    let manager_process_id = if arguments.len() == 4 {
        if arguments[2] != "--manager-process-id"
            || !arguments[3].bytes().all(|v| v.is_ascii_digit())
        {
            return Err(NativeError::InvalidRequest);
        }
        Some(
            arguments[3]
                .parse::<u32>()
                .ok()
                .filter(|pid| *pid > 0)
                .ok_or(NativeError::InvalidRequest)?,
        )
    } else {
        None
    };
    if action == LocalInstallAction::Prepare && manager_process_id.is_some() {
        return Err(NativeError::InvalidRequest);
    }
    if matches!(
        action,
        LocalInstallAction::Install | LocalInstallAction::Repair
    ) && manager_process_id.is_none()
    {
        return Err(NativeError::InvalidRequest);
    }
    Ok(LocalInstallCommand {
        action,
        manager_process_id,
    })
}
#[cfg(any(windows, test))]
pub(crate) mod diagnostics;
#[cfg(windows)]
mod windows;
/// Executes fixed setup only from an elevated installed provisioner process.
///
/// # Errors
/// Refuses foreign services, inactive/copy clients, missing privileges and unsafe policy.
pub fn apply_local_install(command: LocalInstallCommand) -> Result<(), NativeError> {
    #[cfg(windows)]
    {
        windows::apply(command)
    }
    #[cfg(not(windows))]
    {
        let _ = command;
        Err(NativeError::UnsupportedPlatform)
    }
}

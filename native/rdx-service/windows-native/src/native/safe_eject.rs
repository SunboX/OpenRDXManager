// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed safe-eject preparation; reachable only from retained safe volume leases.

use windows::Win32::System::Ioctl::{IOCTL_STORAGE_MEDIA_REMOVAL, PREVENT_MEDIA_REMOVAL};

use super::{
    DeviceIoControl, NativeDevice, NativeError, NativeVolumeLease, VolumeMutationOutcome,
    execute_buffered, kernel_handle, map_windows_error, size_of,
};
use crate::safe_eject::{
    SafeEjectIo, SafeEjectStep, allow_device_removal_request, run_prepared_safe_eject,
    validate_allow_device_removal,
};

/// Borrows, rather than releases, the disk and volume locks through all three steps.
struct PreparedEjectIo<'a> {
    device: &'a NativeDevice,
    leases: &'a [NativeVolumeLease],
}

impl SafeEjectIo for PreparedEjectIo<'_> {
    /// Refuses stale disk or volume authority immediately before every step.
    fn revalidate(&mut self) -> Result<(), NativeError> {
        let result = self.device.revalidate_volume_leases(self.leases);
        if result.is_err() {
            eprintln!("openrdx-hardware: trace windows-safe-eject-binding-failed");
        }
        result
    }

    /// Executes exactly one fixed step with bounded, identifier-free diagnostics.
    fn execute(&mut self, step: SafeEjectStep) -> Result<(), NativeError> {
        let result = match step {
            SafeEjectStep::AllowWindowsRemoval => allow_windows_removal(self.device),
            SafeEjectStep::AllowDeviceRemoval => {
                let completion = execute_buffered(
                    kernel_handle(&self.device.handle),
                    allow_device_removal_request(),
                );
                validate_allow_device_removal(completion)
            }
            SafeEjectStep::Eject => match self.device.eject_media() {
                VolumeMutationOutcome::Succeeded => Ok(()),
                VolumeMutationOutcome::NotAttempted(error)
                | VolumeMutationOutcome::CompletionUnknown(error) => Err(error),
            },
        };
        // Only fixed allowlisted breadcrumbs survive the main-process filter.
        // Retain the causal step even if departure readback later times out;
        // never expose identities, paths, raw sense, or payloads.
        let code = match (step, result.is_ok()) {
            (SafeEjectStep::AllowWindowsRemoval, true) => "windows-safe-eject-allow-os-succeeded",
            (SafeEjectStep::AllowWindowsRemoval, false) => "windows-safe-eject-allow-os-failed",
            (SafeEjectStep::AllowDeviceRemoval, true) => {
                "windows-safe-eject-allow-device-succeeded"
            }
            (SafeEjectStep::AllowDeviceRemoval, false) => "windows-safe-eject-allow-device-failed",
            (SafeEjectStep::Eject, true) => "windows-safe-eject-ioctl-succeeded",
            (SafeEjectStep::Eject, false) => "windows-safe-eject-ioctl-failed",
        };
        eprintln!("openrdx-hardware: trace {code}");
        result
    }
}

/// Clears only the Windows removal lock on the retained selected disk handle.
fn allow_windows_removal(device: &NativeDevice) -> Result<(), NativeError> {
    let request = PREVENT_MEDIA_REMOVAL {
        PreventMediaRemoval: false,
    };
    let mut returned = 0_u32;
    // SAFETY: the retained exact handle, initialized one-byte request, and
    // returned-count storage remain live through this synchronous no-output call.
    unsafe {
        DeviceIoControl(
            kernel_handle(&device.handle),
            IOCTL_STORAGE_MEDIA_REMOVAL,
            Some((&raw const request).cast()),
            size_of::<PREVENT_MEDIA_REMOVAL>() as u32,
            None,
            0,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error)?;
    if returned != 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(())
}

impl NativeDevice {
    /// Prepares normal safe eject after the caller has dismounted or proven no mounts.
    /// The caller retains the exact leases; force eject never calls this method.
    pub(crate) fn prepared_safe_eject(
        &self,
        leases: &[NativeVolumeLease],
    ) -> VolumeMutationOutcome {
        run_prepared_safe_eject(&mut PreparedEjectIo {
            device: self,
            leases,
        })
    }
}

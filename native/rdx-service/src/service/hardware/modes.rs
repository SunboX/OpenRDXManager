// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact retained-lease page-0x34 configuration execution.

use super::*;

impl<B: PlatformBackend> HardwareWorker<B> {
    /// Executes a page-0x34 setter on one retained lease, then rediscovers and verifies it.
    pub(super) fn execute_mode_operation(
        &mut self,
        request: &OperationRequest,
        observer: &mut HostWorkerObserver<'_>,
    ) -> Result<(), HostOperationFailure> {
        if !observer.reached("device-configuring", false) {
            return Err(cancelled_host_failure("device-configuring"));
        }
        let (device_id, revision) = operation_target(request).expect("mode request has a target");
        let mut resolved = self
            .registry
            .resolve(&mut self.platform, device_id, revision)
            .map_err(|_| {
                HostOperationFailure::preflight(
                    "device-configuring",
                    HostPrimitiveError::StaleBinding,
                )
            })?;
        let (mutation, expected) = match request {
            OperationRequest::DriveModeSet { mode, .. } => (
                configure_registry_drive_mode(&mut resolved, *mode)?,
                match mode {
                    crate::model::DriveMode::Removable => 1,
                    crate::model::DriveMode::Fixed => 2,
                },
            ),
            OperationRequest::SataModeSet { mode, .. } => (
                configure_registry_sata_mode(&mut resolved, *mode)?,
                match mode {
                    crate::model::SataMode::OnePointFiveGThreeG => 2,
                    crate::model::SataMode::ThreeGSixG => 3,
                },
            ),
            _ => {
                return Err(HostOperationFailure::preflight(
                    "device-configuring",
                    HostPrimitiveError::Other,
                ));
            }
        };
        let requires_reconnect = mutation.requires_reconnect();
        let primary_failure = mutation.into_failure();
        drop(resolved);
        if !observer.reached("device-reconnecting", false) {
            return Err(cancelled_host_failure("device-reconnecting"));
        }
        let rebound_revision = if requires_reconnect {
            let mut rebound = None;
            for _ in 0..15 {
                if let Ok(report) = self.scan_devices()
                    && let Some(snapshot) = report
                        .snapshots()
                        .iter()
                        .find(|snapshot| &snapshot.id == device_id)
                {
                    rebound = Some(snapshot.revision);
                    break;
                }
            }
            rebound.ok_or_else(|| {
                primary_failure.clone().unwrap_or_else(|| {
                    HostOperationFailure::preflight(
                        "device-reconnecting",
                        HostPrimitiveError::StaleBinding,
                    )
                })
            })?
        } else {
            revision
        };
        if !observer.reached("device-readback", false) {
            return Err(cancelled_host_failure("device-readback"));
        }
        let mut rebound = self
            .registry
            .resolve(&mut self.platform, device_id, rebound_revision)
            .map_err(|_| {
                primary_failure.clone().unwrap_or_else(|| {
                    HostOperationFailure::preflight(
                        "device-readback",
                        HostPrimitiveError::StaleBinding,
                    )
                })
            })?;
        let readback = verify_registry_mode(&mut rebound, operation_kind(request), expected);
        primary_failure.map_or(readback, Err)
    }
}

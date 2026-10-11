// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authoritative discovery inventory installation and public list projection.

use serde_json::{Value, json};

use crate::model::DeviceSnapshot;
use crate::platform::ValidatedDiscoveryReport;

use super::contract::{action_failure, action_success, validate_inventory};
use super::{
    MAX_SAFE_JSON_INTEGER, ScanResult, ServiceBackend, ServiceProtocolError, ServiceRejection,
    ServiceRuntime,
};

impl<B: ServiceBackend> ServiceRuntime<B> {
    /// Returns a revision-stable full discovery list.
    pub(super) fn list_devices(&mut self) -> Result<Value, ServiceProtocolError> {
        match self.backend.list_devices() {
            Ok(devices) => {
                self.install_inventory(devices, false)?;
                let mut result = json!({
                    "ok": true,
                    "listRevision": self.list_revision,
                    "devices": self.devices
                });
                self.attach_discovery_diagnostics(&mut result);
                Ok(result)
            }
            Err(error) => Ok(action_failure(error.as_str())),
        }
    }

    /// Performs one bounded scan and emits the exact list event before its response.
    pub(super) fn scan_devices(&mut self) -> Result<ScanResult, ServiceProtocolError> {
        match self.refresh_inventory()? {
            Ok(()) => {
                let mut event = json!({
                    "type": "event",
                    "channel": "device",
                    "event": {
                        "type": "list",
                        "listRevision": self.list_revision,
                        "devices": self.devices
                    }
                });
                self.attach_discovery_diagnostics(
                    event.get_mut("event").expect("trusted event envelope"),
                );
                Ok(ScanResult {
                    event: Some(event),
                    result: action_success(),
                })
            }
            Err(error) => Ok(ScanResult {
                event: None,
                result: action_failure(error.as_str()),
            }),
        }
    }

    /// Refreshes and validates one complete inventory without wire serialization.
    pub(super) fn refresh_inventory(
        &mut self,
    ) -> Result<Result<(), ServiceRejection>, ServiceProtocolError> {
        if self.active.is_some() {
            return Ok(Err(super::service_rejection("operation-in-progress")));
        }
        let report = match self.backend.scan_report() {
            Ok(report) => report,
            Err(error) => return Ok(Err(error)),
        };
        self.discovery_diagnostics = report.diagnostics().clone();
        let devices = report.into_snapshots();
        self.install_inventory(devices, true)?;
        Ok(Ok(()))
    }

    /// Installs one worker-owned refresh and builds its ordered public list event.
    pub(super) fn install_operation_inventory(
        &mut self,
        report: ValidatedDiscoveryReport,
    ) -> Result<Value, ServiceProtocolError> {
        self.discovery_diagnostics = report.diagnostics().clone();
        self.install_inventory(report.into_snapshots(), true)?;
        self.backend
            .commit_operation_inventory(&self.devices)
            .map_err(|_| ServiceProtocolError::BackendContract)?;
        let mut event = json!({
            "type": "event",
            "channel": "device",
            "event": {
                "type": "list",
                "listRevision": self.list_revision,
                "devices": self.devices
            }
        });
        self.attach_discovery_diagnostics(event.get_mut("event").expect("trusted event envelope"));
        Ok(event)
    }

    /// Adds diagnostics only after a pass saw candidates, preserving v1 empty-list frames.
    fn attach_discovery_diagnostics(&self, value: &mut Value) {
        if self.discovery_diagnostics.candidate_count() > 0 {
            value
                .as_object_mut()
                .expect("trusted discovery result is an object")
                .insert(
                    "diagnostics".to_owned(),
                    serde_json::to_value(&self.discovery_diagnostics)
                        .expect("bounded diagnostics serialize"),
                );
        }
    }

    /// Validates and installs one complete backend inventory.
    fn install_inventory(
        &mut self,
        devices: Vec<DeviceSnapshot>,
        advance_revision: bool,
    ) -> Result<(), ServiceProtocolError> {
        validate_inventory(&devices, self.descriptor.mode)?;
        if advance_revision {
            self.list_revision = self
                .list_revision
                .checked_add(1)
                .filter(|revision| *revision <= MAX_SAFE_JSON_INTEGER)
                .ok_or(ServiceProtocolError::BackendContract)?;
        } else if self.inventory_initialized && devices != self.devices {
            return Err(ServiceProtocolError::BackendContract);
        }
        self.devices = devices;
        self.inventory_initialized = true;
        Ok(())
    }
}

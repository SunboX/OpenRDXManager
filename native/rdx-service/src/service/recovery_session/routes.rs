// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict framed recovery routes, separated from the ordinary operation vocabulary.

use super::super::messages::EmptyPayload;
use super::super::{
    ServiceBackend, ServiceProtocolError, ServiceRuntime, action_failure, parse_payload,
};
use serde::Deserialize;
use serde_json::Value;

/// Exact explicit association of an existing unit profile and a current physical dock.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartPayload {
    bundle_id: String,
    target_token: String,
    acknowledged: bool,
}

/// Closed gate name; caller-selected phases cannot authorize native continuation.
#[derive(Deserialize)]
enum Stage {
    #[serde(rename = "recovery-awaiting-power-cycle")]
    PowerCycle,
}

/// Exact one-use fresh operator acknowledgment tied to the active attempt.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContinuePayload {
    attempt_id: String,
    stage: Stage,
    acknowledged: bool,
}

impl<B: ServiceBackend> ServiceRuntime<B> {
    /// Routes strict recovery payloads before admitting any ordinary hardware request.
    pub(in crate::service) fn handle_recovery_request(
        &mut self,
        method: &str,
        payload: Value,
    ) -> Result<Value, ServiceProtocolError> {
        match method {
            "recovery-list" => {
                parse_payload::<EmptyPayload>(payload)?;
                Ok(self.recovery.list())
            }
            "recovery-status" => {
                parse_payload::<EmptyPayload>(payload)?;
                Ok(self.recovery.status())
            }
            "recovery-start" => {
                let payload = parse_payload::<StartPayload>(payload)?;
                if self.recovery.is_active() {
                    return Ok(action_failure("recovery-in-progress"));
                }
                if self.active.is_some() {
                    return Ok(action_failure("operation-in-progress"));
                }
                if let Err(error) = self.backend.require_recovery_idle() {
                    return Ok(action_failure(error.as_str()));
                }
                Ok(self.recovery.start(
                    payload.bundle_id,
                    payload.target_token,
                    payload.acknowledged,
                ))
            }
            "recovery-continue" => {
                let payload = parse_payload::<ContinuePayload>(payload)?;
                let Stage::PowerCycle = payload.stage;
                Ok(self
                    .recovery
                    .acknowledge(&payload.attempt_id, payload.acknowledged))
            }
            _ => Err(ServiceProtocolError::ProtocolViolation),
        }
    }
}

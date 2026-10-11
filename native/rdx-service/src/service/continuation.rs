// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-owner, single-use acknowledgments for the two firmware power-cycle stages.

use super::{OperationKind, ServiceBackend, ServiceProtocolError, ServiceRuntime, action_failure};
use crate::model::OperationId;
use serde::Deserialize;
use serde_json::{Value, json};

/// Closed operator checkpoints; no arbitrary stage can cross the service boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(super) enum ContinuationStage {
    /// First acknowledgment, before ROM discovery or programming.
    #[serde(rename = "firmware-awaiting-bootloader")]
    Bootloader,
    /// Second acknowledgment, before bootstrap receiver probing.
    #[serde(rename = "firmware-awaiting-bootstrap")]
    Bootstrap,
}

impl ContinuationStage {
    /// Parses only the two explicit operator checkpoints.
    pub(super) fn parse(stage: &str) -> Option<Self> {
        match stage {
            "firmware-awaiting-bootloader" => Some(Self::Bootloader),
            "firmware-awaiting-bootstrap" => Some(Self::Bootstrap),
            _ => None,
        }
    }

    /// Returns the stable service/UI spelling.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Bootloader => "firmware-awaiting-bootloader",
            Self::Bootstrap => "firmware-awaiting-bootstrap",
        }
    }
}

/// Strict acknowledgment payload with no reusable token or additional authority.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ContinuePayload {
    /// Exact active operation owner; an acknowledgment cannot change it.
    pub(super) operation_id: OperationId,
    /// One closed power-cycle checkpoint, never an arbitrary operation stage.
    pub(super) stage: ContinuationStage,
}

impl<B: ServiceBackend> ServiceRuntime<B> {
    /// Accepts one exact active-stage acknowledgment while preserving the operation lock.
    pub(super) fn continue_operation(
        &mut self,
        operation_id: OperationId,
        stage: ContinuationStage,
    ) -> Result<Value, ServiceProtocolError> {
        if !super::valid_operation_id(&operation_id) {
            return Err(ServiceProtocolError::ProtocolViolation);
        }
        if self.descriptor.mode == super::ServiceMode::NoDevice {
            return Ok(action_failure("transport-unavailable"));
        }
        let Some(active) = self.active.as_mut() else {
            return Ok(action_failure("operation-not-found"));
        };
        if active.operation_id != operation_id {
            return Ok(action_failure("operation-not-found"));
        }
        let (required, accepted) = match stage {
            ContinuationStage::Bootloader => (0, 1),
            ContinuationStage::Bootstrap => (1, 3),
        };
        if active.kind != OperationKind::FirmwareUpdate
            || active.stage != stage.as_str()
            || active.phase != super::OperationPhase::Running
            || !active.operation_released
            || active.cancellation_requested
            || !active.cancellation_closed
            || active.continued_stages != required
        {
            return Ok(action_failure("operation-not-continuable"));
        }
        match self
            .backend
            .continue_operation(&operation_id, stage.as_str())
        {
            Ok(()) => {
                // Keep the stage and exclusive operation reservation intact; only
                // native worker observations may advance the lifecycle afterward.
                active.continued_stages = accepted;
                Ok(json!({"ok":true, "operationId":operation_id}))
            }
            Err(error) => Ok(action_failure(error.as_str())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DeviceId, DeviceSnapshot, DiscoveryRevision, FirmwareFileToken, OperationRequest,
    };
    use crate::service::{
        ActiveOperation, OperationPhase, ServiceDescriptor, ServiceEventSink, ServicePlatform,
        ServiceRejection,
    };

    /// Records only high-level continuation calls; this fixture has no hardware.
    struct Backend {
        accepted: usize,
        reject: bool,
    }

    impl ServiceBackend for Backend {
        /// Supplies a native descriptor for this wholly synthetic control fixture.
        fn descriptor(&self) -> ServiceDescriptor {
            ServiceDescriptor::native_available(ServicePlatform::Darwin, "continuation-test")
                .unwrap()
        }
        /// Supplies no device or private path data.
        fn list_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
            Ok(vec![])
        }
        /// Performs no discovery while testing acknowledgment dispatch.
        fn scan_devices(&mut self) -> Result<Vec<DeviceSnapshot>, ServiceRejection> {
            Ok(vec![])
        }
        /// Leaves admission to the explicit synthetic reservation helper.
        fn start_operation(
            &mut self,
            _: OperationId,
            _: OperationRequest,
            _: ServiceEventSink,
        ) -> Result<(), ServiceRejection> {
            Ok(())
        }
        /// Detects accidental cancellation on the continuation path.
        fn cancel_operation(&mut self, _: &OperationId) -> Result<(), ServiceRejection> {
            panic!("continuation cannot cancel")
        }
        /// Counts only high-level acknowledgments without touching hardware.
        fn continue_operation(&mut self, _: &OperationId, _: &str) -> Result<(), ServiceRejection> {
            if self.reject {
                return Err(crate::service::service_rejection(
                    "operation-not-continuable",
                ));
            }
            self.accepted += 1;
            Ok(())
        }
        /// Supports trait teardown without performing cleanup operations.
        fn shutdown(&mut self) -> Result<(), ServiceRejection> {
            Ok(())
        }
    }

    /// Sets a synthetic active firmware reservation at a published waiting stage.
    fn runtime() -> ServiceRuntime<Backend> {
        let (sender, _receiver) = std::sync::mpsc::sync_channel(8);
        let sink = ServiceEventSink::new(sender, crate::service::crash::CrashAdmission::new());
        let mut runtime = ServiceRuntime::new(
            Backend {
                accepted: 0,
                reject: false,
            },
            sink,
        );
        runtime.handshaken = true;
        let request = OperationRequest::FirmwareUpdate {
            device_id: DeviceId::new("rdx:continuation").unwrap(),
            device_revision: DiscoveryRevision::new(1).unwrap(),
            firmware_file_token: FirmwareFileToken::new("firmware:continuation").unwrap(),
        };
        let mut active =
            ActiveOperation::new(OperationId::new("op:continuation").unwrap(), &request).unwrap();
        active.phase = OperationPhase::Running;
        active.operation_released = true;
        active.stage = "firmware-awaiting-bootloader".into();
        active.cancellation_closed = true;
        runtime.active = Some(active);
        runtime
    }

    /// Uses the actual strict request envelope, with monotonic identifiers.
    fn send(
        runtime: &mut ServiceRuntime<Backend>,
        payload: Value,
    ) -> Result<Value, ServiceProtocolError> {
        let request = json!({"type":"request", "protocolVersion":1,
            "requestId":format!("request:{}", runtime.last_request_id+1), "method":"operation-continue", "payload":payload});
        let (frames, stopped) = runtime.handle_message(request)?;
        assert!(!stopped);
        Ok(frames[0]["result"].clone())
    }

    /// One current-stage acknowledgment preserves ownership and rejects duplicates.
    #[test]
    fn continuation_protocol_accepts_exact_owner_and_stage_once_without_releasing_lock() {
        let mut runtime = runtime();
        let payload =
            json!({"operationId":"op:continuation", "stage":"firmware-awaiting-bootloader"});
        assert_eq!(
            send(&mut runtime, payload.clone()).unwrap(),
            json!({"ok":true,"operationId":"op:continuation"})
        );
        assert_eq!(
            send(&mut runtime, payload).unwrap(),
            json!({"ok":false,"reason":"operation-not-continuable"})
        );
        assert_eq!(runtime.backend.accepted, 1);
        assert!(runtime.active.as_ref().unwrap().cancellation_closed);
        assert_eq!(
            runtime.active.as_ref().unwrap().stage,
            "firmware-awaiting-bootloader"
        );
        runtime.active.as_mut().unwrap().stage = "firmware-awaiting-bootstrap".into();
        assert_eq!(
            send(
                &mut runtime,
                json!({"operationId":"op:continuation","stage":"firmware-awaiting-bootstrap"})
            )
            .unwrap()["ok"],
            true
        );
        assert_eq!(runtime.backend.accepted, 2);
        assert!(runtime.active.is_some());
    }

    /// Stale or foreign requests never reach the accepting synthetic backend.
    #[test]
    fn continuation_protocol_rejects_foreign_stale_and_wrong_stage_before_backend() {
        let mut runtime = runtime();
        for payload in [
            json!({"operationId":"op:foreign","stage":"firmware-awaiting-bootloader"}),
            json!({"operationId":"op:continuation","stage":"firmware-awaiting-bootstrap"}),
        ] {
            assert_eq!(send(&mut runtime, payload).unwrap()["ok"], false);
        }
        runtime.active.as_mut().unwrap().kind = OperationKind::SelfTest;
        let payload =
            json!({"operationId":"op:continuation","stage":"firmware-awaiting-bootloader"});
        assert_eq!(send(&mut runtime, payload.clone()).unwrap()["ok"], false);
        runtime.active = None;
        assert_eq!(
            send(&mut runtime, payload).unwrap(),
            json!({"ok":false,"reason":"operation-not-found"})
        );
        assert_eq!(runtime.backend.accepted, 0);
    }

    /// Additional, absent or arbitrary fields fail the actual strict wire parser.
    #[test]
    fn continuation_payload_rejects_extra_missing_and_arbitrary_stage_fields() {
        for payload in [
            json!({"operationId":"op:continuation","stage":"firmware-resetting"}),
            json!({"operationId":"op:continuation","stage":"firmware-awaiting-bootloader","skip":true}),
            json!({"operationId":"op:continuation"}),
            json!({"stage":"firmware-awaiting-bootloader"}),
            json!({"operationId":"op:continuation","stage":null}),
        ] {
            assert!(matches!(
                send(&mut runtime(), payload),
                Err(ServiceProtocolError::ProtocolViolation)
            ));
        }
    }

    /// A backend rejection does not falsely consume runtime authority.
    #[test]
    fn continuation_backend_rejection_does_not_consume_runtime_checkpoint() {
        let mut runtime = runtime();
        runtime.backend.reject = true;
        let payload =
            json!({"operationId":"op:continuation","stage":"firmware-awaiting-bootloader"});
        assert_eq!(send(&mut runtime, payload.clone()).unwrap()["ok"], false);
        runtime.backend.reject = false;
        assert_eq!(send(&mut runtime, payload).unwrap()["ok"], true);
    }

    /// Admission requires the causal lifecycle and the preceding acknowledgment.
    #[test]
    fn continuation_cannot_skip_first_stage_or_ack_unreleased_or_cancellable_work() {
        for mutate in [
            (|active: &mut ActiveOperation| active.stage = "firmware-awaiting-bootstrap".into())
                as fn(&mut ActiveOperation),
            |active| active.operation_released = false,
            |active| active.phase = OperationPhase::Accepted,
            |active| active.cancellation_closed = false,
            |active| active.cancellation_requested = true,
        ] {
            let mut runtime = runtime();
            mutate(runtime.active.as_mut().unwrap());
            let stage = runtime.active.as_ref().unwrap().stage.clone();
            assert_eq!(
                send(
                    &mut runtime,
                    json!({"operationId":"op:continuation","stage":stage})
                )
                .unwrap()["ok"],
                false
            );
            assert_eq!(runtime.backend.accepted, 0);
        }
    }
}

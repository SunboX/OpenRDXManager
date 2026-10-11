// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact operation-stage graphs used by progress event validation.

use crate::model::OperationKind;

use super::OperationStage;

/// Returns the exact native subset of the Phase 1 per-kind stage graph.
pub(super) fn operation_graph(kind: OperationKind) -> Option<&'static [OperationStage]> {
    const SELF_TEST: &[OperationStage] = &[
        OperationStage::DiagnosticRunning,
        OperationStage::DiagnosticCleanup,
    ];
    const LED_TEST: &[OperationStage] = &[
        OperationStage::LedTesting,
        OperationStage::LedRestoring,
        OperationStage::LedReadback,
    ];
    const FIRMWARE_UPDATE: &[OperationStage] = &[
        OperationStage::FirmwareValidating,
        OperationStage::FirmwareCapturing,
        OperationStage::FirmwareCompatibilitySetup,
        OperationStage::FirmwareStaging,
        OperationStage::FirmwareAwaitingBootloader,
        OperationStage::FirmwareProgrammingBootstrap,
        OperationStage::FirmwareAwaitingBootstrap,
        OperationStage::FirmwareRestoringIdentity,
        OperationStage::FirmwareWriting,
        OperationStage::FirmwareFinalizing,
        OperationStage::DeviceReconnecting,
        OperationStage::FirmwareReadback,
    ];
    const DEVICE_CONFIGURATION: &[OperationStage] = &[
        OperationStage::DeviceConfiguring,
        OperationStage::DeviceReconnecting,
        OperationStage::DeviceReadback,
    ];
    const EJECT_SAFE: &[OperationStage] = &[
        OperationStage::HostUnmounting,
        OperationStage::HostEjecting,
        OperationStage::EjectReadback,
    ];
    const EJECT_FORCE: &[OperationStage] =
        &[OperationStage::HostEjecting, OperationStage::EjectReadback];
    match kind {
        OperationKind::SelfTest => Some(SELF_TEST),
        OperationKind::LedTest => Some(LED_TEST),
        OperationKind::FirmwareUpdate => Some(FIRMWARE_UPDATE),
        OperationKind::DriveModeSet | OperationKind::SataModeSet => Some(DEVICE_CONFIGURATION),
        OperationKind::EjectSafe => Some(EJECT_SAFE),
        OperationKind::EjectForce => Some(EJECT_FORCE),
        _ => None,
    }
}

/// Accepts adjacent phases plus the two explicit direct-update branches.
pub(super) fn is_stage_transition_allowed(
    kind: OperationKind,
    current: OperationStage,
    next: OperationStage,
) -> bool {
    if kind == OperationKind::FirmwareUpdate
        && ((current == OperationStage::FirmwareValidating
            && next == OperationStage::FirmwareWriting)
            || (current == OperationStage::FirmwareWriting
                && next == OperationStage::DeviceReconnecting))
    {
        return true;
    }
    let Some(graph) = operation_graph(kind) else {
        return false;
    };
    let Some(current_index) = graph.iter().position(|stage| *stage == current) else {
        return false;
    };
    let Some(next_index) = graph.iter().position(|stage| *stage == next) else {
        return false;
    };
    next_index >= current_index && next_index <= current_index + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps both native progress publishers on the explicit first-install route.
    #[test]
    fn firmware_installation_stage_vocabulary_is_complete() {
        let stages: Vec<_> = operation_graph(OperationKind::FirmwareUpdate)
            .unwrap()
            .iter()
            .map(|stage| stage.as_str())
            .collect();
        assert_eq!(
            stages,
            [
                "firmware-validating",
                "firmware-capturing",
                "firmware-compatibility-setup",
                "firmware-staging",
                "firmware-awaiting-bootloader",
                "firmware-programming-bootstrap",
                "firmware-awaiting-bootstrap",
                "firmware-restoring-identity",
                "firmware-writing",
                "firmware-finalizing",
                "device-reconnecting",
                "firmware-readback",
            ]
        );
    }

    /// Ordinary updates bypass installation, while entered installation cannot skip a boundary.
    #[test]
    fn firmware_installation_transitions_preserve_the_direct_update_branch() {
        let kind = OperationKind::FirmwareUpdate;
        let graph = operation_graph(kind).unwrap();
        for (index, current) in graph.iter().copied().enumerate() {
            for (next_index, next) in graph.iter().copied().enumerate() {
                let direct = (current == OperationStage::FirmwareValidating
                    && next == OperationStage::FirmwareWriting)
                    || (current == OperationStage::FirmwareWriting
                        && next == OperationStage::DeviceReconnecting);
                assert_eq!(
                    is_stage_transition_allowed(kind, current, next),
                    next_index == index || next_index == index + 1 || direct,
                    "{} -> {}",
                    current.as_str(),
                    next.as_str()
                );
            }
        }
    }
}

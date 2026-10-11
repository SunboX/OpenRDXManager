// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic sequence tests never construct a native backend or read real bundles.

use super::*;

#[derive(Default)]
struct Observer;

impl RecoveryObserver for Observer {
    fn reached(&mut self, _: RecoveryStage) -> Result<(), RecoveryError> {
        Ok(())
    }
    fn operator_acknowledged(&mut self) -> Result<bool, RecoveryError> {
        Ok(true)
    }
}

#[derive(Default)]
struct Attempt {
    calls: Vec<&'static str>,
    events: Vec<MigrationEvent>,
    fail: Option<&'static str>,
    fail_journal: Option<MigrationEvent>,
}

impl Attempt {
    fn call(&mut self, value: &'static str) -> Result<(), RecoveryError> {
        self.calls.push(value);
        if self.fail == Some(value) {
            Err(RecoveryError::RomOperationUnknown)
        } else {
            Ok(())
        }
    }
}

impl RecoveryAttempt for Attempt {
    fn journal(&mut self, event: MigrationEvent) -> Result<(), RecoveryError> {
        self.events.push(event);
        if self.fail_journal == Some(event) {
            Err(RecoveryError::StorageUnavailable)
        } else {
            Ok(())
        }
    }
    fn identify_rom(&mut self) -> Result<(), RecoveryError> {
        self.call("identify")
    }
    fn setup_rom(&mut self) -> Result<(), RecoveryError> {
        self.call("setup")
    }
    fn program_rom(&mut self) -> Result<(), RecoveryError> {
        self.call("program")
    }
    fn reset_rom(&mut self) -> Result<(), RecoveryError> {
        self.call("reset")
    }
    fn release_rom(&mut self) {
        self.calls.push("release")
    }
    fn arm_power_cycle(&mut self) -> Result<(), RecoveryError> {
        self.call("arm-power-cycle")
    }
    fn await_application(&mut self, _: &mut dyn RecoveryObserver) -> Result<(), RecoveryError> {
        self.call("operator-and-usb")
    }
    fn finish_release(&mut self, _: &mut dyn RecoveryObserver) -> Result<(), RecoveryError> {
        self.call("verify-and-final-update")
    }
}

/// All required success steps occur once, with a journal before each ROM mutation.
#[test]
fn successful_recovery_has_one_ordered_attempt() {
    let mut attempt = Attempt::default();
    assert_eq!(
        run_sequence(&mut attempt, &mut Observer),
        Ok(RecoveryOutcome::FinalReleaseVerified)
    );
    assert_eq!(
        attempt.calls,
        [
            "identify",
            "setup",
            "program",
            "reset",
            "release",
            "arm-power-cycle",
            "operator-and-usb",
            "verify-and-final-update"
        ]
    );
    assert_eq!(
        attempt.events,
        [
            MigrationEvent::RomObserved,
            MigrationEvent::RomSetupDispatching,
            MigrationEvent::RomSetupAccepted,
            MigrationEvent::RomTransferDispatching,
            MigrationEvent::RomTransferComplete,
            MigrationEvent::RomResetDispatching,
            MigrationEvent::RomResetAccepted,
            MigrationEvent::AwaitingBootstrapPowerCycle
        ]
    );
}

/// Every ambiguous operation stops without retry, reset cleanup or final transfer.
#[test]
fn each_operation_failure_stops_at_its_boundary() {
    for step in [
        "identify",
        "setup",
        "program",
        "reset",
        "arm-power-cycle",
        "operator-and-usb",
        "verify-and-final-update",
    ] {
        let mut attempt = Attempt {
            fail: Some(step),
            ..Attempt::default()
        };
        assert!(run_sequence(&mut attempt, &mut Observer).is_err());
        assert_eq!(attempt.calls.last(), Some(&step));
        assert_eq!(
            attempt.events.last(),
            Some(&MigrationEvent::RecoveryRequired)
        );
        assert_eq!(
            attempt.calls.iter().filter(|call| **call == step).count(),
            1
        );
    }
}

/// Journal failures prohibit the operation whose intent could not be persisted.
#[test]
fn journal_failure_blocks_the_next_mutation() {
    for (event, forbidden) in [
        (MigrationEvent::RomSetupDispatching, "setup"),
        (MigrationEvent::RomTransferDispatching, "program"),
        (MigrationEvent::RomResetDispatching, "reset"),
    ] {
        let mut attempt = Attempt {
            fail_journal: Some(event),
            ..Attempt::default()
        };
        assert_eq!(
            run_sequence(&mut attempt, &mut Observer),
            Err(RecoveryError::StorageUnavailable)
        );
        assert!(!attempt.calls.contains(&forbidden));
    }
}

/// The single-attempt final transfer must never finalize or retry a failed chunk.
#[test]
fn every_final_transfer_failure_stops_without_activation_or_retry() {
    use crate::transport::{CommandDispatch, TransportError, TransportResponse};
    let (bytes, metadata) = crate::firmware::openrdx_test_image();
    let image = crate::firmware::FirmwareImage::from_openrdx_bytes(bytes, &metadata).unwrap();
    for failure in 0..17 {
        let mut commands = Vec::new();
        let mut events = Vec::new();
        let result = transfer_once(
            &image,
            &mut |command| {
                commands.push(command.cdb().to_vec());
                if commands.len() - 1 == failure {
                    CommandDispatch::CompletionUnknown(TransportError::DeviceRemoved)
                } else {
                    CommandDispatch::Succeeded(TransportResponse::new(Vec::new()).unwrap())
                }
            },
            &mut |event| {
                events.push(event);
                Ok(())
            },
            &mut Observer,
        );
        assert_eq!(result, Err(RecoveryError::FinalUpdateUnknown));
        assert_eq!(commands.len(), failure + 1);
        assert!(commands[..failure.min(16)].iter().all(|cdb| cdb[1] == 4));
        assert!(!events.contains(&MigrationEvent::FinalActivationAccepted));
        if failure < 16 {
            assert!(commands.iter().all(|cdb| cdb[1] == 4));
        }
    }
}

/// Mode05 follows exactly16 successful chunks and separately durable commit intent.
#[test]
fn final_transfer_uses_normal_exact_chunk_and_finalizer_contract() {
    use crate::transport::{CommandDispatch, TransportResponse};
    let (bytes, metadata) = crate::firmware::openrdx_test_image();
    let image = crate::firmware::FirmwareImage::from_openrdx_bytes(bytes, &metadata).unwrap();
    let mut commands = Vec::new();
    let mut events = Vec::new();
    transfer_once(
        &image,
        &mut |command| {
            commands.push((command.cdb().to_vec(), command.data().len()));
            CommandDispatch::Succeeded(TransportResponse::new(Vec::new()).unwrap())
        },
        &mut |event| {
            events.push(event);
            Ok(())
        },
        &mut Observer,
    )
    .unwrap();
    assert_eq!(commands.len(), 17);
    assert_eq!(commands[15].1, 670);
    assert_eq!(
        commands[16],
        (vec![0x3b, 5, 0, 0, 0xf2, 0x9e, 0, 0, 0, 0], 0)
    );
    assert_eq!(
        events,
        [
            MigrationEvent::FinalUpdateStarted,
            MigrationEvent::FinalTransferComplete,
            MigrationEvent::FinalActivationDispatching,
            MigrationEvent::FinalActivationAccepted
        ]
    );
}

/// Malformed public arguments stop before entering platform or artifact operations.
#[test]
fn invalid_bundle_ids_are_rejected_without_hardware() {
    for value in [
        "",
        "/private/file",
        "migration-01-0",
        "migration-1-",
        "migration-X-1",
        "migration-1-0/other",
        "migration-1-0\n",
    ] {
        assert_eq!(
            recover_existing(value, &mut Observer),
            Err(RecoveryError::InvalidArguments)
        );
        assert_eq!(
            verify_existing_records(value),
            Err(RecoveryError::InvalidArguments)
        );
    }
    assert!(valid_bundle_id("migration-0-0"));
    assert!(valid_bundle_id("migration-abcdef-123"));
}

/// A failed observer stops before a setup whose progress could not be presented.
#[test]
fn failed_progress_cannot_trigger_the_next_mutation() {
    struct FailedObserver;
    impl RecoveryObserver for FailedObserver {
        fn reached(&mut self, stage: RecoveryStage) -> Result<(), RecoveryError> {
            if stage == RecoveryStage::SettingUpRom {
                Err(RecoveryError::ObserverUnavailable)
            } else {
                Ok(())
            }
        }
        fn operator_acknowledged(&mut self) -> Result<bool, RecoveryError> {
            panic!("not reached")
        }
    }
    let mut attempt = Attempt::default();
    assert_eq!(
        run_sequence(&mut attempt, &mut FailedObserver),
        Err(RecoveryError::ObserverUnavailable)
    );
    assert_eq!(attempt.calls, ["identify"]);
    assert_eq!(
        attempt.events.last(),
        Some(&MigrationEvent::RecoveryRequired)
    );
}

/// Enumeration never supplies consent and an unchanged pre-prompt epoch is insufficient.
#[test]
fn power_cycle_requires_operator_and_returned_target() {
    let mut gate = PowerCycleGate::new(Some(10));
    assert!(!gate.observe(Some(10), true));
    assert!(!gate.observe(None, false));
    assert!(gate.observe(Some(11), false));

    let mut gate = PowerCycleGate::new(Some(10));
    assert!(!gate.observe(Some(11), false));
    assert!(gate.observe(Some(11), true));

    let mut gate = PowerCycleGate::new(None);
    assert!(!gate.observe(Some(11), false));
    assert!(!gate.observe(None, true));
    assert!(gate.observe(Some(11), false));
}

/// Neither accepted chunks nor visible progress can replace durable commit intent.
#[test]
fn final_journal_failure_never_dispatches_activation() {
    use crate::transport::{CommandDispatch, TransportResponse};
    let (bytes, metadata) = crate::firmware::openrdx_test_image();
    let image = crate::firmware::FirmwareImage::from_openrdx_bytes(bytes, &metadata).unwrap();
    for failure in [
        MigrationEvent::FinalUpdateStarted,
        MigrationEvent::FinalTransferComplete,
        MigrationEvent::FinalActivationDispatching,
    ] {
        let mut commands = Vec::new();
        assert_eq!(
            transfer_once(
                &image,
                &mut |command| {
                    commands.push(command.cdb().to_vec());
                    CommandDispatch::Succeeded(TransportResponse::new(Vec::new()).unwrap())
                },
                &mut |event| {
                    if event == failure {
                        Err(RecoveryError::StorageUnavailable)
                    } else {
                        Ok(())
                    }
                },
                &mut Observer,
            ),
            Err(RecoveryError::StorageUnavailable)
        );
        assert!(commands.iter().all(|cdb| cdb[1] == 4));
        if failure == MigrationEvent::FinalUpdateStarted {
            assert!(commands.is_empty());
        }
    }
}

/// The target lookup binds location and enumeration epoch, independently of receipt data.
#[test]
fn selected_route_token_changes_on_port_or_epoch_change() {
    let original = (0x0020_0000, 10);
    let moved = (0x0030_0000, 20);
    let code = |candidate: &(u32, u64)| target_token(candidate.0, candidate.1);
    assert_ne!(code(&original), code(&moved));
    assert_ne!(code(&moved), code(&(moved.0, moved.1 + 1)));
    let candidates = [original, moved];
    assert_eq!(
        select_observed_target(&candidates, &code(&moved), code),
        Ok(&moved)
    );
    assert!(select_observed_target(&[original], &code(&moved), code).is_err());
    assert!(select_observed_target(&[moved, moved], &code(&moved), code).is_err());
}

/// Invalid selections and untrusted/standalone contexts fail before native access.
#[test]
fn selected_recovery_rejects_untrusted_inputs_without_native_access() {
    for token in [
        "",
        "recovery-rom:abc",
        "recovery-rom:/path",
        "recovery-rom:UPPER",
    ] {
        let selection = RecoverySelection {
            bundle_id: "migration-1-0".into(),
            target_token: token.into(),
        };
        assert_eq!(
            recover_selected(&selection, &mut Observer),
            Err(RecoveryError::InvalidArguments)
        );
    }
    let selection = RecoverySelection {
        bundle_id: "migration-1-0".into(),
        target_token: target_token(0x0030_0000, 20),
    };
    assert!(validate_selection(&selection).is_ok());
    for context in [
        super::super::ServiceExecutionContext::development_stdio(),
        super::super::ServiceExecutionContext::authenticated_platform_endpoint(false),
        super::super::ServiceExecutionContext::privileged_direct_cli(true),
    ] {
        assert_eq!(
            recover_selected_in_service(&selection, &mut Observer, context),
            Err(RecoveryError::PrivilegeRequired)
        );
    }
    assert!(
        serde_json::from_value::<RecoverySelection>(serde_json::json!({
            "bundleId":"migration-1-0", "targetToken": selection.target_token, "serial":"override"
        }))
        .is_err()
    );
}

/// A disconnected UI cannot issue the next final chunk or a cleanup finalizer.
#[test]
fn disconnected_observer_stops_final_transfer_before_dispatch() {
    struct Disconnected;
    impl RecoveryObserver for Disconnected {
        fn reached(&mut self, _: RecoveryStage) -> Result<(), RecoveryError> {
            Ok(())
        }
        fn ensure_connected(&mut self) -> Result<(), RecoveryError> {
            Err(RecoveryError::ObserverUnavailable)
        }
        fn operator_acknowledged(&mut self) -> Result<bool, RecoveryError> {
            panic!("not reached")
        }
    }
    let (bytes, metadata) = crate::firmware::openrdx_test_image();
    let image = crate::firmware::FirmwareImage::from_openrdx_bytes(bytes, &metadata).unwrap();
    let mut events = Vec::new();
    assert_eq!(
        transfer_once(
            &image,
            &mut |_| panic!("must not dispatch"),
            &mut |event| {
                events.push(event);
                Ok(())
            },
            &mut Disconnected
        ),
        Err(RecoveryError::ObserverUnavailable)
    );
    assert_eq!(events, [MigrationEvent::FinalUpdateStarted]);
    let mut attempt = Attempt::default();
    assert_eq!(
        run_sequence(&mut attempt, &mut Disconnected),
        Err(RecoveryError::ObserverUnavailable)
    );
    assert!(attempt.calls.is_empty());
    assert_eq!(attempt.events, [MigrationEvent::RecoveryRequired]);
}

/// An operational target or duplicate-serial observation blocks every setup call.
#[test]
fn pre_erase_observation_must_be_absent_and_successful() {
    for observed in [Ok(Some(17)), Err(RecoveryError::TargetUnavailable)] {
        assert_eq!(
            setup_after_absent_application(|| observed, || panic!("must not erase")),
            Err(RecoveryError::TargetUnavailable)
        );
    }
    let calls = std::cell::RefCell::new(Vec::new());
    assert_eq!(
        setup_after_absent_application(
            || {
                calls.borrow_mut().push("observe");
                Ok(None)
            },
            || {
                calls.borrow_mut().push("setup");
                Ok(())
            }
        ),
        Ok(())
    );
    assert_eq!(calls.into_inner(), ["observe", "setup"]);
    assert_eq!(
        setup_after_absent_application(|| Ok(None), || Err(RecoveryError::RomOperationUnknown)),
        Err(RecoveryError::RomOperationUnknown)
    );
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact macOS staging evidence remains distinct from successful programming.

use rdx_service::platform::macos::{
    MacOsIoFailure, NativeScsiTaskCompletion, SCSI_SERVICE_RESPONSE_TASK_COMPLETE, build_scsi_task,
    convert_scsi_task_completion,
};
use rdx_service::protocol::write_buffer;
use rdx_service::transport::{CommandDispatch, TransportError};

/// Supplies a complete fixed-format sense fixture with no per-device data.
fn signature_sense() -> Vec<u8> {
    vec![0x70, 0, 7, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x74, 8, 0, 0, 0, 0]
}

/// Builds a literal TASK_COMPLETE/CHECK CONDITION response for the given count.
fn completion(transferred: u32) -> NativeScsiTaskCompletion {
    NativeScsiTaskCompletion::device(
        2,
        SCSI_SERVICE_RESPONSE_TASK_COMPLETE,
        transferred,
        Vec::new(),
        18,
        signature_sense(),
    )
}

/// Only the exact documented complete tail receives typed evidence, never success.
#[test]
fn compatibility_staging_signature_requires_the_complete_exact_tail() {
    let packet = build_scsi_task(&write_buffer(4, 61440, &[0; 670]).unwrap()).unwrap();
    let outcome = convert_scsi_task_completion(&packet, completion(670));
    assert_eq!(
        outcome,
        CommandDispatch::CompletionUnknown(TransportError::CompatibilityStagingSignature)
    );
    let error = outcome.error().unwrap();
    assert!(error.is_firmware_signature_rejection());
    assert!(!error.permits_firmware_retry());
    assert!(error.is_ambiguous());
    assert!(outcome.response().is_none());
    for transferred in [0, 1, 669, 671, u32::MAX] {
        assert!(matches!(
            convert_scsi_task_completion(&packet, completion(transferred)),
            CommandDispatch::CompletionUnknown(TransportError::CheckCondition(_))
        ));
    }
    for (offset, length) in [
        (0, 670),
        (61439, 670),
        (61441, 670),
        (61440, 669),
        (61440, 671),
    ] {
        let packet = build_scsi_task(&write_buffer(4, offset, &vec![0; length]).unwrap()).unwrap();
        assert!(matches!(
            convert_scsi_task_completion(&packet, completion(length as u32)),
            CommandDispatch::CompletionUnknown(TransportError::CheckCondition(_))
        ));
    }
}

/// Native failure, incomplete task completion and malformed sense cannot authorize staging.
#[test]
fn compatibility_staging_signature_rejects_other_native_completion_shapes() {
    let packet = build_scsi_task(&write_buffer(4, 61440, &[0; 670]).unwrap()).unwrap();
    let mut malformed = signature_sense();
    malformed[7] = 9;
    let mut different = signature_sense();
    different[13] = 9;
    let mut deferred = signature_sense();
    deferred[0] = 0x71;
    for response in [
        NativeScsiTaskCompletion::not_attempted(MacOsIoFailure::Busy),
        NativeScsiTaskCompletion::attempted_error(MacOsIoFailure::TimedOut),
        NativeScsiTaskCompletion::device(2, 0, 670, vec![], 18, signature_sense()),
        NativeScsiTaskCompletion::device(0, 2, 670, vec![], 18, signature_sense()),
        NativeScsiTaskCompletion::device(8, 2, 670, vec![], 18, signature_sense()),
        NativeScsiTaskCompletion::device(2, 2, 670, vec![], 0, vec![]),
        NativeScsiTaskCompletion::device(2, 2, 670, vec![], 19, signature_sense()),
        NativeScsiTaskCompletion::device(2, 2, 670, vec![], 253, vec![0; 253]),
        NativeScsiTaskCompletion::device(2, 2, 670, vec![], 18, malformed),
        NativeScsiTaskCompletion::device(2, 2, 670, vec![], 18, different),
        NativeScsiTaskCompletion::device(2, 2, 670, vec![], 18, deferred),
        NativeScsiTaskCompletion::device(2, 2, 670, vec![], 8, vec![0x73, 7, 0x74, 8, 0, 0, 0, 0]),
    ] {
        assert_ne!(
            convert_scsi_task_completion(&packet, response).error(),
            Some(&TransportError::CompatibilityStagingSignature)
        );
    }
}

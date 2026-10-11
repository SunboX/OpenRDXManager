// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cached cartridge identity must never override fresh media absence.

use crate::media_presence::require_cartridge_ready;
use crate::{Completion, NativeError, ScsiOperation};
use std::collections::VecDeque;

/// Creates one exact successful no-data readiness completion.
fn good() -> Completion {
    Completion::Device {
        status: 0,
        masked_status: 0,
        message_status: 0,
        host_status: 0,
        driver_status: 0,
        info: 0,
        residual: 0,
        data: vec![],
        sense_reported_length: 0,
        sense: vec![],
    }
}

/// Creates bounded fixed-format sense from one closed readiness observation.
fn sense(key: u8, asc: u8) -> Completion {
    let mut bytes = vec![0; 18];
    bytes[0] = 0x70;
    bytes[2] = key;
    bytes[7] = 10;
    bytes[12] = asc;
    Completion::Device {
        status: 2,
        masked_status: 1,
        message_status: 0,
        host_status: 0,
        driver_status: 8,
        info: 1,
        residual: 0,
        data: vec![],
        sense_reported_length: bytes.len(),
        sense: bytes,
    }
}

/// Reproduces an empty dock still serving a cached, well-formed VPD identity.
#[test]
fn no_media_blocks_cached_identity_without_retry() {
    let mut probes = 0;
    let failure = require_cartridge_ready(|| {
        probes += 1;
        sense(2, 0x3a)
    });
    assert!(matches!(
        failure,
        Some(Completion::Device { status: 2, .. })
    ));
    assert_eq!(probes, 1);
}

/// Insertion unit attention is consumed only through bounded read-only probes.
#[test]
fn insertion_attention_requires_a_subsequent_successful_probe() {
    let mut observations = VecDeque::from([sense(6, 0x28), good()]);
    assert!(require_cartridge_ready(|| observations.pop_front().expect("ordered probe")).is_none());
    assert!(observations.is_empty());
    let mut probes = 0;
    assert!(
        require_cartridge_ready(|| {
            probes += 1;
            sense(6, 0x28)
        })
        .is_some()
    );
    assert_eq!(probes, 3);
}

/// Removal and malformed transport evidence cannot masquerade as a loaded cartridge.
#[test]
fn transport_loss_and_unexpected_data_fail_closed() {
    assert!(
        require_cartridge_ready(|| Completion::NotAttempted(NativeError::DeviceRemoved)).is_some()
    );
    let mut result = good();
    if let Completion::Device { data, .. } = &mut result {
        data.push(0);
    }
    let mut result = Some(result);
    assert!(require_cartridge_ready(|| result.take().expect("single failed probe")).is_some());
}

/// The added readiness command is standard, no-data, and gates only cartridge VPD.
#[test]
fn readiness_is_no_data_and_only_cartridge_identity_requires_it() {
    let probe = ScsiOperation::test_unit_ready()
        .into_request()
        .expect("bounded request");
    assert_eq!(probe.cdb(), &[0; 6]);
    assert!(probe.data().is_empty());
    assert!(!probe.needs_cartridge_readiness());
    for operation in [
        ScsiOperation::inquiry_media_identification(),
        ScsiOperation::inquiry_media_device(),
    ] {
        assert!(
            operation
                .into_request()
                .expect("cartridge query")
                .needs_cartridge_readiness()
        );
    }
    assert!(
        !ScsiOperation::inquiry_standard()
            .into_request()
            .expect("dock identity")
            .needs_cartridge_readiness()
    );
}

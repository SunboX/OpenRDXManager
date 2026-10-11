// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed commands sent to the single hardware owner.

use super::*;

pub(super) enum WorkerCommand {
    ManufacturingBackup {
        request: crate::service::manufacturing::BackupRequest,
        capture: bool,
        reply: SyncSender<Result<crate::service::manufacturing::BackupInventory, ServiceRejection>>,
    },
    ManufacturingRestore {
        request: crate::service::manufacturing::RestoreRequest,
        reply: SyncSender<Result<crate::service::manufacturing::BackupInventory, ServiceRejection>>,
    },
    Scan(SyncSender<Result<ValidatedDiscoveryReport, ServiceRejection>>),
    IssueConfirmation(
        ConfirmationRequest,
        SyncSender<Result<ConfirmationToken, ServiceRejection>>,
    ),
    BeginFirmwareRegistration {
        file_token: FirmwareFileToken,
        extension: String,
        total_bytes: usize,
        open_rdx: Option<crate::firmware::OpenRdxImageMetadata>,
        reply: SyncSender<Result<(), ServiceRejection>>,
    },
    AppendFirmwareRegistration {
        file_token: FirmwareFileToken,
        offset: usize,
        bytes: Vec<u8>,
        reply: SyncSender<Result<(), ServiceRejection>>,
    },
    CommitFirmwareRegistration(FirmwareFileToken, SyncSender<Result<(), ServiceRejection>>),
    AbortFirmwareRegistration(FirmwareFileToken, SyncSender<Result<(), ServiceRejection>>),
    Prepare {
        operation_id: OperationId,
        request: OperationRequest,
        events: ServiceEventSink,
        control: Arc<OperationControl>,
        reply: SyncSender<Result<(), ServiceRejection>>,
    },
    Shutdown(SyncSender<Result<(), ServiceRejection>>),
}

/// Shared exact-operation identity and pre-dispatch release/cancellation gate.
#[derive(Clone)]
pub(super) struct ActiveHostOperation {
    pub(super) operation_id: OperationId,
    pub(super) control: Arc<OperationControl>,
}

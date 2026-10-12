// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded construction of requests before crossing the Windows FFI boundary.

use crate::{
    DataDirection, MAX_CDB_LENGTH, MAX_SENSE_LENGTH, MAX_TIMEOUT_SECONDS, MAX_TRANSFER_LENGTH,
    NativeError, ScsiRequest,
};

#[cfg(any(windows, test))]
impl ScsiRequest {
    /// Copies a trusted parent request after independently enforcing FFI bounds.
    ///
    /// # Errors
    ///
    /// Returns [`NativeError::InvalidRequest`] before FFI for any empty or
    /// oversized CDB, transfer, sense buffer, timeout, or inconsistent data phase.
    pub(super) fn new(
        cdb: &[u8],
        direction: DataDirection,
        data: Vec<u8>,
        timeout_seconds: u32,
        sense_capacity: usize,
    ) -> Result<Self, NativeError> {
        let direction_is_consistent = match direction {
            DataDirection::None => data.is_empty(),
            DataDirection::FromDevice | DataDirection::ToDevice => !data.is_empty(),
        };
        if cdb.is_empty()
            || cdb.len() > MAX_CDB_LENGTH
            || data.len() > MAX_TRANSFER_LENGTH
            || !(1..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds)
            || sense_capacity > MAX_SENSE_LENGTH
            || !direction_is_consistent
        {
            return Err(NativeError::InvalidRequest);
        }

        let mut copied_cdb = [0_u8; MAX_CDB_LENGTH];
        copied_cdb[..cdb.len()].copy_from_slice(cdb);
        Ok(Self {
            cdb: copied_cdb,
            cdb_length: cdb.len() as u8,
            direction,
            data,
            timeout_seconds,
            sense_capacity: sense_capacity as u8,
        })
    }
}

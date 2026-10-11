// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded service frame input and output helpers.

use std::io::{self, Read, Write};

use serde_json::Value;

use super::{MAX_SERVICE_FRAME_BYTES, ServiceProtocolError};

/// Reads one frame without allocating its payload before validating the prefix.
pub(super) fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Value>, ServiceProtocolError> {
    let mut header = [0_u8; 4];
    let mut header_read = 0;
    while header_read < header.len() {
        match reader.read(&mut header[header_read..]) {
            Ok(0) if header_read == 0 => return Ok(None),
            Ok(0) => return Err(ServiceProtocolError::MalformedFrame),
            Ok(read) => header_read += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ServiceProtocolError::Io),
        }
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_SERVICE_FRAME_BYTES {
        return Err(ServiceProtocolError::InvalidFrameLength);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| match error.kind() {
            io::ErrorKind::UnexpectedEof => ServiceProtocolError::MalformedFrame,
            _ => ServiceProtocolError::Io,
        })?;
    serde_json::from_slice(&payload).map_err(|_| ServiceProtocolError::MalformedFrame)
}

/// Writes and flushes one bounded JSON object frame.
pub(super) fn write_frame<W: Write>(
    writer: &mut W,
    value: &Value,
) -> Result<(), ServiceProtocolError> {
    if !value.is_object() {
        return Err(ServiceProtocolError::BackendContract);
    }
    let payload = serde_json::to_vec(value).map_err(|_| ServiceProtocolError::BackendContract)?;
    if payload.is_empty() || payload.len() > MAX_SERVICE_FRAME_BYTES {
        return Err(ServiceProtocolError::BackendContract);
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

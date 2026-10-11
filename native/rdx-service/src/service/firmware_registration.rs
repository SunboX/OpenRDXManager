// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict decoding helpers for the bounded firmware registration protocol.

use base64::Engine as _;

use super::ServiceRejection;

/// Decodes exactly one canonical non-empty 4-KiB firmware frame.
pub(super) fn decode_firmware_chunk(encoded: &str) -> Result<Vec<u8>, ServiceRejection> {
    const MAX_ENCODED_CHUNK_BYTES: usize = 5_464;
    if encoded.is_empty() || encoded.len() > MAX_ENCODED_CHUNK_BYTES || !encoded.is_ascii() {
        return Err(invalid_registration());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid_registration())?;
    if bytes.is_empty()
        || bytes.len() > 4_096
        || base64::engine::general_purpose::STANDARD.encode(&bytes) != encoded
    {
        return Err(invalid_registration());
    }
    Ok(bytes)
}

/// Creates the fixed sanitized registration rejection.
fn invalid_registration() -> ServiceRejection {
    ServiceRejection::new("firmware-registration-invalid")
        .expect("trusted registration rejection is valid")
}

#[cfg(test)]
mod tests {
    use super::decode_firmware_chunk;

    /// Canonical base64 accepts one bounded frame and rejects abuse before allocation growth.
    #[test]
    fn firmware_chunk_decoder_enforces_canonical_frame_bounds() {
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            vec![0xA5; 4_096],
        );
        assert_eq!(decode_firmware_chunk(&encoded).unwrap().len(), 4_096);
        assert!(decode_firmware_chunk("").is_err());
        assert!(decode_firmware_chunk("YQ").is_err());
        assert!(decode_firmware_chunk(&"A".repeat(5_465)).is_err());
        assert!(decode_firmware_chunk("////\n").is_err());
    }
}

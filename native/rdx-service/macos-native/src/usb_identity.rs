// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-only physical USB properties bound to an exact retained SCSI service.

use crate::{MacDevice, NativeError};

/// Actual USB ancestor properties, never a caller-supplied rematch authority.
pub struct MacUsbIdentity {
    serial: String,
    location_id: u32,
    vendor_id: u16,
    product_id: u16,
}

impl MacUsbIdentity {
    /// Encodes actual observed USB properties for the bounded private child pipe.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + self.serial.len());
        bytes.extend_from_slice(&self.location_id.to_le_bytes());
        bytes.extend_from_slice(&self.vendor_id.to_le_bytes());
        bytes.extend_from_slice(&self.product_id.to_le_bytes());
        bytes.extend_from_slice(self.serial.as_bytes());
        bytes
    }

    /// Rejects incomplete or non-ASCII identity frames received from the child.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NativeError> {
        if !(9..=8 + crate::ffi::MAX_TEXT_BYTES).contains(&bytes.len())
            || !bytes[8..].iter().all(|byte| (0x20..=0x7e).contains(byte))
        {
            return Err(NativeError::InvalidRequest);
        }
        let identity = Self {
            location_id: u32::from_le_bytes(bytes[..4].try_into().expect("fixed slice")),
            vendor_id: u16::from_le_bytes(bytes[4..6].try_into().expect("fixed slice")),
            product_id: u16::from_le_bytes(bytes[6..8].try_into().expect("fixed slice")),
            serial: String::from_utf8(bytes[8..].to_vec())
                .map_err(|_| NativeError::InvalidRequest)?,
        };
        if identity.location_id == 0 || identity.vendor_id == 0 || identity.product_id == 0 {
            return Err(NativeError::EvidenceIncomplete);
        }
        Ok(identity)
    }

    /// Returns the actual USB ancestor serial, independent of SCSI unit serial.
    #[must_use]
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// Returns the actual IOKit USB `locationID` property.
    #[must_use]
    pub const fn location_id(&self) -> u32 {
        self.location_id
    }

    /// Returns the actual IOKit USB `idVendor` property.
    #[must_use]
    pub const fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// Returns the actual IOKit USB `idProduct` property.
    #[must_use]
    pub const fn product_id(&self) -> u16 {
        self.product_id
    }
}

impl std::fmt::Debug for MacUsbIdentity {
    /// Keeps physical location and identity out of ordinary diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacUsbIdentity(<private>)")
    }
}

impl MacDevice {
    /// Reads USB ancestor identity after exact retained-service revalidation.
    ///
    /// # Errors
    ///
    /// Missing, malformed, stale or non-USB properties fail closed; this method
    /// never rematches by location, detaches a driver, or acquires transport.
    pub fn usb_identity(&mut self) -> Result<MacUsbIdentity, NativeError> {
        #[cfg(target_os = "macos")]
        {
            let mut identity = MacUsbIdentity {
                serial: String::new(),
                location_id: 0,
                vendor_id: 0,
                product_id: 0,
            };
            let mut serial = [0; crate::ffi::MAX_TEXT_BYTES + 1];
            // SAFETY: the exact device and three distinct integer outputs stay
            // alive for the synchronous C call; no registry object escapes it.
            let status = unsafe {
                crate::ffi::rdx_macos_copy_usb_identity(
                    self.inner.as_ptr(),
                    &mut identity.location_id,
                    &mut identity.vendor_id,
                    &mut identity.product_id,
                    serial.as_mut_ptr(),
                )
            };
            crate::status_result(status)?;
            identity.serial = crate::optional_record_text(1, &serial)
                .filter(|value| value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)))
                .ok_or(NativeError::EvidenceIncomplete)?
                .to_owned();
            Ok(identity)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identity framing preserves distinct USB properties without printing them.
    #[test]
    fn private_usb_frame_roundtrip_and_malformed_rejection() {
        let identity = MacUsbIdentity {
            serial: "001234567890".to_owned(),
            location_id: 0x200000,
            vendor_id: 0x1a5a,
            product_id: 6,
        };
        let bytes = identity.encode();
        let copy = MacUsbIdentity::decode(&bytes).expect("complete identity");
        assert_eq!(copy.encode(), bytes);
        assert_eq!(format!("{copy:?}"), "MacUsbIdentity(<private>)");
        for end in 0..9 {
            assert!(MacUsbIdentity::decode(&bytes[..end]).is_err());
        }
        let mut invalid = bytes.clone();
        invalid[8] = 0;
        assert!(MacUsbIdentity::decode(&invalid).is_err());
        invalid[..4].fill(0);
        invalid[8] = b'0';
        assert!(MacUsbIdentity::decode(&invalid).is_err());
        assert!(MacUsbIdentity::decode(&[b'0'; 9 + crate::ffi::MAX_TEXT_BYTES]).is_err());
    }
}

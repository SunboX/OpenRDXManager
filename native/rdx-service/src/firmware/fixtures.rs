// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic containers for explicit fixture transports, never production trust.

use std::path::Path;
use std::sync::OnceLock;

use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::rand_core::{CryptoRng, Error, RngCore};
use rsa::signature::{SignatureEncoding, Signer};

use super::*;

/// Reproducible entropy used only to generate an ephemeral, public test identity.
/// It is deliberately predictable and must never generate a production key.
struct FixtureRng(u64);

impl RngCore for FixtureRng {
    /// Returns the next deterministic word; no OS entropy or persistent key is used.
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    /// Returns a deterministic four-byte word for the RSA test generator.
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    /// Fills the generator's requested entropy without external file dependencies.
    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for chunk in destination.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }
    /// Supplies the fixture generator's infallible deterministic entropy.
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}
// RSA requires this marker. Its deliberately non-secret identity exists only
// in the explicit fixture module and is never accepted by the vendor loader.
impl CryptoRng for FixtureRng {}

/// Generates the same disposable test key once, without storing private material.
fn key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::new(&mut FixtureRng(0x6f70_656e_7264_7831), 1024)
            .expect("deterministic fixture RSA key")
    })
}

/// Builds a format-compatible 0283 container with synthetic TI payload and RSA signature.
/// The owned public OpenRDX envelope supplies structural metadata, not vendor bytes.
pub fn bytes() -> Vec<u8> {
    static IMAGE: OnceLock<Vec<u8>> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            let template = include_bytes!("../../../../test/fixtures/OpenRDX-v1-07.bin");
            let mut bytes = vec![0_u8; template.len()];
            bytes[..SIGNATURE_START].copy_from_slice(&template[..SIGNATURE_START]);
            let boot_end = bytes.len() - TRAILER_LENGTH;
            fill_boot_region(&mut bytes[BOOT_REGION_START..boot_end]);
            let signature =
                SigningKey::<Sha256>::new(key().clone()).sign(&bytes[BOOT_REGION_START..boot_end]);
            bytes[SIGNATURE_START..SIGNATURE_END].copy_from_slice(&signature.to_vec());
            let metadata_check = rdx_rolling_check(&bytes[..METADATA_CHECK_START], u32::MAX);
            bytes[METADATA_CHECK_START..BOOT_REGION_START]
                .copy_from_slice(&metadata_check.to_be_bytes());
            let boot_check = rdx_rolling_check(&bytes[BOOT_REGION_START..boot_end], 0);
            bytes[boot_end..].copy_from_slice(&boot_check.to_be_bytes());
            bytes
        })
        .clone()
}

/// Produces non-executable, deterministic TI records with exact per-record sums.
pub(super) fn fill_boot_region(boot: &mut [u8]) {
    boot[..2].copy_from_slice(&TUSB9261_FIRMWARE_ID.to_le_bytes());
    let mut cursor = 2;
    for (record, length) in [(1_u8, 16_usize), (2_u8, boot.len() - 30)] {
        boot[cursor] = record;
        boot[cursor + 1..cursor + 5].copy_from_slice(&(length as u32).to_le_bytes());
        let start = cursor + 5;
        for (offset, byte) in boot[start..start + length].iter_mut().enumerate() {
            *byte = (offset as u8).wrapping_mul(17).wrapping_add(record);
        }
        boot[start + length] = boot[start..start + length]
            .iter()
            .fold(0_u8, |sum, byte| sum.wrapping_add(*byte));
        cursor = start + length + 1;
    }
    assert_eq!(cursor, boot.len());
}

/// Validates synthetic bytes through the real structural parser and explicit fixture RSA key.
///
/// # Errors
/// Rejects malformed structure, product, checksums or fixture signature. The
/// production vendor loader rejects these bytes even with `fixtures` enabled.
pub fn from_bytes(
    mut bytes: Vec<u8>,
    expected_product: ProductFamily,
) -> Result<FirmwareImage, FirmwareImageError> {
    let validate = || {
        if expected_product != ProductFamily::Usb3Sata3 {
            return Err(FirmwareImageError::UnsupportedProductFamily(
                expected_product,
            ));
        }
        validate_file_size(bytes.len())?;
        let revision = validate_container_structure(&bytes, expected_product)?;
        signature::verify_with_key(&bytes, bytes.len() - TRAILER_LENGTH, key().to_public_key())?;
        Ok(revision)
    };
    match validate() {
        Ok(revision) => Ok(FirmwareImage {
            sha256: Sha256::digest(&bytes).into(),
            bytes: bytes.into_boxed_slice(),
            revision,
            expected_revision: revision,
            product: expected_product,
            signature_evidence: SignatureEvidence::FixtureSignatureVerified,
        }),
        Err(error) => {
            bytes.zeroize();
            Err(error)
        }
    }
}

/// Retains production file/structure rejection before explicitly validating a fixture signature.
///
/// # Errors
/// Returns all real loader errors unchanged, except that a vendor signature
/// rejection is followed by separate fixture-key validation in this test API.
pub fn load(
    path: impl AsRef<Path>,
    expected_product: ProductFamily,
) -> Result<FirmwareImage, FirmwareImageError> {
    match FirmwareImage::load(&path, expected_product) {
        Err(FirmwareImageError::InvalidSignature) => from_bytes(
            std::fs::read(path).map_err(FirmwareImageError::Io)?,
            expected_product,
        ),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Production trust stays pinned even in a fixture-enabled test build.
    #[test]
    fn synthetic_signature_is_explicit_and_never_vendor_evidence() {
        let bytes = bytes();
        assert!(matches!(
            FirmwareImage::from_bytes(bytes.clone(), ProductFamily::Usb3Sata3),
            Err(FirmwareImageError::InvalidSignature)
        ));
        let image = from_bytes(bytes, ProductFamily::Usb3Sata3).unwrap();
        assert_eq!(
            image.signature_evidence(),
            SignatureEvidence::FixtureSignatureVerified
        );
        assert_eq!(image.revision().get(), 283);
    }
}

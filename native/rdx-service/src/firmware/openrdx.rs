// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenRDX's explicit SHA-256 integrity format; it is not a vendor RSA signature.
//!
//! See `docs/development/firmware-updates.md` for the producer and receiver evidence.

use serde::Deserialize;

use super::*;

const CONTAINER_LENGTH: usize = 0xF29E;
const TEMPLATE_PREFIX_SHA256: &str =
    "c608917c4693a5cd01e6f67219040e7441013c0f1670601864d6c88b6b4267eb";

/// Path-free release facts paired with the selected image by the main process.
/// Hashes detect corruption/mismatched files; they do not authenticate an author.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenRdxImageMetadata {
    container_sha256: String,
    boot_region_sha256: String,
    release_version: String,
}

impl OpenRdxImageMetadata {
    /// Checks bounded release notation and derives the exact SCSI readback revision.
    fn expected_revision(&self) -> Result<FirmwareRevision, FirmwareImageError> {
        let invalid = || FirmwareImageError::InvalidOpenRdxManifest;
        let (major, minor) = self.release_version.split_once('.').ok_or_else(invalid)?;
        if !(1..=2).contains(&major.len())
            || minor.len() != 2
            || !major
                .bytes()
                .chain(minor.bytes())
                .all(|byte| byte.is_ascii_digit())
            || (major.len() > 1 && major.starts_with('0'))
        {
            return Err(invalid());
        }
        let value = major.parse::<u16>().map_err(|_| invalid())? * 100
            + minor.parse::<u16>().map_err(|_| invalid())?;
        // Release-based SCSI revisions were introduced in 1.06. Older 0001
        // images need explicit legacy metadata; their version is not inferable.
        if value < 106 {
            return Err(invalid());
        }
        FirmwareRevision::new(value)
    }
}

impl FirmwareImage {
    /// Validates an explicitly selected OpenRDX release without relaxing RSA loading.
    ///
    /// # Errors
    /// Rejects malformed release facts, mismatched hashes/template, TI records,
    /// rolling checks, marker, digest or reserved bytes. Transfer still requires
    /// a fresh OpenRDX receiver authorization; this does not enable first installation.
    pub fn from_openrdx_bytes(
        mut bytes: Vec<u8>,
        metadata: &OpenRdxImageMetadata,
    ) -> Result<Self, FirmwareImageError> {
        let result = validate_openrdx(&bytes, metadata);
        match result {
            Ok((revision, expected_revision)) => Ok(Self {
                sha256: Sha256::digest(&bytes).into(),
                bytes: bytes.into_boxed_slice(),
                revision,
                expected_revision,
                product: ProductFamily::Usb3Sata3,
                signature_evidence: SignatureEvidence::OpenRdxIntegrityVerified,
            }),
            Err(error) => {
                bytes.zeroize();
                Err(error)
            }
        }
    }
}

/// Validates the exact fixed envelope and integrity block emitted by the release builder.
fn validate_openrdx(
    bytes: &[u8],
    metadata: &OpenRdxImageMetadata,
) -> Result<(FirmwareRevision, FirmwareRevision), FirmwareImageError> {
    let expected_revision = metadata.expected_revision()?;
    if bytes.len() != CONTAINER_LENGTH
        || format!("{:x}", Sha256::digest(bytes)) != metadata.container_sha256
    {
        return Err(FirmwareImageError::InvalidOpenRdxManifest);
    }
    let boot_end = bytes.len() - TRAILER_LENGTH;
    if format!("{:x}", Sha256::digest(&bytes[..SIGNATURE_START])) != TEMPLATE_PREFIX_SHA256
        || format!("{:x}", Sha256::digest(&bytes[BOOT_REGION_START..boot_end]))
            != metadata.boot_region_sha256
    {
        return Err(FirmwareImageError::InvalidOpenRdxManifest);
    }
    let revision = validate_container_structure(bytes, ProductFamily::Usb3Sata3)?;
    let authentication = &bytes[SIGNATURE_START..SIGNATURE_END];
    let digest: [u8; 32] = Sha256::digest(&bytes[BOOT_REGION_START..boot_end]).into();
    if &authentication[..8] != b"OPENRDX1"
        || authentication[8..40] != digest
        || authentication[40..].iter().any(|byte| *byte != 0)
    {
        return Err(FirmwareImageError::InvalidOpenRdxIntegrity);
    }
    Ok((revision, expected_revision))
}

/// Builds a deterministic format fixture from immutable vendor evidence without
/// modifying the evidence or claiming that the resulting image is an OpenRDX build.
#[cfg(test)]
pub(crate) fn test_image() -> (Vec<u8>, OpenRdxImageMetadata) {
    test_image_for_release("1.07")
}

/// Supplies synthetic release metadata for worker revision-readback tests.
#[cfg(test)]
pub(crate) fn test_image_for_release(release_version: &str) -> (Vec<u8>, OpenRdxImageMetadata) {
    let mut bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../original-inputs/RDX2E__STD__F-0283.bin"),
    )
    .unwrap();
    let boot_end = bytes.len() - 4;
    let boot_digest: [u8; 32] = Sha256::digest(&bytes[BOOT_REGION_START..boot_end]).into();
    bytes[SIGNATURE_START..SIGNATURE_END].fill(0);
    bytes[SIGNATURE_START..SIGNATURE_START + 8].copy_from_slice(b"OPENRDX1");
    bytes[SIGNATURE_START + 8..SIGNATURE_START + 40].copy_from_slice(&boot_digest);
    let check = rdx_rolling_check(&bytes[..METADATA_CHECK_START], u32::MAX);
    bytes[METADATA_CHECK_START..BOOT_REGION_START].copy_from_slice(&check.to_be_bytes());
    let metadata = OpenRdxImageMetadata {
        container_sha256: format!("{:x}", Sha256::digest(&bytes)),
        boot_region_sha256: format!("{:x}", Sha256::digest(&bytes[BOOT_REGION_START..boot_end])),
        release_version: release_version.to_owned(),
    };
    (bytes, metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OpenRDX acceptance is explicit, preserves template metadata, and gates transfer.
    #[test]
    fn openrdx_requires_explicit_metadata_and_supported_receiver() {
        let (bytes, metadata) = test_image();
        assert!(matches!(
            FirmwareImage::from_bytes(bytes.clone(), ProductFamily::Usb3Sata3),
            Err(FirmwareImageError::InvalidSignature)
        ));
        let image = FirmwareImage::from_openrdx_bytes(bytes, &metadata).unwrap();
        assert_eq!(image.revision().get(), 283);
        assert_eq!(image.expected_revision().get(), 107);
        assert_eq!(
            image.signature_evidence(),
            SignatureEvidence::OpenRdxIntegrityVerified
        );
        for revision in [1, 106, 107, 108, 109, 110, 111] {
            assert!(
                image
                    .authorize_for_registry(
                        FirmwareRevision::new(revision).unwrap(),
                        ProductFamily::Usb3Sata3
                    )
                    .is_ok()
            );
        }
        for revision in [0, 105, 112, 277, 278, 283] {
            assert!(matches!(
                image.authorize_for_registry(
                    FirmwareRevision::new(revision).unwrap(),
                    ProductFamily::Usb3Sata3
                ),
                Err(FirmwareImageError::OpenRdxReceiverRequired)
            ));
        }
        assert!(matches!(
            image.authorize_for_registry(
                FirmwareRevision::new(1).unwrap(),
                ProductFamily::Usb2Sata1
            ),
            Err(FirmwareImageError::ProductMismatch)
        ));
    }

    /// Hashes, the pinned envelope, explicit marker, digest and reserved bytes are mandatory.
    #[test]
    fn openrdx_rejects_corruption_even_with_repaired_outer_checks() {
        let (original, metadata) = test_image();
        for offset in [
            0,
            0x0c,
            SIGNATURE_START,
            SIGNATURE_START + 8,
            SIGNATURE_START + 40,
            BOOT_REGION_START + 20,
        ] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            let check = rdx_rolling_check(&bytes[..METADATA_CHECK_START], u32::MAX);
            bytes[METADATA_CHECK_START..BOOT_REGION_START].copy_from_slice(&check.to_be_bytes());
            let mut repaired_manifest = metadata.clone();
            repaired_manifest.container_sha256 = format!("{:x}", Sha256::digest(&bytes));
            assert!(
                FirmwareImage::from_openrdx_bytes(bytes, &repaired_manifest).is_err(),
                "offset {offset:x}"
            );
        }
        for version in ["1.7", "01.07", "1.06.0", "100.00", "1.05", "-1.07", "1.xx"] {
            let mut altered = metadata.clone();
            altered.release_version = version.to_owned();
            assert!(FirmwareImage::from_openrdx_bytes(original.clone(), &altered).is_err());
        }
        let mut altered = metadata.clone();
        altered.container_sha256 = "0".repeat(64);
        assert!(FirmwareImage::from_openrdx_bytes(original.clone(), &altered).is_err());
        assert!(FirmwareImage::from_openrdx_bytes(original[..300].to_vec(), &metadata).is_err());
    }
}

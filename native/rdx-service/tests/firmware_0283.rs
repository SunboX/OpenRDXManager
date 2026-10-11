// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fs::{self, File};
use std::path::PathBuf;

use rdx_service::firmware::{
    FirmwareImage, FirmwareImageError, FirmwareRevision, InstallableFirmwareImage,
    MAX_FIRMWARE_IMAGE_SIZE, ProductFamily, SignatureEvidence,
};
use rdx_service::host::{
    DeviceInterface, FirmwareAuthorizationError, FixtureDevice, SessionDevice, SessionGeneration,
};
use rdx_service::model::{DeviceId, DeviceIdentity, DiscoveryRevision};
use tempfile::{TempDir, tempdir};

const METADATA_CHECK_OFFSET: usize = 0x188;
const BOOT_REGION_OFFSET: usize = 0x18C;
const RDX_CHECK_POLYNOMIAL: u32 = 0x04C1_1DB7;

/// Resolves the immutable vendor firmware without copying it into a test fixture.
fn firmware_0283_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("original-inputs/RDX2E__STD__F-0283.bin")
}

/// Reads the immutable evidence into test memory for ephemeral negative mutations.
fn firmware_0283_bytes() -> Vec<u8> {
    fs::read(firmware_0283_path()).expect("immutable firmware evidence")
}

/// Authorizes one image through fresh identity-bound fixture evidence.
fn authorize_image(
    image: FirmwareImage,
    installed: u16,
) -> Result<InstallableFirmwareImage, FirmwareAuthorizationError> {
    let fixture = FixtureDevice::new(SessionDevice::fixture(
        DeviceIdentity {
            id: DeviceId::new("rdx:firmware-validator").unwrap(),
            revision: DiscoveryRevision::new(1).unwrap(),
        },
        ProductFamily::Usb3Sata3,
        FirmwareRevision::new(installed).unwrap(),
        DeviceInterface::Sata3,
        false,
        SessionGeneration::new(1).unwrap(),
    ));
    fixture.open().authorize_firmware(image)
}

/// Owns a temporary mutation path for one validation test.
struct TemporaryFirmware {
    _directory: TempDir,
    path: PathBuf,
}

/// Writes test bytes outside the repository with a controlled filename.
fn temporary_firmware(filename: &str, bytes: &[u8]) -> TemporaryFirmware {
    let directory = tempdir().expect("temporary firmware directory");
    let path = directory.path().join(filename);
    fs::write(&path, bytes).expect("temporary firmware mutation");
    TemporaryFirmware {
        _directory: directory,
        path,
    }
}

/// Implements the independently documented drive rolling check for mutation setup.
fn evidence_rolling_check(bytes: &[u8], initial: u32) -> u32 {
    let mut value = initial;
    for byte in bytes {
        let mut working = (u32::from(*byte) ^ (value >> 24)) << 24;
        for _ in 0..8 {
            working = working.wrapping_shl(1);
            if working & 0x8000_0000 != 0 {
                working ^= RDX_CHECK_POLYNOMIAL;
            }
        }
        value = working ^ value.wrapping_shl(8);
    }
    value
}

/// Rewrites the stored metadata check after an intentional test mutation.
fn rewrite_metadata_check(bytes: &mut [u8]) {
    let check = evidence_rolling_check(&bytes[..METADATA_CHECK_OFFSET], u32::MAX);
    bytes[METADATA_CHECK_OFFSET..BOOT_REGION_OFFSET].copy_from_slice(&check.to_be_bytes());
}

/// Rewrites the stored TI boot-region check after an intentional test mutation.
fn rewrite_boot_check(bytes: &mut [u8]) {
    let trailer_offset = bytes.len() - 4;
    let check = evidence_rolling_check(&bytes[BOOT_REGION_OFFSET..trailer_offset], 0);
    bytes[trailer_offset..].copy_from_slice(&check.to_be_bytes());
}

/// Anchors parsing and transfer boundaries to the exact analyzed 0283 evidence.
#[test]
fn firmware_0283_has_verified_identity_sixteen_chunks_and_exact_tail() {
    let image = FirmwareImage::load(firmware_0283_path(), ProductFamily::Usb3Sata3)
        .expect("analyzed 0283 image");

    assert_eq!(image.len(), 62_110);
    assert_eq!(image.revision().get(), 283);
    assert_eq!(image.signature_evidence(), SignatureEvidence::Verified);
    assert_eq!(
        image.sha256(),
        [
            0x73, 0xd5, 0x28, 0x80, 0x1a, 0xef, 0xc0, 0x32, 0xd3, 0xa5, 0x36, 0x37, 0xb0, 0x35,
            0xf6, 0x5d, 0x72, 0x80, 0x91, 0x51, 0xb2, 0xf1, 0x27, 0xc6, 0xb2, 0x05, 0x0e, 0x9b,
            0xac, 0xc7, 0x6f, 0x3b,
        ]
    );
    let installable = authorize_image(image, 278).expect("0283 is authorized from signed-era 0278");
    let chunks = installable.chunks().collect::<Vec<_>>();
    assert_eq!(chunks.len(), 16);
    assert_eq!((chunks[0].offset(), chunks[0].bytes().len()), (0, 0x1000));
    assert_eq!(
        (chunks[15].offset(), chunks[15].bytes().len()),
        (0xF000, 0x029E)
    );
    assert_eq!(chunks.concat_bytes(), installable.bytes());
    assert_eq!(
        installable
            .finalize_command()
            .expect("bounded finalize command")
            .cdb(),
        &[0x3B, 0x05, 0, 0x00, 0xF2, 0x9E, 0, 0, 0, 0]
    );
}

/// Rejects the legacy product path before exposing modern firmware chunks.
#[test]
fn rejects_wrong_expected_product_family() {
    assert!(matches!(
        FirmwareImage::load(firmware_0283_path(), ProductFamily::Usb2Sata1),
        Err(FirmwareImageError::UnsupportedProductFamily(
            ProductFamily::Usb2Sata1
        ))
    ));
}

/// Rejects an extension that belongs to the separate legacy update protocol.
#[test]
fn rejects_wrong_extension_before_opening_the_path() {
    let legacy_path = firmware_0283_path().with_extension("bip");

    assert!(matches!(
        FirmwareImage::load(legacy_path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::UnsupportedExtension)
    ));
}

/// Accepts the documented extension without making its ASCII case significant.
#[test]
fn accepts_uppercase_bin_extension() {
    let firmware = temporary_firmware("future.BIN", &firmware_0283_bytes());

    assert!(FirmwareImage::load(&firmware.path, ProductFamily::Usb3Sata3).is_ok());
}

/// Rejects sparse oversize inputs from handle metadata before allocating or reading them.
#[test]
fn rejects_file_beyond_the_24_bit_transport_boundary() {
    let directory = tempdir().expect("temporary firmware directory");
    let path = directory.path().join("oversize.bin");
    let file = File::create(&path).expect("sparse temporary firmware");
    file.set_len((MAX_FIRMWARE_IMAGE_SIZE + 1) as u64)
        .expect("oversize sparse length");

    assert!(matches!(
        FirmwareImage::load(path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::FileTooLarge {
            maximum: MAX_FIRMWARE_IMAGE_SIZE,
            actual
        }) if actual == MAX_FIRMWARE_IMAGE_SIZE + 1
    ));
}

/// Distinguishes a pre-header truncation from a nearly complete length mismatch.
#[test]
fn rejects_short_and_one_byte_truncated_images() {
    let bytes = firmware_0283_bytes();
    let short = temporary_firmware("short.bin", &bytes[..32]);
    let truncated = temporary_firmware("truncated.bin", &bytes[..bytes.len() - 1]);

    assert!(matches!(
        FirmwareImage::load(short.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::FileTooSmall { .. })
    ));
    assert!(matches!(
        FirmwareImage::load(truncated.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::InvalidHeaderLength)
    ));
}

/// Rejects both outer-length and type-1 record-boundary mutations.
#[test]
fn rejects_header_and_record_boundary_mutations() {
    let mut header_bytes = firmware_0283_bytes();
    header_bytes[7] ^= 1;
    let header = temporary_firmware("bad-header.bin", &header_bytes);

    let mut record_bytes = firmware_0283_bytes();
    record_bytes[0x2B] ^= 1;
    let record = temporary_firmware("bad-record.bin", &record_bytes);

    assert!(matches!(
        FirmwareImage::load(header.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::InvalidHeaderLength)
    ));
    assert!(matches!(
        FirmwareImage::load(record.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::InvalidFirmwareRecord)
    ));
}

/// Rejects record counts outside the exact protocol `1..=100` bound.
#[test]
fn rejects_zero_and_excessive_record_counts() {
    for (name, count) in [("zero-records.bin", 0_u32), ("too-many-records.bin", 101)] {
        let mut bytes = firmware_0283_bytes();
        bytes[0x20..0x24].copy_from_slice(&count.to_be_bytes());
        let firmware = temporary_firmware(name, &bytes);

        assert!(matches!(
            FirmwareImage::load(firmware.path, ProductFamily::Usb3Sata3),
            Err(FirmwareImageError::InvalidRecordCount(actual)) if actual == count
        ));
    }
}

/// Rejects a product marker that does not identify the selected USB3/SATA3 family.
#[test]
fn rejects_embedded_wrong_family_marker() {
    let mut bytes = firmware_0283_bytes();
    bytes[0x6C..0x70].copy_from_slice(b"S1  ");
    rewrite_metadata_check(&mut bytes);
    let firmware = temporary_firmware("wrong-product.bin", &bytes);

    assert!(matches!(
        FirmwareImage::load(firmware.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::ProductMismatch)
    ));
}

/// Rejects independently corrupted metadata and TI-region rolling checks.
#[test]
fn rejects_metadata_and_boot_rolling_check_mutations() {
    let mut metadata_bytes = firmware_0283_bytes();
    metadata_bytes[METADATA_CHECK_OFFSET] ^= 1;
    let metadata = temporary_firmware("bad-metadata-check.bin", &metadata_bytes);

    let mut boot_bytes = firmware_0283_bytes();
    boot_bytes[0x200] ^= 1;
    let boot = temporary_firmware("bad-boot-check.bin", &boot_bytes);

    assert!(matches!(
        FirmwareImage::load(metadata.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::RollingCheckMismatch { region: "metadata" })
    ));
    assert!(matches!(
        FirmwareImage::load(boot.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::RollingCheckMismatch { region: "boot" })
    ));
}

/// Catches a TI payload mutation even after its outer rolling check is repaired.
#[test]
fn rejects_ti_record_checksum_mutation_independently_of_outer_check() {
    let mut bytes = firmware_0283_bytes();
    bytes[0x200] ^= 1;
    rewrite_boot_check(&mut bytes);
    let firmware = temporary_firmware("bad-ti-check.bin", &bytes);

    assert!(matches!(
        FirmwareImage::load(firmware.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::InvalidTiBootRecords)
    ));
}

/// Catches signature corruption even after the non-cryptographic metadata check is repaired.
#[test]
fn rejects_signature_mutation_independently_of_metadata_check() {
    let mut bytes = firmware_0283_bytes();
    bytes[0x108] ^= 1;
    rewrite_metadata_check(&mut bytes);
    let firmware = temporary_firmware("bad-signature.bin", &bytes);

    assert!(matches!(
        FirmwareImage::load(firmware.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::InvalidSignature)
    ));
}

/// Accepts a future matching revision structurally instead of hash-allowlisting only 0283.
#[test]
fn accepts_future_matching_metadata_with_the_same_valid_signed_boot_region() {
    let mut bytes = firmware_0283_bytes();
    bytes[0x0C..0x10].copy_from_slice(b"0284");
    bytes[0x60..0x64].copy_from_slice(b"0284");
    rewrite_metadata_check(&mut bytes);
    let firmware = temporary_firmware("future-0284.bin", &bytes);

    let image = FirmwareImage::load(firmware.path, ProductFamily::Usb3Sata3)
        .expect("structurally valid future metadata");
    assert_eq!(image.revision().get(), 284);
    assert_ne!(
        image.sha256(),
        FirmwareImage::load(firmware_0283_path(), ProductFamily::Usb3Sata3)
            .unwrap()
            .sha256()
    );
}

/// Loads repaired pre-0278 metadata but rejects its authorization from the signed era.
#[test]
fn signed_downgrade_policy_blocks_pre_0278_but_not_signed_to_signed_rollback() {
    let mut bytes = firmware_0283_bytes();
    bytes[0x0C..0x10].copy_from_slice(b"0277");
    bytes[0x60..0x64].copy_from_slice(b"0277");
    rewrite_metadata_check(&mut bytes);
    let firmware = temporary_firmware("repaired-0277.bin", &bytes);
    let candidate = FirmwareImage::load(firmware.path, ProductFamily::Usb3Sata3)
        .expect("metadata is structural and outside the verified boot-region signature");

    assert_eq!(candidate.revision().get(), 277);
    assert_eq!(candidate.signature_evidence(), SignatureEvidence::Verified);
    assert!(matches!(
        authorize_image(candidate, 278),
        Err(FirmwareAuthorizationError::Image(
            FirmwareImageError::UnsignedDowngradeBlocked {
                installed: 278,
                candidate: 277
            }
        ))
    ));

    let image = FirmwareImage::load(firmware_0283_path(), ProductFamily::Usb3Sata3).unwrap();
    assert!(authorize_image(image, 300).is_ok());
}

/// Keeps the modern loader signature requirement independent of a pre-0278 label.
#[test]
fn modern_loader_does_not_treat_pre_0278_metadata_as_an_unsigned_bypass() {
    let mut bytes = firmware_0283_bytes();
    bytes[0x0C..0x10].copy_from_slice(b"0277");
    bytes[0x60..0x64].copy_from_slice(b"0277");
    bytes[0x108..0x188].fill(0);
    rewrite_metadata_check(&mut bytes);
    let firmware = temporary_firmware("unsigned-0277.bin", &bytes);

    assert!(matches!(
        FirmwareImage::load(firmware.path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::InvalidSignature)
    ));
}

/// Proves chunks remain attached to the validated snapshot after the source changes.
#[test]
fn loaded_image_does_not_reopen_a_changed_source_path() {
    let firmware = temporary_firmware("snapshot.bin", &firmware_0283_bytes());
    let image = FirmwareImage::load(&firmware.path, ProductFamily::Usb3Sata3).unwrap();
    fs::write(&firmware.path, vec![0_u8; 32]).expect("replace temporary source after load");
    let installable = authorize_image(image, 283).expect("same-revision authorization");

    assert_eq!(installable.len(), 62_110);
    assert_eq!(&installable.bytes()[..4], &[0x00, 0x00, 0xF2, 0x7E]);
    assert_eq!(installable.chunks().len(), 16);
}

/// Rejects a directory even when its name carries the expected extension.
#[test]
fn rejects_non_regular_file_handles() {
    let directory = tempdir().expect("temporary parent directory");
    let path = directory.path().join("directory.bin");
    fs::create_dir(&path).expect("temporary directory named like firmware");

    assert!(matches!(
        FirmwareImage::load(path, ProductFamily::Usb3Sata3),
        Err(FirmwareImageError::NotARegularFile)
    ));
}

/// Concatenates borrowed firmware chunks for exact immutable-snapshot comparison.
trait ConcatFirmwareChunks {
    /// Returns one test-only concatenation of all borrowed chunk bytes.
    fn concat_bytes(&self) -> Vec<u8>;
}

impl ConcatFirmwareChunks for Vec<rdx_service::firmware::FirmwareChunk<'_>> {
    fn concat_bytes(&self) -> Vec<u8> {
        self.iter()
            .flat_map(|chunk| chunk.bytes().iter().copied())
            .collect()
    }
}

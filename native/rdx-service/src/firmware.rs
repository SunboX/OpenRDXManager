// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Immutable validation and authorization for the proven modern RDX `.BIN` format.
//!
//! Structural fields and transfer boundaries come from
//! `docs/protocols/firmware-update.md` and
//! the firmware 0283 reference inventory. The RSA key,
//! algorithm, and signed range are the independently reproduced evidence in
//! `analysis/private-firmware/signature/signature-verification.json`; the
//! validator does not infer a different cryptographic format. That signature
//! covers the TI boot region, not the product and revision metadata, so those
//! fields remain structural evidence rather than cryptographic identity.
//!
//! The vendor loader requires the proven signature for every accepted image;
//! genuine unsigned pre-0278 images are intentionally unsupported. The separate
//! OpenRDX loader verifies its explicit integrity block and release metadata,
//! and restricts authorization to supported existing OpenRDX receivers. A caller
//! must still obtain a fresh identity-bound device-session authorization before
//! any transfer bytes or commands become accessible. Product metadata alone is
//! not live-device proof.

pub(crate) mod manufacturing;

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{self, Read};
use std::path::Path;

use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

mod openrdx;
pub use openrdx::OpenRdxImageMetadata;
#[cfg(test)]
pub(crate) use openrdx::{test_image as openrdx_test_image, test_image_for_release};

use crate::host::{DeviceSession, SessionCapabilityId, SessionGeneration};
use crate::model::DeviceIdentity;
use crate::protocol::{Command, ProtocolBuildError, write_buffer};

/// Exact transfer size specified by the modern Manager update path.
pub const FIRMWARE_CHUNK_SIZE: usize = 0x1000;
/// Largest image representable by the modern WRITE BUFFER offset field.
pub const MAX_FIRMWARE_IMAGE_SIZE: usize = 0xFF_FFFF;
/// First firmware revision documented as using digitally signed images.
pub const FIRST_SIGNED_FIRMWARE_REVISION: u16 = 278;

const OUTER_HEADER_LENGTH: usize = 0x20;
const MAX_RECORD_COUNT: u32 = 100;
const TYPE_ONE_RECORD_HEADER_LENGTH: usize = 0x1C;
const PRODUCT_METADATA_LENGTH: usize = 0xA0;
const SIGNATURE_START: usize = 0x108;
const SIGNATURE_END: usize = 0x188;
const METADATA_CHECK_START: usize = SIGNATURE_END;
const BOOT_REGION_START: usize = 0x18C;
const TRAILER_LENGTH: usize = 4;
const TUSB9261_FIRMWARE_ID: u16 = 0x9260;
const TUSB9261_DESCRIPTOR_RECORD: u8 = 1;
const TUSB9261_FIRMWARE_RECORD: u8 = 2;
const RDX_CHECK_POLYNOMIAL: u32 = 0x04C1_1DB7;
const RDX_SIGNING_EXPONENT: u32 = 65_537;
const RDX_SIGNING_MODULUS: [u8; 128] = [
    0xc1, 0x57, 0x05, 0x3a, 0xda, 0x43, 0x42, 0xb3, 0x55, 0x87, 0xc2, 0x82, 0x27, 0x20, 0x4b, 0xef,
    0x0f, 0x4e, 0x15, 0x64, 0xe8, 0x47, 0x81, 0xd1, 0xa5, 0x47, 0x09, 0xeb, 0x1c, 0x12, 0x71, 0x65,
    0x02, 0x16, 0x1c, 0x1d, 0x88, 0x72, 0xda, 0x47, 0x41, 0xd5, 0xc2, 0x05, 0xdd, 0x4e, 0x75, 0x32,
    0x8f, 0x46, 0x08, 0x5c, 0xea, 0x6e, 0x0d, 0xcc, 0x0e, 0x9f, 0xa0, 0x66, 0x38, 0xe6, 0x33, 0x7c,
    0x57, 0xae, 0xcf, 0xa6, 0x18, 0x1b, 0x3b, 0x32, 0x5d, 0x82, 0xec, 0xb1, 0xe5, 0x57, 0xe5, 0x23,
    0xc7, 0x7e, 0x2a, 0xe2, 0x01, 0xa6, 0x3d, 0xca, 0xb7, 0xf4, 0x71, 0x81, 0x0f, 0x58, 0xfb, 0x3f,
    0xfb, 0x6c, 0xc9, 0xaf, 0xfc, 0x3a, 0x02, 0xf0, 0xc5, 0xfb, 0xe4, 0xd1, 0x3c, 0xbb, 0x0f, 0x31,
    0x73, 0xd1, 0x58, 0x27, 0x85, 0xa7, 0xe8, 0xb2, 0x65, 0x63, 0xaf, 0xc6, 0x86, 0x03, 0x80, 0x75,
];

/// Product families whose firmware containers follow distinct vendor formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductFamily {
    /// USB 3 and SATA 3 products using the signed TAD `.BIN` container.
    Usb3Sata3,
    /// USB 2 and SATA 1 products using the separate legacy `.BIP` path.
    Usb2Sata1,
}

/// Scope of the cryptographic evidence established for an accepted image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureEvidence {
    /// The RSA-1024 PKCS#1 v1.5 SHA-256 signature over only the TI boot region
    /// verified locally.
    ///
    /// This does not authenticate the outer product or revision metadata.
    Verified,
    /// Explicit OPENRDX1 marker and boot SHA-256 verified against paired release
    /// facts. This is integrity evidence, not proof of a vendor RSA signature.
    OpenRdxIntegrityVerified,
}

/// Four-decimal-digit firmware revision embedded in a modern TAD image.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FirmwareRevision(u16);

impl FirmwareRevision {
    /// Creates a revision representable by the documented four-ASCII-digit field.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareImageError::InvalidRevision`] above `9999`.
    pub fn new(value: u16) -> Result<Self, FirmwareImageError> {
        if value > 9999 {
            return Err(FirmwareImageError::InvalidRevision);
        }
        Ok(Self(value))
    }

    /// Returns the decimal value represented by the four embedded digits.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Identifies the supported installed receivers, independently of the image
    /// being sent. Their delayed reset also applies when restoring vendor firmware.
    pub(crate) const fn has_openrdx_update_receiver(self) -> bool {
        matches!(self.0, 1 | 106 | 107 | 108 | 109 | 110 | 111)
    }
}

/// One borrowed 4-KiB-or-smaller transfer from an authorized immutable snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareChunk<'a> {
    offset: u32,
    bytes: &'a [u8],
}

impl FirmwareChunk<'_> {
    /// Returns the absolute byte offset encoded into the WRITE BUFFER CDB.
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns bytes borrowed from the authorized immutable image snapshot.
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
}

/// Validated metadata and an immutable image snapshot that is not transferable.
///
/// Transfer access is deliberately absent from this type. Consume it through
/// an identity-bound [`crate::host::DeviceSession`] after fresh live validation.
pub struct FirmwareImage {
    bytes: Box<[u8]>,
    revision: FirmwareRevision,
    product: ProductFamily,
    sha256: [u8; 32],
    expected_revision: FirmwareRevision,
    signature_evidence: SignatureEvidence,
}

impl FirmwareImage {
    /// Opens, reads once, validates, and retains a modern firmware image.
    ///
    /// The file length is checked on the opened handle before a bounded read.
    /// All chunks exposed after authorization borrow the resulting owned
    /// snapshot, avoiding a second path lookup or read between validation and
    /// transfer.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareImageError`] for I/O failure, unsupported extension or
    /// family, unsafe size, inconsistent structure/product/version data, failed
    /// record/check validation, or failed cryptographic signature validation.
    pub fn load(
        path: impl AsRef<Path>,
        expected_product: ProductFamily,
    ) -> Result<Self, FirmwareImageError> {
        let path = path.as_ref();
        validate_extension(path)?;
        if expected_product != ProductFamily::Usb3Sata3 {
            return Err(FirmwareImageError::UnsupportedProductFamily(
                expected_product,
            ));
        }

        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Open directory/reparse handles for type inspection instead of
            // following a link or misreporting a directory as an I/O failure.
            // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT.
            options.custom_flags(0x0200_0000 | 0x0020_0000);
        }
        let mut file = options.open(path).map_err(FirmwareImageError::Io)?;
        let metadata = file.metadata().map_err(FirmwareImageError::Io)?;
        if !metadata.is_file() {
            return Err(FirmwareImageError::NotARegularFile);
        }
        let expected_length =
            usize::try_from(metadata.len()).map_err(|_| FirmwareImageError::FileTooLarge {
                maximum: MAX_FIRMWARE_IMAGE_SIZE,
                actual: usize::MAX,
            })?;
        validate_file_size(expected_length)?;

        let mut bytes = Vec::with_capacity(expected_length);
        file.by_ref()
            .take((MAX_FIRMWARE_IMAGE_SIZE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(FirmwareImageError::Io)?;
        if bytes.len() != expected_length {
            return Err(FirmwareImageError::FileChangedDuringRead {
                expected: expected_length,
                actual: bytes.len(),
            });
        }

        Self::from_bytes(bytes, expected_product)
    }

    /// Validates and owns one path-free modern firmware byte snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareImageError`] for an unsupported family, unsafe size,
    /// invalid structure/product/revision data, or failed signature evidence.
    pub fn from_bytes(
        mut bytes: Vec<u8>,
        expected_product: ProductFamily,
    ) -> Result<Self, FirmwareImageError> {
        if expected_product != ProductFamily::Usb3Sata3 {
            bytes.zeroize();
            return Err(FirmwareImageError::UnsupportedProductFamily(
                expected_product,
            ));
        }
        if let Err(error) = validate_file_size(bytes.len()) {
            bytes.zeroize();
            return Err(error);
        }
        let revision = match validate_container(&bytes, expected_product) {
            Ok(revision) => revision,
            Err(error) => {
                bytes.zeroize();
                return Err(error);
            }
        };
        let sha256: [u8; 32] = Sha256::digest(&bytes).into();
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            revision,
            product: expected_product,
            sha256,
            expected_revision: revision,
            signature_evidence: SignatureEvidence::Verified,
        })
    }

    /// Returns the immutable image length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether the immutable image contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the firmware revision parsed from matching header and metadata fields.
    pub const fn revision(&self) -> FirmwareRevision {
        self.revision
    }

    /// Returns the product family established by structural metadata markers.
    ///
    /// The signed boot region does not cover these markers. This value must be
    /// compared with fresh live-device discovery before transfer.
    pub const fn product(&self) -> ProductFamily {
        self.product
    }

    /// Returns the SHA-256 identity of the immutable snapshot.
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Returns the boot-region signature evidence required before acceptance.
    ///
    /// Product and revision metadata are outside the verified signature scope.
    pub const fn signature_evidence(&self) -> SignatureEvidence {
        self.signature_evidence
    }

    /// Returns the expected reported revision after activation, separately from
    /// the template revision retained in an OpenRDX container's outer metadata.
    pub const fn expected_revision(&self) -> FirmwareRevision {
        self.expected_revision
    }

    /// Supplies immutable verified bytes only to the native migration controller.
    #[cfg(target_os = "macos")]
    pub(crate) fn migration_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Revalidates registry-owned family and installed-revision policy.
    pub(crate) fn authorize_for_registry(
        &self,
        installed: FirmwareRevision,
        family: ProductFamily,
    ) -> Result<(), FirmwareImageError> {
        if family != self.product {
            return Err(FirmwareImageError::ProductMismatch);
        }
        // These are the receiver revisions admitted by the current OpenRDX
        // updater. Never allow an integrity-only image on vendor firmware.
        if self.signature_evidence == SignatureEvidence::OpenRdxIntegrityVerified
            && !installed.has_openrdx_update_receiver()
        {
            return Err(FirmwareImageError::OpenRdxReceiverRequired);
        }
        if installed.0 >= FIRST_SIGNED_FIRMWARE_REVISION
            && self.revision.0 < FIRST_SIGNED_FIRMWARE_REVISION
        {
            return Err(FirmwareImageError::UnsignedDowngradeBlocked {
                installed: installed.0,
                candidate: self.revision.0,
            });
        }
        Ok(())
    }

    /// Iterates over exact 4-KiB transfers and a final short tail.
    pub(crate) fn registry_chunks(&self) -> impl ExactSizeIterator<Item = FirmwareChunk<'_>> {
        self.bytes
            .chunks(FIRMWARE_CHUNK_SIZE)
            .enumerate()
            .map(|(index, bytes)| FirmwareChunk {
                offset: (index * FIRMWARE_CHUNK_SIZE) as u32,
                bytes,
            })
    }

    /// Builds the evidence-backed no-data mode-5 finalizer.
    pub(crate) fn registry_finalize_command(&self) -> Result<Command, ProtocolBuildError> {
        write_buffer(0x05, self.len() as u32, &[])
    }

    /// Consumes validated metadata and binds transfer to fresh live-session evidence.
    ///
    /// Only this transition can create an [`InstallableFirmwareImage`]. The
    /// installed revision must come from the selected live device; a later
    /// device operation must revalidate both revision and family if either can
    /// change between discovery and transfer.
    ///
    /// # Errors
    ///
    /// Returns [`FirmwareImageError::UnsignedDowngradeBlocked`] when revision
    /// 0278 or later is offered a pre-0278 candidate. Signed-to-signed rollback
    /// behavior is not established, so no general numeric rollback ban is added.
    pub(crate) fn authorize_for_session(
        self,
        installed: FirmwareRevision,
        identity: DeviceIdentity,
        family: ProductFamily,
        generation: SessionGeneration,
        capability_id: SessionCapabilityId,
    ) -> Result<InstallableFirmwareImage, FirmwareImageError> {
        self.authorize_for_registry(installed, family)?;
        Ok(InstallableFirmwareImage {
            image: self,
            authorization: FirmwareAuthorizationBinding {
                identity,
                family,
                installed_revision: installed,
                generation,
                capability_id,
            },
        })
    }
}

impl Drop for FirmwareImage {
    /// Clears the owned image snapshot before releasing its allocation.
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug)]
struct FirmwareAuthorizationBinding {
    identity: DeviceIdentity,
    family: ProductFamily,
    installed_revision: FirmwareRevision,
    generation: SessionGeneration,
    capability_id: SessionCapabilityId,
}

/// An immutable modern image authorized against an installed firmware revision.
///
/// This type is constructible only through
/// [`crate::host::DeviceSession::authorize_firmware`], making live identity,
/// family, generation, and installed-revision policy structurally mandatory.
pub struct InstallableFirmwareImage {
    image: FirmwareImage,
    authorization: FirmwareAuthorizationBinding,
}

impl InstallableFirmwareImage {
    /// Returns the authorized immutable image length in bytes.
    pub fn len(&self) -> usize {
        self.image.bytes.len()
    }

    /// Reports whether the authorized immutable image contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.image.bytes.is_empty()
    }

    /// Returns the firmware revision authorized for transfer.
    pub const fn revision(&self) -> FirmwareRevision {
        self.image.revision
    }

    /// Returns the structurally matched product family authorized for transfer.
    pub const fn product(&self) -> ProductFamily {
        self.image.product
    }

    /// Returns the SHA-256 identity of the authorized immutable snapshot.
    pub const fn sha256(&self) -> [u8; 32] {
        self.image.sha256
    }

    /// Returns the boot-region signature evidence for the authorized image.
    pub const fn signature_evidence(&self) -> SignatureEvidence {
        self.image.signature_evidence()
    }

    /// Returns the exact reported revision expected after this authorized update.
    pub const fn expected_revision(&self) -> FirmwareRevision {
        self.image.expected_revision()
    }

    /// Returns the complete authorized snapshot for native transport consumers.
    pub fn bytes(&self) -> &[u8] {
        &self.image.bytes
    }

    /// Iterates over exact 4-KiB transfers and a final short tail if present.
    pub fn chunks(&self) -> impl ExactSizeIterator<Item = FirmwareChunk<'_>> {
        self.image
            .bytes
            .chunks(FIRMWARE_CHUNK_SIZE)
            .enumerate()
            .map(|(index, bytes)| FirmwareChunk {
                offset: (index * FIRMWARE_CHUNK_SIZE) as u32,
                bytes,
            })
    }

    /// Builds the exact zero-length mode-5 command at the immutable image length.
    ///
    /// # Errors
    ///
    /// Returns a protocol build error if the already-bounded length cannot be
    /// represented by the command builder.
    pub fn finalize_command(&self) -> Result<Command, ProtocolBuildError> {
        write_buffer(0x05, self.image.bytes.len() as u32, &[])
    }

    /// Reports whether fresh live evidence still matches the consumed authorization.
    pub(crate) fn is_authorized_for(&self, session: &DeviceSession) -> bool {
        let device = session.device();
        self.authorization.identity == *device.identity()
            && self.authorization.family == device.product_family()
            && self.authorization.installed_revision == device.installed_revision()
            && self.authorization.generation == device.generation()
            && session.has_capability(&self.authorization.capability_id)
    }

    /// Reports whether an operation-owned reconnect preserved authorization evidence.
    ///
    /// Discovery revision and generation must advance during reconnect, so this
    /// check retains the exact physical ID, family, and installed revision that
    /// authorized the consumed image while the session validates the new lease.
    pub(crate) fn is_authorized_after_rebind(&self, session: &DeviceSession) -> bool {
        let device = session.device();
        self.authorization.identity.id == device.identity().id
            && self.authorization.family == device.product_family()
            && self.authorization.installed_revision == device.installed_revision()
            && session.has_capability(&self.authorization.capability_id)
    }

    /// Reports whether a rebound lease retains the private authorization lineage.
    pub(crate) fn has_rebound_lineage(&self, session: &DeviceSession) -> bool {
        let device = session.device();
        self.authorization.identity.id == device.identity().id
            && self.authorization.family == device.product_family()
            && session.has_capability(&self.authorization.capability_id)
    }

    /// Returns the exact live revision against which this image was authorized.
    pub(crate) const fn authorized_installed_revision(&self) -> FirmwareRevision {
        self.authorization.installed_revision
    }
}

/// A local firmware file failed an evidence-backed pre-transfer validation.
#[derive(Debug)]
pub enum FirmwareImageError {
    /// Opening, inspecting, or reading the selected file failed.
    Io(io::Error),
    /// The selected file does not have the modern `.BIN` extension.
    UnsupportedExtension,
    /// The selected product belongs to the unimplemented legacy path.
    UnsupportedProductFamily(ProductFamily),
    /// The opened handle does not refer to a regular file.
    NotARegularFile,
    /// The file is too short to hold the proven signed-container regions.
    FileTooSmall {
        /// Smallest safe structural length.
        minimum: usize,
        /// Observed handle length.
        actual: usize,
    },
    /// The file exceeds the bounded modern transport offset.
    FileTooLarge {
        /// Largest accepted byte length.
        maximum: usize,
        /// Observed handle length.
        actual: usize,
    },
    /// The opened file's byte count changed between handle metadata and its read.
    FileChangedDuringRead {
        /// Length observed on the opened handle before reading.
        expected: usize,
        /// Bounded byte count actually read.
        actual: usize,
    },
    /// The outer header length fields do not describe the immutable snapshot.
    InvalidHeaderLength,
    /// A required fixed-width byte range is truncated.
    TruncatedStructure,
    /// The record count is zero or exceeds the bound of 100.
    InvalidRecordCount(u32),
    /// No required type-1 modern firmware record was found.
    MissingFirmwareRecord,
    /// The type-1 record failed its boundary/additive relation.
    InvalidFirmwareRecord,
    /// The target address is not the proven TUSB9261 load address `0x4000`.
    UnsupportedLoadAddress(u32),
    /// Embedded product markers do not match the selected product family.
    ProductMismatch,
    /// A revision field is not exactly four decimal ASCII digits.
    InvalidRevision,
    /// The outer and product-metadata revision fields disagree.
    RevisionMismatch,
    /// A reproduced drive rolling check does not match its stored value.
    RollingCheckMismatch {
        /// Stable name of the failed covered region.
        region: &'static str,
    },
    /// The embedded TI boot record sequence, length, or additive checksum is invalid.
    InvalidTiBootRecords,
    /// The documented RSA signature does not validate the complete TI boot region.
    InvalidSignature,
    /// Paired OpenRDX release metadata does not identify this exact container.
    InvalidOpenRdxManifest,
    /// The explicit OpenRDX marker, digest or reserved integrity bytes are invalid.
    InvalidOpenRdxIntegrity,
    /// Integrity-only OpenRDX images require an already supported OpenRDX receiver.
    OpenRdxReceiverRequired,
    /// A pre-signed-era candidate would cross the documented downgrade boundary.
    UnsignedDowngradeBlocked {
        /// Currently installed decimal firmware revision.
        installed: u16,
        /// Candidate decimal firmware revision.
        candidate: u16,
    },
}

impl Display for FirmwareImageError {
    /// Formats a path-free description suitable for native preflight diagnostics.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOpenRdxManifest => {
                formatter.write_str("OpenRDX release metadata does not match the image")
            }
            Self::InvalidOpenRdxIntegrity => {
                formatter.write_str("OpenRDX image integrity validation failed")
            }
            Self::OpenRdxReceiverRequired => {
                formatter.write_str("OpenRDX image requires an existing supported OpenRDX receiver")
            }
            Self::Io(error) => write!(formatter, "firmware file I/O failed: {error}"),
            Self::UnsupportedExtension => {
                formatter.write_str("modern firmware requires a .BIN file")
            }
            Self::UnsupportedProductFamily(product) => {
                write!(
                    formatter,
                    "unsupported firmware product family: {product:?}"
                )
            }
            Self::NotARegularFile => formatter.write_str("firmware input is not a regular file"),
            Self::FileTooSmall { minimum, actual } => {
                write!(
                    formatter,
                    "firmware requires at least {minimum} bytes, received {actual}"
                )
            }
            Self::FileTooLarge { maximum, actual } => {
                write!(
                    formatter,
                    "firmware accepts at most {maximum} bytes, received {actual}"
                )
            }
            Self::FileChangedDuringRead { expected, actual } => write!(
                formatter,
                "firmware length changed during read: expected {expected} bytes, received {actual}"
            ),
            Self::InvalidHeaderLength => {
                formatter.write_str("firmware outer lengths are inconsistent")
            }
            Self::TruncatedStructure => formatter.write_str("firmware structure is truncated"),
            Self::InvalidRecordCount(count) => {
                write!(formatter, "invalid firmware record count {count}")
            }
            Self::MissingFirmwareRecord => formatter.write_str("firmware type-1 record is missing"),
            Self::InvalidFirmwareRecord => {
                formatter.write_str("firmware type-1 record is inconsistent")
            }
            Self::UnsupportedLoadAddress(address) => {
                write!(
                    formatter,
                    "unsupported firmware load address 0x{address:08X}"
                )
            }
            Self::ProductMismatch => {
                formatter.write_str("firmware product does not match the selected drive")
            }
            Self::InvalidRevision => {
                formatter.write_str("firmware revision is not four decimal digits")
            }
            Self::RevisionMismatch => formatter.write_str("firmware revision fields disagree"),
            Self::RollingCheckMismatch { region } => {
                write!(formatter, "firmware {region} rolling check failed")
            }
            Self::InvalidTiBootRecords => {
                formatter.write_str("firmware TI boot records are invalid")
            }
            Self::InvalidSignature => formatter.write_str("firmware signature validation failed"),
            Self::UnsignedDowngradeBlocked {
                installed,
                candidate,
            } => write!(
                formatter,
                "unsigned firmware revision {candidate:04} cannot replace signed-era revision {installed:04}"
            ),
        }
    }
}

impl Error for FirmwareImageError {
    /// Returns the underlying file error when validation failed during I/O.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Rejects filenames outside the documented case-insensitive `.BIN` path.
fn validate_extension(path: &Path) -> Result<(), FirmwareImageError> {
    let supported = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("bin"));
    if supported {
        Ok(())
    } else {
        Err(FirmwareImageError::UnsupportedExtension)
    }
}

/// Applies a fixed pre-allocation lower bound and the 24-bit transport upper bound.
fn validate_file_size(length: usize) -> Result<(), FirmwareImageError> {
    let minimum = BOOT_REGION_START + TRAILER_LENGTH;
    if length < minimum {
        return Err(FirmwareImageError::FileTooSmall {
            minimum,
            actual: length,
        });
    }
    if length > MAX_FIRMWARE_IMAGE_SIZE {
        return Err(FirmwareImageError::FileTooLarge {
            maximum: MAX_FIRMWARE_IMAGE_SIZE,
            actual: length,
        });
    }
    Ok(())
}

/// Validates the complete modern container and returns its embedded revision.
fn validate_container(
    bytes: &[u8],
    expected_product: ProductFamily,
) -> Result<FirmwareRevision, FirmwareImageError> {
    let revision = validate_container_structure(bytes, expected_product)?;
    verify_signature(bytes, bytes.len() - TRAILER_LENGTH)?;
    Ok(revision)
}

/// Validates shared container, product, rolling-check and TI-record structure.
fn validate_container_structure(
    bytes: &[u8],
    expected_product: ProductFamily,
) -> Result<FirmwareRevision, FirmwareImageError> {
    let first_length = read_be_u32(bytes, 0)? as usize;
    let total_length = read_be_u32(bytes, 4)? as usize;
    if total_length != bytes.len()
        || first_length.checked_add(OUTER_HEADER_LENGTH) != Some(total_length)
    {
        return Err(FirmwareImageError::InvalidHeaderLength);
    }

    let header_revision = parse_revision(required_range(bytes, 0x0C, 4)?)?;
    let product_metadata = validate_type_one_record(bytes)?;
    validate_product(product_metadata, expected_product)?;
    let metadata_revision = parse_revision(required_range(product_metadata, 0, 4)?)?;
    if header_revision != metadata_revision {
        return Err(FirmwareImageError::RevisionMismatch);
    }

    let boot_end = bytes
        .len()
        .checked_sub(TRAILER_LENGTH)
        .ok_or(FirmwareImageError::TruncatedStructure)?;
    validate_rolling_checks(bytes, boot_end)?;
    validate_ti_boot_records(required_range(
        bytes,
        BOOT_REGION_START,
        boot_end - BOOT_REGION_START,
    )?)?;
    Ok(header_revision)
}

/// Finds and validates the type-1 record, returning its product metadata.
fn validate_type_one_record(bytes: &[u8]) -> Result<&[u8], FirmwareImageError> {
    let record_count = read_be_u32(bytes, OUTER_HEADER_LENGTH)?;
    if !(1..=MAX_RECORD_COUNT).contains(&record_count) {
        return Err(FirmwareImageError::InvalidRecordCount(record_count));
    }

    let mut cursor = OUTER_HEADER_LENGTH + 4;
    for _ in 0..record_count {
        let record_type = read_be_u32(bytes, cursor)?;
        cursor += 4;
        if record_type != 1 {
            continue;
        }

        let header_offset = cursor;
        let header = required_range(bytes, header_offset, TYPE_ONE_RECORD_HEADER_LENGTH)?;
        let record_length = read_be_u32(header, 0)? as usize;
        let load_address = read_be_u32(header, 8)?;
        let boundary_start = read_be_u32(header, 12)?;
        let metadata_displacement = read_be_u32(header, 16)?;
        let boundary_end = read_be_u32(header, 20)?;
        if record_length.checked_add(header_offset) != Some(bytes.len())
            || boundary_start.checked_add(metadata_displacement) != Some(boundary_end)
        {
            return Err(FirmwareImageError::InvalidFirmwareRecord);
        }
        if load_address != 0x4000 {
            return Err(FirmwareImageError::UnsupportedLoadAddress(load_address));
        }

        let after_header = header_offset + TYPE_ONE_RECORD_HEADER_LENGTH;
        let metadata_block_start = after_header
            .checked_add(metadata_displacement as usize)
            .and_then(|offset| offset.checked_sub(0x18))
            .ok_or(FirmwareImageError::InvalidFirmwareRecord)?;
        // The parser reads a four-byte prefix immediately before the
        // product structure reached through the record displacement.
        let metadata_start = metadata_block_start
            .checked_add(4)
            .ok_or(FirmwareImageError::InvalidFirmwareRecord)?;
        return required_range(bytes, metadata_start, PRODUCT_METADATA_LENGTH);
    }
    Err(FirmwareImageError::MissingFirmwareRecord)
}

/// Matches the exact USB3/SATA3 metadata markers from the accepted image.
fn validate_product(
    metadata: &[u8],
    expected_product: ProductFamily,
) -> Result<(), FirmwareImageError> {
    let matches = expected_product == ProductFamily::Usb3Sata3
        && required_range(metadata, 12, 4)? == b"S3  "
        && required_range(metadata, 16, 4)? == b"R2eF";
    if matches {
        Ok(())
    } else {
        Err(FirmwareImageError::ProductMismatch)
    }
}

/// Parses exactly four decimal ASCII digits without accepting lossy text.
fn parse_revision(bytes: &[u8]) -> Result<FirmwareRevision, FirmwareImageError> {
    if bytes.len() != 4 || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(FirmwareImageError::InvalidRevision);
    }
    let value = bytes
        .iter()
        .fold(0_u16, |value, digit| value * 10 + u16::from(*digit - b'0'));
    FirmwareRevision::new(value)
}

/// Reproduces both rolling checks used by the drive's streamed parser.
fn validate_rolling_checks(bytes: &[u8], boot_end: usize) -> Result<(), FirmwareImageError> {
    let stored_metadata = read_be_u32(bytes, METADATA_CHECK_START)?;
    let calculated_metadata = rdx_rolling_check(&bytes[..METADATA_CHECK_START], u32::MAX);
    if stored_metadata != calculated_metadata
        || rdx_rolling_check(
            required_range(bytes, METADATA_CHECK_START, 4)?,
            calculated_metadata,
        ) != 0
    {
        return Err(FirmwareImageError::RollingCheckMismatch { region: "metadata" });
    }

    let stored_boot = read_be_u32(bytes, boot_end)?;
    let calculated_boot = rdx_rolling_check(
        required_range(bytes, BOOT_REGION_START, boot_end - BOOT_REGION_START)?,
        0,
    );
    if stored_boot != calculated_boot {
        return Err(FirmwareImageError::RollingCheckMismatch { region: "boot" });
    }
    Ok(())
}

/// Validates the exact TI identifier and descriptor/firmware record checksums.
fn validate_ti_boot_records(bytes: &[u8]) -> Result<(), FirmwareImageError> {
    if read_le_u16(bytes, 0)? != TUSB9261_FIRMWARE_ID {
        return Err(FirmwareImageError::InvalidTiBootRecords);
    }

    let mut cursor = 2;
    let mut saw_descriptor = false;
    let mut saw_firmware = false;
    while cursor < bytes.len() {
        let record_type = *bytes
            .get(cursor)
            .ok_or(FirmwareImageError::InvalidTiBootRecords)?;
        let payload_length = read_le_u32(bytes, cursor + 1)? as usize;
        let payload_start = cursor
            .checked_add(5)
            .ok_or(FirmwareImageError::InvalidTiBootRecords)?;
        let checksum_offset = payload_start
            .checked_add(payload_length)
            .filter(|offset| *offset < bytes.len())
            .ok_or(FirmwareImageError::InvalidTiBootRecords)?;
        let payload = &bytes[payload_start..checksum_offset];
        let stored_checksum = bytes[checksum_offset];
        let calculated_checksum = payload
            .iter()
            .fold(0_u8, |checksum, byte| checksum.wrapping_add(*byte));
        if stored_checksum != calculated_checksum {
            return Err(FirmwareImageError::InvalidTiBootRecords);
        }

        match record_type {
            TUSB9261_DESCRIPTOR_RECORD if !saw_descriptor && !saw_firmware => {
                saw_descriptor = true;
            }
            TUSB9261_FIRMWARE_RECORD if saw_descriptor && !saw_firmware => {
                saw_firmware = true;
            }
            _ => return Err(FirmwareImageError::InvalidTiBootRecords),
        }
        cursor = checksum_offset + 1;
        if saw_firmware {
            break;
        }
    }
    if saw_descriptor && saw_firmware && cursor == bytes.len() {
        Ok(())
    } else {
        Err(FirmwareImageError::InvalidTiBootRecords)
    }
}

/// Verifies the proven RSA-1024 PKCS#1 v1.5 signature over the TI boot region.
fn verify_signature(bytes: &[u8], boot_end: usize) -> Result<(), FirmwareImageError> {
    let key = RsaPublicKey::new(
        BigUint::from_bytes_be(&RDX_SIGNING_MODULUS),
        BigUint::from(RDX_SIGNING_EXPONENT),
    )
    .map_err(|_| FirmwareImageError::InvalidSignature)?;
    let verifier = VerifyingKey::<Sha256>::new(key);
    let signature = Signature::try_from(required_range(
        bytes,
        SIGNATURE_START,
        SIGNATURE_END - SIGNATURE_START,
    )?)
    .map_err(|_| FirmwareImageError::InvalidSignature)?;
    verifier
        .verify(&bytes[BOOT_REGION_START..boot_end], &signature)
        .map_err(|_| FirmwareImageError::InvalidSignature)
}

/// Implements the exact rolling-check routine defined at drive address `0x0800A840`.
fn rdx_rolling_check(bytes: &[u8], initial: u32) -> u32 {
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

/// Returns a checked fixed-width range without indexing malformed input.
fn required_range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], FirmwareImageError> {
    let end = offset
        .checked_add(length)
        .ok_or(FirmwareImageError::TruncatedStructure)?;
    bytes
        .get(offset..end)
        .ok_or(FirmwareImageError::TruncatedStructure)
}

/// Reads one checked big-endian 32-bit field.
fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, FirmwareImageError> {
    let bytes: [u8; 4] = required_range(bytes, offset, 4)?
        .try_into()
        .map_err(|_| FirmwareImageError::TruncatedStructure)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Reads one checked little-endian 32-bit field.
fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, FirmwareImageError> {
    let bytes: [u8; 4] = required_range(bytes, offset, 4)?
        .try_into()
        .map_err(|_| FirmwareImageError::TruncatedStructure)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Reads one checked little-endian 16-bit field.
fn read_le_u16(bytes: &[u8], offset: usize) -> Result<u16, FirmwareImageError> {
    let bytes: [u8; 2] = required_range(bytes, offset, 2)?
        .try_into()
        .map_err(|_| FirmwareImageError::TruncatedStructure)?;
    Ok(u16::from_le_bytes(bytes))
}

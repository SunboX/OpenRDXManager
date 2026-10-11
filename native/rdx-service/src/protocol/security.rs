// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Evidence-gated parsing for inbound security descriptors.

use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{EvidenceStatus, ProtocolParseError};

const DESCRIPTOR_HEADER_LENGTH: usize = 4;
const C0_BASE_BODY_LENGTH: usize = 0x4C;
const C1_SHORT_BODY_LENGTH: usize = 0x10;
const C1_FULL_BODY_LENGTH: usize = 0x80;
const SHA256_BLOCK_LENGTH: usize = 64;
const SHA256_OUTPUT_LENGTH: usize = 32;
const AUTHENTICATION_OUTPUT_LENGTH: usize = 64;
const MAX_CREDENTIAL_BYTES: usize = 4096;
const MAX_KDF_ITERATIONS: u32 = 10_000_000;

/// Largest complete inbound descriptor accepted from the reader.
pub const MAX_INBOUND_SECURITY_DESCRIPTOR_LENGTH: usize =
    DESCRIPTOR_HEADER_LENGTH + C1_FULL_BODY_LENGTH;

/// Largest SECURITY PROTOCOL IN aggregate allocation.
pub const MAX_INBOUND_SECURITY_AGGREGATE_LENGTH: usize = 0x1000;

/// Per-slot and global parameters for the two-stage authentication KDF.
pub struct AuthenticationKdfParameters {
    slot_salt: Zeroizing<[u8; SHA256_OUTPUT_LENGTH]>,
    slot_iterations: u32,
    global_salt: Zeroizing<[u8; SHA256_OUTPUT_LENGTH]>,
    global_iterations: u32,
}

impl AuthenticationKdfParameters {
    /// Creates bounded parameters from one validated descriptor set.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationKdfError::InvalidIterationCount`] when either
    /// count is zero or exceeds the service's denial-of-service bound.
    pub fn new(
        slot_salt: [u8; SHA256_OUTPUT_LENGTH],
        slot_iterations: u32,
        global_salt: [u8; SHA256_OUTPUT_LENGTH],
        global_iterations: u32,
    ) -> Result<Self, AuthenticationKdfError> {
        validate_iteration_count("slot", slot_iterations)?;
        validate_iteration_count("global", global_iterations)?;
        Ok(Self {
            slot_salt: Zeroizing::new(slot_salt),
            slot_iterations,
            global_salt: Zeroizing::new(global_salt),
            global_iterations,
        })
    }
}

impl Debug for AuthenticationKdfParameters {
    /// Formats only non-secret bounds and redacts both device-provided salts.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticationKdfParameters")
            .field("slot_salt", &"<redacted>")
            .field("slot_iterations", &self.slot_iterations)
            .field("global_salt", &"<redacted>")
            .field("global_iterations", &self.global_iterations)
            .finish()
    }
}

/// One 64-byte result of the two-stage PBKDF2-HMAC-SHA-256 derivation.
pub struct AuthenticationMaterial(Zeroizing<Vec<u8>>);

impl AuthenticationMaterial {
    /// Borrows the transient material for evidence-backed descriptor assembly.
    /// Callers must not log, persist, or copy this value beyond an operation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for AuthenticationMaterial {
    /// Redacts the derived bytes while retaining their structural length.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "AuthenticationMaterial(<redacted:{} bytes>)",
            self.0.len()
        )
    }
}

/// Failure to derive bounded authentication material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationKdfError {
    /// A device-provided KDF iteration count is zero or exceeds the service bound.
    InvalidIterationCount {
        /// Parameter stage whose count was rejected.
        stage: &'static str,
        /// Rejected count.
        value: u32,
    },
    /// The UTF-8 credential buffer is empty or larger than the UI bound.
    InvalidCredentialLength {
        /// Supplied credential byte length.
        actual: usize,
    },
}

impl Display for AuthenticationKdfError {
    /// Formats a redacted failure without credential bytes or salts.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIterationCount { stage, value } => {
                write!(formatter, "invalid {stage} KDF iteration count {value}")
            }
            Self::InvalidCredentialLength { actual } => {
                write!(
                    formatter,
                    "invalid transient credential byte length {actual}"
                )
            }
        }
    }
}

impl Error for AuthenticationKdfError {}

/// Derives the exact 64-byte two-stage authentication material.
///
/// The credential, first-stage output, HMAC work buffers, and returned material
/// all use zeroizing storage. Descriptor selector/field semantics remain
/// incomplete, so deriving these bytes does not authorize a device write.
///
/// # Errors
///
/// Returns [`AuthenticationKdfError::InvalidCredentialLength`] for an empty or
/// oversized byte buffer.
pub fn derive_authentication_material(
    credential: Zeroizing<Vec<u8>>,
    parameters: &AuthenticationKdfParameters,
) -> Result<AuthenticationMaterial, AuthenticationKdfError> {
    if credential.is_empty() || credential.len() > MAX_CREDENTIAL_BYTES {
        return Err(AuthenticationKdfError::InvalidCredentialLength {
            actual: credential.len(),
        });
    }
    let stage_one = pbkdf2_hmac_sha256(
        &credential,
        &parameters.slot_salt[..],
        parameters.slot_iterations,
        AUTHENTICATION_OUTPUT_LENGTH,
    );
    let stage_two = pbkdf2_hmac_sha256(
        &stage_one,
        &parameters.global_salt[..],
        parameters.global_iterations,
        AUTHENTICATION_OUTPUT_LENGTH,
    );
    Ok(AuthenticationMaterial(stage_two))
}

/// One complete, length-validated descriptor from a device response.
///
/// The descriptor body may contain credential or key material. It is retained
/// only in private zeroizing storage so callers can inspect non-secret metadata
/// without receiving an unrestricted secret buffer.
pub struct InboundSecurityDescriptor {
    id: u8,
    flags: u8,
    body: Zeroizing<Vec<u8>>,
}

impl InboundSecurityDescriptor {
    /// Parses one complete descriptor with an independently verified inbound layout.
    ///
    /// Accepted layouts are the base `0xC0` body and the short and full `0xC1`
    /// bodies. The optional variable-length `0xC0` extension is not accepted
    /// because its complete bounds are not independently proven. Inbound `0xC5`
    /// is also rejected: the reader proves bytes it accesses, but not
    /// an exact declared-length pair.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolParseError`] for incomplete, oversized, unsupported,
    /// or inconsistent descriptor bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolParseError> {
        ensure_descriptor_bounds(bytes)?;

        let declared_body = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        let declared_total = DESCRIPTOR_HEADER_LENGTH + declared_body;
        if declared_total != bytes.len() {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "inbound security descriptor total length",
                declared: declared_total,
                actual: bytes.len(),
            });
        }
        if !is_supported_inbound_layout(bytes[0], declared_body) {
            return Err(ProtocolParseError::UnsupportedValue {
                context: "inbound security descriptor ID/length layout",
                value: (u64::from(bytes[0]) << 16) | u64::from(declared_body as u16),
            });
        }

        Ok(Self {
            id: bytes[0],
            flags: bytes[1],
            body: Zeroizing::new(bytes[DESCRIPTOR_HEADER_LENGTH..].to_vec()),
        })
    }

    /// Returns the descriptor ID.
    #[must_use]
    pub const fn id(&self) -> u8 {
        self.id
    }

    /// Returns the descriptor's uninterpreted flags byte.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Returns the descriptor body length without exposing its contents.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Returns the evidence level for the inbound descriptor layout.
    #[must_use]
    pub const fn evidence(&self) -> EvidenceStatus {
        EvidenceStatus::ImplementationReference
    }
}

impl Debug for InboundSecurityDescriptor {
    /// Formats descriptor metadata while always redacting sensitive body bytes.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InboundSecurityDescriptor")
            .field("id", &self.id)
            .field("flags", &self.flags)
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

/// Parses a complete inbound aggregate in wire order.
///
/// Unknown or outbound-only descriptor layouts are rejected rather than
/// assigned inbound meaning. Descriptor bodies remain in private zeroizing
/// storage in the returned values.
///
/// # Errors
///
/// Returns [`ProtocolParseError`] when the aggregate is empty or oversized, a
/// descriptor header/body is truncated, or any descriptor layout is unsupported.
pub fn parse_inbound_security_descriptors(
    bytes: &[u8],
) -> Result<Vec<InboundSecurityDescriptor>, ProtocolParseError> {
    if bytes.len() > MAX_INBOUND_SECURITY_AGGREGATE_LENGTH {
        return Err(ProtocolParseError::PayloadTooLarge {
            context: "inbound security descriptor aggregate",
            maximum: MAX_INBOUND_SECURITY_AGGREGATE_LENGTH,
            actual: bytes.len(),
        });
    }
    if bytes.len() < DESCRIPTOR_HEADER_LENGTH {
        return Err(ProtocolParseError::PayloadTooShort {
            context: "inbound security descriptor aggregate",
            minimum: DESCRIPTOR_HEADER_LENGTH,
            actual: bytes.len(),
        });
    }

    let mut descriptors = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < DESCRIPTOR_HEADER_LENGTH {
            return Err(ProtocolParseError::PayloadTooShort {
                context: "inbound security descriptor header",
                minimum: DESCRIPTOR_HEADER_LENGTH,
                actual: remaining,
            });
        }

        let declared_body = usize::from(u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]));
        let record_length = DESCRIPTOR_HEADER_LENGTH + declared_body;
        if record_length > remaining {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "inbound security descriptor aggregate record",
                declared: record_length,
                actual: remaining,
            });
        }

        descriptors.push(InboundSecurityDescriptor::parse(
            &bytes[offset..offset + record_length],
        )?);
        offset += record_length;
    }

    Ok(descriptors)
}

/// A descriptor layout used by legacy outbound serialization.
///
/// This type describes framing evidence only. It cannot construct a payload,
/// and [`Self::write_evidence`] remains incomplete for every layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundSecurityDescriptorLayout {
    id: u8,
    body_len: usize,
}

impl OutboundSecurityDescriptorLayout {
    /// Returns the outbound serialization layout for `id`, if present.
    #[must_use]
    pub const fn for_id(id: u8) -> Option<Self> {
        let body_len = match id {
            0xC1 => 0x70,
            0xC2 | 0xC4 => 0x44,
            0xC3 => 0x28,
            0xC5 => 0x04,
            _ => return None,
        };
        Some(Self { id, body_len })
    }

    /// Returns the outbound serialization descriptor ID.
    #[must_use]
    pub const fn id(self) -> u8 {
        self.id
    }

    /// Returns the outbound serialization body length.
    #[must_use]
    pub const fn body_len(self) -> usize {
        self.body_len
    }

    /// Returns the evidence status for the serializer's ID/length layout.
    #[must_use]
    pub const fn layout_evidence(self) -> SecurityEvidence {
        SecurityEvidence::ImplementationReference
    }

    /// Returns the evidence status for emitting this outbound descriptor.
    ///
    /// The enclosing selector and aggregate payload semantics are unresolved,
    /// so every outbound write remains disabled.
    #[must_use]
    pub const fn write_evidence(self) -> SecurityEvidence {
        SecurityEvidence::Incomplete
    }
}

/// Security behavior or protocol action whose evidence can be queried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityOperation {
    /// Display the documented eight-slot credential and permission policy.
    DisplayCredentialPolicy,
    /// Parse inbound descriptors without exposing their bodies.
    ParseInboundDescriptor,
    /// Create a credential on the cartridge.
    CreateCredential,
    /// Authenticate a credential for the current media session.
    Authenticate,
    /// Close the current authenticated session.
    CloseSession,
    /// Change an existing credential through the temporary-slot workflow.
    ChangeCredential,
    /// Delete a credential slot.
    DeleteCredential,
    /// Add or remove automatic drive/media authentication state.
    AutomaticAuthentication,
    /// Configure or remove the AES protected-volume mode.
    ConfigureAes,
}

/// Evidence level governing whether a security behavior may be implemented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityEvidence {
    /// User-visible policy is stated in bundled vendor documentation.
    Documented,
    /// A read-only wire layout is supported by an implementation reference.
    ImplementationReference,
    /// Exact selector, aggregate payload, or on-media semantics remain unresolved.
    Incomplete,
}

impl SecurityEvidence {
    /// Returns the evidence available for a security behavior or action.
    ///
    /// Mutating device operations remain incomplete and therefore unavailable;
    /// inbound descriptor parsing does not make an outbound write mapping proven.
    #[must_use]
    pub const fn for_operation(operation: SecurityOperation) -> Self {
        match operation {
            SecurityOperation::DisplayCredentialPolicy => Self::Documented,
            SecurityOperation::ParseInboundDescriptor => Self::ImplementationReference,
            SecurityOperation::CreateCredential
            | SecurityOperation::Authenticate
            | SecurityOperation::CloseSession
            | SecurityOperation::ChangeCredential
            | SecurityOperation::DeleteCredential
            | SecurityOperation::AutomaticAuthentication
            | SecurityOperation::ConfigureAes => Self::Incomplete,
        }
    }
}

/// Validates the absolute inbound descriptor allocation bounds.
fn ensure_descriptor_bounds(bytes: &[u8]) -> Result<(), ProtocolParseError> {
    if bytes.len() > MAX_INBOUND_SECURITY_DESCRIPTOR_LENGTH {
        return Err(ProtocolParseError::PayloadTooLarge {
            context: "inbound security descriptor",
            maximum: MAX_INBOUND_SECURITY_DESCRIPTOR_LENGTH,
            actual: bytes.len(),
        });
    }
    if bytes.len() < DESCRIPTOR_HEADER_LENGTH {
        return Err(ProtocolParseError::PayloadTooShort {
            context: "inbound security descriptor header",
            minimum: DESCRIPTOR_HEADER_LENGTH,
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Reports whether an ID/body-length pair is consumed by the reader.
const fn is_supported_inbound_layout(id: u8, body_len: usize) -> bool {
    matches!(
        (id, body_len),
        (0xC0, C0_BASE_BODY_LENGTH) | (0xC1, C1_SHORT_BODY_LENGTH | C1_FULL_BODY_LENGTH)
    )
}

/// Rejects a device-provided iteration count that could disable the service.
fn validate_iteration_count(stage: &'static str, value: u32) -> Result<(), AuthenticationKdfError> {
    if value == 0 || value > MAX_KDF_ITERATIONS {
        return Err(AuthenticationKdfError::InvalidIterationCount { stage, value });
    }
    Ok(())
}

/// Computes bounded PBKDF2-HMAC-SHA-256 into zeroizing output storage.
fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_length: usize,
) -> Zeroizing<Vec<u8>> {
    let block_count = output_length.div_ceil(SHA256_OUTPUT_LENGTH);
    let mut output = Zeroizing::new(Vec::with_capacity(output_length));
    for block_index in 1..=block_count {
        let mut input = Zeroizing::new(Vec::with_capacity(salt.len() + 4));
        input.extend_from_slice(salt);
        input.extend_from_slice(&(block_index as u32).to_be_bytes());
        let mut previous = hmac_sha256(password, &input);
        let mut accumulated = Zeroizing::new(*previous);
        for _ in 1..iterations {
            previous = hmac_sha256(password, &previous[..]);
            for (target, source) in accumulated.iter_mut().zip(previous.iter()) {
                *target ^= *source;
            }
        }
        output.extend_from_slice(&accumulated[..]);
    }
    output.truncate(output_length);
    output
}

/// Computes HMAC-SHA-256 while zeroizing normalized keys and digest intermediates.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; SHA256_OUTPUT_LENGTH]> {
    let mut normalized_key = Zeroizing::new([0_u8; SHA256_BLOCK_LENGTH]);
    if key.len() > SHA256_BLOCK_LENGTH {
        let digest: Zeroizing<[u8; SHA256_OUTPUT_LENGTH]> =
            Zeroizing::new(Sha256::digest(key).into());
        normalized_key[..SHA256_OUTPUT_LENGTH].copy_from_slice(&digest[..]);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = Zeroizing::new([0x36_u8; SHA256_BLOCK_LENGTH]);
    let mut outer_pad = Zeroizing::new([0x5C_u8; SHA256_BLOCK_LENGTH]);
    for index in 0..SHA256_BLOCK_LENGTH {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad[..]);
    inner.update(data);
    let inner_digest: Zeroizing<[u8; SHA256_OUTPUT_LENGTH]> =
        Zeroizing::new(inner.finalize().into());
    let mut outer = Sha256::new();
    outer.update(&outer_pad[..]);
    outer.update(&inner_digest[..]);
    Zeroizing::new(outer.finalize().into())
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroize;

    use super::InboundSecurityDescriptor;

    /// Proves that the private sensitive storage can be zeroized in place.
    #[test]
    fn sensitive_storage_zeroizes_in_place() {
        let mut fixture = vec![0xC1, 0, 0, 0x10];
        fixture.extend_from_slice(b"TOP_SECRET_VALUE");
        let mut descriptor =
            InboundSecurityDescriptor::parse(&fixture).expect("complete short C1 descriptor");

        descriptor.body.zeroize();

        assert!(descriptor.body.iter().all(|byte| *byte == 0));
    }
}

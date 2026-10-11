// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Renderer-safe structured error contracts.

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::model::{MessageKey, ReasonCode, SupportCorrelationId};
use crate::transport::DispatchCertainty;

/// Maximum cleanup records retained in one renderer-safe terminal failure.
pub const MAX_CLEANUP_EVIDENCE: usize = 16;
/// Maximum recovered retry records retained in one terminal failure.
pub const MAX_ATTEMPT_HISTORY: usize = 1;

/// Categorizes a reported failure without exposing host implementation details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCategory {
    /// A host platform or prerequisite prevented the operation.
    Platform,
    /// A bounded device transport command or connection failed.
    Transport,
}

/// Sanitized SCSI sense details safe for service clients and logs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SenseSummary {
    /// Stable, kebab-case interpretation of the sense condition.
    pub key: ReasonCode,
    /// Optional additional-sense code when a documented interpretation exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asc: Option<u8>,
    /// Optional additional-sense qualifier when a documented interpretation exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ascq: Option<u8>,
    /// Translation key for the safe user-visible description.
    pub message_key: MessageKey,
}

/// One bounded safe primary-adjacent or cleanup failure observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    /// Stable graph stage where this evidence was observed.
    stage: ReasonCode,
    /// Stable path-free failure code.
    code: ReasonCode,
    /// Optional explicit command-dispatch certainty.
    #[serde(skip_serializing_if = "Option::is_none")]
    dispatch_certainty: Option<DispatchCertainty>,
    /// Optional sanitized sense interpretation.
    #[serde(skip_serializing_if = "Option::is_none")]
    sense_summary: Option<SenseSummary>,
}

impl FailureEvidence {
    /// Creates one strict failure observation that cannot claim dispatch success.
    ///
    /// # Errors
    ///
    /// Returns an error when failure evidence carries `succeeded` certainty.
    pub fn new(
        stage: ReasonCode,
        code: ReasonCode,
        dispatch_certainty: Option<DispatchCertainty>,
        sense_summary: Option<SenseSummary>,
    ) -> Result<Self, &'static str> {
        if dispatch_certainty == Some(DispatchCertainty::Succeeded) {
            return Err("failure dispatch certainty cannot be succeeded");
        }
        Ok(Self {
            stage,
            code,
            dispatch_certainty,
            sense_summary,
        })
    }

    /// Returns the graph stage where the failure was observed.
    #[must_use]
    pub const fn stage(&self) -> &ReasonCode {
        &self.stage
    }

    /// Returns the stable sanitized failure code.
    #[must_use]
    pub const fn code(&self) -> &ReasonCode {
        &self.code
    }

    /// Returns explicit dispatch certainty when the evidence came from a command.
    #[must_use]
    pub const fn dispatch_certainty(&self) -> Option<DispatchCertainty> {
        self.dispatch_certainty
    }

    /// Returns the optional sanitized sense interpretation.
    #[must_use]
    pub const fn sense_summary(&self) -> Option<&SenseSummary> {
        self.sense_summary.as_ref()
    }
}

impl<'de> Deserialize<'de> for FailureEvidence {
    /// Deserializes a strict flat failure record and rejects success evidence.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawFailureEvidence {
            stage: ReasonCode,
            code: ReasonCode,
            dispatch_certainty: Option<DispatchCertainty>,
            sense_summary: Option<SenseSummary>,
        }

        let raw = RawFailureEvidence::deserialize(deserializer)?;
        Self::new(
            raw.stage,
            raw.code,
            raw.dispatch_certainty,
            raw.sense_summary,
        )
        .map_err(de::Error::custom)
    }
}

/// One recovered firmware transfer-attempt observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptEvidence {
    attempt: u8,
    stage: ReasonCode,
    code: ReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    dispatch_certainty: Option<DispatchCertainty>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sense_summary: Option<SenseSummary>,
}

impl AttemptEvidence {
    /// Creates evidence for the only recoverable whole-file attempt: attempt one.
    ///
    /// # Errors
    ///
    /// Returns an error unless this is attempt one at a firmware retry stage.
    pub fn new(attempt: u8, evidence: FailureEvidence) -> Result<Self, &'static str> {
        if attempt != 1 {
            return Err("recovered firmware attempt must be one");
        }
        if !matches!(
            evidence.stage.as_str(),
            "firmware-writing" | "firmware-finalizing"
        ) {
            return Err("recovered attempt stage must be firmware writing or finalizing");
        }
        Ok(Self {
            attempt,
            stage: evidence.stage,
            code: evidence.code,
            dispatch_certainty: evidence.dispatch_certainty,
            sense_summary: evidence.sense_summary,
        })
    }

    /// Returns the one-based whole-file attempt number.
    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    /// Returns the graph stage where this attempt evidence was observed.
    #[must_use]
    pub const fn stage(&self) -> &ReasonCode {
        &self.stage
    }

    /// Returns the stable sanitized attempt failure code.
    #[must_use]
    pub const fn code(&self) -> &ReasonCode {
        &self.code
    }
}

impl<'de> Deserialize<'de> for AttemptEvidence {
    /// Deserializes a strict flat attempt record and validates its range.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawAttemptEvidence {
            attempt: u8,
            stage: ReasonCode,
            code: ReasonCode,
            dispatch_certainty: Option<DispatchCertainty>,
            sense_summary: Option<SenseSummary>,
        }

        let raw = RawAttemptEvidence::deserialize(deserializer)?;
        Self::new(
            raw.attempt,
            FailureEvidence::new(
                raw.stage,
                raw.code,
                raw.dispatch_certainty,
                raw.sense_summary,
            )
            .map_err(de::Error::custom)?,
        )
        .map_err(de::Error::custom)
    }
}

/// Bounded cleanup evidence retained without replacing the primary cause.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CleanupEvidence(Box<[FailureEvidence]>);

impl CleanupEvidence {
    /// Creates a cleanup transcript within the shared renderer bound.
    ///
    /// # Errors
    ///
    /// Returns an error above [`MAX_CLEANUP_EVIDENCE`].
    pub fn new(evidence: Vec<FailureEvidence>) -> Result<Self, &'static str> {
        if evidence.len() > MAX_CLEANUP_EVIDENCE {
            return Err("cleanup evidence exceeds shared bound");
        }
        Ok(Self(evidence.into_boxed_slice()))
    }

    /// Returns cleanup records in observation order.
    #[must_use]
    pub fn as_slice(&self) -> &[FailureEvidence] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CleanupEvidence {
    /// Deserializes and bounds one cleanup transcript.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::<FailureEvidence>::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Bounded recovered-attempt transcript retained separately from primary failure.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AttemptHistory(Box<[AttemptEvidence]>);

impl AttemptHistory {
    /// Creates a retry transcript within the shared renderer bound.
    ///
    /// # Errors
    ///
    /// Returns an error above the single recovered-attempt bound.
    pub fn new(evidence: Vec<AttemptEvidence>) -> Result<Self, &'static str> {
        if evidence.len() > MAX_ATTEMPT_HISTORY {
            return Err("attempt history exceeds shared bound");
        }
        Ok(Self(evidence.into_boxed_slice()))
    }

    /// Returns recovered attempts in observation order.
    #[must_use]
    pub fn as_slice(&self) -> &[AttemptEvidence] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AttemptHistory {
    /// Deserializes and bounds one monotonic retry transcript.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Vec::<AttemptEvidence>::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Complete safe failure information emitted by native operation events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RdxError {
    /// Stable kebab-case error code for programmatic handling.
    pub code: ReasonCode,
    /// Translation key selected by trusted application code.
    pub message_key: MessageKey,
    /// Stable kebab-case operation stage where the failure occurred.
    pub stage: ReasonCode,
    /// Coarse safe failure category.
    pub category: ErrorCategory,
    /// Whether the documented operation policy allows a retry.
    pub retryable: bool,
    /// Exact command-dispatch certainty when the primary cause came from a command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch_certainty: Option<DispatchCertainty>,
    /// Optional sanitized sense interpretation; raw sense bytes are never serialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sense_summary: Option<SenseSummary>,
    /// Opaque support correlation identifier with no host path or secret material.
    pub support_correlation_id: SupportCorrelationId,
    /// Bounded cleanup failures that did not replace the primary cause.
    pub cleanup_evidence: CleanupEvidence,
    /// Bounded recovered retry failures that were never promoted to primary.
    pub attempt_history: AttemptHistory,
}

impl<'de> Deserialize<'de> for RdxError {
    /// Deserializes the exact renderer-safe error and rejects success as failure evidence.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct RawRdxError {
            code: ReasonCode,
            message_key: MessageKey,
            stage: ReasonCode,
            category: ErrorCategory,
            retryable: bool,
            dispatch_certainty: Option<DispatchCertainty>,
            sense_summary: Option<SenseSummary>,
            support_correlation_id: SupportCorrelationId,
            cleanup_evidence: CleanupEvidence,
            attempt_history: AttemptHistory,
        }

        let raw = RawRdxError::deserialize(deserializer)?;
        if raw.dispatch_certainty == Some(DispatchCertainty::Succeeded) {
            return Err(de::Error::custom(
                "failure dispatch certainty cannot be succeeded",
            ));
        }
        Ok(Self {
            code: raw.code,
            message_key: raw.message_key,
            stage: raw.stage,
            category: raw.category,
            retryable: raw.retryable,
            dispatch_certainty: raw.dispatch_certainty,
            sense_summary: raw.sense_summary,
            support_correlation_id: raw.support_correlation_id,
            cleanup_evidence: raw.cleanup_evidence,
            attempt_history: raw.attempt_history,
        })
    }
}

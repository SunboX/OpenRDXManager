// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed path-free discovery stages; never native text, identity or reply data.

/// A rejection stage from the existing candidate validation sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryFailure {
    /// OS metadata is malformed before transport work.
    Metadata,
    /// The exact private candidate recipe cannot be reopened.
    RegistryRecipe,
    /// Registry identity hints do not identify an RDX dock.
    Prefilter,
    /// The exact nonexclusive registry authority could not open.
    RegistryOpen,
    /// Exact media mapping could not be established.
    MediaMap,
    /// The existing unmount boundary returned a failure.
    Unmount,
    /// The existing isolated SCSI worker could not acquire authority.
    WorkerAcquisition,
    /// Mandatory standard INQUIRY has no proven successful reply.
    StandardInquiry,
    /// Mandatory identification VPD page 0x83 has no proven reply.
    Vpd83Inquiry,
    /// Mandatory feature MODE page 0x31 has no proven reply.
    Mode31Probe,
    /// Required INQUIRY identity parsing rejected the bytes.
    InquiryIdentity,
    /// Required MODE feature page parsing/code validation failed.
    Mode31Page,
    /// Probed identity does not corroborate enumerated hints.
    MetadataMismatch,
    /// The proven product family is unsupported.
    Product,
    /// The proven interface contradicts its enumerated hint.
    Interface,
    /// The existing Windows arrival preference could not apply.
    ArrivalPreference,
    /// Required host-volume facts could not be obtained.
    HostFacts,
    /// Media presence and exact fingerprint evidence disagree.
    HostMediaEvidence,
    /// An immutable discovery command could not be constructed.
    CommandConfiguration,
}

impl DiscoveryFailure {
    /// Returns only a compiled fixed stage token, without caller/native strings.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Metadata => "candidate-metadata-invalid",
            Self::RegistryRecipe => "candidate-registry-recipe-unavailable",
            Self::Prefilter => "candidate-metadata-prefilter-rejected",
            Self::RegistryOpen => "candidate-registry-open-failed",
            Self::MediaMap => "candidate-media-map-failed",
            Self::Unmount => "candidate-unmount-failed",
            Self::WorkerAcquisition => "candidate-worker-acquisition-failed",
            Self::StandardInquiry => "candidate-standard-inquiry-failed",
            Self::Vpd83Inquiry => "candidate-vpd83-inquiry-failed",
            Self::Mode31Probe => "candidate-mode31-probe-failed",
            Self::InquiryIdentity => "candidate-inquiry-identity-invalid",
            Self::Mode31Page => "candidate-mode31-invalid",
            Self::MetadataMismatch => "candidate-inquiry-metadata-mismatch",
            Self::Product => "candidate-product-unsupported",
            Self::Interface => "candidate-interface-mismatch",
            Self::ArrivalPreference => "candidate-drive-letter-preference-failed",
            Self::HostFacts => "candidate-host-facts-failed",
            Self::HostMediaEvidence => "candidate-host-media-evidence-invalid",
            Self::CommandConfiguration => "candidate-command-configuration-invalid",
        }
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared hardware-free registry fixtures, included in the integration test scope.

type RecordedCall = (String, DiscoveryProbe, Vec<u8>);
type CallLog = Arc<Mutex<Vec<RecordedCall>>>;
/// Builds a complete standard INQUIRY response with RDX identity fields.
fn standard_inquiry(serial_family: u8, feature_mask_0: u8, feature_mask_1: u8) -> Vec<u8> {
    let mut bytes = vec![b' '; 43];
    bytes[0] = 0;
    bytes[4] = 38;
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..36].copy_from_slice(b"0283");
    bytes[36] = serial_family;
    bytes[37..40].copy_from_slice(b"RDX");
    bytes[40] = 2;
    bytes[41] = feature_mask_0;
    bytes[42] = feature_mask_1;
    bytes
}

/// Builds the fixed-layout device-identification page used for dock serials.
fn device_identification(serial: &str) -> Vec<u8> {
    assert_eq!(serial.len(), 10);
    let mut bytes = vec![b' '; 42];
    bytes[0] = 0;
    bytes[1] = 0x83;
    bytes[2..4].copy_from_slice(&38_u16.to_be_bytes());
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..42].copy_from_slice(serial.as_bytes());
    bytes
}

/// Builds the smallest complete MODE SENSE page `0x31` response.
fn capability_page() -> Vec<u8> {
    vec![0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0x31, 0x03, 0, 0, 0x18]
}

/// Builds a complete MODE page `0x34` reporting fixed-disk mode.
fn operation_mode_page() -> Vec<u8> {
    vec![0x00, 0x0D, 0, 0, 0, 0, 0, 0, 0x34, 0x05, 0, 0, 0x02, 0, 0]
}

/// Builds a complete drive LOG page reporting adapter power.
fn drive_status_page() -> Vec<u8> {
    vec![0x20, 0, 0, 8, 0, 5, 0, 4, 0, 0, 0, 0]
}

/// Builds the complete drive page fields used by the original Manager.
fn complete_drive_status_page() -> Vec<u8> {
    vec![
        0x20, 0, 0, 44, // page header
        0, 0, 0, 2, 0, 0, // status: Good
        0, 1, 0, 4, 0, 0, 0, 42, // load count
        0, 2, 0, 4, 0, 0, 0, 0, // drive errors: none
        0, 3, 0, 2, 0, 1, // cam home
        0, 4, 0, 4, 0, 0, 0, 3, // connection type
        0, 5, 0, 4, 0, 0, 0, 0, // adapter powered
    ]
}

/// Builds the original Manager's variable-width cartridge VPD page `0xC0`.
fn media_identification_page() -> Vec<u8> {
    let fields = [
        "320000",
        "1",
        "HDD MODEL",
        "HDD-SERIAL-000000001",
        "Imation",
        "RDX 320GB",
        "CART-SERIAL-0001",
        "TEST-CARTRIDGE",
    ];
    let mut bytes = vec![0, 0xC0, 0, 0, 0];
    for field in fields {
        bytes.extend_from_slice(field.as_bytes());
        bytes.push(0);
    }
    let payload_length = u16::try_from(bytes.len() - 4).expect("bounded C0 fixture");
    bytes[2..4].copy_from_slice(&payload_length.to_be_bytes());
    bytes
}

/// Builds the ATA identify-device VPD page `0xC2`.
fn media_device_page() -> Vec<u8> {
    let mut bytes = vec![b' '; 0x62];
    bytes[0] = 0;
    bytes[1] = 0xC2;
    bytes[2..4].copy_from_slice(&0x5E_u16.to_be_bytes());
    bytes[0x18..0x2C].copy_from_slice(b"HDD-SERIAL-000000001");
    bytes[0x32..0x3A].copy_from_slice(b"FW1234  ");
    bytes[0x3A..0x62].copy_from_slice(b"HDD MODEL                               ");
    bytes
}

/// Builds all fixed cartridge telemetry parameters from page `0x21`.
fn cartridge_status_page() -> Vec<u8> {
    let mut bytes = vec![0x21, 0, 0, 0];
    for (code, value, width) in [
        (0_u16, 0_u32, 2_usize),
        (1, 12, 4),
        (2, 320_000, 4),
        (3, 319_000, 4),
        (4, 1_000, 4),
        (5, 1_234, 4),
        (6, 5_678, 4),
        (7, 0, 4),
        (8, 0, 4),
        (9, 0, 4),
        (10, 3, 4),
    ] {
        bytes.extend_from_slice(&code.to_be_bytes());
        bytes.push(0);
        bytes.push(width as u8);
        bytes.extend_from_slice(&value.to_be_bytes()[4 - width..]);
    }
    let body_length = u16::try_from(bytes.len() - 4).expect("bounded page 0x21 fixture");
    bytes[2..4].copy_from_slice(&body_length.to_be_bytes());
    bytes
}

/// Builds standard temperature LOG page `0x0D` with current Celsius at byte nine.
fn temperature_page() -> Vec<u8> {
    vec![0x0D, 0, 0, 6, 0, 0, 0, 2, 0, 39]
}

/// Converts successful response bytes into one explicit transport outcome.
fn response(bytes: Vec<u8>) -> CommandDispatch {
    CommandDispatch::Succeeded(TransportResponse::new(bytes).expect("bounded fixture response"))
}

/// Complete response set keyed by the service-owned probe identity.
fn complete_responses(serial: &str) -> BTreeMap<DiscoveryProbe, CommandDispatch> {
    complete_responses_with_masks(serial, 0x08, 0x10)
}

/// Complete response set with caller-selected inquiry feature masks.
fn complete_responses_with_masks(
    serial: &str,
    feature_mask_0: u8,
    feature_mask_1: u8,
) -> BTreeMap<DiscoveryProbe, CommandDispatch> {
    BTreeMap::from([
        (
            DiscoveryProbe::StandardInquiry,
            response(standard_inquiry(0x35, feature_mask_0, feature_mask_1)),
        ),
        (
            DiscoveryProbe::DeviceIdentification,
            response(device_identification(serial)),
        ),
        (DiscoveryProbe::CapabilityPage, response(capability_page())),
        (
            DiscoveryProbe::OperationMode,
            response(operation_mode_page()),
        ),
        (DiscoveryProbe::DriveStatus, response(drive_status_page())),
    ])
}

/// Deterministic backend which records only safe candidate tokens and exact probes.
struct FixtureBackend {
    capabilities: PlatformCapabilities,
    candidates: Vec<CandidateDevice>,
    responses: BTreeMap<String, BTreeMap<DiscoveryProbe, CommandDispatch>>,
    calls: CallLog,
    enumeration_calls: usize,
    refresh_commits: usize,
    refresh_aborts: usize,
    fail_next_matching_allocation: bool,
    facts: HostVolumeFacts,
    host_facts_failure: Option<PrimitiveFailure>,
    available_drive_letters: Result<Vec<DriveLetter>, PrimitiveFailure>,
    open_failures: BTreeMap<String, PlatformError>,
    open_calls: usize,
    open_failure_stage: Option<rdx_service::platform::DiscoveryFailure>,
    refreshed_facts: Option<HostVolumeFacts>,
}

impl FixtureBackend {
    /// Creates one fully capable but explicitly hardware-unverified backend.
    fn new(candidates: Vec<CandidateDevice>) -> Self {
        Self {
            capabilities: PlatformCapabilities::try_new(
                true, true, true, true, true, true, true, false,
            )
            .expect("consistent fixture capabilities"),
            candidates,
            responses: BTreeMap::new(),
            calls: Arc::new(Mutex::new(Vec::new())),
            enumeration_calls: 0,
            refresh_commits: 0,
            refresh_aborts: 0,
            fail_next_matching_allocation: false,
            facts: HostVolumeFacts {
                media_present: false,
                writable: false,
                mounted: false,
                free_bytes: 0,
                capacity_bytes: 0,
                filesystem: None,
                topology: VolumeTopology::Simple,
                media_fingerprint: None,
            },
            host_facts_failure: None,
            available_drive_letters: Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::UnsupportedPlatform,
            )),
            open_failures: BTreeMap::new(),
            open_calls: 0,
            open_failure_stage: None,
            refreshed_facts: None,
        }
    }

    /// Adds the exact discovery responses for one safe backend token.
    fn with_responses(
        mut self,
        token: &str,
        responses: BTreeMap<DiscoveryProbe, CommandDispatch>,
    ) -> Self {
        self.responses.insert(token.to_owned(), responses);
        self
    }

    /// Returns a stable copy of safe recorded commands after all leases close.
    fn calls(&self) -> Vec<RecordedCall> {
        self.calls
            .lock()
            .expect("fixture call log remains available")
            .clone()
    }

    /// Injects one transient matcher-allocation failure without consuming candidates.
    fn fail_matching_allocation_once(&mut self) {
        self.fail_next_matching_allocation = true;
    }

    /// Configures one authoritative current cartridge for discovery and resolution.
    fn with_media(mut self, fingerprint: [u8; 32], capacity_bytes: u64) -> Self {
        self.facts = HostVolumeFacts {
            media_present: true,
            writable: true,
            mounted: true,
            free_bytes: capacity_bytes / 2,
            capacity_bytes,
            filesystem: Some(FileSystem::Ntfs),
            topology: VolumeTopology::Simple,
            media_fingerprint: Some(fingerprint),
        };
        self
    }

    /// Rejects one exact candidate before lease creation with a typed platform failure.
    fn with_open_failure(mut self, token: &str, error: PlatformError) -> Self {
        self.open_failures.insert(token.to_owned(), error);
        self
    }

    /// Supplies a compiled diagnostic stage for a controlled failing open.
    fn with_open_stage(mut self, stage: rdx_service::platform::DiscoveryFailure) -> Self {
        self.open_failure_stage = Some(stage);
        self
    }

    /// Configures a non-disruptive host-volume refresh for an already validated dock.
    fn with_refreshed_media(mut self, fingerprint: [u8; 32], capacity_bytes: u64) -> Self {
        self.refreshed_facts = Some(HostVolumeFacts {
            media_present: true,
            writable: true,
            mounted: true,
            free_bytes: capacity_bytes / 2,
            capacity_bytes,
            filesystem: Some(FileSystem::Ntfs),
            topology: VolumeTopology::Simple,
            media_fingerprint: Some(fingerprint),
        });
        self
    }
}

impl PlatformBackend for FixtureBackend {
    fn capabilities(&self) -> PlatformCapabilities {
        self.capabilities
    }

    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        self.enumeration_calls += 1;
        if !self.capabilities.discovery_available() {
            return Err(PlatformError::DiscoveryUnavailable);
        }
        if std::mem::take(&mut self.fail_next_matching_allocation) {
            return Err(PlatformError::EnumerationFailed);
        }
        Ok(std::mem::take(&mut self.candidates))
    }

    /// Reads the fixture's closed stage without any simulated native work.
    fn last_candidate_open_failure(&self) -> Option<rdx_service::platform::DiscoveryFailure> {
        self.open_failure_stage
    }

    fn open_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        self.open_calls += 1;
        if let Some(error) = self.open_failures.get(candidate.token()).copied() {
            return Err(error);
        }
        let responses = self
            .responses
            .get(candidate.token())
            .cloned()
            .unwrap_or_default();
        Ok(CandidateLease::new(FixtureHandle {
            token: candidate.token().to_owned(),
            responses,
            calls: Arc::clone(&self.calls),
            facts: self.facts,
            host_facts_failure: self.host_facts_failure,
            available_drive_letters: self.available_drive_letters.clone(),
        }))
    }

    fn refresh_candidate_host_facts(
        &mut self,
        candidate: &CandidateDevice,
        previous: &CandidateDevice,
        _previous_facts: Option<HostVolumeFacts>,
    ) -> Result<Option<HostVolumeFacts>, PlatformError> {
        if candidate.token() == previous.token()
            || (candidate.token().starts_with("refresh-")
                && matches!(previous.token(), "initial" | "refresh-current"))
        {
            Ok(self.refreshed_facts)
        } else {
            Ok(None)
        }
    }

    fn commit_candidate_refresh(&mut self) {
        self.refresh_commits += 1;
    }

    fn abort_candidate_refresh(&mut self) {
        self.refresh_aborts += 1;
    }
}

/// One exact fixture lease which dispatches only through its retained response set.
struct FixtureHandle {
    token: String,
    responses: BTreeMap<DiscoveryProbe, CommandDispatch>,
    calls: CallLog,
    facts: HostVolumeFacts,
    host_facts_failure: Option<PrimitiveFailure>,
    available_drive_letters: Result<Vec<DriveLetter>, PrimitiveFailure>,
}

impl PlatformDeviceHandle for FixtureHandle {
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        let Some(probe) = probe_for_command(command) else {
            return CommandDispatch::NotSent(TransportError::Unavailable);
        };
        self.calls
            .lock()
            .expect("fixture call log remains available")
            .push((self.token.clone(), probe, command.cdb().to_vec()));
        self.responses
            .get(&probe)
            .cloned()
            .unwrap_or(CommandDispatch::NotSent(TransportError::Unavailable))
    }

    /// Reports the fixture's configured authoritative cartridge facts.
    fn host_volume_facts(&mut self) -> Result<HostVolumeFacts, PrimitiveFailure> {
        match &self.host_facts_failure {
            Some(error) => Err(*error),
            None => Ok(self.facts),
        }
    }

    /// Reports only the fixture's bounded authoritative Windows letter set.
    fn available_drive_letters(&mut self) -> Result<Vec<DriveLetter>, PrimitiveFailure> {
        self.available_drive_letters.clone()
    }
}

/// Recognizes only the literal service-owned discovery and status commands.
fn probe_for_command(command: &Command) -> Option<DiscoveryProbe> {
    match command.cdb() {
        [0x12, 0, 0, 0, 0xFE, 0] => Some(DiscoveryProbe::StandardInquiry),
        [0x12, 1, 0x83, 0, 0xFE, 0] => Some(DiscoveryProbe::DeviceIdentification),
        [0x12, 1, 0xC0, 0, 0xFE, 0] => Some(DiscoveryProbe::MediaIdentification),
        [0x12, 1, 0xC2, 0x02, 0, 0] => Some(DiscoveryProbe::MediaDevice),
        [0x5A, 0, 0x31, 0, 0, 0, 0, 0, 0xFE, 0] => Some(DiscoveryProbe::CapabilityPage),
        [0x5A, 0, 0x34, 0, 0, 0, 0, 0, 0xFE, 0] => Some(DiscoveryProbe::OperationMode),
        [0x4D, 0, 0x20, 0, 0, 0, 0, 0, 0xFE, 0] => Some(DiscoveryProbe::DriveStatus),
        [0x4D, 0, 0x21, 0, 0, 0, 0, 0, 0xFE, 0] => Some(DiscoveryProbe::CartridgeStatus),
        [0x4D, 0, 0x0D, 0, 0, 0, 0, 0, 0xFE, 0] => Some(DiscoveryProbe::Temperature),
        _ => None,
    }
}

/// Builds one untrusted OS candidate whose metadata must never substitute probe evidence.
fn candidate(token: &str, locator: &str, serial: &str) -> CandidateDevice {
    candidate_with_metadata(
        token,
        locator,
        CandidateMetadata::new(
            Some("TANDBERG".to_owned()),
            Some("RDX".to_owned()),
            Some(serial.to_owned()),
            Some(DeviceInterface::Usb3),
        ),
    )
}

/// Creates a candidate with intentionally caller-controlled untrusted hints.
fn candidate_with_metadata(
    token: &str,
    locator: &str,
    metadata: CandidateMetadata,
) -> CandidateDevice {
    CandidateDevice::new(token, locator, metadata).expect("bounded fixture candidate")
}

/// Creates a backend whose every listed candidate has complete matching evidence.
fn complete_backend(candidates: &[(&str, &str, &str)]) -> FixtureBackend {
    let devices = candidates
        .iter()
        .map(|(token, locator, serial)| candidate(token, locator, serial))
        .collect();
    candidates.iter().fold(
        FixtureBackend::new(devices),
        |backend, (token, _, serial)| backend.with_responses(token, complete_responses(serial)),
    )
}

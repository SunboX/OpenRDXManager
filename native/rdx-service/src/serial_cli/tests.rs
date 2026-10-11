// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic serial safety contracts; no test enumerates or opens live hardware.

use super::flow::SerialTransport;
use super::plan::Plan;
use super::record::{RecordState, Sector};
use super::*;

/// Synthetic valid sector with nonzero neighbors catches accidental sector clearing.
fn fixture() -> Sector {
    let mut erased = [0xff; 4096];
    erased[256..].fill(0xa5);
    record::expected_sector(&erased, "000123456789", true).unwrap()
}

/// Creates an explicit synthetic target and normal plan.
fn plan_fixture() -> (Plan, Sector, Target) {
    let sector = fixture();
    let target = Target {
        serial: "000123456789".into(),
        location: 0x100000,
    };
    let plan = Plan::new(
        &sector,
        target.serial.clone(),
        target.location,
        "009876543210".into(),
        false,
    )
    .unwrap();
    (plan, sector, target)
}

/// Constructs the complete standard inquiry header used by the strict identity guard.
fn inquiry() -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[4] = 59;
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..36].copy_from_slice(b"0109");
    bytes[37..40].copy_from_slice(b"RDX");
    bytes
}

/// Records flow order and emulates exactly one receiver-side serial transition.
struct Fake {
    sector: Sector,
    supported: bool,
    writes: usize,
    chunks: Vec<u8>,
    bay: u8,
    neighbor_corruption: bool,
    cam: bool,
    mechanism_state: u8,
}

impl Fake {
    /// Starts from exact caller evidence with no mutation or physical media.
    fn new(sector: Sector) -> Self {
        Self {
            sector,
            supported: true,
            writes: 0,
            chunks: vec![],
            bay: 0,
            neighbor_corruption: false,
            cam: false,
            mechanism_state: 0,
        }
    }
}

impl SerialTransport for Fake {
    /// Returns synthetic identity, never real hardware.
    fn inquiry(&mut self) -> Result<Vec<u8>> {
        Ok(inquiry())
    }
    /// Exposes the physical-bay parameter in its exact two-byte field.
    fn drive_log(&mut self) -> Result<Vec<u8>> {
        Ok(vec![0x20, 0, 0, 6, 0, 3, 0, 2, 0, self.bay])
    }
    /// Returns physical GPIO5 independently of the GPIO2 CAM input.
    fn mechanism_diagnostics(&mut self) -> Result<Vec<u8>> {
        let mut bytes = vec![0; 128];
        bytes[..4].copy_from_slice(b"RDXM");
        bytes[4] = 1;
        bytes[5] = self.mechanism_state;
        bytes[10] = if self.bay == 0 { 0x20 } else { 0 } | if self.cam { 4 } else { 0 };
        Ok(bytes)
    }
    /// Records every fixed read to prove full-sector coverage before and after write.
    fn sector_chunk(&mut self, index: u8) -> Result<Vec<u8>> {
        self.chunks.push(index);
        Ok(self.sector[usize::from(index) * 128..(usize::from(index) + 1) * 128].to_vec())
    }
    /// Emulates old firmware rejecting the no-data probe.
    fn capability(&mut self) -> Result<()> {
        if self.supported {
            Ok(())
        } else {
            Err("unsupported")
        }
    }
    /// Emulates firmware checksum/sector comparison before patching the serial.
    fn set_serial(&mut self, payload: Vec<u8>) -> Result<()> {
        assert_eq!(&payload[..8], b"RDXSER01");
        assert_eq!(
            u32::from_le_bytes(payload[8..12].try_into().unwrap()),
            record::crc32(&self.sector)
        );
        assert_eq!(&payload[24..], &self.sector[..256]);
        let new = format!("00{}", std::str::from_utf8(&payload[14..24]).unwrap());
        self.sector = record::expected_sector(&self.sector, &new, payload[12] == 1).unwrap();
        if self.neighbor_corruption {
            self.sector[4095] ^= 1;
        }
        self.writes += 1;
        Ok(())
    }
}

/// Serial text retains all leading zeros and rejects wildcards and partial digits.
#[test]
fn decimal_validation_and_closed_cli_grammar() {
    assert!(record::validate_usb_serial("000000000001").is_ok());
    for serial in [
        "123456789012",
        "00123456789",
        "00123456789x",
        "00１２３４５６７８９０",
        "*",
    ] {
        assert!(record::validate_usb_serial(serial).is_err());
    }
    let args = [
        "inspect",
        "--usb-serial",
        "000000000001",
        "--location-id",
        "0x100000",
    ];
    assert!(matches!(
        parse(args.iter().map(OsString::from)).unwrap(),
        Action::Inspect { .. }
    ));
    for arguments in [
        vec!["apply", "--new-usb-serial", "000000000001"],
        vec!["inspect", "--usb-serial", "000000000001"],
        vec![
            "inspect",
            "--usb-serial",
            "000000000001",
            "--location-id",
            "0",
        ],
    ] {
        assert!(parse(arguments.into_iter().map(OsString::from)).is_err());
    }
}

/// The standard CRC vector and record transitions preserve every unrelated sector byte.
#[test]
fn checksums_record_states_and_exact_reconstruction() {
    assert_eq!(record::crc32(b"123456789"), 0xcbf43926);
    assert_eq!(record::state(&[0xff; 4096]), RecordState::Erased);
    let sector = fixture();
    assert_eq!(record::state(&sector), RecordState::Valid);
    assert_eq!(
        record::expected_record(&[0xff; 256], "000123456789", true).unwrap(),
        sector[..256]
    );
    assert_eq!(
        record::record_usb_serial(&sector).as_deref(),
        Some("000123456789")
    );
    assert_eq!(&sector[0x76..0x7a], &[0x5a, 0x1a, 6, 0]);
    assert_eq!(
        &sector[0x9c..0xa6],
        &[b'1', b'0', b'1', b'0', b'2', b'0', b'1', b'0', 0x38, 0]
    );
    let changed = record::expected_sector(&sector, "000000000001", false).unwrap();
    for index in 0..4096 {
        if !(0..4).contains(&index) && !(8..18).contains(&index) {
            assert_eq!(sector[index], changed[index]);
        }
    }
    let mut corrupt = sector;
    corrupt[90] ^= 1;
    assert_eq!(record::state(&corrupt), RecordState::Corrupt);
    for reconstruct in [false, true] {
        assert!(record::expected_sector(&corrupt, "000000000001", reconstruct).is_err());
    }
    assert!(record::expected_sector(&[0xff; 4096], "000000000001", false).is_err());
    assert!(record::expected_sector(&sector, "000000000001", true).is_err());
    assert!(record::sector_from_bytes(&[0xff; 256]).is_err());
}

/// Altering a checksum, CRC, target, or any neighbor byte makes a prepared plan unusable.
#[test]
fn plan_roundtrip_wrong_serial_stale_plan_and_bad_crc() {
    let (mut plan, sector, target) = plan_fixture();
    let encoded = serde_json::to_vec(&plan).unwrap();
    let decoded: Plan = serde_json::from_slice(&encoded).unwrap();
    decoded.validate(&sector).unwrap();
    decoded
        .validate_live(&sector, &sector, &target.serial, target.location)
        .unwrap();
    assert!(
        decoded
            .validate_live(&sector, &sector, "000000000001", target.location)
            .is_err()
    );
    assert!(
        decoded
            .validate_live(&sector, &sector, &target.serial, target.location + 1)
            .is_err()
    );
    let mut stale = sector;
    stale[4000] ^= 1;
    assert_eq!(
        decoded.validate_live(&sector, &stale, &target.serial, target.location),
        Err("serial-plan-stale")
    );
    assert!(decoded.validate(&stale).is_err());
    plan.sector_crc32 ^= 1;
    assert!(plan.validate(&sector).is_err());
}

/// Old firmware, stale evidence, a nonempty bay, or failed persistence issues no serial write.
#[test]
fn old_firmware_and_failed_preconditions_never_mutate() {
    let (plan, sector, target) = plan_fixture();
    let mut fake = Fake::new(sector);
    fake.supported = false;
    let mut attempts = 0;
    assert_eq!(
        flow::apply_record(&mut fake, &plan, &sector, &target, || {
            attempts += 1;
            Ok(())
        }),
        Err("serial-capability-unavailable-no-write")
    );
    assert_eq!((fake.writes, attempts), (0, 0));
    fake.supported = true;
    fake.bay = 1;
    assert!(flow::apply_record(&mut fake, &plan, &sector, &target, || Ok(())).is_err());
    assert_eq!(fake.writes, 0);
    fake.bay = 0;
    fake.sector[3000] ^= 1;
    assert_eq!(
        flow::apply_record(&mut fake, &plan, &sector, &target, || Ok(())),
        Err("serial-plan-stale")
    );
    assert_eq!(fake.writes, 0);
    fake.sector = sector;
    assert!(flow::apply_record(&mut fake, &plan, &sector, &target, || Err("sync-failed")).is_err());
    assert_eq!(fake.writes, 0);
}

/// Both complete 32-chunk reads are required, and one changed neighbor defeats verification.
#[test]
fn full_sector_write_readback_is_exact() {
    let (plan, sector, target) = plan_fixture();
    let mut fake = Fake::new(sector);
    let result = flow::apply_record(&mut fake, &plan, &sector, &target, || Ok(())).unwrap();
    assert_eq!(record::sha256(&result), plan.expected_sector_sha256);
    assert_eq!(fake.writes, 1);
    assert_eq!(fake.chunks, (0..32).chain(0..32).collect::<Vec<u8>>());
    let mut fake = Fake::new(sector);
    fake.neighbor_corruption = true;
    assert_eq!(
        flow::apply_record(&mut fake, &plan, &sector, &target, || Ok(())),
        Err("serial-write-readback-mismatch-no-reset")
    );
}

/// Durable evidence refuses replacement, tampering, hard links, symlinks, and repeated attempts.
#[cfg(unix)]
#[test]
fn private_evidence_roundtrip_and_no_overwrite() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temporary = tempfile::tempdir().unwrap();
    // macOS /var may be a symlink; production correctly requires its canonical absolute spelling.
    let root = temporary.path().canonicalize().unwrap();
    let path = root.join("plan");
    let (plan, sector, _) = plan_fixture();
    let evidence = storage::Evidence::create(&path, &plan, &sector).unwrap();
    assert_eq!(evidence.load().unwrap().1, sector);
    assert!(storage::Evidence::create(&path, &plan, &sector).is_err());
    evidence.write_new("apply-attempt.json", b"{}").unwrap();
    assert!(evidence.write_new("apply-attempt.json", b"{}").is_err());
    symlink(&path, root.join("linked")).unwrap();
    assert!(storage::Evidence::open(&root.join("linked")).is_err());
    std::fs::hard_link(path.join("sector.bin"), root.join("extra-link")).unwrap();
    assert!(evidence.load().is_err());
    std::fs::remove_file(root.join("extra-link")).unwrap();
    std::fs::set_permissions(
        path.join("sector.bin"),
        std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    assert!(evidence.load().is_err());
    std::fs::set_permissions(
        path.join("sector.bin"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(evidence.load().is_ok());
    std::fs::write(path.join("sector.bin"), [0; 4096]).unwrap();
    assert!(evidence.load().is_err());
    std::fs::remove_file(path.join("sector.bin")).unwrap();
    symlink(root.join("missing"), path.join("sector.bin")).unwrap();
    assert!(evidence.load().is_err());
}

/// Offline preparation accepts only a complete sector and declares the missing device evidence.
#[cfg(unix)]
#[test]
fn offline_prepare_labels_reconstruction_and_device_limit() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let input = root.join("sector.bin");
    std::fs::write(&input, [0xff; 4096]).unwrap();
    let output = root.join("prepared");
    let args = vec![
        OsString::from("prepare"),
        "--usb-serial".into(),
        "000123456789".into(),
        "--location-id".into(),
        "0x100000".into(),
        "--new-usb-serial".into(),
        "000000000001".into(),
        "--output-dir".into(),
        output.into_os_string(),
        "--sector-file".into(),
        input.into_os_string(),
        "--reconstruct-erased".into(),
    ];
    let value = run(args.into_iter()).unwrap();
    assert_eq!(value["originalFactoryDataLost"], true);
    assert_eq!(value["source"], "offline-unverified-device");
    assert_eq!(value["hardwareMutationPerformed"], false);
}

/// Physical cartridge presence is independent of both CAM states and requires an idle mechanism.
#[test]
fn gpio5_sensor_proves_absence_independently_of_gpio2_cam() {
    for cam in [false, true] {
        let mut fake = Fake::new(fixture());
        fake.cam = cam;
        assert!(flow::snapshot(&mut fake).is_ok());
        fake.bay = 1;
        assert_eq!(
            flow::snapshot(&mut fake),
            Err("serial-physical-bay-not-empty")
        );
        fake.bay = 0;
        fake.mechanism_state = 1;
        assert_eq!(flow::snapshot(&mut fake), Err("serial-mechanism-not-idle"));
    }
}

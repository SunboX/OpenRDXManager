// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use tempfile::TempDir;

use super::*;
use crate::sg::media_identity_request;

/// The production child boundary either masks `/dev` while retaining only fd
/// 9, or fails before exec when the host forbids private mount namespaces.
#[test]
#[cfg(target_os = "linux")]
fn formatter_child_namespace_is_runtime_fail_closed() {
    assert!(crate::native::retained_fd_namespace_runtime_contract());
}

/// Creates one synthetic sysfs tree with an exact sg device and block ancestry.
fn sysfs_fixture() -> (TempDir, SysfsRoots) {
    let temp = tempfile::tempdir().expect("temporary sysfs");
    let sys = temp.path().join("sys");
    let class_root = sys.join("class/scsi_generic");
    let devices_root = sys.join("devices");
    let device_root = devices_root.join("pci0000:00/host1/target1:0:0/1:0:0:0");
    let sg_root = device_root.join("scsi_generic/sg2");
    let scsi_subsystem = sys.join("bus/scsi");
    let block_subsystem = sys.join("class/block");
    let bdi_subsystem = sys.join("class/bdi");
    let bdi_target = devices_root.join("virtual/bdi/8:0");
    fs::create_dir_all(&sg_root).expect("sg fixture directory");
    fs::create_dir_all(&class_root).expect("sg class fixture directory");
    fs::create_dir_all(&scsi_subsystem).expect("scsi subsystem fixture");
    fs::create_dir_all(&block_subsystem).expect("block subsystem fixture");
    fs::create_dir_all(&bdi_subsystem).expect("bdi subsystem fixture");
    fs::create_dir_all(&bdi_target).expect("bdi fixture");
    let scsi_subsystem = fs::canonicalize(scsi_subsystem).expect("canonical scsi subsystem");
    let block_subsystem = fs::canonicalize(block_subsystem).expect("canonical block subsystem");
    let bdi_subsystem = fs::canonicalize(bdi_subsystem).expect("canonical bdi subsystem");
    let bdi_target = fs::canonicalize(bdi_target).expect("canonical bdi target");
    fs::write(sg_root.join("dev"), "21:2\n").expect("sg device number");
    symlink(&scsi_subsystem, device_root.join("subsystem")).expect("scsi subsystem link");
    fs::write(
        device_root.join("uevent"),
        "DEVTYPE=scsi_device\nDRIVER=sd\n",
    )
    .expect("SCSI device type fixture");
    symlink(
        "../../devices/pci0000:00/host1/target1:0:0/1:0:0:0/scsi_generic/sg2",
        class_root.join("sg2"),
    )
    .expect("class symlink");

    let block_root = device_root.join("block/sda");
    fs::create_dir_all(block_root.join("holders")).expect("disk holders fixture");
    fs::create_dir_all(block_root.join("slaves")).expect("disk slaves fixture");
    fs::create_dir_all(block_root.join("queue")).expect("gendisk metadata fixture");
    fs::create_dir_all(block_root.join("sda1/holders")).expect("partition holders fixture");
    fs::write(block_root.join("dev"), "8:0\n").expect("disk device number");
    fs::write(block_root.join("sda1/dev"), "8:1\n").expect("partition device number");
    fs::write(block_root.join("sda1/partition"), "1\n").expect("partition index");
    symlink(&block_subsystem, block_root.join("subsystem")).expect("disk subsystem link");
    symlink(&bdi_target, block_root.join("bdi")).expect("disk bdi link");
    symlink(&block_subsystem, block_root.join("sda1/subsystem")).expect("partition subsystem link");
    symlink(&bdi_subsystem, bdi_target.join("subsystem")).expect("bdi subsystem link");
    symlink(&bdi_target, bdi_subsystem.join("8:0")).expect("bdi class alias");
    let canonical_block_root = fs::canonicalize(&block_root).expect("canonical block root");
    symlink(&canonical_block_root, block_subsystem.join("sda")).expect("disk class alias");
    symlink(
        canonical_block_root.join("sda1"),
        block_subsystem.join("sda1"),
    )
    .expect("partition class alias");

    let roots = SysfsRoots::new(class_root, devices_root).expect("bounded fixture roots");
    (temp, roots)
}

/// Component-wise resolution accepts one exact in-tree sg class link.
#[test]
fn sysfs_candidate_recipe_pins_devpath_and_device_number() {
    let (_temp, roots) = sysfs_fixture();

    let candidates = enumerate_candidates_at(&roots).expect("bounded sysfs enumeration");

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].token(), "linux-sg-2");
    let recipe = candidates[0].recipe().to_owned();
    let decoded = decode_recipe(&recipe).expect("private exact recipe");
    assert_eq!(decoded.sg_index(), 2);
    assert_eq!(decoded.device_number(), DeviceNumber::new(21, 2));
    assert_eq!(
        decoded.relative_devpath(),
        Path::new("pci0000:00/host1/target1:0:0/1:0:0:0/scsi_generic/sg2")
    );
    assert!(!format!("{:?}", candidates[0]).contains("pci0000"));
}

/// Traversal, outside-root links, and mismatched sg names never become candidates.
#[test]
fn hostile_sysfs_links_fail_closed() {
    let (_temp, roots) = sysfs_fixture();
    let outside = roots
        .devices_root()
        .parent()
        .expect("synthetic sys root")
        .join("outside/sg3");
    fs::create_dir_all(&outside).expect("outside fixture");
    fs::write(outside.join("dev"), "21:3\n").expect("outside dev number");
    symlink("../../outside/sg3", roots.class_root().join("sg3")).expect("outside class link");

    let candidates = enumerate_candidates_at(&roots).expect("hostile entries are skipped");

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].token(), "linux-sg-2");
}

/// An absolute class link is accepted only when it remains under this sysfs root.
#[test]
fn absolute_in_root_sysfs_link_resolves_from_the_sysfs_root() {
    let (_temp, roots) = sysfs_fixture();
    fs::remove_file(roots.class_root().join("sg2")).expect("remove relative class link");
    symlink(
        roots
            .devices_root()
            .join("pci0000:00/host1/target1:0:0/1:0:0:0/scsi_generic/sg2"),
        roots.class_root().join("sg2"),
    )
    .expect("absolute in-root class link");

    let candidates = enumerate_candidates_at(&roots).expect("bounded sysfs enumeration");

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].token(), "linux-sg-2");
}

/// Oversized and malformed device-number evidence is rejected before a recipe exists.
#[test]
fn malformed_or_long_sysfs_evidence_is_rejected() {
    let (_temp, roots) = sysfs_fixture();
    let sg2 = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/scsi_generic/sg2/dev");

    for hostile in ["-1:2\n", "21:-2\n", "21:2 trailing\n", "4294967296:2\n"] {
        fs::write(&sg2, hostile).expect("replace hostile dev evidence");
        assert!(
            enumerate_candidates_at(&roots)
                .expect("bounded enumeration")
                .is_empty()
        );
    }
    fs::write(&sg2, "1".repeat(MAX_SYSFS_ATTRIBUTE_BYTES + 1)).expect("replace long dev evidence");
    assert!(
        enumerate_candidates_at(&roots)
            .expect("bounded enumeration")
            .is_empty()
    );
}

/// Exact before/open/after proofs reject path reuse, non-sg nodes, and hotplug races.
#[test]
fn opened_device_proof_must_match_both_sysfs_snapshots() {
    let expected = DeviceBinding::new(
        2,
        "pci0000:00/host1/target1:0:0/1:0:0:0/scsi_generic/sg2".into(),
        DeviceNumber::new(21, 2),
    )
    .expect("bounded binding");
    let opened = OpenedDeviceProof::new(true, DeviceNumber::new(21, 2));

    assert!(binding_is_stable(&expected, &expected, opened, &expected));
    assert!(!binding_is_stable(
        &expected,
        &expected,
        OpenedDeviceProof::new(false, DeviceNumber::new(21, 2)),
        &expected,
    ));
    let swapped = DeviceBinding::new(
        2,
        "pci0000:00/host1/target1:0:0/9:0:0:0/scsi_generic/sg2".into(),
        DeviceNumber::new(21, 2),
    )
    .expect("bounded swapped binding");
    assert!(!binding_is_stable(&expected, &expected, opened, &swapped));
    assert!(!binding_is_stable(
        &expected,
        &expected,
        OpenedDeviceProof::new(true, DeviceNumber::new(21, 9)),
        &expected,
    ));
}

/// A retained sysfs directory, rather than a reusable path/device pair, is
/// required when promoting one enumerated candidate into an SG lease.
#[test]
fn retained_sysfs_instance_rejects_same_path_and_device_number_recreation() {
    let binding = DeviceBinding::new(
        2,
        "pci0000:00/host1/target1:0:0/1:0:0:0/scsi_generic/sg2".into(),
        DeviceNumber::new(21, 2),
    )
    .expect("bounded binding");
    let retained_at_enumeration = SysfsInstanceProof::new(true, 41, 9001);
    let opened = OpenedDeviceProof::new(true, DeviceNumber::new(21, 2));

    assert!(candidate_instance_is_stable(
        &binding,
        &binding,
        retained_at_enumeration,
        retained_at_enumeration,
        retained_at_enumeration,
        opened,
        &binding,
    ));
    assert!(!candidate_instance_is_stable(
        &binding,
        &binding,
        retained_at_enumeration,
        retained_at_enumeration,
        SysfsInstanceProof::new(true, 41, 9002),
        opened,
        &binding,
    ));
    assert!(!candidate_instance_is_stable(
        &binding,
        &binding,
        retained_at_enumeration,
        SysfsInstanceProof::new(true, 41, 9002),
        retained_at_enumeration,
        opened,
        &binding,
    ));
}

/// A promoted SG descriptor cannot authorize a volume pin after its retained
/// sysfs instance has been replaced by the same path and device number.
#[test]
fn retained_sg_authority_rejects_same_key_replacement_during_volume_pin() {
    let retained_at_open = SysfsInstanceProof::new(true, 41, 9001);

    assert!(retained_sysfs_instance_is_current(
        retained_at_open,
        retained_at_open,
        retained_at_open,
    ));
    assert!(!retained_sysfs_instance_is_current(
        retained_at_open,
        retained_at_open,
        SysfsInstanceProof::new(true, 41, 9002),
    ));
    assert!(!retained_sysfs_instance_is_current(
        retained_at_open,
        SysfsInstanceProof::new(true, 42, 9001),
        retained_at_open,
    ));
}

/// Linux's split `dev_t` encoding round-trips large major and minor values.
#[test]
fn linux_device_number_decoding_matches_sysmacros_layout() {
    let major = 0x0001_2345_u64;
    let minor = 0x0067_89AB_u64;
    let encoded = (minor & 0xFF)
        | ((major & 0xFFF) << 8)
        | ((minor & 0xFFFF_FF00) << 12)
        | ((major & 0xFFFF_F000) << 32);

    assert_eq!(
        device_number_from_linux_dev_t(encoded),
        DeviceNumber::new(major as u32, minor as u32),
    );
}

/// A destructive Linux lease is bound to actively queried cartridge pages,
/// never to a reusable gendisk sequence, capacity, or dock serial.
#[test]
fn media_identity_requires_two_current_cartridge_vpd_serials() {
    let c0_request = media_identity_request(0xC0).expect("bounded C0 request");
    assert_eq!(c0_request.cdb(), &[0x12, 1, 0xC0, 0, 0xFE, 0]);
    assert_eq!(c0_request.data().len(), 0xFE);
    let c2_request = media_identity_request(0xC2).expect("C2 request");
    assert_eq!(c2_request.cdb(), &[0x12, 1, 0xC2, 0x02, 0x04, 0]);
    assert_eq!(c2_request.data().len(), 0x204);

    let mut c0 = vec![0_u8; 0x56];
    c0[1] = 0xC0;
    c0[2..4].copy_from_slice(&0x52_u16.to_be_bytes());
    c0[0x42..0x56].copy_from_slice(b"CARTRIDGE-SERIAL-001");
    let mut c2 = vec![0_u8; 0x2C];
    c2[1] = 0xC2;
    c2[2..4].copy_from_slice(&0x28_u16.to_be_bytes());
    c2[0x18..0x2C].copy_from_slice(b"MEDIUM-SERIAL-000001");

    let first = media_identity_material_from_vpd(&c0, &c2).expect("current medium identity");
    c2[0x2B] = b'2';
    let swapped = media_identity_material_from_vpd(&c0, &c2).expect("replacement identity");
    assert_ne!(first, swapped, "same-capacity media replacement must drift");

    c2[0x18..0x2C].fill(b' ');
    assert_eq!(
        media_identity_material_from_vpd(&c0, &c2),
        Err(NativeError::EvidenceIncomplete)
    );
    c2[1] = 0x83;
    assert_eq!(
        media_identity_material_from_vpd(&c0, &c2),
        Err(NativeError::EvidenceIncomplete)
    );

    let mut full_c0 = vec![0_u8; 0xFE];
    full_c0[1] = 0xC0;
    full_c0[2..4].copy_from_slice(&0xFA_u16.to_be_bytes());
    full_c0[0x42..0x56].copy_from_slice(b"CARTRIDGE-SERIAL-001");
    let mut full_c2 = vec![0_u8; 0x200];
    full_c2[1] = 0xC2;
    full_c2[2..4].copy_from_slice(&0x01FC_u16.to_be_bytes());
    full_c2[0x18..0x2C].copy_from_slice(b"MEDIUM-SERIAL-000001");
    assert_eq!(
        media_identity_material_from_vpd(&full_c0, &full_c2),
        Ok(first)
    );
    full_c2.truncate(0x1FF);
    assert_eq!(
        media_identity_material_from_vpd(&full_c0, &full_c2),
        Err(NativeError::EvidenceIncomplete)
    );
}

/// A full ATA identify payload needs the VPD header as well as its 512 bytes.
/// The previously requested 512-byte response truncates this valid page and
/// must remain rejected instead of authorizing a partial cartridge identity.
#[test]
fn cartridge_identity_request_fits_full_ata_vpd_page() {
    let mut c0 = vec![0_u8; 130];
    c0[1] = 0xC0;
    c0[2..4].copy_from_slice(&126_u16.to_be_bytes());
    c0[0x42..0x56].copy_from_slice(b"CARTRIDGE-SERIAL-001");

    let mut c2 = vec![0_u8; 4 + 512];
    c2[1] = 0xC2;
    c2[2..4].copy_from_slice(&512_u16.to_be_bytes());
    c2[0x18..0x2C].copy_from_slice(b"MEDIUM-SERIAL-000001");
    let identity = media_identity_material_from_vpd(&c0, &c2).expect("complete identity");
    assert_eq!(
        media_identity_material_from_vpd(&c0, &c2[..512]),
        Err(NativeError::EvidenceIncomplete),
        "a present serial does not make the truncated page complete",
    );

    let request = media_identity_request(0xC2).expect("bounded ATA identity request");
    let allocation = usize::from(u16::from_be_bytes([request.cdb()[3], request.cdb()[4]]));
    assert!(
        allocation >= c2.len(),
        "the transfer must fit header and payload"
    );
    assert_eq!(request.data().len(), allocation);
    assert_eq!(
        media_identity_material_from_vpd(&c0, &c2[..c2.len().min(allocation)]),
        Ok(identity),
    );
}

/// Block mapping follows only the exact SCSI-device ancestry and includes partitions.
#[test]
fn block_ancestry_maps_exact_disk_and_partition_numbers() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");

    let topology = block_topology_for(&roots, &binding).expect("bounded block ancestry");
    let blocks = topology.bindings();

    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].name(), "sda");
    assert_eq!(blocks[0].device_number(), DeviceNumber::new(8, 0));
    assert_eq!(blocks[1].name(), "sda1");
    assert_eq!(blocks[1].device_number(), DeviceNumber::new(8, 1));
}

/// A disk BDI link must name the exact disk major/minor rather than another
/// otherwise valid BDI instance under the real virtual-device directory.
#[test]
fn block_topology_rejects_wrong_bdi_device_number() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let disk = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/block/sda");
    let replacement = roots.devices_root().join("virtual/bdi/8:9");
    fs::create_dir_all(&replacement).expect("replacement BDI");
    symlink(
        roots.sys_root().join("class/bdi"),
        replacement.join("subsystem"),
    )
    .expect("replacement BDI subsystem");
    symlink(&replacement, roots.sys_root().join("class/bdi/8:9"))
        .expect("replacement BDI class alias");
    fs::remove_file(disk.join("bdi")).expect("remove original BDI link");
    symlink(&replacement, disk.join("bdi")).expect("wrong disk BDI link");

    assert_eq!(
        block_topology_for(&roots, &binding),
        Err(NativeError::EnumerationFailed),
    );
}

/// A BDI-shaped virtual device with a different subsystem cannot become the
/// backing-device authority for a physical disk.
#[test]
fn block_topology_rejects_wrong_bdi_subsystem() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let bdi = roots.devices_root().join("virtual/bdi/8:0");
    fs::remove_file(bdi.join("subsystem")).expect("remove BDI subsystem");
    symlink(roots.sys_root().join("class/block"), bdi.join("subsystem"))
        .expect("wrong BDI subsystem");

    assert_eq!(
        block_topology_for(&roots, &binding),
        Err(NativeError::EnumerationFailed),
    );
}

/// The exact `/sys/class/bdi/<major>:<minor>` alias must resolve to the disk's
/// confined real BDI device rather than an arbitrary sysfs directory.
#[test]
fn block_topology_rejects_escaping_bdi_class_alias() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let class_alias = roots.sys_root().join("class/bdi/8:0");
    let outside = roots
        .sys_root()
        .parent()
        .expect("synthetic sys parent")
        .join("outside-bdi");
    fs::create_dir(&outside).expect("outside BDI-shaped directory");
    symlink(
        roots.sys_root().join("class/bdi"),
        outside.join("subsystem"),
    )
    .expect("outside BDI subsystem");
    fs::remove_file(&class_alias).expect("remove exact BDI class alias");
    symlink(&outside, &class_alias).expect("escaping BDI class alias");

    assert_eq!(
        block_topology_for(&roots, &binding),
        Err(NativeError::EnumerationFailed),
    );
}

/// Each block node must retain the exact class alias to its physical sysfs
/// instance; a same-name alias redirected to a partition is not equivalent.
#[test]
fn block_topology_rejects_retargeted_block_class_alias() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let class_alias = roots.sys_root().join("class/block/sda");
    let partition = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/block/sda/sda1");
    fs::remove_file(&class_alias).expect("remove disk class alias");
    symlink(&partition, &class_alias).expect("retarget disk class alias");

    assert_eq!(
        block_topology_for(&roots, &binding),
        Err(NativeError::EnumerationFailed),
    );
}

/// A same-name, same-major/minor block directory replacement during pinning
/// cannot satisfy the retained block authority proof.
#[test]
fn retained_block_authority_rejects_same_key_replacement_during_pin() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let topology = block_topology_for(&roots, &binding).expect("exact topology");
    let disk = &topology.nodes()[0];
    let node_at_open = SysfsInstanceProof::new(true, 41, 7001);
    let bdi_at_open = SysfsInstanceProof::new(true, 41, 8001);
    let opened = OpenedBlockProof::new(true, DeviceNumber::new(8, 0));

    assert!(retained_block_authority_is_current(
        disk,
        disk,
        node_at_open,
        node_at_open,
        node_at_open,
        opened,
        Some(bdi_at_open),
        Some(bdi_at_open),
        Some(bdi_at_open),
    ));
    assert!(!retained_block_authority_is_current(
        disk,
        disk,
        node_at_open,
        node_at_open,
        SysfsInstanceProof::new(true, 41, 7002),
        opened,
        Some(bdi_at_open),
        Some(bdi_at_open),
        Some(bdi_at_open),
    ));
}

/// Recreating the exact BDI key during a pin cannot preserve whole-disk
/// authority even when the disk directory and block descriptor remain stable.
#[test]
fn retained_block_authority_rejects_same_key_bdi_replacement() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let topology = block_topology_for(&roots, &binding).expect("exact topology");
    let disk = &topology.nodes()[0];
    let node = SysfsInstanceProof::new(true, 41, 7001);
    let bdi_at_open = SysfsInstanceProof::new(true, 41, 8001);

    assert!(!retained_block_authority_is_current(
        disk,
        disk,
        node,
        node,
        node,
        OpenedBlockProof::new(true, DeviceNumber::new(8, 0)),
        Some(bdi_at_open),
        Some(bdi_at_open),
        Some(SysfsInstanceProof::new(true, 41, 8002)),
    ));
}

/// Retained sysfs identity alone cannot authorize a different device number or
/// a non-block descriptor opened through `/dev/<kernel-name>`.
#[test]
fn retained_block_authority_requires_exact_opened_block_descriptor() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let topology = block_topology_for(&roots, &binding).expect("exact topology");
    let disk = &topology.nodes()[0];
    let node = SysfsInstanceProof::new(true, 41, 7001);
    let bdi = SysfsInstanceProof::new(true, 41, 8001);

    for opened in [
        OpenedBlockProof::new(false, DeviceNumber::new(8, 0)),
        OpenedBlockProof::new(true, DeviceNumber::new(8, 9)),
    ] {
        assert!(!retained_block_authority_is_current(
            disk,
            disk,
            node,
            node,
            node,
            opened,
            Some(bdi),
            Some(bdi),
            Some(bdi),
        ));
    }
}

/// The volume lease budget counts each block node, block descriptor, disk BDI,
/// and mount handle before native code opens an unbounded set.
#[test]
fn retained_volume_handle_budget_rejects_overflow_before_open() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let topology = block_topology_for(&roots, &binding).expect("exact topology");

    assert_eq!(retained_volume_handle_count(topology.nodes(), 507), Ok(512),);
    assert_eq!(
        retained_volume_handle_count(topology.nodes(), 508),
        Err(NativeError::ResourceLimit),
    );
    assert_eq!(
        retained_volume_handle_count(topology.nodes(), usize::MAX),
        Err(NativeError::ResourceLimit),
    );
}

/// A block symlink that escapes the exact device ancestry is rejected.
#[test]
fn block_ancestry_rejects_symlink_escape() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let block_root = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/block");
    let outside = roots
        .devices_root()
        .parent()
        .expect("synthetic sys root")
        .join("outside-block");
    fs::create_dir_all(&outside).expect("outside block");
    fs::write(outside.join("dev"), "9:9\n").expect("outside dev number");
    symlink(&outside, block_root.join("evil")).expect("hostile block link");

    assert_eq!(
        block_bindings_for(&roots, &binding),
        Err(NativeError::EnumerationFailed),
    );
}

/// A dev-bearing child without kernel partition evidence cannot become a volume.
#[test]
fn block_ancestry_rejects_fake_partition_directory() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let fake = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/block/sda/sdaevil");
    fs::create_dir_all(&fake).expect("fake partition directory");
    fs::write(fake.join("dev"), "8:99\n").expect("fake partition device number");

    assert_eq!(
        block_bindings_for(&roots, &binding),
        Err(NativeError::EnumerationFailed),
    );
}

/// Device-mapper evidence and a holders/slaves cycle are traversed boundedly
/// and rejected as incomplete rather than flattened into a physical volume.
#[test]
fn block_topology_rejects_device_mapper_cycle() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let disk = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/block/sda");
    let dm = create_virtual_block(&roots, "dm-0", "253:0");
    fs::create_dir(dm.join("dm")).expect("device mapper evidence");
    symlink(&dm, disk.join("holders/dm-0")).expect("disk holder link");
    symlink(&disk, dm.join("slaves/sda")).expect("dm slave link");

    assert_eq!(
        block_bindings_for(&roots, &binding),
        Err(NativeError::EvidenceIncomplete),
    );
}

/// A multi-slave device-mapper graph is not treated as a provable single
/// device, including the shape used by multipath and spanned volumes.
#[test]
fn block_topology_rejects_multipath_or_spanned_graph() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let disk = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/block/sda");
    let dm = create_virtual_block(&roots, "dm-0", "253:0");
    let other = create_virtual_block(&roots, "sdb", "8:16");
    fs::create_dir(dm.join("dm")).expect("device mapper evidence");
    symlink(&dm, disk.join("holders/dm-0")).expect("disk holder link");
    symlink(&disk, dm.join("slaves/sda")).expect("first dm slave");
    symlink(&other, dm.join("slaves/sdb")).expect("second dm slave");

    assert_eq!(
        block_bindings_for(&roots, &binding),
        Err(NativeError::EvidenceIncomplete),
    );
}

/// Graph links must remain beneath `/sys/devices` even if their target is
/// otherwise a plausible block-subsystem node under the synthetic sysfs root.
#[test]
fn block_topology_rejects_graph_traversal_outside_devices() {
    let (_temp, roots) = sysfs_fixture();
    let candidate = enumerate_candidates_at(&roots)
        .expect("bounded candidates")
        .pop()
        .expect("one candidate");
    let binding = decode_recipe(candidate.recipe()).expect("exact binding");
    let disk = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0/block/sda");
    let outside = roots
        .devices_root()
        .parent()
        .expect("synthetic sys root")
        .join("outside-block");
    fs::create_dir_all(outside.join("holders")).expect("outside holders");
    fs::create_dir_all(outside.join("slaves")).expect("outside slaves");
    fs::write(outside.join("dev"), "253:9\n").expect("outside dev number");
    symlink(
        roots
            .devices_root()
            .parent()
            .expect("synthetic sys root")
            .join("class/block"),
        outside.join("subsystem"),
    )
    .expect("outside subsystem link");
    symlink(&outside, disk.join("holders/evil")).expect("escaping graph link");

    assert_eq!(
        block_bindings_for(&roots, &binding),
        Err(NativeError::EnumerationFailed),
    );
}

/// Creates one realistic block-subsystem graph node beneath `/sys/devices`.
fn create_virtual_block(roots: &SysfsRoots, name: &str, device_number: &str) -> std::path::PathBuf {
    let path = roots.devices_root().join("virtual/block").join(name);
    fs::create_dir_all(path.join("holders")).expect("virtual holders");
    fs::create_dir_all(path.join("slaves")).expect("virtual slaves");
    fs::write(path.join("dev"), format!("{device_number}\n")).expect("virtual dev number");
    symlink(
        roots
            .devices_root()
            .parent()
            .expect("synthetic sys root")
            .join("class/block"),
        path.join("subsystem"),
    )
    .expect("virtual block subsystem");
    path
}

/// Mountinfo parsing decodes only documented octal escapes and exact device numbers.
#[test]
fn mountinfo_parser_decodes_escapes_and_matches_exact_major_minor() {
    let input =
        b"36 25 8:1 /root\\134name /media/My\\040RDX rw,nosuid shared:7 - ext4 /dev/sda1 rw\n\
                  37 25 8:2 / /media/Other rw - ext4 /dev/sda2 rw\n";
    let records = parse_mountinfo(input).expect("bounded mountinfo");

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].device_number(), DeviceNumber::new(8, 1));
    assert_eq!(records[0].root(), b"/root\\name");
    assert_eq!(records[0].mount_point(), b"/media/My RDX");
    let wanted = BTreeSet::from([DeviceNumber::new(8, 1)]);
    let matches = mounts_for_devices(&records, &wanted);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].mount_point(), b"/media/My RDX");
}

/// Hostile escapes, malformed separators, long lines, and numeric overflow fail closed.
#[test]
fn mountinfo_parser_rejects_hostile_input() {
    for hostile in [
        b"36 25 8:1 / /media/bad\\000 rw - ext4 /dev/sda1 rw\n".as_slice(),
        b"36 25 8:1 / /media/bad\\999 rw - ext4 /dev/sda1 rw\n".as_slice(),
        b"36 25 8:1 / /media/../etc rw - ext4 /dev/sda1 rw\n".as_slice(),
        b"36 25 8:1 / /media//rdx rw - ext4 /dev/sda1 rw\n".as_slice(),
        b"36 25 8:1 / /media/rdx rw ext4 /dev/sda1 rw\n".as_slice(),
        b"36 25 4294967296:1 / /media/rdx rw - ext4 /dev/sda1 rw\n".as_slice(),
    ] {
        assert_eq!(
            parse_mountinfo(hostile),
            Err(NativeError::EnumerationFailed)
        );
    }
    let mut long = b"36 25 8:1 / /media/".to_vec();
    long.extend(vec![b'A'; MAX_MOUNTINFO_LINE_BYTES]);
    long.extend_from_slice(b" rw - ext4 /dev/sda1 rw\n");
    assert_eq!(parse_mountinfo(&long), Err(NativeError::ResourceLimit));
}

/// Canonical mount snapshots ignore record order but preserve every exact
/// identity field, decoded escape, filesystem, source, and option.
#[test]
fn mount_snapshot_equality_is_order_independent_and_exact() {
    let first = b"36 25 8:1 /root\\134name /media/My\\040RDX rw,nosuid shared:7 - ext4 /dev/disk\\040one rw\n\
                  37 25 8:2 / /media/Other rw - xfs /dev/sdb2 rw\n";
    let reordered = b"37 25 8:2 / /media/Other rw - xfs /dev/sdb2 rw\n\
                      36 25 8:1 /root\\134name /media/My\\040RDX rw,nosuid shared:7 - ext4 /dev/disk\\040one rw\n";
    let added = b"37 25 8:2 / /media/Other rw - xfs /dev/sdb2 rw\n\
                  36 25 8:1 /root\\134name /media/My\\040RDX rw,nosuid shared:7 - ext4 /dev/disk\\040one rw\n\
                  38 25 8:1 / /media/Second rw - ext4 /dev/sda1 rw\n";
    let changed_source =
        b"36 25 8:1 /root\\134name /media/My\\040RDX rw,nosuid shared:7 - ext4 /dev/replaced rw\n\
                           37 25 8:2 / /media/Other rw - xfs /dev/sdb2 rw\n";
    let wanted = BTreeSet::from([DeviceNumber::new(8, 1), DeviceNumber::new(8, 2)]);

    let expected = canonical_mounts_for_devices(&parse_mountinfo(first).unwrap(), &wanted).unwrap();
    let reordered =
        canonical_mounts_for_devices(&parse_mountinfo(reordered).unwrap(), &wanted).unwrap();
    let added = canonical_mounts_for_devices(&parse_mountinfo(added).unwrap(), &wanted).unwrap();
    let changed =
        canonical_mounts_for_devices(&parse_mountinfo(changed_source).unwrap(), &wanted).unwrap();

    assert_eq!(expected, reordered);
    assert_ne!(expected, added);
    assert_ne!(expected, changed);
}

/// Duplicate mount IDs and stacked records at one selected mount point are
/// ambiguous topology and therefore fail closed.
#[test]
fn mount_snapshot_rejects_duplicate_ids_and_stacked_mounts() {
    let duplicate_id = b"36 25 8:1 / /media/One rw - ext4 /dev/sda1 rw\n\
                         36 25 8:2 / /media/Two rw - ext4 /dev/sda2 rw\n";
    assert_eq!(
        parse_mountinfo(duplicate_id),
        Err(NativeError::EnumerationFailed),
    );

    let stacked = b"36 25 8:1 / /media/RDX rw - ext4 /dev/sda1 rw\n\
                    37 25 0:42 /nested /media/RDX ro - overlay overlay ro\n";
    let wanted = BTreeSet::from([DeviceNumber::new(8, 1)]);
    assert_eq!(
        canonical_mounts_for_devices(&parse_mountinfo(stacked).unwrap(), &wanted),
        Err(NativeError::EvidenceIncomplete),
    );
}

/// Active udev rules require exact VID/PID constraints and reject broad chmod grants.
#[test]
fn udev_rule_parser_distinguishes_inert_constrained_and_unsafe_rules() {
    let inert = "# inactive\n";
    let constrained = r#"ACTION=="add|change", SUBSYSTEM=="scsi_generic", ATTRS{idVendor}=="1a5a", ATTRS{idProduct}=="0006", OWNER="root", GROUP="root", MODE="0600""#;
    let broad = r#"SUBSYSTEM=="scsi_generic", GROUP="openrdx""#;
    let world = r#"SUBSYSTEM=="scsi_generic", MODE="0666""#;
    let extra_group = format!("{constrained}, GROUP=\"disk\"");
    let extra_mode = format!("{constrained}, MODE=\"0660\"");
    let interactive = constrained.replace("GROUP=\"root\"", "GROUP=\"openrdx\"");

    assert_eq!(inspect_udev_rules(inert), UdevRuleState::InactiveTemplate);
    assert_eq!(inspect_udev_rules(constrained), UdevRuleState::Constrained);
    assert_eq!(inspect_udev_rules(broad), UdevRuleState::Unsafe);
    assert_eq!(inspect_udev_rules(world), UdevRuleState::Unsafe);
    assert_eq!(inspect_udev_rules(&extra_group), UdevRuleState::Unsafe);
    assert_eq!(inspect_udev_rules(&extra_mode), UdevRuleState::Unsafe);
    assert_eq!(inspect_udev_rules(&interactive), UdevRuleState::Unsafe);
}

/// Current supplementary groups are compared to the exact configured group GID.
#[test]
fn group_membership_parser_distinguishes_configured_and_current_membership() {
    let group = b"root:x:0:\nopenrdx:x:991:alice\n";
    let duplicate = b"openrdx:x:991:alice\nopenrdx:x:992:bob\n";
    let current = b"Name:\topenrdx\nGroups:\t20 80 991\n";
    let stale = b"Name:\topenrdx\nGroups:\t20 80\n";
    let malformed = b"Name:\topenrdx\nGroups:\t20 invalid 991\n";

    assert_eq!(configured_group_gid(group), Some(991));
    assert_eq!(configured_group_gid(duplicate), None);
    assert!(process_has_group(current, 991));
    assert!(!process_has_group(stale, 991));
    assert!(!process_has_group(malformed, 991));
}

/// The packaged policy authenticates each request through one narrow action.
#[test]
fn polkit_policy_parser_rejects_broad_authority() {
    let packaged = include_str!("../../resources/linux/org.openrdx.hardware.policy");
    let broad = packaged.replace("<allow_any>no</allow_any>", "<allow_any>yes</allow_any>");
    let commented = format!("<!-- {packaged} -->\n<policyconfig/>\n");

    assert!(polkit_policy_is_narrow(packaged));
    assert!(!polkit_policy_is_narrow(&broad));
    assert!(!polkit_policy_is_narrow(&commented));
}

/// Semantic operations have no raw-CDB constructor and retain exact SG fields.
#[test]
fn semantic_operation_builds_exact_pinned_request_layout() {
    let request = ScsiOperation::log_sense_cartridge()
        .with_timeout_ms(1_001)
        .expect("bounded timeout")
        .into_request()
        .expect("bounded request");

    assert_eq!(request.cdb(), &[0x4D, 0, 0x21, 0, 0, 0, 0, 0, 0xFE, 0]);
    assert_eq!(request.direction(), DataDirection::FromDevice);
    assert_eq!(request.data().len(), 0xFE);
    assert_eq!(request.timeout_ms(), 1_001);
    assert_eq!(request.sense_capacity(), MAX_SENSE_LENGTH);
    assert_eq!(
        std::mem::size_of::<SgIoHeader>(),
        if usize::BITS == 64 { 88 } else { 64 }
    );
}

struct FakeCloser;

static CLOSE_COUNT: AtomicUsize = AtomicUsize::new(0);

impl ResourceCloser<i32> for FakeCloser {
    /// Counts one exact fake close.
    fn close(_resource: i32) {
        CLOSE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

/// Every retained native resource in a bounded set is closed exactly once when
/// the owning collection drops.
#[test]
fn resource_guards_close_all_fake_descriptors_exactly_once() {
    CLOSE_COUNT.store(0, Ordering::SeqCst);
    {
        let guards = (17..22)
            .map(ResourceGuard::<_, FakeCloser>::new)
            .collect::<Vec<_>>();
        assert_eq!(guards[0].copied(), 17);
        assert_eq!(CLOSE_COUNT.load(Ordering::SeqCst), 0);
    }
    assert_eq!(CLOSE_COUNT.load(Ordering::SeqCst), 5);
}

#[path = "tests/scsi_ancestry.rs"]
mod scsi_ancestry;

#[path = "tests/mountinfo_roots.rs"]
mod mountinfo_roots;

#[path = "tests/host_unmount.rs"]
mod host_unmount;

#[path = "tests/media_presence.rs"]
mod media_presence;

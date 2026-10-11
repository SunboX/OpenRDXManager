// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Realistic SCSI host/target/device ancestry and ambiguous-type rejection.

use super::*;

/// Adds the kernel's parent SCSI nodes without introducing extra device authority.
fn scsi_parent_fixture(roots: &SysfsRoots) -> std::path::PathBuf {
    let device = roots
        .devices_root()
        .join("pci0000:00/host1/target1:0:0/1:0:0:0");
    let target = device.parent().expect("target ancestor");
    let host = target.parent().expect("host ancestor");
    for (node, kind) in [(target, "scsi_target"), (host, "scsi_host")] {
        symlink(roots.sys_root().join("bus/scsi"), node.join("subsystem"))
            .expect("shared SCSI subsystem");
        fs::write(node.join("uevent"), format!("DEVTYPE={kind}\n")).expect("kernel device type");
    }
    device
}

/// Parent targets and hosts use the same subsystem without being SCSI devices.
#[test]
fn block_topology_accepts_scsi_target_and_host_ancestors() {
    let (_temp, roots) = sysfs_fixture();
    scsi_parent_fixture(&roots);
    let candidate = enumerate_candidates_at(&roots)
        .expect("enumeration")
        .pop()
        .expect("candidate");
    let binding = decode_recipe(candidate.recipe()).expect("binding");
    let blocks = block_bindings_for(&roots, &binding).expect("exact device topology");
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].name(), "sda");
    assert_eq!(blocks[1].name(), "sda1");
}

/// Missing, duplicate, unknown, and contradictory types never grant authority.
#[test]
fn block_topology_rejects_ambiguous_scsi_device_types() {
    let (_temp, roots) = sysfs_fixture();
    let device = scsi_parent_fixture(&roots);
    let candidate = enumerate_candidates_at(&roots)
        .expect("enumeration")
        .pop()
        .expect("candidate");
    let binding = decode_recipe(candidate.recipe()).expect("binding");
    for contents in [
        "DRIVER=sd\n",
        "DEVTYPE=scsi_device\nDEVTYPE=scsi_device\n",
        "DEVTYPE=unknown\n",
        "DEVTYPE=scsi_target\n",
    ] {
        fs::write(device.join("uevent"), contents).expect("replace type");
        assert_eq!(
            block_topology_for(&roots, &binding),
            Err(NativeError::EnumerationFailed)
        );
    }
    fs::write(device.join("uevent"), "DEVTYPE=scsi_device\n").expect("restore type");
    fs::write(
        device.parent().expect("target").join("uevent"),
        "DEVTYPE=scsi_device\n",
    )
    .expect("contradictory ancestor type");
    assert_eq!(
        block_topology_for(&roots, &binding),
        Err(NativeError::EnumerationFailed)
    );
}

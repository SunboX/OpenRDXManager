// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit root-only UDisks acceptance against a disposable loop image.

use super::*;
use std::fs::File;
use std::io::Read;
use std::process::{Command, Stdio};
use zbus::zvariant::Fd;

/// Owns only the loop object created from this test's temporary image.
struct LoopCleanup {
    connection: Connection,
    owner: String,
    object: OwnedObjectPath,
}

impl Drop for LoopCleanup {
    /// Attempts normal unmount and deletes only this test-created loop object.
    fn drop(&mut self) {
        let _ = bounded(async {
            // Partitioned tests can unwind before explicit unmount. Select children
            // only by their root-owned Partition.Table link to this owned loop.
            let manager = uncached_proxy(
                &self.connection,
                &self.owner,
                "/org/freedesktop/UDisks2/Manager",
                "org.freedesktop.UDisks2.Manager",
            )
            .await?;
            let options: HashMap<&str, Value<'_>> = HashMap::new();
            let objects: Vec<OwnedObjectPath> = manager
                .call("GetBlockDevices", &(options,))
                .await
                .map_err(|_| NativeError::Other)?;
            for object in objects.into_iter().take(MAX_CANDIDATES) {
                let partition = uncached_proxy(
                    &self.connection,
                    &self.owner,
                    object.as_str(),
                    "org.freedesktop.UDisks2.Partition",
                )
                .await?;
                if partition
                    .get_property::<OwnedObjectPath>("Table")
                    .await
                    .ok()
                    .as_ref()
                    != Some(&self.object)
                {
                    continue;
                }
                let filesystem =
                    uncached_proxy(&self.connection, &self.owner, object.as_str(), FILESYSTEM)
                        .await?;
                let _ = filesystem
                    .call::<_, _, ()>("Unmount", &(unmount_options(),))
                    .await;
            }
            if let Ok(filesystem) = uncached_proxy(
                &self.connection,
                &self.owner,
                self.object.as_str(),
                FILESYSTEM,
            )
            .await
            {
                let _ = filesystem
                    .call::<_, _, ()>("Unmount", &(unmount_options(),))
                    .await;
            }
            let loop_proxy = uncached_proxy(
                &self.connection,
                &self.owner,
                self.object.as_str(),
                "org.freedesktop.UDisks2.Loop",
            )
            .await?;
            let options: HashMap<&str, Value<'_>> = HashMap::new();
            loop_proxy
                .call::<_, _, ()>("Delete", &(options,))
                .await
                .map_err(|_| NativeError::Other)
        });
    }
}

/// Exercises the actual daemon without selecting or ejecting any physical drive.
#[test]
#[ignore = "requires root, UDisks2 and mkfs.exfat; creates only a temporary loop image"]
fn normal_unmount_of_disposable_loop_preserves_busy_users() {
    assert_eq!(super::super::effective_uid(), 0);
    let image = tempfile::Builder::new()
        .prefix("openrdx-unmount-test-")
        .tempfile()
        .expect("owned image");
    image
        .as_file()
        .set_len(32 * 1024 * 1024)
        .expect("image length");
    let status = Command::new("/usr/sbin/mkfs.exfat")
        .args(["-L", "RDXTest"])
        .arg(image.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("temporary image formatter");
    assert!(status.success());

    let (loop_guard, mount_point, device) = bounded(async {
        let connection = Connection::system()
            .await
            .map_err(|_| NativeError::DependencyMissing)?;
        let bus = uncached_proxy(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await?;
        let owner: String = bus
            .call("GetNameOwner", &(SERVICE,))
            .await
            .map_err(|_| NativeError::Other)?;
        drop(bus);
        let manager = uncached_proxy(
            &connection,
            &owner,
            "/org/freedesktop/UDisks2/Manager",
            "org.freedesktop.UDisks2.Manager",
        )
        .await?;
        let options = HashMap::from([("no-part-scan", Value::Bool(true))]);
        let object: OwnedObjectPath = manager
            .call("LoopSetup", &(Fd::from(image.as_file()), options))
            .await
            .map_err(|_| NativeError::Other)?;
        assert!(
            object
                .as_str()
                .starts_with("/org/freedesktop/UDisks2/block_devices/loop")
        );
        drop(manager);
        let guard = LoopCleanup {
            connection,
            owner,
            object,
        };
        let block = uncached_proxy(
            &guard.connection,
            &guard.owner,
            guard.object.as_str(),
            BLOCK,
        )
        .await?;
        let raw: u64 = block
            .get_property("DeviceNumber")
            .await
            .map_err(|_| NativeError::Other)?;
        let filesystem = uncached_proxy(
            &guard.connection,
            &guard.owner,
            guard.object.as_str(),
            FILESYSTEM,
        )
        .await?;
        let options = HashMap::from([("fstype", Value::Str("exfat".into()))]);
        let point: String = filesystem
            .call("Mount", &(options,))
            .await
            .map_err(|_| NativeError::Other)?;
        drop(filesystem);
        drop(block);
        Ok((guard, point, device_number_from_linux_dev_t(raw)))
    })
    .expect("test loop setup and mount");

    // The exact block inode remains pinned without opening the media for I/O.
    // Fixed formatting tools can still reopen their inherited /proc fd path.
    let name = loop_guard
        .object
        .as_str()
        .rsplit('/')
        .next()
        .expect("loop name");
    let identity = super::super::open_exact_block(name, device).expect("identity-only block lease");
    let fd_info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", identity.copied()))
        .expect("own descriptor flags");
    let flags = fd_info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .and_then(|value| u32::from_str_radix(value, 8).ok())
        .expect("kernel flags");
    assert_ne!(flags & libc::O_PATH as u32, 0);
    let mut reader = File::open(format!("/proc/self/fd/{}", identity.copied()))
        .expect("fixed tools can reopen exact authority");
    let mut sector = [0; 512];
    reader
        .read_exact(&mut sector)
        .expect("owned image boot sector");
    assert_eq!(&sector[3..11], b"EXFAT   ");
    drop(reader);

    let points = vec![mount_point.as_bytes().to_vec()];
    let host = UDisksUnmount::prepare(device, points).expect("exact daemon/kernel mount evidence");
    let external_user = File::open(&mount_point).expect("simulated open directory user");
    assert_eq!(
        host.unmount(),
        HostOperationOutcome::DefinitelyRejected(NativeError::Busy)
    );
    assert!(
        std::path::Path::new(&mount_point).is_dir(),
        "busy refusal preserves the mounted volume"
    );
    drop(external_user);
    assert_eq!(host.unmount(), HostOperationOutcome::Succeeded);
    let records = super::super::parse_mountinfo(
        &std::fs::read("/proc/self/mountinfo").expect("kernel inventory"),
    )
    .expect("mount records");
    assert!(
        records
            .iter()
            .all(|record| record.device_number() != device)
    );
    drop(loop_guard);
}

/// Creates a loop solely from a newly allocated image owned by the calling test.
fn setup_owned_loop(image: &File) -> (LoopCleanup, crate::identity::DeviceNumber, String) {
    bounded(async {
        let connection = Connection::system()
            .await
            .map_err(|_| NativeError::DependencyMissing)?;
        let bus = uncached_proxy(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .await?;
        let owner: String = bus
            .call("GetNameOwner", &(SERVICE,))
            .await
            .map_err(|_| NativeError::Other)?;
        let manager = uncached_proxy(
            &connection,
            &owner,
            "/org/freedesktop/UDisks2/Manager",
            "org.freedesktop.UDisks2.Manager",
        )
        .await?;
        let options = HashMap::from([("no-part-scan", Value::Bool(false))]);
        let object: OwnedObjectPath = manager
            .call("LoopSetup", &(Fd::from(image), options))
            .await
            .map_err(|_| NativeError::Other)?;
        assert!(
            object
                .as_str()
                .starts_with("/org/freedesktop/UDisks2/block_devices/loop")
        );
        let block = uncached_proxy(&connection, &owner, object.as_str(), BLOCK).await?;
        let raw: u64 = block
            .get_property("DeviceNumber")
            .await
            .map_err(|_| NativeError::Other)?;
        let name = object
            .as_str()
            .rsplit('/')
            .next()
            .expect("owned loop name")
            .to_owned();
        drop(block);
        drop(manager);
        drop(bus);
        Ok((
            LoopCleanup {
                connection,
                owner,
                object,
            },
            device_number_from_linux_dev_t(raw),
            name,
        ))
    })
    .expect("owned loop setup")
}

/// Checks every production formatter, partition personality, signature and mount.
#[test]
#[ignore = "requires root, UDisks2 and fixed mkfs tools; formats only test-created loop images"]
fn all_linux_formats_on_disposable_partitioned_loops() {
    use super::super::formatting::format_disposable_loop;
    use crate::HostFilesystem;
    use crate::identity::read_device_number;
    use std::path::Path;
    assert_eq!(super::super::effective_uid(), 0);
    for selected in [
        HostFilesystem::Ntfs,
        HostFilesystem::ExFat,
        HostFilesystem::Ext2,
        HostFilesystem::Ext3,
        HostFilesystem::Ext4,
        HostFilesystem::Xfs,
        HostFilesystem::Btrfs,
        HostFilesystem::F2fs,
        HostFilesystem::Fat16,
        HostFilesystem::Fat32,
    ] {
        eprintln!("Verifying {selected:?} on an owned disposable image");
        let image = tempfile::Builder::new()
            .prefix("openrdx-format-test-")
            .tempfile()
            .expect("owned image");
        image
            .as_file()
            .set_len(1024 * 1024 * 1024)
            .expect("image size");
        let (guard, disk, name) = setup_owned_loop(image.as_file());
        let authority =
            super::super::open_exact_block(&name, disk).expect("owned whole disk authority");
        assert_eq!(
            format_disposable_loop(selected, authority.copied(), disk, true),
            HostOperationOutcome::Succeeded,
            "partition {selected:?}"
        );
        let partition_name = format!("{name}p1");
        let sysfs = Path::new("/sys/class/block").join(&partition_name);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !sysfs.join("dev").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let partition = read_device_number(&sysfs.join("dev")).expect("owned partition number");
        assert_eq!(
            std::fs::read_to_string(sysfs.join("start")).unwrap().trim(),
            "2048"
        );
        assert_eq!(
            std::fs::read_to_string(sysfs.join("size")).unwrap().trim(),
            "2095104"
        );
        let authority = super::super::open_exact_block(&partition_name, partition)
            .expect("owned partition authority");
        assert_eq!(
            format_disposable_loop(selected, authority.copied(), partition, false),
            HostOperationOutcome::Succeeded,
            "formatter {selected:?}"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let host = loop {
            match UDisksUnmount::prepare_format(partition) {
                Ok(host) => break host,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(error) => panic!("host rediscovery {selected:?}: {error:?}"),
            }
        };
        assert_eq!(
            host.mount_formatted(selected),
            HostOperationOutcome::Succeeded,
            "signature and mount {selected:?}"
        );
        let records =
            super::super::parse_mountinfo(&std::fs::read("/proc/self/mountinfo").unwrap()).unwrap();
        let devices = std::collections::BTreeSet::from([disk, partition]);
        let (mounts, bindings) = super::super::btrfs::selected_mounts(&records, &devices)
            .expect("single-device membership proof");
        assert_eq!(mounts.len(), 1, "exact mounted partition {selected:?}");
        assert!(selected.mount_matches(mounts[0].filesystem_type()));
        assert_eq!(bindings.get(&mounts[0].mount_id()), Some(&partition));
        assert_eq!(host.read_filesystem(), Ok(selected));
        let mut volume =
            pin_owned_loop_volume(&name, disk, &partition_name, partition, mounts, bindings);
        assert_eq!(volume.mounted_filesystem(), Some(selected));
        let exact_host = UDisksUnmount::prepare(
            partition,
            volume
                ._mount_snapshot
                .iter()
                .map(|mount| mount.mount_point().to_vec())
                .collect(),
        )
        .unwrap();
        assert_eq!(exact_host.read_label(), Ok("OPENRDX".into()));
        assert_eq!(volume.read_label(), Ok("OPENRDX".into()));
        if matches!(
            selected,
            HostFilesystem::F2fs | HostFilesystem::Fat16 | HostFilesystem::Fat32
        ) {
            assert_eq!(
                volume.set_label("RDXTest"),
                HostOperationOutcome::NotAttempted(NativeError::UnsupportedPlatform)
            );
            assert_eq!(volume.read_label(), Ok("OPENRDX".into()));
        } else {
            assert_eq!(
                volume.set_label("RDXTest"),
                HostOperationOutcome::Succeeded,
                "rename {selected:?}"
            );
            assert_eq!(volume.read_label(), Ok("RDXTest".into()));
            assert_eq!(
                volume.set_label(""),
                HostOperationOutcome::Succeeded,
                "clear {selected:?}"
            );
            assert_eq!(volume.read_label(), Ok("".into()));
        }
        assert!(
            volume.mounted_facts().is_ok(),
            "mounted space facts {selected:?}"
        );
        assert_eq!(
            volume.unmount_all(),
            HostOperationOutcome::Succeeded,
            "production normal unmount {selected:?}"
        );
        drop(volume);
        drop(guard);
    }
}

/// Pins only the two sysfs nodes and mounts derived from a test-owned loop image.
fn pin_owned_loop_volume(
    name: &str,
    disk: crate::identity::DeviceNumber,
    partition_name: &str,
    partition: crate::identity::DeviceNumber,
    mounts: Vec<crate::mountinfo::MountRecord>,
    bindings: std::collections::BTreeMap<u64, crate::identity::DeviceNumber>,
) -> super::super::NativeVolumeLeases {
    use super::super::*;
    let roots = SysfsRoots::native().unwrap();
    let disk_path = std::fs::canonicalize(Path::new("/sys/class/block").join(name)).unwrap();
    let partition_path =
        std::fs::canonicalize(Path::new("/sys/class/block").join(partition_name)).unwrap();
    let disk_node = BlockNodeProof {
        name: name.into(),
        relative_path: disk_path.strip_prefix(roots.devices_root()).unwrap().into(),
        device_number: disk,
        partition: None,
        bdi: Some(crate::block::validate_bdi_binding(&roots, &disk_path, disk).unwrap()),
    };
    let partition_node = BlockNodeProof {
        name: partition_name.into(),
        relative_path: partition_path
            .strip_prefix(roots.devices_root())
            .unwrap()
            .into(),
        device_number: partition,
        partition: Some(1),
        bdi: None,
    };
    let block_authorities = vec![
        RetainedBlockAuthority::open(&roots, &disk_node).unwrap(),
        RetainedBlockAuthority::open(&roots, &partition_node).unwrap(),
    ];
    let mut handles = Vec::new();
    for mount in &mounts {
        let directory = btrfs::open_record_mount(mount).unwrap();
        let tree = open_exact_mount_tree(mount.mount_point()).unwrap();
        let restore = open_mount_restore_authority(mount.mount_point(), &directory).unwrap();
        handles.push(RetainedMount {
            directory,
            tree,
            mount_id: mount.mount_id(),
            restore,
        });
    }
    NativeVolumeLeases {
        _block_authorities: block_authorities,
        _mount_fds: handles,
        _topology: BlockTopology {
            scsi_device_relative: disk_node.relative_path.clone(),
            bindings: vec![
                BlockBinding {
                    name: name.into(),
                    device_number: disk,
                },
                BlockBinding {
                    name: partition_name.into(),
                    device_number: partition,
                },
            ],
            nodes: vec![disk_node, partition_node],
        },
        _mount_snapshot: mounts,
        _mount_bindings: bindings,
    }
}

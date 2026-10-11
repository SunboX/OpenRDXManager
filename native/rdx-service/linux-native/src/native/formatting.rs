// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed Linux partitioning and filesystem tool operations.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::*;

const SFDISK_PATHS: [&str; 2] = ["/usr/sbin/sfdisk", "/sbin/sfdisk"];
const PARTITION_REDISCOVERY_ATTEMPTS: usize = 100;
const PARTITION_REDISCOVERY_DELAY: Duration = Duration::from_millis(100);
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_BLOCK_FD: libc::c_int = 9;
const CHILD_BLOCK_PATH: &str = "/proc/self/fd/9";
const PARTITION_START_SECTORS: u64 = 2_048;
const GPT_TAIL_SECTORS: u64 = 33;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SinglePartitionLayout {
    Mbr { size_sectors: u64 },
    Gpt { size_sectors: u64 },
}

impl SinglePartitionLayout {
    /// Returns the exact partition extent expected after kernel rediscovery.
    const fn extent(self) -> (u64, u64) {
        match self {
            Self::Mbr { size_sectors } | Self::Gpt { size_sectors } => {
                (PARTITION_START_SECTORS, size_sectors)
            }
        }
    }
}

impl NativeDevice {
    /// Checks executable dependencies and exact current authority without mutation.
    pub(crate) fn preflight_format(
        &mut self,
        filesystem: HostFilesystem,
    ) -> Result<(), NativeError> {
        self.format_selection = None;
        self.revalidate_sg_authority()?;
        self.media_identity_material()?;
        required_tool(&SFDISK_PATHS)?;
        required_tool(filesystem.tool_paths())?;
        let leases = self.pin_volumes()?;
        let (_, capacity) = leases.media_facts()?;
        let (_, size) = single_partition_layout(capacity)?.extent();
        filesystem.check_capacity(size * 512)?;
        super::udisks::UDisksUnmount::prepare_format(
            leases.exact_block_authority(None)?.node.device_number(),
        )?;
        self.format_selection = Some((filesystem, capacity));
        Ok(())
    }

    /// Runs exact-argv `sfdisk` against the revalidated sole whole block node.
    pub(crate) fn create_single_partition(&mut self, signature: u32) -> HostOperationOutcome {
        let Some((filesystem, selected_capacity)) = self.format_selection else {
            return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
        };
        if signature == 0 {
            return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
        }
        let tool = match required_tool(&SFDISK_PATHS) {
            Ok(tool) => tool,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        if let Err(error) = self.media_identity_material() {
            return HostOperationOutcome::NotAttempted(error);
        }
        let leases = match self.pin_volumes() {
            Ok(leases) => leases,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        if leases.mount_count() != 0 {
            return HostOperationOutcome::NotAttempted(NativeError::Busy);
        }
        let (_, capacity) = match leases.media_facts() {
            Ok(facts) => facts,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let layout = match single_partition_layout(capacity) {
            Ok(layout) => layout,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        let authority = match leases.exact_block_authority(None) {
            Ok(authority) => authority,
            Err(error) => return HostOperationOutcome::NotAttempted(error),
        };
        if capacity != selected_capacity {
            return HostOperationOutcome::NotAttempted(NativeError::DeviceRemoved);
        }
        let script = partition_script(layout, filesystem, signature);
        let outcome = run_tool_with_stdin(
            tool,
            &["--wipe", "always", "--wipe-partitions", "always"],
            authority,
            script.as_bytes(),
        );
        if outcome != HostOperationOutcome::Succeeded {
            return outcome;
        }
        if self.revalidate_sg_authority().is_err() {
            return HostOperationOutcome::CompletionUnknown(NativeError::DeviceRemoved);
        }
        HostOperationOutcome::Succeeded
    }

    /// Runs the selected exact-argv formatter against the sole exact partition.
    pub(crate) fn format_partition(&mut self, filesystem: HostFilesystem) -> HostOperationOutcome {
        if self.format_selection.map(|selection| selection.0) != Some(filesystem) {
            return HostOperationOutcome::NotAttempted(NativeError::InvalidRequest);
        }
        let tool = match required_tool(filesystem.tool_paths()) {
            Ok(tool) => tool,
            Err(error) => return HostOperationOutcome::CompletionUnknown(error),
        };
        if let Err(error) = self.media_identity_material() {
            return HostOperationOutcome::CompletionUnknown(error);
        }
        let leases = match self.wait_for_sole_partition() {
            Ok(leases) => leases,
            Err(error) => return HostOperationOutcome::CompletionUnknown(error),
        };
        let authority = match leases.exact_block_authority(Some(1)) {
            Ok(authority) => authority,
            Err(error) => return HostOperationOutcome::CompletionUnknown(error),
        };
        let outcome = run_tool(tool, filesystem.arguments(), authority);
        if outcome != HostOperationOutcome::Succeeded {
            return outcome;
        }
        if self.revalidate_sg_authority().is_err() {
            return HostOperationOutcome::CompletionUnknown(NativeError::DeviceRemoved);
        }
        HostOperationOutcome::Succeeded
    }

    /// Waits a fixed interval for kernel partition rediscovery under fresh authority checks.
    fn wait_for_sole_partition(&mut self) -> Result<NativeVolumeLeases, NativeError> {
        for attempt in 0..PARTITION_REDISCOVERY_ATTEMPTS {
            self.revalidate_sg_authority()?;
            self.media_identity_material()?;
            let leases = self.pin_volumes()?;
            if leases.mount_count() != 0 {
                return Err(NativeError::Busy);
            }
            match leases.exact_block_authority(Some(1)) {
                Ok(_) => {
                    let (_, capacity) = leases.media_facts()?;
                    let expected = single_partition_layout(capacity)?.extent();
                    if leases.sole_partition_extent()? == expected {
                        return Ok(leases);
                    }
                    return Err(NativeError::EvidenceIncomplete);
                }
                Err(NativeError::EvidenceIncomplete) => {
                    if attempt + 1 == PARTITION_REDISCOVERY_ATTEMPTS {
                        break;
                    }
                    thread::sleep(PARTITION_REDISCOVERY_DELAY);
                }
                Err(error) => return Err(error),
            }
        }
        Err(NativeError::TimedOut)
    }

    /// Waits until the retained exact device reports no cartridge block media.
    pub(crate) fn verify_eject_departure(&mut self) -> Result<(), NativeError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.media_identity_material() {
                Err(NativeError::NoMedia) => return Ok(()),
                Err(error) => return Err(error),
                Ok(_) if Instant::now() >= deadline => return Err(NativeError::TimedOut),
                Ok(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Waits for one exact mounted partition of the requested filesystem and capacity.
    pub(crate) fn verify_format_rediscovery(
        &mut self,
        filesystem: HostFilesystem,
        previous_capacity: u64,
    ) -> Result<(), NativeError> {
        let deadline = Instant::now() + Duration::from_secs(15);
        if self.format_selection != Some((filesystem, previous_capacity)) {
            return Err(NativeError::InvalidRequest);
        }
        let leases = self.pin_volumes()?;
        if leases.block_count() != 2
            || leases.mount_count() > 1
            || leases.sole_partition_extent()?
                != single_partition_layout(previous_capacity)?.extent()
            || leases.media_facts()?.1 != previous_capacity
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        let partition = leases.exact_block_authority(Some(1))?;
        let host = super::udisks::UDisksUnmount::prepare_format(partition.node.device_number())?;
        partition.revalidate(&self.roots)?;
        let outcome = host.mount_formatted(filesystem);
        drop(leases);
        match outcome {
            HostOperationOutcome::Succeeded => {}
            HostOperationOutcome::NotAttempted(error)
            | HostOperationOutcome::DefinitelyRejected(error)
            | HostOperationOutcome::CompletionUnknown(error) => return Err(error),
        }
        loop {
            self.media_identity_material()?;
            match self.pin_volumes() {
                Ok(leases)
                    if leases.block_count() == 2
                        && leases.mount_count() == 1
                        && leases.sole_partition_extent().is_ok_and(|extent| {
                            single_partition_layout(previous_capacity)
                                .is_ok_and(|layout| extent == layout.extent())
                        })
                        && leases
                            .media_facts()
                            .is_ok_and(|(_, capacity)| capacity == previous_capacity)
                        && leases
                            .mounted_filesystem_type()
                            .is_ok_and(|actual| filesystem.mount_matches(actual)) =>
                {
                    self.format_selection = None;
                    return Ok(());
                }
                Err(NativeError::DeviceRemoved | NativeError::EvidenceIncomplete)
                    if Instant::now() < deadline => {}
                Err(error) => return Err(error),
                Ok(_) if Instant::now() >= deadline => return Err(NativeError::TimedOut),
                Ok(_) => {}
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Selects MBR only while its 32-bit sector count represents the full extent.
fn single_partition_layout(capacity_bytes: u64) -> Result<SinglePartitionLayout, NativeError> {
    if capacity_bytes % 512 != 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let total_sectors = capacity_bytes / 512;
    let mbr_size = total_sectors
        .checked_sub(PARTITION_START_SECTORS)
        .ok_or(NativeError::EvidenceIncomplete)?;
    if mbr_size == 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    if mbr_size <= u64::from(u32::MAX) {
        return Ok(SinglePartitionLayout::Mbr {
            size_sectors: mbr_size,
        });
    }
    let gpt_size = mbr_size
        .checked_sub(GPT_TAIL_SECTORS)
        .ok_or(NativeError::EvidenceIncomplete)?;
    Ok(SinglePartitionLayout::Gpt {
        size_sectors: gpt_size,
    })
}

/// Chooses one fixed root-owned executable path without consulting `PATH`.
fn required_tool<'paths>(paths: &'paths [&str]) -> Result<&'paths str, NativeError> {
    paths
        .iter()
        .copied()
        .find(|path| {
            fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o111 != 0
                    && metadata.mode() & 0o022 == 0
            })
        })
        .ok_or(NativeError::DependencyMissing)
}

/// Writes the selected partition personality using fixed app-built table fields.
fn partition_script(
    layout: SinglePartitionLayout,
    filesystem: HostFilesystem,
    signature: u32,
) -> String {
    match layout {
        SinglePartitionLayout::Mbr { size_sectors } => format!(
            "label: dos\nlabel-id: 0x{signature:08x}\nstart={PARTITION_START_SECTORS}, size={size_sectors}, type={}{}\n",
            filesystem.mbr_type(),
            if matches!(filesystem, HostFilesystem::Ntfs | HostFilesystem::ExFat) {
                ", bootable"
            } else {
                ""
            }
        ),
        SinglePartitionLayout::Gpt { size_sectors } => format!(
            "label: gpt\nstart={PARTITION_START_SECTORS}, size={size_sectors}, type={}\n",
            filesystem.gpt_type()
        ),
    }
}

/// Exercises the production descriptor sandbox and layout on a test-owned loop.
#[cfg(test)]
pub(super) fn format_disposable_loop(
    filesystem: HostFilesystem,
    source: libc::c_int,
    device: DeviceNumber,
    partition: bool,
) -> HostOperationOutcome {
    let tool = if partition {
        required_tool(&SFDISK_PATHS)
    } else {
        required_tool(filesystem.tool_paths())
    };
    let tool = match tool {
        Ok(tool) => tool,
        Err(error) => return HostOperationOutcome::NotAttempted(error),
    };
    let mut command = Command::new(tool);
    command
        .args(if partition {
            &["--wipe", "always", "--wipe-partitions", "always"][..]
        } else {
            filesystem.arguments()
        })
        .arg(CHILD_BLOCK_PATH)
        .stdin(if partition {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_retained_fd(&mut command, source, device);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return HostOperationOutcome::NotAttempted(NativeError::Other),
    };
    if partition {
        let script = partition_script(
            single_partition_layout(1024 * 1024 * 1024).expect("test capacity"),
            filesystem,
            0x12345678,
        );
        let mut stdin = child.stdin.take().expect("test layout pipe");
        if stdin.write_all(script.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return HostOperationOutcome::CompletionUnknown(NativeError::Other);
        }
    }
    wait_bounded(child, Instant::now() + TOOL_TIMEOUT)
}

/// Executes one fixed tool with exact arguments and no shell or inherited text output.
fn run_tool(
    tool: &str,
    arguments: &[&str],
    authority: &RetainedBlockAuthority,
) -> HostOperationOutcome {
    let mut command = Command::new(tool);
    command
        .args(arguments)
        .arg(CHILD_BLOCK_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_retained_fd(
        &mut command,
        authority.block_fd.copied(),
        authority.node.device_number(),
    );
    let child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return HostOperationOutcome::NotAttempted(NativeError::DependencyMissing),
    };
    wait_bounded(child, Instant::now() + TOOL_TIMEOUT)
}

/// Executes one fixed tool with an app-built bounded stdin layout description.
fn run_tool_with_stdin(
    tool: &str,
    arguments: &[&str],
    authority: &RetainedBlockAuthority,
    input: &[u8],
) -> HostOperationOutcome {
    let mut command = Command::new(tool);
    command
        .args(arguments)
        .arg(CHILD_BLOCK_PATH)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_retained_fd(
        &mut command,
        authority.block_fd.copied(),
        authority.node.device_number(),
    );
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return HostOperationOutcome::NotAttempted(NativeError::DependencyMissing),
    };
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return HostOperationOutcome::CompletionUnknown(NativeError::Other);
    };
    if stdin.write_all(input).is_err() {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return HostOperationOutcome::CompletionUnknown(NativeError::Other);
    }
    drop(stdin);
    wait_bounded(child, Instant::now() + TOOL_TIMEOUT)
}

/// Installs one retained exact block descriptor at the fixed child-only fd.
fn configure_retained_fd(command: &mut Command, source: libc::c_int, expected: DeviceNumber) {
    configure_retained_fd_with_expectation(command, source, RetainedFdExpectation::Block(expected));
}

/// File identity admitted at the child-only descriptor validation boundary.
#[derive(Clone, Copy)]
enum RetainedFdExpectation {
    Block(DeviceNumber),
    #[cfg(test)]
    AppOwnedFile,
}

/// Installs and validates one descriptor before masking the device namespace.
fn configure_retained_fd_with_expectation(
    command: &mut Command,
    source: libc::c_int,
    expected: RetainedFdExpectation,
) {
    // SAFETY: this closure runs after fork and before exec, touches only scalar
    // descriptors, and either installs the retained duplicate or aborts exec.
    unsafe {
        command.pre_exec(move || {
            if source == CHILD_BLOCK_FD {
                let flags = libc::fcntl(source, libc::F_GETFD);
                if flags < 0 || libc::fcntl(source, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(source, CHILD_BLOCK_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if libc::fstat(CHILD_BLOCK_FD, stat.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: successful fstat initializes the complete structure.
            let stat = stat.assume_init();
            let identity_matches = match expected {
                RetainedFdExpectation::Block(device) => {
                    file_type(stat.st_mode) == libc::S_IFBLK
                        && device_number(stat.st_rdev) == device
                }
                #[cfg(test)]
                RetainedFdExpectation::AppOwnedFile => file_type(stat.st_mode) == libc::S_IFREG,
            };
            if !identity_matches {
                return Err(std::io::Error::from_raw_os_error(libc::ENODEV));
            }
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::mount(
                c"openrdx-sandbox".as_ptr(),
                c"/dev".as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=4096,mode=000".as_ptr().cast(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Exercises fd inheritance and `/dev` masking against an app-owned file.
#[cfg(test)]
pub(crate) fn retained_fd_namespace_runtime_contract() -> bool {
    use std::os::fd::AsRawFd;

    let file = match tempfile::tempfile() {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut readlink = Command::new("/usr/bin/readlink");
    readlink.arg(CHILD_BLOCK_PATH).stderr(Stdio::null());
    configure_retained_fd_with_expectation(
        &mut readlink,
        file.as_raw_fd(),
        RetainedFdExpectation::AppOwnedFile,
    );
    let inherited = match readlink.output() {
        Ok(output) if output.status.success() => {
            let target = String::from_utf8_lossy(&output.stdout);
            !target.trim().is_empty() && !target.trim().starts_with("/dev/")
        }
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::ENOSYS)
            ) =>
        {
            // A host that forbids mount namespaces proves the production
            // formatter fails before exec rather than reopening a device path.
            return true;
        }
        Ok(_) | Err(_) => false,
    };
    if !inherited {
        return false;
    }
    let mut find = Command::new("/usr/bin/find");
    find.args(["/dev", "-mindepth", "1", "-print"])
        .stderr(Stdio::null());
    configure_retained_fd_with_expectation(
        &mut find,
        file.as_raw_fd(),
        RetainedFdExpectation::AppOwnedFile,
    );
    find.output()
        .is_ok_and(|output| output.status.success() && output.stdout.is_empty())
}

/// Waits under one absolute deadline, terminating and draining on timeout.
fn wait_bounded(mut child: std::process::Child, deadline: Instant) -> HostOperationOutcome {
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return HostOperationOutcome::Succeeded,
            Ok(Some(_)) | Err(_) => {
                return HostOperationOutcome::CompletionUnknown(NativeError::Other);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return HostOperationOutcome::CompletionUnknown(NativeError::TimedOut);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MBR is selected through its final representable sector and GPT immediately after it.
    #[test]
    fn layout_selection_covers_mbr_and_gpt_capacity_boundary() {
        let maximum_mbr_sectors = PARTITION_START_SECTORS + u64::from(u32::MAX);
        assert_eq!(
            single_partition_layout(maximum_mbr_sectors * 512),
            Ok(SinglePartitionLayout::Mbr {
                size_sectors: u64::from(u32::MAX)
            })
        );
        assert_eq!(
            single_partition_layout((maximum_mbr_sectors + 1) * 512),
            Ok(SinglePartitionLayout::Gpt {
                size_sectors: u64::from(u32::MAX) + 1 - GPT_TAIL_SECTORS
            })
        );
    }

    /// A large Linux cartridge gets a GPT Linux GUID, while cross-host data keeps its GUID.
    #[test]
    fn scripts_use_selected_filesystem_partition_types() {
        let gpt = single_partition_layout(3 * 1024_u64.pow(4)).unwrap();
        for fs in [
            HostFilesystem::Ext4,
            HostFilesystem::Xfs,
            HostFilesystem::Btrfs,
            HostFilesystem::F2fs,
        ] {
            let script = partition_script(gpt, fs, 1);
            assert!(script.starts_with("label: gpt\n"));
            assert!(script.contains("type=0FC63DAF-8483-4772-8E79-3D69D8477DE4"));
        }
        assert!(
            partition_script(gpt, HostFilesystem::ExFat, 1)
                .contains("type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
        );
        let mbr = single_partition_layout(1024 * 1024 * 1024).unwrap();
        assert!(partition_script(mbr, HostFilesystem::Ext4, 1).contains("type=83"));
        assert!(partition_script(mbr, HostFilesystem::Fat16, 1).contains("type=e"));
        assert!(partition_script(mbr, HostFilesystem::Fat32, 1).contains("type=c"));
    }

    /// Misaligned and too-small media fail before any native tool can be started.
    #[test]
    fn layout_selection_rejects_unrepresentable_preflight_inputs() {
        assert_eq!(
            single_partition_layout(PARTITION_START_SECTORS * 512),
            Err(NativeError::EvidenceIncomplete)
        );
        assert_eq!(
            single_partition_layout(PARTITION_START_SECTORS * 512 + 1),
            Err(NativeError::EvidenceIncomplete)
        );
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Descriptor-relative owner-only durable files, receipt and bounded journal.

#[cfg(any(target_os = "macos", test))]
pub(super) mod inventory;
#[cfg(any(target_os = "macos", test))]
pub(super) mod loader;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub(crate) mod manufacturing;
#[cfg(any(target_os = "macos", test))]
mod provenance;

use super::profile::{self, digest};
use super::{MigrationCapture, MigrationError, MigrationEvent};
use rustix::fs::{self, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PRIVATE_DIRECTORY: Mode = Mode::from_raw_mode(0o700);
const PRIVATE_FILE: Mode = Mode::from_raw_mode(0o600);
const MAX_METADATA: usize = 8192;
const MAX_JOURNAL: usize = 65536;
const MAX_EVENTS: usize = 128;
const BUILD_EVIDENCE: &[u8] = include_bytes!("../../resources/migration/build-evidence.json");
static NEXT_BUNDLE: AtomicU64 = AtomicU64::new(0);
const ARTIFACT_NAMES: [&str; 6] = [
    "capture.json",
    "migration-package.bin",
    "migration-bootstrap.rom.bin",
    "OpenRDX-v1-07.bin",
    "migration-template.rom.bin",
    "bootstrap-build-evidence.json",
];
const ARTIFACT_LIMITS: [usize; 6] = [65536, 384, 65535, 62110, 65535, 65536];

/// Collapses all OS errors, including private path details, into one fixed class.
fn storage_error<T>(_error: T) -> MigrationError {
    MigrationError::StorageUnavailable
}

/// Requires a directory owned by the selected user with no group/other write.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn validate_owned_directory(directory: &File, owner: u32) -> Result<(), MigrationError> {
    let status = directory.metadata().map_err(storage_error)?;
    if !status.is_dir() || status.uid() != owner || status.mode() & 0o022 != 0 {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

/// Opens and checks each existing production ancestor before descending through it.
#[cfg(target_os = "macos")]
fn secure_system_parent() -> Result<File, MigrationError> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut parent = File::from(fs::open("/", flags, Mode::empty()).map_err(storage_error)?);
    validate_owned_directory(&parent, 0)?;
    for name in ["private", "var", "db"] {
        parent =
            File::from(fs::openat(&parent, name, flags, Mode::empty()).map_err(storage_error)?);
        validate_owned_directory(&parent, 0)?;
    }
    Ok(parent)
}

/// Checks the existing fixed privileged ancestry without creating or syncing it.
#[cfg(target_os = "macos")]
pub(super) fn check_existing_fixed_root() -> Result<(), MigrationError> {
    if !existing_fixed_root_available()? {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

/// Distinguishes an absent recovery root from unsafe existing fixed ancestry.
#[cfg(target_os = "macos")]
pub(super) fn existing_fixed_root_available() -> Result<bool, MigrationError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(MigrationError::StorageUnavailable);
    }
    existing_root_under(&secure_system_parent()?, 0)
}

/// Checks only the fixed children under a safe parent, with no provisioning side effects.
#[cfg(any(target_os = "macos", test))]
pub(super) fn existing_root_under(parent: &File, owner: u32) -> Result<bool, MigrationError> {
    validate_owned_directory(parent, owner)?;
    let service = match fs::openat(
        parent,
        "OpenRDXManager",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(storage_error(error)),
    };
    validate_owned_directory(&service, owner)?;
    let recovery = match fs::openat(
        &service,
        "recovery",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(error) => return Err(storage_error(error)),
    };
    validate_directory(&recovery)?;
    Ok(true)
}

/// Creates a missing fixed child exclusively; an existing child is never chmodded.
#[cfg(any(target_os = "macos", test))]
fn ensure_child(parent: &File, name: &str, owner: u32) -> Result<File, MigrationError> {
    validate_owned_directory(parent, owner)?;
    let created = match fs::mkdirat(parent, name, PRIVATE_DIRECTORY) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(error) => return Err(storage_error(error)),
    };
    let child = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    validate_owned_directory(&child, owner)?;
    if created {
        // Only our newly created descriptor may need its umask-reduced mode fixed.
        fs::fchmod(&child, PRIVATE_DIRECTORY).map_err(storage_error)?;
    }
    child.sync_all().map_err(storage_error)?;
    parent.sync_all().map_err(storage_error)?;
    Ok(child)
}

/// Ensures only the two fixed service-owned children below a checked parent exist.
///
/// Production supplies the root-owned system database descriptor; synthetic unit
/// tests inject a private temporary descriptor. No input supplies child names.
#[cfg(any(target_os = "macos", test))]
pub(super) fn ensure_tree(parent: &File, owner: u32) -> Result<(), MigrationError> {
    let service = ensure_child(parent, "OpenRDXManager", owner)?;
    let recovery = ensure_child(&service, "recovery", owner)?;
    // Existing safe parents may be 0755, but per-unit artifacts require a 0700 root.
    if recovery.metadata().map_err(storage_error)?.mode() & 0o7777 != 0o700 {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

/// Provisions the fixed production root only under a privileged macOS service.
#[cfg(target_os = "macos")]
pub(super) fn ensure_fixed_root() -> Result<(), MigrationError> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(MigrationError::StorageUnavailable);
    }
    ensure_tree(&secure_system_parent()?, 0)?;
    // Close construction descriptors and independently recheck the complete path.
    open_directory(Path::new(super::RECOVERY_ROOT), true)?;
    Ok(())
}

/// Opens every absolute-path component separately, never following any symlink.
fn open_directory(path: &Path, private: bool) -> Result<File, MigrationError> {
    if !path.is_absolute() {
        return Err(MigrationError::StorageUnavailable);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(fs::open("/", flags, Mode::empty()).map_err(storage_error)?);
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(
                    fs::openat(&directory, name, flags, Mode::empty()).map_err(storage_error)?,
                );
            }
            _ => return Err(MigrationError::StorageUnavailable),
        }
    }
    if private {
        validate_directory(&directory)?;
    }
    Ok(directory)
}

/// Checks the descriptor's exact private mode and effective-user ownership.
fn validate_directory(directory: &File) -> Result<(), MigrationError> {
    let status = directory.metadata().map_err(storage_error)?;
    if !status.is_dir()
        || status.mode() & 0o7777 != 0o700
        || status.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

/// Opens an existing child directory relative to its already validated parent.
fn open_child(parent: &File, name: &str) -> Result<File, MigrationError> {
    let directory = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    validate_directory(&directory)?;
    Ok(directory)
}

/// Rejects missing or extra entries through the anchored directory descriptor.
fn validate_inventory(directory: &File) -> Result<(), MigrationError> {
    let mut expected: Vec<_> = ARTIFACT_NAMES
        .iter()
        .map(|name| name.as_bytes().to_vec())
        .collect();
    expected.push(b"bundle.json".to_vec());
    expected.sort();
    let mut actual = Vec::new();
    for entry in fs::Dir::read_from(directory).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        actual.push(name.to_vec());
        if actual.len() > expected.len() {
            return Err(MigrationError::StorageUnavailable);
        }
    }
    actual.sort();
    if actual != expected {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(())
}

/// Captures inode, size and timestamps to detect changes across a bounded read.
fn identity(status: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        status.dev(),
        status.ino(),
        status.len(),
        status.mtime(),
        status.mtime_nsec(),
        status.ctime(),
        status.ctime_nsec(),
    )
}

/// Rejects oversized, aliased, nonregular or insufficiently private artifacts.
fn validate_file(file: &File, maximum: usize) -> Result<Metadata, MigrationError> {
    let status = file.metadata().map_err(storage_error)?;
    if !status.is_file()
        || status.nlink() != 1
        || status.len() == 0
        || status.len() > maximum as u64
        || status.mode() & 0o7777 != 0o600
        || status.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(status)
}

/// Reads a stable bounded private file; nonblocking open rejects FIFOs without hanging.
fn read_file(parent: &File, name: &str, maximum: usize) -> Result<Vec<u8>, MigrationError> {
    let file = File::from(
        fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(storage_error)?,
    );
    read_open_file(&file, maximum)
}

/// Checks size and stable metadata before/after a maximum-plus-one bounded read.
fn read_open_file(mut file: &File, maximum: usize) -> Result<Vec<u8>, MigrationError> {
    let before = validate_file(file, maximum)?;
    file.seek(SeekFrom::Start(0)).map_err(storage_error)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(storage_error)?;
    let after = validate_file(file, maximum)?;
    if bytes.len() as u64 != before.len() || identity(&before) != identity(&after) {
        return Err(MigrationError::StorageUnavailable);
    }
    Ok(bytes)
}

/// Exclusively creates an owner-only file, writes all bytes, and syncs its contents.
fn write_file(parent: &File, name: &str, bytes: &[u8]) -> Result<(), MigrationError> {
    let mut file = File::from(
        fs::openat(
            parent,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            PRIVATE_FILE,
        )
        .map_err(storage_error)?,
    );
    fs::fchmod(&file, PRIVATE_FILE).map_err(storage_error)?;
    file.write_all(bytes).map_err(storage_error)?;
    file.sync_all().map_err(storage_error)
}

/// Closed artifact inventory, with no caller-controlled relative paths.
pub(super) struct Artifacts {
    pub(super) capture: Vec<u8>,
    pub(super) package: Vec<u8>,
    pub(super) bootstrap: Vec<u8>,
    pub(super) final_image: Vec<u8>,
    template: Vec<u8>,
    build_evidence: Vec<u8>,
}

impl Artifacts {
    /// Serializes the bounded capture and owns immutable artifacts for storage.
    pub(super) fn new(
        capture: &MigrationCapture,
        package: &[u8],
        bootstrap: &[u8],
        final_image: &[u8],
    ) -> Result<Self, MigrationError> {
        Ok(Self {
            capture: serde_json::to_vec(capture).map_err(|_| MigrationError::StorageUnavailable)?,
            package: package.to_vec(),
            bootstrap: bootstrap.to_vec(),
            final_image: final_image.to_vec(),
            template: profile::TEMPLATE.to_vec(),
            build_evidence: BUILD_EVIDENCE.to_vec(),
        })
    }

    /// Enumerates the fixed file names and bounded immutable byte slices.
    fn inventory(&self) -> [&[u8]; 6] {
        [
            &self.capture,
            &self.package,
            &self.bootstrap,
            &self.final_image,
            &self.template,
            &self.build_evidence,
        ]
    }

    /// Reads the complete fixed inventory using independent file descriptors.
    fn reopen(directory: &File) -> Result<Self, MigrationError> {
        Ok(Self {
            capture: read_file(directory, ARTIFACT_NAMES[0], ARTIFACT_LIMITS[0])?,
            package: read_file(directory, ARTIFACT_NAMES[1], ARTIFACT_LIMITS[1])?,
            bootstrap: read_file(directory, ARTIFACT_NAMES[2], ARTIFACT_LIMITS[2])?,
            final_image: read_file(directory, ARTIFACT_NAMES[3], ARTIFACT_LIMITS[3])?,
            template: read_file(directory, ARTIFACT_NAMES[4], ARTIFACT_LIMITS[4])?,
            build_evidence: read_file(directory, ARTIFACT_NAMES[5], ARTIFACT_LIMITS[5])?,
        })
    }

    /// Builds canonical integrity metadata, including explicit evidence limitations.
    fn manifest(&self) -> Result<Vec<u8>, MigrationError> {
        let files: Vec<_> = ARTIFACT_NAMES.iter().zip(self.inventory()).map(|(name, bytes)| {
            serde_json::json!({"name": name, "bytes": bytes.len(), "sha256": digest(bytes)})
        }).collect();
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion":1, "kind":"openrdx-semantic-migration-recovery-bundle",
            "complete":true, "templateSha256":profile::TEMPLATE_SHA256, "releaseVersion":"1.07",
            "rawFlashBackup":false, "firmwareContentVerified":false, "hardwareQualified":false,
            "freshSourceRequired":true, "files":files,
        }))
        .map_err(storage_error)
    }
}

/// A separately retained immutable receipt binds the fixed bundle's manifest.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema_version: u8,
    bundle: String,
    manifest_sha256: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "sourceBundle"
    )]
    source_bundle: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "sourceReceiptSha256"
    )]
    source_receipt_sha256: Option<String>,
}

/// Validates canonical receipt shape while leaving version-one bytes unchanged.
impl Receipt {
    /// Admits a plain original receipt or one flat, digest-bound recovery origin.
    fn parse(bytes: &[u8], name: &str) -> Result<Self, MigrationError> {
        let receipt: Self = serde_json::from_slice(bytes).map_err(storage_error)?;
        let version_valid = match (
            receipt.schema_version,
            &receipt.source_bundle,
            &receipt.source_receipt_sha256,
        ) {
            (1, None, None) => true,
            (2, Some(source), Some(hash)) => {
                source != name
                    && valid_bundle_id(source)
                    && hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }
            _ => false,
        };
        if !version_valid
            || !valid_bundle_id(name)
            || receipt.bundle != name
            || serde_json::to_vec(&receipt).map_err(storage_error)? != bytes
        {
            return Err(MigrationError::StorageUnavailable);
        }
        Ok(receipt)
    }
}

/// Accepts only canonical generated timestamp/counter identifiers, never paths.
fn valid_bundle_id(name: &str) -> bool {
    let Some(value) = name.strip_prefix("migration-") else {
        return false;
    };
    let Some((timestamp, counter)) = value.split_once('-') else {
        return false;
    };
    let canonical = |part: &str, maximum: usize| {
        !part.is_empty()
            && part.len() <= maximum
            && (part == "0" || !part.starts_with('0'))
            && part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    canonical(timestamp, 32) && canonical(counter, 16)
}

/// Closed append-only journal representation binds every entry to the receipt.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEntry {
    schema_version: u8,
    sequence: usize,
    event: MigrationEvent,
    receipt_sha256: String,
    previous_sha256: String,
}

/// Serializes a single bounded journal record with no caller-controlled text.
fn journal_line(
    sequence: usize,
    event: MigrationEvent,
    receipt: &[u8],
    previous: &[u8],
) -> Result<Vec<u8>, MigrationError> {
    let mut bytes = serde_json::to_vec(&JournalEntry {
        schema_version: 1,
        sequence,
        event,
        receipt_sha256: digest(receipt),
        previous_sha256: digest(previous),
    })
    .map_err(storage_error)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Retained trusted receipt/journal digests, never formatted through Debug.
pub(super) struct RecoveryStore {
    root: PathBuf,
    name: String,
    directory: PathBuf,
    receipt: Vec<u8>,
    journal: Vec<u8>,
    events: usize,
    failed: bool,
}

impl RecoveryStore {
    /// Exclusively creates an artifact set and returns independent reopened bytes.
    pub(super) fn create(
        root: &Path,
        artifacts: Artifacts,
    ) -> Result<(Self, Artifacts), MigrationError> {
        Self::create_inner(root, artifacts, None)
    }

    /// Creates either an original receipt or a new copy with a checked flat origin.
    fn create_inner(
        root: &Path,
        artifacts: Artifacts,
        source: Option<(&str, &str)>,
    ) -> Result<(Self, Artifacts), MigrationError> {
        for (bytes, maximum) in artifacts.inventory().into_iter().zip(ARTIFACT_LIMITS) {
            if bytes.is_empty() || bytes.len() > maximum {
                return Err(MigrationError::StorageUnavailable);
            }
        }
        let parent = open_directory(root, true)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(storage_error)?
            .as_nanos();
        let name = format!(
            "migration-{timestamp:x}-{:x}",
            NEXT_BUNDLE.fetch_add(1, Ordering::Relaxed)
        );
        // mkdirat is exclusive. A collision or partial prior operation is never resumed.
        fs::mkdirat(&parent, name.as_str(), PRIVATE_DIRECTORY).map_err(storage_error)?;
        let directory = File::from(
            fs::openat(
                &parent,
                name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(storage_error)?,
        );
        fs::fchmod(&directory, PRIVATE_DIRECTORY).map_err(storage_error)?;
        validate_directory(&directory)?;
        parent.sync_all().map_err(storage_error)?;
        for (name, bytes) in ARTIFACT_NAMES.iter().zip(artifacts.inventory()) {
            write_file(&directory, name, bytes)?;
        }
        directory.sync_all().map_err(storage_error)?;
        let manifest = artifacts.manifest()?;
        if manifest.len() > MAX_METADATA {
            return Err(MigrationError::StorageUnavailable);
        }
        // Completion metadata follows every synced artifact; the receipt remains outside.
        write_file(&directory, "bundle.json", &manifest)?;
        directory.sync_all().map_err(storage_error)?;
        let receipt = serde_json::to_vec(&Receipt {
            schema_version: if source.is_some() { 2 } else { 1 },
            bundle: name.clone(),
            manifest_sha256: digest(&manifest),
            source_bundle: source.map(|(name, _)| name.to_owned()),
            source_receipt_sha256: source.map(|(_, hash)| hash.to_owned()),
        })
        .map_err(storage_error)?;
        write_file(&parent, &format!("{name}.receipt.json"), &receipt)?;
        let journal = journal_line(0, MigrationEvent::Prepared, &receipt, &[])?;
        write_file(&parent, &format!("{name}.journal.jsonl"), &journal)?;
        parent.sync_all().map_err(storage_error)?;
        drop(directory);
        drop(parent);
        let store = Self {
            root: root.to_path_buf(),
            directory: root.join(&name),
            name,
            receipt,
            journal,
            events: 1,
            failed: false,
        };
        let reopened = store.reopen()?;
        Ok((store, reopened))
    }
    /// Returns the prepared private recovery directory.
    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }
    /// Appends and syncs one bounded journal event.
    pub(super) fn append(&mut self, event: MigrationEvent) -> Result<(), MigrationError> {
        if self.failed {
            return Err(MigrationError::StorageUnavailable);
        }
        // Any partial append or uncertain sync permanently taints this writer.
        self.failed = true;
        self.append_inner(event)?;
        self.failed = false;
        Ok(())
    }

    /// Reopens all files and independently verifies receipt, inventory and template.
    pub(super) fn reopen(&self) -> Result<Artifacts, MigrationError> {
        let parent = open_directory(&self.root, true)?;
        if read_file(
            &parent,
            &format!("{}.receipt.json", self.name),
            MAX_METADATA,
        )? != self.receipt
            || read_file(
                &parent,
                &format!("{}.journal.jsonl", self.name),
                MAX_JOURNAL,
            )? != self.journal
        {
            return Err(MigrationError::StorageUnavailable);
        }
        let receipt = Receipt::parse(&self.receipt, &self.name)?;
        let directory = open_child(&parent, &self.name)?;
        validate_inventory(&directory)?;
        let manifest = read_file(&directory, "bundle.json", MAX_METADATA)?;
        if digest(&manifest) != receipt.manifest_sha256 {
            return Err(MigrationError::StorageUnavailable);
        }
        let artifacts = Artifacts::reopen(&directory)?;
        if manifest != artifacts.manifest()?
            || artifacts.template != profile::TEMPLATE
            || artifacts.build_evidence != BUILD_EVIDENCE
        {
            return Err(MigrationError::StorageUnavailable);
        }
        if receipt.schema_version == 2 {
            #[cfg(any(target_os = "macos", test))]
            self.verify_origin(&receipt, &artifacts)?;
            #[cfg(not(any(target_os = "macos", test)))]
            return Err(MigrationError::StorageUnavailable);
        }
        Ok(artifacts)
    }

    /// Locks the journal, verifies its retained bytes, then appends and reopens it.
    fn append_inner(&mut self, event: MigrationEvent) -> Result<(), MigrationError> {
        if self.events >= MAX_EVENTS {
            return Err(MigrationError::StorageUnavailable);
        }
        if event == MigrationEvent::RecoveryResumed
            && (self.events != 1 || Receipt::parse(&self.receipt, &self.name)?.schema_version != 2)
        {
            return Err(MigrationError::StorageUnavailable);
        }
        // A recorded dispatch prerequisite is usable only while every immutable
        // recovery artifact still matches the independently retained receipt.
        self.reopen()?;
        let parent = open_directory(&self.root, true)?;
        if read_file(
            &parent,
            &format!("{}.receipt.json", self.name),
            MAX_METADATA,
        )? != self.receipt
        {
            return Err(MigrationError::StorageUnavailable);
        }
        let journal_name = format!("{}.journal.jsonl", self.name);
        let mut file = File::from(
            fs::openat(
                &parent,
                journal_name.as_str(),
                OFlags::RDWR
                    | OFlags::APPEND
                    | OFlags::NOFOLLOW
                    | OFlags::NONBLOCK
                    | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(storage_error)?,
        );
        fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(storage_error)?;
        if read_open_file(&file, MAX_JOURNAL)? != self.journal {
            return Err(MigrationError::StorageUnavailable);
        }
        let line = journal_line(self.events, event, &self.receipt, &self.journal)?;
        if self.journal.len() + line.len() > MAX_JOURNAL {
            return Err(MigrationError::StorageUnavailable);
        }
        file.write_all(&line).map_err(storage_error)?;
        file.sync_all().map_err(storage_error)?;
        parent.sync_all().map_err(storage_error)?;
        let mut expected = self.journal.clone();
        expected.extend_from_slice(&line);
        if read_file(&parent, &journal_name, MAX_JOURNAL)? != expected {
            return Err(MigrationError::StorageUnavailable);
        }
        self.journal = expected;
        self.events += 1;
        Ok(())
    }
}

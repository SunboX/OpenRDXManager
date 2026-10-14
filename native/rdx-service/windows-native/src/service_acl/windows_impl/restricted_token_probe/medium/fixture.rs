// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact private fixture ownership, immutable staged bytes and scoped cleanup.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

/// Owns only its atomically created private root and exact staged executable.
pub(super) enum Variant {
    Proof,
    Wait,
}
/// Owns only its atomically created private root and exact staged executable.
pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) executable: PathBuf,
    pub(super) identity: FileIdentity,
    pub(super) digest: [u8; 32],
    payload_pins: Vec<File>,
    _ancestor_pins: Vec<File>,
    cleaned: bool,
}
impl Fixture {
    /// Borrows only the retained root/image pins; observers cannot replace or close owned handles.
    pub(super) fn retained_payload(&self) -> Option<(&File, &File)> {
        if self.payload_pins.len() != 2 {
            return None;
        }
        Some((&self.payload_pins[0], &self.payload_pins[1]))
    }

    /// Copies fixed CI-compiled bytes from a pinned source into an owned protected namespace.
    pub(super) fn create(administrator: &OwnedSid, variant: Variant) -> Result<Self, NativeError> {
        let basename = match variant {
            Variant::Proof => "openrdx-token-child.exe",
            Variant::Wait => "openrdx-token-wait-child.exe",
        };
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../out/verification")
            .join(basename);
        let mut source = crate::local_trust::windows::open(&source, false)?;
        let digest = hash(&mut source)?;
        let (root, ancestor_pins) = crate::local_trust::windows::token_verifier_fixture_root()?;
        let executable = root.join("openrdx-token-child.exe");
        let mut fixture = Self {
            root,
            executable,
            identity: FileIdentity {
                volume: 0,
                index_high: 0,
                index_low: 0,
            },
            digest,
            payload_pins: Vec::new(),
            _ancestor_pins: ancestor_pins,
            cleaned: false,
        };
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&fixture.executable)
            .map_err(|_| NativeError::Other)?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| NativeError::Other)?;
        std::io::copy(&mut source, &mut writer).map_err(|_| NativeError::Other)?;
        writer.flush().map_err(|_| NativeError::Other)?;
        writer.sync_all().map_err(|_| NativeError::Other)?;
        // Writer must be closed before strict read-only immutable protection/pinning.
        drop(writer);
        let administrator = private_sid_text(administrator)?;
        crate::local_trust::windows::protect(&fixture.executable, &administrator)?;
        for path in [&fixture.root, &fixture.executable] {
            let mut pin = crate::local_trust::windows::open(path, false)?;
            crate::local_trust::validate_runtime_acl(&crate::local_trust::windows::evidence(
                &pin,
            )?)?;
            if path == &fixture.executable && hash(&mut pin)? != fixture.digest {
                return Err(NativeError::AccessDenied);
            }
            fixture.payload_pins.push(pin);
        }
        fixture.identity = file_identity(&fixture.executable)?;
        Ok(fixture)
    }

    /// Removes only the exact owned executable/root after payload and child handles close.
    pub(super) fn cleanup(&mut self) -> Result<(), NativeError> {
        self.payload_pins.clear();
        if self.executable.exists() {
            std::fs::remove_file(&self.executable).map_err(|_| NativeError::Other)?;
        }
        std::fs::remove_dir(&self.root).map_err(|_| NativeError::Other)?;
        self.cleaned = true;
        Ok(())
    }
}
impl Drop for Fixture {
    /// Best effort fallback preserves the original proof failure; no recursive/unrelated cleanup.
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

/// Hashes one bounded pinned binary, never printing bytes or digests.
pub(super) fn hash(file: &mut File) -> Result<[u8; 32], NativeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| NativeError::Other)?;
    let length = file.metadata().map_err(|_| NativeError::Other)?.len();
    if !(1..=32 * 1024 * 1024).contains(&length) {
        return Err(NativeError::ResourceLimit);
    }
    let mut hasher = Sha256::new();
    let mut total = 0;
    let mut buffer = [0_u8; 16_384];
    loop {
        let count = file.read(&mut buffer).map_err(|_| NativeError::Other)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > length {
            return Err(NativeError::Other);
        }
        hasher.update(&buffer[..count]);
    }
    if total != length {
        return Err(NativeError::Other);
    }
    Ok(hasher.finalize().into())
}

/// Converts only the actual administrator's SID for existing canonical protection, without output.
fn private_sid_text(sid: &OwnedSid) -> Result<String, NativeError> {
    let mut pointer = PWSTR::null();
    // SAFETY: owned validated SID and writable LocalAlloc output.
    unsafe { ConvertSidToStringSidW(sid.pointer(), &mut pointer) }.map_err(map_native_error)?;
    struct Allocation(PWSTR);
    impl Drop for Allocation {
        /// Closes exactly this conversion's LocalAlloc storage.
        fn drop(&mut self) {
            // SAFETY: successful conversion returns one owned LocalAlloc allocation.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
        }
    }
    let owned = Allocation(pointer);
    // SAFETY: conversion returns a live NUL-terminated Windows string.
    unsafe { owned.0.to_string() }.map_err(|_| NativeError::Other)
}

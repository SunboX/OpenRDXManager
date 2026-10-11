// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed Windows Virtual Disk Service filesystem formatter.

use std::thread;
use std::time::{Duration, Instant};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

use windows::Win32::Storage::VirtualDiskService::{
    CLSID_VdsLoader, IEnumVdsObject, IVdsPack, IVdsService, IVdsServiceLoader, IVdsSwProvider,
    IVdsVolume, IVdsVolumeMF3, VDS_E_OPERATION_PENDING, VDS_FSOF_FORCE, VDS_FSOF_QUICK,
    VDS_QUERY_SOFTWARE_PROVIDERS,
};
use windows::Win32::System::Com::{
    CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
    CoUninitialize,
};
use windows::core::{HRESULT, Interface, PCWSTR, PWSTR};

use crate::{HostFilesystem, NativeError};

use super::map_windows_error;
use crate::volume::canonical_volume_guid_path;

mod disk_safety;

/// Proves the exact GPT disk is online and has no active Windows protected role.
pub(super) fn require_inactive_mac_disk(
    number: u32,
    capacity: u64,
    id: windows::core::GUID,
) -> Result<(), NativeError> {
    let mut request = vec![2];
    request.extend_from_slice(&number.to_le_bytes());
    request.extend_from_slice(&capacity.to_le_bytes());
    request.extend_from_slice(&id.to_u128().to_le_bytes());
    run_worker(&request)
}

const MAX_VDS_OBJECTS: usize = 512;
const VDS_FORMAT_TIMEOUT: Duration = Duration::from_secs(30);
const VDS_CANCEL_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const VDS_READY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_VDS_GUID_PATHS: u32 = 16;
const MAX_VDS_GUID_PATH_UNITS: usize = 64;
const VDS_WORKER_TIMEOUT: Duration = Duration::from_secs(50);
const VDS_WORKER_MAGIC: &[u8; 8] = b"RDXVDS2\0";

struct ComApartment;

impl ComApartment {
    /// Initializes a dedicated multithreaded COM apartment for one synchronous call.
    fn initialize() -> Result<Self, NativeError> {
        // SAFETY: no reserved pointer is supplied and this call is paired with Drop.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(map_windows_error)?;
        Ok(Self)
    }
}

impl Drop for ComApartment {
    /// Balances the successful apartment initialization on the same thread.
    fn drop(&mut self) {
        // SAFETY: this guard exists only after successful CoInitializeEx.
        unsafe { CoUninitialize() };
    }
}

/// Loads VDS and proves the software-provider graph is available without mutation.
pub(super) fn preflight() -> Result<(), NativeError> {
    run_worker(&[0])
}

/// Loads VDS inside the killable helper and proves provider readiness.
fn preflight_local() -> Result<(), NativeError> {
    let _apartment = ComApartment::initialize()?;
    let service = load_service()?;
    wait_service_ready_bounded(&service)?;
    // SAFETY: querying providers is read-only and returns an owned enumerator.
    let providers = unsafe { service.QueryProviders(VDS_QUERY_SOFTWARE_PROVIDERS.0 as u32) }
        .map_err(map_windows_error)?;
    if next_object(&providers)?.is_none() {
        return Err(NativeError::EvidenceIncomplete);
    }
    Ok(())
}

/// Formats the exact VDS volume whose GUID matches the retained volume identity.
pub(super) fn format_volume(
    volume_key: &[u16],
    filesystem: HostFilesystem,
) -> Result<(), NativeError> {
    let expected = canonical_volume_key(volume_key)?;
    let units = expected.encode_utf16().collect::<Vec<_>>();
    let length = u16::try_from(units.len()).map_err(|_| NativeError::ResourceLimit)?;
    let mut request = Vec::with_capacity(4 + units.len() * 2);
    request.push(1);
    request.push(match filesystem {
        HostFilesystem::Ntfs => 0,
        HostFilesystem::ExFat => 1,
    });
    request.extend_from_slice(&length.to_le_bytes());
    for unit in units {
        request.extend_from_slice(&unit.to_le_bytes());
    }
    run_worker(&request)
}

/// Formats one exact volume inside the killable VDS helper process.
fn format_volume_local(volume_key: &[u16], filesystem: HostFilesystem) -> Result<(), NativeError> {
    let expected = canonical_volume_key(volume_key)?;
    let _apartment = ComApartment::initialize()?;
    let service = load_service()?;
    wait_service_ready_bounded(&service)?;
    // SAFETY: read-only software-provider enumeration returns owned COM objects.
    let providers = unsafe { service.QueryProviders(VDS_QUERY_SOFTWARE_PROVIDERS.0 as u32) }
        .map_err(map_windows_error)?;
    let mut inspected = 0_usize;
    while let Some(provider) = next_object(&providers)? {
        inspected = bounded_increment(inspected)?;
        let provider: IVdsSwProvider = provider.cast().map_err(map_windows_error)?;
        // SAFETY: provider remains live and returns an owned pack enumerator.
        let packs = unsafe { provider.QueryPacks() }.map_err(map_windows_error)?;
        while let Some(pack) = next_object(&packs)? {
            inspected = bounded_increment(inspected)?;
            let pack: IVdsPack = pack.cast().map_err(map_windows_error)?;
            // SAFETY: pack remains live and returns an owned volume enumerator.
            let volumes = unsafe { pack.QueryVolumes() }.map_err(map_windows_error)?;
            while let Some(volume) = next_object(&volumes)? {
                inspected = bounded_increment(inspected)?;
                let volume: IVdsVolume = volume.cast().map_err(map_windows_error)?;
                if volume_key_matches(&volume, &expected)? {
                    let formatter: IVdsVolumeMF3 = volume.cast().map_err(map_windows_error)?;
                    let filesystem_name = match filesystem {
                        HostFilesystem::Ntfs => wide_nul("NTFS"),
                        HostFilesystem::ExFat => wide_nul("exFAT"),
                    };
                    let label = wide_nul("OPENRDX");
                    // Both supported filesystems use quick format. A full NTFS
                    // surface pass on a large cartridge exceeds the bounded job
                    // lifetime and would be cancelled after filesystem dispatch.
                    let options = (VDS_FSOF_FORCE.0 | VDS_FSOF_QUICK.0) as u32;
                    // SAFETY: strings are fixed NUL-terminated values; formatter
                    // is the exact matched volume and returns an owned async job.
                    let operation = unsafe {
                        formatter.FormatEx2(
                            PCWSTR(filesystem_name.as_ptr()),
                            0,
                            0,
                            PCWSTR(label.as_ptr()),
                            options,
                        )
                    }
                    .map_err(map_windows_error)?;
                    let mut result = HRESULT(0);
                    wait_async_bounded(&operation, &mut result)?;
                    return Ok(());
                }
            }
        }
    }
    Err(NativeError::DeviceRemoved)
}

/// Runs one VDS request in a fresh copy of the exact current service executable.
fn run_worker(request: &[u8]) -> Result<(), NativeError> {
    let executable = std::env::current_exe().map_err(|_| NativeError::EvidenceIncomplete)?;
    let mut child = Command::new(executable)
        .arg("--openrdx-internal-vds-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| NativeError::Other)?;
    let Some(mut input) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(NativeError::Other);
    };
    if input.write_all(VDS_WORKER_MAGIC).is_err() || input.write_all(request).is_err() {
        drop(input);
        let _ = child.kill();
        let _ = child.wait();
        return Err(NativeError::Other);
    }
    drop(input);
    let deadline = Instant::now() + VDS_WORKER_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return decode_worker_exit(status.code()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NativeError::TimedOut);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NativeError::Other);
            }
        }
    }
}

/// Executes one bounded private worker request received only on inherited stdin.
pub(super) fn run_internal_worker() -> u8 {
    let mut input = std::io::stdin().lock();
    let mut magic = [0_u8; 8];
    if input.read_exact(&mut magic).is_err() || &magic != VDS_WORKER_MAGIC {
        return encode_worker_error(NativeError::InvalidRequest);
    }
    let mut operation = [0_u8; 1];
    if input.read_exact(&mut operation).is_err() {
        return encode_worker_error(NativeError::InvalidRequest);
    }
    let result = match operation[0] {
        0 => {
            let mut trailing = [0_u8; 1];
            if input.read(&mut trailing).ok() != Some(0) {
                return encode_worker_error(NativeError::InvalidRequest);
            }
            preflight_local()
        }
        1 => {
            let mut header = [0_u8; 3];
            if input.read_exact(&mut header).is_err() {
                return encode_worker_error(NativeError::InvalidRequest);
            }
            let filesystem = match header[0] {
                0 => HostFilesystem::Ntfs,
                1 => HostFilesystem::ExFat,
                _ => return encode_worker_error(NativeError::InvalidRequest),
            };
            let length = usize::from(u16::from_le_bytes([header[1], header[2]]));
            if !(1..=1_024).contains(&length) {
                return encode_worker_error(NativeError::InvalidRequest);
            }
            let mut bytes = vec![0_u8; length * 2];
            if input.read_exact(&mut bytes).is_err() {
                return encode_worker_error(NativeError::InvalidRequest);
            }
            let mut trailing = [0_u8; 1];
            if input.read(&mut trailing).ok() != Some(0) {
                return encode_worker_error(NativeError::InvalidRequest);
            }
            let mut key = bytes
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            key.push(0);
            format_volume_local(&key, filesystem)
        }
        2 => {
            let mut bytes = [0_u8; 28];
            let mut trailing = [0_u8; 1];
            if input.read_exact(&mut bytes).is_err() || input.read(&mut trailing).ok() != Some(0) {
                return encode_worker_error(NativeError::InvalidRequest);
            }
            let number = u32::from_le_bytes(bytes[..4].try_into().expect("fixed disk number"));
            let capacity = u64::from_le_bytes(bytes[4..12].try_into().expect("fixed capacity"));
            let id = windows::core::GUID::from_u128(u128::from_le_bytes(
                bytes[12..].try_into().expect("fixed GUID"),
            ));
            disk_safety::require_inactive_disk(number, capacity, id)
        }
        _ => return encode_worker_error(NativeError::InvalidRequest),
    };
    result.map_or_else(encode_worker_error, |()| 0)
}

/// Encodes one sanitized helper failure as a stable nonzero process code.
const fn encode_worker_error(error: NativeError) -> u8 {
    match error {
        NativeError::InvalidRequest => 2,
        NativeError::AccessDenied => 3,
        NativeError::Busy => 4,
        NativeError::ReadOnly => 5,
        NativeError::Cancelled => 6,
        NativeError::TimedOut => 7,
        NativeError::DeviceRemoved => 8,
        NativeError::NoMedia => 9,
        NativeError::EnumerationFailed => 10,
        NativeError::EvidenceIncomplete => 11,
        NativeError::ResourceLimit => 12,
        NativeError::UnsupportedPlatform | NativeError::Other => 13,
    }
}

/// Decodes a fully reaped helper process result.
fn decode_worker_exit(code: Option<i32>) -> Result<(), NativeError> {
    match code {
        Some(0) => Ok(()),
        Some(2) => Err(NativeError::InvalidRequest),
        Some(3) => Err(NativeError::AccessDenied),
        Some(4) => Err(NativeError::Busy),
        Some(5) => Err(NativeError::ReadOnly),
        Some(6) => Err(NativeError::Cancelled),
        Some(7) => Err(NativeError::TimedOut),
        Some(8) => Err(NativeError::DeviceRemoved),
        Some(9) => Err(NativeError::NoMedia),
        Some(10) => Err(NativeError::EnumerationFailed),
        Some(11) => Err(NativeError::EvidenceIncomplete),
        Some(12) => Err(NativeError::ResourceLimit),
        Some(13) | Some(_) | None => Err(NativeError::Other),
    }
}

/// Polls one VDS async operation under an absolute deadline and drains cancellation.
fn wait_async_bounded(
    operation: &windows::Win32::Storage::VirtualDiskService::IVdsAsync,
    result: &mut HRESULT,
) -> Result<(), NativeError> {
    let deadline = Instant::now() + VDS_FORMAT_TIMEOUT;
    loop {
        if !query_async_pending(operation, result)? {
            return result.ok().map_err(map_windows_error);
        }
        if Instant::now() >= deadline {
            // SAFETY: cancellation targets this owned exact async operation only.
            let _ = unsafe { operation.Cancel() };
            let drain_deadline = Instant::now() + VDS_CANCEL_DRAIN_TIMEOUT;
            while Instant::now() < drain_deadline {
                if matches!(query_async_pending(operation, result), Ok(false)) {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
            return Err(NativeError::TimedOut);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Polls once, accepting pending from either QueryStatus HRESULT channel.
fn query_async_pending(
    operation: &windows::Win32::Storage::VirtualDiskService::IVdsAsync,
    result: &mut HRESULT,
) -> Result<bool, NativeError> {
    let mut percent = 0_u32;
    *result = VDS_E_OPERATION_PENDING;
    // SAFETY: the owned async interface is live and both outputs are writable.
    let query = unsafe { operation.QueryStatus(result, &mut percent) }
        .map_err(|error| error.code().0 as u32);
    crate::vds_status::query_is_pending(query, result.0 as u32)
        .map_err(|code| map_windows_error(HRESULT(code as i32).into()))
}

/// Creates and readies one local VDS service interface.
fn load_service() -> Result<IVdsService, NativeError> {
    // SAFETY: CLSID is fixed, aggregation is disabled, and the requested interface is typed.
    let loader: IVdsServiceLoader =
        unsafe { CoCreateInstance(&CLSID_VdsLoader, None, CLSCTX_LOCAL_SERVER) }
            .map_err(map_windows_error)?;
    // SAFETY: null machine name selects the local host and returns an owned service.
    unsafe { loader.LoadService(PCWSTR::null()) }.map_err(map_windows_error)
}

/// Fetches at most one owned COM object from a bounded VDS enumerator.
fn next_object(
    enumerator: &IEnumVdsObject,
) -> Result<Option<windows::core::IUnknown>, NativeError> {
    let mut objects = [None];
    let mut fetched = 0_u32;
    // SAFETY: one-slot output and fetched counter are valid writable storage.
    unsafe { enumerator.Next(&mut objects, &mut fetched) }.map_err(map_windows_error)?;
    match fetched {
        0 => Ok(None),
        1 => objects[0]
            .take()
            .ok_or(NativeError::EvidenceIncomplete)
            .map(Some),
        _ => Err(NativeError::EvidenceIncomplete),
    }
}

/// Compares a VDS volume GUID with the already-retained Win32 volume GUID path.
fn volume_key_matches(volume: &IVdsVolume, expected: &str) -> Result<bool, NativeError> {
    let formatter: IVdsVolumeMF3 = volume.cast().map_err(map_windows_error)?;
    let mut path_array: *mut PWSTR = std::ptr::null_mut();
    let mut path_count = 0_u32;
    // SAFETY: outputs are exact writable storage and the live interface owns
    // the authoritative GUID pathname query. The returned allocation is guarded below.
    unsafe { formatter.QueryVolumeGuidPathnames(&mut path_array, &mut path_count) }
        .map_err(map_windows_error)?;
    let allocation = TaskMemStringArray::new(path_array);
    if allocation.base.is_null() || path_count == 0 || path_count > MAX_VDS_GUID_PATHS {
        return Err(NativeError::EvidenceIncomplete);
    }
    let paths = unsafe { copy_vds_guid_paths(allocation.base, path_count)? };
    Ok(paths
        .iter()
        .filter(|path| path.as_str() == expected)
        .count()
        == 1)
}

/// Canonicalizes one bounded NUL-terminated retained volume GUID key.
fn canonical_volume_key(key: &[u16]) -> Result<String, NativeError> {
    if key.len() < 2 || key.last() != Some(&0) {
        return Err(NativeError::EvidenceIncomplete);
    }
    canonical_volume_guid_path(&key[..key.len() - 1]).map_err(|_| NativeError::EvidenceIncomplete)
}

/// Owns the COM task-memory string array returned by VDS.
struct TaskMemStringArray {
    base: *mut PWSTR,
}

impl TaskMemStringArray {
    /// Captures the one VDS-owned pathname allocation for exactly-once release.
    const fn new(base: *mut PWSTR) -> Self {
        Self { base }
    }
}

impl Drop for TaskMemStringArray {
    fn drop(&mut self) {
        if self.base.is_null() {
            return;
        }
        // SAFETY: QueryVolumeGuidPathnames transfers one CoTaskMem allocation;
        // the pointed-to strings are part of that returned allocation and must
        // not be released individually.
        unsafe { CoTaskMemFree(Some(self.base.cast())) };
    }
}

/// Validates and canonicalizes the counted VDS GUID path pointer array.
/// Windows may repeat a valid alias for the same COM volume (observed on a
/// system volume). Repetition is not ambiguous membership: collapse aliases
/// only after validating every entry, preserving exact GUID matching.
unsafe fn copy_vds_guid_paths(
    path_array: *mut PWSTR,
    path_count: u32,
) -> Result<Vec<String>, NativeError> {
    let mut paths = Vec::with_capacity(path_count as usize);
    for index in 0..path_count as usize {
        // SAFETY: the successful VDS call promised `path_count` pointer slots.
        let path = unsafe { *path_array.add(index) };
        if path.is_null() {
            return Err(NativeError::EvidenceIncomplete);
        }
        let cursor = path.as_ptr();
        let mut length = 0_usize;
        while length <= MAX_VDS_GUID_PATH_UNITS {
            // SAFETY: VDS promises each counted element is NUL-terminated; the
            // per-string bound prevents an unbounded native read.
            if unsafe { *cursor.add(length) } == 0 {
                break;
            }
            length += 1;
        }
        if length == 0 || length > MAX_VDS_GUID_PATH_UNITS {
            return Err(NativeError::EvidenceIncomplete);
        }
        // SAFETY: the bounded terminator above proves this initialized slice.
        let path = unsafe { std::slice::from_raw_parts(cursor, length) };
        paths.push(canonical_volume_guid_path(path).map_err(|_| NativeError::EvidenceIncomplete)?);
    }
    paths.sort_unstable();
    paths.dedup();
    Ok(paths)
}

/// Polls the documented nonblocking readiness API under one absolute deadline.
fn wait_service_ready_bounded(service: &IVdsService) -> Result<(), NativeError> {
    let deadline = Instant::now() + VDS_READY_TIMEOUT;
    loop {
        // SAFETY: IsServiceReady is the VDS nonblocking readiness probe. Calling
        // its vtable directly preserves S_FALSE, which the generated Result API erases.
        let status =
            unsafe { (Interface::vtable(service).IsServiceReady)(Interface::as_raw(service)) };
        if status == windows::Win32::Foundation::S_OK {
            return Ok(());
        }
        if status != windows::Win32::Foundation::S_FALSE {
            return Err(map_windows_error(status.into()));
        }
        if Instant::now() >= deadline {
            return Err(NativeError::TimedOut);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Advances the global traversal bound.
fn bounded_increment(value: usize) -> Result<usize, NativeError> {
    let next = value.checked_add(1).ok_or(NativeError::ResourceLimit)?;
    if next > MAX_VDS_OBJECTS {
        Err(NativeError::ResourceLimit)
    } else {
        Ok(next)
    }
}

/// Encodes one fixed ASCII VDS string with a terminating UTF-16 NUL.
fn wide_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

#[cfg(test)]
mod tests;

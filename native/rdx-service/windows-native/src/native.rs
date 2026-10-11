// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audited Windows-only SetupAPI, SPTI, volume, service, and token calls.

use std::collections::BTreeSet;
use std::ffi::{OsStr, c_void};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::ptr::NonNull;
use std::thread;
use std::time::Duration;

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SP_DEVICE_INTERFACE_DATA,
    SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW,
    SetupDiGetDeviceInterfaceDetailW,
};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BUSY, ERROR_BUSY_DRIVE, ERROR_DEV_NOT_EXIST,
    ERROR_DEVICE_NOT_AVAILABLE, ERROR_DEVICE_NOT_CONNECTED, ERROR_DEVICE_REMOVED,
    ERROR_FILE_NOT_FOUND, ERROR_GEN_FAILURE, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE,
    ERROR_LOCK_VIOLATION, ERROR_MORE_DATA, ERROR_NO_MEDIA_IN_DRIVE, ERROR_NO_MORE_ITEMS,
    ERROR_NO_SUCH_DEVICE, ERROR_NOT_READY, ERROR_OPERATION_ABORTED, ERROR_PATH_NOT_FOUND,
    ERROR_RETRY, ERROR_SEM_TIMEOUT, ERROR_SHARING_VIOLATION, ERROR_TIMEOUT, ERROR_WRITE_PROTECT,
    GENERIC_READ, GENERIC_WRITE, HANDLE, WIN32_ERROR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    PARTITION_BASIC_DATA_GUID,
};
use windows::Win32::Storage::IscsiDisc::{
    IOCTL_SCSI_PASS_THROUGH, IOCTL_SCSI_PASS_THROUGH_DIRECT, SCSI_IOCTL_DATA_IN,
    SCSI_IOCTL_DATA_OUT, SCSI_IOCTL_DATA_UNSPECIFIED, SCSI_PASS_THROUGH, SCSI_PASS_THROUGH_DIRECT,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    CREATE_DISK, CREATE_DISK_0, CREATE_DISK_GPT, CREATE_DISK_MBR, DISK_GEOMETRY_EX,
    DRIVE_LAYOUT_INFORMATION_EX, DRIVE_LAYOUT_INFORMATION_EX_0, DRIVE_LAYOUT_INFORMATION_GPT,
    DRIVE_LAYOUT_INFORMATION_MBR, GPT_ATTRIBUTE_LEGACY_BIOS_BOOTABLE,
    GPT_ATTRIBUTE_PLATFORM_REQUIRED, GPT_ATTRIBUTES, GUID_DEVINTERFACE_DISK,
    IOCTL_DISK_CREATE_DISK, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
    IOCTL_DISK_IS_WRITABLE, IOCTL_DISK_SET_DRIVE_LAYOUT_EX, IOCTL_DISK_UPDATE_PROPERTIES,
    IOCTL_STORAGE_CHECK_VERIFY2, IOCTL_STORAGE_EJECT_MEDIA, IOCTL_STORAGE_GET_DEVICE_NUMBER,
    IOCTL_STORAGE_QUERY_PROPERTY, PARTITION_IFS, PARTITION_INFORMATION_EX,
    PARTITION_INFORMATION_EX_0, PARTITION_INFORMATION_GPT, PARTITION_INFORMATION_MBR,
    PARTITION_MSFT_RECOVERY, PARTITION_STYLE_GPT, PARTITION_STYLE_MBR, PARTITION_STYLE_RAW,
    PARTITION_SYSTEM, PARTITION_WINDOWS_SYSTEM, PropertyStandardQuery, STORAGE_DEVICE_NUMBER,
    STORAGE_PROPERTY_QUERY, StorageAdapterProperty,
};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};
use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;
use windows::core::{Error, PCWSTR};

use super::{
    AdapterConstraints, Completion, DataDirection, DecodedRecipe, DeviceIdentityProof,
    DiskCandidate, DiskLayoutStyle, FileTestOutcome, HostFilesystem, HostOperationOutcome,
    NativeError, Readiness, ResourceCloser, ResourceGuard, ScsiRequest, StorageDeviceIdentity,
    VolumeInventory, VolumeMutationOutcome, aligned_transfer_layout, bounded_returned_length,
    decode_recipe, parse_adapter_descriptor, partition_style_for_capacity,
};

const MAX_CANDIDATES: usize = 128;
const MAX_INSTANCE_ID_UNITS: usize = 201;
const MAX_DETAIL_BYTES: usize = 65_536;
const MAX_ADAPTER_DESCRIPTOR_BYTES: usize = 4_096;
const MAX_DISK_PARTITIONS: usize = 128;
/// Official Windows GPT type for an ordinary data partition.
const MICROSOFT_BASIC_DATA: windows::core::GUID = PARTITION_BASIC_DATA_GUID;

mod format;
mod layout;
mod mac_layout;
mod mutations;
mod readiness;
mod safe_eject;
mod vds;
mod volume_label;
mod volumes;

/// Runs the fixed private VDS helper protocol on inherited standard input.
pub(crate) fn run_internal_vds_worker() -> u8 {
    vds::run_internal_worker()
}

pub(super) use volumes::NativeVolumeLease;

struct KernelHandleCloser;

impl ResourceCloser<isize> for KernelHandleCloser {
    /// Closes one kernel handle recovered from its private scalar storage.
    fn close(resource: isize) {
        // SAFETY: ResourceGuard owns this non-invalid handle exactly once and
        // no call uses it after Drop begins.
        let _ = unsafe { CloseHandle(HANDLE(resource as *mut c_void)) };
    }
}

struct DeviceInfoCloser;

impl ResourceCloser<isize> for DeviceInfoCloser {
    /// Releases one SetupAPI information set exactly once.
    fn close(resource: isize) {
        // SAFETY: ResourceGuard owns the HDEVINFO returned by SetupDiGetClassDevsW.
        let _ = unsafe { SetupDiDestroyDeviceInfoList(HDEVINFO(resource)) };
    }
}

type KernelHandle = ResourceGuard<isize, KernelHandleCloser>;
type DeviceInfoSet = ResourceGuard<isize, DeviceInfoCloser>;

/// Exact opened physical disk retained by the parent lease.
pub(super) struct NativeDevice {
    handle: KernelHandle,
    identity: DeviceIdentityProof,
    constraints: AdapterConstraints,
    pending_format: std::sync::Mutex<Option<format::CreatedLayout>>,
}

impl NativeDevice {
    /// Revalidates the private instance/disk recipe before and after exact open.
    pub(super) fn open(recipe: &OsStr) -> Result<Self, NativeError> {
        let recipe = decode_recipe(recipe)?;
        require_present_recipe(&recipe)?;
        let physical_path = wide_null(OsStr::new(&format!(
            r"\\.\PhysicalDrive{}",
            recipe.disk_number
        )));
        let handle = open_path(&physical_path, GENERIC_READ.0 | GENERIC_WRITE.0)?;
        let device_number = storage_device_number(kernel_handle(&handle))?;
        let identity = DeviceIdentityProof::new(recipe, device_number)?;
        let constraints = adapter_constraints(kernel_handle(&handle))?;
        revalidate_present_identity(&identity, &handle)?;
        Ok(Self {
            handle,
            identity,
            constraints,
            pending_format: std::sync::Mutex::new(None),
        })
    }

    /// Executes only direct data transfer or buffered no-data SPTI requests.
    pub(super) fn execute(&mut self, request: ScsiRequest) -> Completion {
        match request.direction {
            DataDirection::None => execute_buffered(kernel_handle(&self.handle), request),
            DataDirection::FromDevice | DataDirection::ToDevice => {
                execute_direct(kernel_handle(&self.handle), request, self.constraints)
            }
        }
    }

    /// Pins volumes between exact pre/post instance and handle revalidation.
    pub(super) fn pin_volumes(
        &self,
    ) -> Result<(Vec<char>, usize, VolumeInventory, Vec<NativeVolumeLease>), NativeError> {
        let retained_disk_number = revalidate_present_identity(&self.identity, &self.handle)?;
        let scanned = volumes::pin_disk_volumes(retained_disk_number)?;
        self.revalidate_volume_leases(&scanned.leases)?;
        Ok((
            scanned.drive_letters,
            scanned.mount_path_count,
            scanned.inventory,
            scanned.leases,
        ))
    }

    /// Revalidates the exact parent instance around every retained volume snapshot.
    pub(super) fn revalidate_volume_leases(
        &self,
        leases: &[NativeVolumeLease],
    ) -> Result<(), NativeError> {
        revalidate_present_identity(&self.identity, &self.handle)?;
        for lease in leases {
            lease.revalidate()?;
        }
        revalidate_present_identity(&self.identity, &self.handle)?;
        Ok(())
    }

    /// Consumes a closed safe-dismount operation behind complete fresh validation.
    pub(super) fn dismount_for_safe_eject(
        &self,
        leases: &[NativeVolumeLease],
        inventory: &VolumeInventory,
    ) -> VolumeMutationOutcome {
        mutations::dismount_for_safe_eject(self, leases, inventory)
    }

    /// Revalidates this exact instance and invokes the physical storage eject IOCTL once.
    pub(super) fn eject_media(&self) -> VolumeMutationOutcome {
        if let Err(error) = revalidate_present_identity(&self.identity, &self.handle) {
            return VolumeMutationOutcome::NotAttempted(error);
        }
        let mut returned = 0_u32;
        // SAFETY: the retained exact disk handle is live; this no-buffer IOCTL is
        // synchronous and `returned` is valid writable output storage.
        match unsafe {
            DeviceIoControl(
                kernel_handle(&self.handle),
                IOCTL_STORAGE_EJECT_MEDIA,
                None,
                0,
                None,
                0,
                Some(&mut returned),
                None,
            )
        } {
            Ok(()) if returned == 0 => VolumeMutationOutcome::Succeeded,
            Ok(()) => VolumeMutationOutcome::CompletionUnknown(NativeError::Other),
            Err(error) => VolumeMutationOutcome::CompletionUnknown(map_windows_error(error)),
        }
    }

    /// Revalidates SetupAPI instance and the same physical handle without mutation.
    pub(super) fn revalidate_exact(&self) -> Result<(), NativeError> {
        revalidate_present_identity(&self.identity, &self.handle).map(|_| ())
    }

    /// Returns the exact kernel media-change generation under retained disk authority.
    pub(super) fn media_identity_material(&self) -> Result<Vec<u8>, NativeError> {
        self.revalidate_exact()?;
        let mut generation = 0_u32;
        let mut returned = 0_u32;
        // SAFETY: the retained exact disk handle is live and generation is exact
        // writable storage for the synchronous media-verification IOCTL.
        unsafe {
            DeviceIoControl(
                kernel_handle(&self.handle),
                IOCTL_STORAGE_CHECK_VERIFY2,
                None,
                0,
                Some((&raw mut generation).cast()),
                size_of::<u32>() as u32,
                Some(&mut returned),
                None,
            )
        }
        .map_err(map_windows_error)?;
        if returned as usize != size_of::<u32>() {
            return Err(NativeError::EvidenceIncomplete);
        }
        self.revalidate_exact()?;
        let storage = storage_device_identity(kernel_handle(&self.handle))?;
        let mut material = Vec::with_capacity(16);
        material.extend_from_slice(&generation.to_be_bytes());
        material.extend_from_slice(&storage.device_type.to_be_bytes());
        material.extend_from_slice(&storage.device_number.to_be_bytes());
        material.extend_from_slice(&storage.partition_number.to_be_bytes());
        Ok(material)
    }
}

/// Probes adapter metadata and current-process authority independently.
pub(super) fn probe_readiness() -> Readiness {
    let adapter_available = open_device_info_set().is_ok();
    readiness::probe_readiness(adapter_available)
}

/// Enumerates present disk interfaces and discards every symbolic path after use.
pub(super) fn enumerate_disk_candidates() -> Result<Vec<DiskCandidate>, NativeError> {
    let set = open_device_info_set()?;
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    let mut index = 0_u32;
    loop {
        let mut interface = SP_DEVICE_INTERFACE_DATA {
            cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: set and interface are valid for this synchronous SetupAPI call.
        let result = unsafe {
            SetupDiEnumDeviceInterfaces(
                device_info_handle(&set),
                None,
                &GUID_DEVINTERFACE_DISK,
                index,
                &mut interface,
            )
        };
        if let Err(error) = result {
            if win32_error_code(&error) == Some(ERROR_NO_MORE_ITEMS) {
                break;
            }
            return Err(map_windows_error(error));
        }
        index = index.checked_add(1).ok_or(NativeError::ResourceLimit)?;

        match disk_candidate_from_interface(&set, &interface) {
            Ok(candidate) => {
                let key = (
                    candidate.disk_number,
                    candidate.instance_id.to_ascii_uppercase(),
                );
                if seen.insert(key) {
                    candidates.push(candidate);
                    if candidates.len() > MAX_CANDIDATES {
                        return Err(NativeError::ResourceLimit);
                    }
                }
            }
            Err(NativeError::AccessDenied | NativeError::Busy | NativeError::DeviceRemoved) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(candidates)
}

/// Opens one present disk-interface information set.
fn open_device_info_set() -> Result<DeviceInfoSet, NativeError> {
    // SAFETY: GUID and flags are valid, and no HWND or enumerator pointer is supplied.
    let set = unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_DISK),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    }
    .map_err(map_windows_error)?;
    Ok(DeviceInfoSet::new(set.0))
}

/// Resolves one interface to disk number plus exact Plug and Play instance ID.
fn disk_candidate_from_interface(
    set: &DeviceInfoSet,
    interface: &SP_DEVICE_INTERFACE_DATA,
) -> Result<DiskCandidate, NativeError> {
    let (path, dev_info) = interface_detail(set, interface)?;
    let instance_id = device_instance_id(set, &dev_info)?;
    let interface_handle = open_path(&path, 0)?;
    let disk_number = storage_device_number(kernel_handle(&interface_handle))?;
    Ok(DiskCandidate::new(disk_number, instance_id))
}

/// Performs the documented two-call variable-size interface-detail query.
fn interface_detail(
    set: &DeviceInfoSet,
    interface: &SP_DEVICE_INTERFACE_DATA,
) -> Result<(Vec<u16>, SP_DEVINFO_DATA), NativeError> {
    let mut required = 0_u32;
    let mut dev_info = SP_DEVINFO_DATA {
        cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    };
    // SAFETY: the first documented query supplies no detail buffer and receives size.
    let first = unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            device_info_handle(set),
            interface,
            None,
            0,
            Some(&mut required),
            Some(&mut dev_info),
        )
    };
    match first {
        Err(error) if win32_error_code(&error) == Some(ERROR_INSUFFICIENT_BUFFER) => {}
        Err(error) => return Err(map_windows_error(error)),
        Ok(()) => return Err(NativeError::EnumerationFailed),
    }
    let required = required as usize;
    let path_offset = offset_of!(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath);
    if required < path_offset + size_of::<u16>() || required > MAX_DETAIL_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    let words = required.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let detail = storage
        .as_mut_ptr()
        .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
    // SAFETY: usize storage provides sufficient alignment and size for the fixed header.
    unsafe {
        (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
    }
    // SAFETY: detail points to required writable bytes and dev_info is initialized.
    let mut returned_required = required as u32;
    unsafe {
        SetupDiGetDeviceInterfaceDetailW(
            device_info_handle(set),
            interface,
            Some(detail),
            required as u32,
            Some(&mut returned_required),
            Some(&mut dev_info),
        )
    }
    .map_err(map_windows_error)?;
    let returned_required = returned_required as usize;
    if returned_required < path_offset + size_of::<u16>() || returned_required > required {
        return Err(NativeError::EnumerationFailed);
    }

    let unit_capacity = (returned_required - path_offset) / size_of::<u16>();
    // SAFETY: path_offset is u16-aligned within the validated allocation and the
    // slice is bounded by required bytes returned by SetupAPI.
    let units = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>().add(path_offset).cast::<u16>(),
            unit_capacity,
        )
    };
    let terminator = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(NativeError::EnumerationFailed)?;
    let mut path = units[..terminator].to_vec();
    if path.is_empty() {
        return Err(NativeError::EnumerationFailed);
    }
    path.push(0);
    Ok((path, dev_info))
}

/// Performs the documented bounded two-call device-instance query.
fn device_instance_id(
    set: &DeviceInfoSet,
    dev_info: &SP_DEVINFO_DATA,
) -> Result<String, NativeError> {
    let mut required = 0_u32;
    // SAFETY: first call supplies no output buffer and receives required UTF-16 units.
    let first = unsafe {
        SetupDiGetDeviceInstanceIdW(device_info_handle(set), dev_info, None, Some(&mut required))
    };
    match first {
        Err(error) if win32_error_code(&error) == Some(ERROR_INSUFFICIENT_BUFFER) => {}
        Err(error) => return Err(map_windows_error(error)),
        Ok(()) => return Err(NativeError::EnumerationFailed),
    }
    let required = required as usize;
    if !(2..=MAX_INSTANCE_ID_UNITS).contains(&required) {
        return Err(NativeError::ResourceLimit);
    }
    let mut buffer = vec![0_u16; required];
    // SAFETY: buffer contains the required number of writable UTF-16 units.
    let mut returned_required = required as u32;
    unsafe {
        SetupDiGetDeviceInstanceIdW(
            device_info_handle(set),
            dev_info,
            Some(&mut buffer),
            Some(&mut returned_required),
        )
    }
    .map_err(map_windows_error)?;
    let returned_required = returned_required as usize;
    if returned_required == 0 || returned_required > required {
        return Err(NativeError::EnumerationFailed);
    }
    let terminator = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(NativeError::EnumerationFailed)?;
    if terminator == 0 || terminator + 1 > returned_required {
        return Err(NativeError::EnumerationFailed);
    }
    String::from_utf16(&buffer[..terminator]).map_err(|_| NativeError::EnumerationFailed)
}

/// Ensures the recipe's exact instance/disk pair is present before any open.
fn require_present_recipe(recipe: &DecodedRecipe) -> Result<(), NativeError> {
    let candidate = present_instance(recipe.instance_id.as_str())?;
    if candidate.disk_number != recipe.disk_number {
        return Err(NativeError::DeviceRemoved);
    }
    Ok(())
}

/// Revalidates SetupAPI identity together with the retained physical handle.
fn revalidate_present_identity(
    identity: &DeviceIdentityProof,
    handle: &KernelHandle,
) -> Result<u32, NativeError> {
    let candidate = present_instance(identity.instance_id())?;
    let retained_disk_number = storage_device_number(kernel_handle(handle))?;
    identity.revalidate(
        &candidate.instance_id,
        candidate.disk_number,
        retained_disk_number,
    )?;
    Ok(retained_disk_number)
}

/// Resolves exactly one present interface for the retained Plug and Play instance.
fn present_instance(instance_id: &str) -> Result<DiskCandidate, NativeError> {
    let mut matches = enumerate_disk_candidates()?
        .into_iter()
        .filter(|candidate| instance_ids_match(&candidate.instance_id, instance_id));
    let candidate = matches.next().ok_or(NativeError::DeviceRemoved)?;
    if matches.next().is_some() {
        return Err(NativeError::DeviceRemoved);
    }
    Ok(candidate)
}

/// Applies Windows' case-insensitive ASCII instance-ID comparison conservatively.
fn instance_ids_match(left: &str, right: &str) -> bool {
    left == right || left.eq_ignore_ascii_case(right)
}

/// Opens a native path with mandatory sharing and exact requested access.
fn open_path(path: &[u16], desired_access: u32) -> Result<KernelHandle, NativeError> {
    if path.last() != Some(&0) {
        return Err(NativeError::InvalidRequest);
    }
    // SAFETY: path is NUL-terminated for this call; the result is immediately owned.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(map_windows_error)?;
    Ok(KernelHandle::new(handle.0 as isize))
}

/// Queries the physical disk number associated with one open disk-like handle.
fn storage_device_number(handle: HANDLE) -> Result<u32, NativeError> {
    storage_device_identity(handle).map(|identity| identity.device_number)
}

/// Queries the complete storage identity associated with one open handle.
fn storage_device_identity(handle: HANDLE) -> Result<StorageDeviceIdentity, NativeError> {
    let mut output = STORAGE_DEVICE_NUMBER::default();
    let mut returned = 0_u32;
    // SAFETY: output is a valid initialized integer-only structure and points to
    // exactly its writable size for this synchronous storage query.
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            None,
            0,
            Some((&raw mut output).cast()),
            size_of::<STORAGE_DEVICE_NUMBER>() as u32,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error)?;
    if (returned as usize) < size_of::<STORAGE_DEVICE_NUMBER>() {
        return Err(NativeError::Other);
    }
    Ok(StorageDeviceIdentity {
        device_type: output.DeviceType,
        device_number: output.DeviceNumber,
        partition_number: output.PartitionNumber,
    })
}

/// Queries and validates the exact adapter transfer and alignment constraints.
fn adapter_constraints(handle: HANDLE) -> Result<AdapterConstraints, NativeError> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageAdapterProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    let mut header = [0_u8; 8];
    let returned = query_storage_property(handle, &query, &mut header)?;
    bounded_returned_length(returned, header.len(), header.len())?;
    let descriptor_size = u32::from_le_bytes(
        header[4..8]
            .try_into()
            .expect("fixed descriptor size field is present"),
    ) as usize;
    if !(20..=MAX_ADAPTER_DESCRIPTOR_BYTES).contains(&descriptor_size) {
        return Err(NativeError::ResourceLimit);
    }

    let mut descriptor = vec![0_u8; descriptor_size];
    let returned = query_storage_property(handle, &query, &mut descriptor)?;
    let returned = bounded_returned_length(returned, descriptor.len(), 20)?;
    parse_adapter_descriptor(&descriptor[..returned])
}

/// Issues the fixed read-only storage adapter property query.
fn query_storage_property(
    handle: HANDLE,
    query: &STORAGE_PROPERTY_QUERY,
    output: &mut [u8],
) -> Result<u32, NativeError> {
    let output_length = u32::try_from(output.len()).map_err(|_| NativeError::ResourceLimit)?;
    let mut returned = 0_u32;
    // SAFETY: query is an initialized integer-only structure; output is live and
    // writable for output_length bytes during this synchronous property query.
    unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some((query as *const STORAGE_PROPERTY_QUERY).cast()),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(output.as_mut_ptr().cast()),
            output_length,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error)?;
    Ok(returned)
}

#[repr(C)]
struct DirectControl {
    header: SCSI_PASS_THROUGH_DIRECT,
    sense: [u8; super::MAX_SENSE_LENGTH],
}

#[repr(C)]
struct BufferedControl {
    header: SCSI_PASS_THROUGH,
    sense: [u8; super::MAX_SENSE_LENGTH],
}

struct AlignedBuffer {
    allocation: NonNull<c_void>,
    data: NonNull<c_void>,
    length: usize,
}

impl AlignedBuffer {
    /// Allocates page-aligned, zeroed storage suitable for direct device access.
    fn new(length: usize, constraints: AdapterConstraints) -> Result<Self, NativeError> {
        let initial_layout = aligned_transfer_layout(0, length, constraints)?;
        // SAFETY: arguments request a private page-aligned read/write allocation.
        let allocation = unsafe {
            VirtualAlloc(
                None,
                initial_layout.allocation_length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        let allocation = NonNull::new(allocation).ok_or(NativeError::Other)?;
        let layout =
            match aligned_transfer_layout(allocation.as_ptr() as usize, length, constraints) {
                Ok(layout) => layout,
                Err(error) => {
                    // SAFETY: allocation is the base just returned by VirtualAlloc.
                    let _ = unsafe { VirtualFree(allocation.as_ptr(), 0, MEM_RELEASE) };
                    return Err(error);
                }
            };
        // SAFETY: layout proves the offset plus length remains inside allocation.
        let data = unsafe {
            NonNull::new_unchecked(
                allocation
                    .as_ptr()
                    .cast::<u8>()
                    .add(layout.data_offset)
                    .cast(),
            )
        };
        Ok(Self {
            allocation,
            data,
            length,
        })
    }

    /// Returns the stable pointer used only during the synchronous IOCTL.
    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.data.as_ptr()
    }

    /// Copies trusted outbound bytes into the aligned allocation.
    fn copy_from(&mut self, bytes: &[u8]) -> Result<(), NativeError> {
        if bytes.len() != self.length {
            return Err(NativeError::InvalidRequest);
        }
        // SAFETY: both regions are valid for exactly self.length non-overlapping bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.data.as_ptr().cast::<u8>(),
                self.length,
            );
        }
        Ok(())
    }

    /// Copies the complete bounded aligned allocation into safe Rust storage.
    fn to_vec(&self) -> Vec<u8> {
        // SAFETY: the allocation remains live and initialized for self.length bytes.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr().cast::<u8>(), self.length).to_vec() }
    }
}

impl Drop for AlignedBuffer {
    /// Releases the entire VirtualAlloc region exactly once.
    fn drop(&mut self) {
        // SAFETY: pointer is the base returned by VirtualAlloc and MEM_RELEASE requires size zero.
        let _ = unsafe { VirtualFree(self.allocation.as_ptr(), 0, MEM_RELEASE) };
    }
}

/// Executes data-in/out with direct SPTI and a page-aligned data allocation.
fn execute_direct(
    handle: HANDLE,
    request: ScsiRequest,
    constraints: AdapterConstraints,
) -> Completion {
    let mut data = match AlignedBuffer::new(request.data.len(), constraints) {
        Ok(data) => data,
        Err(error) => return Completion::NotAttempted(error),
    };
    if request.direction == DataDirection::ToDevice && data.copy_from(&request.data).is_err() {
        return Completion::NotAttempted(NativeError::InvalidRequest);
    }
    let mut control = DirectControl {
        header: SCSI_PASS_THROUGH_DIRECT {
            Length: size_of::<SCSI_PASS_THROUGH_DIRECT>() as u16,
            ScsiStatus: 0,
            PathId: 0,
            TargetId: 0,
            Lun: 0,
            CdbLength: request.cdb_length,
            SenseInfoLength: request.sense_capacity,
            DataIn: match request.direction {
                DataDirection::FromDevice => SCSI_IOCTL_DATA_IN as u8,
                DataDirection::ToDevice => SCSI_IOCTL_DATA_OUT as u8,
                DataDirection::None => SCSI_IOCTL_DATA_UNSPECIFIED as u8,
            },
            DataTransferLength: request.data.len() as u32,
            TimeOutValue: request.timeout_seconds,
            DataBuffer: data.as_mut_ptr(),
            SenseInfoOffset: offset_of!(DirectControl, sense) as u32,
            Cdb: request.cdb,
        },
        sense: [0; super::MAX_SENSE_LENGTH],
    };
    let mut returned = 0_u32;
    let diagnostic = super::spti_diagnostics::Observation::begin(
        &control.header.Cdb[..usize::from(control.header.CdbLength).min(16)],
        control.header.DataIn,
        control.header.DataTransferLength,
    );
    // SAFETY: control and aligned data remain live, writable, and stable for the
    // documented synchronous direct pass-through call.
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_SCSI_PASS_THROUGH_DIRECT,
            Some((&raw const control).cast()),
            size_of::<DirectControl>() as u32,
            Some((&raw mut control).cast()),
            size_of::<DirectControl>() as u32,
            Some(&mut returned),
            None,
        )
    };
    if let Err(error) = result {
        if let Some(diagnostic) = &diagnostic {
            diagnostic.failed(false, returned);
        }
        return Completion::AttemptedError(map_windows_error(error));
    }
    let returned = match bounded_returned_length(
        returned,
        size_of::<DirectControl>(),
        size_of::<SCSI_PASS_THROUGH_DIRECT>(),
    ) {
        Ok(returned) => returned,
        Err(error) => {
            if let Some(diagnostic) = &diagnostic {
                diagnostic.failed(true, returned);
            }
            return Completion::AttemptedError(error);
        }
    };
    let sense_reported_length = usize::from(control.header.SenseInfoLength);
    let sense_available_length = returned
        .saturating_sub(offset_of!(DirectControl, sense))
        .min(control.sense.len());
    let sense_copy_length = sense_reported_length.min(sense_available_length);
    if let Some(diagnostic) = &diagnostic {
        diagnostic.complete(
            control.header.ScsiStatus,
            control.header.DataTransferLength,
            sense_reported_length,
            &control.sense[..sense_copy_length],
            returned as u32,
        );
    }
    Completion::Device {
        scsi_status: control.header.ScsiStatus,
        transferred_length: control.header.DataTransferLength,
        data: if request.direction == DataDirection::FromDevice {
            data.to_vec()
        } else {
            Vec::new()
        },
        sense_reported_length,
        sense: control.sense[..sense_copy_length].to_vec(),
    }
}

/// Executes a no-data command with buffered SPTI and embedded request sense.
fn execute_buffered(handle: HANDLE, request: ScsiRequest) -> Completion {
    let mut control = BufferedControl {
        header: SCSI_PASS_THROUGH {
            Length: size_of::<SCSI_PASS_THROUGH>() as u16,
            ScsiStatus: 0,
            PathId: 0,
            TargetId: 0,
            Lun: 0,
            CdbLength: request.cdb_length,
            SenseInfoLength: request.sense_capacity,
            DataIn: SCSI_IOCTL_DATA_UNSPECIFIED as u8,
            DataTransferLength: 0,
            TimeOutValue: request.timeout_seconds,
            DataBufferOffset: 0,
            SenseInfoOffset: offset_of!(BufferedControl, sense) as u32,
            Cdb: request.cdb,
        },
        sense: [0; super::MAX_SENSE_LENGTH],
    };
    let mut returned = 0_u32;
    let diagnostic = super::spti_diagnostics::Observation::begin(
        &control.header.Cdb[..usize::from(control.header.CdbLength).min(16)],
        control.header.DataIn,
        control.header.DataTransferLength,
    );
    // SAFETY: one stable in/out control buffer covers header and bounded sense
    // for the documented synchronous buffered pass-through call.
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_SCSI_PASS_THROUGH,
            Some((&raw const control).cast()),
            size_of::<BufferedControl>() as u32,
            Some((&raw mut control).cast()),
            size_of::<BufferedControl>() as u32,
            Some(&mut returned),
            None,
        )
    };
    if let Err(error) = result {
        if let Some(diagnostic) = &diagnostic {
            diagnostic.failed(false, returned);
        }
        return Completion::AttemptedError(map_windows_error(error));
    }
    let returned = match bounded_returned_length(
        returned,
        size_of::<BufferedControl>(),
        size_of::<SCSI_PASS_THROUGH>(),
    ) {
        Ok(returned) => returned,
        Err(error) => {
            if let Some(diagnostic) = &diagnostic {
                diagnostic.failed(true, returned);
            }
            return Completion::AttemptedError(error);
        }
    };
    let sense_reported_length = usize::from(control.header.SenseInfoLength);
    let sense_available_length = returned
        .saturating_sub(offset_of!(BufferedControl, sense))
        .min(control.sense.len());
    let sense_copy_length = sense_reported_length.min(sense_available_length);
    if let Some(diagnostic) = &diagnostic {
        diagnostic.complete(
            control.header.ScsiStatus,
            control.header.DataTransferLength,
            sense_reported_length,
            &control.sense[..sense_copy_length],
            returned as u32,
        );
    }
    Completion::Device {
        scsi_status: control.header.ScsiStatus,
        transferred_length: control.header.DataTransferLength,
        data: Vec::new(),
        sense_reported_length,
        sense: control.sense[..sense_copy_length].to_vec(),
    }
}

/// Converts an OS string to one NUL-terminated UTF-16 buffer.
fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

/// Reconstructs a private kernel HANDLE only for one native call.
fn kernel_handle(handle: &KernelHandle) -> HANDLE {
    HANDLE(handle.copied() as *mut c_void)
}

/// Reconstructs a private HDEVINFO only for one SetupAPI call.
fn device_info_handle(handle: &DeviceInfoSet) -> HDEVINFO {
    HDEVINFO(handle.copied())
}

/// Converts a windows-rs HRESULT_FROM_WIN32 error to a stable failure class.
fn map_windows_error(error: Error) -> NativeError {
    win32_error_code(&error).map_or(NativeError::Other, map_win32_code)
}

/// Extracts only a wrapped Win32 code without retaining native error text.
fn win32_error_code(error: &Error) -> Option<WIN32_ERROR> {
    let raw = error.code().0 as u32;
    if raw & 0xFFFF_0000 == 0x8007_0000 {
        Some(WIN32_ERROR(raw & 0xFFFF))
    } else {
        None
    }
}

/// Maps only behaviorally relevant Win32 codes and discards native text.
fn map_win32_code(code: WIN32_ERROR) -> NativeError {
    match code {
        ERROR_ACCESS_DENIED => NativeError::AccessDenied,
        ERROR_BUSY
        | ERROR_BUSY_DRIVE
        | ERROR_SHARING_VIOLATION
        | ERROR_LOCK_VIOLATION
        | ERROR_RETRY => NativeError::Busy,
        ERROR_NOT_READY | ERROR_NO_MEDIA_IN_DRIVE => NativeError::NoMedia,
        ERROR_OPERATION_ABORTED => NativeError::Cancelled,
        ERROR_SEM_TIMEOUT | ERROR_TIMEOUT => NativeError::TimedOut,
        ERROR_DEVICE_NOT_CONNECTED
        | ERROR_DEVICE_NOT_AVAILABLE
        | ERROR_DEVICE_REMOVED
        | ERROR_DEV_NOT_EXIST
        | ERROR_INVALID_HANDLE
        | ERROR_NO_SUCH_DEVICE
        | ERROR_FILE_NOT_FOUND
        | ERROR_PATH_NOT_FOUND
        | ERROR_GEN_FAILURE => NativeError::DeviceRemoved,
        ERROR_MORE_DATA | ERROR_INSUFFICIENT_BUFFER => NativeError::ResourceLimit,
        _ => NativeError::Other,
    }
}

#[cfg(test)]
mod tests;

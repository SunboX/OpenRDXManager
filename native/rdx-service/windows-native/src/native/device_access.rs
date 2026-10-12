// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed installer-only per-instance permissions. Never changes disk-class policy.
use super::*;
use crate::local_trust::windows::{evidence, open};
use crate::local_trust::{LOCAL_ENROLLMENT_ROOT, validate_runtime_acl};
use serde::{Deserialize, Serialize};
use std::path::Path;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    SPDRP_SECURITY_SDS, SetupDiGetDeviceRegistryPropertyW, SetupDiOpenDeviceInfoW,
    SetupDiSetDeviceRegistryPropertyW,
};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT, SetEntriesInAclW, TRUSTEE_IS_NAME,
    TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::*;
use windows::core::PWSTR;

const RECORD: &str = "device-access.json";
const SERVICE_ACCOUNT: &str = "NT SERVICE\\OpenRDXHardwareService";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviousPolicy {
    schema_version: u32,
    devices: Vec<DevicePolicy>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DevicePolicy {
    instance: String,
    serial: String,
    previous: Option<String>,
    installed: String,
    volumes: Vec<VolumePolicy>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VolumePolicy {
    instance: String,
    topology: String,
    previous: Option<String>,
    installed: String,
}
struct MappedVolume {
    instance: String,
    info: SP_DEVINFO_DATA,
    handle: KernelHandle,
    topology: crate::VolumeTopology,
}
struct Allocation(*mut c_void);
impl Drop for Allocation {
    /// Releases one descriptor/ACL API allocation.
    fn drop(&mut self) {
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
    }
}
/// Copies a current device-instance registry policy, preserving absence exactly.
fn instance_policy(
    set: &DeviceInfoSet,
    info: &SP_DEVINFO_DATA,
) -> Result<Option<String>, NativeError> {
    let mut storage = vec![0u8; 65536];
    let mut kind = 0;
    let mut needed = 0;
    let result = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            device_info_handle(set),
            info,
            SPDRP_SECURITY_SDS,
            Some(&mut kind),
            Some(&mut storage),
            Some(&mut needed),
        )
    };
    if let Err(error) = result {
        if win32_error_code(&error).is_some_and(|v| v.0 == 13) {
            return Ok(None);
        }
        return Err(map_windows_error(error));
    }
    if needed < 2 || needed as usize > storage.len() || needed % 2 != 0 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let units: Vec<u16> = storage[..needed as usize]
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    if units.last() != Some(&0) {
        return Err(NativeError::EvidenceIncomplete);
    }
    String::from_utf16(&units[..units.len() - 1])
        .map(Some)
        .map_err(|_| NativeError::EvidenceIncomplete)
}
/// Writes only one already-identified device instance property, never a class property.
fn set_instance_policy(
    set: &DeviceInfoSet,
    info: &SP_DEVINFO_DATA,
    policy: Option<&str>,
) -> Result<(), NativeError> {
    let bytes = policy.map(|v| {
        v.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    });
    let mut info = *info;
    unsafe {
        SetupDiSetDeviceRegistryPropertyW(
            device_info_handle(set),
            &mut info,
            SPDRP_SECURITY_SDS,
            bytes.as_deref(),
        )
    }
    .map_err(map_windows_error)
}
/// Converts a native descriptor to exact owner/group/DACL evidence for restoration.
fn descriptor_text(descriptor: PSECURITY_DESCRIPTOR) -> Result<String, NativeError> {
    let mut output = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut output,
            None,
        )
    }
    .map_err(map_windows_error)?;
    let allocation = Allocation(output.0.cast());
    unsafe { PWSTR(allocation.0.cast()).to_string() }.map_err(|_| NativeError::EvidenceIncomplete)
}
/// Copies current effective device ACL when no explicit instance property exists.
fn current_device_policy(handle: HANDLE) -> Result<String, NativeError> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(map_windows_error)?;
    let descriptor = Allocation(descriptor.0);
    descriptor_text(PSECURITY_DESCRIPTOR(descriptor.0))
}
/// Adds only the fixed service SID read/write grant while preserving every prior ACE.
fn grant_service(previous: &str) -> Result<String, NativeError> {
    let previous = wide_null(OsStr::new(previous));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(previous.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(map_windows_error)?;
    let descriptor = Allocation(descriptor.0);
    let mut present = false.into();
    let mut defaulted = false.into();
    let mut dacl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(descriptor.0),
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
    }
    .map_err(map_windows_error)?;
    if !present.as_bool() || dacl.is_null() || !unsafe { IsValidAcl(dacl).as_bool() } {
        return Err(NativeError::AccessDenied);
    }
    let mut account = wide_null(OsStr::new(SERVICE_ACCOUNT));
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_READ.0 | GENERIC_WRITE.0,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: ACE_FLAGS(0),
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_NAME,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(account.as_mut_ptr()),
            ..Default::default()
        },
    };
    let mut updated = std::ptr::null_mut();
    unsafe { SetEntriesInAclW(Some(&[entry]), Some(dacl), &mut updated) }
        .ok()
        .map_err(map_windows_error)?;
    let updated = Allocation(updated.cast());
    let mut absolute = SECURITY_DESCRIPTOR::default();
    unsafe {
        InitializeSecurityDescriptor(
            PSECURITY_DESCRIPTOR((&mut absolute as *mut SECURITY_DESCRIPTOR).cast()),
            1,
        )
    }
    .map_err(map_windows_error)?;
    let mut owner = PSID::default();
    let mut group = PSID::default();
    unsafe {
        GetSecurityDescriptorOwner(
            PSECURITY_DESCRIPTOR(descriptor.0),
            &mut owner,
            &mut defaulted,
        )
    }
    .map_err(map_windows_error)?;
    unsafe {
        GetSecurityDescriptorGroup(
            PSECURITY_DESCRIPTOR(descriptor.0),
            &mut group,
            &mut defaulted,
        )
    }
    .map_err(map_windows_error)?;
    let absolute = PSECURITY_DESCRIPTOR((&mut absolute as *mut SECURITY_DESCRIPTOR).cast());
    unsafe { SetSecurityDescriptorOwner(absolute, Some(owner), false) }
        .map_err(map_windows_error)?;
    unsafe { SetSecurityDescriptorGroup(absolute, Some(group), false) }
        .map_err(map_windows_error)?;
    unsafe { SetSecurityDescriptorDacl(absolute, true, Some(updated.0.cast()), false) }
        .map_err(map_windows_error)?;
    descriptor_text(absolute)
}
/// Executes only standard INQUIRY and device-identification INQUIRY on the retained device.
fn rdx_identity(device: &mut NativeDevice) -> Result<String, NativeError> {
    let inquiry = |device: &mut NativeDevice, vpd: bool| -> Result<Vec<u8>, NativeError> {
        let cdb = [0x12, u8::from(vpd), if vpd { 0x83 } else { 0 }, 0, 254, 0];
        let request = ScsiRequest::new(&cdb, DataDirection::FromDevice, vec![0; 254], 10, 252)?;
        match device.execute(request) {
            Completion::Device {
                scsi_status: 0,
                transferred_length,
                mut data,
                ..
            } => {
                if transferred_length as usize > data.len() {
                    return Err(NativeError::EvidenceIncomplete);
                }
                data.truncate(transferred_length as usize);
                if data.len() < 5 {
                    return Err(NativeError::EvidenceIncomplete);
                }
                let declared = if vpd {
                    u16::from_be_bytes([data[2], data[3]]) as usize + 4
                } else {
                    data[4] as usize + 5
                };
                if declared > data.len() {
                    return Err(NativeError::EvidenceIncomplete);
                }
                data.truncate(declared);
                Ok(data)
            }
            _ => Err(NativeError::EvidenceIncomplete),
        }
    };
    let standard = inquiry(device, false)?;
    let vpd = inquiry(device, true)?;
    device.revalidate_exact()?;
    crate::rdx_permission_identity(&standard, &vpd)
}
/// Encodes only SetupAPI-generated candidates; no external device input is accepted.
fn device_for(candidate: &DiskCandidate) -> Result<NativeDevice, NativeError> {
    let mut recipe = format!("win1:{:08X}:", candidate.disk_number);
    for unit in candidate.instance_id.encode_utf16() {
        use std::fmt::Write;
        write!(recipe, "{unit:04X}").map_err(|_| NativeError::Other)?;
    }
    NativeDevice::open(OsStr::new(&recipe))
}
/// Opens only a present instance whose exact identity was verified by retained hardware evidence.
fn instance_info(set: &DeviceInfoSet, instance: &str) -> Result<SP_DEVINFO_DATA, NativeError> {
    let instance = wide_null(OsStr::new(instance));
    let mut info = SP_DEVINFO_DATA {
        cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
        ..Default::default()
    };
    unsafe {
        SetupDiOpenDeviceInfoW(
            device_info_handle(set),
            PCWSTR(instance.as_ptr()),
            None,
            0,
            Some(&mut info),
        )
    }
    .map_err(map_windows_error)?;
    Ok(info)
}
/// Reads only fixed protected previous-policy storage; malformed records fail closed.
fn read_records() -> Result<PreviousPolicy, NativeError> {
    use std::io::Read;
    let path = Path::new(LOCAL_ENROLLMENT_ROOT).join(RECORD);
    if !path.exists() {
        return Ok(PreviousPolicy {
            schema_version: 1,
            devices: Vec::new(),
        });
    }
    let mut file = open(&path, false)?;
    validate_runtime_acl(&evidence(&file)?)?;
    if file
        .metadata()
        .map_err(|_| NativeError::AccessDenied)?
        .len()
        > 1048576
    {
        return Err(NativeError::ResourceLimit);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| NativeError::AccessDenied)?;
    let records: PreviousPolicy =
        serde_json::from_slice(&bytes).map_err(|_| NativeError::EvidenceIncomplete)?;
    if records.schema_version != 1 || records.devices.len() > 128 {
        return Err(NativeError::EvidenceIncomplete);
    }
    let mut seen = BTreeSet::new();
    for entry in &records.devices {
        if entry.instance.len() > 201
            || entry.serial.len() > 10
            || entry.installed.len() > 65536
            || entry.previous.as_ref().is_some_and(|v| v.len() > 65536)
            || entry.volumes.len() > 256
            || entry.volumes.iter().any(|v| {
                v.instance.len() > 201
                    || v.topology.len() > 256
                    || v.installed.len() > 65536
                    || v.previous.as_ref().is_some_and(|s| s.len() > 65536)
            })
            || !seen.insert(entry.instance.clone())
        {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    Ok(records)
}
/// Durably records exact prior policy before touching a device permission.
fn write_records(records: &PreviousPolicy, _administrator_sid: &str) -> Result<(), NativeError> {
    let bytes = serde_json::to_vec(records).map_err(|_| NativeError::Other)?;
    crate::local_trust::windows::write_device_policy(&bytes)
}
/// Enrolls only positively identified RDX instances, preserving prior policy for safe removal.
/// Effective permissions require driver restart/physical acceptance; no LocalSystem fallback.
pub(crate) fn provision(administrator_sid: &str) -> Result<(), NativeError> {
    let set = open_device_info_set()?;
    let mut records = read_records()?;
    for candidate in enumerate_disk_candidates()? {
        let mut device = match device_for(&candidate) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let serial = match rdx_identity(&mut device) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let info = instance_info(&set, &candidate.instance_id)?;
        let previous = instance_policy(&set, &info)?;
        if let Some(existing) = records
            .devices
            .iter()
            .find(|v| v.instance == candidate.instance_id)
        {
            if !crate::safe_device_acl_repair(
                &existing.instance,
                &existing.serial,
                &existing.installed,
                existing.previous.as_deref(),
                &candidate.instance_id,
                &serial,
                previous.as_deref(),
            ) {
                return Err(NativeError::AccessDenied);
            }
            let volume_set = volume_info_set()?;
            let mapped = mapped_volumes(&volume_set, candidate.disk_number)?;
            // Validate every current journal match before changing any policy.
            for volume in &mapped {
                if let Some(recorded) = existing.volumes.iter().find(|v| {
                    v.instance == volume.instance && v.topology == topology_key(&volume.topology)
                }) {
                    let current = instance_policy(&volume_set, &volume.info)?;
                    if current.as_deref() != Some(recorded.installed.as_str())
                        && current != recorded.previous
                    {
                        return Err(NativeError::AccessDenied);
                    }
                }
            }
            device.revalidate_exact()?;
            set_instance_policy(&set, &info, Some(&existing.installed))?;
            if instance_policy(&set, &info)?.as_deref() != Some(existing.installed.as_str()) {
                return Err(NativeError::AccessDenied);
            }
            for volume in &mapped {
                if let Some(recorded) = existing.volumes.iter().find(|v| {
                    v.instance == volume.instance && v.topology == topology_key(&volume.topology)
                }) {
                    device.revalidate_exact()?;
                    if super::volumes::volume_topology(kernel_handle(&volume.handle))?
                        != volume.topology
                    {
                        return Err(NativeError::DeviceRemoved);
                    }
                    set_instance_policy(&volume_set, &volume.info, Some(&recorded.installed))?;
                    if instance_policy(&volume_set, &volume.info)?.as_deref()
                        != Some(recorded.installed.as_str())
                    {
                        return Err(NativeError::AccessDenied);
                    }
                }
            }
            continue;
        }
        // Driver-level instance security is scoped to this positively identified
        // device. Preserve every existing system ACE; only our service SID is added.
        let effective = match &previous {
            Some(v) => v.clone(),
            None => current_device_policy(kernel_handle(&device.handle))?,
        };
        let installed = grant_service(&effective)?;
        records.devices.push(DevicePolicy {
            instance: candidate.instance_id.clone(),
            serial,
            previous: previous.clone(),
            installed: installed.clone(),
            volumes: Vec::new(),
        });
        let volume_set = volume_info_set()?;
        let mapped = mapped_volumes(&volume_set, candidate.disk_number)?;
        for volume in &mapped {
            let previous = instance_policy(&volume_set, &volume.info)?;
            let effective = match &previous {
                Some(v) => v.clone(),
                None => current_device_policy(kernel_handle(&volume.handle))?,
            };
            records
                .devices
                .last_mut()
                .ok_or(NativeError::Other)?
                .volumes
                .push(VolumePolicy {
                    instance: volume.instance.clone(),
                    topology: topology_key(&volume.topology),
                    previous,
                    installed: grant_service(&effective)?,
                });
        }
        write_records(&records, administrator_sid)?;
        device.revalidate_exact()?;
        set_instance_policy(&set, &info, Some(&installed))?;
        if instance_policy(&set, &info)?.as_deref() != Some(installed.as_str()) {
            return Err(NativeError::AccessDenied);
        }
        for (volume, recorded) in mapped
            .iter()
            .zip(&records.devices.last().ok_or(NativeError::Other)?.volumes)
        {
            device.revalidate_exact()?;
            if super::volumes::volume_topology(kernel_handle(&volume.handle))? != volume.topology {
                return Err(NativeError::DeviceRemoved);
            }
            set_instance_policy(&volume_set, &volume.info, Some(&recorded.installed))?;
            if instance_policy(&volume_set, &volume.info)?.as_deref()
                != Some(recorded.installed.as_str())
            {
                return Err(NativeError::AccessDenied);
            }
        }
        device.revalidate_exact()?;
        eprintln!(
            "OpenRDX device permission enrolled: reconnect/restart the device and run Repair; effective disk and volume access remain unverified"
        );
    }
    Ok(())
}
/// Restores only still-matching recorded device policy; preserves foreign/admin changes.
pub(crate) fn restore() -> Result<(), NativeError> {
    let records = read_records()?;
    let set = open_device_info_set()?;
    for candidate in enumerate_disk_candidates()? {
        let Some(record) = records
            .devices
            .iter()
            .find(|v| v.instance == candidate.instance_id)
        else {
            continue;
        };
        let mut device = device_for(&candidate)?;
        let serial = rdx_identity(&mut device)?;
        let info = instance_info(&set, &candidate.instance_id)?;
        let current = instance_policy(&set, &info)?;
        if crate::safe_device_acl_restore(
            &record.instance,
            &record.serial,
            &record.installed,
            &candidate.instance_id,
            &serial,
            current.as_deref().unwrap_or(""),
        ) {
            device.revalidate_exact()?;
            set_instance_policy(&set, &info, record.previous.as_deref())?;
            if instance_policy(&set, &info)? != record.previous {
                return Err(NativeError::AccessDenied);
            }
            let volume_set = volume_info_set()?;
            for volume in mapped_volumes(&volume_set, candidate.disk_number)? {
                let Some(recorded) = record.volumes.iter().find(|v| {
                    v.instance == volume.instance && v.topology == topology_key(&volume.topology)
                }) else {
                    continue;
                };
                if instance_policy(&volume_set, &volume.info)?.as_deref()
                    == Some(recorded.installed.as_str())
                {
                    device.revalidate_exact()?;
                    if super::volumes::volume_topology(kernel_handle(&volume.handle))?
                        != volume.topology
                    {
                        return Err(NativeError::DeviceRemoved);
                    }
                    set_instance_policy(&volume_set, &volume.info, recorded.previous.as_deref())?;
                    if instance_policy(&volume_set, &volume.info)? != recorded.previous {
                        return Err(NativeError::AccessDenied);
                    }
                }
            }
        }
    }
    // Disconnected device records remain protected for later administrator repair;
    // removal does not invent a device instance or overwrite another policy.
    Ok(())
}

/// Opens only the present volume-interface information set, with no class mutation rights.
fn volume_info_set() -> Result<DeviceInfoSet, NativeError> {
    let guid = windows::Win32::System::Ioctl::GUID_DEVINTERFACE_VOLUME;
    let raw = unsafe {
        SetupDiGetClassDevsW(
            Some(&guid),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    }
    .map_err(map_windows_error)?;
    Ok(DeviceInfoSet::new(raw.0))
}
/// Binds volume permissions to one unambiguous physical extent and complete storage number.
fn mapped_volumes(set: &DeviceInfoSet, disk_number: u32) -> Result<Vec<MappedVolume>, NativeError> {
    let guid = windows::Win32::System::Ioctl::GUID_DEVINTERFACE_VOLUME;
    let mut index = 0;
    let mut mapped = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        let mut interface = SP_DEVICE_INTERFACE_DATA {
            cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };
        let next = unsafe {
            SetupDiEnumDeviceInterfaces(device_info_handle(set), None, &guid, index, &mut interface)
        };
        if let Err(error) = next {
            if win32_error_code(&error) == Some(ERROR_NO_MORE_ITEMS) {
                break;
            }
            return Err(map_windows_error(error));
        }
        index += 1;
        if index > 256 {
            return Err(NativeError::ResourceLimit);
        }
        let (path, info) = interface_detail(set, &interface)?;
        let instance = device_instance_id(set, &info)?;
        let handle = open_path(&path, 0)?;
        let topology = super::volumes::volume_topology(kernel_handle(&handle))?;
        if let crate::VolumeMembership::Target(topology) =
            crate::classify_volume_probe(Ok(topology), disk_number)?
        {
            if !seen.insert(instance.clone()) {
                return Err(NativeError::EvidenceIncomplete);
            }
            mapped.push(MappedVolume {
                instance,
                info,
                handle,
                topology,
            });
        }
    }
    Ok(mapped)
}
/// Serializes only the complete verified volume generation for protected restoration records.
fn topology_key(topology: &crate::VolumeTopology) -> String {
    let extent = &topology.extents[0];
    format!(
        "{}:{}:{}:{}:{}:{}",
        topology.storage.device_type,
        topology.storage.device_number,
        topology.storage.partition_number,
        extent.disk_number,
        extent.starting_offset,
        extent.extent_length
    )
}

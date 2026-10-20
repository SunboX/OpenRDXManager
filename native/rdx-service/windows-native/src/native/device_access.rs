// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed installer-only per-instance permissions. Never changes disk-class policy.
use super::*;
use crate::installer_volume_policy::{
    VolumeObservation, VolumePolicy, plan_volume_policies, validate_volume_policies,
    volume_media_ready,
};
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
use windows::Win32::Storage::FileSystem::READ_CONTROL;
use windows::core::PWSTR;
mod live_policy;

const RECORD: &str = "device-access.json";
const SERVICE_ACCOUNT: &str = "NT SERVICE\\OpenRDXHardwareService";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PreviousPolicy {
    schema_version: u32,
    #[serde(default)]
    previous_volume_maintenance_right: Option<bool>,
    devices: Vec<DevicePolicy>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DevicePolicy {
    instance: String,
    serial: String,
    previous: Option<String>,
    installed: String,
    #[serde(default)]
    effective: Option<crate::effective_volume_policy::EffectiveVolumePolicy>,
    volumes: Vec<VolumePolicy>,
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
            previous_volume_maintenance_right: None,
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
        validate_volume_policies(&entry.volumes)?;
        if let Some(effective) = &entry.effective {
            effective.validate()?;
        }
        if entry.instance.len() > 201
            || entry.serial.len() > 10
            || entry.installed.len() > 65536
            || entry.previous.as_ref().is_some_and(|v| v.len() > 65536)
            || !seen.insert(entry.instance.clone())
        {
            return Err(NativeError::EvidenceIncomplete);
        }
    }
    Ok(records)
}
/// Durably records exact prior policy before touching a device permission.
fn write_records(records: &PreviousPolicy) -> Result<(), NativeError> {
    let bytes = serde_json::to_vec(records).map_err(|_| NativeError::Other)?;
    crate::local_trust::windows::write_device_policy(&bytes)
}
struct VolumeRightJournal<'a>(&'a mut PreviousPolicy);
impl crate::volume_privilege::journal::PrivilegeJournal for VolumeRightJournal<'_> {
    /// Reads this installation's protected original privilege ownership.
    fn previous(&self) -> Option<bool> {
        self.0.previous_volume_maintenance_right
    }
    /// Reads only the compiled service SID's current volume-maintenance right.
    fn current(&self) -> Result<bool, NativeError> {
        crate::volume_privilege::has_service_right()
    }
    /// Publishes the complete protected journal before advancing in-memory ownership.
    fn store(&mut self, previous: Option<bool>) -> Result<(), NativeError> {
        let original = self.0.previous_volume_maintenance_right;
        self.0.previous_volume_maintenance_right = previous;
        if let Err(error) = write_records(self.0) {
            self.0.previous_volume_maintenance_right = original;
            return Err(error);
        }
        Ok(())
    }
    /// Changes only the fixed service-specific right through the closed LSA adapter.
    fn set(&mut self, present: bool) -> Result<(), NativeError> {
        crate::volume_privilege::set_service_right(present)
    }
}
/// Enrolls only positively identified RDX instances, preserving prior policy for safe removal.
/// Effective permissions require driver restart/physical acceptance; no LocalSystem fallback.
pub(crate) fn provision(_administrator_sid: &str) -> Result<(), NativeError> {
    let set = open_device_info_set()?;
    let mut records = read_records()?;
    crate::volume_privilege::journal::enroll(&mut VolumeRightJournal(&mut records))?;
    for candidate in enumerate_disk_candidates()? {
        let Some(mut device) = crate::device_access::permission_probe_result(
            &candidate.instance_id,
            device_for(&candidate),
        )
        .inspect_err(|error| {
            eprintln!("OpenRDX device permission failure: phase=open reason={error:?}")
        })?
        else {
            continue;
        };
        let Some(serial) = crate::device_access::permission_probe_result(
            &candidate.instance_id,
            rdx_identity(&mut device),
        )
        .inspect_err(|error| {
            eprintln!("OpenRDX device permission failure: phase=identity reason={error:?}")
        })?
        else {
            continue;
        };
        let info = instance_info(&set, &candidate.instance_id)?;
        let previous = instance_policy(&set, &info)?;
        let index = if let Some(index) = records
            .devices
            .iter()
            .position(|v| v.instance == candidate.instance_id)
        {
            let existing = &records.devices[index];
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
            index
        } else {
            // Preserve the original property before adding only the fixed service
            // SID to this positively identified physical RDX instance.
            let effective = match &previous {
                Some(v) => v.clone(),
                None => current_device_policy(kernel_handle(&device.handle))?,
            };
            records.devices.push(DevicePolicy {
                instance: candidate.instance_id.clone(),
                serial: serial.clone(),
                previous,
                installed: grant_service(&effective)?,
                effective: None,
                volumes: Vec::new(),
            });
            records.devices.len() - 1
        };
        let disk_policy = disk_policy_handle(&device)?;
        let recorded = &mut records.devices[index];
        if let Some(effective) = &mut recorded.effective {
            effective.previous = live_policy::canonical(&effective.previous)?;
            effective.installed = live_policy::canonical(&effective.installed)?;
        }
        recorded.effective = Some(crate::effective_volume_policy::EffectiveVolumePolicy::plan(
            recorded.effective.as_ref(),
            live_policy::read(kernel_handle(&disk_policy))?,
            live_policy::grant,
        )?);
        let volume_set = volume_info_set()?;
        let mapped = mapped_volumes_for_device(&volume_set, &device, candidate.disk_number)?;
        let observed = mapped
            .iter()
            .map(|volume| {
                Ok(VolumeObservation {
                    instance: volume.instance.clone(),
                    topology: topology_key(&volume.topology),
                    current: instance_policy(&volume_set, &volume.info)?,
                })
            })
            .collect::<Result<Vec<_>, NativeError>>()?;
        let planned = plan_volume_policies(&records.devices[index].volumes, &observed, |i| {
            let effective = match &observed[i].current {
                Some(v) => v.clone(),
                None => current_device_policy(kernel_handle(&mapped[i].handle))?,
            };
            grant_service(&effective)
        })?;
        records.devices[index].volumes = planned;
        // Registry properties affect future PnP generations, not necessarily the
        // live NTFS volume object. Journal its independent DACL before updating it.
        for volume in &mapped {
            let recorded = records.devices[index]
                .volumes
                .iter_mut()
                .find(|v| {
                    v.instance == volume.instance && v.topology == topology_key(&volume.topology)
                })
                .ok_or(NativeError::EvidenceIncomplete)?;
            if let Some(effective) = &mut recorded.effective {
                // Earlier setup journals retained generic masks, whereas Windows
                // stores expanded file rights on live volume objects. Migrate only
                // that representation before the same exact foreign-policy check.
                effective.previous = live_policy::canonical(&effective.previous)?;
                effective.installed = live_policy::canonical(&effective.installed)?;
            }
            recorded.effective = Some(crate::effective_volume_policy::EffectiveVolumePolicy::plan(
                recorded.effective.as_ref(),
                live_policy::read(kernel_handle(&volume.handle))?,
                live_policy::grant,
            )?);
        }
        // Initial installation and Repair share the same write-ahead boundary.
        // Absent volumes stay recorded; newly ready cartridges are added here.
        write_records(&records)?;
        let recorded_device = &records.devices[index];
        device.revalidate_exact()?;
        let current = instance_policy(&set, &info)?;
        if !crate::safe_device_acl_repair(
            &recorded_device.instance,
            &recorded_device.serial,
            &recorded_device.installed,
            recorded_device.previous.as_deref(),
            &candidate.instance_id,
            &serial,
            current.as_deref(),
        ) {
            return Err(NativeError::AccessDenied);
        }
        set_instance_policy(&set, &info, Some(&recorded_device.installed))?;
        if instance_policy(&set, &info)?.as_deref() != Some(recorded_device.installed.as_str()) {
            return Err(NativeError::AccessDenied);
        }
        device.revalidate_exact()?;
        revalidate_present_identity(&device.identity, &disk_policy)?;
        let effective = recorded_device
            .effective
            .as_ref()
            .ok_or(NativeError::EvidenceIncomplete)?;
        let current = live_policy::read(kernel_handle(&disk_policy))?;
        if current != effective.previous && current != effective.installed {
            return Err(NativeError::AccessDenied);
        }
        live_policy::replace(kernel_handle(&disk_policy), &current, &effective.installed)?;
        device.revalidate_exact()?;
        for volume in &mapped {
            let recorded = recorded_device
                .volumes
                .iter()
                .find(|v| {
                    v.instance == volume.instance && v.topology == topology_key(&volume.topology)
                })
                .ok_or(NativeError::EvidenceIncomplete)?;
            device.revalidate_exact()?;
            if super::volumes::volume_topology(kernel_handle(&volume.handle))? != volume.topology {
                return Err(NativeError::DeviceRemoved);
            }
            // Preserve an administrator change made after planning/journaling.
            let current = instance_policy(&volume_set, &volume.info)?;
            if current.as_deref() != Some(recorded.installed.as_str())
                && current != recorded.previous
            {
                return Err(NativeError::AccessDenied);
            }
            set_instance_policy(&volume_set, &volume.info, Some(&recorded.installed))?;
            if instance_policy(&volume_set, &volume.info)?.as_deref()
                != Some(recorded.installed.as_str())
            {
                return Err(NativeError::AccessDenied);
            }
            device.revalidate_exact()?;
            if super::volumes::volume_topology(kernel_handle(&volume.handle))? != volume.topology {
                return Err(NativeError::DeviceRemoved);
            }
            let effective = recorded
                .effective
                .as_ref()
                .ok_or(NativeError::EvidenceIncomplete)?;
            let current = live_policy::read(kernel_handle(&volume.handle))?;
            if current != effective.previous && current != effective.installed {
                return Err(NativeError::AccessDenied);
            }
            live_policy::replace(
                kernel_handle(&volume.handle),
                &current,
                &effective.installed,
            )?;
        }
        device.revalidate_exact()?;
        eprintln!(
            "OpenRDX device permission enrolled: live dock and target volume permissions verified; installed service scan still required"
        );
    }
    Ok(())
}
/// Restores only still-matching recorded device policy; preserves foreign/admin changes.
pub(crate) fn restore() -> Result<(), NativeError> {
    let mut records = read_records().inspect_err(|error| {
        eprintln!("OpenRDX removal permission failure: phase=journal-read reason={error:?}");
    })?;
    let set = open_device_info_set()?;
    for candidate in enumerate_disk_candidates()? {
        let Some(record) = records
            .devices
            .iter()
            .find(|v| v.instance == candidate.instance_id)
        else {
            continue;
        };
        let mut device = device_for(&candidate).inspect_err(|error| {
            eprintln!("OpenRDX removal permission failure: phase=device-open reason={error:?}");
        })?;
        let serial = rdx_identity(&mut device).inspect_err(|error| {
            eprintln!("OpenRDX removal permission failure: phase=device-identity reason={error:?}");
        })?;
        let info = instance_info(&set, &candidate.instance_id)?;
        device.revalidate_exact()?;
        let current = instance_policy(&set, &info)?;
        // Volume cleanup may resume after a previous empty-dock removal already
        // restored the disk. A foreign parent policy is never admitted.
        if !crate::safe_device_acl_repair(
            &record.instance,
            &record.serial,
            &record.installed,
            record.previous.as_deref(),
            &candidate.instance_id,
            &serial,
            current.as_deref(),
        ) {
            continue;
        }
        if let Some(effective) = &record.effective {
            let disk_policy = disk_policy_handle(&device)?;
            let mut effective = effective.clone();
            effective.previous = live_policy::canonical(&effective.previous)?;
            effective.installed = live_policy::canonical(&effective.installed)?;
            let current = live_policy::read(kernel_handle(&disk_policy))?;
            if let Some(previous) = effective.restore_target(&current) {
                revalidate_present_identity(&device.identity, &disk_policy)?;
                live_policy::replace(kernel_handle(&disk_policy), &current, previous)?;
            }
            device.revalidate_exact()?;
        }
        if crate::safe_device_acl_restore(
            &record.instance,
            &record.serial,
            &record.installed,
            &candidate.instance_id,
            &serial,
            current.as_deref().unwrap_or(""),
        ) {
            set_instance_policy(&set, &info, record.previous.as_deref()).inspect_err(|error| {
                eprintln!(
                    "OpenRDX removal permission failure: phase=device-policy reason={error:?}"
                );
            })?;
            if instance_policy(&set, &info)? != record.previous {
                return Err(NativeError::AccessDenied);
            }
        }
        let volume_set = volume_info_set()?;
        for volume in mapped_volumes_for_device(&volume_set, &device, candidate.disk_number)
            .inspect_err(|error| {
                eprintln!(
                    "OpenRDX removal permission failure: phase=volume-mapping reason={error:?}"
                );
            })?
        {
            let Some(recorded) = record.volumes.iter().find(|v| {
                v.instance == volume.instance && v.topology == topology_key(&volume.topology)
            }) else {
                continue;
            };
            if let Some(effective) = &recorded.effective {
                device.revalidate_exact()?;
                if super::volumes::volume_topology(kernel_handle(&volume.handle))?
                    != volume.topology
                {
                    return Err(NativeError::DeviceRemoved);
                }
                let current = live_policy::read(kernel_handle(&volume.handle))?;
                let mut effective = effective.clone();
                effective.previous = live_policy::canonical(&effective.previous)?;
                effective.installed = live_policy::canonical(&effective.installed)?;
                if let Some(previous) = effective.restore_target(&current) {
                    live_policy::replace(kernel_handle(&volume.handle), &current, previous)?;
                }
            }
            if instance_policy(&volume_set, &volume.info)?.as_deref()
                == Some(recorded.installed.as_str())
            {
                device.revalidate_exact()?;
                if super::volumes::volume_topology(kernel_handle(&volume.handle))?
                    != volume.topology
                {
                    return Err(NativeError::DeviceRemoved);
                }
                if instance_policy(&volume_set, &volume.info)?.as_deref()
                    != Some(recorded.installed.as_str())
                {
                    continue;
                }
                set_instance_policy(&volume_set, &volume.info, recorded.previous.as_deref()).inspect_err(|error| {
                    eprintln!("OpenRDX removal permission failure: phase=volume-policy reason={error:?}");
                })?;
                if instance_policy(&volume_set, &volume.info)? != recorded.previous {
                    return Err(NativeError::AccessDenied);
                }
            }
        }
    }
    // Disconnected device records remain protected for later administrator repair;
    // removal does not invent a device instance or overwrite another policy.
    crate::volume_privilege::journal::restore(&mut VolumeRightJournal(&mut records)).inspect_err(
        |error| {
            eprintln!(
                "OpenRDX removal permission failure: phase=volume-privilege reason={error:?}"
            );
        },
    )?;
    Ok(())
}

/// Opens ACL authority only after positive RDX identity and rebinds both handles.
/// The disk number comes from the retained exact SetupAPI proof, never an IPC path.
fn disk_policy_handle(device: &NativeDevice) -> Result<KernelHandle, NativeError> {
    device.revalidate_exact()?;
    let path = wide_null(OsStr::new(&format!(
        r"\\.\PhysicalDrive{}",
        device.identity.disk_number()
    )));
    let handle = open_path(
        &path,
        READ_CONTROL.0 | windows::Win32::Storage::FileSystem::WRITE_DAC.0,
    )?;
    revalidate_present_identity(&device.identity, &handle)?;
    device.revalidate_exact()?;
    Ok(handle)
}

#[cfg(test)]
mod privilege_journal_tests {
    use super::*;

    /// Older device journals remain readable and live restoration evidence round trips.
    #[test]
    fn physical_device_live_policy_preserves_legacy_and_original_evidence() {
        let mut record: DevicePolicy = serde_json::from_str(r#"{"instance":"fixture","serial":"123","previous":null,"installed":"registry-grant","volumes":[]}"#).unwrap();
        assert!(record.effective.is_none());
        record.effective = Some(
            crate::effective_volume_policy::EffectiveVolumePolicy::plan(
                None,
                "original".into(),
                |_| Ok("live-grant".into()),
            )
            .unwrap(),
        );
        let repaired: DevicePolicy =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        let policy = repaired.effective.unwrap();
        assert_eq!(policy.previous, "original");
        assert_eq!(policy.restore_target("live-grant"), Some("original"));
        assert_eq!(policy.restore_target("administrator-change"), None);
    }

    /// Legacy journals mean unrecorded, never an inferred pre-existing privilege.
    #[test]
    fn legacy_device_policy_requires_volume_right_enrollment() {
        let record: PreviousPolicy =
            serde_json::from_str(r#"{"schemaVersion":1,"devices":[]}"#).unwrap();
        assert_eq!(record.previous_volume_maintenance_right, None);
    }

    /// Repair round trips keep original privilege ownership for safe uninstall.
    #[test]
    fn volume_right_journal_preserves_both_prior_states() {
        for previous in [false, true] {
            let record = PreviousPolicy {
                schema_version: 1,
                previous_volume_maintenance_right: Some(previous),
                devices: Vec::new(),
            };
            let encoded = serde_json::to_vec(&record).unwrap();
            let restored: PreviousPolicy = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(restored.previous_volume_maintenance_right, Some(previous));
        }
    }
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
/// Defers only installer volume ACL work while an exactly retained RDX dock is
/// not ready. Captures the result before post-query revalidation even on failure.
fn mapped_volumes_for_device(
    set: &DeviceInfoSet,
    device: &NativeDevice,
    disk_number: u32,
) -> Result<Vec<MappedVolume>, NativeError> {
    device.revalidate_exact()?;
    let mut generation = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: exact retained device and writable scalar output for a query-only IOCTL.
    let result = unsafe {
        DeviceIoControl(
            kernel_handle(&device.handle),
            IOCTL_STORAGE_CHECK_VERIFY2,
            None,
            0,
            Some((&raw mut generation).cast()),
            size_of::<u32>() as u32,
            Some(&mut returned),
            None,
        )
    }
    .map_err(map_windows_error);
    device.revalidate_exact()?;
    if result.is_ok() && returned != 0 && returned as usize != size_of::<u32>() {
        return Err(NativeError::EvidenceIncomplete);
    }
    if !volume_media_ready(result)? {
        // No volume authority is fabricated from an empty removable-drive extent.
        // Retained journal entries remain available for later Repair/removal.
        eprintln!(
            "OpenRDX volume permission work deferred: cartridge media is not ready; recorded policies preserved"
        );
        return Ok(Vec::new());
    }
    mapped_volumes(set, disk_number)
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
            // Only a verified target needs ACL-query rights. Re-prove its exact
            // topology and instance across the new handle; unrelated volumes keep
            // the zero-access metadata query used by strict classification.
            let policy_handle = open_path(
                &path,
                READ_CONTROL.0 | windows::Win32::Storage::FileSystem::WRITE_DAC.0,
            )?;
            if super::volumes::volume_topology(kernel_handle(&policy_handle))? != topology
                || device_instance_id(set, &info)? != instance
            {
                return Err(NativeError::DeviceRemoved);
            }
            mapped.push(MappedVolume {
                instance,
                info,
                handle: policy_handle,
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

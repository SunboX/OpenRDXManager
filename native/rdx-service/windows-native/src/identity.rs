// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable exact-instance and volume-identity proofs.

use std::ffi::OsStr;
use std::mem::size_of;

use super::NativeError;

// Microsoft FILE_DEVICE_* values from winioctl.h, kept portable for host-free tests.
const FILE_DEVICE_CD_ROM: u32 = 0x0000_0002;
const FILE_DEVICE_DISK: u32 = 0x0000_0007;

/// Exact service-owned reopen identity recovered from an opaque recipe.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct DecodedRecipe {
    pub(super) disk_number: u32,
    pub(super) instance_id: String,
}

/// Decodes only the versioned disk-number and UTF-16 instance recipe.
pub(super) fn decode_recipe(recipe: &OsStr) -> Result<DecodedRecipe, NativeError> {
    let recipe = recipe.to_str().ok_or(NativeError::InvalidRequest)?;
    let mut fields = recipe.split(':');
    let version = fields.next().ok_or(NativeError::InvalidRequest)?;
    let disk = fields.next().ok_or(NativeError::InvalidRequest)?;
    let encoded_instance = fields.next().ok_or(NativeError::InvalidRequest)?;
    if version != "win1"
        || disk.len() != 8
        || encoded_instance.is_empty()
        || encoded_instance.len() % 4 != 0
        || encoded_instance.len() > 800
        || fields.next().is_some()
    {
        return Err(NativeError::InvalidRequest);
    }

    let disk_number = u32::from_str_radix(disk, 16).map_err(|_| NativeError::InvalidRequest)?;
    let mut units = Vec::with_capacity(encoded_instance.len() / 4);
    for chunk in encoded_instance.as_bytes().chunks_exact(4) {
        let digits = std::str::from_utf8(chunk).map_err(|_| NativeError::InvalidRequest)?;
        units.push(u16::from_str_radix(digits, 16).map_err(|_| NativeError::InvalidRequest)?);
    }
    let instance_id = String::from_utf16(&units).map_err(|_| NativeError::InvalidRequest)?;
    if instance_id.trim() != instance_id || instance_id.chars().any(char::is_control) {
        return Err(NativeError::InvalidRequest);
    }
    Ok(DecodedRecipe {
        disk_number,
        instance_id,
    })
}

/// Retained exact instance recipe plus the device number proven at handle open.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct DeviceIdentityProof {
    recipe: DecodedRecipe,
    opened_device_number: u32,
}

impl DeviceIdentityProof {
    /// Binds the recipe to the device number observed from the new live handle.
    pub(super) fn new(
        recipe: DecodedRecipe,
        opened_device_number: u32,
    ) -> Result<Self, NativeError> {
        if recipe.disk_number != opened_device_number {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(Self {
            recipe,
            opened_device_number,
        })
    }

    /// Returns the retained exact Plug and Play instance proof.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(super) fn instance_id(&self) -> &str {
        &self.recipe.instance_id
    }

    /// Returns the disk number bound to the exact retained instance recipe.
    #[cfg(windows)]
    pub(super) const fn disk_number(&self) -> u32 {
        self.recipe.disk_number
    }

    /// Revalidates SetupAPI identity and the still-live physical handle together.
    pub(super) fn revalidate(
        &self,
        observed_instance_id: &str,
        observed_interface_disk_number: u32,
        retained_handle_disk_number: u32,
    ) -> Result<(), NativeError> {
        let instance_matches = self.recipe.instance_id == observed_instance_id
            || self
                .recipe
                .instance_id
                .eq_ignore_ascii_case(observed_instance_id);
        if !instance_matches
            || observed_interface_disk_number != self.recipe.disk_number
            || retained_handle_disk_number != self.opened_device_number
            || retained_handle_disk_number != self.recipe.disk_number
        {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(())
    }
}

/// Full `STORAGE_DEVICE_NUMBER` identity copied from one live volume handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StorageDeviceIdentity {
    pub(super) device_type: u32,
    pub(super) device_number: u32,
    pub(super) partition_number: u32,
}

/// Full physical extent copied from one `VOLUME_DISK_EXTENTS` response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VolumeExtent {
    pub(super) disk_number: u32,
    pub(super) starting_offset: i64,
    pub(super) extent_length: i64,
}

/// Exact storage identity and ordered extent topology of one retained handle.
/// Optical volumes retain their identity but have no applicable disk extents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct VolumeTopology {
    pub(super) storage: StorageDeviceIdentity,
    pub(super) extents: Vec<VolumeExtent>,
}

/// Queries disk extents only after a successful same-handle disk-type proof.
///
/// Optical volumes still enter the complete inventory with their mount paths,
/// but the disk-only IOCTL does not apply to them. Unknown types and identity
/// failures are not treated as unrelated; every actual disk query stays strict.
pub(super) fn query_volume_topology(
    storage: Result<StorageDeviceIdentity, NativeError>,
    read_extents: impl FnOnce() -> Result<Vec<VolumeExtent>, NativeError>,
) -> Result<VolumeTopology, NativeError> {
    let storage = storage?;
    let extents = match storage.device_type {
        FILE_DEVICE_DISK => read_extents()?,
        FILE_DEVICE_CD_ROM => Vec::new(),
        _ => return Err(NativeError::EnumerationFailed),
    };
    Ok(VolumeTopology { storage, extents })
}

impl VolumeTopology {
    /// Rejects any storage or ordered-extent change after the handle was pinned.
    #[cfg(test)]
    pub(super) fn revalidate(&self, current: &Self) -> Result<(), NativeError> {
        if self != current {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(())
    }
}

/// Complete-inspection disposition for one enumerated Windows volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum VolumeMembership {
    /// The inspected topology does not name the retained target disk.
    Unrelated,
    /// One exact, non-spanned topology belongs solely to the target disk.
    Target(VolumeTopology),
}

/// Propagates every inspection failure and admits only one exact target extent.
pub(super) fn classify_volume_probe(
    probe: Result<VolumeTopology, NativeError>,
    expected_disk_number: u32,
) -> Result<VolumeMembership, NativeError> {
    let topology = probe?;
    // Device numbers belong to separate type namespaces: CD-ROM 0 is never disk 0.
    if topology.storage.device_type == FILE_DEVICE_CD_ROM && topology.extents.is_empty() {
        return Ok(VolumeMembership::Unrelated);
    }
    if topology.storage.device_type != FILE_DEVICE_DISK {
        return Err(NativeError::EnumerationFailed);
    }
    if topology.extents.is_empty()
        || topology
            .extents
            .iter()
            .any(|extent| extent.starting_offset < 0 || extent.extent_length <= 0)
    {
        return Err(NativeError::EnumerationFailed);
    }

    if topology.extents.len() != 1
        || topology.storage.device_number != topology.extents[0].disk_number
    {
        return Err(NativeError::EnumerationFailed);
    }
    if topology.storage.device_number != expected_disk_number {
        return Ok(VolumeMembership::Unrelated);
    }
    Ok(VolumeMembership::Target(topology))
}

#[cfg(test)]
mod volume_probe_tests;

/// Computes the exact bounded allocation for a variable extent array.
pub(super) fn volume_extent_buffer_length(
    count: u32,
    extent_offset: usize,
    extent_stride: usize,
    maximum: usize,
) -> Result<usize, NativeError> {
    if count == 0 || extent_offset < size_of::<u32>() || extent_stride < 20 {
        return Err(NativeError::EnumerationFailed);
    }
    let required = extent_offset
        .checked_add(
            (count as usize)
                .checked_mul(extent_stride)
                .ok_or(NativeError::ResourceLimit)?,
        )
        .ok_or(NativeError::ResourceLimit)?;
    if required > maximum {
        return Err(NativeError::ResourceLimit);
    }
    Ok(required)
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete, internally consistent renderer-safe device snapshots.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, de};

use super::{
    Capability, DeviceId, DeviceIdentity, DiscoveryRevision, DisplayText, DriveStatus, Media,
    MediaState, OperationKind,
};

/// Renderer-safe snapshot of one validated RDX device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceSnapshot {
    /// Opaque stable RDX device identifier.
    pub id: DeviceId,
    /// Service-owned revision for stale-request rejection.
    pub revision: DiscoveryRevision,
    /// Bounded vendor display text.
    pub vendor: DisplayText,
    /// Bounded product display text.
    pub product: DisplayText,
    /// Bounded device serial display text.
    pub serial: DisplayText,
    /// Current drive status and known product facts.
    pub drive: DriveStatus,
    /// Cartridge data, if present, with no OS path.
    pub media: Option<Media>,
    /// State derived from the presence of `media`.
    pub media_state: MediaState,
    /// Sparse map of only published high-level operation capabilities.
    pub capabilities: BTreeMap<OperationKind, Capability>,
}

impl DeviceSnapshot {
    /// Returns the revisioned identity used for trusted stale-request comparisons.
    pub fn identity(&self) -> DeviceIdentity {
        DeviceIdentity {
            id: self.id.clone(),
            revision: self.revision,
        }
    }

    /// Reports whether the serialized media fields agree with their normalized state.
    pub fn has_consistent_media_state(&self) -> bool {
        matches!(
            (&self.media, self.media_state),
            (None, MediaState::NoMedia) | (Some(_), MediaState::Present)
        )
    }

    /// Reports whether complete typed status and every legacy duplicate agree.
    pub fn has_consistent_status_details(&self) -> bool {
        self.drive.has_consistent_legacy_projection()
            && self.drive.details.vendor.reported_value() == Some(&self.vendor)
            && self.drive.details.product.reported_value() == Some(&self.product)
            && self.drive.details.serial_number.reported_value() == Some(&self.serial)
            && self
                .media
                .as_ref()
                .is_none_or(Media::has_consistent_status_details)
    }
}

/// Private borrowed representation used only after snapshot consistency checks.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSnapshotRef<'a> {
    id: &'a DeviceId,
    revision: DiscoveryRevision,
    vendor: &'a DisplayText,
    product: &'a DisplayText,
    serial: &'a DisplayText,
    drive: &'a DriveStatus,
    media: &'a Option<Media>,
    media_state: MediaState,
    capabilities: &'a BTreeMap<OperationKind, Capability>,
}

impl Serialize for DeviceSnapshot {
    /// Serializes only a complete, internally consistent production snapshot.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if !self.has_consistent_media_state() || !self.has_consistent_status_details() {
            return Err(serde::ser::Error::custom("inconsistent device snapshot"));
        }
        DeviceSnapshotRef {
            id: &self.id,
            revision: self.revision,
            vendor: &self.vendor,
            product: &self.product,
            serial: &self.serial,
            drive: &self.drive,
            media: &self.media,
            media_state: self.media_state,
            capabilities: &self.capabilities,
        }
        .serialize(serializer)
    }
}

/// Private strict wire representation used to validate derived media state.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceSnapshotWire {
    id: DeviceId,
    revision: DiscoveryRevision,
    vendor: DisplayText,
    product: DisplayText,
    serial: DisplayText,
    drive: DriveStatus,
    media: Option<Media>,
    media_state: MediaState,
    capabilities: BTreeMap<OperationKind, Capability>,
}

impl TryFrom<DeviceSnapshotWire> for DeviceSnapshot {
    type Error = &'static str;

    /// Converts a strict wire snapshot only when all derived fields agree.
    fn try_from(value: DeviceSnapshotWire) -> Result<Self, Self::Error> {
        let snapshot = Self {
            id: value.id,
            revision: value.revision,
            vendor: value.vendor,
            product: value.product,
            serial: value.serial,
            drive: value.drive,
            media: value.media,
            media_state: value.media_state,
            capabilities: value.capabilities,
        };
        if !snapshot.has_consistent_media_state() || !snapshot.has_consistent_status_details() {
            return Err("device snapshot must contain consistent status details");
        }
        Ok(snapshot)
    }
}

impl<'de> Deserialize<'de> for DeviceSnapshot {
    /// Deserializes only a complete, internally consistent snapshot.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        DeviceSnapshotWire::deserialize(deserializer)?
            .try_into()
            .map_err(de::Error::custom)
    }
}

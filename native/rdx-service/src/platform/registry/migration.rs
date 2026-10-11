// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed vendor source capture and OpenRDX record reads on one retained lease.

use super::ResolvedDevice;

impl super::DeviceRegistry {
    /// Derives only the existing opaque target ID from a validated saved source.
    /// This pure lookup key is not live-device or physical-location proof.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn migration_target_id(
        capture: &crate::migration::MigrationCapture,
    ) -> Result<crate::model::DeviceId, super::PlatformError> {
        crate::migration::validate_source_capture(capture)
            .map_err(|_| super::PlatformError::StaleDeviceBinding)?;
        let serial = std::str::from_utf8(&capture.factory[16..26])
            .map_err(|_| super::PlatformError::StaleDeviceBinding)?;
        super::derive_device_id("TANDBERG", "RDX", serial)
    }
}

impl ResolvedDevice<'_> {
    /// Probes the fixed restore extension between fresh exact-identity and empty-bay checks.
    /// Unsupported firmware or incomplete live evidence returns false without mutation.
    pub(crate) fn supports_manufacturing_restore(&mut self) -> bool {
        if self.require_manufacturing_restore_ready().is_err() {
            return false;
        }
        let outcome =
            self.execute_firmware(&crate::protocol::openrdx_manufacturing_restore_capability());
        outcome
            .response()
            .is_some_and(|response| response.data().is_empty())
            && self.require_manufacturing_restore_ready().is_ok()
    }

    /// Captures every manufacturing-sector byte between live exact-identity and bay checks.
    /// Raw erased or damaged records remain admissible for original-record recovery.
    pub(crate) fn manufacturing_sector(
        &mut self,
    ) -> Result<zeroize::Zeroizing<[u8; 4096]>, crate::operations::HostPrimitiveError> {
        use crate::operations::HostPrimitiveError;
        self.require_manufacturing_restore_ready()?;
        let mut sector = zeroize::Zeroizing::new([0u8; 4096]);
        for index in 0..32 {
            let command = crate::protocol::openrdx_manufacturing_sector_chunk(index)
                .map_err(|_| HostPrimitiveError::ManufacturingUnreadable)?;
            let outcome = self.execute_firmware(&command);
            let bytes = outcome
                .response()
                .ok_or(HostPrimitiveError::ManufacturingUnreadable)?
                .data();
            if bytes.len() != 128 {
                return Err(HostPrimitiveError::ManufacturingUnreadable);
            }
            let offset = usize::from(index) * 128;
            sector[offset..offset + 128].copy_from_slice(bytes);
        }
        self.require_manufacturing_restore_ready()?;
        Ok(sector)
    }

    /// Restores one valid saved record after a fresh whole-sector compare, then verifies all bytes.
    /// The service must first durably back up `expected` and confirm the selected saved serial.
    /// `allow_identity_change` requires separate operator consent to recover a replacement identity.
    /// Sends at most once and never resets the receiver, including after ambiguous failure.
    pub(crate) fn restore_manufacturing_record(
        &mut self,
        expected: &[u8; 4096],
        desired: &[u8; 256],
        allow_identity_change: bool,
    ) -> Result<(), crate::operations::HostPrimitiveError> {
        use crate::operations::HostPrimitiveError;
        // A valid checksum does not establish that a reconstructed identity is original.
        // Replacing it requires the service's separate explicit recovery confirmation.
        if crate::serial_record::state(expected) == crate::serial_record::RecordState::Valid
            && !allow_identity_change
            && (desired[8..18] != expected[8..18]
                || desired[8..18] != *self.entry.snapshot.serial.as_str().as_bytes())
        {
            return Err(HostPrimitiveError::ManufacturingInvalid);
        }
        let mut payload = zeroize::Zeroizing::new([0u8; 528]);
        payload[..8].copy_from_slice(b"RDXMFG01");
        payload[8..12].copy_from_slice(&crate::serial_record::crc32(expected).to_le_bytes());
        payload[16..272].copy_from_slice(&expected[..256]);
        payload[272..].copy_from_slice(desired);
        let command = crate::protocol::openrdx_restore_manufacturing(&payload[..])
            .map_err(|_| HostPrimitiveError::ManufacturingInvalid)?;
        self.require_manufacturing_restore_ready()?;
        if !self.supports_manufacturing_restore() {
            return Err(HostPrimitiveError::ManufacturingRestoreUnsupported);
        }
        if self.manufacturing_sector()?.as_ref() != expected {
            return Err(HostPrimitiveError::ManufacturingChanged);
        }
        let outcome = self.execute_firmware(&command);
        match outcome {
            crate::transport::CommandDispatch::NotSent(_)
            | crate::transport::CommandDispatch::DefinitelyRejected(_) => {
                return Err(HostPrimitiveError::ManufacturingUnreadable);
            }
            crate::transport::CommandDispatch::Succeeded(response)
                if response.data().is_empty() => {}
            _ => return Err(HostPrimitiveError::ManufacturingRestoreUnknown),
        }
        // Once a write succeeds or may have run, incomplete verification cannot
        // release the actor's recovery gate as an ordinary read failure.
        let actual = self
            .manufacturing_sector()
            .map_err(|_| HostPrimitiveError::ManufacturingRestoreUnknown)?;
        if actual[..256] != desired[..] || actual[256..] != expected[256..] {
            return Err(HostPrimitiveError::ManufacturingRestoreUnknown);
        }
        Ok(())
    }

    /// Requires a supported receiver, freshly absent logical media, and an idle empty physical bay.
    fn require_manufacturing_restore_ready(
        &mut self,
    ) -> Result<(), crate::operations::HostPrimitiveError> {
        use crate::operations::HostPrimitiveError;
        let (family, revision, media) = self
            .firmware_facts()
            .map_err(|_| HostPrimitiveError::ManufacturingUnreadable)?;
        if family != crate::firmware::ProductFamily::Usb3Sata3
            || !revision.has_openrdx_update_receiver()
        {
            return Err(HostPrimitiveError::ManufacturingRestoreUnsupported);
        }
        if media {
            return Err(HostPrimitiveError::MediaPresent);
        }
        let outcome = self.execute_firmware(&crate::protocol::openrdx_mechanism_diagnostics());
        let bytes = outcome
            .response()
            .ok_or(HostPrimitiveError::ManufacturingUnreadable)?
            .data();
        if bytes.len() != 128 || &bytes[..4] != b"RDXM" || bytes[4] != 1 {
            return Err(HostPrimitiveError::ManufacturingUnreadable);
        }
        // The active-low GPIO5 cartridge sensor is independent of the mechanism CAM input.
        if bytes[10] & 0x20 == 0 {
            return Err(HostPrimitiveError::MediaPresent);
        }
        if bytes[5] != 0 {
            return Err(HostPrimitiveError::Busy);
        }
        Ok(())
    }

    /// Captures exact raw manufacturing bytes between full same-lease identity checks.
    /// This ordinary-update path accepts supported OpenRDX receivers independently
    /// of the migration profile's deliberately pinned 0107 readback contract.
    pub(crate) fn manufacturing_record(
        &mut self,
    ) -> Result<
        crate::firmware::manufacturing::ManufacturingRecord,
        crate::operations::HostPrimitiveError,
    > {
        use crate::operations::HostPrimitiveError;
        let unreadable = HostPrimitiveError::ManufacturingUnreadable;
        let (family, revision, media) = self.firmware_facts().map_err(|_| unreadable)?;
        if family != crate::firmware::ProductFamily::Usb3Sata3
            || !revision.has_openrdx_update_receiver()
            || media
        {
            return Err(unreadable);
        }
        let mut bytes = zeroize::Zeroizing::new([0u8; 256]);
        for (part, command) in [
            crate::protocol::openrdx_manufacturing_record_first(),
            crate::protocol::openrdx_manufacturing_record_second(),
        ]
        .iter()
        .enumerate()
        {
            let outcome = self.execute_firmware(command);
            let response = outcome.response().ok_or(unreadable)?;
            if response.data().len() != 128 {
                return Err(unreadable);
            }
            bytes[part * 128..(part + 1) * 128].copy_from_slice(response.data());
        }
        self.revalidate_identity().map_err(|_| unreadable)?;
        Ok(crate::firmware::manufacturing::ManufacturingRecord::capture(bytes))
    }

    /// Captures only the fixed identity/state reads through this retained lease.
    ///
    /// The source or readback profile validates revision and record contents;
    /// this boundary also brackets the capture with exact INQUIRY equality.
    pub fn migration_capture(
        &mut self,
    ) -> Result<crate::migration::MigrationCapture, crate::migration::MigrationError> {
        use crate::migration::MigrationError;
        if !self.active {
            return Err(MigrationError::InvalidCapture);
        }
        self.revalidate_identity()
            .map_err(|_| MigrationError::InvalidCapture)?;
        let usb = self.lease.handle.migration_usb_identity()?;
        crate::migration::capture::collect(usb, &mut |command| self.execute_firmware(command))
    }

    /// Reads the three fixed OpenRDX SPI record ranges through this retained lease.
    pub fn migration_readback(
        &mut self,
    ) -> Result<crate::migration::MigrationReadback, crate::migration::MigrationError> {
        use crate::migration::MigrationError;
        if !self.active {
            return Err(MigrationError::ReadbackMismatch);
        }
        self.revalidate_identity()
            .map_err(|_| MigrationError::ReadbackMismatch)?;
        let usb = self.lease.handle.migration_usb_identity()?;
        crate::migration::readback::collect(usb, &mut |command| self.execute_firmware(command))
    }
}

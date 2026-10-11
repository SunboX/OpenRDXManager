// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed vendor-only source capture. OpenRDX readback uses its separate SPI reader.

use super::{MigrationCapture, MigrationError, MigrationUsbIdentity};
use crate::protocol::{
    Command, InquiryPage, inquiry, log_sense, mode_sense, vendor_0283_factory_info,
    vendor_0283_usb_identity,
};
use crate::transport::CommandDispatch;

/// Reads complete responses, stopping on the first failure or changing identity.
///
/// The caller retains one exact active lease for every dispatch. No arbitrary
/// opcode, offset, reset, configuration change or write is available here.
pub(crate) fn collect(
    usb: MigrationUsbIdentity,
    dispatch: &mut impl FnMut(&Command) -> CommandDispatch,
) -> Result<MigrationCapture, MigrationError> {
    let inquiry_command = inquiry(InquiryPage::Standard);
    let first = read(&inquiry_command, 64, 64, dispatch)?;
    // A foreign revision cannot cause additional private vendor reads.
    if &first[32..36] != b"0283" {
        return Err(MigrationError::InvalidCapture);
    }
    let factory = read(&vendor_0283_factory_info(), 172, 172, dispatch)?;
    let usb_response = read(&vendor_0283_usb_identity(), 32, 32, dispatch)?;
    let drive_log = read(
        &log_sense(0x20).expect("fixed documented page"),
        4,
        254,
        dispatch,
    )?;
    let mode_sense = read(
        &mode_sense(0x34).expect("fixed documented page"),
        8,
        254,
        dispatch,
    )?;
    if read(&inquiry_command, 64, 64, dispatch)? != first {
        return Err(MigrationError::InvalidCapture);
    }
    Ok(MigrationCapture {
        usb,
        inquiry: first,
        factory,
        usb_response,
        drive_log,
        mode_sense,
    })
}

/// Copies only actual successful receive bytes after enforcing the fixed bounds.
fn read(
    command: &Command,
    minimum: usize,
    maximum: usize,
    dispatch: &mut impl FnMut(&Command) -> CommandDispatch,
) -> Result<Vec<u8>, MigrationError> {
    let outcome = dispatch(command);
    let response = outcome.response().ok_or(MigrationError::InvalidCapture)?;
    if !(minimum..=maximum).contains(&response.data().len()) {
        return Err(MigrationError::InvalidCapture);
    }
    Ok(response.data().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DataDirection;
    use crate::transport::{TransportError, TransportResponse};

    /// Synthetic observations test sequence ownership without opening hardware.
    fn fixture() -> (MigrationUsbIdentity, Vec<Vec<u8>>) {
        let usb = MigrationUsbIdentity {
            serial: "001234567890".to_owned(),
            location_id: 0x200000,
            vendor_id: 0x1a5a,
            product_id: 6,
        };
        let mut inquiry = vec![0; 64];
        inquiry[32..36].copy_from_slice(b"0283");
        (
            usb,
            vec![
                inquiry.clone(),
                vec![0; 172],
                vec![0; 32],
                vec![0; 56],
                vec![0; 32],
                inquiry,
            ],
        )
    }

    /// Only the vendor receiver supports this source capture command vocabulary.
    #[test]
    fn sequence_is_only_six_fixed_reads() {
        let (usb, mut data) = fixture();
        let mut calls = Vec::new();
        let result = collect(usb, &mut |command| {
            assert_eq!(command.direction(), DataDirection::FromDevice);
            calls.push(command.cdb().to_vec());
            CommandDispatch::Succeeded(TransportResponse::new(data.remove(0)).unwrap())
        });
        assert!(result.is_ok());
        assert_eq!(
            calls.iter().map(|cdb| cdb[0]).collect::<Vec<_>>(),
            [0x12, 0x3c, 0x3c, 0x4d, 0x5a, 0x12]
        );
        assert_eq!(calls[0], calls[5]);
        assert_eq!(calls[1][2], 2);
        assert_eq!(calls[2][2], 10);
    }

    /// No later read, reset or cleanup command follows an ambiguous failure.
    #[test]
    fn every_read_failure_stops_immediately() {
        for failure in 0..6 {
            let (usb, mut data) = fixture();
            let mut calls = 0;
            assert!(
                collect(usb, &mut |_| {
                    let index = calls;
                    calls += 1;
                    if index == failure {
                        CommandDispatch::CompletionUnknown(TransportError::Timeout)
                    } else {
                        CommandDispatch::Succeeded(TransportResponse::new(data.remove(0)).unwrap())
                    }
                })
                .is_err()
            );
            assert_eq!(calls, failure + 1);
        }
    }

    /// Short records and a changed INQUIRY can never become a source profile.
    #[test]
    fn incomplete_or_changed_observations_are_rejected() {
        for changed in 0..6 {
            let (usb, mut data) = fixture();
            data[changed].clear();
            assert!(
                collect(usb, &mut |_| CommandDispatch::Succeeded(
                    TransportResponse::new(data.remove(0)).unwrap()
                ))
                .is_err()
            );
        }
        let (usb, mut data) = fixture();
        data[5][1] ^= 1;
        assert!(
            collect(usb, &mut |_| CommandDispatch::Succeeded(
                TransportResponse::new(data.remove(0)).unwrap()
            ))
            .is_err()
        );
    }
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Execute the production polling loop against a local COM async object.

use std::cell::Cell;
use std::rc::Rc;
use windows::Win32::Storage::VirtualDiskService::{
    IVdsAsync, IVdsAsync_Impl, VDS_ASYNC_OUTPUT, VDS_E_OPERATION_PENDING,
};
use windows::core::{HRESULT, Result};

#[windows::core::implement(IVdsAsync)]
struct PendingJob {
    polls: Rc<Cell<u32>>,
    cancellations: Rc<Cell<u32>>,
    terminal: HRESULT,
}

impl IVdsAsync_Impl for PendingJob_Impl {
    /// Counts cancellation to detect premature abandonment of a pending job.
    fn Cancel(&self) -> Result<()> {
        self.cancellations.set(self.cancellations.get() + 1);
        Ok(())
    }

    /// The production loop must use nonblocking QueryStatus rather than Wait.
    fn Wait(&self, _result: *mut HRESULT, _output: *mut VDS_ASYNC_OUTPUT) -> Result<()> {
        Err(HRESULT(0x8000_4001_u32 as i32).into())
    }

    /// Returns pending first as the method error, then as the operation result.
    fn QueryStatus(&self, result: *mut HRESULT, percent: *mut u32) -> Result<()> {
        let poll = self.polls.get();
        self.polls.set(poll + 1);
        if poll == 0 {
            return Err(VDS_E_OPERATION_PENDING.into());
        }
        // SAFETY: QueryStatus's COM contract supplies valid writable outputs.
        unsafe {
            result.write(if poll == 1 {
                VDS_E_OPERATION_PENDING
            } else {
                self.terminal
            });
            percent.write(if poll == 1 { 50 } else { 100 });
        }
        Ok(())
    }
}

/// The actual Windows wrapper and production loop must survive both pending forms.
#[test]
fn production_loop_waits_for_completion_after_method_pending() {
    let polls = Rc::new(Cell::new(0));
    let cancellations = Rc::new(Cell::new(0));
    let operation: IVdsAsync = PendingJob {
        polls: polls.clone(),
        cancellations: cancellations.clone(),
        terminal: HRESULT(0),
    }
    .into();
    let mut result = HRESULT(0);
    assert_eq!(super::wait_async_bounded(&operation, &mut result), Ok(()));
    assert_eq!(polls.get(), 3);
    assert_eq!(cancellations.get(), 0);
    assert_eq!(result, HRESULT(0));
}

/// A real terminal failure still propagates after pending, without claiming success.
#[test]
fn production_loop_preserves_terminal_failure_after_pending() {
    let polls = Rc::new(Cell::new(0));
    let operation: IVdsAsync = PendingJob {
        polls: polls.clone(),
        cancellations: Rc::new(Cell::new(0)),
        terminal: HRESULT(0x8007_0005_u32 as i32),
    }
    .into();
    let mut result = HRESULT(0);
    assert_eq!(
        super::wait_async_bounded(&operation, &mut result),
        Err(crate::NativeError::AccessDenied)
    );
    assert_eq!(polls.get(), 3);
}

/// Copies test-owned, terminated strings through the production native parser.
fn parse_guid_paths(paths: &[&str]) -> std::result::Result<Vec<String>, crate::NativeError> {
    let mut strings = paths
        .iter()
        .map(|path| path.encode_utf16().chain([0]).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let mut pointers = strings
        .iter_mut()
        .map(|string| windows::core::PWSTR(string.as_mut_ptr()))
        .collect::<Vec<_>>();
    // SAFETY: each pointer names a live NUL-terminated allocation and the
    // declared count is exactly the size of the live pointer array.
    unsafe { super::copy_vds_guid_paths(pointers.as_mut_ptr(), pointers.len() as u32) }
}

const SYSTEM_VOLUME: &str = r"\\?\Volume{11111111-2222-4333-8444-555555555555}\";
const TARGET_VOLUME: &str = r"\\?\Volume{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}\";

/// Real VDS can repeat an unrelated system-volume alias during RDX lookup.
#[test]
fn duplicate_unrelated_guid_alias_does_not_abort_exact_target_lookup() {
    let unrelated = parse_guid_paths(&[SYSTEM_VOLUME, SYSTEM_VOLUME]).unwrap();
    let expected = TARGET_VOLUME.to_ascii_uppercase();
    assert_eq!(unrelated, vec![SYSTEM_VOLUME.to_ascii_uppercase()]);
    assert!(!unrelated.contains(&expected));
    let target = parse_guid_paths(&[TARGET_VOLUME]).unwrap();
    assert_eq!(target.iter().filter(|path| **path == expected).count(), 1);
}

/// Repeated aliases within one COM volume prove the same exact GUID once.
#[test]
fn target_aliases_are_deduplicated_after_case_normalization() {
    let uppercase = TARGET_VOLUME.to_ascii_uppercase();
    assert_eq!(
        parse_guid_paths(&[TARGET_VOLUME, &uppercase]),
        Ok(vec![uppercase])
    );
}

/// Distinct valid GUID aliases remain distinct rather than becoming a target.
#[test]
fn distinct_volume_aliases_are_preserved() {
    let paths = parse_guid_paths(&[SYSTEM_VOLUME, TARGET_VOLUME]).unwrap();
    assert_eq!(paths.len(), 2);
    assert!(paths.contains(&SYSTEM_VOLUME.to_ascii_uppercase()));
    assert!(paths.contains(&TARGET_VOLUME.to_ascii_uppercase()));
}

/// A malformed entry still rejects the entire result even after valid duplicates.
#[test]
fn duplicate_aliases_do_not_hide_malformed_guid_evidence() {
    for invalid in ["", "F:\\", r"\\?\Volume{invalid}\"] {
        assert_eq!(
            parse_guid_paths(&[SYSTEM_VOLUME, SYSTEM_VOLUME, invalid]),
            Err(crate::NativeError::EvidenceIncomplete)
        );
    }
}

/// A counted null entry remains invalid; it cannot be treated as an alias.
#[test]
fn counted_null_guid_path_is_rejected() {
    let mut pointers = [windows::core::PWSTR::null()];
    // SAFETY: the declared slot exists; the parser must reject its null pointer
    // before dereferencing it.
    assert_eq!(
        unsafe { super::copy_vds_guid_paths(pointers.as_mut_ptr(), 1) },
        Err(crate::NativeError::EvidenceIncomplete)
    );
}

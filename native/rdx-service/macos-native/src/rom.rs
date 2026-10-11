// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed, one-attempt TI ROM programming with explicit caller-owned journaling.

use crate::{NativeError, RomCandidate};

/// Failure facts for one explicit ROM operation, never proof of SPI contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RomFailure {
    /// Sanitized reason for the rejected or incomplete operation.
    pub error: NativeError,
    /// Whether the native transfer API was invoked for this operation.
    pub attempted: bool,
    /// Whether this operation may have changed hardware without proven completion.
    pub outcome_unknown: bool,
    /// Known OS transfer count for this operation; absent when unreported/unusable.
    pub transferred: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum Command {
    Identify = 1,
    Setup = 2,
    Program = 3,
    Reset = 4,
}

impl RomFailure {
    /// Records a local rejection with no transfer invocation and a known zero count.
    fn rejected(error: NativeError) -> Self {
        Self {
            error,
            attempted: false,
            outcome_unknown: false,
            transferred: Some(0),
        }
    }
}

/// One exact-parent native ROM lease. Creating/importing the module sends no IO.
///
/// `open` binds IOHID and the vendor bulk interface without capture or seizure.
/// The caller must validate its personalized pinned image and durably journal
/// each intent before invoking setup, program, or reset. Ordinary ROM setup
/// erases the whole SPI chip. This transport does not establish preservation.
pub struct RomSession {
    driver: Driver<NativeTransport>,
}

impl RomSession {
    /// Opens the single global TI ROM device at this exact captured location.
    ///
    /// # Errors
    /// Missing/ambiguous devices, changed ancestry, claimed interfaces, or missing
    /// active HID/vendor descriptors reject without setup, program, or reset.
    pub fn open(location_id: u32) -> Result<Self, NativeError> {
        if location_id == 0 {
            return Err(NativeError::InvalidRequest);
        }
        Ok(Self {
            driver: Driver::new(NativeTransport::open(location_id, None)?),
        })
    }

    /// Opens exactly one previously observed ROM parent, allowing other ROM devices.
    ///
    /// # Errors
    /// Re-enumeration, replacement, changed ancestry or unavailable interfaces reject
    /// without a ROM report or programming transfer. Every subsequent command also
    /// revalidates this exact epoch; the generic ROM serial proves no unit identity.
    pub fn open_selected(candidate: &RomCandidate) -> Result<Self, NativeError> {
        Ok(Self {
            driver: Driver::new(NativeTransport::open(
                candidate.location_id(),
                Some(candidate),
            )?),
        })
    }

    /// Sends only feature GET A1/01, value 0300, length 2, requiring bytes 60 92.
    ///
    /// # Errors
    /// Invalid sequence/timeouts, native failure, or a different/short response
    /// reject identification. A native attempt cannot be repeated in this lease.
    pub fn identify(&mut self, timeout_ms: u32) -> Result<(), NativeError> {
        self.driver
            .advance(Command::Identify, &[], timeout_ms)
            .map(|_| ())
            .map_err(|failure| failure.error)
    }

    /// Sends the nine-byte output report 01 followed by eight zeroes, once.
    ///
    /// # Errors
    /// Requires identification and a 1..=120000 millisecond timeout. Any attempted
    /// failure makes recovery state unknown and prohibits further commands.
    pub fn setup(&mut self, timeout_ms: u32) -> Result<(), RomFailure> {
        self.driver
            .advance(Command::Setup, &[], timeout_ms)
            .map(|_| ())
    }

    /// Sends the complete 22..=65535-byte image in one bulk OUT transfer on 02.
    ///
    /// # Errors
    /// Requires completed setup and finite timeout. Short/failed transfers retain
    /// a known partial OS count but never resend a tail or authorize reset.
    /// Successful OS transfer completion does not verify SPI contents.
    pub fn program(&mut self, image: &[u8], timeout_ms: u32) -> Result<usize, RomFailure> {
        self.driver.advance(Command::Program, image, timeout_ms)
    }

    /// Sends the nine-byte output report 02 followed by eight zeroes, once.
    ///
    /// # Errors
    /// Requires complete programming and finite timeout. An uncertain result
    /// remains unknown; release never sends reset, retries, or reconnects.
    pub fn reset(&mut self, timeout_ms: u32) -> Result<(), RomFailure> {
        self.driver
            .advance(Command::Reset, &[], timeout_ms)
            .map(|_| ())
    }
}

impl std::fmt::Debug for RomSession {
    /// Keeps registry identity, physical port and firmware contents private.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RomSession(<private>)")
    }
}

/// Injectable transport boundary; implementations do not retry or send cleanup IO.
trait Transport {
    /// Executes exactly the supplied command with a finite timeout.
    fn execute(
        &mut self,
        command: Command,
        image: &[u8],
        timeout_ms: u32,
    ) -> Result<usize, RomFailure>;
}

/// Enforces the one-attempt sequence above the native ownership boundary.
struct Driver<T> {
    transport: T,
    next: Option<Command>,
}

impl<T: Transport> Driver<T> {
    /// Creates an unopened command sequence without executing any IO.
    fn new(transport: T) -> Self {
        Self {
            transport,
            next: Some(Command::Identify),
        }
    }

    /// Advances only after complete bounded native success.
    fn advance(
        &mut self,
        command: Command,
        image: &[u8],
        timeout_ms: u32,
    ) -> Result<usize, RomFailure> {
        if self.next != Some(command)
            || !(1..=120_000).contains(&timeout_ms)
            || (command == Command::Program && !(22..=65_535).contains(&image.len()))
            || (command != Command::Program && !image.is_empty())
        {
            return Err(RomFailure::rejected(NativeError::InvalidRequest));
        }
        // Poison before crossing the boundary: even a thrown/unknown result must
        // never authorize an automatic second attempt or a cleanup reset.
        self.next = None;
        let actual = self.transport.execute(command, image, timeout_ms)?;
        let expected = match command {
            Command::Identify => 2,
            Command::Setup | Command::Reset => 9,
            Command::Program => image.len(),
        };
        if actual != expected {
            return Err(RomFailure {
                error: NativeError::EvidenceIncomplete,
                attempted: true,
                outcome_unknown: true,
                transferred: (actual <= expected).then_some(actual),
            });
        }
        self.next = match command {
            Command::Identify => Some(Command::Setup),
            Command::Setup => Some(Command::Program),
            Command::Program => Some(Command::Reset),
            Command::Reset => None,
        };
        Ok(actual)
    }
}

/// Thread-bound IOHID run-loop ownership; deliberately neither Send nor Sync.
struct NativeTransport {
    #[cfg(target_os = "macos")]
    inner: std::ptr::NonNull<std::ffi::c_void>,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl NativeTransport {
    /// Acquires only the exact parent and its active non-seized interface lease.
    fn open(location_id: u32, candidate: Option<&RomCandidate>) -> Result<Self, NativeError> {
        #[cfg(target_os = "macos")]
        {
            let mut pointer = std::ptr::null_mut();
            // SAFETY: C initializes the sole output and transfers one opaque owner.
            let status = unsafe {
                match candidate {
                    Some(candidate) => {
                        native::rdx_macos_rom_open_selected(&candidate.record(), &mut pointer)
                    }
                    None => native::rdx_macos_rom_open(location_id, &mut pointer),
                }
            };
            if status != 0 {
                if !pointer.is_null() {
                    // SAFETY: a defensive cleanup of an owner unexpectedly returned on error.
                    unsafe { native::rdx_macos_rom_release(pointer) };
                }
                return Err(crate::status_error(status));
            }
            Ok(Self {
                inner: std::ptr::NonNull::new(pointer).ok_or(NativeError::Other)?,
                _thread_bound: std::marker::PhantomData,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (location_id, candidate);
            Err(NativeError::UnsupportedPlatform)
        }
    }
}

impl Transport for NativeTransport {
    /// Makes one synchronous boundary call; C owns asynchronous HID storage.
    fn execute(
        &mut self,
        command: Command,
        image: &[u8],
        timeout_ms: u32,
    ) -> Result<usize, RomFailure> {
        #[cfg(target_os = "macos")]
        {
            let mut result = native::ResultRecord::default();
            // SAFETY: the non-Send unique owner, immutable image and output remain
            // live for this call. C copies image bytes before async/native transfer.
            unsafe {
                native::rdx_macos_rom_execute(
                    self.inner.as_ptr(),
                    command as u32,
                    image.as_ptr(),
                    image.len() as u32,
                    timeout_ms,
                    &mut result,
                )
            };
            result.into_result()
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (command, image, timeout_ms);
            Err(RomFailure::rejected(NativeError::UnsupportedPlatform))
        }
    }
}

impl Drop for NativeTransport {
    /// Releases interfaces and callback storage without sending any device command.
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        // SAFETY: this thread-bound owner is released exactly once.
        unsafe {
            native::rdx_macos_rom_release(self.inner.as_ptr())
        };
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Default)]
    pub(super) struct ResultRecord {
        status: u32,
        attempted: u32,
        transferred_known: u32,
        transferred: u32,
    }

    impl ResultRecord {
        /// Validates fixed-width flags before exposing bounded completion evidence.
        pub(super) fn into_result(self) -> Result<usize, RomFailure> {
            if self.attempted > 1
                || self.transferred_known > 1
                || self.transferred > 65_535
                || (self.attempted == 0 && self.transferred != 0)
                || (self.transferred_known == 0 && self.transferred != 0)
                || (self.status == 0 && (self.attempted != 1 || self.transferred_known != 1))
            {
                return Err(RomFailure {
                    error: NativeError::Other,
                    attempted: true,
                    outcome_unknown: true,
                    transferred: None,
                });
            }
            let transferred = (self.transferred_known == 1).then_some(self.transferred as usize);
            if self.status == 0 && self.attempted == 1 {
                if let Some(count) = transferred {
                    return Ok(count);
                }
            }
            Err(RomFailure {
                error: if self.status == 0 {
                    NativeError::Other
                } else {
                    crate::status_error(self.status)
                },
                attempted: self.attempted == 1,
                outcome_unknown: self.attempted == 1,
                transferred,
            })
        }
    }

    unsafe extern "C" {
        pub(super) fn rdx_macos_rom_open(location_id: u32, output: *mut *mut c_void) -> u32;
        pub(super) fn rdx_macos_rom_open_selected(
            candidate: *const crate::rom_inventory::CandidateRecord,
            output: *mut *mut c_void,
        ) -> u32;
        pub(super) fn rdx_macos_rom_release(session: *mut c_void);
        pub(super) fn rdx_macos_rom_execute(
            session: *mut c_void,
            command: u32,
            bytes: *const u8,
            length: u32,
            timeout_ms: u32,
            result: *mut ResultRecord,
        );
        #[cfg(all(test, feature = "test-hooks"))]
        pub(super) fn rdx_macos_rom_test_contract() -> bool;
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Impossible success records cannot be downgraded to a safe preflight rejection.
        #[test]
        fn rom_malformed_native_result_remains_unknown() {
            for record in [
                ResultRecord::default(),
                ResultRecord {
                    status: 0,
                    attempted: 1,
                    transferred_known: 0,
                    transferred: 0,
                },
                ResultRecord {
                    status: 5,
                    attempted: 2,
                    transferred_known: 1,
                    transferred: 7,
                },
                ResultRecord {
                    status: 5,
                    attempted: 1,
                    transferred_known: 1,
                    transferred: 65_536,
                },
            ] {
                let failure = record.into_result().unwrap_err();
                assert!(failure.attempted && failure.outcome_unknown);
                assert_eq!(failure.transferred, None);
            }
        }

        /// A native timeout count is retained while a local rejection stays unattempted.
        #[test]
        fn rom_native_failure_retains_partial_count() {
            assert_eq!(
                ResultRecord {
                    status: 5,
                    attempted: 1,
                    transferred_known: 1,
                    transferred: 7
                }
                .into_result(),
                Err(RomFailure {
                    error: NativeError::TimedOut,
                    attempted: true,
                    outcome_unknown: true,
                    transferred: Some(7)
                })
            );
            assert_eq!(
                ResultRecord {
                    status: 1,
                    attempted: 0,
                    transferred_known: 1,
                    transferred: 0
                }
                .into_result(),
                Err(RomFailure::rejected(NativeError::InvalidRequest))
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Native selection, request packing and callback validation use no registry IO.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn rom_native_selection_and_completion_contract() {
        // SAFETY: the hook calls only pure native boundaries with stack fixtures.
        assert!(unsafe { native::rdx_macos_rom_test_contract() });
    }

    #[derive(Default)]
    struct Recording {
        calls: Vec<(Command, Vec<u8>, u32)>,
        result: Option<Result<usize, RomFailure>>,
    }

    impl Transport for Recording {
        /// Records boundary traffic and supplies a complete result unless overridden.
        fn execute(
            &mut self,
            command: Command,
            image: &[u8],
            timeout_ms: u32,
        ) -> Result<usize, RomFailure> {
            self.calls.push((command, image.to_vec(), timeout_ms));
            self.result.take().unwrap_or(Ok(match command {
                Command::Identify => 2,
                Command::Setup | Command::Reset => 9,
                Command::Program => image.len(),
            }))
        }
    }

    /// Removing a stage gate must never admit a write before identification/setup.
    #[test]
    fn rom_requires_explicit_order_and_never_issues_implicit_commands() {
        let mut driver = Driver::new(Recording::default());
        assert!(driver.advance(Command::Setup, &[], 1000).is_err());
        assert!(driver.advance(Command::Program, &[0; 22], 1000).is_err());
        assert!(driver.advance(Command::Reset, &[], 1000).is_err());
        assert!(driver.transport.calls.is_empty());
        assert_eq!(driver.advance(Command::Identify, &[], 1000), Ok(2));
        assert_eq!(driver.transport.calls.len(), 1);
        assert!(driver.advance(Command::Identify, &[], 1000).is_err());
        assert_eq!(driver.advance(Command::Setup, &[], 1000), Ok(9));
        assert!(driver.advance(Command::Reset, &[], 1000).is_err());
        assert_eq!(driver.advance(Command::Program, &[0x60; 22], 1000), Ok(22));
        assert_eq!(driver.transport.calls.len(), 3);
        assert_eq!(driver.advance(Command::Reset, &[], 1000), Ok(9));
        assert!(driver.advance(Command::Reset, &[], 1000).is_err());
        assert_eq!(
            driver.transport.calls,
            vec![
                (Command::Identify, vec![], 1000),
                (Command::Setup, vec![], 1000),
                (Command::Program, vec![0x60; 22], 1000),
                (Command::Reset, vec![], 1000),
            ]
        );
    }

    /// Infinite timeouts and out-of-range images must fail before transfer admission.
    #[test]
    fn rom_bounds_are_checked_before_io() {
        let mut driver = Driver::new(Recording::default());
        for timeout in [0, 120_001, u32::MAX] {
            assert!(driver.advance(Command::Identify, &[], timeout).is_err());
        }
        assert!(driver.transport.calls.is_empty());
        assert_eq!(driver.advance(Command::Identify, &[], 1), Ok(2));
        assert_eq!(driver.advance(Command::Setup, &[], 120_000), Ok(9));
        for image in [vec![], vec![0; 21], vec![0; 65_536]] {
            let failure = driver.advance(Command::Program, &image, 1000).unwrap_err();
            assert!(!failure.attempted);
        }
        assert_eq!(driver.transport.calls.len(), 2);
        assert_eq!(
            driver.advance(Command::Program, &vec![0; 65_535], 1000),
            Ok(65_535)
        );
    }

    /// A timeout with partial count must poison the sequence and retain that count.
    #[test]
    fn rom_partial_failure_cannot_be_retried_or_reset() {
        let mut driver = Driver::new(Recording::default());
        driver.advance(Command::Identify, &[], 1000).unwrap();
        driver.advance(Command::Setup, &[], 1000).unwrap();
        let failure = RomFailure {
            error: NativeError::TimedOut,
            attempted: true,
            outcome_unknown: true,
            transferred: Some(7),
        };
        driver.transport.result = Some(Err(failure));
        assert_eq!(
            driver.advance(Command::Program, &[0; 22], 1000),
            Err(failure)
        );
        assert!(driver.advance(Command::Program, &[0; 22], 1000).is_err());
        assert!(driver.advance(Command::Reset, &[], 1000).is_err());
        assert_eq!(driver.transport.calls.len(), 3);
    }

    /// A short OS success is still incomplete and must never authorize reset.
    #[test]
    fn rom_short_success_is_an_unknown_failure() {
        let mut driver = Driver::new(Recording::default());
        driver.advance(Command::Identify, &[], 1000).unwrap();
        driver.advance(Command::Setup, &[], 1000).unwrap();
        driver.transport.result = Some(Ok(21));
        let failure = driver
            .advance(Command::Program, &[0; 22], 1000)
            .unwrap_err();
        assert!(failure.attempted && failure.outcome_unknown);
        assert_eq!(failure.transferred, Some(21));
        assert!(driver.advance(Command::Reset, &[], 1000).is_err());
        assert_eq!(driver.transport.calls.len(), 3);
    }
}

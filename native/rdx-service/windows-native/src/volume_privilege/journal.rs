// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Write-ahead ownership across install, repair, uninstall and reinstall.
use crate::NativeError;

/// Fixed-account policy and its protected installation ownership record.
pub(crate) trait PrivilegeJournal {
    /// Reads the original right presence retained through repairs.
    fn previous(&self) -> Option<bool>;
    /// Observes the current fixed service right.
    fn current(&self) -> Result<bool, NativeError>;
    /// Durably records ownership before granting, or clears it after restoration.
    fn store(&mut self, previous: Option<bool>) -> Result<(), NativeError>;
    /// Changes only the compiled service right, preserving unrelated policy.
    fn set(&mut self, present: bool) -> Result<(), NativeError>;
}

/// Journals the original policy before granting; Repair never replaces ownership.
pub(crate) fn enroll(io: &mut impl PrivilegeJournal) -> Result<(), NativeError> {
    if io.previous().is_none() {
        let previous = io.current()?;
        io.store(Some(previous))?;
    }
    io.set(true)
}

/// Restores only an owned grant, then closes this installation's journal generation.
pub(crate) fn restore(io: &mut impl PrivilegeJournal) -> Result<(), NativeError> {
    if let Some(previous) = io.previous() {
        if !previous && io.current()? {
            io.set(false)?;
        }
        io.store(None)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Policy {
        previous: Option<bool>,
        current: bool,
        fail_store: bool,
        events: Vec<&'static str>,
    }
    impl PrivilegeJournal for Policy {
        /// Returns the fake durable original policy.
        fn previous(&self) -> Option<bool> {
            self.previous
        }
        /// Returns the fake current account policy.
        fn current(&self) -> Result<bool, NativeError> {
            Ok(self.current)
        }
        /// Models an atomic journal publication, including failure before publication.
        fn store(&mut self, previous: Option<bool>) -> Result<(), NativeError> {
            self.events.push("store");
            if self.fail_store {
                return Err(NativeError::AccessDenied);
            }
            self.previous = previous;
            Ok(())
        }
        /// Models changing only the fixed right.
        fn set(&mut self, present: bool) -> Result<(), NativeError> {
            self.events.push(if present { "grant" } else { "revoke" });
            self.current = present;
            Ok(())
        }
    }
    /// Builds an untouched installation without a prior ownership generation.
    fn policy(current: bool) -> Policy {
        Policy {
            previous: None,
            current,
            fail_store: false,
            events: Vec::new(),
        }
    }

    /// Failed write-ahead publication cannot grant the filesystem privilege.
    #[test]
    fn failed_journal_prevents_grant() {
        let mut io = policy(false);
        io.fail_store = true;
        assert_eq!(enroll(&mut io), Err(NativeError::AccessDenied));
        assert!(!io.current);
        assert_eq!(io.events, ["store"]);
    }
    /// Repair preserves original ownership and uninstall revokes before clearing it.
    #[test]
    fn repair_and_removal_preserve_original_ownership() {
        let mut io = policy(false);
        enroll(&mut io).unwrap();
        enroll(&mut io).unwrap();
        restore(&mut io).unwrap();
        assert_eq!(io.events, ["store", "grant", "grant", "revoke", "store"]);
        assert_eq!(io.previous, None);
        assert!(!io.current);
    }
    /// A later administrator grant must be captured afresh by a reinstallation.
    #[test]
    fn reinstall_preserves_a_new_administrator_grant() {
        let mut io = policy(false);
        enroll(&mut io).unwrap();
        restore(&mut io).unwrap();
        io.current = true;
        enroll(&mut io).unwrap();
        assert_eq!(io.previous, Some(true));
        restore(&mut io).unwrap();
        assert!(io.current);
        assert_eq!(io.previous, None);
    }
    /// A failed ownership clear remains retryable without repeating a revocation.
    #[test]
    fn interrupted_removal_resumes_without_a_second_revoke() {
        let mut io = policy(false);
        enroll(&mut io).unwrap();
        io.fail_store = true;
        assert_eq!(restore(&mut io), Err(NativeError::AccessDenied));
        assert!(!io.current);
        assert_eq!(io.previous, Some(false));
        io.fail_store = false;
        restore(&mut io).unwrap();
        assert_eq!(
            io.events.iter().filter(|event| **event == "revoke").count(),
            1
        );
        assert_eq!(io.previous, None);
    }
}

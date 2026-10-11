// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::ffi;

/// Snapshot of native ownership counters used by leak-oriented tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceCounters(ffi::ResourceCounters);

impl ResourceCounters {
    /// Returns the cumulative number of native result allocations.
    #[must_use]
    pub const fn result_allocations(self) -> u64 {
        self.0.result_allocations
    }

    /// Returns the cumulative number of native result frees.
    #[must_use]
    pub const fn result_frees(self) -> u64 {
        self.0.result_frees
    }

    /// Returns cumulative tracked IOKit object acquisitions.
    #[must_use]
    pub const fn io_acquisitions(self) -> u64 {
        self.0.io_acquisitions
    }

    /// Returns cumulative tracked IOKit object releases.
    #[must_use]
    pub const fn io_releases(self) -> u64 {
        self.0.io_releases
    }

    /// Returns cumulative documented task-interface plug-in acquisitions.
    #[must_use]
    pub const fn plugin_acquisitions(self) -> u64 {
        self.0.plugin_acquisitions
    }

    /// Returns cumulative documented task-interface query acquisitions.
    #[must_use]
    pub const fn interface_acquisitions(self) -> u64 {
        self.0.interface_acquisitions
    }

    /// Returns cumulative successful exclusive SCSI authority acquisitions.
    #[must_use]
    pub const fn exclusive_acquisitions(self) -> u64 {
        self.0.exclusive_acquisitions
    }

    /// Returns cumulative heap callback-context allocations.
    #[must_use]
    pub const fn da_context_allocations(self) -> u64 {
        self.0.da_context_allocations
    }

    /// Returns cumulative heap callback-context frees.
    #[must_use]
    pub const fn da_context_frees(self) -> u64 {
        self.0.da_context_frees
    }

    /// Returns the exact current bounded callback-context count.
    #[must_use]
    pub const fn da_contexts_outstanding(self) -> u64 {
        self.0.da_contexts_outstanding
    }

    /// Returns the number of result allocations not yet freed.
    #[must_use]
    pub const fn live_results(self) -> Option<u64> {
        self.0.result_allocations.checked_sub(self.0.result_frees)
    }

    /// Returns whether every tracked native acquisition has a matching release.
    #[must_use]
    pub const fn native_resources_balanced(self) -> bool {
        self.0.io_acquisitions == self.0.io_releases
            && self.0.cf_acquisitions == self.0.cf_releases
            && self.0.plugin_acquisitions == self.0.plugin_releases
            && self.0.interface_acquisitions == self.0.interface_releases
            && self.0.exclusive_acquisitions == self.0.exclusive_releases
            && self.0.task_acquisitions == self.0.task_releases
            && self.0.device_allocations == self.0.device_frees
            && self.0.scsi_lease_allocations == self.0.scsi_lease_frees
            && self.0.da_registry_allocations == self.0.da_registry_frees
            && self.0.da_context_allocations == self.0.da_context_frees
            && self.0.da_contexts_outstanding == 0
    }

    /// Returns whether every counter delta since `before` is exact and paired.
    #[must_use]
    pub fn balanced_since(self, before: Self) -> bool {
        fn exact_pair(
            after_acquire: u64,
            before_acquire: u64,
            after_release: u64,
            before_release: u64,
        ) -> bool {
            matches!(
                (
                    after_acquire.checked_sub(before_acquire),
                    after_release.checked_sub(before_release)
                ),
                (Some(acquired), Some(released)) if acquired == released
            )
        }

        exact_pair(
            self.0.result_allocations,
            before.0.result_allocations,
            self.0.result_frees,
            before.0.result_frees,
        ) && exact_pair(
            self.0.io_acquisitions,
            before.0.io_acquisitions,
            self.0.io_releases,
            before.0.io_releases,
        ) && exact_pair(
            self.0.cf_acquisitions,
            before.0.cf_acquisitions,
            self.0.cf_releases,
            before.0.cf_releases,
        ) && exact_pair(
            self.0.plugin_acquisitions,
            before.0.plugin_acquisitions,
            self.0.plugin_releases,
            before.0.plugin_releases,
        ) && exact_pair(
            self.0.interface_acquisitions,
            before.0.interface_acquisitions,
            self.0.interface_releases,
            before.0.interface_releases,
        ) && exact_pair(
            self.0.exclusive_acquisitions,
            before.0.exclusive_acquisitions,
            self.0.exclusive_releases,
            before.0.exclusive_releases,
        ) && exact_pair(
            self.0.task_acquisitions,
            before.0.task_acquisitions,
            self.0.task_releases,
            before.0.task_releases,
        ) && exact_pair(
            self.0.device_allocations,
            before.0.device_allocations,
            self.0.device_frees,
            before.0.device_frees,
        ) && exact_pair(
            self.0.scsi_lease_allocations,
            before.0.scsi_lease_allocations,
            self.0.scsi_lease_frees,
            before.0.scsi_lease_frees,
        ) && exact_pair(
            self.0.da_registry_allocations,
            before.0.da_registry_allocations,
            self.0.da_registry_frees,
            before.0.da_registry_frees,
        ) && exact_pair(
            self.0.da_context_allocations,
            before.0.da_context_allocations,
            self.0.da_context_frees,
            before.0.da_context_frees,
        ) && self.0.da_contexts_outstanding == before.0.da_contexts_outstanding
    }
}

/// Returns a leak-oriented snapshot of the C bridge ownership counters.
#[must_use]
pub fn resource_counters() -> ResourceCounters {
    #[cfg(target_os = "macos")]
    {
        let mut native = ffi::ResourceCounters::default();
        // SAFETY: `native` is writable and has the exact fixed C layout.
        unsafe { ffi::rdx_macos_get_resource_counters(&mut native) };
        ResourceCounters(native)
    }
    #[cfg(not(target_os = "macos"))]
    {
        ResourceCounters::default()
    }
}

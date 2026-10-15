// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::operations::{FileSystem, VolumeTopology};
use std::sync::{Arc, Mutex};

/// Records only fixed test events and synthetic facts; no native capability or IO is fabricated.
struct Parent {
    trace: Arc<Mutex<Vec<&'static str>>>,
    facts: HostVolumeFacts,
    busy: bool,
}
impl CaptureAuthority for Parent {
    /// Independent physical/mount facts, sampled before the exact handoff.
    fn facts(&mut self) -> Result<HostVolumeFacts, NativeError> {
        self.trace.lock().unwrap().push("facts");
        Ok(self.facts)
    }
    /// Refuses before release when mounted storage cannot be safely unmounted.
    fn unmount(&mut self) -> Result<(), NativeError> {
        self.trace.lock().unwrap().push("unmount");
        if self.busy {
            return Err(NativeError::Busy);
        }
        self.facts.mounted = false;
        Ok(())
    }
    /// Preserves the post-prepare mapping invalidation event.
    fn invalidate(&mut self) {
        self.trace.lock().unwrap().push("invalidate");
    }
}
impl Drop for Parent {
    /// Makes the actual Rust ownership boundary observable before a factory callback.
    fn drop(&mut self) {
        self.trace.lock().unwrap().push("drop-parent");
    }
}

/// Supplies a complete known mounted cartridge snapshot; no device is contacted.
fn facts() -> HostVolumeFacts {
    HostVolumeFacts {
        media_present: true,
        mounted: true,
        writable: true,
        free_bytes: 500,
        capacity_bytes: 1000,
        filesystem: Some(FileSystem::ExFat),
        media_fingerprint: Some([0xA5; 32]),
        topology: VolumeTopology::Simple,
    }
}

/// Initial acquisition must release the retained exact parent before any new capture process starts.
#[test]
fn worker_lifecycle_initial_spawn_occurs_after_parent_drop() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let parent = Parent {
        trace: trace.clone(),
        facts: facts(),
        busy: false,
    };
    assert_eq!(
        release_parent_and_spawn(Some(parent), || {
            trace.lock().unwrap().push("spawn");
            Ok(7)
        }),
        Ok(7)
    );
    assert_eq!(*trace.lock().unwrap(), ["drop-parent", "spawn"]);
}

/// Reacquisition retains the old mount/cached-facts preparation, invalidation, drop, then spawn order.
#[test]
fn worker_lifecycle_reacquire_prepares_storage_then_drops_parent_before_spawn() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut parent = Some(Parent {
        trace: trace.clone(),
        facts: facts(),
        busy: false,
    });
    let mut worker = None;
    let mut cached = Some(facts());
    start_worker(&mut parent, &mut worker, &mut cached, false, || {
        trace.lock().unwrap().push("spawn");
        Ok(7)
    })
    .unwrap();
    assert!(parent.is_none());
    assert_eq!(worker, Some(7));
    assert_eq!(cached, Some(facts()));
    assert_eq!(
        *trace.lock().unwrap(),
        ["facts", "unmount", "invalidate", "drop-parent", "spawn"]
    );
}

/// Busy unmount remains the original error, retains the parent, and never calls the worker factory.
#[test]
fn worker_lifecycle_busy_unmount_prevents_parent_drop_and_spawn() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut parent = Some(Parent {
        trace: trace.clone(),
        facts: facts(),
        busy: true,
    });
    let mut worker: Option<u64> = None;
    let mut cached = Some(facts());
    assert_eq!(
        start_worker(&mut parent, &mut worker, &mut cached, false, || panic!(
            "no spawn after busy"
        )),
        Err(NativeError::Busy)
    );
    assert!(parent.is_some());
    assert!(worker.is_none());
    assert_eq!(cached, Some(facts()));
    assert_eq!(*trace.lock().unwrap(), ["facts", "unmount"]);
}

/// Refused new worker authority does not restore parent IO or fabricate a capture fallback.
#[test]
fn worker_lifecycle_refused_factory_leaves_parent_released_and_worker_absent() {
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut parent = Some(Parent {
        trace: trace.clone(),
        facts: facts(),
        busy: false,
    });
    let mut worker: Option<u64> = None;
    let mut cached = Some(facts());
    assert_eq!(
        start_worker(&mut parent, &mut worker, &mut cached, false, || {
            trace.lock().unwrap().push("refuse");
            Err(NativeError::AccessDenied)
        }),
        Err(NativeError::AccessDenied)
    );
    assert!(parent.is_none());
    assert!(worker.is_none());
    assert_eq!(cached, Some(facts()));
    assert_eq!(
        *trace.lock().unwrap(),
        ["facts", "unmount", "invalidate", "drop-parent", "refuse"]
    );
}

/// Existing admitted commands and their release retain the worker without any fresh GUI admission.
#[test]
fn worker_lifecycle_retained_worker_continues_without_new_spawn_or_parent_work() {
    let mut parent: Option<Parent> = None;
    let mut worker = Some(Vec::<&str>::new());
    let mut cached = Some(facts());
    for command in [
        "first-admitted-command",
        "second-admitted-command",
        "existing-cleanup",
    ] {
        start_worker(&mut parent, &mut worker, &mut cached, false, || {
            panic!("no new GUI check for retained worker")
        })
        .unwrap();
        worker.as_mut().unwrap().push(command);
    }
    assert_eq!(
        worker.take().unwrap(),
        [
            "first-admitted-command",
            "second-admitted-command",
            "existing-cleanup"
        ]
    );
    assert_eq!(cached, Some(facts()));
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed UDisks2 normal-unmount authority on the root-owned system bus.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use futures_lite::future::FutureExt;
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{Connection, Proxy, proxy::CacheProperties};

use crate::identity::{DeviceNumber, device_number_from_linux_dev_t};
use crate::{HostFilesystem, HostOperationOutcome, MAX_CANDIDATES, NativeError};

const SERVICE: &str = "org.freedesktop.UDisks2";
const BLOCK: &str = "org.freedesktop.UDisks2.Block";
const FILESYSTEM: &str = "org.freedesktop.UDisks2.Filesystem";
const DEADLINE: Duration = Duration::from_secs(25);

/// A verified block object on one exact, root-owned daemon connection.
pub(super) struct UDisksUnmount {
    connection: Connection,
    owner: String,
    object: OwnedObjectPath,
    device: DeviceNumber,
    mount_points: Vec<Vec<u8>>,
}

impl UDisksUnmount {
    /// Resolves exactly one object with the retained device number and mount set.
    pub(super) fn prepare(
        device: DeviceNumber,
        mount_points: Vec<Vec<u8>>,
    ) -> Result<Self, NativeError> {
        Self::prepare_internal(device, mount_points, true)
    }

    /// Resolves a freshly formatted block before the daemon exposes Filesystem.
    pub(super) fn prepare_format(device: DeviceNumber) -> Result<Self, NativeError> {
        Self::prepare_internal(device, Vec::new(), false)
    }

    /// Binds the root-owned daemon and exact block, optionally requiring mounts.
    fn prepare_internal(
        device: DeviceNumber,
        mount_points: Vec<Vec<u8>>,
        mounts_required: bool,
    ) -> Result<Self, NativeError> {
        bounded(async {
            let connection = Connection::system()
                .await
                .map_err(|_| NativeError::DependencyMissing)?;
            let bus = uncached_proxy(
                &connection,
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
            )
            .await?;
            let owner: String = bus
                .call("GetNameOwner", &(SERVICE,))
                .await
                .map_err(|_| NativeError::DependencyMissing)?;
            let uid: u32 = bus
                .call("GetConnectionUnixUser", &(&owner,))
                .await
                .map_err(|_| NativeError::AccessDenied)?;
            if uid != 0 {
                return Err(NativeError::AccessDenied);
            }
            let manager = uncached_proxy(
                &connection,
                &owner,
                "/org/freedesktop/UDisks2/Manager",
                "org.freedesktop.UDisks2.Manager",
            )
            .await?;
            let options: HashMap<&str, Value<'_>> = HashMap::new();
            let objects: Vec<OwnedObjectPath> = manager
                .call("GetBlockDevices", &(options,))
                .await
                .map_err(|_| NativeError::DependencyMissing)?;
            if objects.len() > MAX_CANDIDATES {
                return Err(NativeError::ResourceLimit);
            }
            let mut selected = None;
            for object in objects {
                let block = uncached_proxy(&connection, &owner, object.as_str(), BLOCK).await?;
                let raw: u64 = block
                    .get_property("DeviceNumber")
                    .await
                    .map_err(|_| NativeError::EvidenceIncomplete)?;
                if device_number_from_linux_dev_t(raw) == device
                    && selected.replace(object).is_some()
                {
                    return Err(NativeError::EvidenceIncomplete);
                }
            }
            let object = selected.ok_or(NativeError::DeviceRemoved)?;
            drop(manager);
            drop(bus);
            let binding = Self {
                connection,
                owner,
                object,
                device,
                mount_points,
            };
            binding.validate_block().await?;
            if mounts_required {
                binding.validate().await?;
            }
            Ok(binding)
        })
    }

    /// Checks uncached daemon evidence immediately before the normal unmount call.
    async fn validate_block(&self) -> Result<(), NativeError> {
        let block =
            uncached_proxy(&self.connection, &self.owner, self.object.as_str(), BLOCK).await?;
        let raw: u64 = block
            .get_property("DeviceNumber")
            .await
            .map_err(|_| NativeError::DeviceRemoved)?;
        if device_number_from_linux_dev_t(raw) != self.device {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(())
    }

    /// Checks every exact mount before a normal unmount call.
    async fn validate(&self) -> Result<(), NativeError> {
        self.validate_block().await?;
        let filesystem = uncached_proxy(
            &self.connection,
            &self.owner,
            self.object.as_str(),
            FILESYSTEM,
        )
        .await?;
        let reported: Vec<Vec<u8>> = filesystem
            .get_property("MountPoints")
            .await
            .map_err(|_| NativeError::EvidenceIncomplete)?;
        if !mount_points_match(&reported, &self.mount_points) {
            return Err(NativeError::DeviceRemoved);
        }
        Ok(())
    }

    /// Reads the on-disk personality independently of the kernel mount driver.
    pub(super) fn read_filesystem(&self) -> Result<HostFilesystem, NativeError> {
        bounded(async {
            self.validate_block().await?;
            let block =
                uncached_proxy(&self.connection, &self.owner, self.object.as_str(), BLOCK).await?;
            let kind: String = block
                .get_property("IdType")
                .await
                .map_err(|_| NativeError::EvidenceIncomplete)?;
            let version: String = block
                .get_property("IdVersion")
                .await
                .map_err(|_| NativeError::EvidenceIncomplete)?;
            self.validate_block().await?;
            HostFilesystem::ALL
                .into_iter()
                .find(|filesystem| filesystem.signature_matches(&kind, &version))
                .ok_or(NativeError::EvidenceIncomplete)
        })
    }

    /// Reads the current label from uncached root-owned evidence for this mounted block.
    pub(super) fn read_label(&self) -> Result<String, NativeError> {
        bounded(async {
            self.validate().await?;
            let block =
                uncached_proxy(&self.connection, &self.owner, self.object.as_str(), BLOCK).await?;
            let label: String = block
                .get_property("IdLabel")
                .await
                .map_err(|_| NativeError::EvidenceIncomplete)?;
            self.validate().await?;
            if label.encode_utf16().count() > 32 || label.chars().any(char::is_control) {
                return Err(NativeError::EvidenceIncomplete);
            }
            Ok(label)
        })
    }

    /// Changes only this exact mounted filesystem label and waits for daemon readback.
    pub(super) fn set_label(&self, label: &str) -> HostOperationOutcome {
        bounded_outcome(async {
            if let Err(error) = self.validate().await {
                return HostOperationOutcome::NotAttempted(error);
            }
            let filesystem = match uncached_proxy(
                &self.connection,
                &self.owner,
                self.object.as_str(),
                FILESYSTEM,
            )
            .await
            {
                Ok(proxy) => proxy,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            let options = HashMap::from([("auth.no_user_interaction", Value::Bool(true))]);
            if let Err(error) = filesystem
                .call::<_, _, ()>("SetLabel", &(label, options))
                .await
            {
                return match error {
                    zbus::Error::MethodError(name, _, _)
                        if name.as_str() == "org.freedesktop.UDisks2.Error.NotSupported" =>
                    {
                        HostOperationOutcome::DefinitelyRejected(NativeError::UnsupportedPlatform)
                    }
                    zbus::Error::MethodError(name, _, _)
                        if name.as_str() == "org.freedesktop.UDisks2.Error.DeviceBusy" =>
                    {
                        HostOperationOutcome::DefinitelyRejected(NativeError::Busy)
                    }
                    _ => HostOperationOutcome::CompletionUnknown(NativeError::Other),
                };
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let block =
                match uncached_proxy(&self.connection, &self.owner, self.object.as_str(), BLOCK)
                    .await
                {
                    Ok(proxy) => proxy,
                    Err(error) => return HostOperationOutcome::CompletionUnknown(error),
                };
            loop {
                if let Err(error) = self.validate().await {
                    return HostOperationOutcome::CompletionUnknown(error);
                }
                if block
                    .get_property::<String>("IdLabel")
                    .await
                    .is_ok_and(|actual| actual == label)
                {
                    return HostOperationOutcome::Succeeded;
                }
                if std::time::Instant::now() >= deadline {
                    return HostOperationOutcome::CompletionUnknown(
                        NativeError::EvidenceIncomplete,
                    );
                }
                async_io::Timer::after(Duration::from_millis(100)).await;
            }
        })
    }

    /// Refreshes daemon evidence after a verified kernel-only label mutation.
    pub(super) fn rescan_label(&self, label: &str) -> HostOperationOutcome {
        bounded_outcome(async {
            if let Err(error) = self.validate().await {
                return HostOperationOutcome::CompletionUnknown(error);
            }
            let block =
                match uncached_proxy(&self.connection, &self.owner, self.object.as_str(), BLOCK)
                    .await
                {
                    Ok(proxy) => proxy,
                    Err(error) => return HostOperationOutcome::CompletionUnknown(error),
                };
            let options = HashMap::from([("auth.no_user_interaction", Value::Bool(true))]);
            if block.call::<_, _, ()>("Rescan", &(options,)).await.is_err() {
                return HostOperationOutcome::CompletionUnknown(NativeError::Other);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if let Err(error) = self.validate().await {
                    return HostOperationOutcome::CompletionUnknown(error);
                }
                if block
                    .get_property::<String>("IdLabel")
                    .await
                    .is_ok_and(|actual| actual == label)
                {
                    return HostOperationOutcome::Succeeded;
                }
                if std::time::Instant::now() >= deadline {
                    return HostOperationOutcome::CompletionUnknown(
                        NativeError::EvidenceIncomplete,
                    );
                }
                async_io::Timer::after(Duration::from_millis(100)).await;
            }
        })
    }

    /// Refreshes the exact block signature and mounts through the host daemon.
    /// Mount-driver names alone cannot distinguish ext3/ext4 or FAT16/FAT32.
    pub(super) fn mount_formatted(&self, selected: HostFilesystem) -> HostOperationOutcome {
        bounded_outcome(async {
            if let Err(error) = self.validate_block().await {
                return HostOperationOutcome::NotAttempted(error);
            }
            let block =
                match uncached_proxy(&self.connection, &self.owner, self.object.as_str(), BLOCK)
                    .await
                {
                    Ok(block) => block,
                    Err(error) => return HostOperationOutcome::NotAttempted(error),
                };
            let options = HashMap::from([("auth.no_user_interaction", Value::Bool(true))]);
            if block.call::<_, _, ()>("Rescan", &(options,)).await.is_err() {
                return HostOperationOutcome::CompletionUnknown(NativeError::Other);
            }
            // Rescan triggers udev asynchronously. Wait for the new on-disk
            // signature before requiring the newly created Filesystem interface.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if let Err(error) = self.validate_block().await {
                    return HostOperationOutcome::CompletionUnknown(error);
                }
                let kind: Result<String, _> = block.get_property("IdType").await;
                let version: Result<String, _> = block.get_property("IdVersion").await;
                if kind
                    .as_ref()
                    .ok()
                    .zip(version.as_ref().ok())
                    .is_some_and(|(kind, version)| selected.signature_matches(kind, version))
                {
                    let filesystem = match uncached_proxy(
                        &self.connection,
                        &self.owner,
                        self.object.as_str(),
                        FILESYSTEM,
                    )
                    .await
                    {
                        Ok(filesystem) => filesystem,
                        Err(error) => return HostOperationOutcome::NotAttempted(error),
                    };
                    if let Ok(points) = filesystem.get_property::<Vec<Vec<u8>>>("MountPoints").await
                    {
                        if !points.is_empty() {
                            // Desktop automount may win the race. The caller must
                            // still prove the complete exact kernel mount afterward.
                            return HostOperationOutcome::Succeeded;
                        }
                        let options =
                            HashMap::from([("auth.no_user_interaction", Value::Bool(true))]);
                        return match filesystem.call::<_, _, String>("Mount", &(options,)).await {
                            Ok(_) => HostOperationOutcome::Succeeded,
                            Err(_) => HostOperationOutcome::CompletionUnknown(NativeError::Other),
                        };
                    }
                }
                if std::time::Instant::now() >= deadline {
                    return HostOperationOutcome::CompletionUnknown(
                        NativeError::EvidenceIncomplete,
                    );
                }
                async_io::Timer::after(Duration::from_millis(100)).await;
            }
        })
    }

    /// Requests only UDisks2 Filesystem.Unmount with force explicitly false.
    pub(super) fn unmount(&self) -> HostOperationOutcome {
        bounded_outcome(async {
            if let Err(error) = self.validate().await {
                return HostOperationOutcome::NotAttempted(error);
            }
            let filesystem = match uncached_proxy(
                &self.connection,
                &self.owner,
                self.object.as_str(),
                FILESYSTEM,
            )
            .await
            {
                Ok(proxy) => proxy,
                Err(error) => return HostOperationOutcome::NotAttempted(error),
            };
            match filesystem
                .call::<_, _, ()>("Unmount", &(unmount_options(),))
                .await
            {
                Ok(()) => HostOperationOutcome::Succeeded,
                Err(zbus::Error::MethodError(name, _, _))
                    if name.as_str() == "org.freedesktop.UDisks2.Error.DeviceBusy" =>
                {
                    HostOperationOutcome::DefinitelyRejected(NativeError::Busy)
                }
                Err(zbus::Error::MethodError(name, _, _))
                    if matches!(
                        name.as_str(),
                        "org.freedesktop.UDisks2.Error.NotAuthorized"
                            | "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain"
                            | "org.freedesktop.UDisks2.Error.NotAuthorizedDismissed"
                    ) =>
                {
                    HostOperationOutcome::DefinitelyRejected(NativeError::AccessDenied)
                }
                Err(_) => HostOperationOutcome::CompletionUnknown(NativeError::Other),
            }
        })
    }
}

/// Disables property caching so removal and replacement cannot reuse old evidence.
async fn uncached_proxy<'a>(
    connection: &'a Connection,
    owner: &'a str,
    object: &'a str,
    interface: &'a str,
) -> Result<Proxy<'a>, NativeError> {
    zbus::proxy::Builder::<Proxy<'a>>::new(connection)
        .destination(owner)
        .map_err(|_| NativeError::EvidenceIncomplete)?
        .path(object)
        .map_err(|_| NativeError::EvidenceIncomplete)?
        .interface(interface)
        .map_err(|_| NativeError::EvidenceIncomplete)?
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(|_| NativeError::DependencyMissing)
}

/// Builds the complete closed policy; no user authentication or force is allowed.
fn unmount_options() -> HashMap<&'static str, Value<'static>> {
    HashMap::from([
        ("force", Value::Bool(false)),
        ("auth.no_user_interaction", Value::Bool(true)),
    ])
}

/// Requires the complete exact byte-preserving mount set from the host daemon.
fn mount_points_match(reported: &[Vec<u8>], expected: &[Vec<u8>]) -> bool {
    if reported.len() != expected.len() {
        return false;
    }
    let mut actual = Vec::new();
    for point in reported {
        let Some(point) = point.strip_suffix(&[0]) else {
            return false;
        };
        if point.contains(&0) || !point.starts_with(b"/") {
            return false;
        }
        actual.push(point.to_vec());
    }
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    actual == expected && actual.windows(2).all(|pair| pair[0] != pair[1])
}

/// Bounds all read-only preparation calls together and drops stalled requests.
fn bounded<T>(future: impl Future<Output = Result<T, NativeError>>) -> Result<T, NativeError> {
    async_io::block_on(future.or(async {
        async_io::Timer::after(DEADLINE).await;
        Err(NativeError::TimedOut)
    }))
}

/// A timed-out mutating request stays ambiguous and never unlocks physical eject.
fn bounded_outcome(future: impl Future<Output = HostOperationOutcome>) -> HostOperationOutcome {
    async_io::block_on(future.or(async {
        async_io::Timer::after(DEADLINE).await;
        HostOperationOutcome::CompletionUnknown(NativeError::TimedOut)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forces and interactive authorization are absent from the normal OS request.
    #[test]
    fn normal_unmount_has_no_force_or_interactive_fallback() {
        let options = unmount_options();
        assert_eq!(options.len(), 2);
        assert_eq!(options["force"], Value::Bool(false));
        assert_eq!(options["auth.no_user_interaction"], Value::Bool(true));
    }

    /// Host lookup must agree with every mount and reject malformed or extra roots.
    #[test]
    fn daemon_mount_points_require_exact_complete_kernel_evidence() {
        let expected = vec![b"/media/rdx".to_vec()];
        assert!(mount_points_match(&[b"/media/rdx\0".to_vec()], &expected));
        for reported in [
            vec![],
            vec![b"/media/other\0".to_vec()],
            vec![b"/media/rdx".to_vec()],
            vec![b"/media/rdx\0\0".to_vec()],
            vec![b"/media/rdx\0".to_vec(), b"/media/rdx\0".to_vec()],
        ] {
            assert!(!mount_points_match(&reported, &expected));
        }
    }
}

#[cfg(test)]
#[path = "udisks_tests.rs"]
mod live_tests;

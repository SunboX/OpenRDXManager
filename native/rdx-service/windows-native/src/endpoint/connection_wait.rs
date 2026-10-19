// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded acceptance on one retained protected nonblocking pipe instance.

use crate::NativeError;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE,
};
use windows::Win32::System::Pipes::{ConnectNamedPipe, DisconnectNamedPipe};

/// Waits for a client without releasing the listener's namespace-owning handle.
pub(super) fn wait_for_manager<F>(handle: HANDLE, stop_requested: &F) -> Result<(), NativeError>
where
    F: Fn() -> bool,
{
    wait_with_timeout(handle, stop_requested, Duration::from_secs(10))
}

/// Shares one absolute deadline across idle polls and abandoned clients.
fn wait_with_timeout<F>(
    handle: HANDLE,
    stop_requested: &F,
    timeout: Duration,
) -> Result<(), NativeError>
where
    F: Fn() -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if stop_requested() {
            return Err(NativeError::Cancelled);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(NativeError::TimedOut)?;
        // SAFETY: the owned pipe is nonblocking, without overlapped I/O.
        match unsafe { ConnectNamedPipe(handle, None) } {
            // In PIPE_NOWAIT mode success can mean that a disconnected instance
            // has become available, not that a peer is connected. Authenticate
            // only after the kernel reports ERROR_PIPE_CONNECTED.
            Ok(()) => {}
            Err(error) if error.code() == ERROR_PIPE_CONNECTED.to_hresult() => return Ok(()),
            Err(error) if error.code() == ERROR_PIPE_LISTENING.to_hresult() => {}
            Err(error) if error.code() == ERROR_NO_DATA.to_hresult() => {
                // An early client closed before acceptance. Reset that client's
                // state on this same protected instance, retaining namespace
                // ownership and the original deadline for the next client.
                // SAFETY: only this listener owns the unaccepted server handle.
                unsafe { DisconnectNamedPipe(handle) }.map_err(|_| NativeError::Other)?;
            }
            Err(_) => return Err(NativeError::Other),
        }
        std::thread::sleep(remaining.min(Duration::from_millis(5)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::TemporaryHandle;
    use std::sync::mpsc;
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    };
    use windows::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, WaitNamedPipeW,
    };
    use windows::core::PCWSTR;

    /// Creates a private instance in the real abandoned-client kernel state.
    fn abandoned_server(suffix: &str) -> (TemporaryHandle, Vec<u16>) {
        let name: Vec<u16> = format!(
            r"\\.\pipe\OpenRDXAbandonedPipeTest-{}-{suffix}",
            std::process::id()
        )
        .encode_utf16()
        .chain([0])
        .collect();
        // SAFETY: unique private test name, no production service or device.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                128,
                128,
                100,
                None,
            )
        };
        assert!(!handle.is_invalid());
        let server = TemporaryHandle(handle);
        // SAFETY: the private server exists; this client is closed before accept.
        let abandoned = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                Default::default(),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .unwrap();
        drop(TemporaryHandle(abandoned));
        // SAFETY: observes the exact real Windows state that used to be polled forever.
        assert_eq!(
            unsafe { ConnectNamedPipe(server.raw(), None) }
                .unwrap_err()
                .code(),
            ERROR_NO_DATA.to_hresult()
        );
        (server, name)
    }

    /// A disconnected early client must not wedge the next real connection.
    #[test]
    fn abandoned_client_does_not_block_next_connection() {
        let (server, name) = abandoned_server("reconnect");
        let (release, hold) = mpsc::channel();
        let client = std::thread::spawn(move || {
            // SAFETY: only the private test pipe is addressed, with a bounded wait.
            assert!(unsafe { WaitNamedPipeW(PCWSTR(name.as_ptr()), 2000) }.as_bool());
            let connected = unsafe {
                CreateFileW(
                    PCWSTR(name.as_ptr()),
                    (GENERIC_READ | GENERIC_WRITE).0,
                    Default::default(),
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            }
            .unwrap();
            let _client = TemporaryHandle(connected);
            let _ = hold.recv_timeout(Duration::from_secs(5));
        });
        let accepted = wait_with_timeout(server.raw(), &|| false, Duration::from_secs(2));
        let _ = release.send(());
        client.join().unwrap();
        assert_eq!(accepted, Ok(()));
    }

    /// Resetting a disconnected instance must never admit an absent client.
    #[test]
    fn reset_listening_instance_is_not_a_connected_peer() {
        let (server, _name) = abandoned_server("listening");
        assert_eq!(
            wait_with_timeout(server.raw(), &|| false, Duration::from_millis(30)),
            Err(NativeError::TimedOut)
        );
    }

    /// STOP wins even when the same attempt's deadline has already expired.
    #[test]
    fn cancellation_precedes_expired_acceptance() {
        assert_eq!(
            wait_with_timeout(HANDLE::default(), &|| true, Duration::ZERO),
            Err(NativeError::Cancelled)
        );
        assert_eq!(
            wait_with_timeout(HANDLE::default(), &|| false, Duration::ZERO),
            Err(NativeError::TimedOut)
        );
    }
}

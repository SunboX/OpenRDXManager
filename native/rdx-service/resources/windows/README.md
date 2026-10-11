<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows native verification contract

`openrdx-hardware-service.xml` is declarative packaging metadata, not an
automatic installer or elevation request. It records a demand-started,
noninteractive `LocalService` identity and the minimum access expected by the
adapter. The companion `openrdx-service-acl.exe` plus
`provision-openrdx-service-access.ps1` form the installable, idempotent service
DACL contract invoked by the signed elevated installer. The thin PowerShell
wrapper makes no ACL or identity decision and is never invoked by Electron.
The executable enters the Windows SCM dispatcher before opening the pipe,
registers only STOP and SHUTDOWN controls, and publishes the exact
`START_PENDING` -> `RUNNING` -> `STOP_PENDING` -> `STOPPED` lifecycle. The
control handler atomically closes connection admission; active reads poll that
state within 250 ms, and `STOPPED` is not published until every RAII connection
lease drains. Eight is the concurrent pipe-instance bound, not a lifetime
session limit: idle accept timeouts retain the pending instance and sequential
sessions continue until STOP/SHUTDOWN while first-instance namespace ownership
remains continuous. Readiness grants process authority only when SCM evidence binds the
current PID to one stable running own-process service, its stable demand-start
and exact executable configuration, and a read-only query of that process
token proves the `LocalService` user SID. The configured account name is not
runtime authority. Registration or running state alone is informational. A
non-service process remains unauthorized until it can prove both elevation and
access to an exact retained device instance.

Production IPC uses only the fixed local named pipe. The metadata requires a
protected DACL granting the service SID, built-in administrators, and the exact
current interactive user resolved from a verified session token at connection
time; anonymous, network, inherited, and caller-authored SID claims are denied.
The current-user ACE is the numeric client-only mask `0x00100183` (read data,
write data, read/write attributes, and synchronize); it excludes both
`FILE_CREATE_PIPE_INSTANCE` and generic write. Electron therefore uses the
packaged direct N-API connector instead of Node/libuv's generic-write pipe open.
That handle-free connector first requests only query-config, query-status, and
start rights for the fixed service. Before demand activation it validates the
exact own-process/LocalService configuration, quoted binary and file identity,
normal error control, empty dependency/load-order configuration, and stable
service snapshot. It calls `StartServiceW` only from `STOPPED`, tolerates the
documented already-running race, and polls `START_PENDING`/`STOP_PENDING` for at
most five seconds. The native transport applies one absolute seven-second
deadline across SCM activation, pipe appearance and connection, and server
identity validation. JavaScript owns a fixed eight-second outer watchdog, then
starts the separate absolute two-second first-frame deadline only after verified
transport readiness.

A signed elevated installer invokes the fixed provisioner with only an action
and a live manager process ID. The provisioner requires that process to be in
the active console session and to have the exact file identity of the trusted,
Authenticode-verified installed `OpenRDXManager.exe` derived from its own fixed
package location. If that exact live manager process is unavailable, the
installer must keep the ACL unchanged and ask the user to launch the installed
manager before retrying; it must not substitute another console process or raw
SID. The provisioner opens only `OpenRDXHardwareService`, derives `TokenUser`
from the pinned process, revalidates the immutable LocalService configuration
and sibling service binary, and reads the existing DACL. It then uses
`SetServiceObjectSecurity` to install a protected canonical ACL containing only
LocalSystem and Administrators full service authority, LocalService
query-status, and the manager's numeric service mask `0x00000015`. The manager
receives query-config, query-status, and start, but no stop, change-config, or
delete right. Provision is idempotent, Verify performs no mutation, and Remove
deletes manager access while preserving and re-reading the three service
authorities. No command accepts a raw service name, executable path, or SID.

The same signed provisioner owns the fixed
`HKLM\SOFTWARE\OpenRDXManager\DriveLetters` root contract. Provision creates
that final key with its protected descriptor in the creation call, with
built-in Administrators as owner, LocalSystem as group, and canonical allowed
ACEs only. LocalSystem and Administrators retain full registry authority.
LocalService receives query/set/create/enumerate plus read-control on the root
so readiness can re-verify the descriptor, and an inherit-only child ACE adding
delete on exact serial child keys; it receives no
permission to delete the preference root. The interactive manager SID is not
present. An existing foreign, inherited, reordered, or broadened ACL is
rejected without repair. A new empty key is rolled back if the paired service
DACL transaction does not finish and re-verify. Verify is read-only, and
runtime readiness remains false until owner, group, protected inheritance, and
the complete canonical DACL all match.

Install ordering is: place and signature-verify the complete application,
register the fixed service, keep the exact installed manager running, invoke
Provision, invoke Verify, then permit first demand start. Uninstall ordering is:
keep the exact installed manager and provisioner present, invoke Remove, verify
success, unregister the service, then remove package files. The thin wrapper is:

```powershell
.\provision-openrdx-service-access.ps1 -Action Provision -ManagerProcessId $managerPid
.\provision-openrdx-service-access.ps1 -Action Verify -ManagerProcessId $managerPid
.\provision-openrdx-service-access.ps1 -Action Remove -ManagerProcessId $managerPid
```

The connector then verifies the pipe server PID against two stable SCM
status/config snapshots, the exact running own-process service, the exact
configured command and executable file identity, and the LocalService process
token before publishing `connect` or any framed bytes.
The pipe rejects remote clients, caps concurrent instances at eight, caps framed payloads
at 65,536 bytes, bounds connection acceptance to ten seconds, and applies a
two-second handshake deadline. A signed installer must materialize the
remaining registration and device-ACL contract without broadening either ACL.
The application does not install, register, elevate, or start the service by
itself.

The LocalService process is also the mandatory first creator and lifetime
namespace owner of `Global\OpenRDXHardwareMutation`. Its protected DACL grants
only LocalSystem, built-in Administrators, and LocalService the numeric
`SYNCHRONIZE | MUTEX_MODIFY_STATE` mask `0x00100001`. Each authenticated service
session and each fully elevated direct `rdxctl` hardware mutation acquires that same
mutex with a zero timeout before constructing a registry-owning backend and
retains it through backend destruction. A pre-existing namespace object,
missing service-created namespace, inaccessible DACL, or live owner fails
closed; no code falls back to an unrelated process-local lock.

Successful `QueryServiceStatusEx` calls trust the initialized status structure;
`pcbBytesNeeded` is used only after the documented insufficient-buffer failure
and authorizes at most one bounded retry.

The Windows companion crate is target-gated. Its public boundary exposes
semantic OpenRDX operations and sanitized results, not Win32 handles, device
paths, arbitrary IOCTL codes, or raw CDB submission. Candidate enumeration is
not RDX admission; the service registry still validates the exact device
identity and capabilities through the retained lease.
SPTI results preserve whether `DeviceIoControl` was invoked. Pre-call
validation/allocation failures remain `NotSent`; any API-invoked failure is
completion-unknown and cannot authorize a transparent retry.
Volume discovery revalidates that exact instance and live disk handle before
and after mapping. Every enumerated volume must be inspectable. A target volume
must have one unambiguous physical extent and a matching complete
`STORAGE_DEVICE_NUMBER`; its ordered topology is then retained with a
lifetime-bound opaque handle lease. The same full evidence is queried again
after enumeration. Safe dismount consumes the exclusive lease set rather than
accepting a volume path or validation-only token. It repeats the complete
enumeration twice, rejects any set/topology/mount drift or inspection failure,
rechecks the original handles, locks every target volume, revalidates the exact
parent, and only then issues the closed dismount operation. Success returns an
opaque, non-cloneable guard that keeps those exact handles and locks alive for
the future Task 6 physical-eject operation; dropping it releases the locks.
Target volume mapping stays query-only; the retained target handle is upgraded
to read-write access only for the declared lock/dismount mutation boundary.

The manufacturing backup store pins every local ancestor with no-follow handles
that deny write/delete sharing. It compares each requested child with the exact
opened spelling from `GetFinalPathNameByHandleW(FILE_NAME_OPENED | VOLUME_NAME_GUID)`,
then continues from the same handle's normalized volume path. This admits real
Windows 8.3 aliases such as `RUNNER~1` without relaxing reparse rejection, file
identity or the complete protected owner/DACL checks. Existing unsafe stores are
rejected without repair. Disposable tests use a current-user policy and exercise
the same durable writer and independent readback; production retains only the
fixed privileged ProgramData store.

Run these commands on a native, current 64-bit Windows CI runner with Rust
1.85 or newer and Node selected from the repository `.nvmrc`:

```powershell
cargo fmt --manifest-path native/rdx-service/Cargo.toml -- --check
cargo check --manifest-path native/rdx-service/Cargo.toml --all-features
cargo check --manifest-path native/rdx-service/Cargo.toml --no-default-features
cargo clippy --manifest-path native/rdx-service/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path native/rdx-service/Cargo.toml --all-features
cargo doc --manifest-path native/rdx-service/Cargo.toml --no-deps --all-features

cargo fmt --manifest-path native/rdx-service/windows-native/Cargo.toml -- --check
cargo check --manifest-path native/rdx-service/windows-native/Cargo.toml --all-features
cargo check --manifest-path native/rdx-service/windows-native/Cargo.toml --no-default-features
cargo clippy --manifest-path native/rdx-service/windows-native/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path native/rdx-service/windows-native/Cargo.toml --all-features
cargo doc --manifest-path native/rdx-service/windows-native/Cargo.toml --no-deps --all-features
cargo build --release --locked --manifest-path native/rdx-service/windows-native/Cargo.toml --bin openrdx-service-acl

npm ci
npm test
npm run smoke
```

The no-device tests may enumerate zero RDX devices and must still pass. Record
Windows compilation, Windows no-device runtime, and physical RDX acceptance as
separate evidence. Neither macOS tests nor cross-compilation are Windows native
runtime proof, and `hardwareVerified` remains `false` until explicit physical
acceptance evidence exists.

The native layout follows Microsoft's current documentation for
[SetupDiGetDeviceInterfaceDetailW](https://learn.microsoft.com/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetailw),
[direct SCSI pass-through](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddscsi/ni-ntddscsi-ioctl_scsi_pass_through_direct),
[storage-adapter property queries](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_query_property),
and
[volume disk extents](https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents).
Pinned volume identity additionally follows
[IOCTL_STORAGE_GET_DEVICE_NUMBER](https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_get_device_number).
The consuming safe-dismount boundary follows
[FSCTL_LOCK_VOLUME](https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume)
and
[FSCTL_DISMOUNT_VOLUME](https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume).
Service authority follows Microsoft's documentation for
[QueryServiceStatusEx](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
and
[QueryServiceConfigW](https://learn.microsoft.com/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
plus read-only process-token inspection through
[OpenProcessToken](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
and
[GetTokenInformation](https://learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation).

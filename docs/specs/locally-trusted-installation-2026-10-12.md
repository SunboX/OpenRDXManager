<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Locally trusted installation

Status: approved by the user on 2026-10-12; implementation and verification in
progress. This document does not establish hardware support.

## Goal

Install OpenRDXManager and its privileged hardware service on Windows and macOS
without purchasing a public code-signing certificate. Administrator approval
establishes trust in one complete installed application. The service continues
to authenticate the caller through operating-system evidence, and the app
authenticates the service before sending protocol requests.

Existing vendor firmware validation, device identity checks, operation locks,
renderer isolation and protocol limits remain mandatory.

## Approaches considered

1. **Administrator-installed application with pinned identity — recommended.**
   Protect the complete installed runtime and enroll its exact content. This
   keeps trust specific to OpenRDXManager and does not add a certificate authority
   to the machine. Updates require an elevated installer to renew enrollment.
2. **Private certificate authority and local signing.** This adds certificate
   issuance, storage, renewal and trust-store administration. The current macOS
   requirement would still need changing; trusting a private CA is not a proven
   replacement for the current service registration flow.
3. **Official distribution signing.** Preserves publisher identity and gives a
   route to notarization, but requires signing credentials and does not satisfy
   the requested certificate-free installation mode.

## Trust boundary

The administrator explicitly approves the installer downloaded from the chosen
source. Local enrollment records that decision; it does not prove the publisher
of an unsigned download. Operating-system download warnings can remain.

Only an elevated installer may create, replace or remove enrollment. Neither
renderer messages, environment variables, command-line application arguments nor
an IPC peer can enroll a path, hash, account or signing requirement. Missing,
malformed, unsupported or tampered enrollment denies privileged access.

Protect every application component that can execute or influence privileged
requests: Electron, app ASAR, unpacked JavaScript, native addons, helpers,
frameworks and executable dependencies. User preferences and backups live
outside that protected runtime and cannot become executable configuration.

Generate a bounded, versioned inventory after packaging has completed all
executable editing and ad-hoc signing. Paths are relative, unique and confined
to the installation. SHA-256 pins runtime files; macOS enrollment additionally
pins the executable's CodeDirectory hash. The elevated installer verifies the
final installed inventory before committing enrollment.

Readers validate owners, complete access-control policy, regular-file type and
link/reparse restrictions on the enrollment and installed runtime. Verification
uses retained handles and checks identities again to reject replacement races.
Do not silently repair an existing installation owned by another principal or
weaken its access controls. Public hashes may be readable; ordinary users must
never be able to change them. Enrollment is not a bearer secret.

Disable packaged Electron's RunAsNode, NODE_OPTIONS and command-line inspection
fuses. Enable embedded ASAR integrity and loading only the packaged ASAR. Reject
untrusted executable startup modes; inspect the actual packaged fuse states.
Keep the existing MCP bridge running under external Node with its protected,
unpacked dependency tree. No renderer Node access is introduced.

An administrator or compromised operating system can replace trusted code and
policy. Local enrollment does not claim to defend against that authority, or
against every possible compromise of an already authenticated app process.

## Windows installation and authentication

Use the elevated NSIS installer and a fixed machine-wide Program Files location
matching the native endpoint contract. Remove arbitrary installation-directory
selection for this mode. Only SYSTEM and Administrators may modify the runtime;
LocalService and interactive users receive the required read/execute access.
Use a separate protected ProgramData enrollment directory, readable as needed
but writable only by SYSTEM and Administrators.

Register only `OpenRDXHardwareService`, using its fixed quoted executable and
arguments, demand start and the existing LocalService account. Enable the
service-specific SID. Preserve canonical service and drive-letter registry
permissions. Provision the interactive user's query-config/query-status/start
rights from a verified live installed Manager process, retaining the existing
active-session and TokenUser checks. If this process is unavailable, setup
remains incomplete with a concrete retry instruction; no arbitrary SID is
substituted.

For local enrollment, replace the provisioner's mandatory public Authenticode
trust decision with protected-package verification. At every pipe connection,
retain kernel PID/session/SID checks and require the exact enrolled installed
executable identity. Verify the complete installed runtime before admitting a
service session. An identical executable copied elsewhere is not authorized.

Retain the client connector's two stable SCM snapshots, server PID, exact binary
identity and LocalService token validation. Add enrollment verification and
service-specific SID verification before protocol bytes are admitted.

Windows raw device access is a separate gate from caller authentication. The
current metadata explicitly requires device permissions that the installer has
not implemented. Setup must enroll only positively identified attached RDX
device instances and their verified target-volume objects, granting the service
SID the necessary access while preserving existing system permissions. Never
change the disk-class ACL or grant all LocalService processes, Users or Everyone
raw disk access. Save the prior per-instance policy in protected storage and
restore only changes still matching our recorded installation state.

Device restart requirements and effective disk/volume permissions must be tested
on Windows. If a driver does not support the scoped grant, report that device as
unsupported; do not silently fall back to LocalSystem. A newly attached or
re-created device instance may require an administrator-approved Repair run with
the device connected. Installer completion and physical device readiness are
reported separately.

## macOS installation and authentication

Add an unsigned `.pkg` installer for the local mode. Install the complete,
ad-hoc-sealed app at `/Applications/OpenRDXManager.app`, protected against
ordinary-user modification, and the helper at a fixed protected system path.
Install a root-owned launch daemon under `/Library/LaunchDaemons` with absolute
helper paths. The local service uses the fixed label `com.openrdx.hardware.local`
and socket `/var/run/openrdx-hardware-local.sock`; its standalone plist remains
`/Library/LaunchDaemons/com.openrdx.hardware.plist`. The separately signed route
retains `com.openrdx.hardware` and `/var/run/openrdx-hardware.sock`. Both routes
retain strict protected socket and authenticated peer checks, and share the
existing hardware mutation lease. Package setup registers the local service
using the administrator-authorized system installation path. Do not assume
ad-hoc signing works through the existing SMAppService registration flow.

Store bounded root-owned enrollment under
`/Library/Application Support/OpenRDXManager/LocalTrust`. Generate a narrowly
parsed requirement combining `com.openrdx.manager` and the enrolled CodeDirectory
hash. Accept no caller-supplied requirement expressions. At connection time,
retain the active console UID, LOCAL_PEERCRED, LOCAL_PEERTOKEN audit-token guest
lookup and strict SecCode validity checks. Additionally require the exact
protected installed app location and verified resource inventory. Another app
using the same bundle identifier, or a copy of our app elsewhere, is rejected.

Add a native macOS client connector that retains its socket while proving the
root-owned endpoint, kernel server credentials and enrolled helper identity.
Only then expose connection readiness or permit protocol bytes. The current
Node socket transport does not perform this server-identity verification.

The local-mode UI displays installed service status and directs missing or
broken enrollment to the package installer. Keep the existing signed
SMAppService mode distinct; each mode owns its separate registration and socket.
An upgrade may retire a previous local registration under the old label only
after protected historical ownership and exact standalone path/program checks,
while retaining the setup and hardware leases. Preserve legacy signed or foreign
registrations at the old label. A foreign registration at the new local label
still blocks setup. Respect OS denial and background-service controls.

Keep ad-hoc signing for executable seals. Evaluate hardened runtime and
entitlements against Electron, its native addons and both architectures; do not
claim those checks passed until the packaged app has actually launched.

## Upgrade, removal and portable distributions

Stop accepting sessions and quiesce active operations before updating service
files. Do not forcibly interrupt hardware mutations. Replace protected runtime
files, verify the final inventory, atomically publish the new enrollment and
restart the verified service. On failure, either restore a verified previous
generation or leave device access disabled with a repair instruction. Never
serve a mixture of old policy and new runtime.

Uninstall stops/unregisters the owned service, revokes enrollment, removes only
owned setup artifacts and restores recorded device ACL changes when safe. Keep
user data and backups. Do not remove a foreign service or policy occupying the
same name.

Windows ZIP and macOS ZIP app copies are portable distributions and do not
silently enroll privileged access. Include the macOS package in the DMG, retain
ZIP app distribution, and publish the package as an additional explicit asset.
Update asset inventory, checksums and documentation accordingly. Installed local
mode is provided by Windows EXE and macOS PKG.

## Implementation boundaries

Introduce focused native local-trust modules and dedicated installer setup
entrypoints. Existing Windows endpoint and service-ACL files are already near
the 1,000-line limit; do not grow them past it. Reuse identity/ACL helpers where
they enforce the same contract. Keep signed and local policy selection explicit
and installer-owned, with no runtime downgrade on signature failure.

Owning sources: `scripts/installer-config.mjs`,
`scripts/prepare-installer-runtime.mjs`, `native/rdx-service/src/endpoint.rs`,
`native/rdx-service/windows-native/src/endpoint.rs`,
`native/rdx-service/windows-native/src/service_acl.rs`,
`native/rdx-service/native/macos/rdx_endpoint.c`,
`native/service-management/macos/openrdx_service_management.mm`, and
`src/main/device-service-endpoint.mjs`. Installer hooks, native client support,
localized setup UI, release inventory and user guides form the remaining scope.

## Acceptance evidence

- Deterministic policy tests reject writable/foreign/malformed enrollment,
  symlinks/reparse points, duplicates, traversal, hard links, tampered runtime,
  stale process identities, copies, spoofed peers and update races.
- Test an authenticated installed app session and rejection of an ordinary
  unauthorized client on each native Windows/macOS architecture. Merely starting
  the service or running a mock is insufficient.
- Exercise clean install, idempotent repair, upgrade, failed setup rollback and
  uninstall on disposable native systems. Verify permissions and absence of
  certificate-authority changes. Test administrator cancellation.
- Run relevant native quality checks, `npm test`, `npm run format:check`,
  Electron smoke, packaged launch and external-Node MCP verification. Check
  packaged fuse states and final artifact inventory after every packaging step.
- Perform separately authorized, non-destructive RDX device checks on Windows
  and macOS. Verify device/volume access as the actual installed service account.
  Do not claim physical support from hardware-free CI.
- Require all affected installer gates to pass before publishing a release.
  This task does not itself publish or replace the existing release.

## Platform references

- Apple's [ad-hoc signature documentation](https://developer.apple.com/documentation/security/seccodesignatureflags/adhoc)
  explains why certificate-identity constraints cannot match ad-hoc code.
- Apple's [code-signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements)
  document pinning a specific code generation using a CodeDirectory hash.
- Apple's [launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
  describes system launch daemons and socket activation. It does not establish
  successful installation on every currently supported macOS version.
- Microsoft's [device-instance security property](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-security)
  documents scoped device security configuration. Effective permissions for
  our disk/volume stack still require native device verification.

## Fresh executable supervisor amendment, 2026-10-13

Privileged host diagnostics reproduced `acl_get_fd_np` returning EINVAL immediately after fork, with unchanged retained hardware-lock identity and successful subsequent descriptor checks. Native CI also observed the same call failing later during repair. The internal syscall cause remains unconfirmed. Apple's [fork caveat](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/man/man2/fork.2) requires exec before library work that is not documented safe after fork; the existing supervisor performs allocating trust checks in that interval. Replace that execution pattern, preserving every admission check.

The package CLI starts a fresh copy of its own verified executable with `posix_spawn`, fixed file actions and a cleared environment except literal `LANG=C`. The internal role is exactly `--internal-supervisor`, with no caller-supplied paths, process IDs, descriptors, configuration or trust roots. The public five-action parser remains unchanged. Internal entry requires root, exact arity, the protected source generation and valid inherited roles before any bootout, enrollment revocation or registration.

Fixed child descriptors are 3 setup lease, 4 hardware lease, 5 the fixed listening transaction socket, 6 a connected root-peer ready channel, 7 the verified package CLI inode and 8 its protected sibling inventory inode. Parent staging duplicates are above these destinations, use close-on-exec, and cannot overwrite another source. Standard streams are opened on `/dev/null`; unrelated descriptors and inherited dynamic-loader/environment configuration must not reach the child. After exec, transferred descriptors regain close-on-exec before any subprocess is started. Source directories, file identities and hashes remain retained and rechecked through spawn and readiness.

The fresh child independently verifies its kernel executable path, source ancestry, inventory pin and descriptor identities; rechecks both fixed root-private single-link leases and their kernel locks; proves the exact listening socket namespace and connected root peer; and repeats historical runtime ownership and registration evidence. A bounded versioned launch frame confirms the private channel. Caller-provided state never selects a registration or bypasses a check.

Parent and child overlap ownership of the same open-file descriptions until readiness. Neither explicitly unlocks them during transfer. Existing commit verification, protected hashes/seals, kernel peer authentication, fixed bootstrap ownership, disabled-on-failure recovery and the 600-second transaction deadline remain required. Spawn or readiness failure refuses payload replacement, preserves the original bounded diagnostic, and terminates/reaps only the exact child returned by the spawn API under a bounded cleanup deadline. Socket cleanup must target the exact owned inode. Failure never triggers an automatic root retry or alternate trust policy.

An ordinary-user exec fixture proves inode and kernel-flock continuity after parent handles close; this is transport evidence only. Privileged installation, repair, copied/tampered rejection, all native architecture builds and the selected read-only physical dock test remain required before publication.

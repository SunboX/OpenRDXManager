<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# macOS privileged service specification — 2026-08-29

Historical design. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

## Goal

Make the packaged Electron application discover and control the connected RDX
hardware on current macOS without running Electron as root, weakening renderer
sandboxing, or asking the user to execute terminal commands. Replace the
misleading `candidate-validation-failed` screen with exact, actionable service
and mounted-media states.

The first physical acceptance target is the connected TANDBERG RDX USB dock,
serial `007820746632`, firmware `0227`, with the disposable 320 GB test
cartridge. The serial is acceptance evidence only and must not be hard-coded in
application or service policy.

## Confirmed Root Cause

The USB Bulk-Only Transport fallback can reach the connected dock when the
native service runs with root authority and the cartridge volume is unmounted.
The normal Electron development runtime deliberately launches the native service
as an unprivileged `stdio` child, so its handshake reports
`insufficient-permission / privileged-service-unavailable`.

The main process currently retains that exact platform capability, but the
main-to-renderer service event and state schemas drop it. The renderer therefore
enables discovery whenever the mode is `native`, even when `hardwareReady` is
false. A scan then reduces the candidate-local failure to the generic
`candidate-validation-failed` diagnostic shown in the supplied screenshot.

On macOS, mounted media is a second prerequisite. Background discovery must not
silently unmount user volumes. The existing native acquisition correctly refuses
exclusive SCSI/USB capture while the cartridge is mounted, but the UI does not
currently offer a safe transition into a management session.

## Considered Approaches

### 1. Embedded `SMAppService` launch daemon (selected)

Package the helper and launchd property list inside a signed application bundle,
register the daemon with `SMAppService`, and connect Electron main to the fixed
root-owned launchd socket. macOS owns admin approval and daemon lifecycle.

This matches the installed macOS SDK contract: the daemon property list lives in
`Contents/Library/LaunchDaemons`, its executable may be selected with
`BundleProgram`, and an administrator approves the daemon in System Settings.
It preserves application relocation support and avoids copying mutable binaries
into privileged filesystem locations.

The app bundle must be code signed. A locally signed Apple Development build is
used only for this Mac's implementation and hardware acceptance. A distributable
build still requires an appropriate Developer ID identity and notarization; local
hardware proof is not release-signing proof.

### 2. Legacy privileged installer package (not selected)

A signed installer could copy the helper and plist into
`/Library/PrivilegedHelperTools` and `/Library/LaunchDaemons`. This is compatible
with launchd but adds installer scripts, duplicated upgrade state, privileged
file replacement, and a separate removal path. It remains a contingency only if
current macOS conclusively rejects a correctly formed local development
`SMAppService` build.

### 3. Run Electron or a development child as root (rejected)

This would grant the Chromium renderer and the complete Electron process tree
unnecessary system authority, undermine the existing security boundary, and
still leave packaging and service lifecycle unresolved.

## Architecture

### Packaged application bundle

Add a deterministic macOS packaging script that creates:

```text
OpenRDXManager.app/
  Contents/
    Info.plist
    MacOS/OpenRDXManager
    Library/
      LaunchDaemons/com.openrdx.hardware.plist
      LaunchServices/openrdx-hardware
    Resources/
      app.asar
      native/macos/openrdx-service-management.node
```

The `LaunchServices` helper is the sole packaged service executable. The macOS
packaged-path resolver is updated to that location so packaging and diagnostics
cannot drift between two helper copies. Electron never launches it as a
privileged child. The production transport continues to connect only to
`/var/run/openrdx-hardware.sock` and never falls back to `stdio`.

The bundle identifier is `com.openrdx.manager`; the helper label remains
`com.openrdx.hardware`. The package script rejects an absent signing identity,
unsigned nested code, unexpected bundle identifiers, incorrect bundle layout,
or failed strict signature verification. Signing proceeds inside-out: native
addon and helper first, application bundle last. The development script accepts
only an explicitly selected identity and never guesses between installed
certificates.

Registration is performed from the final application location. The local
acceptance bundle may run outside `/Applications`, but release installation
places it in `/Applications` so the daemon remains available before login as
recommended by the macOS SDK.

### ServiceManagement bridge

Add a narrow native N-API addon loaded only by Electron main on packaged macOS.
It exposes four fixed operations:

- obtain the status of `com.openrdx.hardware.plist`;
- register the daemon;
- unregister the daemon;
- open the Login Items/System Settings panel after a deliberate user action.

The addon accepts no path, label, plist name, command, environment, or arbitrary
argument from JavaScript. It maps native status and errors to a closed set of
sanitized values:

- `not-registered`;
- `enabled`;
- `requires-approval`;
- `not-found`;
- `invalid-signature`;
- `registration-failed`.

Registration is initiated only from an explicit main-owned setup action.
`requires-approval` produces guidance and an “Open System Settings” button; it
is not reported as a missing RDX drive. Updated helper or plist artifacts are
unregistered and re-registered before reconnection, as required by the SDK.

### Helper peer authentication

The root daemon continues to obtain its socket exclusively from launchd, verify
kernel peer credentials, bind Security.framework validation to the accepted
socket audit token, and hold the process-global hardware lock for the complete
session.

Replace the externally provisioned
`/Library/PrivilegedHelperTools/com.openrdx.manager.requirement` dependency for
the embedded-service path. The signed helper derives its own ten-character Team
Identifier through Security.framework and constructs exactly:

```text
identifier "com.openrdx.manager" and anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"
```

The derived team must satisfy the existing strict grammar. Missing, malformed,
ad-hoc, or conflicting signing evidence fails before socket acceptance. This
binds the accepted manager to the same signing team as the immutable embedded
helper without trusting a user-writable configuration file.

The root-owned socket remains mode `0660` and group `staff`, but filesystem
access alone is not authority. Every accepted manager still must pass code
identity verification. The two-second first-frame deadline, bounded connection
count, framing limits, ownership lock, and operation policy remain unchanged.

### Main process service state

Introduce a `MacOsPrivilegedServiceController` owned by Electron main. At
startup it reads ServiceManagement status before starting the device runtime.
It never treats registration as proof that the daemon is running; after an
enabled status it must connect and complete the existing service handshake.

The controller publishes a strict setup state alongside runtime state. The
service runtime publishes the complete handshaken `platformCapability`,
including its exact `state` and optional sanitized `reason`, through shared
schemas to renderer state. `hardwareReady` remains a derived convenience value,
not a substitute for the capability object.

Discovery admission requires all of:

- service status `ready`;
- service mode `native`;
- privileged handshake evidence;
- platform capability `available`.

If any prerequisite is false, scan actions are disabled or redirected to the
applicable setup action. A generic candidate rejection never overrides a more
specific service or platform failure.

### Safe mounted-candidate transition

Auto Scan stays read-only and non-mutating. A mounted RDX candidate is published
as a sanitized candidate outcome with reason `media-mounted` and an opaque,
single-use preparation token scoped to the current discovery generation. No raw
BSD disk name, IOKit path, USB location, or SCSI command reaches the renderer.

The no-device view shows “RDX cartridge is mounted by macOS” and an explicit
“Unmount and connect” action. After confirmation:

1. main validates the token schema and sends the high-level preparation intent;
2. the service re-enumerates the candidate and proves the same retained USB
   serial, topology, media identity, and discovery generation;
3. Disk Arbitration requests a normal bounded unmount without force;
4. native acquisition captures the exact USB device and validates RDX identity
   with INQUIRY;
5. the service publishes the normal opaque device and refreshed list revision.

Token expiry, topology drift, device removal, multiple matching candidates,
unmount denial, timeout, or failed RDX identity validation aborts without trying
another disk. The user receives the exact sanitized outcome.

While a USB capture lease is active, the app states that the cartridge volume is
temporarily unavailable in Finder. Releasing the device or stopping the service
destroys the capture, waits for the Apple storage driver to rematch, and reports
cleanup failure rather than claiming success without evidence.

Host-volume operations preserve the existing release/rematch discipline. An
operation that needs a mounted filesystem releases SCSI capture, revalidates the
same serial/topology/media fingerprint, requests a normal mount only when the
operation contract requires it, performs the bounded host operation, and then
re-establishes device identity before further SCSI management. No stale mount
path survives capture transitions.

## Renderer Behavior

The screenshot's orange `candidate-validation-failed` panel is replaced by the
highest-priority actionable state:

1. helper not registered: “Hardware service setup required”;
2. helper awaiting approval: “Allow OpenRDXManager in Login Items”;
3. helper enabled but unreachable: “Hardware service unavailable” with retry;
4. platform permission unavailable: exact permission guidance;
5. mounted RDX candidate: “Unmount and connect”;
6. validated empty list: “No RDX drives detected”;
7. genuine post-prerequisite candidate rejection: bounded validation details.

The top-bar hardware badge uses the same state and never contradicts the central
card. Scan buttons are enabled only when discovery admission is true. Setup,
approval, retry, and unmount actions use existing Phosphor icons and the current
cyan/orange visual language; no new icon dependency is needed.

All new copy is added to all eight locale catalogs. Unknown translations do not
fall back to raw reason identifiers in visible UI.

## API and Schema Changes

Extend the shared main/preload/renderer contracts with:

- complete `platformCapability` on service events, service readiness, and device
  list results;
- `privileged` on the ready service state;
- closed `privilegedServiceSetup` state for macOS;
- bounded candidate outcomes containing only `reason`, `count`, and optional
  opaque `preparationToken`;
- `service.setup`, `service.openApprovalSettings`, and
  `devices.prepareCandidate` intents.

Every schema rejects unknown keys. Setup and candidate-preparation actions are
main-process owned, serialized with the operation coordinator, unavailable on
Windows and Linux, and never accept caller-selected native paths or commands.

## Failure and Recovery Semantics

- An unregistered helper is a setup state, not a drive-validation failure.
- User-denied approval remains `requires-approval`; the app never loops
  registration or opens System Settings without a click.
- Invalid signatures fail closed and instruct the developer to rebuild; no
  unprivileged child fallback is attempted.
- Socket absence after `enabled` is `service-unavailable`; retry first refreshes
  ServiceManagement status.
- Mounted media is `busy/media-mounted`; background scans never unmount it.
- Any uncertain unmount, capture, SCSI, mount, or cleanup completion remains
  explicit and blocks mutation until a fresh discovery proves state.
- App shutdown closes the framed session and releases native capture. It does not
  unregister the daemon; uninstall is an explicit maintenance action.

## Testing

### Deterministic tests

- ServiceManagement addon rejects every input and returns only the closed status
  vocabulary.
- Package layout contains the exact helper/plist paths and no development `stdio`
  activation path.
- Strict code signing verification covers the helper, addon, and final bundle.
- The helper derives and validates the team-pinned manager requirement; ad-hoc,
  malformed, mismatched-team, and broadened requirements fail.
- Renderer schemas carry `platformCapability`, `privileged`, and setup state
  without unknown fields.
- Discovery buttons remain disabled for every non-available capability.
- State precedence selects service setup/approval before candidate rejection.
- Mounted candidate tokens are generation-bound, one-shot, opaque, and rejected
  after expiry or identity drift.
- Auto Scan never invokes unmount; the confirmed preparation flow invokes only
  exact normal unmount.
- Capture release and driver-rematch cleanup occurs on success, cancellation,
  disconnect, malformed response, and shutdown.
- Existing Windows and Linux transport, service, schema, and renderer suites stay
  green.

### Runtime and physical acceptance

1. Build the native service, ServiceManagement addon, and packaged app with Node
   22.16.0 and the explicitly selected Apple Development identity.
2. Verify nested and bundle signatures with `codesign --verify --deep --strict`
   and inspect designated requirements before registration.
3. Launch the packaged app, register the daemon, and let the user complete any
   standard macOS approval UI. Do not request or capture a password in the app.
4. Confirm an authenticated privileged handshake reports capability `available`.
5. With the cartridge mounted, confirm the UI reports `media-mounted`, not
   `candidate-validation-failed`.
6. Use “Unmount and connect”; require TANDBERG/RDX identity, serial
   `007820746632`, revision `0227`, and a nonempty opaque device ID.
7. Run status refresh and read-only diagnostics first. Run LED, write/read, safe
   eject, and format only through their existing confirmation and cleanup gates
   on the disposable cartridge.
8. Stop the app and prove capture release, driver rematch, and stable disk state.
9. Run `npm test`, `npm run native:quality`, `npm run format:check`, packaged
   Electron smoke, and focused Git diff inspection.

Physical results must record what macOS reported separately from what the user
visually observed. The local Apple Development build proves this Mac and device;
it does not prove notarized distribution or physical Windows/Linux behavior.

## Release and Rollback Boundaries

This implementation may create and locally run a signed development app and may
register its embedded service because the user explicitly approved that system
change. It does not publish, push, notarize, or distribute artifacts.

Rollback unregisters `com.openrdx.hardware` through the same fixed
ServiceManagement bridge, waits for service termination and socket removal, and
then removes only the generated local application bundle. It does not delete
unrelated launchd jobs, Login Items, devices, volumes, or user data.

If current macOS rejects the correctly signed local development bundle because a
notarized Developer ID build is mandatory, implementation stops at that proven
boundary. The legacy installer approach is not activated automatically.

## Approved Decisions

- Keep Electron and its renderer unprivileged.
- Use an embedded `SMAppService` launch daemon and the fixed authenticated socket.
- Use a narrow native ServiceManagement bridge with no caller-selected paths.
- Bind manager acceptance to the helper's own signing team and fixed manager
  identifier.
- Preserve non-mutating Auto Scan and require explicit confirmation before
  unmounting a mounted RDX cartridge.
- Carry exact service/platform state to the UI and prioritize it over generic
  candidate diagnostics.
- Use the existing Phosphor icon set and established cyberpunk visual system.
- Treat local Apple Development hardware proof separately from notarized release
  proof.

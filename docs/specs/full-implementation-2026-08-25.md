<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Full implementation specification — 2026-08-25

Historical design. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

## Goal

Turn the secure, intentionally empty Electron scaffold into a modern cross-platform RDX management application. The app must expose every user-visible capability documented under `docs/protocols/features/`, control real RDX hardware through native Windows, Linux, and macOS transports, preserve the original Manager's drive-list and four-area mental model, and present it in a cleaner dark cyberpunk interface inspired by the supplied Analytics Console reference.

The current development machine has no attached RDX dock. Completion therefore distinguishes source/build/runtime verification from physical-device verification. No feature may be described as hardware-verified until its acceptance flow has run against a supported physical dock on the named operating system.

## Evidence and Safety Policy

The numbered feature documents, the two protocol references, the extracted binaries and focused implementation review under `analysis/`, the four supplied PDFs, and the related parent-folder firmware projects are implementation evidence. They are not all equally authoritative:

1. Exact reference CDBs, byte layouts, checks, parser behavior, OS API calls, and proven return mappings may be implemented directly and covered with golden tests.
2. Vendor-documented workflows, warnings, limits, and compatibility rules define user-visible behavior and prerequisite gates.
3. Strong inferences may inform read-only parsing or diagnostics when clearly labeled and independently bounded.
4. Unknown selector meanings, descriptor fields, on-media encryption layout, or OS behavior must not be guessed for a privileged or mutating command.

The application uses an explicit `evidence-incomplete` capability state. The UI explains why the feature is unavailable and links to the relevant evidence boundary. Resolving an unknown requires focused protocol review, a deterministic fixture, and a test proving the reference mapping before the operation can be enabled.

## Scope

### Included

- A complete Electron renderer for device discovery, status, encryption/password management, tests, utilities, logs, summary/support, updates, language selection, settings, and no-device/error states.
- A narrow preload bridge and main-process orchestration layer with schema validation, operation locking, dialogs, tray behavior, event logging, update checks, localization, and lifecycle management.
- A Rust native hardware service with a shared RDX command/parser layer and platform adapters for Windows, Linux, and macOS.
- Real device enumeration, inquiry/status, exact reference diagnostics, firmware update, mode changes, safe eject, host-side write/read test, and applicable platform volume operations.
- Focused verification of security selector/descriptor behavior from supplied artifacts before enabling real security writes.
- A command-line companion supporting help, version, scan, eject target, and force-eject behavior.
- Automated tests and native build checks for all three operating systems, plus a documented physical-hardware acceptance matrix.
- Eight UI languages: English, Chinese, German, French, Italian, Portuguese, Spanish, and Japanese.
- Local, freely licensed fonts and Phosphor Icons; no remote renderer resources.

### Not Included in This Implementation

- Guessing proprietary security fields or inventing a new encryption format that is incompatible with vendor RDX media.
- Claiming compatibility with historical operating systems that the selected Electron/runtime toolchains no longer support. The app displays the documented historical vendor matrix as reference material while targeting current toolchain-supported Windows, Linux, and macOS releases.
- Code signing, notarization, commercial installer distribution, publishing, deployment, or release. Build metadata and privilege/service manifests may be implemented, but external signing and distribution remain separate release work.
- Current availability of historical vendor HTTP/FTP endpoints. Update handling must fail safely when an endpoint or manifest is unavailable.

## Product Structure

### Unified Window

The original application used a Drive List window and a separate four-tab Management pop-up. OpenRDXManager combines these into one responsive command-center window:

- a persistent left device rail showing every validated RDX dock;
- a central workspace with **Status**, **Encryption**, **Tests**, and **Utilities**;
- a right command/activity rail on wide windows;
- a top bar for service health, event log, help/support, and global status;
- operation drawers and dialogs for focused, stepwise workflows.

This keeps the selected dock, media state, privilege state, current operation, and recent evidence visible without allowing two conflicting windows to control one device.

### Visual System

- Blue-black background and dark navy panels.
- Cyan for selection, live data, routine actions, and transport health.
- Orange for recommended attention and critical but intentional operations.
- Red only for destructive actions, irreversible consequences, and failures.
- Green for confirmed success and healthy state.
- Thin luminous borders, restrained glow, a subtle scanline texture, geometric headings, and highly readable body text.
- Oxanium for display headings and Inter for dense data/body copy, bundled locally under their free licenses.
- Phosphor Icons from the MIT-licensed `@phosphor-icons/web` package, bundled locally. Its broad hardware, storage, security, diagnostic, connectivity, status, navigation, and system-action catalog plus regular, bold, fill, thin, and duotone variants fits the technical neon interface without requiring improvised glyphs.
- Duotone icons identify device and feature categories, regular icons serve navigation and routine controls, bold/fill variants are reserved for compact status emphasis, and destructive actions pair a red icon with explicit text. No critical action or state relies on an icon alone; icon-only secondary controls receive accessible labels and tooltips.
- Motion is short and functional: state changes, progress, drawer transitions, and error focus. Reduced-motion preferences disable decorative animation.

### Responsive and Accessible Behavior

The design targets a comfortable `1280 x 800` window and remains usable at `1024 x 768`. The right rail collapses first; device selection becomes a drawer at narrower widths. All actions are keyboard reachable, focus is visible, dialogs trap and restore focus correctly, colors meet accessible contrast, icons have labels, tables retain semantic headers, and live progress uses restrained announcements.

## Architecture

### Electron Renderer

The renderer remains sandboxed with `contextIsolation: true`, `sandbox: true`, and `nodeIntegration: false`. It uses native ESM, semantic HTML, focused CSS files, and small rendering/controller modules rather than introducing a framework or bundler.

The renderer owns presentation state only:

- selected device and active area;
- forms and local validation;
- modal/drawer visibility;
- translated copy;
- progress and operation results received from main.

It never receives a raw SCSI method, OS device path mutation primitive, process launcher, unrestricted filesystem API, or arbitrary service message.

### Preload Contract

The preload bridge exposes a frozen, named API grouped by intent:

- `devices.list()` and `devices.scan()`;
- `devices.subscribe(listener)`;
- `operations.start(request)` and narrowly scoped safe cancellation;
- `operations.subscribe(listener)`;
- `files.chooseFirmware()` and explicit export destinations;
- `logs.list()`, `logs.setEnabled()`, and `logs.export()`;
- `support.generateSummary()`;
- `updates.check()`;
- `settings.get()` and validated settings changes;
- application metadata and platform capability reads.

Every request and event passes exact schema validation in both preload and main. Unknown keys, unknown operations, stale device revisions, invalid enum values, oversized strings, and malformed identifiers are rejected.

### Electron Main Process

The main process owns:

- `DeviceServiceClient`: starts, handshakes with, supervises, and restarts the native service;
- `OperationCoordinator`: enforces one active operation per application and serializes device-changing work;
- `SafetyPolicy`: checks operation class, confirmation token, device identity revision, media state, privilege, and platform capability;
- `EventLogger`: rotates local logs, redacts secrets, and emits UI-safe activity entries;
- `SupportSummaryService`: combines sanitized host/application state with device data;
- `UpdateService`: retrieves and validates version metadata without applying firmware automatically;
- `LocalizationService`: selects one of eight bundled catalogs from saved settings or `-l <code>`;
- tray, menu, activate, close-during-operation, and cross-platform quit behavior.

### Native Hardware Service

`native/rdx-service/` is one Rust package with a testable library and two binaries:

- `openrdx-hardware`: long-lived local service used by Electron;
- `rdxctl`: command-line scan/eject/version interface.

The library is split by responsibility:

- `model`: device identity, capability, media, status, operation, progress, and error types;
- `protocol`: exact command builders, bounded parsers, sense decoding, firmware validation, security descriptors, and endian helpers;
- `operations`: high-level status, diagnostic, firmware, mode, eject, security, and host-volume state machines;
- `transport`: a minimal raw-command trait plus deterministic fixture transport;
- `platform/windows`, `platform/linux`, and `platform/macos`: enumeration, raw transport, privilege, mount/eject/format, and platform-only configuration;
- `service`: framed local request/event protocol, handshake, limits, and cancellation policy;
- `redaction`: zeroization and log-safe representations.

The service accepts only high-level operation requests. Raw CDB submission is internal to the protocol/transport layers and is never part of public Electron IPC.

### Local Service Protocol

Electron launches or connects to the hardware service through an OS-local, access-controlled channel. Messages are length-framed typed payloads with:

- protocol version and platform capability handshake;
- request ID and operation ID;
- stable dock identity plus discovery revision;
- exact operation variant and bounded parameters;
- progress events with stage, fraction, message key, and recoverability;
- terminal success or structured failure;
- no diagnostic serialization of passwords, derived keys, or firmware bytes.

The service independently repeats device identity, capability, media-state, and evidence checks. A renderer or main-process validation bug must not be sufficient to send an unsafe command.

### Platform Adapters

#### Windows

- SetupAPI and Configuration Manager for discovery.
- `CreateFileW`, `IOCTL_SCSI_PASS_THROUGH_DIRECT`, and buffered pass-through for raw commands.
- Win32 disk/volume APIs for dismount, layout, mount, and eject.
- Persistent drive-letter mapping keyed to dock serial, with current-platform implementation rather than depending silently on the old RDXmon binary.
- A constrained elevated service or helper endpoint with an access-controlled named pipe for privileged operations.

#### Linux

- udev/sysfs for candidate discovery and stable device-to-volume mapping.
- `SG_IO` for raw commands, including data-in, data-out, sense, timeout, and residual handling.
- Mount/volume integration through native APIs and explicitly detected host tools where no stable library API exists.
- udev and polkit/service definitions that grant only the required device/service access.

#### macOS

- IOKit device discovery and SCSI task interfaces where the current device stack exposes them.
- Disk Arbitration for unmount and eject.
- ServiceManagement-based privileged helper boundary and platform-native volume operations.
- A capability probe that reports `transport-unavailable` instead of pretending raw pass-through exists when the active macOS driver stack does not expose a safe user-client path.

The macOS adapter must not reuse the obsolete vendor kernel extension on modern systems or disable platform security. If a modern supported dock requires a separately signed DriverKit component that cannot be built without an entitlement, the app reports the precise missing transport capability and the design treats entitlement/signing as external release work.

## Device and Operation Model

### Stable Device Identity

Each discovered candidate has an internal opaque ID plus OS path, vendor, product, serial, connection type, and discovery revision. A device becomes manageable only after identity/capability replies are consistent with RDX. UI requests contain the opaque ID and revision, never a renderer-supplied OS path.

### Capability States

Every feature resolves to one of:

- `available`;
- `busy`;
- `unsupported-product`;
- `unsupported-platform`;
- `wrong-media-state`;
- `authentication-required`;
- `insufficient-permission`;
- `host-dependency-missing`;
- `evidence-incomplete`;
- `transport-unavailable`;
- `hardware-unverified` metadata in About/diagnostics, which does not by itself disable a fixture-tested operation.

The UI shows the exact reason rather than silently hiding every unavailable control. Product-inapplicable controls may be hidden only when their absence makes the screen clearer, while status/support still exposes the reason.

### Operation Classes

- **Read-only:** discovery, inquiry/status, update check, summaries, logs.
- **Routine:** self-test, LED test with cleanup, safe eject, access enable/disable.
- **Configuration:** drive letter, drive mode, SATA mode, password-slot changes.
- **Critical:** firmware update, forced eject.
- **Destructive:** partition/format, AES setup/removal/reset, passwordless erase.

Critical and destructive operations use a preflight stepper. Destructive operations require an exact-device confirmation derived from the visible dock and cartridge identity. One operation locks device switching, other areas, conflicting actions, and window close until the service reaches a safe terminal state. Cancellation is available only for stages the operation explicitly declares cancellable.

## Complete Feature Coverage

### 1. Discovery and Auto Scan

Enumerate supported docks, validate candidates with INQUIRY/status/capability commands, display every Drive List field, provide a debounced manual scan, and enable a non-overlapping one-second Auto Scan by default. No-media docks remain visible. Empty lists disable management actions and present setup/permission diagnostics.

### 2. Drive and Cartridge Status

Display every documented drive and cartridge field, including blank/no-media behavior, bounded LOG SENSE parameter parsing, capacity, read/write counters, status, write protection, cam, bus power, modes, policy, and external-only qualifiers. Preserve raw sense and unavailable-field reasons for the support view without exposing arbitrary binary buffers to the renderer.

### 3. Event Logging

Provide an enabled/disabled setting, timestamped structured operation entries, redacted OS/SCSI errors, deterministic rotation to `_RDXManager.bak`, UI filtering, and export. Passwords, key material, firmware bytes, authorization blobs, and unrestricted environment data never enter logs.

### 4. System Summary

Generate `RdxSystemSummary.txt` from sanitized host/application/service state and all currently discoverable RDX devices. The workflow chooses a destination, shows the saved path, and explains which contextual details to attach to a support request. XML summary generation is available through the CLI only after its schema is defined rather than invented.

### 5. Help, About, and Updates

Bundle local help derived from the current docs, implement F1, About, Support, and explicit/silent update checks, and distinguish Manager updates from applicable dock firmware. Network or manifest failure changes no device state. Firmware application always remains a separate local-image Utility workflow.

### 6-11. Encryption, Passwords, Permissions, and Automatic Authentication

Implement all documented screen states, warnings, strength levels, reset-policy choices, access enable/disable states, master/additional slot limits, unique names, permissions, change/delete flows, temporary-slot requirement, SATA III automatic-association lifecycle, read-only option, and reinsertion verification guidance.

Real security commands are enabled only after the focused review establishes and tests the exact selector/descriptor mapping and, for AES mode, the compatible on-media host encryption format. Basic protection, session authentication, and slot operations may become available independently when their specific mapping is proven. AES setup/removal remains blocked if compatible cross-platform volume handling is not proven; the app must not substitute an incompatible new format.

Passwords are limited exactly as specified in the implementation reference, converted to transient byte buffers only at the service boundary, zeroized after use, and never persisted. Loss/reset/data-recovery and warranty warnings remain explicit.

### 12-14. Tests

- Self Test sends exact `1D 04 00 00 00 00`, supports the documented no-media then with-media isolation procedure, and reports SCSI/sense results.
- LED Test sends the exact on/off payloads, sequences visible phases, and always attempts to restore normal LED ownership after success, failure, removal, or service shutdown.
- Write/Read Test validates a selected mounted writable RDX volume, creates a uniquely named test file, writes deterministic data, flushes, closes, reopens, reads, compares, and deletes it. Cleanup failure is reported separately.

All tests share stage progress, green success, gray/red failure, prerequisites, result evidence, and event-log entries.

### 15. Firmware Update

Accept `.BIP` only for proven USB2/SATA1 legacy paths and `.BIN` only for proven USB3/SATA3 paths. Require no media, validate structure/product/version/signature policy, warn against power loss, stream exact chunks, perform the documented single whole-file retry, finalize, poll reconnect, and confirm the reported revision. Signed-firmware downgrade restrictions and signature sense failures are first-class results. Utility locking remains active through reconnect or a terminal recovery state.

### 16. Persistent Drive Letter

On supported Windows USB3 docks with no media, list available letters, set/reset a serial-specific preference, and verify the result after future media arrival. Other platforms report not applicable. The implementation changes only the selected dock mapping.

### 17. Partition and Format

Require inserted writable media and exact-device destructive confirmation. Offer NTFS default and exFAT quick format where the host has supported tooling, perform safe dismount/layout/format/rediscovery, ensure a non-zero MBR signature when using that layout, and prove the formatted volume reappears. Missing filesystem tooling becomes `host-dependency-missing` rather than a partial destructive attempt.

### 18. Fixed/Removable Mode

Require mode-change support and no media, read page `0x34`, preserve unrelated bytes, write only the operation-mode field with correct saved-page semantics, refresh/reconnect, and verify readback. Selecting the current value sends no setter.

### 19. SATA III Link Mode

Expose only on SATA III, require no media or complete the safe-eject offer first, retain `1.5G / 3G` as the recommended default, explain the SSD-only benefit of `3G / 6G`, write the exact field, issue the unit reset, reconnect, and verify readback. Selecting the current value sends no setter.

### 20. Eject and CLI

Safe eject flushes/unmounts through the host, applies required RDX policy/command handling, and confirms media departure. Force eject is separately confirmed and describes cached-data risk. `rdxctl` supports help, version, scan, eject target, and force options with stable documented process exit codes defined by this project.

### 21. Language Selection

Select English, Chinese, German, French, Italian, Portuguese, Spanish, or Japanese from settings or `-l <code>`. Invalid codes fall back to English and produce a non-sensitive warning. Application, native file-dialog labels controlled by the app, progress, errors, and help navigation use message keys; raw device/vendor strings remain unchanged.

### 22. Tray and Background Integration

Provide tray device/status summary, open/focus, scan, safe eject for the selected ready device, logging state, and Exit. Background scan never overlaps. Sleep/wake stops active polling, invalidates stale sessions, refreshes on wake, and never initiates eject. The app warns instead of exiting during an unsafe operation stage.

### 23. Installation, Launch, Exit, and Uninstallation

Implement application lifecycle, startup argument parsing, privilege/service readiness diagnostics, first-run host-dependency checks, and clean service shutdown. Platform packaging/service installation manifests may be prepared, but signed installers, deployment, and uninstall verification remain release work requiring explicit authorization and platform credentials.

### 24. Platform, Hardware, and Media Compatibility

Build the runtime capability matrix from host OS, privilege/service state, INQUIRY identity, firmware revision, interface type, capability pages, and media state. Display the historical vendor compatibility matrix separately from the application's live capability result.

### 25. Support and Troubleshooting

Provide a guided diagnostic order: updates, logging, status, tests, summary. Include write-protect/read-only checks, SATA driver limitation history, cache/removal-policy guidance, firmware retry guidance, exact documented support contacts, and the relevant historical fixes. Administrative host-driver changes remain explanatory help, not automated mutations.

## Error Handling and Recovery

Errors carry a stable code, translated user message key, stage, platform/transport category, retryability, device identity, optional safe sense summary, and support correlation ID. Raw stack traces and sensitive payloads stay out of renderer messages.

The operation coordinator differentiates:

- preflight rejection before any command;
- host operation failure before device mutation;
- command/sense failure with no further stage;
- partial multi-stage operation requiring explicit recovery guidance;
- expected disconnect followed by reconnect timeout;
- device removal or identity change;
- cleanup/rollback failure after the primary failure.

Retries occur only where documented or demonstrably idempotent. Firmware performs one full retry from offset zero on ordinary transfer failure. Destructive formatting and security operations never restart automatically after an ambiguous partial result.

## Persistence and Privacy

Settings persist language, Auto Scan, Event Logging, window bounds, last non-sensitive view, and optional update-check preference. Device passwords, derived keys, automatic-auth secrets, authorization external forms, raw firmware data, and cartridge file contents never persist in renderer storage or app settings.

Logs and summaries are local-only. Network access is limited to explicit or configured silent update metadata checks. The application never uploads a summary, log, device identifier, or usage analytics.

## Testing and Verification

### JavaScript Tests

- Preload API allowlist and rejected-input tests.
- Main-process schema, safety policy, operation locking, service supervision, log redaction/rotation, localization, and lifecycle tests.
- Renderer state and DOM tests for every primary state, feature gate, dialog, progress stage, no-device view, error view, and language switch.
- Accessibility checks for keyboard order, labels, dialog focus, and status announcements.

### Rust Tests

- Exact golden bytes for every reference CDB and payload.
- Bounded parser tests for normal, short, malformed, and unknown parameters.
- Sense/result mapping tests.
- Firmware validation/chunk/finalize/retry/reconnect fixtures.
- Security descriptor/KDF tests using only proven reference fixtures.
- Operation state-machine tests using a deterministic fake transport and fake host adapter.
- Public service protocol limits, identity revision, capability rejection, cancellation, redaction, and crash recovery tests.

### Cross-Platform Build Verification

The native service and Electron application are built/tested on current supported macOS, Windows, and Linux runners. Platform adapters have compile-time and fixture coverage on their native OS. A successful build is not hardware proof.

### Runtime and Visual Verification

- `npm test` for the full JavaScript suite.
- `cargo test` for the native library/service.
- `npm run format:check` and Rust formatting/lint checks.
- `npm run smoke` to create and load a real Electron window and complete a service handshake in no-device mode.
- Browser/Electron interaction of every main screen and dialog at `1024 x 768` and `1440 x 900`, with screenshot review for clipping, contrast, focus, loading, empty, disabled, warning, and error states.

### Physical Hardware Acceptance

Maintain a matrix by operating system, dock model/interface, firmware revision, cartridge type, and operation. Read-only status comes first, followed by safe diagnostics, eject, configuration with no media, controlled firmware on a recoverable test dock, password/security fixtures, and destructive format only on explicitly disposable media.

Until hardware is attached, the handoff states plainly:

- what was unit/fixture tested;
- what compiled and ran on each OS;
- what is implemented but hardware-unverified;
- what remains evidence-incomplete or needs platform signing/entitlement.

## Implementation Sequence

1. Establish shared models, schemas, fixture device data, renderer shell, localization, and Phosphor/font assets.
2. Add preload/main boundaries, service supervision, logs, operation locking, and the no-device/fixture runtime.
3. Build Rust protocol primitives, parsers, fake transport, service protocol, and safe read-only discovery/status.
4. Add Windows, Linux, and macOS native adapters with native build checks.
5. Implement tests, eject, mode setters, firmware validation/update, and platform volume operations in increasing risk order.
6. Perform focused security protocol review and enable each credential/AES operation only as its exact mapping becomes proven.
7. Complete help, updates, summary, tray, CLI, compatibility, troubleshooting, and all eight translations.
8. Run the full verification suite, visual QA, focused diff review, and publish the pending hardware-acceptance matrix without claiming unavailable physical proof.

## Approved Design Decisions

- Unified dashboard rather than reproducing the old two-window layout.
- Guided preflight workflows for critical/destructive operations.
- Rust native hardware service with Windows, Linux, and macOS adapters.
- Two validation boundaries and no renderer raw-command API.
- Explicit evidence-incomplete and hardware-unverified states.
- Dark cyan/orange Analytics Console-inspired styling with locally bundled Phosphor Icons.

<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Vendor feature documentation implementation plan — 2026-08-25

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Incorporate every feature-relevant, operational, compatibility, warning, troubleshooting, and release-history detail from the four bundled PDFs into the RDX Manager feature documentation.

**Architecture:** Preserve the existing 22 feature-specific documents and their implementation implementation/protocol sections. Add PDF-derived sections with explicit source/page provenance, correct conflicting details, and create three focused documents for installation, compatibility, and support material that does not belong to a device command feature.

**Technology:** Markdown, extracted PDF text, shell-based coverage/link checks

**Spec:** `original-inputs/RDX+Manager+Manual+1022447+Rev+F.pdf`, `original-inputs/RDX+Manager+2.0.1+Release+Notes.pdf`, `original-inputs/RDX+Dock+USB+3.0+FW_0283+Release+Notes.pdf`, and `original-inputs/RDX+Manager+for+Mac+Release+Notes+ver.+0.1.0.1.pdf`

## Constraints

- Preserve all verified implementation CDB layouts, return values, offsets, and transport behavior.
- Label PDF statements as documented behavior or historical release information; do not present release-note claims as newly implementation protocol facts.
- Include minor fixes, UI states, defaults, prerequisites, warnings, and troubleshooting details, not only headline features.
- Correct the event-log backup filename to `_RDXManager.bak`.
- Keep all feature documentation below `docs/protocols/features/` and maintain working relative links.

---

### Task 1: Drive-list and host-facing features

**Files:**

- Modify: `docs/protocols/features/01-drive-discovery-and-auto-scan.md`
- Modify: `docs/protocols/features/02-drive-and-cartridge-status.md`
- Modify: `docs/protocols/features/03-event-logging.md`
- Modify: `docs/protocols/features/04-system-summary.md`
- Modify: `docs/protocols/features/05-help-and-update-checking.md`
- Modify: `docs/protocols/features/21-gui-language-selection.md`
- Modify: `docs/protocols/features/22-tray-and-background-integration.md`

**Interfaces:**

- Consumes: manual chapters 2-4 and Windows/Mac release histories.
- Produces: complete UI, timing, status-field, logging, language, summary, tray, and host-integration behavior.

- [ ] Add exact Drive List columns, button/menu behavior, one-second scan behavior, empty-list state, and rapid-scan historical fix.
- [ ] Add every documented Status field and external-only qualifier.
- [ ] Correct restart rotation to `_RDXManager.bak` and add support-use guidance.
- [ ] Add text-summary workflow, support attachment guidance, encryption-status history, and historical command-line XML summary capability without inventing its switch syntax.
- [ ] Add Help/F1/About/Support/update behavior and minor release-history details.
- [ ] Add Japanese and exact bundled translation evidence.
- [ ] Add install/service/tray, removal-policy, RDXmon timer, sleep, and background fixes.

### Task 2: Security and credential features

**Files:**

- Modify: `docs/protocols/features/06-full-disk-aes-256-xts-encryption.md`
- Modify: `docs/protocols/features/07-basic-password-protection.md`
- Modify: `docs/protocols/features/08-disable-and-enable-cartridge-access.md`
- Modify: `docs/protocols/features/09-change-and-remove-protection.md`
- Modify: `docs/protocols/features/10-advanced-passwords-and-permissions.md`
- Modify: `docs/protocols/features/11-automatic-drive-media-authentication.md`

**Interfaces:**

- Consumes: manual pages 16-30 and Windows/firmware release notes.
- Produces: exact workflows, limits, permission semantics, progress behavior, prerequisites, data-loss boundaries, and compatibility.

- [ ] Add USB3 firmware 0283 prerequisite and SATA III protected-media compatibility.
- [ ] Add exact password-strength scale and recommendations.
- [ ] Add reset/erase checkbox implications, physical-access warning, impossible recovery, and warranty statement.
- [ ] Add enable/disable/change/remove dialog flows and progress outcomes.
- [ ] Add eight-slot permission model, master-slot restrictions, naming, and confirmation behavior.
- [ ] Add automatic-authentication read-only option, re-enable procedure, button states, reinsertion verification, and seven-drive/unlimited-cartridge limits.

### Task 3: Tests and drive utilities

**Files:**

- Modify: `docs/protocols/features/12-self-test.md`
- Modify: `docs/protocols/features/13-led-test.md`
- Modify: `docs/protocols/features/14-write-read-test.md`
- Modify: `docs/protocols/features/15-firmware-update.md`
- Modify: `docs/protocols/features/16-set-and-reset-drive-letter.md`
- Modify: `docs/protocols/features/17-partition-and-format-cartridge.md`
- Modify: `docs/protocols/features/18-change-drive-mode.md`
- Modify: `docs/protocols/features/19-change-sata-iii-mode.md`
- Modify: `docs/protocols/features/20-eject-cartridge-and-command-line.md`

**Interfaces:**

- Consumes: manual pages 30-37, firmware release notes, Windows release notes, and existing protocol descriptions.
- Produces: complete user-visible test/utility behavior while preserving exact protocol details.

- [ ] Add common green/gray progress behavior and per-test prerequisites/results.
- [ ] Add firmware file-family/model rules, media-removal flow, retry guidance, signed-firmware downgrade restriction, affected models, and 0227/0278/0283 behavior history.
- [ ] Add USB3-only persistent drive-letter applicability, available-letter filtering, RDXmon override, and reset behavior.
- [ ] Add NTFS default, exFAT option, quick-format semantics, MBR-signature safeguard, confirmation, and progress.
- [ ] Add media-ejection prerequisite, default/recommended SATA setting, SSD-only performance benefit, and disabled USB control.
- [ ] Add GUI/CLI eject steps, administrator requirement, fixed-mode and host-disconnect history, macOS sleep fixes, cache/FUA implications, and safe/forced boundaries.

### Task 4: Cross-cutting PDF features and index

**Files:**

- Create: `docs/protocols/features/23-installation-launch-exit-and-uninstallation.md`
- Create: `docs/protocols/features/24-platform-hardware-and-media-compatibility.md`
- Create: `docs/protocols/features/25-support-troubleshooting-and-known-limitations.md`
- Modify: `docs/protocols/features/README.md`

**Interfaces:**

- Consumes: all four PDFs.
- Produces: discoverable documentation for administrative requirements, silent install, supported systems/models/media, support workflow, write-protect/read-only diagnosis, SATA-driver limitation, and historical installation fixes.

- [ ] Document normal and `isSilent=true` installation, launch, Exit, uninstall, privilege, previous-version replacement, and historical installer fixes.
- [ ] Document the complete Windows/macOS compatibility matrix, all QuikStor/QuikStation and media compatibility, backward-compatible USB/SATA scope, and firmware/model-specific qualifications.
- [ ] Document support-summary procedure, support information checklist, regional contacts, cannot-write checks, read-only SATA limitation, tested Intel driver, boot-risk warning, and update checks.
- [ ] Add all three documents to the feature index and describe PDF-derived versus implementation evidence boundaries.

### Task 5: Verification

**Files:**

- Modify: `analysis/VERIFICATION.md`

**Interfaces:**

- Consumes: all enriched feature documents.
- Produces: reproducible proof of section completeness, working links, PDF-term coverage, and corrected factual details.

- [ ] Run a required-section check for all 25 feature files.
- [ ] Resolve every local Markdown link and report zero missing targets.
- [ ] Search for the incorrect `_RDXManager.txt.bak` form and require zero matches.
- [ ] Search for a defined checklist of high- and low-priority PDF details and require every item to appear in an appropriate feature file.
- [ ] Record commands and results in `analysis/VERIFICATION.md`.

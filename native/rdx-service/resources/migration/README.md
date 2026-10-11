<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Migration bootstrap build inputs

These reviewed, unpersonalized files are embedded by the native service. Keep
them in source control: normal application builds do not regenerate firmware.

- `openrdx-migration-template.rom.bin`: copied unchanged from the research
  bootstrap build; SHA-256
  `4ed054e7d257fb67d0690fb9e168081d67aaafca01c99d1c3bca52d6ce686cf8`.
- `build-evidence.json`: provenance for that template, including compiler and
  source revisions. It records that hardware verification has not occurred.

The optional research build lives in `analysis/migration-bootstrap/`. Updating
these inputs requires reviewing its regenerated template and evidence together;
the compiled template digest remains an independent integrity check. No device
records are included in the template.

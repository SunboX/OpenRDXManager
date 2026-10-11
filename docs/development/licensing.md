<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Licensing

OpenRDXManager follows the licensing split used by [OpenRDX](https://github.com/SunboX/OpenRDX): repository-owned software uses `AGPL-3.0-or-later`; project documentation and non-code media use `CC-BY-SA-4.0`.

The root [LICENSE](../../LICENSE), [NOTICE](../../NOTICE) and [commercial licensing notice](../../COMMERCIAL-LICENSE.md) describe the project grants and attribution. Full license texts are in `LICENSES/`. A commercial licensing notice is not itself a license grant.

## File notices

Hand-written source and documentation carry SPDX copyright and license notices where their file format supports comments. [`.reuse/dep5`](../../.reuse/dep5) supplies repository-wide per-file metadata, including JSON, lockfiles, images, structured configuration, generated source, retained evidence and compile-fail fixtures. Line-sensitive fixtures and files close to the source line limit use metadata rather than extra header lines. This keeps diagnostic baselines and data formats intact.

New project code should carry `SPDX-FileCopyrightText: 2026 André Fiedler` and `SPDX-License-Identifier: AGPL-3.0-or-later`, adjusted for the actual contributors and years. Project-authored Markdown and images use `CC-BY-SA-4.0`. Keep package metadata consistent with these declarations.

## Third-party boundaries

Vendor documents and original firmware retain the publisher's terms. The firmware fixtures and migration bootstrap retain the Texas Instruments / OpenRDX split declared in `.reuse/dep5`; their bytes are unchanged. A `LicenseRef` notice records this boundary and does not grant redistribution rights.

Dependencies retain the licenses and notices supplied by their packages. When preparing an application distribution, retain the notices required for all shipped dependencies and verify the terms of every bundled third-party artifact. The project licenses do not replace those terms.

Return to [development documentation](README.md).

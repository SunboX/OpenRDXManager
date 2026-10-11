<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Installation

OpenRDXManager runs on macOS, Windows and Linux. Opening its window and obtaining device access are separate steps: the native hardware service must be available and authorized before a dock can be managed.

## Launch and device access

1. Connect the RDX dock and launch OpenRDXManager.
2. Follow any service setup or approval action shown by the application.
3. Check the service status, then select the dock in the device rail. Use **Scan for RDX devices** if it has not appeared.
4. Check the selected dock's identity and cartridge status before starting an operation.

Available actions depend on the operating system, service privileges, dock firmware and inserted media. An unavailable action includes a reason; a visible application window alone does not establish hardware access.

## Run from source

The source checkout needs Node.js 22.12.0 or newer, npm and Rust with Cargo. `.nvmrc` selects Node.js 22.16.0. Run these commands from the project directory:

```sh
nvm install
nvm use
npm ci
npm start
```

On macOS, use the approved Terminal and enter administrator credentials only in its `sudo` prompt. Follow the [macOS development setup](development/macos-hardware-access.md) if the helper cannot start.

Windows source builds also require Microsoft C++ Build Tools matching the selected Node/Rust architecture. Raw-device access needs the required Windows privileges; the development launcher does not request elevation automatically.

Linux mounted-cartridge operations require the system bus and UDisks2. Formatting also needs the native tool for the selected filesystem. See [development dependencies](development/dependencies.md) and the [project requirements](development/runtime-setup.md#requirements).

Continue with [app usage](app-usage.md) or [troubleshooting](troubleshooting.md).

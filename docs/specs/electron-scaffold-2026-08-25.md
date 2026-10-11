<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Electron scaffold specification — 2026-08-25

Historical design. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

## Goal

Create a minimal, empty Electron desktop application named OpenRDXManager in the existing `OpenRDXManager` folder. The scaffold must use plain JavaScript native ECMAScript modules (`.mjs`) and launch without a transpiler, bundler, frontend framework, or packaging system.

## Scope

The application opens one blank window titled `OpenRDXManager`. This task adds only the project foundation: Electron lifecycle handling, a local HTML renderer, secure window defaults, basic project metadata, and focused automated checks. Device access, RDX features, menus, installers, application packaging, auto-update, persistence, and visual design are out of scope.

## Architecture

The npm package is a private native-ESM project whose entry point is `src/main.mjs`. Electron's main process owns application lifecycle and creates a single `BrowserWindow`. That window loads `src/index.html` from disk. The page loads an intentionally empty `src/renderer.mjs` module so future renderer behavior has an established entry point.

Window settings live in a small Electron-independent module. This keeps the security-sensitive configuration easy to inspect and allows Node's built-in test runner to verify it without starting a graphical Electron process.

## Components

- `package.json`: project identity, Node.js requirement, Electron development dependency, and start/test scripts.
- `.nvmrc`: selects the installed Node.js 22 runtime compatible with the current Electron release.
- `src/main.mjs`: Electron startup, window creation, macOS reactivation, and cross-platform shutdown behavior.
- `src/window-options.mjs`: immutable default window dimensions and web preferences.
- `src/index.html`: minimal blank document with the application title and renderer module reference.
- `src/renderer.mjs`: empty renderer entry point.
- `test/window-options.test.mjs`: verifies dimensions and secure Electron defaults.
- `test/project-structure.test.mjs`: verifies the package entry point and blank renderer document contract.
- `.gitignore`: excludes dependencies, logs, and generated build output.
- `README.md`: minimal setup, launch, and test instructions.

## Runtime Flow

1. `npm start` launches Electron using the package entry point.
2. Electron waits until the application is ready.
3. The main process creates one browser window using the shared window options.
4. The window loads the local HTML file and displays an empty renderer surface.
5. Closing all windows quits on Windows and Linux. On macOS, the app remains active and recreates the window when its dock icon is selected.

## Security and Error Handling

The renderer runs with context isolation and sandboxing enabled and Node integration disabled. No preload bridge is added because the empty renderer has no privileged capability to expose. A failed HTML load is reported to standard error and terminates the application with a failing exit code rather than leaving a broken window running.

## Testing and Verification

Implementation follows a red-green sequence with Node's built-in test runner. Tests first describe the required project structure and browser-window security settings, are observed failing before source files exist, and then pass after the minimal scaffold is added.

Final verification consists of:

1. Selecting Node.js 22.16.0, installing the current Electron release selected by npm, and recording it in the lockfile.
2. Running the complete automated test suite.
3. Starting the real Electron application in a deterministic smoke-test mode that creates and loads the window, reports successful loading, and exits cleanly.
4. Checking the focused Git diff/status to confirm no files outside `OpenRDXManager` were changed or staged.

## Deliberate Omissions

Electron Forge, Vite, TypeScript, linting frameworks, UI libraries, application icons, distributable packaging, and feature code are intentionally omitted. They can be introduced later when a concrete requirement justifies them.

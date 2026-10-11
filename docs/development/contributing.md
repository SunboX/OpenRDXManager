<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Contributing

## Formatting

Format the application source, tests, root Markdown files, and package metadata:

```sh
npm run format
```

Check formatting without changing files:

```sh
npm run format:check
```

The formatter is intentionally scoped away from `analysis/`, `docs/`, and `original-inputs/` so research artifacts and vendor source material are not rewritten.

## Project Layout

```text
OpenRDXManager/
├── src/
│   ├── main.mjs             Electron lifecycle and window creation
│   ├── window-options.mjs   Secure BrowserWindow defaults
│   ├── index.html           Local-only dashboard document and CSP
│   ├── renderer.mjs         Renderer/service-binding entry point
│   ├── renderer/            Store, controller, intents, and views
│   └── styles/              Local responsive dashboard styles
├── electron-test/               Separate real-Electron QA entrypoints
├── test/                    Node test-runner suites
├── docs/                    RDX and project documentation
├── analysis/                Extraction and protocol review material
└── original-inputs/         Immutable vendor source material
```

## Security Baseline

The renderer is sandboxed, uses context isolation, and has Node integration disabled. Privileged functionality should remain in the Electron main process and be exposed to the renderer only through a narrow, validated preload bridge when a concrete feature requires it.

## Development Guidelines

See [`AGENTS.md`](../../AGENTS.md) for repository structure, coding conventions, testing expectations, Electron security rules, and contribution guidance.

Return to [development documentation](README.md).

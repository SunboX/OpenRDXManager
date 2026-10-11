<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Development dependencies

Use the Node version selected by `.nvmrc` before installing or running:

```sh
nvm install
nvm use
npm ci
npm start
```

To use that version in new terminals as well, run `nvm alias default 22.16.0`.
An already-open terminal retains its active Node version until `nvm use` runs.

`npm start` and `npm run smoke` also work from an older Node shell when the
project's Node version is already installed by nvm. Their launcher selects the
installed `.nvmrc` version before running the build, authorization, and Electron.
It gives every child the selected Node and npm paths without changing the
parent terminal. A supported active Node version is retained. If the pinned
version is missing, run the reported `nvm install` command once.

`node_modules` contains native executables and must not be shared between
operating systems or CPU architectures. Keep `package-lock.json` when moving a
checkout; install its locked dependencies on the destination computer.

The project's `postinstall` hook runs Electron's `install-electron` command.
Electron 44 otherwise defers that download until its first use; explicitly
installing it makes the executable available before runtime verification.

The `prebuild:preload` hook checks the project's Node requirement and executes
esbuild and Electron before building. This covers `npm start`, `npm run smoke`,
`npm run build:runtime`, and the Electron test commands through their existing
preload build hooks. The Electron probe runs only as Node; it does not open a
window or contact the hardware service.

If native dependencies are missing or incompatible, the hook runs the active
npm CLI with `ci --include=dev --include=optional` once, explicitly targeting
the current host, then checks the executables again in a fresh process.
This replaces `node_modules` without changing the lockfile. Repair may need
network access; an installation failure or failed second check stops the build
and reports the problem. A healthy installation does not trigger a reinstall.

Direct build and test commands still require a supported active Node version;
their dependency hook stops before installation with the exact `nvm` commands
when needed. The startup launcher and dependency hook do not change a caller's
shell version or its global configuration.

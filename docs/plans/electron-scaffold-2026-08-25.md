<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Electron scaffold implementation plan — 2026-08-25

Historical plan. This records the requirements and approach at the stated date; it does not establish current completion or hardware acceptance. See [verification](../verification/README.md) for recorded results.

**Goal:** Create a minimal, empty Electron application named OpenRDXManager using native JavaScript ECMAScript modules.

**Architecture:** Electron's main process creates one securely configured `BrowserWindow` and loads a blank local HTML document with an empty renderer module. Browser-window settings remain in an Electron-independent module so Node's built-in test runner can verify the security contract without launching a GUI.

**Technology:** Node.js, npm, Electron, JavaScript native ESM (`.mjs`), HTML, Node test runner

**Spec:** `docs/specs/electron-scaffold-2026-08-25.md`

## Constraints

- Use plain JavaScript native ECMAScript modules (`.mjs`).
- Do not add a transpiler, bundler, frontend framework, packaging system, preload bridge, or application features.
- The application window title is exactly `OpenRDXManager` and its renderer body is blank.
- Enable context isolation and sandboxing; disable Node integration.
- Keep all changes inside the `OpenRDXManager` folder.
- Require Node.js 22.12.0 or newer and select Node.js 22.16.0 through `.nvmrc` in this workspace.
- Use the current Electron release resolved by npm and commit the generated lockfile.

---

### Task 1: Project and Renderer Contract

**Files:**

- Create: `.gitignore`
- Create: `.nvmrc`
- Create: `package.json`
- Create: `package-lock.json`
- Create: `README.md`
- Create: `src/index.html`
- Create: `src/renderer.mjs`
- Create: `test/project-structure.test.mjs`

**Interfaces:**

- Consumes: Node.js and npm from the host environment.
- Produces: npm scripts `start`, `test`, and `smoke`; Electron entry point `src/main.mjs`; blank renderer document `src/index.html`.

- [ ] **Step 1: Write the failing project-contract test**

Create `test/project-structure.test.mjs`:

```js
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const packageUrl = new URL('../package.json', import.meta.url)
const htmlUrl = new URL('../src/index.html', import.meta.url)
const rendererUrl = new URL('../src/renderer.mjs', import.meta.url)

test('package exposes the minimal native-ESM Electron commands', async () => {
    const packageJson = JSON.parse(await readFile(packageUrl, 'utf8'))

    assert.equal(packageJson.name, 'openrdxmanager')
    assert.equal(packageJson.productName, 'OpenRDXManager')
    assert.equal(packageJson.private, true)
    assert.equal(packageJson.type, 'module')
    assert.equal(packageJson.engines.node, '>=22.12.0')
    assert.equal(packageJson.main, 'src/main.mjs')
    assert.equal(packageJson.scripts.start, 'electron .')
    assert.equal(packageJson.scripts.test, 'node --test')
    assert.equal(packageJson.scripts.smoke, 'electron . --smoke-test')
    assert.match(packageJson.devDependencies.electron, /^\^?\d+\.\d+\.\d+$/)
})

test('renderer document is blank and loads the ESM renderer entry point', async () => {
    const [html, renderer] = await Promise.all([readFile(htmlUrl, 'utf8'), readFile(rendererUrl, 'utf8')])

    assert.match(html, /<title>OpenRDXManager<\/title>/)
    assert.match(html, /<body>\s*<script type="module" src="\.\/renderer\.mjs"><\/script>\s*<\/body>/)
    assert.equal(renderer.trim(), '')
})
```

- [ ] **Step 2: Run the test to verify it fails for the missing package**

Run: `node --test test/project-structure.test.mjs`

Expected: FAIL with `ENOENT` for `package.json` and `src/index.html`.

- [ ] **Step 3: Add the minimal project and renderer files**

Create `.gitignore`:

```gitignore
node_modules/
dist/
out/
*.log
.DS_Store
```

Create `package.json` without a hand-written Electron version; npm fills it in during installation:

```json
{
    "name": "openrdxmanager",
    "productName": "OpenRDXManager",
    "version": "0.1.0",
    "description": "A minimal Electron application for OpenRDXManager.",
    "private": true,
    "type": "module",
    "engines": {
        "node": ">=22.12.0"
    },
    "main": "src/main.mjs",
    "scripts": {
        "start": "electron .",
        "test": "node --test",
        "smoke": "electron . --smoke-test"
    }
}
```

Create `.nvmrc`:

```text
22.16.0
```

Create `src/index.html`:

```html
<!doctype html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>OpenRDXManager</title>
    </head>
    <body>
        <script type="module" src="./renderer.mjs"></script>
    </body>
</html>
```

Create a zero-byte `src/renderer.mjs`.

Create `README.md`:

````markdown
# OpenRDXManager

Minimal Electron application scaffold using native JavaScript modules.

## Development

Node.js 22.12 or newer is required. With nvm, select the checked-in version first:

```sh
nvm use
npm install
npm start
```

Run the automated checks with `npm test`.
````

- [ ] **Step 4: Install the current Electron release**

Run: `nvm use && npm install --save-dev electron@latest`

Expected: npm adds an exact compatible Electron range to `devDependencies`, creates `package-lock.json`, and exits successfully.

- [ ] **Step 5: Run the focused test and verify it passes**

Run: `npm test -- test/project-structure.test.mjs`

Expected: 2 tests pass with 0 failures.

- [ ] **Step 6: Commit the project contract**

```bash
git add .gitignore .nvmrc package.json package-lock.json README.md src/index.html src/renderer.mjs test/project-structure.test.mjs
git commit -m "build: initialize OpenRDXManager Electron project"
```

---

### Task 2: Secure Browser Window Options

**Files:**

- Create: `src/window-options.mjs`
- Create: `test/window-options.test.mjs`

**Interfaces:**

- Consumes: no Electron runtime APIs.
- Produces: immutable named export `windowOptions` with `width`, `height`, and `webPreferences` for `BrowserWindow`.

- [ ] **Step 1: Write the failing window-options test**

Create `test/window-options.test.mjs`:

```js
import assert from 'node:assert/strict'
import test from 'node:test'

import { windowOptions } from '../src/window-options.mjs'

test('window uses a practical default size', () => {
    assert.equal(windowOptions.width, 1024)
    assert.equal(windowOptions.height, 768)
})

test('renderer uses secure Electron defaults explicitly', () => {
    assert.deepEqual(windowOptions.webPreferences, {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true
    })
    assert.equal(Object.isFrozen(windowOptions), true)
    assert.equal(Object.isFrozen(windowOptions.webPreferences), true)
})
```

- [ ] **Step 2: Run the test to verify it fails for the missing module**

Run: `node --test test/window-options.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/window-options.mjs`.

- [ ] **Step 3: Implement immutable secure defaults**

Create `src/window-options.mjs`:

```js
export const windowOptions = Object.freeze({
    width: 1024,
    height: 768,
    webPreferences: Object.freeze({
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true
    })
})
```

- [ ] **Step 4: Run the complete test suite and verify it passes**

Run: `npm test`

Expected: 4 tests pass with 0 failures.

- [ ] **Step 5: Commit the window configuration**

```bash
git add src/window-options.mjs test/window-options.test.mjs
git commit -m "feat: define secure Electron window defaults"
```

---

### Task 3: Electron Lifecycle and Startup Smoke Test

**Files:**

- Create: `src/main.mjs`

**Interfaces:**

- Consumes: Electron `app` and `BrowserWindow`; Node's `fileURLToPath`; `windowOptions` from `src/window-options.mjs`; `--smoke-test` from the `smoke` npm script.
- Produces: one loaded application window in normal mode; deterministic success message and clean exit in smoke-test mode.

- [ ] **Step 1: Run the smoke command to verify it fails for the missing main process**

Run: `npm run smoke`

Expected: FAIL because Electron cannot find `src/main.mjs`.

- [ ] **Step 2: Implement the minimal Electron lifecycle**

Create `src/main.mjs`:

```js
import { fileURLToPath } from 'node:url'
import { app, BrowserWindow } from 'electron/main'

import { windowOptions } from './window-options.mjs'

const htmlPath = fileURLToPath(new URL('./index.html', import.meta.url))
const isSmokeTest = process.argv.includes('--smoke-test')

async function createWindow() {
    const window = new BrowserWindow(windowOptions)
    await window.loadFile(htmlPath)
    return window
}

async function start() {
    await app.whenReady()
    await createWindow()

    if (isSmokeTest) {
        console.log('OpenRDXManager smoke test passed')
        app.quit()
        return
    }

    app.on('activate', async () => {
        if (BrowserWindow.getAllWindows().length === 0) {
            await createWindow()
        }
    })
}

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit()
    }
})

start().catch((error) => {
    console.error('Failed to start OpenRDXManager:', error)
    process.exitCode = 1
    app.quit()
})
```

- [ ] **Step 3: Run the smoke command and verify real Electron startup**

Run: `env -u ELECTRON_RUN_AS_NODE npm run smoke`

Expected: output contains `OpenRDXManager smoke test passed` and the command exits with status 0. Removing `ELECTRON_RUN_AS_NODE` is required only in the Codex host environment, where that variable is inherited globally; the npm script itself remains cross-platform.

- [ ] **Step 4: Run all automated tests**

Run: `npm test`

Expected: 4 tests pass with 0 failures.

- [ ] **Step 5: Check the focused repository state**

Run: `git diff --check && git status --short -- .gitignore .nvmrc package.json package-lock.json README.md src test docs/plans/electron-scaffold-2026-08-25.md docs/specs/electron-scaffold-2026-08-25.md`

Expected: no whitespace errors; only the planned OpenRDXManager main-process and plan files remain uncommitted within the focused path list. Pre-existing untracked research and documentation files remain untouched.

- [ ] **Step 6: Commit the Electron lifecycle**

```bash
git add src/main.mjs docs/plans/electron-scaffold-2026-08-25.md
git commit -m "feat: launch empty OpenRDXManager window"
```

- [ ] **Step 7: Perform final fresh verification**

Run: `nvm use && npm test && env -u ELECTRON_RUN_AS_NODE npm run smoke && git status --short -- .gitignore .nvmrc package.json package-lock.json README.md src test docs/plans/electron-scaffold-2026-08-25.md docs/specs/electron-scaffold-2026-08-25.md`

Expected: 4 tests pass, smoke output reports successful loading, and the command reports no uncommitted scaffold files. Pre-existing untracked research and documentation files are outside this focused status check.

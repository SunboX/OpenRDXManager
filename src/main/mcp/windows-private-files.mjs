// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { win32 } from 'node:path'
import { randomBytes } from 'node:crypto'
import { resolveWindowsMcpAddonPath } from './windows-addon-path.mjs'

const require = createRequire(import.meta.url)
const applicationRoot = fileURLToPath(new URL('../../../', import.meta.url))

/** Resolves the fixed development/packaged native addon, never a credential-supplied library.
 * @returns {string} Absolute app-owned addon location.
 */
function addonPath() {
    return resolveWindowsMcpAddonPath(applicationRoot, process.resourcesPath)
}

/** Creates closed native storage authority without following a caller-provided library.
 * @param {string} directory - Main-owned local directory.
 * @returns {object} Native fixed-filename operations; construction performs no file I/O.
 */
function store(directory) {
    if (typeof directory !== 'string' || !win32.isAbsolute(directory)) throw new TypeError('unsafe-mcp-directory')
    return require(addonPath()).createMcpStorage(directory)
}

/** Prepares the exact owned MCP directory with native user-only ACL proof.
 * @param {string} directory - Main-owned directory.
 * @returns {Promise<void>} Resolves after verified preparation.
 */
export async function prepareWindowsMcpDirectory(directory) {
    await store(directory).prepare()
}

/** Reads only a fixed MCP filename; credentials require an already-private directory and file.
 * @param {string} path - Main-owned settings path or explicit bridge token path.
 * @param {number} maximum - Strict caller read bound.
 * @returns {Promise<string>} Bounded UTF-8 content; buffers are cleared after conversion.
 */
export async function readWindowsMcpText(path, maximum) {
    if (typeof path !== 'string' || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 4096) throw new TypeError('unsafe-mcp-file')
    const name = win32.basename(path)
    if (!['token', 'settings.json'].includes(name)) throw new TypeError('unsafe-mcp-file')
    const native = store(win32.dirname(path))
    const bytes = await (name === 'token' ? native.readToken() : native.readSettings())
    try {
        if (!Buffer.isBuffer(bytes) || bytes.length > maximum) throw new Error('mcp-file-too-large')
        return bytes.toString('utf8')
    } finally {
        bytes?.fill?.(0)
    }
}

/** Atomically publishes only bounded settings under the fixed native filename.
 * @param {string} directory - Prepared private directory.
 * @param {string} name - Must be settings.json.
 * @param {string} text - Main-validated serialized settings.
 * @returns {Promise<void>} Resolves after flush, readback and atomic publication.
 */
export async function writeWindowsMcpSettings(directory, name, text) {
    if (name !== 'settings.json' || typeof text !== 'string') throw new TypeError('unsafe-mcp-file')
    const bytes = Buffer.from(text, 'utf8')
    try {
        await store(directory).writeSettings(bytes)
    } finally {
        bytes.fill(0)
    }
}

/** Creates an exclusive private credential or verifies the existing one without replacing it.
 * @param {string} directory - Prepared private directory.
 * @returns {Promise<string>} Canonical bearer token retained only by main/bridge.
 */
export async function loadWindowsMcpToken(directory) {
    const entropy = randomBytes(32)
    const proposed = Buffer.from(`${entropy.toString('hex')}\n`, 'ascii')
    entropy.fill(0)
    let actual
    try {
        actual = await store(directory).ensureToken(proposed)
        if (!Buffer.isBuffer(actual) || !/^[a-f0-9]{64}\n?$/.test(actual.toString('ascii'))) throw new Error('invalid-mcp-token')
        return actual.toString('ascii').trim()
    } finally {
        proposed.fill(0)
        actual?.fill?.(0)
    }
}

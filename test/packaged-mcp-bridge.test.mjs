// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { verifyPackagedMcpBridge } from '../scripts/verify-packaged-app.mjs'

/** Builds an ordinary-file packaged bridge tree. @param {object} context - Cleanup owner. @param {string} source - Bridge module body. @returns {Promise<string>} Resources directory. */
async function createPackagedBridge(context, source) {
    const resources = await mkdtemp(join(tmpdir(), 'openrdx-packaged-mcp-'))
    context.after(async () => rm(resources, { recursive: true, force: true }))
    await mkdir(join(resources, 'app.asar.unpacked', 'scripts'), { recursive: true })
    await mkdir(join(resources, 'app.asar.unpacked', 'src', 'main', 'mcp'), { recursive: true })
    await writeFile(join(resources, 'app.asar.unpacked', 'scripts', 'mcp-stdio.mjs'), 'throw new Error("Do not start endpoints during import verification")')
    await writeFile(join(resources, 'app.asar.unpacked', 'src', 'main', 'mcp', 'stdio-bridge.mjs'), source)
    return resources
}

test('the packaged bridge imports through external Node without starting endpoints or credentials', async (context) => {
    const resources = await createPackagedBridge(context, 'export function startStdioBridge() { throw new Error("Must not start") }')
    const output = await verifyPackagedMcpBridge(resources, { platform: 'linux' })
    assert.match(output, /packaged MCP bridge passed: external-node=true/u)
})

test('packaged verification rejects missing transitive SDK imports and invalid bridge exports', async (context) => {
    for (const source of ['import "missing-packaged-sdk"; export function startStdioBridge() {}', 'export const startStdioBridge = null']) {
        const resources = await createPackagedBridge(context, source)
        await assert.rejects(verifyPackagedMcpBridge(resources, { platform: 'linux' }))
    }
})

test('an absent ordinary-file entrypoint cannot be accepted merely because the bridge module imports', async (context) => {
    const resources = await createPackagedBridge(context, 'export function startStdioBridge() {}')
    await rm(join(resources, 'app.asar.unpacked', 'scripts', 'mcp-stdio.mjs'))
    await assert.rejects(verifyPackagedMcpBridge(resources, { platform: 'linux' }), /ENOENT/u)
})

test('Windows packaged verification checks the app-owned N-API export without constructing storage', async (context) => {
    const resources = await createPackagedBridge(context, 'export function startStdioBridge() {}')
    let request
    /** Observes the exact external Node probe without loading a Windows DLL on another host. @param {string} command - Node executable. @param {string[]} args - Module source arguments. @returns {Promise<object>} Probe output. */
    async function execute(command, args) {
        request = { command, args }
        return { stdout: 'OpenRDXManager packaged MCP bridge passed: external-node=true\n', stderr: '' }
    }
    await verifyPackagedMcpBridge(resources, { platform: 'win32', executeImpl: execute })
    assert.equal(request.command, process.execPath)
    const source = request.args.at(-1)
    assert.ok(source.includes(JSON.stringify(join(resources, 'native', 'windows', 'openrdx-windows-client.node'))))
    assert.match(source, /typeof addon\.createMcpStorage/u)
    assert.doesNotMatch(source, /createMcpStorage\(/u)
})

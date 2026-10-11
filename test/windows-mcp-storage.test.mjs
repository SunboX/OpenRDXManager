// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createRequire } from 'node:module'
import { link, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { McpHttpServer } from '../src/main/mcp/server.mjs'
import { McpOperationStore } from '../src/main/mcp/operation-store.mjs'
import { createMcpToolRegistry } from '../src/main/mcp/tool-registry.mjs'
import { preparePrivateDirectory, readPrivateText, writePrivateText, loadMcpToken } from '../src/main/mcp/private-files.mjs'

const windows = { skip: process.platform !== 'win32', timeout: 30_000 }
const require = createRequire(import.meta.url)
const addonPath = fileURLToPath(new URL('../out/native/windows/openrdx-windows-client.node', import.meta.url))
const aclScript = fileURLToPath(new URL('./helpers/windows-log-acl.ps1', import.meta.url))
const execute = promisify(execFile)

/** Creates isolated native storage; no listener, real profile or hardware is used.
 * @param {object} context - Test lifecycle owner.
 * @returns {Promise<object>} Disposable root and closed native operations.
 */
async function fixture(context) {
    const temporary = await mkdtemp(join(tmpdir(), 'openrdx-mcp-native-'))
    context.after(async () => await rm(temporary, { recursive: true, force: true }))
    const directory = join(temporary, 'MCP-André')
    const addon = require(addonPath)
    return { temporary, directory, native: addon.createMcpStorage(directory), addon }
}

/** Independently inspects or deliberately tampers with fixture ACLs without exposing SIDs.
 * @param {string} path - Exact fixture path.
 * @param {string} mode - Fixed helper mode.
 * @returns {Promise<object|undefined>} Private-access proof when inspecting.
 */
async function acl(path, mode = 'inspect') {
    const { stdout } = await execute('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-File', aclScript, path, mode], { windowsHide: true, timeout: 10_000 })
    return mode === 'inspect' ? JSON.parse(stdout) : undefined
}

test('Windows MCP persists private settings and a stable token through production file helpers', windows, async (context) => {
    const { directory } = await fixture(context)
    await preparePrivateDirectory(directory)
    await writePrivateText(directory, 'settings.json', '{"enabled":false,"port":48170}\n')
    await writePrivateText(directory, 'settings.json', '{"enabled":true,"port":48171}\n')
    assert.equal(await readPrivateText(join(directory, 'settings.json')), '{"enabled":true,"port":48171}\n')
    const token = await loadMcpToken(directory)
    assert.match(token, /^[a-f0-9]{64}$/u)
    assert.equal(await loadMcpToken(directory), token)
    assert.equal((await readPrivateText(join(directory, 'token'), 65)).trim(), token)
    for (const path of [directory, join(directory, 'settings.json'), join(directory, 'token')]) assert.equal((await acl(path)).private, true)
    assert.deepEqual((await readdir(directory)).sort(), ['settings.json', 'token'])
    await assert.rejects(readPrivateText(join(directory, 'token'), 10), /too-large/u)
    await assert.rejects(writePrivateText(directory, 'another-file', 'content'), /unsafe/u)
})

test('Windows MCP refuses exposed credentials without changing their bytes or permissions', windows, async (context) => {
    const { directory, native } = await fixture(context)
    await native.prepare()
    const bytes = Buffer.from('a'.repeat(64) + '\n')
    await native.ensureToken(bytes)
    const path = join(directory, 'token')
    await acl(path, 'make-public')
    const before = await acl(path)
    await assert.rejects(native.readToken(), /dacl-unverified/u)
    await assert.rejects(native.ensureToken(Buffer.from('b'.repeat(64) + '\n')), /dacl-unverified/u)
    assert.deepEqual(await readFile(path), bytes)
    assert.deepEqual(await acl(path), before)
})

test('Windows MCP rejects hardlinks before changing contents or ACLs', windows, async (context) => {
    const { temporary, directory, native } = await fixture(context)
    await native.prepare()
    const external = join(temporary, 'existing.txt')
    await writeFile(external, 'keep external')
    const before = await acl(external)
    await link(external, join(directory, 'token'))
    await link(external, join(directory, 'settings.json'))
    await assert.rejects(native.readToken(), /unsafe-object/u)
    await assert.rejects(native.writeSettings(Buffer.from('{"enabled":true}')), /unsafe-object/u)
    assert.equal(await readFile(external, 'utf8'), 'keep external')
    assert.deepEqual(await acl(external), before)
})

test('Windows MCP rejects directory junctions and exposes no arbitrary filename or log operations', windows, async (context) => {
    const { temporary, directory, native, addon } = await fixture(context)
    const external = join(temporary, 'external')
    await mkdir(external)
    await symlink(external, directory, 'junction')
    await assert.rejects(native.prepare(), /unsafe-object/u)
    assert.deepEqual(await readdir(external), [])
    assert.equal(native.rotate, undefined)
    assert.equal(native.openAppend, undefined)
    assert.throws(() => native.readToken.call(addon.createLogSecurity(external)), /receiver-invalid/u)
    assert.throws(() => native.readToken('arbitrary'), /arguments-invalid/u)
    assert.throws(() => native.writeSettings(Buffer.alloc(4097)), /arguments-invalid/u)
    assert.throws(() => native.ensureToken(Buffer.alloc(66)), /arguments-invalid/u)
    assert.throws(() => addon.createMcpStorage(directory, 'token'), /arguments-invalid/u)
})

test('Windows MCP rejects malformed token initialization and oversized existing settings', windows, async (context) => {
    const { directory, native } = await fixture(context)
    await native.prepare()
    await assert.rejects(native.ensureToken(Buffer.from('wrong')), /invalid-mcp-token/u)
    assert.deepEqual(await readdir(directory), [])
    await native.writeSettings(Buffer.from('{}'))
    await writeFile(join(directory, 'settings.json'), Buffer.alloc(4097, 97))
    await assert.rejects(native.readSettings(), /too-large/u)
})

test('Windows MCP refuses exposed settings and preserves existing bytes on failed replacement', windows, async (context) => {
    const { directory, native } = await fixture(context)
    await native.prepare()
    await native.writeSettings(Buffer.from('{"enabled":false}'))
    const path = join(directory, 'settings.json')
    await acl(path, 'make-public')
    const before = await acl(path)
    await assert.rejects(native.writeSettings(Buffer.from('{"enabled":true}')), /dacl-unverified/u)
    await assert.rejects(native.readSettings(), /dacl-unverified/u)
    assert.equal(await readFile(path, 'utf8'), '{"enabled":false}')
    assert.deepEqual(await acl(path), before)
    assert.deepEqual(await readdir(directory), ['settings.json'])
})

test('Windows MCP serializes native credential initialization and never overwrites the winning token', windows, async (context) => {
    const { directory, native } = await fixture(context)
    await native.prepare()
    const results = await Promise.all(Array.from({ length: 16 }, (_, index) => native.ensureToken(Buffer.from(index.toString(16).repeat(64) + '\n'))))
    try {
        for (const result of results) assert.deepEqual(result, results[0])
        assert.deepEqual(await native.readToken(), results[0])
        assert.deepEqual(await readdir(directory), ['token'])
    } finally {
        for (const result of results) result.fill(0)
    }
})

test('Windows MCP rejects directory-valued fixed files without creating temporary artifacts', windows, async (context) => {
    const { directory, native } = await fixture(context)
    await native.prepare()
    await mkdir(join(directory, 'settings.json'))
    await assert.rejects(native.writeSettings(Buffer.from('{}')), /unsafe-object/u)
    await assert.rejects(native.readSettings(), /unsafe-object/u)
    assert.deepEqual(await readdir(directory), ['settings.json'])
})

test('a real Windows stdio bridge authenticates from the private native token file and rejects later exposure', windows, async (context) => {
    const { directory } = await fixture(context)
    await preparePrivateDirectory(directory)
    const token = await loadMcpToken(directory)
    const services = { app: { getInfo: () => ({ ok: true, app: { name: 'Isolated Windows fixture', version: '1', platform: 'win32' } }) } }
    const server = new McpHttpServer({ token, tools: createMcpToolRegistry({ services, operationStore: new McpOperationStore() }) })
    const endpoint = await server.start(0)
    context.after(() => server.stop())
    for (const exposed of [false, true]) {
        if (exposed) await acl(join(directory, 'token'), 'make-public')
        const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL('../scripts/mcp-stdio.mjs', import.meta.url))], env: { OPENRDX_MCP_URL: endpoint, OPENRDX_MCP_TOKEN_FILE: join(directory, 'token') }, stderr: 'pipe' })
        let stderr = ''
        transport.stderr?.on('data', (chunk) => {
            stderr += chunk
        })
        const client = new Client({ name: 'windows-private-file-test', version: '1' })
        try {
            if (exposed) {
                await assert.rejects(client.connect(transport))
                assert.match(stderr, /Cannot connect to OpenRDXManager MCP/u)
            } else {
                await client.connect(transport)
                assert.equal((await client.callTool({ name: 'rdx_app_info', arguments: {} })).structuredContent.app.name, 'Isolated Windows fixture')
                assert.ok((await client.listTools()).tools.some((tool) => tool.name === 'rdx_firmware_update'))
                assert.equal(stderr, '')
            }
        } finally {
            await client.close()
            await transport.close()
        }
        assert.equal(stderr.includes(token), false)
    }
})

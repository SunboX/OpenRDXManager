// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { startStdioBridge } from '../src/main/mcp/stdio-bridge.mjs'

let bridge
let stopped = false

/** @returns {Promise<void>} Releases only this bridge when its client disconnects or terminates. */
async function stop() {
    stopped = true
    await bridge?.close()
}

process.stdin.once('end', () => {
    void stop()
})
process.once('SIGINT', () => {
    void stop()
})
process.once('SIGTERM', () => {
    void stop()
})

try {
    bridge = await startStdioBridge({ url: process.env.OPENRDX_MCP_URL ?? 'http://127.0.0.1:48170/mcp', token: process.env.OPENRDX_MCP_TOKEN, tokenFile: process.env.OPENRDX_MCP_TOKEN_FILE })
    if (stopped) await bridge.close()
} catch {
    console.error('Cannot connect to OpenRDXManager MCP. Start the application, enable MCP, and check the local endpoint and credential configuration.')
    process.exitCode = 1
    process.stdin.destroy()
}

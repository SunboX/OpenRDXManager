// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { installPrivateClipboardFixture } from '../electron-test/mcp-clipboard-fixture.mjs'

test('unattended acceptance clipboard never reads or overwrites the host clipboard', () => {
    const calls = []
    const clipboard = {
        /** @returns {string} Represents private host text which must remain unread. */
        readText() {
            calls.push('read')
            return 'host-private-text'
        },
        /** @returns {void} Records any forbidden host write. */
        writeText() {
            calls.push('write')
        }
    }
    const originalRead = clipboard.readText
    const originalWrite = clipboard.writeText
    const restore = installPrivateClipboardFixture(clipboard)
    assert.equal(clipboard.readText(), '')
    clipboard.writeText('test-owned-configuration')
    assert.equal(clipboard.readText(), 'test-owned-configuration')
    assert.throws(() => clipboard.writeText({}), /invalid-acceptance-clipboard-text/)
    restore()
    restore()
    assert.equal(clipboard.readText, originalRead)
    assert.equal(clipboard.writeText, originalWrite)
    assert.deepEqual(calls, [])
})

test('unattended clipboard fixture rejects invalid APIs and restores partial installation', () => {
    assert.throws(() => installPrivateClipboardFixture({}), /invalid-acceptance-clipboard/)
    /** @returns {string} Uncalled original method used to verify rollback identity. */
    function readText() {
        return 'unread'
    }
    const clipboard = { readText }
    Object.defineProperty(clipboard, 'writeText', {
        /** @returns {void} An immutable host method that must never run. */
        value() {
            assert.fail('host clipboard must not be called')
        },
        writable: false
    })
    assert.throws(() => installPrivateClipboardFixture(clipboard), TypeError)
    assert.equal(clipboard.readText, readText)
})

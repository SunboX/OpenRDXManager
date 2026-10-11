// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { getFormatFilesystemPolicy, isFormatFilesystemSupported, normalizeFormatFilesystem } from '../src/renderer/workflows/format-filesystem-policy.mjs'
import { operationConfirmationRequestSchema, operationRequestSchema } from '../src/shared/schemas.mjs'
import { createUtilityOperationController } from '../src/renderer/workflows/utility-operation-controller.mjs'
import { renderUtilitiesView } from '../src/renderer/views/utilities-view.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { getCatalog } from '../src/locales/catalogs.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { englishCatalog } from '../src/locales/en.mjs'

const linuxChoices = ['ext4', 'ext3', 'ext2', 'xfs', 'btrfs', 'f2fs', 'ntfs', 'exfat', 'fat16', 'fat32']

test('Linux exposes native formats, retains cross-platform choices and defaults to ext4', () => {
    assert.deepEqual(getFormatFilesystemPolicy('linux').filesystemChoices, linuxChoices)
    assert.equal(normalizeFormatFilesystem('linux', undefined), 'ext4')
    assert.equal(normalizeFormatFilesystem('linux', 'ntfs'), 'ntfs')
    for (const choice of linuxChoices.slice(0, 6)) {
        assert.equal(isFormatFilesystemSupported('win32', choice), false)
        assert.equal(isFormatFilesystemSupported('darwin', choice), false)
    }
    for (const value of ['zfs', '/usr/sbin/mkfs.ext4', 'ext4 --force', 'apfs']) {
        assert.equal(isFormatFilesystemSupported('linux', value), false)
    }
})

test('each Linux choice passes unchanged through confirmation and strict operation admission', async () => {
    for (const filesystem of linuxChoices) {
        const request = { kind: 'format', deviceId: 'rdx:format', deviceRevision: 1, filesystem }
        const calls = []
        const controller = createUtilityOperationController({
            operations: {
                /** @param {object} value - Exact selected request. @returns {Promise<object>} Fixture confirmation token. */
                async confirm(value) {
                    calls.push(value)
                    return { ok: true, confirmationToken: 'confirm:format' }
                },
                /** @param {object} value - Confirmed format request. @returns {Promise<object>} Fixture acceptance. */
                async start(value) {
                    calls.push(value)
                    return { ok: true, operationId: 'op:format' }
                }
            }
        })
        assert.equal(operationConfirmationRequestSchema.safeParse(request).success, true)
        assert.equal(operationRequestSchema.safeParse({ ...request, confirmationToken: 'confirm:format' }).success, true)
        assert.equal(operationRequestSchema.safeParse({ ...request, confirmationToken: 'confirm:format', passphrase: 'unexpected' }).success, false)
        assert.equal((await controller.start(request)).ok, true)
        assert.deepEqual(calls, [request, { ...request, confirmationToken: 'confirm:format' }])
    }
})

test('all translations render the Linux menu without incorrectly marking NTFS as the default', () => {
    const dom = new JSDOM('<div></div>')
    const device = createFixtureState({ mode: 'one-device' }).devices[0]
    for (const locale of ['en', 'de', 'es', 'fr', 'it', 'pt', 'ja', 'zh']) {
        const translator = createTranslator(getCatalog(locale), englishCatalog)
        const view = renderUtilitiesView(device, { document: dom.window.document, platform: 'linux', operationIntentAvailable: true, translator })
        const select = view.querySelector('[data-utility-filesystem]')
        assert.deepEqual(
            [...select.options].map(({ value }) => value),
            linuxChoices
        )
        assert.equal(select.value, 'ext4')
        assert.equal(select.querySelector('[value="ntfs"]').textContent, 'NTFS')
        assert.equal(view.textContent.includes('utilities.format.'), false)
    }
    dom.window.close()
})

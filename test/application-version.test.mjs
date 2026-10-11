// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { setImmediate } from 'node:timers/promises'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { applicationMetadata } from '../src/main/application-metadata.mjs'

const metadata = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

test('Manager identity and npm lock use the package version', () => {
    const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'))
    assert.match(metadata.version, /^\d+\.\d+\.\d+(?:-[\w.-]+)?$/u)
    assert.deepEqual(applicationMetadata, { name: metadata.productName, version: metadata.version })
    assert.equal(lock.version, metadata.version)
    assert.equal(lock.packages[''].version, metadata.version)
})

for (const mode of ['one-device', 'no-device', 'service-unavailable']) {
    test(`application version is available in Help/About without cluttering the header in ${mode} state`, async (context) => {
        const dom = new JSDOM('<div id="app"></div>')
        context.after(() => dom.window.close())
        const root = dom.window.document.querySelector('#app')
        const store = createStore(createFixtureState({ mode }))
        let requests = 0
        const supportApi = {
            app: {
                /** @returns {Promise<object>} Returns metadata through the existing safe bridge. */
                async getInfo() {
                    requests++
                    return { ok: true, app: { name: metadata.productName, version: metadata.version, platform: 'darwin' } }
                }
            }
        }
        const controller = mountApplication(root, { store, supportApi })
        context.after(() => controller.destroy())
        await setImmediate()
        assert.equal(root.querySelector('[data-app-version]'), null)
        root.querySelector('[data-action="open-help"]').click()
        await setImmediate()
        assert.match(root.querySelector('.about-card').textContent, new RegExp(metadata.version.replaceAll('.', '\\.')))
        root.querySelector('[data-action="close-support-panel"]').click()
        assert.equal(root.querySelector('[data-app-version]'), null)
        assert.equal(requests, 1, 'header and About share the metadata already loaded at startup')
    })
}

test('failed metadata reads do not fabricate an application version', async (context) => {
    const dom = new JSDOM('<div id="app"></div>')
    context.after(() => dom.window.close())
    const root = dom.window.document.querySelector('#app')
    const supportApi = {
        app: {
            /** @returns {Promise<never>} Simulates an unavailable bridge. */ async getInfo() {
                throw new Error('unavailable')
            }
        }
    }
    const controller = mountApplication(root, { store: createStore(createFixtureState({ mode: 'no-device' })), supportApi })
    context.after(() => controller.destroy())
    await setImmediate()
    assert.equal(root.querySelector('[data-app-version]'), null)
    assert.ok(root.querySelector('.brand'))
})

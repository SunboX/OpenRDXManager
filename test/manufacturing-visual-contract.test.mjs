// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { inspectManufacturing } from '../electron-test/manufacturing-fixture.mjs'

/** @param {object} context - Per-test cleanup owner. @param {boolean} [withTarget=true] - Whether the intended control exists. @returns {Document} Isolated synthetic layout; no Electron or hardware service. */
function fixture(context, withTarget = true) {
    const dom = new JSDOM(`<title>OpenRDXManager</title><div class="brand">OPENRDX</div><div>Fixture preview</div><section data-manufacturing-panel><h3>Factory identity backup</h3><p>Every firmware update saves a verified private backup first</p><label><input data-manufacturing-field="acknowledged" type="checkbox"><span>Confirm original factory identity</span></label>${withTarget ? '<button data-manufacturing-action="restore">Restore factory identity</button>' : ''}</section>`, { url: 'file:///fixture.html' })
    const { document } = dom.window
    const bindings = { document, location: dom.window.location, innerWidth: 1024, innerHeight: 768, getComputedStyle: dom.window.getComputedStyle.bind(dom.window), requestAnimationFrame: (callback) => queueMicrotask(callback) }
    const previous = new Map(Object.keys(bindings).map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
    for (const [key, value] of Object.entries(bindings)) Object.defineProperty(globalThis, key, { value, configurable: true, writable: true })
    context.after(() => {
        for (const [key, descriptor] of previous) {
            if (descriptor) Object.defineProperty(globalThis, key, descriptor)
            else delete globalThis[key]
        }
        dom.window.close()
    })
    document.fonts = { ready: Promise.resolve() }
    const brand = document.querySelector('.brand')
    for (const element of document.querySelectorAll('*')) {
        const top = element === brand ? 0 : element.dataset.manufacturingAction === 'restore' ? 200 : 100
        element.getBoundingClientRect = () => ({ left: 0, top, right: 200, bottom: top + 30, width: 200, height: 30 })
        element.scrollIntoView = () => {}
    }
    document.elementFromPoint = (_x, y) => (y < 100 ? brand : y < 200 ? document.querySelector('[data-manufacturing-field="acknowledged"] + span') : document.querySelector('[data-manufacturing-action="restore"]'))
    return document
}

test('manufacturing capture declares painted brand and confirmation context, replacing old markers', async (context) => {
    const document = fixture(context)
    for (let attempt = 0; attempt < 2; attempt++) {
        const result = await inspectManufacturing('bottom')
        assert.deepEqual(
            result.rasterAnchors.map((anchor) => anchor.name),
            ['brand', 'manufacturing-context']
        )
        assert.equal(result.rasterAnchors[1].rect.top, 100)
        assert.equal(document.querySelectorAll('[data-manufacturing-fiducial]').length, 2)
        assert.equal(document.querySelector('[data-manufacturing-field="acknowledged"] + span [data-manufacturing-fiducial]').getAttribute('aria-hidden'), 'true')
        assert.equal(result.restoreEnabled, true)
        assert.equal(result.fixtureOnly, true)
    }
})

test('manufacturing capture rejects a missing intended control instead of capturing unrelated page content', async (context) => {
    fixture(context, false)
    await assert.rejects(inspectManufacturing('bottom'), /capture target is missing/)
})

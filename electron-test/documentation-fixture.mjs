// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createRendererIntentAdapter, RendererIntentType } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { mountVisualFixture } from './visual-fixture.mjs'

const unavailable = { ok: false, reason: 'hardware-unavailable' }

/** @returns {Promise<object>} Refuses every documentation-fixture mutation. */
async function refuseMutation() {
    return unavailable
}

/** @returns {object} Synthetic read-only manufacturing inventory; contains no private record bytes. */
function manufacturingInventory() {
    return { ok: true, backupSupported: true, restoreSupported: true, backups: [{ backupId: 'record-abcdef-1', deviceId: 'rdx:7810544062', serial: '7810544062', createdAt: 1789128000000, state: 'valid' }], page: 0, hasMore: false }
}

/** @returns {object} Synthetic recovery inventory; neither a device token nor saved profile is usable outside this fixture. */
function recoveryInventory() {
    return { ok: true, targets: [{ token: 'rom:documentation', label: 'USB port 0x00200000' }], bundles: [{ bundleId: 'migration-1-0', serial: '7810544062', sourceVersion: '2.83', targetVersion: '1.07', recoveryNeeded: true }], status: { state: 'idle', revision: 0 } }
}

/**
 * Mounts existing visual scenes or additional read-only documentation surfaces.
 * No native hardware transport, persistent settings, network, or private records are used.
 * @param {string} scene - Controlled documentation scene identifier.
 * @returns {Promise<void>} Resolves after the selected real renderer surface is mounted.
 */
export async function mountDocumentationFixture(scene) {
    globalThis.__documentationFixture?.destroy()
    if (!['manufacturing', 'recovery', 'windows-utilities'].includes(scene)) {
        await mountVisualFixture(scene)
        return
    }
    globalThis.__openRdxVisualFixture?.controller?.destroy()
    const currentRoot = document.querySelector('#app')
    const root = currentRoot.cloneNode(false)
    const base = createFixtureState({ mode: scene === 'recovery' ? 'no-device' : 'one-device' })
    let devices = base.devices
    if (scene === 'manufacturing') devices = [{ ...devices[0], media: null, mediaState: 'no-media' }]
    const store = createStore({ ...base, devices, activeArea: 'utilities', settings: { ...base.settings, autoScan: false, updateChecks: false } })
    currentRoot.replaceWith(root)
    const controller = mountApplication(root, {
        store,
        supportApi: { app: globalThis.openRdx?.app },
        intentAdapter: createRendererIntentAdapter({ supportedIntents: Object.values(RendererIntentType), invoke: refuseMutation }),
        platform: scene === 'windows-utilities' ? 'win32' : 'darwin',
        availableDriveLetters: ['D', 'E', 'F'],
        manufacturingApi:
            scene === 'manufacturing'
                ? {
                      /** @returns {Promise<object>} Returns only synthetic backup metadata. */
                      async list() {
                          return manufacturingInventory()
                      },
                      backup: refuseMutation,
                      restore: refuseMutation,
                      openFolder: refuseMutation
                  }
                : undefined,
        recoveryApi:
            scene === 'recovery'
                ? {
                      /** @returns {Promise<object>} Returns the synthetic recovery picker inventory. */
                      async list() {
                          return recoveryInventory()
                      },
                      /** @returns {Promise<object>} Returns an idle read-only recovery snapshot. */
                      async status() {
                          return { ok: true, status: recoveryInventory().status }
                      },
                      start: refuseMutation,
                      continue: refuseMutation
                  }
                : undefined
    })
    globalThis.__documentationFixture = controller
    await settleDocumentationPaint()
}

/** @returns {Promise<void>} Waits for fonts, local promise work, and two painted frames. */
export async function settleDocumentationPaint() {
    await document.fonts.ready
    await new Promise(requestAnimationFrame)
    await new Promise(requestAnimationFrame)
}

/**
 * Populates a synthetic selection to show the real restore and recovery forms.
 * Only local input events are dispatched; no operation button is clicked.
 * @param {string} name - Controlled documentation capture name.
 * @returns {Promise<void>} Resolves after local form presentation settles.
 */
export async function prepareDocumentationForm(name) {
    if (name === 'help') document.querySelector('[data-help-topic="getting-started"]')?.click()
    const fields =
        name === 'manufacturing-restore'
            ? [
                  ['[data-manufacturing-field="backup"]', 'record-abcdef-1'],
                  ['[data-manufacturing-field="confirmationSerial"]', '7810544062']
              ]
            : name === 'migration-recovery'
              ? [
                    ['[data-recovery-field="bundle"]', 'migration-1-0'],
                    ['[data-recovery-field="target"]', 'rom:documentation']
                ]
              : []
    for (const [selector, value] of fields) {
        const input = document.querySelector(selector)
        if (!input) throw new Error(`Documentation form field is missing: ${selector}`)
        input.value = value
        input.dispatchEvent(new Event(input.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }))
    }
    await settleDocumentationPaint()
}

/**
 * Scrolls an actual feature control into the visible application viewport.
 * @param {string|null} selector - Required feature anchor, or null for the top of the workspace.
 * @returns {Promise<object>} Public scene geometry and visible text for the capture manifest.
 * @throws {Error} When a requested feature is absent or clipped.
 */
export async function prepareDocumentationCapture(selector) {
    if (selector) {
        const target = document.querySelector(selector)
        if (!target) throw new Error(`Documentation feature is missing: ${selector}`)
        target.scrollIntoView({ block: 'center', behavior: 'instant' })
        if (/^H[123]$/.test(target.tagName)) {
            for (let parent = target.parentElement; parent; parent = parent.parentElement) {
                if (parent.scrollHeight > parent.clientHeight && /auto|scroll/.test(getComputedStyle(parent).overflowY)) {
                    parent.scrollTop += target.getBoundingClientRect().top - 220
                    break
                }
            }
        }
    } else {
        for (const element of document.querySelectorAll('*')) {
            if (element.scrollTop !== 0) element.scrollTop = 0
        }
    }
    await settleDocumentationPaint()
    if (selector) {
        const bounds = document.querySelector(selector).getBoundingClientRect()
        if (bounds.top < 0 || bounds.bottom > innerHeight || bounds.left < 0 || bounds.right > innerWidth) throw new Error(`Documentation feature is clipped: ${selector}`)
    }
    if (document.documentElement.scrollWidth > innerWidth) throw new Error('Documentation scene has horizontal overflow')
    return { viewport: { width: innerWidth, height: innerHeight }, fixture: true, anchor: selector, text: document.body.innerText }
}

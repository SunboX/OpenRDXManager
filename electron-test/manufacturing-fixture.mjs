// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { isVisualAnchorUnoccluded } from './visual-anchor-visibility.mjs'

/** @param {Function} predicate - Required DOM condition. @returns {Promise<void>} Waits for observable renderer state with a bounded deadline. */
async function waitFor(predicate) {
    const deadline = performance.now() + 5000
    while (!predicate()) {
        if (performance.now() > deadline) {
            const state = globalThis.__manufacturingFixture?.store.getState()
            throw new Error(`Manufacturing fixture state did not settle: ${JSON.stringify({ selectedDeviceId: state?.selectedDeviceId, manufacturingLocked: state?.manufacturingLocked, service: state?.service.status, panel: document.querySelector('[data-manufacturing-panel]')?.textContent })}`)
        }
        await new Promise(requestAnimationFrame)
    }
}

/** @returns {Promise<void>} Settles local fonts and compositor frames for screenshot capture. */
export async function settlePaint() {
    await document.fonts.ready
    await new Promise(requestAnimationFrame)
    await new Promise(requestAnimationFrame)
}

/** @returns {Promise<void>} Mounts synthetic device state against the production preload manufacturing API; no device transport exists in this entrypoint. */
export async function mountManufacturingFixture() {
    await waitFor(() => document.querySelector('#app')?.children.length > 0)
    const currentRoot = document.querySelector('#app')
    const root = currentRoot.cloneNode(false)
    const base = createFixtureState({ mode: 'one-device' })
    const device = { ...base.devices[0], media: null, mediaState: 'no-media' }
    const store = createStore({ ...base, discovery: { ...base.discovery, epoch: 1, listRevision: 1 }, devices: [device], activeArea: 'utilities', settings: { ...base.settings, autoScan: false, updateChecks: false } })
    currentRoot.replaceWith(root)
    const controller = mountApplication(root, { store, platform: 'darwin', manufacturingApi: globalThis.openRdx.manufacturing })
    globalThis.__manufacturingFixture = { controller, store }
    await waitFor(() => document.querySelector('[data-manufacturing-action="backup"]')?.disabled === false)
    await settlePaint()
}

/** @param {string} field - Closed restore form field. @param {string|boolean} value - Synthetic operator input. @returns {void} Exercises the production delegated form listeners. */
function change(field, value) {
    const input = document.querySelector(`[data-manufacturing-field="${field}"]`)
    if (typeof value === 'boolean') input.checked = value
    else input.value = value
    input.dispatchEvent(new Event(field === 'confirmationSerial' ? 'input' : 'change', { bubbles: true }))
}

/** @returns {Promise<void>} Makes one private-backup request through real preload and main dispatch and waits for verified feedback. */
export async function exerciseBackup() {
    document.querySelector('[data-manufacturing-action="backup"]').click()
    await waitFor(() => document.querySelector('[data-manufacturing-success]')?.textContent.includes('backed up and verified'))
    if (document.querySelector('[data-manufacturing-field="backup"]').value !== '') throw new Error('A saved backup was selected automatically')
    await settlePaint()
}

/** @returns {Promise<void>} Exercises the fixed folder intent through real preload and main dispatch. */
export async function exerciseOpenFolder() {
    const control = document.querySelector('[data-manufacturing-action="open-folder"]')
    if (control.disabled) throw new Error('Backup folder button is unavailable')
    control.click()
    await waitFor(() => !document.querySelector('[data-manufacturing-action="open-folder"]').disabled)
    if (document.querySelector('[data-manufacturing-folder-error]')) throw new Error('Backup folder action failed')
}

/** @returns {Promise<object>} Checks Chromium focus and unchanged select markup across automatic scan transitions without issuing device requests. */
export async function exerciseBackupRefresh() {
    const { store } = globalThis.__manufacturingFixture
    const select = document.querySelector('[data-manufacturing-field="backup"]')
    const mutations = []
    const observer = new MutationObserver((records) => mutations.push(...records))
    const backup = document.querySelector('[data-manufacturing-action="backup"]')
    const backupMutations = []
    const backupObserver = new MutationObserver((records) => backupMutations.push(...records))
    select.focus()
    observer.observe(select, { attributes: true, childList: true, subtree: true, characterData: true })
    backupObserver.observe(backup, { attributes: true, attributeFilter: ['disabled'] })
    try {
        for (let cycle = 0; cycle < 3; cycle += 1) {
            store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
            await settlePaint()
            if (select.disabled || document.activeElement !== select || !select.isConnected) throw new Error('Automatic scanning interrupted the backup selector')
            if (document.querySelector('[data-manufacturing-action="backup"]').disabled) throw new Error('Routine discovery disabled the queued backup action')
            store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
            await settlePaint()
            if (select.disabled || document.activeElement !== select || !select.isConnected) throw new Error('Scan completion interrupted the backup selector')
        }
        if (mutations.length > 0) throw new Error('Automatic scanning rewrote the backup selector')
        if (backupMutations.length > 0 || !backup.isConnected) throw new Error('Automatic scanning flickered the backup action')
        return { cycles: 3, focused: true, enabled: true, selectorMutations: mutations.length }
    } finally {
        observer.disconnect()
        backupObserver.disconnect()
    }
}

/** @returns {Promise<void>} Exercises wrong and exact original serials before authorizing the synthetic restore. */
export async function prepareRestore() {
    change('backup', 'record-abcdef-1')
    change('confirmationSerial', '0000000000')
    change('acknowledged', true)
    if (!document.querySelector('[data-manufacturing-action="restore"]').disabled) throw new Error('Wrong original serial authorized a restore')
    change('confirmationSerial', '7810544062')
    if (document.querySelector('[data-manufacturing-action="restore"]').disabled) throw new Error('Exact confirmed restore remained disabled')
    await settlePaint()
}

/** @returns {Promise<void>} Exercises separate original-identity consent against a different synthetic current identity. */
export async function prepareIdentityRecovery() {
    const { store } = globalThis.__manufacturingFixture
    const state = store.getState()
    const previous = state.devices[0]
    const device = { ...previous, id: 'rdx:0123456789', serial: '0123456789', revision: 5, drive: { ...previous.drive, details: { ...previous.drive.details, serialNumber: { availability: 'reported', value: '0123456789' } } } }
    store.dispatch({ type: 'device/list-replaced', devices: [device], epoch: state.discovery.epoch, listRevision: state.discovery.listRevision + 1 })
    store.dispatch({ type: 'device/select', deviceId: device.id })
    if (store.getState().selectedDeviceId !== device.id) throw new Error('Synthetic identity change was rejected by device discovery')
    document.querySelector('[role="tab"][data-area="utilities"]').click()
    await waitFor(() => document.querySelector('[data-manufacturing-action="backup"]')?.disabled === false)
    change('backup', 'record-abcdef-1')
    change('confirmationSerial', '7810544062')
    change('acknowledged', true)
    if (!document.querySelector('[data-manufacturing-action="restore"]').disabled) throw new Error('Identity replacement was admitted without separate consent')
    change('allowIdentityChange', true)
    if (document.querySelector('[data-manufacturing-action="restore"]').disabled) throw new Error('Explicit original-identity recovery remained disabled')
    await settlePaint()
}

/** @returns {Promise<void>} Submits one explicitly confirmed synthetic restore and verifies the manual power-cycle guidance. */
export async function exerciseRestore() {
    document.querySelector('[data-manufacturing-action="restore"]').click()
    await waitFor(() => document.querySelector('[data-manufacturing-success]')?.textContent.includes('restored and verified'))
    if (document.querySelector('[data-manufacturing-field="confirmationSerial"]').value !== '') throw new Error('Consumed original serial survived the restore')
    if (!document.querySelector('[data-manufacturing-action="restore"]').disabled) throw new Error('Restore could submit twice without a new confirmation')
    await settlePaint()
}

/** @param {Element} element - Required visible fixture anchor. @param {string} name - Closed evidence name. @param {string} fiducialColor - Test-only marker color. @returns {object} Pixel-crop geometry after DOM hit testing. */
function rasterAnchor(element, name, fiducialColor) {
    if (!isVisualAnchorUnoccluded(element, document)) throw new Error(`Manufacturing anchor is not visible: ${name}`)
    const rect = element.getBoundingClientRect()
    if (rect.left < 0 || rect.top < 0 || rect.right > innerWidth || rect.bottom > innerHeight) throw new Error(`Manufacturing anchor is clipped: ${name}`)
    const marker = document.createElement('span')
    marker.dataset.manufacturingFiducial = name
    marker.setAttribute('aria-hidden', 'true')
    marker.style.cssText = `position:absolute;z-index:2147483647;top:1px;left:1px;width:3px;height:3px;pointer-events:none;background:${fiducialColor}`
    if (getComputedStyle(element).position === 'static') element.style.position = 'relative'
    element.append(marker)
    return { name, color: getComputedStyle(element).color, fiducialColor, rect: { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom, width: rect.width, height: rect.height } }
}

/** @param {'top'|'bottom'} region - Desired card region. @returns {Promise<object>} Scrolls actual controls into view and captures DOM overflow, identity and painted-anchor requirements. */
export async function inspectManufacturing(region = 'top') {
    for (const marker of document.querySelectorAll('[data-manufacturing-fiducial]')) marker.remove()
    const panel = document.querySelector('[data-manufacturing-panel]')
    const target = region === 'top' ? panel.querySelector('h2, h3, [role="heading"]') : panel.querySelector('[data-manufacturing-action="restore"]')
    if (!target) throw new Error('Manufacturing capture target is missing')
    target.scrollIntoView({ block: 'center', behavior: 'instant' })
    await waitFor(() => isVisualAnchorUnoccluded(target, document))
    await settlePaint()
    const bounds = panel.getBoundingClientRect()
    const overflow = [...panel.querySelectorAll('button, input, select, label, p')]
        .filter((control) => {
            const rectangle = control.getBoundingClientRect()
            return rectangle.left < bounds.left - 1 || rectangle.right > bounds.right + 1 || control.scrollWidth > control.clientWidth + 2
        })
        .map((control) => `${control.tagName}:${control.dataset.manufacturingAction ?? control.dataset.manufacturingField ?? control.className}`)
    // A disabled restore button intentionally fades its entire subtree,
    // including QA markers. Anchor its non-faded confirmation text instead;
    // the actual restore control must still pass hit-testing above.
    const paintedTarget = region === 'top' ? target : panel.querySelector('[data-manufacturing-field="acknowledged"] + span')
    const rasterAnchors = [rasterAnchor(document.querySelector('.brand'), 'brand', 'rgb(255, 64, 224)'), rasterAnchor(paintedTarget, 'manufacturing-context', 'rgb(64, 255, 128)')]
    return { title: document.title, url: location.href, width: innerWidth, height: innerHeight, bodyTextLength: document.body.textContent.trim().length, panelText: panel.textContent, region, horizontalOverflow: document.documentElement.scrollWidth > innerWidth, controlsOverflow: overflow, restoreEnabled: !panel.querySelector('[data-manufacturing-action="restore"]').disabled, fixtureOnly: document.body.textContent.includes('Fixture preview'), rasterAnchors }
}

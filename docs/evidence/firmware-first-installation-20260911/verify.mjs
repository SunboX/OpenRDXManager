import assert from 'node:assert/strict'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { pathToFileURL } from 'node:url'
const root = process.cwd()
const fixtureOutput = '/tmp/openrdxmanager-installation-evidence'
const evidence = join(root, 'docs/evidence/firmware-first-installation-20260911')
const require = createRequire(join(root, 'package.json'))
const { app, BrowserWindow } = require('electron')
app.setPath('userData', join(fixtureOutput, 'profile'))
app.on('window-all-closed', () => {})
const url = (relative) => pathToFileURL(join(root, relative)).href
/** Runs deterministic, hardware-free renderer evidence capture. */
async function main() {
    await mkdir(fixtureOutput, { recursive: true })
    await mkdir(evidence, { recursive: true })
    const entry = `
import { mountApplication } from ${JSON.stringify(url('src/renderer/app-controller.mjs'))}
import { createFixtureState } from ${JSON.stringify(url('src/renderer/fixture-state.mjs'))}
import { createStore } from ${JSON.stringify(url('src/renderer/store.mjs'))}
import { createRendererIntentAdapter } from ${JSON.stringify(url('src/renderer/intent-adapter.mjs'))}
const fixture = createFixtureState({ mode: 'busy' })
const device = { ...fixture.devices[0], media: null, mediaState: 'no-media' }
const query = new URLSearchParams(location.search)
const stage = query.get('stage')
const absent = query.get('absent') === 'true'
const store = createStore({ ...fixture, activeArea: 'utilities', devices: absent ? [] : [device], selectedDeviceId: absent ? null : device.id, activeOperation: { ...fixture.activeOperation, id: 'op:installation-evidence', stage, cancellationState: 'closed', progress: stage === 'firmware-awaiting-bootloader' ? 0.35 : 0.65 } })
window.proofCalls = []
const intentAdapter = createRendererIntentAdapter({ supportedIntents: ['operation-continue'], invoke: async request => { window.proofCalls.push(request); return { ok: true, operationId: request.operationId } } })
mountApplication(document.querySelector('#app'), { store, intentAdapter })
window.proofReady = true
`
    await writeFile(join(fixtureOutput, 'fixture.mjs'), entry)
    let html = await readFile(join(root, 'src/index.html'), 'utf8')
    html = html.replaceAll(/href="([^"#][^"]*)"/g, (_match, relative) => `href="${pathToFileURL(join(root, 'src', relative)).href}"`)
    html = html.replace('./renderer.mjs', './fixture.mjs').replace('<title>OpenRDXManager</title>', '<title>First-installation preview — simulated device</title>')
    await writeFile(join(fixtureOutput, 'preview.html'), html)
    await app.whenReady()
    const results = []
    for (const [cycle, stage] of [['first', 'firmware-awaiting-bootloader'], ['second', 'firmware-awaiting-bootstrap']]) {
        for (const absent of [false, true]) {
            const suffix = `${cycle}-power-cycle${absent ? '-dock-absent' : ''}`
            const window = new BrowserWindow({ width: 1280, height: 900, show: true, backgroundColor: '#050a13', webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false } })
            const errors = []
            window.webContents.on('console-message', (_event, level, message) => { if (level >= 3) errors.push(message) })
            try {
                await window.loadFile(join(fixtureOutput, 'preview.html'), { query: { stage, absent: String(absent) } })
                for (let index = 0; index < 100; index += 1) {
                    if (await window.webContents.executeJavaScript('window.proofReady === true')) break
                    await delay(50)
                }
                assert.equal(await window.webContents.executeJavaScript('window.proofReady'), true)
                await window.webContents.executeJavaScript('document.fonts.ready')
                await delay(200)
                const inspected = await window.webContents.executeJavaScript(`(() => {
                    const banner = document.querySelector('[data-operation-status]')
                    const prompt = document.querySelector('[data-firmware-installation-guidance]')
                    const button = document.querySelector('[data-action="continue-firmware-installation"]')
                    const rect = banner.getBoundingClientRect()
                    return { text: prompt.textContent, buttonText: button.textContent, enabled: !button.disabled, withinWindow: rect.left >= 0 && rect.right <= innerWidth && rect.top >= document.querySelector('.topbar').getBoundingClientRect().bottom && rect.bottom <= innerHeight, overflow: document.documentElement.scrollWidth > innerWidth || banner.scrollWidth > banner.clientWidth, locked: document.querySelector('#operation-lock-reason') !== null, calls: window.proofCalls.length }
                })()`)
                assert.match(inspected.text, cycle === 'first' ? /First power cycle/ : /Second power cycle/)
                assert.match(inspected.text, /same USB port/)
                assert.match(inspected.text, /J7 open/)
                assert.equal(inspected.buttonText, 'Continue after reconnecting')
                assert.equal(inspected.enabled, true)
                assert.equal(inspected.withinWindow, true)
                assert.equal(inspected.overflow, false)
                assert.equal(inspected.locked, true)
                assert.equal(inspected.calls, 0)
                assert.deepEqual(errors, [])
                await writeFile(join(evidence, `${suffix}.png`), (await window.webContents.capturePage()).toPNG())
                await window.webContents.executeJavaScript(`document.querySelector('[data-action="continue-firmware-installation"]').click()`)
                await delay(100)
                const accepted = await window.webContents.executeJavaScript(`({ disabled: document.querySelector('[data-action="continue-firmware-installation"]').disabled, calls: window.proofCalls.length, successVisible: document.querySelector('[data-operation-success]') !== null })`)
                assert.deepEqual(accepted, { disabled: true, calls: 1, successVisible: false })
                results.push({ scenario: suffix, fixtureOnly: true, inspected, accepted, errors })
            } finally { window.destroy() }
        }
    }
    await writeFile(join(evidence, 'inspection.json'), JSON.stringify(results, null, 2) + '\n')
    console.log(JSON.stringify({ fixtureOnly: true, scenarios: results.length, overflow: false, operatorGateTests: 'passed', output: evidence }))
    app.exit(0)
}
async function start() { try { await main() } catch (error) { console.error(error); app.exit(1) } }
void start()

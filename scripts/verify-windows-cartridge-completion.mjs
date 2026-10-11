// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { fileURLToPath } from 'node:url'
import { writeFile } from 'node:fs/promises'
import { setTimeout as delay } from 'node:timers/promises'
import { createApplicationServiceRuntime } from '../src/main/service-runtime.mjs'

if (process.argv.length !== 2) throw new Error('arguments-not-supported')
const appPath = fileURLToPath(new URL('../', import.meta.url))
const services = {}
const terminals = new Map()
const histories = new Map()
const report = { checkedAt: new Date().toISOString(), checks: [] }
let selectedId = null
const runtime = createApplicationServiceRuntime({
    appPath,
    resourcesPath: appPath,
    isPackaged: false,
    platform: 'win32',
    services,
    logDirectory: fileURLToPath(new URL('../../user-data/logs', import.meta.url)),
    ipcController: {
        /** Leaves device identities within the production state/audit boundary. */
        publishDeviceEvent() {},
        /** Retains only bounded public lifecycle evidence in this report. */
        publishOperationEvent(event) {
            const history = histories.get(event.operationId) ?? []
            history.push({ state: event.state, stage: event.stage })
            histories.set(event.operationId, history)
            if (['succeeded', 'failed', 'cancelled'].includes(event.state)) terminals.set(event.operationId, event)
        }
    }
})

/** Revalidates the exact selected dock and expected cartridge before each operation. */
async function selectedCartridge() {
    const inventory = await runtime.client.list()
    const candidates = inventory.devices?.filter((device) => device.vendor === 'TANDBERG' && device.product === 'RDX') ?? []
    if (!inventory.ok || candidates.length !== 1 || inventory.devices.length !== 1) throw new Error('exact-rdx-selection-unavailable')
    const selected = candidates[0]
    if (selectedId !== null && selected.id !== selectedId) throw new Error('selected-dock-changed')
    if (selected.mediaState !== 'present' || selected.media?.capacityBytes !== 320072933376) throw new Error('expected-320gb-cartridge-required')
    selectedId = selected.id
    return selected
}

/** Runs one approved operation through the actual production coordinator. */
async function checkOperation(kind) {
    if (!['status-refresh', 'self-test', 'write-read-test', 'eject-safe'].includes(kind)) throw new Error('out-of-scope-operation')
    const selected = await selectedCartridge()
    const started = await services.operations.start({ kind, deviceId: selected.id, deviceRevision: selected.revision })
    if (!started.ok) {
        report.checks.push({ kind, admission: started })
        return false
    }
    let nextNotice = Date.now() + 30_000
    while (!terminals.has(started.operationId)) {
        await delay(100)
        if (Date.now() >= nextNotice) {
            console.log(JSON.stringify({ waiting: kind, stage: histories.get(started.operationId)?.at(-1) }))
            nextNotice = Date.now() + 30_000
        }
    }
    const event = terminals.get(started.operationId)
    const check = {
        kind,
        state: event.state,
        stage: event.stage,
        error: event.error?.code ?? null,
        primaryStage: event.error?.stage ?? null,
        category: event.error?.category ?? null,
        cleanupEvidence: event.error?.cleanupEvidence ?? [],
        history: histories.get(started.operationId)
    }
    report.checks.push(check)
    console.log(JSON.stringify(check))
    return event.state === 'succeeded'
}

/** Stops on any failure; never formats, changes encryption, or forces an eject. */
async function verify() {
    try {
        report.readiness = await runtime.start()
        if (report.readiness.status !== 'ready' || !runtime.client.hasPrivilege() || !runtime.client.isHardwareReady()) throw new Error('privileged-native-service-required')
        report.scan = await services.devices.scan({ kind: 'scan' })
        const selected = await selectedCartridge()
        report.device = { vendor: selected.vendor, product: selected.product, firmwareRevision: selected.drive.firmwareRevision, mediaState: selected.mediaState, capacityBytes: selected.media.capacityBytes }
        for (const kind of ['status-refresh', 'self-test', 'write-read-test', 'eject-safe']) {
            if (!(await checkOperation(kind))) break
        }
        const inventory = await runtime.client.list()
        const finalDevice = inventory.devices?.find((device) => device.id === selectedId)
        report.finalDevice = finalDevice ? { mediaState: finalDevice.mediaState, firmwareRevision: finalDevice.drive.firmwareRevision } : null
        report.finalReadiness = runtime.getReadiness()
    } catch (error) {
        report.error = error.message
    } finally {
        report.stopped = await runtime.stop()
        await writeFile(new URL('../../windows-cartridge-completion-verification.json', import.meta.url), JSON.stringify(report, null, 2), { flag: 'wx' })
        console.log(JSON.stringify(report, null, 2))
    }
}

await verify()

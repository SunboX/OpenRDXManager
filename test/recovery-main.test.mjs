// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { MigrationRecoveryService } from '../src/main/migration-recovery-service.mjs'
import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'
import { RecoveryWireClient } from '../src/main/recovery-wire-client.mjs'
import { dispatchApplicationRequest } from '../src/main/application-dispatcher.mjs'
import { IpcChannel } from '../src/shared/ipc-contract.mjs'
import { ShutdownController } from '../src/main/shutdown-controller.mjs'
import { recoveryListResponseSchema, recoveryStartRequestSchema, recoveryStatusResponseSchema } from '../src/shared/recovery-schemas.mjs'

const idle = { state: 'idle', revision: 0 }
const running = { state: 'running', revision: 1, attemptId: 'recovery:test', stage: 'recovery-programming-bootstrap', awaitingAcknowledgment: false }
const selection = { bundleId: 'migration-1-0', targetToken: 'target:test', acknowledged: true }

/** @param {object} overrides - Controlled wire callbacks. @returns {object} Hardware-free service harness. */
function harness(overrides = {}) {
    let ordinary = null
    let generation = 1
    const wire = { list: async () => ({ ok: true, targets: [], bundles: [], status: idle }), status: async () => ({ ok: true, status: idle }), start: async () => ({ ok: true, status: running }), continue: async () => ({ ok: true, status: running }), ...overrides }
    const service = new MigrationRecoveryService({ wire, getActiveOperation: () => ordinary, getGeneration: () => generation, isReady: () => true })
    return {
        service,
        setOrdinary: (value) => {
            ordinary = value
        },
        setGeneration: (value) => {
            generation = value
        }
    }
}

test('recovery contracts reject caller ports, paths, missing acknowledgment and private fields', () => {
    assert.equal(recoveryStartRequestSchema.safeParse(selection).success, true)
    for (const extra of [{ locationId: 1 }, { path: '/tmp/image' }, { acknowledged: false }, { targetToken: '../anything' }]) assert.equal(recoveryStartRequestSchema.safeParse({ ...selection, ...extra }).success, false)
    assert.equal(recoveryListResponseSchema.safeParse({ ok: true, targets: [], bundles: [], status: idle }).success, true)
    assert.equal(recoveryStatusResponseSchema.safeParse({ ok: true, status: { ...running, factoryBytes: 'private' } }).success, false)
    assert.equal(recoveryStatusResponseSchema.safeParse({ ok: true, status: { ...running, state: 'succeeded', awaitingAcknowledgment: true } }).success, false)
})

test('recovery admission reserves synchronously against duplicates and ordinary work', async () => {
    const pending = Promise.withResolvers()
    const { service, setOrdinary } = harness({ start: async () => pending.promise })
    setOrdinary({ operationId: 'op:busy' })
    assert.equal((await service.start(selection)).reason, 'operation-in-progress')
    setOrdinary(null)
    const first = service.start(selection)
    assert.equal(service.isBusy(), true)
    assert.equal((await service.start(selection)).reason, 'operation-in-progress')
    pending.resolve({ ok: true, status: running })
    assert.equal((await first).ok, true)
    assert.equal(service.isBusy(), true)
})

test('uncertain start retains ownership until a fresh status reconciles it', async () => {
    const { service } = harness({ start: async () => ({ ok: false, reason: 'operation-outcome-unknown', ambiguous: true }), status: async () => ({ ok: true, status: { ...running, revision: 8, state: 'failed', reason: 'recovery-target-unavailable' } }) })
    assert.deepEqual(await service.start(selection), { ok: false, reason: 'recovery-outcome-unknown' })
    assert.equal(service.isBusy(), true)
    assert.equal((await service.status()).status.state, 'failed')
    assert.equal(service.isBusy(), false)
})

test('a pre-start idle response cannot release a new recovery reservation', async () => {
    const read = Promise.withResolvers()
    const write = Promise.withResolvers()
    const { service } = harness({ status: async () => read.promise, start: async () => write.promise })
    const earlier = service.status()
    const start = service.start(selection)
    read.resolve({ ok: true, status: idle })
    await earlier
    assert.equal(service.isBusy(), true)
    write.resolve({ ok: true, status: running })
    await start
    assert.equal(service.isBusy(), true)
})

test('power-cycle acknowledgment is exact, current, and consumed before dispatch', async () => {
    let calls = 0
    const waiting = { ...running, stage: 'recovery-awaiting-power-cycle', awaitingAcknowledgment: true }
    const { service } = harness({
        status: async () => ({ ok: true, status: waiting }),
        continue: async () => {
            calls += 1
            return { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }
        }
    })
    await service.status()
    const reply = { attemptId: waiting.attemptId, stage: waiting.stage, acknowledged: true }
    assert.equal((await service.continue({ ...reply, attemptId: 'recovery:other' })).ok, false)
    assert.equal((await service.continue(reply)).reason, 'recovery-outcome-unknown')
    assert.equal((await service.continue(reply)).ok, false)
    assert.equal(calls, 1)
    assert.equal(service.isBusy(), true)
})

test('stale revisions and old generation responses cannot overwrite current progress', async () => {
    let result = { ok: true, status: { ...running, revision: 4 } }
    const { service, setGeneration } = harness({ status: async () => result })
    await service.status()
    result = { ok: true, status: idle }
    assert.equal((await service.status()).status.revision, 4)
    setGeneration(2)
    assert.equal((await service.status()).status.state, 'idle')
    assert.equal(service.isBusy(), false)
})

test('recovery blocks normal scan, device operation and app shutdown through their real admission paths', async () => {
    const { service } = harness()
    const coordinator = new OperationCoordinator({
        dispatch: async () => {
            throw new Error('hardware dispatch must remain unused')
        },
        getRecoveryOwner: service.getActiveOperation.bind(service)
    })
    await service.start(selection)
    assert.equal((await coordinator.scan({ kind: 'scan' })).reason, 'operation-in-progress')
    assert.equal((await coordinator.start({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7 })).reason, 'operation-in-progress')
    assert.equal(coordinator.getShutdownPolicy().allowed, false)
    assert.equal(coordinator.getContext({ kind: 'scan' }).activeOperation.kind, 'firmware-recovery')
})

test('application routes and wire client expose only closed recovery messages', async () => {
    const calls = []
    const wire = new RecoveryWireClient(async (method, payload, schema) => {
        calls.push({ method, payload })
        return schema.parse(method === 'recovery-list' ? { ok: true, targets: [], bundles: [], status: idle } : { ok: true, status: running })
    })
    const services = { recovery: wire }
    assert.equal((await dispatchApplicationRequest(services, IpcChannel.RECOVERY_LIST, {})).ok, true)
    assert.equal((await dispatchApplicationRequest(services, IpcChannel.RECOVERY_START, selection)).ok, true)
    assert.deepEqual(
        calls.map((call) => call.method),
        ['recovery-list', 'recovery-start']
    )
    assert.equal((await dispatchApplicationRequest(services, IpcChannel.RECOVERY_START, { ...selection, locationId: 9 })).ok, false)
    assert.equal((await wire.continue({ attemptId: 'recovery:test', stage: 'recovery-programming-bootstrap', acknowledged: true })).ok, false)
    assert.equal(calls.length, 2)
})

test('a contradictory same-revision terminal cannot release recovery ownership', async () => {
    let result = { ok: true, status: running }
    const { service } = harness({ status: async () => result })
    await service.status()
    result = { ok: true, status: { ...running, state: 'failed', reason: 'recovery-record-readback-mismatch' } }
    assert.equal((await service.status()).ok, false)
    assert.equal(service.isBusy(), true)
})

test('a delayed start reply returns the newer polled terminal instead of resurrecting running state', async () => {
    const pending = Promise.withResolvers()
    const terminal = { ...running, revision: 2, state: 'failed', reason: 'recovery-selected-target-unavailable' }
    const { service } = harness({ start: async () => pending.promise, status: async () => ({ ok: true, status: terminal }) })
    const start = service.start(selection)
    await service.status()
    pending.resolve({ ok: true, status: running })
    assert.deepEqual((await start).status, terminal)
    assert.equal(service.isBusy(), false)
})

test('approved shutdown synchronously closes recovery admission before asynchronous service teardown', async () => {
    let service
    const stopping = Promise.withResolvers()
    const coordinator = new OperationCoordinator({ dispatch: async () => ({ ok: true }), getRecoveryOwner: () => service.getActiveOperation() })
    service = new MigrationRecoveryService({ wire: { start: async () => ({ ok: true, status: running }) }, getActiveOperation: coordinator.getActiveOperation.bind(coordinator), getGeneration: () => 1, isReady: () => true, getAdmissionFailure: () => (coordinator.isShuttingDown() ? 'application-shutting-down' : null) })
    const shutdown = new ShutdownController({ app: { quit: () => {} }, coordinator, runtime: { stop: async () => stopping.promise }, timeoutMs: 1000 })
    shutdown.handleBeforeQuit({ preventDefault: () => {} })
    assert.equal((await service.start(selection)).reason, 'application-shutting-down')
    assert.equal((await coordinator.scan({ kind: 'scan' })).reason, 'application-shutting-down')
    stopping.resolve()
    await shutdown.waitForShutdown()
})

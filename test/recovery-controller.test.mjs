// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { RecoveryController } from '../src/renderer/recovery-controller.mjs'
import { createPreloadApi } from '../src/preload-api.mjs'

const idle = { state: 'idle', revision: 0 }
const waiting = { state: 'running', revision: 2, attemptId: 'recovery:fixture', stage: 'recovery-awaiting-power-cycle', awaitingAcknowledgment: true }
const inventory = { ok: true, targets: [{ token: 'rom:fixture', label: 'USB port 0x00200000' }], bundles: [{ bundleId: 'migration-1-0', serial: '001234567890', sourceVersion: '2.83', targetVersion: '1.07', recoveryNeeded: true }], status: idle }

/** @returns {Promise<void>} Drains pending fixture responses without a real timer. */
async function settled() {
    await new Promise(setImmediate)
}

/** @param {object} overrides - Controlled API responses. @returns {object} A manual service-generation and polling fixture. */
function fixture(overrides = {}) {
    let state = { activeOperation: null, service: { status: 'ready' }, discovery: { epoch: 1, scanStatus: 'idle' } }
    const store = {
        getState: () => state,
        dispatch: (action) => {
            state = { ...state, recoveryLocked: action.locked }
        }
    }
    const api = { list: async () => inventory, status: async () => ({ ok: true, status: idle }), start: async () => ({ ok: true, status: waiting }), continue: async () => ({ ok: true, status: { ...waiting, revision: 3, awaitingAcknowledgment: false } }), ...overrides }
    const controller = new RecoveryController(api, store, () => {}, { setTimeout: () => 1, clearTimeout: () => {} })
    controller.observe(state)
    return {
        controller,
        store,
        api,
        nextGeneration: () => {
            state = { ...state, discovery: { ...state.discovery, epoch: state.discovery.epoch + 1 } }
            controller.observe(state)
        }
    }
}

test('uncertain recovery-start retains ownership and cannot automatically submit or accept another start', async () => {
    let starts = 0
    const f = fixture({
        start: async () => {
            starts += 1
            return { ok: false, reason: 'recovery-outcome-unknown' }
        }
    })
    try {
        await settled()
        f.controller.select('bundle', 'migration-1-0')
        f.controller.select('target', 'rom:fixture')
        f.controller.select('acknowledged', true)
        await f.controller.submit('start')
        assert.equal(f.store.getState().recoveryLocked, true)
        assert.equal(f.controller.getView().reason, 'recovery-outcome-unknown')
        await f.controller.submit('start')
        assert.equal(starts, 1)
    } finally {
        f.controller.destroy()
    }
})

test('a confirmed new service generation may become idle and late old-generation replies are ignored', async () => {
    const old = Promise.withResolvers()
    const f = fixture({ list: async () => ({ ...inventory, status: waiting }), status: async () => old.promise })
    try {
        await settled()
        assert.equal(f.store.getState().recoveryLocked, true)
        const stalePoll = f.controller.poll()
        f.api.list = async () => inventory
        f.nextGeneration()
        await settled()
        assert.equal(f.store.getState().recoveryLocked, false)
        assert.equal(f.controller.getView().status.state, 'idle')
        old.resolve({ ok: true, status: { ...waiting, revision: 99 } })
        await stalePoll
        assert.equal(f.controller.getView().status.state, 'idle')
    } finally {
        f.controller.destroy()
    }
})

test('unsupported or unprivileged inventory does not lock ordinary UI before a mutation', async () => {
    for (const reason of ['recovery-platform-unsupported', 'recovery-privilege-required']) {
        const f = fixture({ list: async () => ({ ok: false, reason }) })
        try {
            await settled()
            assert.equal(f.store.getState().recoveryLocked, false)
            assert.equal(f.controller.getView().reason, reason)
        } finally {
            f.controller.destroy()
        }
    }
})

test('older same-attempt polls cannot reopen a consumed continuation gate or refresh its inventory', async () => {
    let lists = 0
    let continues = 0
    const f = fixture({
        list: async () => {
            lists += 1
            return { ...inventory, status: waiting }
        },
        status: async () => ({ ok: true, status: waiting }),
        continue: async () => {
            continues += 1
            return { ok: true, status: { ...waiting, revision: 3, awaitingAcknowledgment: false } }
        }
    })
    try {
        await settled()
        await f.controller.submit('continue')
        await f.controller.poll()
        await f.controller.submit('continue')
        assert.equal(f.controller.getView().status.revision, 3)
        assert.equal(f.controller.getView().status.awaitingAcknowledgment, false)
        assert.equal(continues, 1)
        assert.equal(lists, 1)
    } finally {
        f.controller.destroy()
    }
})

test('preload recovery exposes only explicit association and exact power-cycle requests', async () => {
    const calls = []
    const api = createPreloadApi({
        invoke: async (channel, request) => {
            calls.push({ channel, request })
            return channel.endsWith(':list') ? inventory : { ok: true, status: waiting }
        },
        on: () => {},
        removeListener: () => {}
    })
    assert.equal(Object.isFrozen(api.recovery), true)
    assert.equal(Object.isFrozen(await api.recovery.list({})), true)
    await api.recovery.status({})
    await api.recovery.start({ bundleId: 'migration-1-0', targetToken: 'rom:fixture', acknowledged: true })
    await api.recovery.continue({ attemptId: waiting.attemptId, stage: waiting.stage, acknowledged: true })
    for (const invalid of [
        { bundleId: 'migration-1-0', targetToken: 'rom:fixture', acknowledged: false },
        { bundleId: 'migration-1-0', targetToken: 'rom:fixture', acknowledged: true, path: '/private/profile' }
    ])
        await assert.rejects(api.recovery.start(invalid), TypeError)
    await assert.rejects(api.recovery.continue({ attemptId: waiting.attemptId, stage: 'recovery-programming-bootstrap', acknowledged: true }), TypeError)
    assert.equal(calls.length, 4)
})

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { ManufacturingService } from '../src/main/manufacturing-service.mjs'
import { manufacturingRequestSchema, manufacturingRestoreRequestSchema, manufacturingResponseSchema } from '../src/shared/manufacturing-schemas.mjs'
import { dispatchApplicationRequest } from '../src/main/application-dispatcher.mjs'
import { IpcChannel } from '../src/shared/ipc-contract.mjs'

const request = { deviceId: 'rdx:synthetic', deviceRevision: 1 }
const inventory = { ok: true, backups: [], backupSupported: true, restoreSupported: false }

/** @param {object} wire - Fake service boundary. @returns {ManufacturingService} Isolated coordinator. */
function service(wire) {
    return new ManufacturingService({ wire, isReady: () => true, getGeneration: () => 1, getActiveOperation: () => null, getAdmissionFailure: () => null })
}

test('backup owns the hardware gate before dispatch and forbids duplicate actions', async () => {
    let finish
    let calls = 0
    const owner = service({
        backup: async () => {
            calls += 1
            return await new Promise((resolve) => {
                finish = resolve
            })
        }
    })
    const pending = owner.backup(request)
    assert.equal(owner.isBusy(), true)
    assert.equal((await owner.backup(request)).reason, 'operation-in-progress')
    assert.equal(calls, 1)
    finish(inventory)
    assert.deepEqual(await pending, inventory)
    assert.equal(owner.isBusy(), false)
})

test('an ambiguous restore retains ownership until an ordered inventory read reconciles it', async () => {
    const owner = service({
        restore: async () => {
            throw new Error('lost reply')
        },
        list: async () => inventory
    })
    const restore = { ...request, backupId: 'record-1-1', acknowledged: true, confirmationSerial: '1234567890' }
    assert.equal((await owner.restore(restore)).reason, 'manufacturing-outcome-unknown')
    assert.equal(owner.isBusy(), true)
    assert.equal((await owner.backup(request)).reason, 'operation-in-progress')
    assert.deepEqual(await owner.list(request), inventory)
    assert.equal(owner.isBusy(), false)
})

test('native post-write uncertainty requires stable-sector reconciliation without replaying restore', async () => {
    const calls = []
    const owner = service({
        restore: async () => ({ ok: false, reason: 'manufacturing-outcome-unknown' }),
        list: async (request) => {
            calls.push(request)
            return inventory
        }
    })
    const restore = { ...request, backupId: 'record-1-1', acknowledged: true, confirmationSerial: '1234567890' }
    assert.equal((await owner.restore(restore)).reason, 'manufacturing-outcome-unknown')
    assert.equal(owner.isBusy(), true)
    await owner.list(request)
    assert.deepEqual(calls, [{ ...request, reconcile: true }])
    assert.equal(owner.isBusy(), false)
})

test('manufacturing routes reject paths, raw bytes, missing consent and malformed backups', async () => {
    for (const extra of [{ path: '/tmp/file' }, { bytes: [1] }, { backupId: '../record' }]) assert.equal(manufacturingRequestSchema.safeParse({ ...request, ...extra }).success, false)
    assert.equal(manufacturingRestoreRequestSchema.safeParse({ ...request, backupId: 'record-1-1', acknowledged: false, confirmationSerial: '1234567890' }).success, false)
    assert.equal(manufacturingResponseSchema.safeParse({ ...inventory, backups: [{ backupId: '../x' }] }).success, false)
    let calls = 0
    const services = {
        manufacturing: {
            backup: async () => {
                calls += 1
                return inventory
            }
        }
    }
    assert.equal((await dispatchApplicationRequest(services, IpcChannel.MANUFACTURING_BACKUP, { ...request, path: '/tmp/x' })).reason, 'invalid-request')
    assert.equal(calls, 0)
    assert.deepEqual(await dispatchApplicationRequest(services, IpcChannel.MANUFACTURING_BACKUP, request), inventory)
    assert.equal(calls, 1)
})

test('identity recovery consent crosses the validated restore boundary only as an explicit boolean', async () => {
    const calls = []
    const owner = service({
        restore: async (request) => {
            calls.push(request)
            return inventory
        }
    })
    const restore = { ...request, backupId: 'record-1-1', acknowledged: true, confirmationSerial: '1234567890', allowIdentityChange: true }
    assert.deepEqual(await owner.restore(restore), inventory)
    assert.deepEqual(calls, [restore])
    for (const allowIdentityChange of ['true', 1, null]) assert.equal(manufacturingRestoreRequestSchema.safeParse({ ...restore, allowIdentityChange }).success, false)
    assert.equal(manufacturingRestoreRequestSchema.safeParse({ ...restore, acknowledged: false }).success, false)
})

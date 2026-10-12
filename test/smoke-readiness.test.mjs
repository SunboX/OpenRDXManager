// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { assertAuthenticatedServiceReadiness, attachSmokeReadinessListeners, getServiceReadinessFailureReason, SmokeReadinessGate } from '../src/main/smoke-readiness.mjs'

test('installed-service acceptance requires a privileged native handshake', () => {
    assert.doesNotThrow(() => assertAuthenticatedServiceReadiness({ status: 'ready', mode: 'native', privileged: true, hardwareReady: false }))
    for (const state of [null, {}, { status: 'unavailable', mode: 'native', privileged: true }, { status: 'ready', mode: 'no-device', privileged: true }, { status: 'ready', mode: 'native', privileged: false }]) {
        assert.throws(() => assertAuthenticatedServiceReadiness(state), /installed-service-authentication-unverified/)
    }
})

test('startup diagnostics retain bounded failure reasons without exposing host paths or native messages', () => {
    assert.equal(getServiceReadinessFailureReason({ status: 'ready', reason: 'ignored' }), 'none')
    assert.equal(getServiceReadinessFailureReason({ status: 'unavailable', reason: 'event-log-unavailable' }), 'event-log-unavailable')
    for (const reason of [undefined, null, '', 'C:\\private\\data', 'native message\nsecret', 'x'.repeat(129), '<script>']) {
        assert.equal(getServiceReadinessFailureReason({ status: 'unavailable', reason }), 'service-unavailable')
    }
})

/**
 * Creates a deterministic one-shot timer implementation for readiness tests.
 * @returns {{scheduleTimeout: Function, cancelTimeout: Function, fire: Function, scheduledCount: Function, cancelledCount: Function}} Injectable timer controls.
 */
function createTimerHarness() {
    /** @type {null | (() => void)} */
    let callback = null
    let scheduled = 0
    let cancelled = 0

    /**
     * Records the timeout callback without consulting wall-clock time.
     * @param {() => void} nextCallback - Timeout callback.
     * @param {number} timeoutMs - Requested bound.
     * @returns {symbol} Stable timer handle.
     */
    function scheduleTimeout(nextCallback, timeoutMs) {
        assert.equal(timeoutMs, 25)
        callback = nextCallback
        scheduled += 1
        return Symbol('smoke-readiness-timer')
    }

    /**
     * Records cancellation and prevents a later synthetic timeout.
     * @returns {void}
     */
    function cancelTimeout() {
        callback = null
        cancelled += 1
    }

    /**
     * Fires the currently scheduled callback exactly once.
     * @returns {void}
     */
    function fire() {
        assert.notEqual(callback, null, 'a readiness timeout must be scheduled')
        const scheduledCallback = callback
        callback = null
        scheduledCallback()
    }

    return {
        scheduleTimeout,
        cancelTimeout,
        fire,
        scheduledCount: () => scheduled,
        cancelledCount: () => cancelled
    }
}

/**
 * Matches the stable public shape of a smoke-readiness failure.
 * @param {string} code - Expected machine-readable failure code.
 * @returns {(error: unknown) => boolean} Assertion predicate.
 */
function hasReadinessCode(code) {
    return (error) => error instanceof Error && error.name === 'SmokeReadinessError' && error.code === code
}

test('smoke readiness times out with a stable error and clears its injected timer', async () => {
    const timer = createTimerHarness()
    const gate = new SmokeReadinessGate({ timeoutMs: 25, scheduleTimeout: timer.scheduleTimeout, cancelTimeout: timer.cancelTimeout })
    const completion = gate.wait()

    assert.equal(timer.scheduledCount(), 1)
    gate.markServiceTerminal({ status: 'ready', mode: 'no-device', hardwareReady: false })
    timer.fire()
    await assert.rejects(completion, hasReadinessCode('smoke-readiness-timeout'))
    assert.equal(timer.cancelledCount(), 1)
})

test('smoke readiness rejects unexpected nonterminal service results without waiting for timeout', async () => {
    const timer = createTimerHarness()
    const gate = new SmokeReadinessGate({ timeoutMs: 25, scheduleTimeout: timer.scheduleTimeout, cancelTimeout: timer.cancelTimeout })
    const completion = gate.wait()

    assert.equal(gate.markServiceTerminal({ status: 'starting' }), false)
    await assert.rejects(completion, hasReadinessCode('smoke-service-not-terminal'))
    assert.equal(timer.cancelledCount(), 1)
})

test('smoke readiness rejects renderer lifecycle failures and cleans up for every path', async () => {
    for (const code of ['smoke-renderer-destroyed', 'smoke-renderer-load-failed', 'smoke-renderer-process-gone']) {
        const timer = createTimerHarness()
        const gate = new SmokeReadinessGate({ timeoutMs: 25, scheduleTimeout: timer.scheduleTimeout, cancelTimeout: timer.cancelTimeout })
        const completion = gate.wait()

        assert.equal(gate.fail(code), true)
        await assert.rejects(completion, hasReadinessCode(code))
        assert.equal(timer.cancelledCount(), 1, `${code} must cancel the timeout`)
        assert.equal(gate.fail(code), false, `${code} must settle at most once`)
    }
})

test('smoke readiness success clears its timer and ignores later failures', async () => {
    const timer = createTimerHarness()
    const gate = new SmokeReadinessGate({ timeoutMs: 25, scheduleTimeout: timer.scheduleTimeout, cancelTimeout: timer.cancelTimeout })
    const completion = gate.wait()

    gate.markRendererMounted()
    assert.equal(gate.markServiceTerminal({ status: 'ready', mode: 'no-device', hardwareReady: false }), true)
    assert.deepEqual(await completion, {
        renderer: 'mounted',
        service: { status: 'ready', mode: 'no-device', hardwareReady: false }
    })
    assert.equal(timer.cancelledCount(), 1)
    assert.equal(gate.fail('smoke-renderer-destroyed'), false)
})

test('disposing pending smoke readiness rejects once and cannot restart its timer', async () => {
    const timer = createTimerHarness()
    const gate = new SmokeReadinessGate({ timeoutMs: 25, scheduleTimeout: timer.scheduleTimeout, cancelTimeout: timer.cancelTimeout })
    const completion = gate.wait()

    gate.dispose()
    assert.equal(timer.cancelledCount(), 1)
    assert.equal(timer.scheduledCount(), 1)
    assert.equal(gate.wait(), completion)
    assert.equal(timer.scheduledCount(), 1)
    await assert.rejects(completion, hasReadinessCode('smoke-readiness-disposed'))
})

test('smoke renderer listeners reject fatal lifecycle events and detach after settlement', async () => {
    const cases = [
        { event: 'destroyed', args: [], code: 'smoke-renderer-destroyed' },
        { event: 'did-fail-load', args: [{}, -2, 'failed', 'file:///app/index.html', true], code: 'smoke-renderer-load-failed' },
        { event: 'render-process-gone', args: [{}, { reason: 'crashed', exitCode: 9 }], code: 'smoke-renderer-process-gone' }
    ]

    for (const testCase of cases) {
        const timer = createTimerHarness()
        const webContents = new EventEmitter()
        const gate = new SmokeReadinessGate({ timeoutMs: 25, scheduleTimeout: timer.scheduleTimeout, cancelTimeout: timer.cancelTimeout })
        attachSmokeReadinessListeners(webContents, gate)
        const completion = gate.wait()

        webContents.emit(testCase.event, ...testCase.args)
        await assert.rejects(completion, hasReadinessCode(testCase.code))
        for (const eventName of ['destroyed', 'did-fail-load', 'render-process-gone']) {
            assert.equal(webContents.listenerCount(eventName), 0, `${testCase.event} must detach ${eventName}`)
        }
    }
})

test('smoke renderer listeners ignore subframe load failures and detach after success', async () => {
    const timer = createTimerHarness()
    const webContents = new EventEmitter()
    const gate = new SmokeReadinessGate({ timeoutMs: 25, scheduleTimeout: timer.scheduleTimeout, cancelTimeout: timer.cancelTimeout })
    attachSmokeReadinessListeners(webContents, gate)
    const completion = gate.wait()

    webContents.emit('did-fail-load', {}, -2, 'failed', 'file:///app/frame.html', false)
    gate.markRendererMounted()
    gate.markServiceTerminal({ status: 'unavailable', reason: 'service-start-failed' })
    await assert.doesNotReject(completion)
    for (const eventName of ['destroyed', 'did-fail-load', 'render-process-gone']) {
        assert.equal(webContents.listenerCount(eventName), 0)
    }
})

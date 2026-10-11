// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { handshakeSchema } from '../src/main/device-service-wire.mjs'

test('accepts an explicit hardware-unverified native service without marking it available', () => {
    const handshake = {
        type: 'handshake',
        protocolVersion: 1,
        serviceVersion: '0.1.0-test',
        platform: 'darwin',
        mode: 'native',
        privileged: true,
        platformCapability: {
            state: 'hardware-unverified',
            reason: 'physical-hardware-unverified'
        }
    }

    assert.deepEqual(handshakeSchema.parse(handshake), handshake)
})

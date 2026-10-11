// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { endpointCounterDeclarations } from '../scripts/receiver-model-contract.mjs'

const header = `typedef struct _EP_INFO_T {
    void *pBuffer;
    UINT32_T dByteCount; /* accumulated bytes */
    INT32_T dBytesRemaining; /* can become negative in the unfixed cleanup */
    UINT32_T dXferLength;
} EP_INFO_T;`

/** @returns {void} Verifies the replay uses the reviewed signed production declaration. */
function testSignedCounter() {
    assert.equal(endpointCounterDeclarations(header), 'INT32_T dBytesRemaining;\n    UINT32_T dByteCount;\n    UINT32_T dXferLength;')
}

/** @returns {void} Rejects drift rather than silently changing the endpoint model. */
function testCounterDrift() {
    for (const changed of [header.replace('INT32_T dBytesRemaining', 'UINT32_T dBytesRemaining'), header.replace('UINT32_T dByteCount', 'UINT16_T dByteCount'), header.replace('UINT32_T dXferLength;', ''), header + header, header.replace('_EP_INFO_T', '_OTHER_T')]) {
        assert.throws(() => endpointCounterDeclarations(changed), /Expected one production|Unreviewed endpoint counter/u)
    }
}

test('receiver replay preserves the production signed remaining counter', testSignedCounter)
test('receiver replay fails closed on counter type or structure drift', testCounterDrift)

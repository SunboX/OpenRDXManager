// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const mainUrl = new URL('../src/main.mjs', import.meta.url)

/** @returns {Promise<void>} Verifies production owns chooser authority and injects it into both narrow boundaries. */
async function testProductionFirmwareWiring() {
    const source = await readFile(mainUrl, 'utf8')
    assert.match(source, /import \{ FirmwareFileSelectionService \} from '\.\/main\/firmware-file-selection-service\.mjs'/u)
    assert.match(source, /showOpenDialog: \(options\) => showFirmwareOpenDialog\(\{ BrowserWindow, dialog \}, options\)/u)
    assert.match(source, /services\.files = Object\.freeze\(\{ chooseFirmware: firmwareFileService\.chooseFirmware\.bind\(firmwareFileService\) \}\)/u)
    assert.match(source, /createApplicationServiceRuntime\(\{[\s\S]*?firmwareFileService,/u)
}

test('production main wires the local firmware chooser into IPC and native registration', testProductionFirmwareWiring)

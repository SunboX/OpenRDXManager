// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { initializeIsolatedElectronProfile } from '../electron-test/isolated-profile.mjs'

test('Electron QA initializes both data paths synchronously in the parent-owned profile', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-profile-contract-'))
    const profile = join(root, 'nested', 'profile')
    const paths = []
    const app = {
        /** @param {string} name - Electron path key. @param {string} value - Selected profile. @returns {void} Records synchronous selection. */
        setPath(name, value) {
            paths.push([name, value])
        }
    }
    try {
        assert.equal(initializeIsolatedElectronProfile(app, profile), profile)
        assert.deepEqual(paths, [
            ['userData', profile],
            ['sessionData', profile]
        ])
        assert.equal((await stat(profile)).isDirectory(), true)
        assert.throws(() => initializeIsolatedElectronProfile(app, 'relative-profile'), /absolute path/)
        assert.equal(paths.length, 2)
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('standalone Electron QA processes receive distinct temporary profiles', async () => {
    const profiles = []
    const app = {
        /** @returns {void} Stand-in for the synchronous Electron path API. */
        setPath() {}
    }
    try {
        profiles.push(initializeIsolatedElectronProfile(app))
        profiles.push(initializeIsolatedElectronProfile(app))
        assert.notEqual(profiles[0], profiles[1])
    } finally {
        for (const profile of profiles) await rm(profile, { recursive: true, force: true })
    }
})

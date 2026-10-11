// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { fileURLToPath } from 'node:url'

import { getAppIconPath } from './app-icon.mjs'

const preloadPath = fileURLToPath(new URL('../out/preload.cjs', import.meta.url))

export const windowOptions = Object.freeze({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 768,
    backgroundColor: '#050a13',
    darkTheme: true,
    titleBarStyle: 'hidden',
    titleBarOverlay: Object.freeze({ color: '#081422', symbolColor: '#deedf7', height: 36 }),
    icon: getAppIconPath(process.platform),
    webPreferences: Object.freeze({
        contextIsolation: true,
        nodeIntegration: false,
        preload: preloadPath,
        sandbox: true
    })
})

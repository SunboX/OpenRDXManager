// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { windowOptions } from '../src/window-options.mjs'

// QA waits for painted animation frames even when another app owns focus.
// Production security/minimum-size defaults remain unchanged and immutable.
export const visualWindowOptions = Object.freeze({
    ...windowOptions,
    show: true,
    webPreferences: Object.freeze({ ...windowOptions.webPreferences, backgroundThrottling: false })
})

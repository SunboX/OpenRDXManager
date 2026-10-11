// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs'

// Read the same manifest in source launches and packaged resources/app. Keep
// this Node-only module in main; renderers receive metadata through validated IPC.
const metadata = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'))

/** Application identity shared by main, MCP, and test entrypoints. */
export const applicationMetadata = Object.freeze({ name: metadata.productName, version: metadata.version })

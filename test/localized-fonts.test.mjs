// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { access, readFile } from 'node:fs/promises'
import test from 'node:test'

test('Chinese and Japanese font resources are local, licensed and complete', async () => {
    const html = await readFile(new URL('../src/index.html', import.meta.url), 'utf8')
    const tokens = await readFile(new URL('../src/styles/tokens.css', import.meta.url), 'utf8')
    for (const language of ['sc', 'jp']) {
        const dependency = `@fontsource-variable/noto-sans-${language}`
        assert.ok(html.includes(`../node_modules/${dependency}/index.css`))
        const stylesheet = new URL(import.meta.resolve(`${dependency}/index.css`))
        const css = await readFile(stylesheet, 'utf8')
        assert.match(css, /font-weight: 100 900/u)
        assert.ok(tokens.includes(`Noto Sans ${language.toUpperCase()} Variable`))
        const assets = [...css.matchAll(/url\(([^)]+)\)/gu)]
        assert.ok(assets.length > 0)
        for (const [, path] of assets) {
            assert.match(path, /^\.\/files\/[^/]+\.woff2$/u)
            await access(new URL(path, stylesheet))
        }
        const license = await readFile(new URL(import.meta.resolve(`${dependency}/LICENSE`)), 'utf8')
        assert.match(license, /SIL OPEN FONT LICENSE/u)
    }
})

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'
import { classifyStartupEvents, observeStartupEvents } from '../scripts/observe-windows-startup-events.mjs'

const since = '2026-10-16T08:00:00.000Z'
const until = '2026-10-16T08:00:05.000Z'

/** @param {object} [fields] Synthetic event fields. @returns {object} Synthetic input, never actual Windows evidence. */
function event(fields = {}) {
    return { channel: 'Application', provider: 'Application Error', id: 1000, time: '2026-10-16T08:00:01.000Z', fields: { AppName: 'openrdx-token-child.exe', ModuleName: 'KERNELBASE.dll', ExceptionCode: 'c0000142', AppPath: 'C:\\private-sentinel\\openrdx-token-child.exe', ...fields } }
}

/** @param {object[]} records Synthetic records. @returns {object} Complete fixed-channel query envelope. */
function envelope(records) {
    return {
        channels: [
            { name: 'Application', status: 'complete' },
            { name: 'System', status: 'complete' }
        ],
        records
    }
}

test('correlates fixed fixture names and time without claiming exact child identity or startup proof', () => {
    const result = classifyStartupEvents(envelope([event()]), { since, until })
    assert.deepEqual(result, { status: 'complete', correlation: 'fixture-name-and-time-only', startupProof: false, records: [{ source: 'application-error', module: 'kernelbase', exception: 'dll-init-failed', count: 1 }] })
    assert.doesNotMatch(JSON.stringify(result), /private-sentinel|AppPath|2026-|\.exe|\.dll/u)
})

test('does not turn a faulting Microsoft module into a cause claim', () => {
    const result = classifyStartupEvents(envelope([event({ ModuleName: 'C:\\private-sentinel\\ntdll.dll', ExceptionCode: 'c0000005' })]), { since, until })
    assert.deepEqual(result.records, [{ source: 'application-error', module: 'other', exception: 'access-violation', count: 1 }])
    assert.equal(Object.hasOwn(result, 'cause'), false)
})

test('rejects unrelated applications, wrong provider/event/channel pairs and records outside the exact window', () => {
    const records = [event({ AppName: 'other.exe' }), { ...event(), provider: 'Windows Error Reporting' }, { ...event(), channel: 'System' }, { ...event(), id: 26 }, { ...event(), time: '2026-10-16T07:59:59.999Z' }, { ...event(), time: '2026-10-16T08:00:05.001Z' }]
    assert.deepEqual(classifyStartupEvents(envelope(records), { since, until }).records, [])
})

test('recognizes only APPCRASH WER fields and a bounded fixture-name popup observation', () => {
    const wer = { ...event(), provider: 'Windows Error Reporting', id: 1001, fields: { EventName: 'APPCRASH', P1: 'openrdx-token-child.exe', P4: 'advapi32.dll', P7: '0xc0000022' } }
    const popup = { ...event(), channel: 'System', provider: 'Application Popup', id: 26, fields: { Caption: 'openrdx-token-child.exe - Application Error', Message: 'The application failed to initialize (0xc0000142). private-sentinel' } }
    const result = classifyStartupEvents(envelope([wer, popup, { ...wer, fields: { ...wer.fields, EventName: 'BEX64' } }, { ...popup, fields: { Message: 'prefixopenrdx-token-child.exe-suffix' } }]), { since, until })
    assert.deepEqual(result.records, [
        { source: 'application-popup', module: 'unknown', exception: 'dll-init-failed', count: 1 },
        { source: 'wer-appcrash', module: 'advapi32', exception: 'access-denied', count: 1 }
    ])
    assert.doesNotMatch(JSON.stringify(result), /private-sentinel/u)
})

test('coalesces bounded observations and distinguishes empty records from an unavailable query', () => {
    assert.equal(classifyStartupEvents(envelope([event(), event()]), { since, until }).records[0].count, 2)
    assert.equal(classifyStartupEvents(envelope([]), { since, until }).status, 'complete')
    const input = envelope([event()])
    input.channels[1].status = 'failed'
    assert.equal(classifyStartupEvents(input, { since, until }).status, 'partial')
    assert.equal(classifyStartupEvents({ channels: [], records: [] }, { since, until }).status, 'invalid')
})

test('refuses oversized, malformed, duplicate-channel and invalid-window evidence without echoing it', () => {
    for (const input of [
        null,
        { privateSentinel: true },
        envelope(Array(65).fill(event())),
        envelope([event({ Message: 'x'.repeat(8193) })]),
        envelope([{ ...event(), time: 'bad-private-sentinel' }]),
        {
            ...envelope([]),
            channels: [
                { name: 'Application', status: 'complete' },
                { name: 'Application', status: 'complete' }
            ]
        }
    ]) {
        assert.deepEqual(classifyStartupEvents(input, { since, until }), { status: 'invalid', correlation: 'fixture-name-and-time-only', startupProof: false, records: [] })
    }
    for (const window of [
        { since: 'bad-private-sentinel', until },
        { since: until, until: since },
        { since, until: '2026-10-16T08:05:00.001Z' }
    ])
        assert.equal(classifyStartupEvents(envelope([]), window).status, 'invalid')
})

test('runs only the fixed reader under bounded output/deadline and never forwards native error text', async () => {
    const result = await observeStartupEvents({
        since,
        until,
        platform: 'win32',
        execute: async (command, args, options) => {
            assert.match(command, /WindowsPowerShell\\v1\.0\\powershell\.exe$/u)
            assert.ok(args.includes('-NoProfile'))
            assert.ok(args.includes('-NonInteractive'))
            assert.equal(args.at(-4), '-Since')
            assert.equal(args.at(-3), since)
            assert.equal(args.at(-2), '-Until')
            assert.equal(args.at(-1), until)
            assert.equal(options.timeout, 8000)
            assert.equal(options.maxBuffer, 4 * 1024 * 1024)
            return { stdout: JSON.stringify(envelope([event()])), stderr: 'private-sentinel' }
        }
    })
    assert.equal(result.status, 'complete')
    assert.doesNotMatch(JSON.stringify(result), /private-sentinel/u)
    const failed = await observeStartupEvents({
        since,
        until,
        platform: 'win32',
        execute: async () => {
            throw new Error('private-sentinel')
        }
    })
    assert.deepEqual(failed, { status: 'unavailable', correlation: 'fixture-name-and-time-only', startupProof: false, records: [] })
})

test('invalid input and non-Windows hosts never execute the reader', async () => {
    const execute = async () => {
        assert.fail('reader should not execute')
    }
    assert.equal((await observeStartupEvents({ since: 'bad', until, platform: 'win32', execute })).status, 'invalid')
    assert.equal((await observeStartupEvents({ since, until, platform: 'darwin', execute })).status, 'unavailable')
})

test('CI retains the original fatal child gate and records diagnostic-only evidence separately', async () => {
    const workflow = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    const gate = workflow.slice(workflow.indexOf('- name: Verify owned medium Windows child'), workflow.indexOf('- name: Observe Windows child startup error records'))
    assert.match(gate, /node scripts\/verify-windows-restricted-token-probe\.mjs --child \| Tee-Object[^\n]+\n\s*\$probeExitCode = \$LASTEXITCODE\n\s*exit \$probeExitCode/u)
    assert.doesNotMatch(gate, /continue-on-error/u)
    assert.match(workflow, /windows-token-startup-events\.log/u)
    assert.match(workflow, /--since \$env:OPENRDX_CHILD_OBSERVATION_START/u)
})

test('actual Windows PowerShell parser rejects entities, duplicate fields and bounds before classification', { skip: process.platform !== 'win32' }, async () => {
    const script = fileURLToPath(new URL('../scripts/read-windows-startup-events.ps1', import.meta.url))
    // Parse the authored helper definition without executing the event-reader entrypoint.
    const code = `$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile('${script.replaceAll("'", "''")}',[ref]$tokens,[ref]$errors);if($errors.Count -ne 0){throw 'parse-failed'};$functions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-StartupEventRow'},$false));if($functions.Count -ne 1){throw 'helper-shape'};. ([ScriptBlock]::Create($functions[0].Extent.Text));$xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData><Data Name="AppName">openrdx-token-child.exe</Data><Data Name="ModuleName">kernelbase.dll</Data><Data Name="ExceptionCode">c0000142</Data><Data Name="PrivateIgnored">private-sentinel</Data></EventData></Event>';$time=[DateTime]::Parse('2026-10-16T08:00:01.000Z').ToUniversalTime();$row=ConvertTo-StartupEventRow $xml Application 'Application Error' 1000 $time;$rejected=0;foreach($bad in @('<!DOCTYPE Event [<!ENTITY leak SYSTEM "file:///private-sentinel">]><Event><EventData><Data Name="AppName">&leak;</Data></EventData></Event>',$xml.Replace('</EventData>','<Data Name="AppName">duplicate</Data></EventData>'),('<Event><EventData><Data Name="Message">'+('x'*8193)+'</Data></EventData></Event>'),('x'*131073))){try{$null=ConvertTo-StartupEventRow $bad Application 'Application Error' 1000 $time}catch{$rejected++}};[ordered]@{row=$row;rejected=$rejected}|ConvertTo-Json -Depth 5 -Compress`
    const { stdout } = await promisify(execFile)('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(code, 'utf16le').toString('base64')], { timeout: 8000, maxBuffer: 65536 })
    const parsed = JSON.parse(stdout.replace(/^\uFEFF/u, ''))
    assert.equal(parsed.rejected, 4)
    assert.doesNotMatch(stdout, /private-sentinel/u)
    assert.equal(classifyStartupEvents(envelope([parsed.row]), { since, until }).records[0].exception, 'dll-init-failed')
})

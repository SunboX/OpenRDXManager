// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Fails a disposable visual process when its parent's diagnostic pipe closes.
 * Without a stream error listener Electron opens a blocking exception dialog,
 * leaving the timed-out test child alive. No output failure can claim success.
 * @param {{exit: (code: number) => void}} app - Owned Electron application.
 * @param {{stdout: object, stderr: object}} streams - Event-emitting output streams.
 * @returns {void} Installs process-lifetime output error listeners.
 */
export function guardVisualOutput(app, streams) {
    /** @returns {void} Terminates this fixture on any failed output stream. */
    function failOutput() {
        app.exit(1)
    }
    streams.stdout.on('error', failOutput)
    streams.stderr.on('error', failOutput)
}

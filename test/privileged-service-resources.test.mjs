// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** Reads one immutable packaging resource relative to the repository root. @param {string} platform - Resource platform folder. @param {string} name - Resource filename. @returns {Promise<string>} UTF-8 contents. */
function readResource(platform, name) {
    return readFile(new URL(`../native/rdx-service/resources/${platform}/${name}`, import.meta.url), 'utf8')
}

test('Linux installation metadata exposes only the fixed root-owned local endpoint and narrow group policy', async () => {
    const [service, socket, sysusers, tmpfiles, policy, udev] = await Promise.all([readResource('linux', 'openrdx-hardware.service'), readResource('linux', 'openrdx-hardware.socket'), readResource('linux', 'openrdx.conf'), readResource('linux', 'openrdx-tmpfiles.conf'), readResource('linux', 'org.openrdx.hardware.policy'), readResource('linux', '70-openrdx.rules')])

    assert.match(service, /^ExecStart=\/usr\/libexec\/openrdx-hardware --service-mode systemd-socket --protocol-version 1$/m)
    assert.match(service, /^User=root$/m)
    assert.match(service, /^StandardInput=null$/m)
    assert.match(service, /^ProtectSystem=strict$/m)
    // Startup opens only the precreated ownership lock for writing. Do not
    // grant a writable runtime directory or weaken the filesystem sandbox.
    assert.deepEqual(
        service.split('\n').filter((line) => line.startsWith('ReadWritePaths=')),
        ['ReadWritePaths=/run/openrdx/openrdx-hardware.lock']
    )
    assert.doesNotMatch(service, /--service-mode stdio/)
    assert.match(socket, /^ListenStream=\/run\/openrdx\/openrdx-hardware\.sock$/m)
    assert.match(socket, /^SocketUser=root$/m)
    assert.match(socket, /^SocketGroup=openrdx$/m)
    assert.match(socket, /^SocketMode=0660$/m)
    assert.match(socket, /^MaxConnections=8$/m)
    // sysusers group records allow only name/ID; user-only description/home/shell
    // fields are rejected during real installation. Do not create users or memberships.
    const groupRecords = sysusers
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))
    assert.deepEqual(
        groupRecords.map((line) => line.split(/\s+/u)),
        [['g', 'openrdx', '-']]
    )
    assert.match(tmpfiles, /^d \/run\/openrdx 0750 root openrdx -$/m)
    assert.match(tmpfiles, /^f \/run\/openrdx\/openrdx-hardware\.lock 0600 root root -$/m)
    assert.match(policy, /<action id="org\.openrdx\.hardware\.manage">/)
    assert.match(policy, /<allow_any>no<\/allow_any>/)
    assert.match(policy, /<allow_inactive>no<\/allow_inactive>/)
    assert.match(policy, /<allow_active>auth_admin<\/allow_active>/)
    assert.doesNotMatch(policy, /auth_admin_keep|<allow_(?:any|inactive)>yes/)
    assert.match(udev, /ATTRS\{idVendor\}=="1a5a"/)
    assert.match(udev, /ATTRS\{idProduct\}=="0006"/)
    assert.match(udev, /OWNER="root"/)
    assert.match(udev, /GROUP="root"/)
    assert.match(udev, /MODE="0600"/)
    assert.doesNotMatch(udev, /GROUP="openrdx"|uaccess|0666/)
})

test('Windows and macOS metadata pin local endpoint bounds without auto-install authority', async () => {
    const [windows, macos, provisioner, readme] = await Promise.all([readResource('windows', 'openrdx-hardware-service.xml'), readResource('macos', 'com.openrdx.hardware.plist'), readResource('windows', 'provision-openrdx-service-access.ps1'), readResource('windows', 'README.md')])

    assert.match(windows, /autoInstall="false"/)
    assert.match(windows, /autoElevate="false"/)
    assert.match(windows, /pipeName="\\\\\.\\pipe\\OpenRDXHardwareService"/)
    assert.match(windows, /protectedDacl="true"/)
    assert.match(windows, /serviceSid="S-1-5-19"/)
    assert.match(windows, /administratorsSid="S-1-5-32-544"/)
    assert.match(windows, /currentUserResolution="verified-session-token-at-connect"/)
    assert.match(windows, /currentUserAccessMask="0x00100183"/)
    assert.match(windows, /currentUserCanCreatePipeInstance="false"/)
    assert.match(windows, /clientConnector="direct-napi"/)
    assert.match(windows, /clientMustVerifyServerPid="true"/)
    assert.match(windows, /clientMustVerifyStableServiceConfig="true"/)
    assert.match(windows, /serviceControlAccess="query-config query-status start"/)
    assert.match(windows, /serviceControlPrincipal="verified-current-manager-user"/)
    assert.match(windows, /serviceControlAccessMask="0x00000015"/)
    assert.match(windows, /serviceControlOtherUnprivilegedAccess="none"/)
    assert.match(windows, /serviceControlCanStop="false"/)
    assert.match(windows, /serviceControlCanChangeConfig="false"/)
    assert.match(windows, /serviceControlCanDelete="false"/)
    assert.match(windows, /activationTimeoutMs="5000"/)
    assert.match(windows, /nativeActivationTimeoutMs="7000"/)
    assert.match(windows, /outerActivationTimeoutMs="8000"/)
    assert.match(windows, /preStartConfigValidation="true"/)
    assert.match(windows, /acceptTimeoutMs="10000"/)
    assert.match(windows, /handshakeTimeoutMs="2000"/)
    assert.match(windows, /dispatcher="windows-scm"/)
    assert.match(windows, /acceptedControls="stop shutdown"/)
    assert.match(windows, /statusSequence="start-pending running stop-pending stopped"/)
    assert.match(windows, /stopPollMs="250"/)
    assert.match(windows, /provisioner="openrdx-service-acl\.exe"/)
    assert.match(windows, /provisionAction="provision"/)
    assert.match(windows, /verifyAction="verify"/)
    assert.match(windows, /removeAction="remove"/)
    assert.match(windows, /key="HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenRDXManager\\DriveLetters"/)
    assert.match(windows, /ownerSid="S-1-5-32-544"/)
    assert.match(windows, /groupSid="S-1-5-18"/)
    assert.match(windows, /localServiceParentAccessMask="0x0002000f"/)
    assert.match(windows, /localServiceChildAccessMask="0x0003000f"/)
    assert.match(windows, /localServiceChildAce="container-inherit inherit-only"/)
    assert.match(windows, /rejectForeignOrBroadenedAcl="true"/)
    assert.match(windows, /verifyBeforeReadiness="true"/)
    assert.match(provisioner, /ValidateSet\('Provision', 'Verify', 'Remove'\)/)
    assert.match(provisioner, /openrdx-service-acl\.exe/)
    assert.match(provisioner, /--manager-process-id/)
    assert.doesNotMatch(provisioner, /--(?:service|path|sid)/)
    assert.match(readme, /idempotent/i)
    assert.match(readme, /SetServiceObjectSecurity/)
    assert.match(readme, /0x00000015/)
    assert.match(readme, /DriveLetters/)
    assert.match(readme, /inherit-only/i)
    assert.match(readme, /runtime readiness remains false/i)
    assert.match(macos, /<key>UserName<\/key>\s*<string>root<\/string>/)
    assert.match(macos, /<string>\/var\/run\/openrdx-hardware\.sock<\/string>/)
    assert.match(macos, /<key>SockPathMode<\/key>\s*<integer>432<\/integer>/)
    assert.match(macos, /<string>launchd-socket<\/string>/)
    assert.doesNotMatch(macos, /<string>stdio<\/string>/)
})

test('Linux idle socket-activation retirement is successful and cannot enter Restart=on-failure', async () => {
    const service = await readResource('linux', 'openrdx-hardware.service')

    assert.match(service, /^Restart=on-failure$/m)
    assert.match(service, /^SuccessExitStatus=0$/m)
    assert.match(service, /^# Idle accept timeout retires cleanly; the socket unit owns future activation\.$/m)
})

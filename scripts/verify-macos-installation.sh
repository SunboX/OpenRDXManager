#!/bin/bash
# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later

# Run only on a disposable native CI machine. This installs and removes the
# fixed system application; it never submits a device mutation request.
set -euo pipefail
[[ "$(uname -s)" == Darwin && "${GITHUB_ACTIONS:-}" == true ]] || {
    echo 'This system installation check requires a disposable macOS CI runner.' >&2
    exit 1
}
version=$(node -p "JSON.parse(require('fs').readFileSync('package.json','utf8')).version")
architecture=$(node -p 'process.arch')
package="dist/installers/OpenRDXManager-${version}-mac-${architecture}.pkg"
cli='/Library/Application Support/OpenRDXManager/LocalTrust/openrdx-local-install'
app='/Applications/OpenRDXManager.app'
pinned_file="$app/Contents/Resources/app.asar.unpacked/package.json"
evidence=$(mktemp -d /private/tmp/openrdx-install-verification.XXXXXX)
original="$evidence/package.json"
restoration_required=false

# Restore the exact file before cleanup, including when a negative check fails.
cleanup() {
    local installation_exit=$?
    if [[ "$installation_exit" != 0 ]]; then
        # Keep bounded native service evidence when installed authentication or
        # repair fails, before any test-owned restoration. This disposable CI
        # host has no physical device or application secrets.
        sudo /bin/launchctl print system/com.openrdx.hardware || true
        sudo /usr/bin/log show --last 5m --style compact --predicate 'process == "openrdx-hardware"' 2>/dev/null | /usr/bin/tail -n 100 || true
    fi
    if [[ "$restoration_required" == true ]]; then
        sudo /bin/cp "$original" "$pinned_file"
        sudo /usr/sbin/chown root:wheel "$pinned_file"
        sudo /bin/chmod 644 "$pinned_file"
    fi
    /bin/rm -rf "$evidence"
}
trap cleanup EXIT

# Record the actual desktop principal used by native peer authentication.
/usr/bin/id
/usr/bin/stat -f 'console-owner=%u:%g mode=%Lp' /dev/console

# Include package-script diagnostics in the job, rather than reporting only
# Installer's generic failure. This runs on the disposable native CI host.
install_package() {
    if sudo /usr/sbin/installer -verboseR -dumplog -pkg "$package" -target /; then
        return 0
    fi
    sudo /usr/bin/tail -n 200 /var/log/install.log
    return 1
}

install_package
sudo "$cli" verify
npm run verify:packaged-app -- --installed --require-service

# An identical portable copy must not inherit the installed path's authority.
/usr/bin/ditto "$app" "$evidence/OpenRDXManager.app"
if "$evidence/OpenRDXManager.app/Contents/MacOS/OpenRDXManager" --service-auth-test --user-data-dir="$evidence/copied-profile" > "$evidence/copied.log" 2>&1; then
    echo 'An unenrolled portable copy authenticated to the service.' >&2
    exit 1
fi
if /usr/bin/grep -q 'installed service authentication passed' "$evidence/copied.log"; then
    echo 'A copied application emitted authenticated readiness.' >&2
    exit 1
fi

# Package JSON stays valid, so only trust checking should deny this edit.
/bin/cp "$pinned_file" "$original"
restoration_required=true
printf '\n' | sudo /usr/bin/tee -a "$pinned_file" > /dev/null
if sudo "$cli" verify; then
    echo 'The provisioner accepted modified installed runtime bytes.' >&2
    exit 1
fi
if npm run verify:packaged-app -- --installed --require-service > "$evidence/tampered.log" 2>&1; then
    echo 'A modified installed application authenticated to the service.' >&2
    exit 1
fi

# An elevated reinstall must replace a damaged, still administrator-owned
# generation, then enroll the new complete bytes and restore authentication.
install_package
restoration_required=false
sudo "$cli" verify
npm run verify:packaged-app -- --installed --require-service
sudo "$cli" remove
[[ ! -e "$app" && ! -e '/Library/PrivilegedHelperTools/openrdx-hardware' && ! -e '/Library/LaunchDaemons/com.openrdx.hardware.plist' ]]
if /bin/launchctl print system/com.openrdx.hardware > /dev/null 2>&1; then
    echo 'The removed service remains registered.' >&2
    exit 1
fi
echo 'macOS installed authentication, copied/tampered runtime rejection, repair and removal passed; no device mutation performed.'

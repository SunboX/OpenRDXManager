#!/bin/sh
# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

# Preserve Electron's Linux desktop integration and supported sandbox setup.
# The package manager owns these files as root; no sandbox is disabled.
chown root:root /opt/OpenRDXManager/chrome-sandbox
chmod 4755 /opt/OpenRDXManager/chrome-sandbox
if command -v update-alternatives >/dev/null 2>&1; then
    update-alternatives --install /usr/bin/OpenRDXManager OpenRDXManager /opt/OpenRDXManager/OpenRDXManager 100
else
    ln -sf /opt/OpenRDXManager/OpenRDXManager /usr/bin/OpenRDXManager
fi
if command -v update-mime-database >/dev/null 2>&1; then update-mime-database /usr/share/mime || true; fi
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database /usr/share/applications || true; fi

# Electron-builder supplies a profile for this exact executable on AppArmor 4.
# Older kernels/parsers retain their existing supported sandbox configuration.
profile_source='/opt/OpenRDXManager/resources/apparmor-profile'
profile_target='/etc/apparmor.d/OpenRDXManager'
if command -v apparmor_status >/dev/null 2>&1 && apparmor_status --enabled >/dev/null 2>&1; then
    if apparmor_parser --skip-kernel-load --debug "$profile_source" >/dev/null 2>&1; then
        install -m 0644 "$profile_source" "$profile_target"
        if ! { [ -x /usr/bin/ischroot ] && /usr/bin/ischroot; }; then
            apparmor_parser --replace --write-cache --skip-read-cache "$profile_target"
        fi
    fi
fi

app_resources='/opt/OpenRDXManager/resources'
service_resources="$app_resources/native/linux"
install -d -m 0755 /usr/lib/sysusers.d /usr/lib/tmpfiles.d /usr/libexec /usr/lib/systemd/system /usr/lib/udev/rules.d /usr/share/polkit-1/actions
install -m 0644 "$service_resources/openrdx.conf" /usr/lib/sysusers.d/openrdx.conf
systemd-sysusers /usr/lib/sysusers.d/openrdx.conf
install -m 0644 "$service_resources/openrdx-tmpfiles.conf" /usr/lib/tmpfiles.d/openrdx.conf
install -m 0755 "$service_resources/openrdx-hardware" /usr/libexec/openrdx-hardware
install -m 0644 "$service_resources/openrdx-hardware.service" /usr/lib/systemd/system/openrdx-hardware.service
install -m 0644 "$service_resources/openrdx-hardware.socket" /usr/lib/systemd/system/openrdx-hardware.socket
install -m 0644 "$service_resources/70-openrdx.rules" /usr/lib/udev/rules.d/70-openrdx.rules
install -m 0644 "$service_resources/org.openrdx.hardware.policy" /usr/share/polkit-1/actions/org.openrdx.hardware.policy
systemd-tmpfiles --create /usr/lib/tmpfiles.d/openrdx.conf
# Container/package builders may not have a running systemd manager.
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now openrdx-hardware.socket
fi
# Group membership is an explicit administrator decision, not an install side effect.

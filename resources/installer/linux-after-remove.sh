#!/bin/sh
# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu

# Do not remove the service while Debian is replacing the package during upgrade.
case "${1:-remove}" in upgrade|failed-upgrade) exit 0 ;; esac
if command -v update-alternatives >/dev/null 2>&1; then
    update-alternatives --remove OpenRDXManager /opt/OpenRDXManager/OpenRDXManager
else
    rm -f /usr/bin/OpenRDXManager
fi
profile='/etc/apparmor.d/OpenRDXManager'
if [ -f "$profile" ]; then
    if command -v apparmor_status >/dev/null 2>&1 && apparmor_status --enabled >/dev/null 2>&1 && ! { [ -x /usr/bin/ischroot ] && /usr/bin/ischroot; }; then
        apparmor_parser --remove "$profile" || true
    fi
    rm -f "$profile"
fi
if [ -d /run/systemd/system ]; then
    systemctl disable --now openrdx-hardware.socket || true
    systemctl stop openrdx-hardware.service || true
fi
rm -f /usr/libexec/openrdx-hardware /usr/lib/systemd/system/openrdx-hardware.service /usr/lib/systemd/system/openrdx-hardware.socket /usr/lib/sysusers.d/openrdx.conf /usr/lib/tmpfiles.d/openrdx.conf /usr/lib/udev/rules.d/70-openrdx.rules /usr/share/polkit-1/actions/org.openrdx.hardware.policy
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
# Preserve user data and the IPC group across uninstall/reinstall.

#!/bin/sh
# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later
# Administrator-run owned removal; native policy preserves user preferences/backups.
set -eu
if [ "$#" -ne 0 ]; then
    echo 'OpenRDXManager uninstall accepts no path or service arguments.' >&2
    exit 1
fi
exec '/Library/Application Support/OpenRDXManager/LocalTrust/openrdx-local-install' remove

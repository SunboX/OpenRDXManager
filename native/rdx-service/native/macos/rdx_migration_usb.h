// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef OPENRDX_RDX_MIGRATION_USB_H
#define OPENRDX_RDX_MIGRATION_USB_H

#include "rdx_iokit.h"

/** Reads registry properties only; zero epoch means absent or the TI ROM loader. */
rdx_macos_status rdx_macos_observe_migration_usb(uint32_t location_id, const uint8_t *serial,
                                                 uint32_t length, uint64_t *epoch);

#if defined(RDX_MACOS_TEST_HOOKS)
/** Exercises pure observation policy with local facts and no IOKit enumeration. */
bool rdx_macos_test_migration_usb_observation_contract(void);
#endif

#endif

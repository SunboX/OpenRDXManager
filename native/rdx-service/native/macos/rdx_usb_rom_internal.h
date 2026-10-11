// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef OPENRDX_RDX_USB_ROM_INTERNAL_H
#define OPENRDX_RDX_USB_ROM_INTERNAL_H

#include "rdx_usb_rom.h"
#include <IOKit/IOKitLib.h>

/** Returns one retained exact selected parent after fresh read-only enumeration. */
rdx_macos_status rdx_rom_find_selected_parent(const rdx_macos_rom_candidate *candidate,
                                              io_service_t *output);

#endif

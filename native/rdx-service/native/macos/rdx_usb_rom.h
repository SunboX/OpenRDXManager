// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#ifndef OPENRDX_RDX_USB_ROM_H
#define OPENRDX_RDX_USB_ROM_H

#include "rdx_iokit.h"

/** Opaque thread-bound TI ROM lease; no operation is performed implicitly. */
typedef struct rdx_macos_rom_session rdx_macos_rom_session;

/** A bounded registry snapshot is continuity evidence, never a per-unit serial. */
#define RDX_MACOS_MAX_ROM_CANDIDATES 16U
typedef struct rdx_macos_rom_candidate {
    uint64_t registry_id;
    uint32_t location_id;
    uint32_t reserved;
} rdx_macos_rom_candidate;

/** Lists only ROM USB parents using read-only IORegistry access; no interface IO.
 * Output is all-or-nothing, deduplicated and bounded to sixteen candidates.
 */
rdx_macos_status rdx_macos_rom_enumerate(rdx_macos_rom_candidate *output, uint32_t capacity,
                                       uint32_t *count);

/** Fixed-width completion facts for one operation, including known partial IO. */
typedef struct rdx_macos_rom_result {
    rdx_macos_status status;
    uint32_t attempted;
    uint32_t transferred_known;
    uint32_t transferred;
} rdx_macos_rom_result;

/** Binds the sole global 0451:926B parent at location without capture or seizure. */
rdx_macos_status rdx_macos_rom_open(uint32_t location_id, rdx_macos_rom_session **output);

/** Binds exactly the selected epoch and location, allowing other ROM parents. */
rdx_macos_status rdx_macos_rom_open_selected(const rdx_macos_rom_candidate *candidate,
                                           rdx_macos_rom_session **output);

/** Releases ownership without reset; unknown callbacks remain quarantined. */
void rdx_macos_rom_release(rdx_macos_rom_session *session);

/** Executes only identify(1), setup(2), one program(3), reset(4), in that order.
 * Timeouts are 1..120000 ms; program is one immutable 22..65535-byte image.
 * Caller validates the pinned personalized image and journals each intent first.
 */
void rdx_macos_rom_execute(rdx_macos_rom_session *session, uint32_t command, const uint8_t *bytes,
                           uint32_t length, uint32_t timeout_ms, rdx_macos_rom_result *result);

#if defined(RDX_MACOS_TEST_HOOKS)
/** Exercises pure native selection, descriptor and completion contracts offline. */
bool rdx_macos_rom_test_contract(void);
#endif

#endif

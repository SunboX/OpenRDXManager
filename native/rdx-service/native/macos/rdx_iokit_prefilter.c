// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <string.h>

/* docs/protocols/high-flash-configuration.md records the
 * fixed SCSI/USB identity as TANDBERG and RDX (with space padding). This
 * property-only filter is deliberately narrower than final admission: Task 1
 * must still validate raw INQUIRY and capability replies through the exact
 * retained service. */
static bool rdx_ascii_equals_padded(
    const char *observed,
    const char *expected
) {
    size_t observed_length = strnlen(
        observed,
        RDX_MACOS_MAX_TEXT_BYTES + 1
    );
    if (observed_length > RDX_MACOS_MAX_TEXT_BYTES) {
        return false;
    }
    while (observed_length > 0 && observed[observed_length - 1] == ' ') {
        observed_length -= 1;
    }
    size_t expected_length = strlen(expected);
    if (observed_length != expected_length) {
        return false;
    }
    for (size_t index = 0; index < expected_length; ++index) {
        unsigned char value = (unsigned char)observed[index];
        if (value >= 'a' && value <= 'z') {
            value = (unsigned char)(value - ('a' - 'A'));
        }
        if (value != (unsigned char)expected[index]) {
            return false;
        }
    }
    return true;
}

bool rdx_macos_candidate_matches_rdx_hint(
    const rdx_macos_candidate_record *candidate
) {
    return rdx_candidate_record_is_valid(candidate) &&
        candidate->has_vendor == 1 && candidate->has_product == 1 &&
        rdx_ascii_equals_padded(candidate->vendor, "TANDBERG") &&
        rdx_ascii_equals_padded(candidate->product, "RDX");
}

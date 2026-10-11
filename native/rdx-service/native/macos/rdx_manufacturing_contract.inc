// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Independently validates fixed manufacturing restore framing and desired checksum. */
static bool rdx_manufacturing_restore_payload_is_valid(const uint8_t *data, uint32_t length) {
    if (data == NULL || length != 528 || memcmp(data, "RDXMFG01", 8) != 0 ||
        data[12] != 0 || data[13] != 0 || data[14] != 0 || data[15] != 0) { return false; }
    uint8_t lanes[4] = {0x78, 0x56, 0x34, 0x12};
    bool erased = true;
    for (size_t index = 0; index < 256; index++) {
        uint8_t byte = data[272 + index];
        if (byte != 0xff) { erased = false; }
        if (index >= 4) { lanes[index & 3] = (uint8_t)(lanes[index & 3] + byte); }
    }
    /* Expected current bytes may be erased or corrupt: the receiver performs
     * exact compare-and-replace against those bytes plus the full-sector CRC. */
    return !erased && memcmp(lanes, data + 272, 4) == 0;
}

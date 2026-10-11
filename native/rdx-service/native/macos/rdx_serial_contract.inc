// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Validates the closed 280-byte serial request independently of every Rust caller. */
static bool rdx_serial_payload_is_valid(const uint8_t *data, uint32_t length) {
    if (data == NULL || length != 280 || memcmp(data, "RDXSER01", 8) != 0 ||
        data[12] > 1 || data[13] != 0) { return false; }
    for (size_t index = 14; index < 24; index++) {
        if (data[index] < '0' || data[index] > '9') { return false; }
    }
    if (data[12] == 1) {
        for (size_t index = 24; index < 280; index++) {
            if (data[index] != 0xff) { return false; }
        }
        return true;
    }
    uint8_t lanes[4] = {0x78, 0x56, 0x34, 0x12};
    for (size_t index = 4; index < 256; index++) {
        lanes[index & 3] = (uint8_t)(lanes[index & 3] + data[index + 24]);
    }
    return memcmp(lanes, &data[24], 4) == 0;
}

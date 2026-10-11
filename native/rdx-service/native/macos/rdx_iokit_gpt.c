// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    RDX_GPT_SECTOR_BYTES = 512,
    RDX_GPT_PARTITION_START = 2048,
    RDX_GPT_ENTRY_COUNT = 128,
    RDX_GPT_ENTRY_BYTES = 128,
    RDX_GPT_ENTRY_SECTORS = 32,
    RDX_GPT_HEADER_BYTES = 92
};

static void rdx_gpt_store_u32(uint8_t *output, uint32_t value) {
    for (uint32_t index = 0; index < 4; ++index) {
        output[index] = (uint8_t)(value >> (index * 8));
    }
}

static void rdx_gpt_store_u64(uint8_t *output, uint64_t value) {
    for (uint32_t index = 0; index < 8; ++index) {
        output[index] = (uint8_t)(value >> (index * 8));
    }
}

#if defined(RDX_MACOS_TEST_HOOKS)
static uint32_t rdx_gpt_load_u32(const uint8_t *input) {
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
        ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static uint64_t rdx_gpt_load_u64(const uint8_t *input) {
    return (uint64_t)rdx_gpt_load_u32(input) |
        ((uint64_t)rdx_gpt_load_u32(input + 4) << 32);
}
#endif

static uint32_t rdx_gpt_crc32(const uint8_t *bytes, size_t length) {
    uint32_t crc = UINT32_MAX;
    for (size_t index = 0; index < length; ++index) {
        crc ^= bytes[index];
        for (uint32_t bit = 0; bit < 8; ++bit) {
            uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1) ^ (UINT32_C(0xEDB88320) & mask);
        }
    }
    return ~crc;
}

static bool rdx_gpt_write(int descriptor, const void *bytes, size_t length,
    uint64_t offset) {
    const uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t written = pwrite(descriptor, cursor, length, (off_t)offset);
        if (written > 0) {
            cursor += (size_t)written;
            length -= (size_t)written;
            offset += (uint64_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

#if defined(RDX_MACOS_TEST_HOOKS)
static bool rdx_gpt_read(int descriptor, void *bytes, size_t length,
    uint64_t offset) {
    uint8_t *cursor = bytes;
    while (length > 0) {
        ssize_t received = pread(descriptor, cursor, length, (off_t)offset);
        if (received > 0) {
            cursor += (size_t)received;
            length -= (size_t)received;
            offset += (uint64_t)received;
        } else if (received < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}
#endif

static void rdx_gpt_guid(uint8_t output[16]) {
    arc4random_buf(output, 16);
    output[7] = (uint8_t)((output[7] & UINT8_C(0x0F)) | UINT8_C(0x40));
    output[8] = (uint8_t)((output[8] & UINT8_C(0x3F)) | UINT8_C(0x80));
}

static void rdx_gpt_header(uint8_t output[RDX_GPT_SECTOR_BYTES],
    uint64_t current_lba, uint64_t alternate_lba, uint64_t last_usable,
    const uint8_t disk_guid[16], uint64_t entries_lba, uint32_t entries_crc) {
    memset(output, 0, RDX_GPT_SECTOR_BYTES);
    memcpy(output, "EFI PART", 8);
    rdx_gpt_store_u32(output + 8, UINT32_C(0x00010000));
    rdx_gpt_store_u32(output + 12, RDX_GPT_HEADER_BYTES);
    rdx_gpt_store_u64(output + 24, current_lba);
    rdx_gpt_store_u64(output + 32, alternate_lba);
    rdx_gpt_store_u64(output + 40, RDX_GPT_PARTITION_START);
    rdx_gpt_store_u64(output + 48, last_usable);
    memcpy(output + 56, disk_guid, 16);
    rdx_gpt_store_u64(output + 72, entries_lba);
    rdx_gpt_store_u32(output + 80, RDX_GPT_ENTRY_COUNT);
    rdx_gpt_store_u32(output + 84, RDX_GPT_ENTRY_BYTES);
    rdx_gpt_store_u32(output + 88, entries_crc);
    rdx_gpt_store_u32(output + 16, rdx_gpt_crc32(output, RDX_GPT_HEADER_BYTES));
}

bool rdx_write_gpt_layout(int descriptor, uint64_t capacity,
    uint32_t signature, uint64_t *volume_sectors) {
    if (descriptor < 0 || signature == 0 || volume_sectors == NULL ||
        capacity % RDX_GPT_SECTOR_BYTES != 0) {
        return false;
    }
    uint64_t total_sectors = capacity / RDX_GPT_SECTOR_BYTES;
    if (total_sectors <= RDX_GPT_PARTITION_START + RDX_GPT_ENTRY_SECTORS + 1) {
        return false;
    }
    uint64_t last_lba = total_sectors - 1;
    uint64_t backup_entries_lba = last_lba - RDX_GPT_ENTRY_SECTORS;
    uint64_t last_usable = backup_entries_lba - 1;
    *volume_sectors = last_usable - RDX_GPT_PARTITION_START + 1;
    uint8_t mbr[RDX_GPT_SECTOR_BYTES] = {0};
    rdx_gpt_store_u32(mbr + 440, signature);
    mbr[450] = UINT8_C(0xEE);
    rdx_gpt_store_u32(mbr + 454, 1);
    rdx_gpt_store_u32(mbr + 458,
        total_sectors - 1 > UINT32_MAX ? UINT32_MAX : (uint32_t)(total_sectors - 1));
    mbr[510] = UINT8_C(0x55);
    mbr[511] = UINT8_C(0xAA);
    uint8_t entries[RDX_GPT_ENTRY_COUNT * RDX_GPT_ENTRY_BYTES] = {0};
    const uint8_t basic_data[16] = {
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
        0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
    };
    memcpy(entries, basic_data, 16);
    rdx_gpt_guid(entries + 16);
    rdx_gpt_store_u64(entries + 32, RDX_GPT_PARTITION_START);
    rdx_gpt_store_u64(entries + 40, last_usable);
    uint32_t entries_crc = rdx_gpt_crc32(entries, sizeof(entries));
    uint8_t disk_guid[16] = {0};
    uint8_t primary[RDX_GPT_SECTOR_BYTES] = {0};
    uint8_t backup[RDX_GPT_SECTOR_BYTES] = {0};
    rdx_gpt_guid(disk_guid);
    rdx_gpt_header(primary, 1, last_lba, last_usable, disk_guid, 2, entries_crc);
    rdx_gpt_header(backup, last_lba, 1, last_usable, disk_guid,
        backup_entries_lba, entries_crc);
    return rdx_gpt_write(descriptor, mbr, sizeof(mbr), 0) &&
        rdx_gpt_write(descriptor, entries, sizeof(entries), 2 * RDX_GPT_SECTOR_BYTES) &&
        rdx_gpt_write(descriptor, primary, sizeof(primary), RDX_GPT_SECTOR_BYTES) &&
        rdx_gpt_write(descriptor, entries, sizeof(entries),
            backup_entries_lba * RDX_GPT_SECTOR_BYTES) &&
        rdx_gpt_write(descriptor, backup, sizeof(backup),
            last_lba * RDX_GPT_SECTOR_BYTES);
}

#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_test_validate_gpt_layout(int descriptor, uint64_t capacity,
    uint32_t signature, uint64_t volume_sectors) {
    uint64_t last_lba = capacity / RDX_GPT_SECTOR_BYTES - 1;
    uint64_t backup_entries_lba = last_lba - RDX_GPT_ENTRY_SECTORS;
    uint64_t last_usable = backup_entries_lba - 1;
    uint8_t mbr[RDX_GPT_SECTOR_BYTES] = {0};
    uint8_t primary[RDX_GPT_SECTOR_BYTES] = {0};
    uint8_t backup[RDX_GPT_SECTOR_BYTES] = {0};
    uint8_t entries[RDX_GPT_ENTRY_COUNT * RDX_GPT_ENTRY_BYTES] = {0};
    uint8_t backup_entries[RDX_GPT_ENTRY_COUNT * RDX_GPT_ENTRY_BYTES] = {0};
    if (!rdx_gpt_read(descriptor, mbr, sizeof(mbr), 0) ||
        !rdx_gpt_read(descriptor, primary, sizeof(primary), RDX_GPT_SECTOR_BYTES) ||
        !rdx_gpt_read(descriptor, entries, sizeof(entries), 2 * RDX_GPT_SECTOR_BYTES) ||
        !rdx_gpt_read(descriptor, backup_entries, sizeof(backup_entries),
            backup_entries_lba * RDX_GPT_SECTOR_BYTES) ||
        !rdx_gpt_read(descriptor, backup, sizeof(backup),
            last_lba * RDX_GPT_SECTOR_BYTES) || mbr[450] != UINT8_C(0xEE) ||
        rdx_gpt_load_u32(mbr + 440) != signature ||
        rdx_gpt_load_u32(mbr + 458) != UINT32_MAX ||
        memcmp(primary, "EFI PART", 8) != 0 || memcmp(backup, "EFI PART", 8) != 0 ||
        rdx_gpt_load_u64(primary + 24) != 1 ||
        rdx_gpt_load_u64(primary + 32) != last_lba ||
        rdx_gpt_load_u64(primary + 40) != RDX_GPT_PARTITION_START ||
        rdx_gpt_load_u64(primary + 48) != last_usable ||
        rdx_gpt_load_u64(backup + 24) != last_lba ||
        rdx_gpt_load_u64(backup + 72) != backup_entries_lba ||
        rdx_gpt_load_u64(entries + 32) != RDX_GPT_PARTITION_START ||
        rdx_gpt_load_u64(entries + 40) != last_usable ||
        memcmp(entries, backup_entries, sizeof(entries)) != 0 ||
        volume_sectors != last_usable - RDX_GPT_PARTITION_START + 1) {
        return false;
    }
    uint32_t primary_crc = rdx_gpt_load_u32(primary + 16);
    uint32_t backup_crc = rdx_gpt_load_u32(backup + 16);
    uint32_t entries_crc = rdx_gpt_crc32(entries, sizeof(entries));
    rdx_gpt_store_u32(primary + 16, 0);
    rdx_gpt_store_u32(backup + 16, 0);
    return primary_crc == rdx_gpt_crc32(primary, RDX_GPT_HEADER_BYTES) &&
        backup_crc == rdx_gpt_crc32(backup, RDX_GPT_HEADER_BYTES) &&
        entries_crc == rdx_gpt_load_u32(primary + 88) &&
        entries_crc == rdx_gpt_load_u32(backup + 88) &&
        memcmp(primary + 56, backup + 56, 16) == 0;
}
#endif

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    RDX_SECTOR_BYTES = 512,
    RDX_PARTITION_START = 2048,
    RDX_EXFAT_BOOT_SECTORS = 24,
    RDX_EXFAT_FAT_OFFSET = 128,
    RDX_EXFAT_SECTORS_PER_CLUSTER = 128,
    RDX_GPT_HEADER_MIN_BYTES = 92,
    RDX_GPT_MAX_ENTRY_COUNT = 128,
    RDX_GPT_ENTRY_BYTES = 128,
    RDX_GPT_MAX_ENTRY_BYTES = RDX_GPT_MAX_ENTRY_COUNT * RDX_GPT_ENTRY_BYTES
};

typedef struct rdx_erase_range {
    uint64_t offset;
    uint64_t length;
} rdx_erase_range;

typedef struct rdx_gpt_erase_plan {
    rdx_erase_range primary_entries;
    rdx_erase_range backup_entries;
    bool primary_entries_present;
    bool backup_entries_present;
} rdx_gpt_erase_plan;

#if defined(RDX_MACOS_TEST_HOOKS)
static uint32_t rdx_test_writes_before_failure = UINT32_MAX;
static bool rdx_test_force_cache_sync_failure = false;
#endif

static void rdx_store_u16(uint8_t *output, uint16_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void rdx_store_u32(uint8_t *output, uint32_t value) {
    for (uint32_t index = 0; index < 4; ++index) {
        output[index] = (uint8_t)(value >> (index * 8));
    }
}

static void rdx_store_u64(uint8_t *output, uint64_t value) {
    for (uint32_t index = 0; index < 8; ++index) {
        output[index] = (uint8_t)(value >> (index * 8));
    }
}

static uint32_t rdx_load_u32(const uint8_t *input) {
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
        ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static uint64_t rdx_load_u64(const uint8_t *input) {
    return (uint64_t)rdx_load_u32(input) |
        ((uint64_t)rdx_load_u32(input + 4) << 32);
}

static bool rdx_write_exact(int descriptor, const void *bytes, size_t length, uint64_t offset) {
#if defined(RDX_MACOS_TEST_HOOKS)
    if (rdx_test_writes_before_failure == 0) {
        return false;
    }
    if (rdx_test_writes_before_failure != UINT32_MAX) {
        --rdx_test_writes_before_failure;
    }
#endif
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

static bool rdx_read_exact(int descriptor, void *bytes, size_t length, uint64_t offset) {
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

static bool rdx_zero_range(int descriptor, uint64_t offset, uint64_t length) {
    uint8_t zeros[64 * 1024] = {0};
    while (length > 0) {
        size_t current = length < sizeof(zeros) ? (size_t)length : sizeof(zeros);
        if (!rdx_write_exact(descriptor, zeros, current, offset)) {
            return false;
        }
        offset += current;
        length -= current;
    }
    return true;
}

static uint32_t rdx_checksum_bytes(uint32_t checksum, const uint8_t *bytes, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        checksum = ((checksum << 31) | (checksum >> 1)) + bytes[index];
    }
    return checksum;
}

static uint32_t rdx_crc32(const uint8_t *bytes, size_t length) {
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

static bool rdx_checked_u64_multiply(uint64_t left, uint64_t right,
    uint64_t *output) {
    if (output == NULL || (left != 0 && right > UINT64_MAX / left)) {
        return false;
    }
    *output = left * right;
    return true;
}

static bool rdx_checked_u64_add(uint64_t left, uint64_t right,
    uint64_t *output) {
    if (output == NULL || right > UINT64_MAX - left) {
        return false;
    }
    *output = left + right;
    return true;
}

static bool rdx_gpt_entry_range(int descriptor, uint8_t *header,
    uint32_t block_size, uint64_t capacity, bool primary,
    rdx_erase_range *range, bool *present) {
    if (range == NULL || present == NULL) {
        return false;
    }
    *range = (rdx_erase_range){0};
    *present = memcmp(header, "EFI PART", 8) == 0;
    if (!*present) {
        return true;
    }
    uint32_t header_size = (uint32_t)header[12] |
        ((uint32_t)header[13] << 8) | ((uint32_t)header[14] << 16) |
        ((uint32_t)header[15] << 24);
    uint32_t stored_crc = (uint32_t)header[16] |
        ((uint32_t)header[17] << 8) | ((uint32_t)header[18] << 16) |
        ((uint32_t)header[19] << 24);
    if (header_size < RDX_GPT_HEADER_MIN_BYTES || header_size > block_size) {
        return false;
    }
    memset(&header[16], 0, 4);
    uint32_t observed_crc = rdx_crc32(header, header_size);
    rdx_store_u32(&header[16], stored_crc);
    uint64_t last_lba = capacity / block_size - 1;
    uint64_t current_lba = rdx_load_u64(header + 24);
    uint64_t alternate_lba = rdx_load_u64(header + 32);
    uint64_t first_usable = rdx_load_u64(header + 40);
    uint64_t last_usable = rdx_load_u64(header + 48);
    uint64_t entry_lba = rdx_load_u64(header + 72);
    uint32_t entry_count = rdx_load_u32(header + 80);
    uint32_t entry_size = rdx_load_u32(header + 84);
    uint32_t entries_crc = rdx_load_u32(header + 88);
    uint64_t entry_bytes = 0;
    uint64_t entry_span = 0;
    uint64_t entry_offset = 0;
    uint64_t entry_end = 0;
    uint64_t first_usable_offset = 0;
    uint64_t last_usable_offset = 0;
    uint64_t backup_header_offset = 0;
    if (rdx_load_u32(header + 8) != UINT32_C(0x00010000) ||
        observed_crc != stored_crc || header[20] != 0 ||
        header[21] != 0 || header[22] != 0 || header[23] != 0 ||
        current_lba != (primary ? 1 : last_lba) ||
        alternate_lba != (primary ? last_lba : 1) ||
        first_usable < 2 || first_usable > last_usable || last_usable >= last_lba ||
        entry_count == 0 || entry_count > RDX_GPT_MAX_ENTRY_COUNT ||
        entry_size < RDX_GPT_ENTRY_BYTES || entry_size % RDX_GPT_ENTRY_BYTES != 0 ||
        !rdx_checked_u64_multiply(entry_count, entry_size, &entry_bytes) ||
        entry_bytes > RDX_GPT_MAX_ENTRY_BYTES) {
        return false;
    }
    uint64_t rounded_entry_bytes = 0;
    if (!rdx_checked_u64_add(entry_bytes, block_size - 1,
            &rounded_entry_bytes)) {
        return false;
    }
    entry_span = rounded_entry_bytes / block_size;
    if (entry_span > UINT64_MAX / block_size) {
        return false;
    }
    entry_span *= block_size;
    if (entry_span > RDX_GPT_MAX_ENTRY_BYTES ||
        !rdx_checked_u64_multiply(entry_lba, block_size, &entry_offset) ||
        !rdx_checked_u64_add(entry_offset, entry_span, &entry_end) ||
        !rdx_checked_u64_multiply(first_usable, block_size,
            &first_usable_offset) ||
        !rdx_checked_u64_multiply(last_usable, block_size,
            &last_usable_offset) ||
        !rdx_checked_u64_multiply(last_lba, block_size,
            &backup_header_offset) ||
        entry_end > capacity ||
        (primary && (entry_lba < 2 || entry_end > first_usable_offset)) ||
        (!primary && (entry_offset <= last_usable_offset ||
            entry_end > backup_header_offset))) {
        return false;
    }
    uint8_t entries[RDX_GPT_MAX_ENTRY_BYTES] = {0};
    if (!rdx_read_exact(descriptor, entries, (size_t)entry_bytes, entry_offset) ||
        rdx_crc32(entries, (size_t)entry_bytes) != entries_crc) {
        return false;
    }
    range->offset = entry_offset;
    range->length = entry_span;
    return true;
}

static bool rdx_build_gpt_erase_plan(int descriptor, uint64_t capacity,
    uint32_t block_size, rdx_gpt_erase_plan *plan) {
    if (plan == NULL || block_size != RDX_SECTOR_BYTES ||
        capacity % block_size != 0 || capacity / block_size <= RDX_PARTITION_START) {
        return false;
    }
    uint8_t primary[RDX_SECTOR_BYTES] = {0};
    uint8_t backup[RDX_SECTOR_BYTES] = {0};
    uint64_t backup_offset = capacity - block_size;
    if (!rdx_read_exact(descriptor, primary, block_size, block_size) ||
        !rdx_read_exact(descriptor, backup, block_size, backup_offset)) {
        return false;
    }
    *plan = (rdx_gpt_erase_plan){0};
    return rdx_gpt_entry_range(descriptor, primary, block_size, capacity, true,
               &plan->primary_entries, &plan->primary_entries_present) &&
        rdx_gpt_entry_range(descriptor, backup, block_size, capacity, false,
            &plan->backup_entries, &plan->backup_entries_present);
}

static bool rdx_invalidate_stale_layout(int descriptor, uint64_t capacity,
    uint32_t block_size, const rdx_gpt_erase_plan *plan) {
    uint64_t canonical_backup = capacity - block_size - RDX_GPT_MAX_ENTRY_BYTES;
    return rdx_zero_range(descriptor, block_size, block_size) &&
        rdx_zero_range(descriptor, capacity - block_size, block_size) &&
        rdx_zero_range(descriptor, 0, block_size) &&
        rdx_zero_range(descriptor, 2 * block_size, RDX_GPT_MAX_ENTRY_BYTES) &&
        rdx_zero_range(descriptor, canonical_backup, RDX_GPT_MAX_ENTRY_BYTES) &&
        (!plan->primary_entries_present ||
            rdx_zero_range(descriptor, plan->primary_entries.offset,
                plan->primary_entries.length)) &&
        (!plan->backup_entries_present ||
            rdx_zero_range(descriptor, plan->backup_entries.offset,
                plan->backup_entries.length)) && fsync(descriptor) == 0;
}

static uint32_t rdx_boot_checksum(const uint8_t *region) {
    uint32_t checksum = 0;
    for (size_t index = 0; index < 11 * RDX_SECTOR_BYTES; ++index) {
        if (index != 106 && index != 107 && index != 112) {
            checksum = ((checksum << 31) | (checksum >> 1)) + region[index];
        }
    }
    return checksum;
}

static size_t rdx_build_upcase(uint8_t output[60]) {
    size_t offset = 0;
    rdx_store_u16(&output[offset], UINT16_C(0xFFFF));
    offset += 2;
    rdx_store_u16(&output[offset], UINT16_C(0x0061));
    offset += 2;
    for (uint16_t value = 'A'; value <= 'Z'; ++value) {
        rdx_store_u16(&output[offset], value);
        offset += 2;
    }
    rdx_store_u16(&output[offset], UINT16_C(0xFFFF));
    offset += 2;
    rdx_store_u16(&output[offset], UINT16_C(0xFF85));
    return offset + 2;
}

static bool rdx_write_mbr(int descriptor, uint32_t signature, uint32_t partition_sectors) {
    // A zero-filled replacement removes every old primary/extended partition
    // entry, so stale EBR chains elsewhere on the medium are no longer reachable.
    uint8_t sector[RDX_SECTOR_BYTES] = {0};
    rdx_store_u32(&sector[440], signature);
    sector[446] = UINT8_C(0x80);
    sector[450] = UINT8_C(0x07);
    rdx_store_u32(&sector[454], RDX_PARTITION_START);
    rdx_store_u32(&sector[458], partition_sectors);
    sector[510] = UINT8_C(0x55);
    sector[511] = UINT8_C(0xAA);
    return rdx_write_exact(descriptor, sector, sizeof(sector), 0);
}

static bool rdx_exfat_geometry(uint64_t volume_sectors, uint32_t *fat_length,
    uint32_t *heap_offset, uint32_t *cluster_count) {
    if (volume_sectors <= RDX_EXFAT_FAT_OFFSET + RDX_EXFAT_SECTORS_PER_CLUSTER) {
        return false;
    }
    uint64_t clusters = volume_sectors / RDX_EXFAT_SECTORS_PER_CLUSTER;
    uint64_t fat = ((clusters + 2) * 4 + RDX_SECTOR_BYTES - 1) / RDX_SECTOR_BYTES;
    uint64_t heap = RDX_EXFAT_FAT_OFFSET + fat;
    heap = (heap + RDX_EXFAT_SECTORS_PER_CLUSTER - 1) &
        ~(uint64_t)(RDX_EXFAT_SECTORS_PER_CLUSTER - 1);
    clusters = (volume_sectors - heap) / RDX_EXFAT_SECTORS_PER_CLUSTER;
    fat = ((clusters + 2) * 4 + RDX_SECTOR_BYTES - 1) / RDX_SECTOR_BYTES;
    heap = RDX_EXFAT_FAT_OFFSET + fat;
    heap = (heap + RDX_EXFAT_SECTORS_PER_CLUSTER - 1) &
        ~(uint64_t)(RDX_EXFAT_SECTORS_PER_CLUSTER - 1);
    clusters = (volume_sectors - heap) / RDX_EXFAT_SECTORS_PER_CLUSTER;
    if (fat == 0 || fat > UINT32_MAX || heap > UINT32_MAX ||
        clusters < 3 || clusters > UINT32_MAX - 2) {
        return false;
    }
    *fat_length = (uint32_t)fat;
    *heap_offset = (uint32_t)heap;
    *cluster_count = (uint32_t)clusters;
    return true;
}

static bool rdx_write_exfat_boot(int descriptor, uint64_t volume_sectors,
    uint32_t fat_length, uint32_t heap_offset, uint32_t cluster_count,
    uint32_t serial, uint32_t allocated_clusters) {
    uint8_t region[RDX_EXFAT_BOOT_SECTORS * RDX_SECTOR_BYTES] = {0};
    uint8_t *boot = region;
    boot[0] = UINT8_C(0xEB);
    boot[1] = UINT8_C(0x76);
    boot[2] = UINT8_C(0x90);
    memcpy(&boot[3], "EXFAT   ", 8);
    rdx_store_u64(&boot[64], RDX_PARTITION_START);
    rdx_store_u64(&boot[72], volume_sectors);
    rdx_store_u32(&boot[80], RDX_EXFAT_FAT_OFFSET);
    rdx_store_u32(&boot[84], fat_length);
    rdx_store_u32(&boot[88], heap_offset);
    rdx_store_u32(&boot[92], cluster_count);
    rdx_store_u32(&boot[96], 2);
    rdx_store_u32(&boot[100], serial);
    rdx_store_u16(&boot[104], UINT16_C(0x0100));
    boot[108] = 9;
    boot[109] = 7;
    boot[110] = 1;
    boot[111] = UINT8_C(0x80);
    boot[112] = (uint8_t)((uint64_t)allocated_clusters * 100 / cluster_count);
    for (size_t sector = 0; sector < 11; ++sector) {
        region[sector * RDX_SECTOR_BYTES + 510] = UINT8_C(0x55);
        region[sector * RDX_SECTOR_BYTES + 511] = UINT8_C(0xAA);
    }
    uint32_t checksum = rdx_boot_checksum(region);
    for (size_t offset = 11 * RDX_SECTOR_BYTES;
         offset < 12 * RDX_SECTOR_BYTES; offset += 4) {
        rdx_store_u32(&region[offset], checksum);
    }
    memcpy(&region[12 * RDX_SECTOR_BYTES], region, 12 * RDX_SECTOR_BYTES);
    return rdx_write_exact(descriptor, region, sizeof(region),
        (uint64_t)RDX_PARTITION_START * RDX_SECTOR_BYTES);
}

static bool rdx_write_fat_chain(int descriptor, uint64_t fat_offset,
    uint32_t first_cluster, uint32_t cluster_length) {
    for (uint32_t index = 0; index < cluster_length; ++index) {
        uint32_t next = index + 1 == cluster_length ? UINT32_C(0xFFFFFFFF) :
            first_cluster + index + 1;
        uint8_t value[4] = {0};
        rdx_store_u32(value, next);
        if (!rdx_write_exact(descriptor, value, sizeof(value),
                fat_offset + (uint64_t)(first_cluster + index) * 4)) {
            return false;
        }
    }
    return true;
}

static bool rdx_write_exfat_metadata(int descriptor, uint64_t partition_byte,
    uint32_t fat_length, uint32_t heap_offset, uint32_t cluster_count) {
    uint64_t cluster_bytes =
        (uint64_t)RDX_EXFAT_SECTORS_PER_CLUSTER * RDX_SECTOR_BYTES;
    uint64_t bitmap_bytes = ((uint64_t)cluster_count + 7) / 8;
    uint32_t bitmap_clusters = (uint32_t)((bitmap_bytes + cluster_bytes - 1) /
        cluster_bytes);
    uint32_t bitmap_cluster = 3;
    uint32_t upcase_cluster = bitmap_cluster + bitmap_clusters;
    uint32_t allocated_clusters = 2 + bitmap_clusters;
    if (upcase_cluster > cluster_count + 1) {
        return false;
    }
    uint64_t fat_byte = partition_byte +
        (uint64_t)RDX_EXFAT_FAT_OFFSET * RDX_SECTOR_BYTES;
    uint64_t heap_byte = partition_byte + (uint64_t)heap_offset * RDX_SECTOR_BYTES;
    if (!rdx_zero_range(descriptor, fat_byte,
            (uint64_t)fat_length * RDX_SECTOR_BYTES)) {
        return false;
    }
    uint8_t reserved_fat[8] = {
        UINT8_C(0xF8), UINT8_C(0xFF), UINT8_C(0xFF), UINT8_C(0xFF),
        UINT8_C(0xFF), UINT8_C(0xFF), UINT8_C(0xFF), UINT8_C(0xFF)
    };
    if (!rdx_write_exact(descriptor, reserved_fat, sizeof(reserved_fat), fat_byte) ||
        !rdx_write_fat_chain(descriptor, fat_byte, 2, 1) ||
        !rdx_write_fat_chain(descriptor, fat_byte, bitmap_cluster, bitmap_clusters) ||
        !rdx_write_fat_chain(descriptor, fat_byte, upcase_cluster, 1) ||
        !rdx_zero_range(descriptor, heap_byte,
            (uint64_t)allocated_clusters * cluster_bytes)) {
        return false;
    }
    uint8_t root[RDX_SECTOR_BYTES] = {0};
    root[0] = UINT8_C(0x81);
    rdx_store_u32(&root[20], bitmap_cluster);
    rdx_store_u64(&root[24], bitmap_bytes);
    uint8_t upcase[60] = {0};
    size_t upcase_bytes = rdx_build_upcase(upcase);
    root[32] = UINT8_C(0x82);
    rdx_store_u32(&root[36], rdx_checksum_bytes(0, upcase, upcase_bytes));
    rdx_store_u32(&root[52], upcase_cluster);
    rdx_store_u64(&root[56], upcase_bytes);
    root[64] = UINT8_C(0x83);
    root[65] = 7;
    const char label[] = "OPENRDX";
    for (size_t index = 0; index < sizeof(label) - 1; ++index) {
        rdx_store_u16(&root[66 + index * 2], (uint16_t)label[index]);
    }
    uint64_t root_byte = heap_byte;
    uint64_t bitmap_byte = heap_byte + (uint64_t)(bitmap_cluster - 2) * cluster_bytes;
    uint64_t upcase_byte = heap_byte + (uint64_t)(upcase_cluster - 2) * cluster_bytes;
    if (!rdx_write_exact(descriptor, root, sizeof(root), root_byte)) {
        return false;
    }
    uint8_t bitmap[RDX_SECTOR_BYTES] = {0};
    for (uint32_t index = 0; index < allocated_clusters; ++index) {
        bitmap[index / 8] |= (uint8_t)(1U << (index % 8));
    }
    return rdx_write_exact(descriptor, bitmap, sizeof(bitmap), bitmap_byte) &&
        rdx_write_exact(descriptor, upcase, upcase_bytes, upcase_byte);
}

static bool rdx_format_exfat_fd(int descriptor, uint64_t capacity,
    uint32_t block_size, uint32_t signature, bool *attempted) {
    struct stat identity = {0};
    if (attempted == NULL) {
        return false;
    }
    *attempted = false;
    if (descriptor < 0 || signature == 0 || block_size != RDX_SECTOR_BYTES ||
        capacity % block_size != 0 ||
        fstat(descriptor, &identity) != 0 ||
        (!S_ISCHR(identity.st_mode) && !S_ISREG(identity.st_mode))) {
        return false;
    }
    uint64_t total_sectors = capacity / RDX_SECTOR_BYTES;
    if (total_sectors <= RDX_PARTITION_START + 32768) {
        return false;
    }
    bool use_gpt = total_sectors - RDX_PARTITION_START > UINT32_MAX;
    uint64_t volume_sectors = use_gpt ?
        total_sectors - RDX_PARTITION_START - RDX_GPT_MAX_ENTRY_BYTES /
            RDX_SECTOR_BYTES - 1 :
        total_sectors - RDX_PARTITION_START;
    uint32_t fat_length = 0;
    uint32_t heap_offset = 0;
    uint32_t cluster_count = 0;
    if (!rdx_exfat_geometry(volume_sectors, &fat_length, &heap_offset, &cluster_count)) {
        return false;
    }
    uint64_t bitmap_bytes = ((uint64_t)cluster_count + 7) / 8;
    uint64_t cluster_bytes =
        (uint64_t)RDX_EXFAT_SECTORS_PER_CLUSTER * RDX_SECTOR_BYTES;
    uint32_t allocated_clusters = 2 + (uint32_t)((bitmap_bytes + cluster_bytes - 1) /
        cluster_bytes);
    rdx_gpt_erase_plan erase_plan = {0};
    if (!rdx_build_gpt_erase_plan(descriptor, capacity, block_size, &erase_plan)) {
        return false;
    }
    // The first zeroing dispatch may partially mutate the retained medium even
    // when its result reports failure, so all later failures are uncertain.
    *attempted = true;
    bool layout_written = false;
    bool written = rdx_invalidate_stale_layout(descriptor, capacity, block_size,
                       &erase_plan);
    if (written) {
        layout_written = use_gpt ?
            rdx_write_gpt_layout(descriptor, capacity, signature, &volume_sectors) :
            rdx_write_mbr(descriptor, signature, (uint32_t)volume_sectors);
    }
    written = written && layout_written &&
        rdx_write_exfat_boot(descriptor, volume_sectors, fat_length, heap_offset,
            cluster_count, signature, allocated_clusters) &&
        rdx_write_exfat_metadata(descriptor,
            (uint64_t)RDX_PARTITION_START * RDX_SECTOR_BYTES,
            fat_length, heap_offset, cluster_count) && fsync(descriptor) == 0;
    if (written && S_ISCHR(identity.st_mode) &&
        ioctl(descriptor, DKIOCSYNCHRONIZECACHE) != 0) {
        written = false;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (written && rdx_test_force_cache_sync_failure) {
        written = false;
    }
#endif
    return written;
}

rdx_macos_status rdx_macos_partition_and_format(rdx_macos_device *device,
    uint32_t filesystem, uint32_t mbr_signature,
    rdx_macos_host_operation_result **out_result) {
    if (out_result == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_result = NULL;
    rdx_macos_host_operation_result *result = rdx_allocate_result(
        sizeof(*result), RDX_MACOS_RESULT_HOST_OPERATION
    );
    if (result == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    rdx_macos_status status = rdx_revalidate_mapping(device);
    bool mounted = status == RDX_MACOS_STATUS_OK &&
        rdx_mapping_has_mounted_media(device);
    if (status != RDX_MACOS_STATUS_OK ||
        filesystem != RDX_MACOS_FILESYSTEM_EXFAT || mbr_signature == 0 ||
        device->whole_raw_fd < 0 || mounted) {
        if (status == RDX_MACOS_STATUS_OK) {
            status = mounted ? RDX_MACOS_STATUS_BUSY : RDX_MACOS_STATUS_INVALID_ARGUMENT;
        }
        result->header.status = status;
        *out_result = result;
        return status;
    }
    if (!rdx_upgrade_retained_whole_raw_for_write(device)) {
        result->header.status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        *out_result = result;
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    uint32_t block_size = 0;
    uint64_t block_count = 0;
    if (ioctl(device->whole_raw_fd, DKIOCGETBLOCKSIZE, &block_size) != 0 ||
        ioctl(device->whole_raw_fd, DKIOCGETBLOCKCOUNT, &block_count) != 0 ||
        block_size != RDX_SECTOR_BYTES || block_count > UINT64_MAX / block_size) {
        result->header.status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        *out_result = result;
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    bool attempted = false;
    bool completed = rdx_format_exfat_fd(device->whole_raw_fd,
        block_count * block_size, block_size, mbr_signature, &attempted) &&
        rdx_revalidate_mapping(device) == RDX_MACOS_STATUS_OK;
    result->attempted = attempted ? 1 : 0;
    if (completed) {
        result->completed = 1;
        status = RDX_MACOS_STATUS_OK;
        rdx_clear_mapping(device);
    } else {
        status = RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    result->header.status = status;
    *out_result = result;
    return status;
}

#if defined(RDX_MACOS_TEST_HOOKS)
enum {
    RDX_TEST_GPT_ENTRY_COUNT = 128,
    RDX_TEST_GPT_ENTRY_SIZE = 128,
    RDX_TEST_GPT_ENTRY_BYTES = RDX_TEST_GPT_ENTRY_COUNT * RDX_TEST_GPT_ENTRY_SIZE
};

static uint32_t rdx_test_load_u32(const uint8_t *input) {
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
        ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static uint64_t rdx_test_load_u64(const uint8_t *input) {
    return (uint64_t)rdx_test_load_u32(input) |
        ((uint64_t)rdx_test_load_u32(input + 4) << 32);
}

static bool rdx_test_read_exact(int descriptor, void *bytes, size_t length,
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

static bool rdx_test_bytes_are_zero(const uint8_t *bytes, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] != 0) {
            return false;
        }
    }
    return true;
}

static bool rdx_test_extended_boot_sectors_are_canonical(const uint8_t *boot) {
    for (size_t sector = 1; sector <= 10; ++sector) {
        const uint8_t *current = &boot[sector * RDX_SECTOR_BYTES];
        if (!rdx_test_bytes_are_zero(current, 510) ||
            current[510] != UINT8_C(0x55) || current[511] != UINT8_C(0xAA)) {
            return false;
        }
    }
    return true;
}

static uint32_t rdx_test_crc32(const uint8_t *bytes, size_t length) {
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

static bool rdx_test_seed_gpt(int descriptor, uint64_t capacity) {
    const uint64_t primary_entry_lba = 8;
    uint64_t last_lba = capacity / RDX_SECTOR_BYTES - 1;
    uint64_t backup_entry_lba = last_lba - 48;
    uint8_t entries[RDX_TEST_GPT_ENTRY_BYTES] = {0};
    const uint8_t basic_data_guid[16] = {
        UINT8_C(0xA2), UINT8_C(0xA0), UINT8_C(0xD0), UINT8_C(0xEB),
        UINT8_C(0xE5), UINT8_C(0xB9), UINT8_C(0x33), UINT8_C(0x44),
        UINT8_C(0x87), UINT8_C(0xC0), UINT8_C(0x68), UINT8_C(0xB6),
        UINT8_C(0xB7), UINT8_C(0x26), UINT8_C(0x99), UINT8_C(0xC7)
    };
    memcpy(entries, basic_data_guid, sizeof(basic_data_guid));
    memset(&entries[16], UINT8_C(0xB6), 16);
    rdx_store_u64(&entries[32], 40);
    rdx_store_u64(&entries[40], last_lba - 49);
    uint32_t entries_crc = rdx_test_crc32(entries, sizeof(entries));
    uint8_t primary[RDX_SECTOR_BYTES] = {0};
    uint8_t backup[RDX_SECTOR_BYTES] = {0};
    memcpy(primary, "EFI PART", 8);
    rdx_store_u32(&primary[8], UINT32_C(0x00010000));
    rdx_store_u32(&primary[12], 92);
    rdx_store_u64(&primary[24], 1);
    rdx_store_u64(&primary[32], last_lba);
    rdx_store_u64(&primary[40], 40);
    rdx_store_u64(&primary[48], last_lba - 49);
    memset(&primary[56], UINT8_C(0x3C), 16);
    rdx_store_u64(&primary[72], primary_entry_lba);
    rdx_store_u32(&primary[80], RDX_TEST_GPT_ENTRY_COUNT);
    rdx_store_u32(&primary[84], RDX_TEST_GPT_ENTRY_SIZE);
    rdx_store_u32(&primary[88], entries_crc);
    rdx_store_u32(&primary[16], rdx_test_crc32(primary, 92));
    memcpy(backup, primary, sizeof(backup));
    memset(&backup[16], 0, 4);
    rdx_store_u64(&backup[24], last_lba);
    rdx_store_u64(&backup[32], 1);
    rdx_store_u64(&backup[72], backup_entry_lba);
    rdx_store_u32(&backup[16], rdx_test_crc32(backup, 92));
    return rdx_write_exact(descriptor, entries, sizeof(entries),
               primary_entry_lba * RDX_SECTOR_BYTES) &&
        rdx_write_exact(descriptor, primary, sizeof(primary), RDX_SECTOR_BYTES) &&
        rdx_write_exact(descriptor, entries, sizeof(entries),
            backup_entry_lba * RDX_SECTOR_BYTES) &&
        rdx_write_exact(descriptor, backup, sizeof(backup),
            last_lba * RDX_SECTOR_BYTES) && fsync(descriptor) == 0;
}

static bool rdx_test_gpt_regions_are_zero(int descriptor, uint64_t capacity) {
    uint64_t last_lba = capacity / RDX_SECTOR_BYTES - 1;
    uint8_t header[RDX_SECTOR_BYTES] = {0};
    uint8_t entries[RDX_TEST_GPT_ENTRY_BYTES] = {0};
    return rdx_test_read_exact(descriptor, header, sizeof(header),
               RDX_SECTOR_BYTES) &&
        rdx_test_bytes_are_zero(header, sizeof(header)) &&
        rdx_test_read_exact(descriptor, header, sizeof(header),
            last_lba * RDX_SECTOR_BYTES) &&
        rdx_test_bytes_are_zero(header, sizeof(header)) &&
        rdx_test_read_exact(descriptor, entries, sizeof(entries),
            2 * RDX_SECTOR_BYTES) &&
        rdx_test_bytes_are_zero(entries, sizeof(entries)) &&
        rdx_test_read_exact(descriptor, entries, sizeof(entries),
            8 * RDX_SECTOR_BYTES) &&
        rdx_test_bytes_are_zero(entries, sizeof(entries)) &&
        rdx_test_read_exact(descriptor, entries, sizeof(entries),
            (last_lba - 32) * RDX_SECTOR_BYTES) &&
        rdx_test_bytes_are_zero(entries, sizeof(entries)) &&
        rdx_test_read_exact(descriptor, entries, sizeof(entries),
            (last_lba - 48) * RDX_SECTOR_BYTES) &&
        rdx_test_bytes_are_zero(entries, sizeof(entries));
}

static bool rdx_test_set_oversized_primary_entry_policy(int descriptor) {
    uint8_t header[RDX_SECTOR_BYTES] = {0};
    if (!rdx_test_read_exact(descriptor, header, sizeof(header),
            RDX_SECTOR_BYTES) || memcmp(header, "EFI PART", 8) != 0) {
        return false;
    }
    memset(&header[16], 0, 4);
    rdx_store_u32(&header[80], RDX_TEST_GPT_ENTRY_COUNT + 1);
    rdx_store_u32(&header[16], rdx_test_crc32(header, 92));
    return rdx_write_exact(descriptor, header, sizeof(header), RDX_SECTOR_BYTES) &&
        fsync(descriptor) == 0;
}

static bool rdx_test_primary_gpt_signature_is_present(int descriptor) {
    uint8_t signature[8] = {0};
    return rdx_test_read_exact(descriptor, signature, sizeof(signature),
               RDX_SECTOR_BYTES) &&
        memcmp(signature, "EFI PART", sizeof(signature)) == 0;
}

static bool rdx_test_validate_exfat(int descriptor, uint64_t capacity,
    uint32_t signature) {
    uint8_t mbr[RDX_SECTOR_BYTES] = {0};
    uint8_t boot[RDX_EXFAT_BOOT_SECTORS * RDX_SECTOR_BYTES] = {0};
    uint64_t partition_byte = (uint64_t)RDX_PARTITION_START * RDX_SECTOR_BYTES;
    uint32_t partition_sectors =
        (uint32_t)(capacity / RDX_SECTOR_BYTES - RDX_PARTITION_START);
    if (!rdx_test_read_exact(descriptor, mbr, sizeof(mbr), 0) ||
        !rdx_test_read_exact(descriptor, boot, sizeof(boot), partition_byte) ||
        rdx_test_load_u32(&mbr[440]) != signature || mbr[446] != UINT8_C(0x80) ||
        mbr[450] != UINT8_C(0x07) ||
        rdx_test_load_u32(&mbr[454]) != RDX_PARTITION_START ||
        rdx_test_load_u32(&mbr[458]) != partition_sectors ||
        mbr[510] != UINT8_C(0x55) || mbr[511] != UINT8_C(0xAA) ||
        boot[0] != UINT8_C(0xEB) || boot[1] != UINT8_C(0x76) ||
        boot[2] != UINT8_C(0x90) || memcmp(&boot[3], "EXFAT   ", 8) != 0 ||
        !rdx_test_bytes_are_zero(&boot[11], 53) ||
        !rdx_test_bytes_are_zero(&boot[113], 397) ||
        !rdx_test_extended_boot_sectors_are_canonical(boot) ||
        memcmp(boot, &boot[12 * RDX_SECTOR_BYTES], 12 * RDX_SECTOR_BYTES) != 0 ||
        rdx_test_load_u64(&boot[64]) != RDX_PARTITION_START ||
        rdx_test_load_u64(&boot[72]) != partition_sectors ||
        rdx_test_load_u32(&boot[80]) != RDX_EXFAT_FAT_OFFSET ||
        rdx_test_load_u32(&boot[96]) != 2 ||
        rdx_test_load_u32(&boot[100]) != signature ||
        boot[104] != 0 || boot[105] != 1 || boot[108] != 9 ||
        boot[109] != 7 || boot[110] != 1 || boot[111] != UINT8_C(0x80) ||
        boot[106] != 0 || boot[107] != 0 || boot[112] > 100 ||
        boot[510] != UINT8_C(0x55) || boot[511] != UINT8_C(0xAA)) {
        return false;
    }
    uint32_t boot_checksum = rdx_boot_checksum(boot);
    for (size_t offset = 11 * RDX_SECTOR_BYTES;
         offset < 12 * RDX_SECTOR_BYTES; offset += 4) {
        if (rdx_test_load_u32(&boot[offset]) != boot_checksum) {
            return false;
        }
    }
    uint32_t fat_length = rdx_test_load_u32(&boot[84]);
    uint32_t heap_offset = rdx_test_load_u32(&boot[88]);
    uint32_t cluster_count = rdx_test_load_u32(&boot[92]);
    uint64_t fat_entries_bytes = ((uint64_t)cluster_count + 2) * 4;
    uint64_t fat_capacity_bytes = (uint64_t)fat_length * RDX_SECTOR_BYTES;
    uint64_t heap_end = (uint64_t)heap_offset +
        (uint64_t)cluster_count * RDX_EXFAT_SECTORS_PER_CLUSTER;
    if (fat_length == 0 || heap_offset < RDX_EXFAT_FAT_OFFSET + fat_length ||
        heap_offset % RDX_EXFAT_SECTORS_PER_CLUSTER != 0 ||
        cluster_count < 3 || fat_entries_bytes > fat_capacity_bytes ||
        heap_end > partition_sectors ||
        partition_sectors - heap_end >= RDX_EXFAT_SECTORS_PER_CLUSTER) {
        return false;
    }
    uint64_t cluster_bytes =
        (uint64_t)RDX_EXFAT_SECTORS_PER_CLUSTER * RDX_SECTOR_BYTES;
    uint64_t bitmap_bytes = ((uint64_t)cluster_count + 7) / 8;
    uint32_t bitmap_clusters = (uint32_t)((bitmap_bytes + cluster_bytes - 1) /
        cluster_bytes);
    uint32_t upcase_cluster = 3 + bitmap_clusters;
    uint32_t allocated_clusters = 2 + bitmap_clusters;
    uint64_t fat_byte = partition_byte +
        (uint64_t)RDX_EXFAT_FAT_OFFSET * RDX_SECTOR_BYTES;
    uint64_t heap_byte = partition_byte + (uint64_t)heap_offset * RDX_SECTOR_BYTES;
    uint8_t fat[32] = {0};
    uint8_t root[96] = {0};
    uint8_t bitmap[RDX_SECTOR_BYTES] = {0};
    uint8_t upcase[60] = {0};
    uint8_t expected_upcase[60] = {0};
    size_t upcase_bytes = rdx_build_upcase(expected_upcase);
    if (!rdx_test_read_exact(descriptor, fat, sizeof(fat), fat_byte) ||
        !rdx_test_read_exact(descriptor, root, sizeof(root), heap_byte) ||
        !rdx_test_read_exact(descriptor, bitmap, sizeof(bitmap),
            heap_byte + cluster_bytes) ||
        !rdx_test_read_exact(descriptor, upcase, upcase_bytes,
            heap_byte + (uint64_t)(upcase_cluster - 2) * cluster_bytes) ||
        rdx_test_load_u32(&fat[0]) != UINT32_C(0xFFFFFFF8) ||
        rdx_test_load_u32(&fat[4]) != UINT32_C(0xFFFFFFFF) ||
        rdx_test_load_u32(&fat[8]) != UINT32_C(0xFFFFFFFF) ||
        root[0] != UINT8_C(0x81) || rdx_test_load_u32(&root[20]) != 3 ||
        rdx_test_load_u64(&root[24]) != bitmap_bytes ||
        root[32] != UINT8_C(0x82) ||
        rdx_test_load_u32(&root[36]) != rdx_checksum_bytes(0, upcase, upcase_bytes) ||
        rdx_test_load_u32(&root[52]) != upcase_cluster ||
        rdx_test_load_u64(&root[56]) != upcase_bytes ||
        root[64] != UINT8_C(0x83) || root[65] != 7 || root[80] != 0 ||
        memcmp(upcase, expected_upcase, upcase_bytes) != 0) {
        return false;
    }
    for (uint32_t index = 0; index < allocated_clusters; ++index) {
        if ((bitmap[index / 8] & (uint8_t)(1U << (index % 8))) == 0) {
            return false;
        }
    }
    for (uint32_t index = allocated_clusters;
         index < sizeof(bitmap) * 8; ++index) {
        if ((bitmap[index / 8] & (uint8_t)(1U << (index % 8))) != 0) {
            return false;
        }
    }
    const char label[] = "OPENRDX";
    for (size_t index = 0; index < sizeof(label) - 1; ++index) {
        if (root[66 + index * 2] != (uint8_t)label[index] ||
            root[67 + index * 2] != 0) {
            return false;
        }
    }
    return true;
}

bool rdx_macos_test_exfat_retained_fd_contract(void) {
    char path[] = "/tmp/openrdx-exfat-test-XXXXXX";
    int descriptor = mkstemp(path);
    (void)unlink(path);
    uint64_t capacity = UINT64_C(128) * 1024 * 1024;
    bool failed_attempted = false;
    bool seeded = descriptor >= 0 && ftruncate(descriptor, (off_t)capacity) == 0 &&
        rdx_test_seed_gpt(descriptor, capacity);
    bool wrong_block_attempted = true;
    bool wrong_block_rejected = seeded &&
        !rdx_format_exfat_fd(descriptor, capacity, 4096,
            UINT32_C(0x12345678), &wrong_block_attempted) &&
        !wrong_block_attempted && rdx_test_primary_gpt_signature_is_present(descriptor);
    bool policy_attempted = true;
    bool oversized_policy_rejected = wrong_block_rejected &&
        rdx_test_set_oversized_primary_entry_policy(descriptor) &&
        !rdx_format_exfat_fd(descriptor, capacity, RDX_SECTOR_BYTES,
            UINT32_C(0x12345678), &policy_attempted) && !policy_attempted &&
        rdx_test_primary_gpt_signature_is_present(descriptor) &&
        rdx_test_seed_gpt(descriptor, capacity);
    rdx_test_writes_before_failure = 1;
    bool failure_is_uncertain = oversized_policy_rejected &&
        !rdx_format_exfat_fd(descriptor, capacity, RDX_SECTOR_BYTES,
            UINT32_C(0x12345678), &failed_attempted) && failed_attempted;
    rdx_test_writes_before_failure = UINT32_MAX;
    bool attempted = false;
    bool passed = failure_is_uncertain && rdx_test_seed_gpt(descriptor, capacity) &&
        rdx_format_exfat_fd(descriptor, capacity, RDX_SECTOR_BYTES,
            UINT32_C(0x12345678), &attempted) && attempted;
    if (passed) {
        passed = rdx_test_validate_exfat(descriptor, capacity, UINT32_C(0x12345678)) &&
            rdx_test_gpt_regions_are_zero(descriptor, capacity);
    }
    if (passed) {
        uint8_t primary[3] = {0};
        uint8_t backup[3] = {0};
        uint64_t partition_byte =
            (uint64_t)RDX_PARTITION_START * RDX_SECTOR_BYTES;
        passed = rdx_test_read_exact(descriptor, primary, sizeof(primary),
                     partition_byte) &&
            rdx_test_read_exact(descriptor, backup, sizeof(backup),
                partition_byte + 12 * RDX_SECTOR_BYTES) &&
            primary[0] == UINT8_C(0xEB) && primary[1] == UINT8_C(0x76) &&
            primary[2] == UINT8_C(0x90) &&
            memcmp(primary, backup, sizeof(primary)) == 0;
    }
    bool cache_failure_attempted = false;
    rdx_test_force_cache_sync_failure = true;
    bool cache_failure_is_uncertain = passed &&
        !rdx_format_exfat_fd(descriptor, capacity, RDX_SECTOR_BYTES,
            UINT32_C(0x12345678), &cache_failure_attempted) &&
        cache_failure_attempted;
    rdx_test_force_cache_sync_failure = false;
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    char small_template[] = "/tmp/openrdx-exfat-small-XXXXXX";
    int small = mkstemp(small_template);
    if (small >= 0) {
        (void)unlink(small_template);
    }
    const uint64_t small_capacity = 4 * 1024 * 1024;
    uint8_t sentinel[RDX_SECTOR_BYTES] = {0};
    uint8_t observed[RDX_SECTOR_BYTES] = {0};
    memset(sentinel, UINT8_C(0x5A), sizeof(sentinel));
    bool small_attempted = true;
    bool small_rejected_without_write = small >= 0 &&
        ftruncate(small, (off_t)small_capacity) == 0 &&
        rdx_write_exact(small, sentinel, sizeof(sentinel), 0) && fsync(small) == 0 &&
        !rdx_format_exfat_fd(small, small_capacity, RDX_SECTOR_BYTES,
            UINT32_C(0x12345678), &small_attempted) && !small_attempted &&
        rdx_test_read_exact(small, observed, sizeof(observed), 0) &&
        memcmp(sentinel, observed, sizeof(sentinel)) == 0;
    if (small >= 0) {
        (void)close(small);
    }
    char large_template[] = "/tmp/openrdx-exfat-large-XXXXXX";
    int large = mkstemp(large_template);
    if (large >= 0) {
        (void)unlink(large_template);
    }
    const uint64_t large_sectors = (uint64_t)UINT32_MAX +
        RDX_PARTITION_START + 65536;
    const uint64_t large_capacity = large_sectors * RDX_SECTOR_BYTES;
    bool large_attempted = false;
    bool large_passed = large >= 0 &&
        ftruncate(large, (off_t)large_capacity) == 0 &&
        rdx_format_exfat_fd(large, large_capacity, RDX_SECTOR_BYTES,
            UINT32_C(0x87654321), &large_attempted) && large_attempted;
    uint64_t large_volume_sectors = large_sectors - RDX_PARTITION_START -
        RDX_GPT_MAX_ENTRY_BYTES / RDX_SECTOR_BYTES - 1;
    uint8_t large_boot[113] = {0};
    if (large_passed) {
        large_passed = rdx_test_validate_gpt_layout(large, large_capacity,
                           UINT32_C(0x87654321), large_volume_sectors) &&
            rdx_test_read_exact(large, large_boot, sizeof(large_boot),
                (uint64_t)RDX_PARTITION_START * RDX_SECTOR_BYTES) &&
            large_boot[0] == UINT8_C(0xEB) && large_boot[1] == UINT8_C(0x76) &&
            large_boot[2] == UINT8_C(0x90) &&
            rdx_test_load_u64(&large_boot[64]) == RDX_PARTITION_START &&
            rdx_test_load_u64(&large_boot[72]) == large_volume_sectors;
    }
    if (large >= 0) {
        (void)close(large);
    }
    return passed && cache_failure_is_uncertain &&
        small_rejected_without_write && large_passed;
}
#endif

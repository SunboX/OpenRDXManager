// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/* Private stable media and partition identity helpers. */
static bool rdx_uuid_text_is_valid(const char *uuid) {
    if (uuid == NULL || strlen(uuid) != 36) {
        return false;
    }
    for (size_t index = 0; index < 36; ++index) {
        bool hyphen = index == 8 || index == 13 || index == 18 || index == 23;
        char value = uuid[index];
        bool hexadecimal = (value >= '0' && value <= '9') ||
            (value >= 'a' && value <= 'f') ||
            (value >= 'A' && value <= 'F');
        if ((hyphen && value != '-') || (!hyphen && !hexadecimal)) {
            return false;
        }
    }
    return true;
}

static bool rdx_copy_bsd_name(
    DADiskRef disk,
    char output[RDX_MACOS_MAX_BSD_NAME_BYTES]
) {
    const char *name = disk == NULL ? NULL : DADiskGetBSDName(disk);
    if (name == NULL || strncmp(name, "disk", 4) != 0) {
        return false;
    }
    size_t length = strlen(name);
    if (length < 5 || length >= RDX_MACOS_MAX_BSD_NAME_BYTES) {
        return false;
    }
    for (size_t index = 4; index < length; ++index) {
        if (name[index] < '0' || name[index] > '9') {
            return false;
        }
    }
    memcpy(output, name, length + 1);
    return true;
}

static bool rdx_mapping_record_can_append(
    const rdx_macos_mapping_result *result,
    uint64_t entry_id,
    uint64_t whole_id,
    const char *uuid
) {
    if (result == NULL || entry_id == 0 || whole_id == 0 ||
        result->whole_registry_entry_id != whole_id ||
        result->media_count >= RDX_MACOS_MAX_MEDIA ||
        !rdx_uuid_text_is_valid(uuid)) {
        return false;
    }
    for (uint64_t index = 0; index < result->media_count; ++index) {
        if (result->media[index].registry_entry_id == entry_id ||
            strcmp(result->media[index].uuid, uuid) == 0) {
            return false;
        }
    }
    return true;
}

static bool rdx_format_uuid(CFTypeRef value, char output[RDX_MACOS_UUID_BYTES]) {
    if (value == NULL) {
        return false;
    }
    if (CFGetTypeID(value) == CFUUIDGetTypeID()) {
        CFUUIDBytes bytes = CFUUIDGetUUIDBytes((CFUUIDRef)value);
        int count = snprintf(
            output,
            RDX_MACOS_UUID_BYTES,
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            bytes.byte0,
            bytes.byte1,
            bytes.byte2,
            bytes.byte3,
            bytes.byte4,
            bytes.byte5,
            bytes.byte6,
            bytes.byte7,
            bytes.byte8,
            bytes.byte9,
            bytes.byte10,
            bytes.byte11,
            bytes.byte12,
            bytes.byte13,
            bytes.byte14,
            bytes.byte15
        );
        return count == 36 && rdx_uuid_text_is_valid(output);
    }
    return CFGetTypeID(value) == CFStringGetTypeID() &&
        CFStringGetCString(
            (CFStringRef)value,
            output,
            RDX_MACOS_UUID_BYTES,
            kCFStringEncodingASCII
        ) &&
        rdx_uuid_text_is_valid(output);
}

bool rdx_format_media_identity(
    uint64_t registry_entry_id,
    uint64_t whole_registry_entry_id,
    char output[RDX_MACOS_UUID_BYTES]
) {
    if (registry_entry_id == 0 || whole_registry_entry_id == 0 || output == NULL) {
        return false;
    }
    int count = snprintf(
        output,
        RDX_MACOS_UUID_BYTES,
        "%08X-%04X-%04X-%04X-%012llX",
        (uint32_t)(whole_registry_entry_id >> 32),
        (uint16_t)(whole_registry_entry_id >> 16),
        (uint16_t)whole_registry_entry_id,
        (uint16_t)(registry_entry_id >> 48),
        (unsigned long long)(registry_entry_id & UINT64_C(0x0000FFFFFFFFFFFF))
    );
    return count == 36 && rdx_uuid_text_is_valid(output);
}

static bool rdx_resolve_media_identity(
    bool stable_identity_present,
    const char stable_identity[RDX_MACOS_UUID_BYTES],
    uint64_t registry_entry_id,
    uint64_t whole_registry_entry_id,
    char output[RDX_MACOS_UUID_BYTES]
) {
    if (output == NULL) {
        return false;
    }
    if (stable_identity_present) {
        if (!rdx_uuid_text_is_valid(stable_identity)) {
            return false;
        }
        memcpy(output, stable_identity, RDX_MACOS_UUID_BYTES);
        return true;
    }
    return rdx_format_media_identity(
        registry_entry_id,
        whole_registry_entry_id,
        output
    );
}

static bool rdx_format_partition_identity(
    const uint8_t mbr[512],
    const uint8_t boot_sector[512],
    uint64_t offset_bytes,
    uint64_t size_bytes,
    char output[RDX_MACOS_UUID_BYTES]
) {
    if (mbr == NULL || boot_sector == NULL || output == NULL ||
        mbr[510] != 0x55 || mbr[511] != 0xAA ||
        offset_bytes == 0 || size_bytes == 0 || offset_bytes % 512 != 0 ||
        size_bytes % 512 != 0) {
        return false;
    }
    uint32_t signature = (uint32_t)mbr[440] |
        ((uint32_t)mbr[441] << 8) |
        ((uint32_t)mbr[442] << 16) |
        ((uint32_t)mbr[443] << 24);
    uint64_t offset_blocks = offset_bytes / 512;
    uint64_t size_blocks = size_bytes / 512;
    if (offset_blocks > UINT64_C(0x0000FFFFFFFFFFFF) ||
        size_blocks > UINT64_C(0x0000FFFFFFFFFFFF)) {
        return false;
    }
    if (signature == 0 || signature == UINT32_MAX) {
        if (boot_sector[510] != 0x55 || boot_sector[511] != 0xAA ||
            memcmp(&boot_sector[3], "NTFS    ", 8) != 0) {
            return false;
        }
        uint64_t volume_serial = 0;
        for (size_t index = 0; index < 8; ++index) {
            volume_serial |= ((uint64_t)boot_sector[72 + index]) << (index * 8);
        }
        if (volume_serial == 0 || volume_serial == UINT64_MAX) {
            return false;
        }
        uint16_t offset_tag = (uint16_t)(
            offset_blocks ^ (offset_blocks >> 16) ^ (offset_blocks >> 32)
        );
        int count = snprintf(
            output,
            RDX_MACOS_UUID_BYTES,
            "%08X-%04X-%04X-%04X-%012llX",
            (uint32_t)(volume_serial >> 32),
            (uint16_t)(volume_serial >> 16),
            (uint16_t)volume_serial,
            offset_tag,
            (unsigned long long)size_blocks
        );
        return count == 36 && rdx_uuid_text_is_valid(output);
    }
    int count = snprintf(
        output,
        RDX_MACOS_UUID_BYTES,
        "%08X-%04X-%04X-%04X-%012llX",
        signature,
        (uint16_t)(offset_blocks >> 32),
        (uint16_t)(offset_blocks >> 16),
        (uint16_t)offset_blocks,
        (unsigned long long)size_blocks
    );
    return count == 36 && rdx_uuid_text_is_valid(output);
}

static bool rdx_copy_partition_identity(
    DADiskRef disk,
    int whole_raw_fd,
    char output[RDX_MACOS_UUID_BYTES]
) {
    io_service_t media = DADiskCopyIOMedia(disk);
    if (media == IO_OBJECT_NULL) {
        return false;
    }
    rdx_track_io_acquire();
    uint64_t offset = 0;
    uint64_t size = 0;
    uint8_t mbr[512] = {0};
    uint8_t boot_sector[512] = {0};
    bool has_fd = whole_raw_fd >= 0;
    bool has_offset = rdx_copy_u64_property(media, CFSTR("Base"), &offset);
    bool has_size = rdx_copy_u64_property(media, CFSTR(kIOMediaSizeKey), &size);
    bool read_mbr = has_fd &&
        pread(whole_raw_fd, mbr, sizeof(mbr), 0) == (ssize_t)sizeof(mbr);
    bool read_boot = has_offset && offset <= INT64_MAX &&
        pread(whole_raw_fd, boot_sector, sizeof(boot_sector), (off_t)offset) ==
            (ssize_t)sizeof(boot_sector);
    bool formatted = read_mbr && read_boot &&
        rdx_format_partition_identity(
            mbr, boot_sector, offset, size, output
        );
    bool valid = has_fd && has_offset && has_size && read_mbr && formatted;
    rdx_release_io(media);
    return valid;
}

static bool rdx_copy_disk_uuid(
    DADiskRef disk,
    int whole_raw_fd,
    uint64_t registry_entry_id,
    uint64_t whole_registry_entry_id,
    char output[RDX_MACOS_UUID_BYTES]
) {
    CFDictionaryRef description = DADiskCopyDescription(disk);
    if (description == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    CFTypeRef value = CFDictionaryGetValue(
        description,
        kDADiskDescriptionMediaUUIDKey
    );
    if (value == NULL) {
        value = CFDictionaryGetValue(
            description,
            kDADiskDescriptionVolumeUUIDKey
        );
    }
    char stable_identity[RDX_MACOS_UUID_BYTES] = {0};
    bool stable_identity_present = value == NULL ?
        rdx_copy_partition_identity(disk, whole_raw_fd, stable_identity) :
        rdx_format_uuid(value, stable_identity);
    bool valid = rdx_resolve_media_identity(
        stable_identity_present,
        stable_identity,
        registry_entry_id,
        whole_registry_entry_id,
        output
    );
    rdx_release_cf(description);
    return valid;
}


// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/* Private deterministic disk-mapping regression tests. */
#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_macos_test_disk_mapping_contract(void) {
    const char *first = "01234567-89AB-CDEF-0123-456789ABCDEF";
    const char *second = "FEDCBA98-7654-3210-FEDC-BA9876543210";
    char fallback[RDX_MACOS_UUID_BYTES] = {0};
    char other_fallback[RDX_MACOS_UUID_BYTES] = {0};
    if (!rdx_format_media_identity(42, 41, fallback) ||
        !rdx_format_media_identity(43, 41, other_fallback) ||
        strcmp(fallback, other_fallback) == 0 ||
        !rdx_uuid_text_is_valid(fallback)) {
        return false;
    }
    char selected_fallback[RDX_MACOS_UUID_BYTES] = {0};
    if (!rdx_resolve_media_identity(
            false,
            "",
            42,
            41,
            selected_fallback
        ) || strcmp(selected_fallback, fallback) != 0) {
        return false;
    }
    uint8_t mbr[512] = {0};
    mbr[440] = 0xB0;
    mbr[441] = 0xEA;
    mbr[442] = 0x42;
    mbr[443] = 0x25;
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    uint8_t ntfs_boot[512] = {0};
    memcpy(&ntfs_boot[3], "NTFS    ", 8);
    ntfs_boot[72] = 0x88;
    ntfs_boot[73] = 0x77;
    ntfs_boot[74] = 0x66;
    ntfs_boot[75] = 0x55;
    ntfs_boot[76] = 0x44;
    ntfs_boot[77] = 0x33;
    ntfs_boot[78] = 0x22;
    ntfs_boot[79] = 0x11;
    ntfs_boot[510] = 0x55;
    ntfs_boot[511] = 0xAA;
    char stable[RDX_MACOS_UUID_BYTES] = {0};
    char same_stable[RDX_MACOS_UUID_BYTES] = {0};
    char other_partition[RDX_MACOS_UUID_BYTES] = {0};
    char ntfs_stable[RDX_MACOS_UUID_BYTES] = {0};
    char other_ntfs_volume[RDX_MACOS_UUID_BYTES] = {0};
    if (!rdx_format_partition_identity(mbr, ntfs_boot, 1048576, 320067338240, stable) ||
        !rdx_format_partition_identity(mbr, ntfs_boot, 1048576, 320067338240, same_stable) ||
        !rdx_format_partition_identity(mbr, ntfs_boot, 2097152, 320067338240, other_partition) ||
        strcmp(stable, same_stable) != 0 ||
        strcmp(stable, other_partition) == 0 ||
        !rdx_uuid_text_is_valid(stable)) {
        return false;
    }
    mbr[440] = 0;
    mbr[441] = 0;
    mbr[442] = 0;
    mbr[443] = 0;
    if (!rdx_format_partition_identity(mbr, ntfs_boot, 1048576, 320067338240, ntfs_stable)) {
        return false;
    }
    ntfs_boot[72] ^= 0x01;
    if (!rdx_format_partition_identity(
            mbr, ntfs_boot, 1048576, 320067338240, other_ntfs_volume
        ) || strcmp(ntfs_stable, other_ntfs_volume) == 0) {
        return false;
    }
    rdx_macos_mapping_result result = {0};
    result.whole_registry_entry_id = 41;
    if (!rdx_mapping_record_can_append(&result, 42, 41, first)) {
        return false;
    }
    result.media[0].registry_entry_id = 42;
    result.media[0].whole_registry_entry_id = 41;
    memcpy(result.media[0].uuid, first, RDX_MACOS_UUID_BYTES);
    result.media_count = 1;
    if (rdx_mapping_record_can_append(&result, 42, 41, second) ||
        rdx_mapping_record_can_append(&result, 43, 41, first) ||
        rdx_mapping_record_can_append(&result, 43, 99, second) ||
        rdx_mapping_record_can_append(&result, 43, 41, "not-a-uuid")) {
        return false;
    }
    result.media_count = RDX_MACOS_MAX_MEDIA;
    return !rdx_mapping_record_can_append(&result, 43, 41, second);
}

/* Exercises physical whole-disk selection against a real disposable APFS image,
 * whose synthesized IOMedia must not be mistaken for a second physical disk. */
bool rdx_macos_test_whole_disk_mapping(const char *bsd) {
    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    DADiskRef disk = session ? DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsd) : NULL;
    io_service_t whole = disk ? DADiskCopyIOMedia(disk) : IO_OBJECT_NULL;
    io_service_t parent = IO_OBJECT_NULL;
    uint64_t expected_id = 0;
    uint64_t parent_id = 0;
    bool valid = whole != IO_OBJECT_NULL && rdx_registry_id(whole, &expected_id) &&
        IORegistryEntryGetParentEntry(whole, kIOServicePlane, &parent) == kIOReturnSuccess &&
        rdx_registry_id(parent, &parent_id);
    if (valid) {
        rdx_macos_device device = {0};
        device.service = parent;
        device.expected.registry_entry_id = parent_id;
        io_service_t found = IO_OBJECT_NULL;
        uint64_t found_id = 0;
        valid = rdx_find_whole_media(&device, &found, &found_id) == RDX_MACOS_STATUS_OK && found_id == expected_id;
        rdx_release_io(found);
    }
    if (parent != IO_OBJECT_NULL) IOObjectRelease(parent);
    if (whole != IO_OBJECT_NULL) IOObjectRelease(whole);
    if (disk) CFRelease(disk);
    if (session) CFRelease(session);
    return valid;
}
#endif

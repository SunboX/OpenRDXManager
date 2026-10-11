// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/* Private mounted-volume facts and APFS-aware binding helpers. */
static bool rdx_copy_mounted_volume_facts(
    DADiskRef disk,
    rdx_macos_mapping_result *result
) {
    if (disk == NULL || result == NULL || result->mounted_media_count != 0) {
        return false;
    }
    CFDictionaryRef description = DADiskCopyDescription(disk);
    if (description == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    CFTypeRef value = CFDictionaryGetValue(
        description,
        kDADiskDescriptionVolumePathKey
    );
    CFTypeRef kind = CFDictionaryGetValue(
        description, kDADiskDescriptionVolumeKindKey
    );
    bool valid = value != NULL && CFGetTypeID(value) == CFURLGetTypeID() &&
        CFURLGetFileSystemRepresentation(
            (CFURLRef)value,
            true,
            (UInt8 *)result->mounted_path,
            RDX_MACOS_MAX_MOUNT_PATH_BYTES
        );
    struct statfs facts = {0};
    struct stat identity = {0};
    if (valid && statfs(result->mounted_path, &facts) == 0 &&
        stat(result->mounted_path, &identity) == 0 && identity.st_dev != 0 &&
        facts.f_bsize > 0 && facts.f_bavail <= UINT64_MAX / (uint64_t)facts.f_bsize) {
        result->free_bytes = (uint64_t)facts.f_bavail * (uint64_t)facts.f_bsize;
        result->mounted_device_id = (uint64_t)identity.st_dev;
        result->mounted_filesystem = RDX_MACOS_VOLUME_FILESYSTEM_UNKNOWN;
        if (kind != NULL && CFGetTypeID(kind) == CFStringGetTypeID()) {
            if (CFStringCompare(
                    (CFStringRef)kind,
                    CFSTR("exfat"),
                    kCFCompareCaseInsensitive
                ) == kCFCompareEqualTo) {
                result->mounted_filesystem = RDX_MACOS_VOLUME_FILESYSTEM_EXFAT;
            } else if (CFStringCompare(
                           (CFStringRef)kind,
                           CFSTR("ntfs"),
                           kCFCompareCaseInsensitive
                       ) == kCFCompareEqualTo) {
                result->mounted_filesystem = RDX_MACOS_VOLUME_FILESYSTEM_NTFS;
            } else if (CFStringCompare((CFStringRef)kind, CFSTR("msdos"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                result->mounted_filesystem = 3;
            } else if (CFStringCompare((CFStringRef)kind, CFSTR("hfs"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                result->mounted_filesystem = 7;
            } else if (CFStringCompare((CFStringRef)kind, CFSTR("apfs"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                result->mounted_filesystem = 11;
            }
        }
    } else {
        valid = false;
    }
    if (!valid) {
        memset(result->mounted_path, 0, sizeof(result->mounted_path));
        result->free_bytes = 0;
        result->mounted_device_id = 0;
        result->mounted_filesystem = RDX_MACOS_VOLUME_FILESYSTEM_UNKNOWN;
    }
    rdx_release_cf(description);
    return valid;
}

static bool rdx_disk_binding_matches(
    DADiskRef disk,
    uint64_t expected_media_id,
    uint64_t expected_whole_id,
    bool expected_whole
) {
    if (disk == NULL || expected_media_id == 0 || expected_whole_id == 0) {
        return false;
    }
    io_service_t media = DADiskCopyIOMedia(disk);
    if (media == IO_OBJECT_NULL) {
        return false;
    }
    rdx_track_io_acquire();
    DADiskRef whole = DADiskCopyWholeDisk(disk);
    if (whole == NULL) {
        rdx_release_io(media);
        return false;
    }
    rdx_track_cf_acquire();
    io_service_t whole_media = DADiskCopyIOMedia(whole);
    if (whole_media == IO_OBJECT_NULL) {
        rdx_release_cf(whole);
        rdx_release_io(media);
        return false;
    }
    rdx_track_io_acquire();
    uint64_t media_id = 0;
    uint64_t whole_id = 0;
    bool matches = rdx_registry_id(media, &media_id) &&
        rdx_registry_id(whole_media, &whole_id) &&
        media_id == expected_media_id &&
        (whole_id == expected_whole_id || (!expected_whole && rdx_apfs_volume_matches(disk, expected_whole_id))) &&
        rdx_disk_is_whole(disk, expected_whole) &&
        rdx_disk_is_whole(whole, true);
    rdx_release_io(whole_media);
    rdx_release_cf(whole);
    rdx_release_io(media);
    return matches;
}


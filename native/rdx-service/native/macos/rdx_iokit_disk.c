// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

static bool rdx_copy_boolean_property(
    io_service_t service,
    CFStringRef key,
    bool *output
) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service,
        key,
        kCFAllocatorDefault,
        0
    );
    if (property == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    bool valid = CFGetTypeID(property) == CFBooleanGetTypeID();
    if (valid) {
        *output = CFBooleanGetValue((CFBooleanRef)property);
    }
    rdx_release_cf(property);
    return valid;
}

static bool rdx_copy_u64_property(
    io_service_t service,
    CFStringRef key,
    uint64_t *output
) {
    if (service == IO_OBJECT_NULL || output == NULL) {
        return false;
    }
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service,
        key,
        kCFAllocatorDefault,
        0
    );
    if (property == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    int64_t number = 0;
    bool valid = CFGetTypeID(property) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)property, kCFNumberSInt64Type, &number) &&
        number > 0;
    if (valid) {
        *output = (uint64_t)number;
    }
    rdx_release_cf(property);
    return valid;
}

static bool rdx_registry_id(io_service_t service, uint64_t *output) {
    return service != IO_OBJECT_NULL && output != NULL &&
        IORegistryEntryGetRegistryEntryID(service, output) == kIOReturnSuccess &&
        *output != 0;
}

static bool rdx_is_descendant_of(io_service_t child, uint64_t ancestor_id) {
    io_registry_entry_t current = child;
    if (current == IO_OBJECT_NULL || IOObjectRetain(current) != kIOReturnSuccess) {
        return false;
    }
    rdx_track_io_acquire();
    bool found = false;
    for (uint32_t depth = 0; depth < 64; ++depth) {
        uint64_t current_id = 0;
        if (rdx_registry_id(current, &current_id) && current_id == ancestor_id) {
            found = true;
            break;
        }
        io_registry_entry_t parent = IO_OBJECT_NULL;
        if (IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent) !=
                kIOReturnSuccess ||
            parent == IO_OBJECT_NULL) {
            break;
        }
        rdx_track_io_acquire();
        rdx_release_io(current);
        current = parent;
    }
    rdx_release_io(current);
    return found;
}

#include "rdx_iokit_disk_identity.inc"

static bool rdx_disk_is_whole(DADiskRef disk, bool expected) {
    CFDictionaryRef description = DADiskCopyDescription(disk);
    if (description == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    CFTypeRef value = CFDictionaryGetValue(
        description,
        kDADiskDescriptionMediaWholeKey
    );
    bool valid = value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID() &&
        CFBooleanGetValue((CFBooleanRef)value) == expected;
    rdx_release_cf(description);
    return valid;
}

static bool rdx_copy_disk_mounted(DADiskRef disk, bool *output) {
    if (disk == NULL || output == NULL) {
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
    bool valid = value == NULL || CFGetTypeID(value) == CFURLGetTypeID();
    if (valid) {
        *output = value != NULL;
    }
    rdx_release_cf(description);
    return valid;
}

static bool rdx_copy_whole_media_facts(
    DADiskRef disk,
    rdx_macos_mapping_result *result
) {
    if (disk == NULL || result == NULL) {
        return false;
    }
    CFDictionaryRef description = DADiskCopyDescription(disk);
    if (description == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    CFTypeRef size = CFDictionaryGetValue(
        description,
        kDADiskDescriptionMediaSizeKey
    );
    CFTypeRef writable = CFDictionaryGetValue(
        description,
        kDADiskDescriptionMediaWritableKey
    );
    int64_t capacity = 0;
    bool valid = size != NULL && CFGetTypeID(size) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)size, kCFNumberSInt64Type, &capacity) &&
        capacity > 0 && writable != NULL &&
        CFGetTypeID(writable) == CFBooleanGetTypeID();
    if (valid) {
        result->capacity_bytes = (uint64_t)capacity;
        result->writable = CFBooleanGetValue((CFBooleanRef)writable) ? 1 : 0;
    }
    rdx_release_cf(description);
    return valid;
}

#include "rdx_iokit_disk_volume.inc"

static rdx_macos_status rdx_create_media_iterator(
    rdx_macos_device *device,
    io_iterator_t *out_iterator
) {
    *out_iterator = IO_OBJECT_NULL;
    IOReturn status = IORegistryEntryCreateIterator(
        device->service,
        kIOServicePlane,
        kIORegistryIterateRecursively,
        out_iterator
    );
    if (status != kIOReturnSuccess || *out_iterator == IO_OBJECT_NULL) {
        return rdx_status_from_io(status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    rdx_track_io_acquire();
    return RDX_MACOS_STATUS_OK;
}

static rdx_macos_status rdx_find_whole_media(
    rdx_macos_device *device,
    io_service_t *out_media,
    uint64_t *out_id
) {
    io_iterator_t iterator = IO_OBJECT_NULL;
    io_service_t entry = IO_OBJECT_NULL;
    rdx_macos_status status = rdx_create_media_iterator(device, &iterator);
    if (status != RDX_MACOS_STATUS_OK) {
        return status;
    }
    while ((entry = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        rdx_track_io_acquire();
        bool whole = false;
        if (IOObjectConformsTo(entry, kIOMediaClass) &&
            !IOObjectConformsTo(entry, "AppleAPFSMedia") &&
            rdx_copy_boolean_property(entry, CFSTR(kIOMediaWholeKey), &whole) &&
            whole) {
            uint64_t entry_id = 0;
            if (!rdx_registry_id(entry, &entry_id) ||
                !rdx_is_descendant_of(entry, device->expected.registry_entry_id)) {
                status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
                goto cleanup;
            }
            if (*out_media != IO_OBJECT_NULL) {
                status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
                goto cleanup;
            }
            *out_media = entry;
            *out_id = entry_id;
            entry = IO_OBJECT_NULL;
        }
        rdx_release_io(entry);
    }
    status = RDX_MACOS_STATUS_OK;

cleanup:
    rdx_release_io(entry);
    rdx_release_io(iterator);
    return status;
}

static rdx_macos_status rdx_add_media_records(
    rdx_macos_device *device,
    DASessionRef session,
    int whole_raw_fd,
    uint64_t whole_id,
    rdx_macos_mapping_result *result,
    DADiskRef disks[RDX_MACOS_MAX_MEDIA],
    io_service_t services[RDX_MACOS_MAX_MEDIA],
    bool mounted[RDX_MACOS_MAX_MEDIA]
) {
    io_iterator_t iterator = IO_OBJECT_NULL;
    io_service_t entry = IO_OBJECT_NULL;
    DADiskRef disk = NULL;
    DADiskRef whole = NULL;
    io_service_t copied_whole = IO_OBJECT_NULL;
    rdx_macos_status status = rdx_create_media_iterator(device, &iterator);
    if (status != RDX_MACOS_STATUS_OK) {
        return status;
    }
    while ((entry = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        rdx_track_io_acquire();
        bool is_whole = false;
        if (!IOObjectConformsTo(entry, kIOMediaClass) ||
            !rdx_copy_boolean_property(entry, CFSTR(kIOMediaWholeKey), &is_whole) ||
            is_whole) {
            rdx_release_io(entry);
            continue;
        }
        if (!rdx_is_descendant_of(entry, device->expected.registry_entry_id)) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        if (rdx_media_has_system_apfs_role(entry)) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        disk = DADiskCreateFromIOMedia(kCFAllocatorDefault, session, entry);
        if (disk == NULL) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        rdx_track_cf_acquire();
        whole = DADiskCopyWholeDisk(disk);
        if (whole == NULL) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        rdx_track_cf_acquire();
        copied_whole = DADiskCopyIOMedia(whole);
        if (copied_whole == IO_OBJECT_NULL) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        rdx_track_io_acquire();
        uint64_t copied_whole_id = 0;
        uint64_t entry_id = 0;
        bool is_mounted = false;
        char uuid[RDX_MACOS_UUID_BYTES] = {0};
        if (!rdx_registry_id(copied_whole, &copied_whole_id) ||
            !rdx_registry_id(entry, &entry_id) ||
            (copied_whole_id != whole_id && !rdx_apfs_volume_matches(disk, whole_id)) ||
            !rdx_disk_is_whole(whole, true) || rdx_disk_is_whole(disk, true) ||
            !rdx_copy_disk_uuid(
                disk,
                whole_raw_fd,
                entry_id,
                whole_id,
                uuid
            ) ||
            !rdx_copy_disk_mounted(disk, &is_mounted)) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        if (result->media_count == RDX_MACOS_MAX_MEDIA) {
            status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
            goto cleanup;
        }
        if (!rdx_mapping_record_can_append(
                result,
                entry_id,
                whole_id,
                uuid
            )) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        uint64_t index = result->media_count;
        result->media[index].registry_entry_id = entry_id;
        result->media[index].whole_registry_entry_id = whole_id;
        memcpy(result->media[index].uuid, uuid, RDX_MACOS_UUID_BYTES);
        disks[index] = disk;
        services[index] = entry;
        mounted[index] = is_mounted;
        if (is_mounted) {
            if (!rdx_copy_mounted_volume_facts(disk, result)) {
                status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
                goto cleanup;
            }
            result->mounted_media_count += 1;
        }
        result->media_count += 1;
        disk = NULL;
        rdx_release_io(copied_whole);
        copied_whole = IO_OBJECT_NULL;
        rdx_release_cf(whole);
        whole = NULL;
    }
    status = RDX_MACOS_STATUS_OK;

cleanup:
    rdx_release_io(copied_whole);
    rdx_release_cf(whole);
    rdx_release_cf(disk);
    rdx_release_io(entry);
    rdx_release_io(iterator);
    return status;
}

void rdx_clear_mapping(rdx_macos_device *device) {
    if (device == NULL) {
        return;
    }
    if (device->whole_raw_fd >= 0) {
        (void)close(device->whole_raw_fd);
        device->whole_raw_fd = -1;
    }
    if (device->whole_claimed && device->whole_disk != NULL) {
        DADiskUnclaim(device->whole_disk);
        device->whole_claimed = false;
    }
    rdx_da_registry *registry = device->da_registry;
    device->da_registry = NULL;
    rdx_da_registry_shutdown(registry, device->session);
    for (uint32_t index = 0; index < device->media_count; ++index) {
        rdx_release_io(device->media_services[index]);
        rdx_release_cf(device->media_disks[index]);
        device->media_services[index] = IO_OBJECT_NULL;
        device->media_disks[index] = NULL;
        device->media_registry_entry_ids[index] = 0;
        memset(device->media_uuids[index], 0, RDX_MACOS_UUID_BYTES);
        device->media_mounted[index] = false;
    }
    device->media_count = 0;
    rdx_release_io(device->whole_media);
    rdx_release_cf(device->whole_disk);
    rdx_release_cf(device->session);
    device->whole_media = IO_OBJECT_NULL;
    device->whole_disk = NULL;
    device->session = NULL;
    device->whole_registry_entry_id = 0;
    memset(device->whole_media_uuid, 0, sizeof(device->whole_media_uuid));
    device->whole_capacity_bytes = 0;
    device->whole_bsd_major = 0;
    device->whole_bsd_minor = 0;
    device->whole_media_uuid_present = false;
    device->whole_media_is_whole = false;
    device->whole_media_ejectable = false;
    device->whole_media_removable = false;
    memset(device->whole_bsd_name, 0, sizeof(device->whole_bsd_name));
    device->whole_mounted = false;
    device->whole_claimed = false;
    device->mapping_pinned = false;
}

void rdx_macos_invalidate_media_mapping(rdx_macos_device *device) {
    /* USB BOT release resets and rematches the storage stack. Discard objects
     * retained by the current Disk Arbitration generation before that reset;
     * stable candidate identity remains owned by `device`. */
    rdx_clear_mapping(device);
}

rdx_macos_status rdx_macos_media_present_without_mapping(
    rdx_macos_device *device,
    uint8_t *out_present
) {
    if (out_present == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_present = 0;
    if (device == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    /* This readback is intentionally incompatible with retained DA or raw-disk
     * authority. Safe Eject must not recreate the references whose lifetime can
     * prevent the storage stack from completing a mechanical eject. */
    if (device->mapping_pinned || device->whole_raw_fd >= 0) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    rdx_macos_status status = rdx_revalidate_device(device);
    if (status != RDX_MACOS_STATUS_OK) {
        return status;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        *out_present = device->whole_registry_entry_id == 0 ? 0 : 1;
        return RDX_MACOS_STATUS_OK;
    }
#endif
    io_service_t observed_whole = IO_OBJECT_NULL;
    uint64_t observed_id = 0;
    status = rdx_find_whole_media(device, &observed_whole, &observed_id);
    if (status != RDX_MACOS_STATUS_OK) {
        rdx_release_io(observed_whole);
        return status;
    }
    if ((observed_whole == IO_OBJECT_NULL) != (observed_id == 0)) {
        rdx_release_io(observed_whole);
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    *out_present = observed_whole == IO_OBJECT_NULL ? 0 : 1;
    rdx_release_io(observed_whole);
    return RDX_MACOS_STATUS_OK;
}

rdx_macos_status rdx_revalidate_mapping(rdx_macos_device *device) {
    if (device == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        rdx_test_record_event(device, RDX_TEST_EVENT_REVALIDATE_MAPPING);
        if (!device->mapping_pinned) {
            return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        }
        return device->test_revalidate_status;
    }
#endif
    rdx_macos_status status = rdx_revalidate_device(device);
    if (status != RDX_MACOS_STATUS_OK || !device->mapping_pinned) {
        return status == RDX_MACOS_STATUS_OK ?
            RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE : status;
    }
    if (device->whole_media == IO_OBJECT_NULL) {
        io_service_t observed_whole = IO_OBJECT_NULL;
        uint64_t observed_id = 0;
        status = rdx_find_whole_media(device, &observed_whole, &observed_id);
        rdx_release_io(observed_whole);
        if (status != RDX_MACOS_STATUS_OK) {
            return status;
        }
        return observed_id == 0 ?
            RDX_MACOS_STATUS_OK : RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    if (device->session == NULL || device->da_registry == NULL ||
        device->whole_disk == NULL || device->whole_media == IO_OBJECT_NULL ||
        device->whole_registry_entry_id == 0 ||
        !rdx_raw_fd_matches_disk(device->whole_raw_fd, device->whole_disk) ||
        !rdx_fresh_whole_media_matches(device, device->whole_raw_fd)) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    uint64_t observed_whole_id = 0;
    if (!rdx_registry_id(device->whole_media, &observed_whole_id) ||
        observed_whole_id != device->whole_registry_entry_id ||
        !rdx_is_descendant_of(
            device->whole_media,
            device->expected.registry_entry_id
        ) ||
        !rdx_disk_binding_matches(
            device->whole_disk,
            observed_whole_id,
            observed_whole_id,
            true
        )) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    bool mounted = false;
    if (!rdx_copy_disk_mounted(device->whole_disk, &mounted) ||
        mounted != device->whole_mounted) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    for (uint32_t index = 0; index < device->media_count; ++index) {
        uint64_t media_id = 0;
        char uuid[RDX_MACOS_UUID_BYTES] = {0};
        if (!rdx_registry_id(device->media_services[index], &media_id) ||
            media_id != device->media_registry_entry_ids[index] ||
            !rdx_disk_binding_matches(
                device->media_disks[index],
                media_id,
                observed_whole_id,
                false
            ) ||
            !rdx_is_descendant_of(
                device->media_services[index],
                device->expected.registry_entry_id
            ) ||
            !rdx_copy_disk_uuid(
                device->media_disks[index],
                device->whole_raw_fd,
                media_id,
                observed_whole_id,
                uuid
            ) ||
            strcmp(uuid, device->media_uuids[index]) != 0 ||
            !rdx_copy_disk_mounted(device->media_disks[index], &mounted) ||
            mounted != device->media_mounted[index]) {
            return RDX_MACOS_STATUS_DEVICE_REMOVED;
        }
    }
    return RDX_MACOS_STATUS_OK;
}

rdx_macos_status rdx_macos_revalidate_media(rdx_macos_device *device) {
    return rdx_revalidate_mapping(device);
}

rdx_macos_status rdx_macos_confirm_unmounted_mapping(rdx_macos_device *device) {
    if (device == NULL || !device->mapping_pinned) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    if (rdx_mapping_has_mounted_media(device)) {
        return RDX_MACOS_STATUS_BUSY;
    }
    device->whole_mounted = false;
    for (uint32_t index = 0; index < device->media_count; ++index) {
        device->media_mounted[index] = false;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake &&
        device->test_revalidate_status == RDX_MACOS_STATUS_DEVICE_REMOVED) {
        device->test_revalidate_status = RDX_MACOS_STATUS_OK;
    }
#endif
    return rdx_revalidate_mapping(device);
}

bool rdx_macos_validate_mounted_fd(rdx_macos_device *device, int descriptor,
    uint64_t expected_device_id) {
    return rdx_validate_mounted_fd(device, descriptor, expected_device_id);
}

bool rdx_mapping_has_mounted_media(rdx_macos_device *device) {
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device != NULL && device->test_fake) {
        rdx_test_record_event(device, RDX_TEST_EVENT_CHECK_MOUNTED);
        return device->test_mounted;
    }
#endif
    if (device == NULL || !device->mapping_pinned) {
        return true;
    }
    if (device->whole_disk == NULL) {
        return false;
    }
    bool mounted = false;
    if (!rdx_copy_disk_mounted(device->whole_disk, &mounted)) {
        return true;
    }
    if (mounted) {
        return true;
    }
    for (uint32_t index = 0; index < device->media_count; ++index) {
        if (!rdx_copy_disk_mounted(device->media_disks[index], &mounted) ||
            mounted) {
            return true;
        }
    }
    return false;
}

rdx_macos_status rdx_macos_map_media(
    rdx_macos_device *device,
    rdx_macos_mapping_result **out_result
) {
    if (out_result == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_result = NULL;
    if (device == NULL || device->mapping_pinned) {
        if (device == NULL) {
            return RDX_MACOS_STATUS_INVALID_ARGUMENT;
        }
    }
    rdx_macos_mapping_result *result = rdx_allocate_result(
        sizeof(*result),
        RDX_MACOS_RESULT_MAPPING
    );
    if (result == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    if (device->mapping_pinned) {
        rdx_macos_status snapshot_status = rdx_revalidate_mapping(device);
        if (snapshot_status == RDX_MACOS_STATUS_OK && device->whole_disk != NULL) {
            result->whole_registry_entry_id = device->whole_registry_entry_id;
            if (!rdx_copy_whole_media_facts(device->whole_disk, result)) {
                snapshot_status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            }
        }
        for (uint32_t index = 0;
             snapshot_status == RDX_MACOS_STATUS_OK && index < device->media_count;
             ++index) {
            result->media[index].registry_entry_id =
                device->media_registry_entry_ids[index];
            result->media[index].whole_registry_entry_id =
                device->whole_registry_entry_id;
            memcpy(
                result->media[index].uuid,
                device->media_uuids[index],
                RDX_MACOS_UUID_BYTES
            );
            if (device->media_mounted[index]) {
                if (!rdx_copy_mounted_volume_facts(device->media_disks[index], result)) {
                    snapshot_status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
                    break;
                }
                result->mounted_media_count += 1;
            }
            result->media_count += 1;
        }
        if (snapshot_status == RDX_MACOS_STATUS_OK && device->whole_mounted) {
            if (!rdx_copy_mounted_volume_facts(device->whole_disk, result)) {
                snapshot_status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            } else {
                result->mounted_media_count += 1;
            }
        }
        result->header.status = snapshot_status;
        *out_result = result;
        return snapshot_status;
    }
    rdx_macos_status status = rdx_revalidate_device(device);
    DASessionRef session = NULL;
    rdx_da_registry *registry = NULL;
    DADiskRef whole_disk = NULL;
    io_service_t whole_media = IO_OBJECT_NULL;
    DADiskRef media_disks[RDX_MACOS_MAX_MEDIA] = {0};
    io_service_t media_services[RDX_MACOS_MAX_MEDIA] = {0};
    bool media_mounted[RDX_MACOS_MAX_MEDIA] = {0};
    int whole_raw_fd = -1;
    if (status != RDX_MACOS_STATUS_OK) {
        goto cleanup;
    }
    status = rdx_find_whole_media(
        device,
        &whole_media,
        &result->whole_registry_entry_id
    );
    if (status != RDX_MACOS_STATUS_OK || whole_media == IO_OBJECT_NULL) {
        if (status == RDX_MACOS_STATUS_OK) {
            device->mapping_pinned = true;
            result->header.status = RDX_MACOS_STATUS_OK;
            *out_result = result;
            return RDX_MACOS_STATUS_OK;
        }
        goto cleanup;
    }
    session = rdx_da_session_create();
    if (session == NULL) {
        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        goto cleanup;
    }
    rdx_track_cf_acquire();
    registry = rdx_da_registry_create();
    if (registry == NULL) {
        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        goto cleanup;
    }
    whole_disk = DADiskCreateFromIOMedia(kCFAllocatorDefault, session, whole_media);
    if (whole_disk == NULL) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    rdx_track_cf_acquire();
    if (!rdx_disk_is_whole(whole_disk, true)) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    char whole_bsd_name[RDX_MACOS_MAX_BSD_NAME_BYTES] = {0};
    if (!rdx_copy_bsd_name(whole_disk, whole_bsd_name)) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    if (!rdx_copy_whole_media_facts(whole_disk, result)) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    char whole_media_uuid[RDX_MACOS_UUID_BYTES] = {0};
    bool whole_media_uuid_present = false;
    uint32_t whole_bsd_major = 0;
    uint32_t whole_bsd_minor = 0;
    uint64_t whole_capacity_bytes = 0;
    bool whole_media_is_whole = false;
    bool whole_media_ejectable = false;
    bool whole_media_removable = false;
    if (!rdx_copy_whole_media_authority(whole_media, whole_media_uuid,
            &whole_media_uuid_present, &whole_bsd_major, &whole_bsd_minor,
            &whole_capacity_bytes, &whole_media_is_whole,
            &whole_media_ejectable, &whole_media_removable) ||
        whole_capacity_bytes != result->capacity_bytes ||
        !whole_media_is_whole || !whole_media_ejectable ||
        !whole_media_removable) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    rdx_macos_device raw_authority = {
        .expected = device->expected,
        .session = session,
        .whole_disk = whole_disk,
        .whole_media = whole_media,
        .whole_registry_entry_id = result->whole_registry_entry_id,
        .whole_capacity_bytes = whole_capacity_bytes,
        .whole_bsd_major = whole_bsd_major,
        .whole_bsd_minor = whole_bsd_minor,
        .whole_media_uuid_present = whole_media_uuid_present,
        .whole_media_is_whole = whole_media_is_whole,
        .whole_media_ejectable = whole_media_ejectable,
        .whole_media_removable = whole_media_removable,
        .whole_raw_fd = -1
    };
    memcpy(
        raw_authority.whole_media_uuid,
        whole_media_uuid,
        RDX_MACOS_UUID_BYTES
    );
    whole_raw_fd = rdx_open_retained_whole_raw(
        &raw_authority, whole_bsd_name, result->capacity_bytes, false
    );
    if (whole_raw_fd < 0) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    bool whole_mounted = false;
    if (!rdx_copy_disk_mounted(whole_disk, &whole_mounted)) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    if (whole_mounted) {
        if (!rdx_copy_mounted_volume_facts(whole_disk, result)) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            goto cleanup;
        }
        result->mounted_media_count += 1;
    }
    status = rdx_add_media_records(
        device,
        session,
        whole_raw_fd,
        result->whole_registry_entry_id,
        result,
        media_disks,
        media_services,
        media_mounted
    );
    if (status != RDX_MACOS_STATUS_OK ||
        rdx_revalidate_device(device) != RDX_MACOS_STATUS_OK) {
        if (status == RDX_MACOS_STATUS_OK) {
            status = RDX_MACOS_STATUS_DEVICE_REMOVED;
        }
        goto cleanup;
    }
    DASessionSetDispatchQueue(session, rdx_da_registry_queue(registry));
    device->session = session;
    device->da_registry = registry;
    device->whole_disk = whole_disk;
    device->whole_media = whole_media;
    device->whole_registry_entry_id = result->whole_registry_entry_id;
    memcpy(device->whole_media_uuid, whole_media_uuid, RDX_MACOS_UUID_BYTES);
    device->whole_capacity_bytes = whole_capacity_bytes;
    device->whole_bsd_major = whole_bsd_major;
    device->whole_bsd_minor = whole_bsd_minor;
    device->whole_media_uuid_present = whole_media_uuid_present;
    device->whole_media_is_whole = whole_media_is_whole;
    device->whole_media_ejectable = whole_media_ejectable;
    device->whole_media_removable = whole_media_removable;
    device->whole_raw_fd = whole_raw_fd;
    memcpy(
        device->whole_bsd_name,
        whole_bsd_name,
        RDX_MACOS_MAX_BSD_NAME_BYTES
    );
    device->whole_mounted = whole_mounted;
    device->mapping_pinned = true;
    device->media_count = (uint32_t)result->media_count;
    session = NULL;
    registry = NULL;
    whole_disk = NULL;
    whole_media = IO_OBJECT_NULL;
    for (uint32_t index = 0; index < device->media_count; ++index) {
        device->media_disks[index] = media_disks[index];
        device->media_services[index] = media_services[index];
        device->media_registry_entry_ids[index] =
            result->media[index].registry_entry_id;
        memcpy(
            device->media_uuids[index],
            result->media[index].uuid,
            RDX_MACOS_UUID_BYTES
        );
        device->media_mounted[index] = media_mounted[index];
        media_disks[index] = NULL;
        media_services[index] = IO_OBJECT_NULL;
    }
    result->header.status = RDX_MACOS_STATUS_OK;
    *out_result = result;
    return RDX_MACOS_STATUS_OK;

cleanup:
    if (whole_raw_fd >= 0) {
        (void)close(whole_raw_fd);
    }
    for (uint32_t index = 0; index < RDX_MACOS_MAX_MEDIA; ++index) {
        rdx_release_io(media_services[index]);
        rdx_release_cf(media_disks[index]);
    }
    rdx_release_cf(whole_disk);
    rdx_release_io(whole_media);
    rdx_da_registry_shutdown(registry, NULL);
    rdx_release_cf(session);
    result->header.status = status;
    *out_result = result;
    return status;
}
#include "rdx_iokit_disk_test.inc"

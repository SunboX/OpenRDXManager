// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static bool rdx_raw_fd_matches_capacity(int descriptor, uint64_t capacity) {
    uint32_t block_size = 0;
    uint64_t block_count = 0;
    struct stat identity = {0};
    return descriptor >= 0 && capacity > 0 && fstat(descriptor, &identity) == 0 &&
        S_ISCHR(identity.st_mode) && ioctl(descriptor, DKIOCGETBLOCKSIZE, &block_size) == 0 &&
        ioctl(descriptor, DKIOCGETBLOCKCOUNT, &block_count) == 0 && block_size > 0 &&
        block_count <= UINT64_MAX / block_size && block_count * block_size == capacity;
}

bool rdx_descriptor_is_writable(int descriptor) {
    int flags = descriptor < 0 ? -1 : fcntl(descriptor, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == O_RDWR;
}

static int rdx_raw_open_flags(bool require_writable) {
    return (require_writable ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW;
}

int rdx_open_retained_whole_raw(
    rdx_macos_device *device,
    const char *bsd_name,
    uint64_t capacity,
    bool require_writable
) {
    char raw_path[RDX_MACOS_MAX_BSD_NAME_BYTES + 7] = {0};
    int count = snprintf(raw_path, sizeof(raw_path), "/dev/r%s", bsd_name);
    if (count <= 0 || (size_t)count >= sizeof(raw_path)) {
        return -1;
    }
    if (!rdx_fresh_whole_media_matches(device, device->whole_raw_fd)) {
        return -1;
    }
    int descriptor = open(raw_path, rdx_raw_open_flags(require_writable));
    if (!rdx_raw_fd_matches_capacity(descriptor, capacity)) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return -1;
    }
    int previous = device->whole_raw_fd;
    device->whole_raw_fd = descriptor;
    bool exact = rdx_fresh_whole_media_matches(device, descriptor);
    device->whole_raw_fd = previous;
    if (!exact) {
        (void)close(descriptor);
        return -1;
    }
    return descriptor;
}

bool rdx_upgrade_retained_whole_raw_for_write(rdx_macos_device *device) {
    if (device == NULL || device->whole_raw_fd < 0) {
        return false;
    }
    if (rdx_descriptor_is_writable(device->whole_raw_fd)) {
        return true;
    }
    int descriptor = rdx_open_retained_whole_raw(
        device,
        device->whole_bsd_name,
        device->whole_capacity_bytes,
        true
    );
    if (descriptor < 0) {
        return false;
    }
    int previous = device->whole_raw_fd;
    device->whole_raw_fd = descriptor;
    (void)close(previous);
    return true;
}

bool rdx_raw_fd_matches_disk(int descriptor, DADiskRef disk) {
    if (disk == NULL) {
        return false;
    }
    CFDictionaryRef description = DADiskCopyDescription(disk);
    if (description == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    CFTypeRef size = CFDictionaryGetValue(description, kDADiskDescriptionMediaSizeKey);
    int64_t capacity = 0;
    bool valid = size != NULL && CFGetTypeID(size) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)size, kCFNumberSInt64Type, &capacity) &&
        capacity > 0 && rdx_raw_fd_matches_capacity(descriptor, (uint64_t)capacity);
    rdx_release_cf(description);
    return valid;
}

static bool rdx_authority_registry_id(io_service_t service, uint64_t *output) {
    return service != IO_OBJECT_NULL && output != NULL &&
        IORegistryEntryGetRegistryEntryID(service, output) == kIOReturnSuccess &&
        *output != 0;
}

static bool rdx_authority_uuid_valid(const char *uuid) {
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

static bool rdx_authority_format_uuid(
    CFTypeRef value,
    char output[RDX_MACOS_UUID_BYTES]
) {
    if (value == NULL) {
        return false;
    }
    if (CFGetTypeID(value) == CFUUIDGetTypeID()) {
        CFUUIDBytes bytes = CFUUIDGetUUIDBytes((CFUUIDRef)value);
        CFUUIDRef copy = CFUUIDCreateFromUUIDBytes(kCFAllocatorDefault, bytes);
        if (copy == NULL) {
            return false;
        }
        rdx_track_cf_acquire();
        CFStringRef text = CFUUIDCreateString(kCFAllocatorDefault, copy);
        if (text != NULL) {
            rdx_track_cf_acquire();
        }
        bool valid = text != NULL && CFStringGetCString(
            text, output, RDX_MACOS_UUID_BYTES, kCFStringEncodingASCII
        ) && rdx_authority_uuid_valid(output);
        rdx_release_cf(text);
        rdx_release_cf(copy);
        return valid;
    }
    return CFGetTypeID(value) == CFStringGetTypeID() &&
        CFStringGetCString((CFStringRef)value, output,
            RDX_MACOS_UUID_BYTES, kCFStringEncodingASCII) &&
        rdx_authority_uuid_valid(output);
}

static bool rdx_authority_number(
    io_service_t service,
    CFStringRef key,
    uint32_t *output
) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0
    );
    if (value == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    int64_t number = -1;
    bool valid = CFGetTypeID(value) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &number) &&
        number >= 0 && number <= UINT32_MAX;
    if (valid) {
        *output = (uint32_t)number;
    }
    rdx_release_cf(value);
    return valid;
}

static bool rdx_authority_number_u64(
    io_service_t service,
    CFStringRef key,
    uint64_t *output
) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0
    );
    if (value == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    int64_t number = 0;
    bool valid = CFGetTypeID(value) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)value, kCFNumberSInt64Type, &number) &&
        number > 0;
    if (valid) {
        *output = (uint64_t)number;
    }
    rdx_release_cf(value);
    return valid;
}

static bool rdx_authority_boolean(
    io_service_t service,
    CFStringRef key,
    bool *output
) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0
    );
    if (value == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    bool valid = CFGetTypeID(value) == CFBooleanGetTypeID();
    if (valid) {
        *output = CFBooleanGetValue((CFBooleanRef)value);
    }
    rdx_release_cf(value);
    return valid;
}

static bool rdx_authority_whole(io_service_t service) {
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        service, CFSTR(kIOMediaWholeKey), kCFAllocatorDefault, 0
    );
    if (value == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    bool whole = CFGetTypeID(value) == CFBooleanGetTypeID() &&
        CFBooleanGetValue((CFBooleanRef)value);
    rdx_release_cf(value);
    return whole;
}

static bool rdx_partition_authority_matches(
    uint64_t expected_registry_entry_id,
    const char *expected_identity,
    uint64_t observed_registry_entry_id,
    const char *observed_uuid,
    bool observed_uuid_present
) {
    if (expected_registry_entry_id == 0 ||
        observed_registry_entry_id != expected_registry_entry_id ||
        !rdx_authority_uuid_valid(expected_identity)) {
        return false;
    }
    return !observed_uuid_present ||
        (rdx_authority_uuid_valid(observed_uuid) &&
            strcmp(observed_uuid, expected_identity) == 0);
}

bool rdx_copy_media_authority(io_service_t media,
    char uuid[RDX_MACOS_UUID_BYTES], bool *uuid_present,
    uint32_t *bsd_major, uint32_t *bsd_minor) {
    if (media == IO_OBJECT_NULL || uuid == NULL || uuid_present == NULL ||
        bsd_major == NULL || bsd_minor == NULL) {
        return false;
    }
    memset(uuid, 0, RDX_MACOS_UUID_BYTES);
    *uuid_present = false;
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        media, CFSTR(kIOMediaUUIDKey), kCFAllocatorDefault, 0
    );
    if (value != NULL) {
        rdx_track_cf_acquire();
        bool valid = rdx_authority_format_uuid(value, uuid);
        rdx_release_cf(value);
        if (!valid) {
            return false;
        }
        *uuid_present = true;
    }
    return rdx_authority_number(media, CFSTR(kIOBSDMajorKey), bsd_major) &&
        rdx_authority_number(media, CFSTR(kIOBSDMinorKey), bsd_minor);
}

bool rdx_copy_whole_media_authority(io_service_t media,
    char uuid[RDX_MACOS_UUID_BYTES], bool *uuid_present,
    uint32_t *bsd_major, uint32_t *bsd_minor, uint64_t *capacity_bytes,
    bool *whole, bool *ejectable, bool *removable) {
    if (media == IO_OBJECT_NULL || uuid == NULL || uuid_present == NULL ||
        bsd_major == NULL || bsd_minor == NULL || capacity_bytes == NULL ||
        whole == NULL || ejectable == NULL || removable == NULL) {
        return false;
    }
    memset(uuid, 0, RDX_MACOS_UUID_BYTES);
    *uuid_present = false;
    CFTypeRef value = IORegistryEntryCreateCFProperty(
        media, CFSTR(kIOMediaUUIDKey), kCFAllocatorDefault, 0
    );
    if (value != NULL) {
        rdx_track_cf_acquire();
        bool valid = rdx_authority_format_uuid(value, uuid);
        rdx_release_cf(value);
        if (!valid) {
            return false;
        }
        *uuid_present = true;
    }
    return rdx_authority_number(media, CFSTR(kIOBSDMajorKey), bsd_major) &&
        rdx_authority_number(media, CFSTR(kIOBSDMinorKey), bsd_minor) &&
        rdx_authority_number_u64(media, CFSTR(kIOMediaSizeKey), capacity_bytes) &&
        rdx_authority_boolean(media, CFSTR(kIOMediaWholeKey), whole) &&
        rdx_authority_boolean(media, CFSTR(kIOMediaEjectableKey), ejectable) &&
        rdx_authority_boolean(media, CFSTR(kIOMediaRemovableKey), removable);
}

static bool rdx_authority_descendant(io_service_t child, uint64_t ancestor_id) {
    io_registry_entry_t current = child;
    if (current == IO_OBJECT_NULL || IOObjectRetain(current) != kIOReturnSuccess) {
        return false;
    }
    rdx_track_io_acquire();
    bool found = false;
    for (uint32_t depth = 0; depth < 64; ++depth) {
        uint64_t current_id = 0;
        if (rdx_authority_registry_id(current, &current_id) &&
            current_id == ancestor_id) {
            found = true;
            break;
        }
        io_registry_entry_t parent = IO_OBJECT_NULL;
        if (IORegistryEntryGetParentEntry(current, kIOServicePlane, &parent) !=
                kIOReturnSuccess || parent == IO_OBJECT_NULL) {
            break;
        }
        rdx_track_io_acquire();
        rdx_release_io(current);
        current = parent;
    }
    rdx_release_io(current);
    return found;
}

static bool rdx_authority_values_match(rdx_macos_device *device,
    uint64_t observed_id, const char *observed_uuid, bool observed_uuid_present,
    uint32_t observed_major, uint32_t observed_minor, uint64_t observed_capacity,
    bool observed_whole, bool observed_ejectable, bool observed_removable) {
    bool uuid_matches = device->whole_media_uuid_present == observed_uuid_present &&
        (!observed_uuid_present ||
            (rdx_authority_uuid_valid(device->whole_media_uuid) &&
                rdx_authority_uuid_valid(observed_uuid) &&
                strcmp(device->whole_media_uuid, observed_uuid) == 0));
    return device->whole_registry_entry_id != 0 &&
        observed_id == device->whole_registry_entry_id &&
        uuid_matches &&
        observed_major == device->whole_bsd_major &&
        observed_minor == device->whole_bsd_minor &&
        observed_capacity == device->whole_capacity_bytes &&
        observed_whole == device->whole_media_is_whole && observed_whole &&
        observed_ejectable == device->whole_media_ejectable && observed_ejectable &&
        observed_removable == device->whole_media_removable && observed_removable;
}

static bool rdx_apfs_role_is_system(CFTypeRef value) {
    if (value == NULL) {
        return false;
    }
    if (CFGetTypeID(value) == CFStringGetTypeID()) {
        const CFStringRef denied[] = {
            CFSTR("System"), CFSTR("Data"), CFSTR("Preboot"),
            CFSTR("Recovery"), CFSTR("VM")
        };
        for (size_t index = 0; index < sizeof(denied) / sizeof(denied[0]); ++index) {
            if (CFStringCompare((CFStringRef)value, denied[index],
                    kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                return true;
            }
        }
        return false;
    }
    if (CFGetTypeID(value) == CFArrayGetTypeID()) {
        CFArrayRef roles = (CFArrayRef)value;
        for (CFIndex index = 0; index < CFArrayGetCount(roles); ++index) {
            if (rdx_apfs_role_is_system(CFArrayGetValueAtIndex(roles, index))) {
                return true;
            }
        }
    }
    return false;
}

bool rdx_media_has_system_apfs_role(io_service_t media) {
    const CFStringRef keys[] = {CFSTR("Role"), CFSTR("APFSRole")};
    for (size_t index = 0; index < sizeof(keys) / sizeof(keys[0]); ++index) {
        CFTypeRef value = IORegistryEntryCreateCFProperty(
            media, keys[index], kCFAllocatorDefault, 0
        );
        if (value != NULL) {
            rdx_track_cf_acquire();
            bool denied = rdx_apfs_role_is_system(value);
            rdx_release_cf(value);
            if (denied) {
                return true;
            }
        }
    }
    return false;
}

bool rdx_fresh_whole_media_matches(rdx_macos_device *device, int descriptor) {
    if (device == NULL || device->session == NULL || device->whole_disk == NULL) {
        return false;
    }
    struct stat opened = {0};
    if (descriptor >= 0 && (fstat(descriptor, &opened) != 0 ||
        !S_ISCHR(opened.st_mode) ||
        (uint32_t)major(opened.st_rdev) != device->whole_bsd_major ||
        (uint32_t)minor(opened.st_rdev) != device->whole_bsd_minor)) {
        return false;
    }
    CFMutableDictionaryRef matching = IOServiceMatching(kIOMediaClass);
    io_iterator_t iterator = IO_OBJECT_NULL;
    if (matching == NULL || IOServiceGetMatchingServices(
            kIOMainPortDefault, matching, &iterator
        ) != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        return false;
    }
    rdx_track_io_acquire();
    io_service_t entry = IO_OBJECT_NULL;
    io_service_t matched = IO_OBJECT_NULL;
    while ((entry = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        rdx_track_io_acquire();
        uint32_t observed_major = 0;
        uint32_t observed_minor = 0;
        uint64_t observed_capacity = 0;
        bool observed_uuid_present = false;
        bool observed_whole = false;
        bool observed_ejectable = false;
        bool observed_removable = false;
        char observed_uuid[RDX_MACOS_UUID_BYTES] = {0};
        if (rdx_authority_whole(entry) &&
            rdx_copy_whole_media_authority(entry, observed_uuid,
                &observed_uuid_present, &observed_major, &observed_minor,
                &observed_capacity, &observed_whole, &observed_ejectable,
                &observed_removable) &&
            observed_major == device->whole_bsd_major &&
            observed_minor == device->whole_bsd_minor) {
            if (matched != IO_OBJECT_NULL) {
                rdx_release_io(entry);
                rdx_release_io(matched);
                rdx_release_io(iterator);
                return false;
            }
            matched = entry;
            entry = IO_OBJECT_NULL;
        }
        rdx_release_io(entry);
    }
    rdx_release_io(iterator);
    if (matched == IO_OBJECT_NULL) {
        return false;
    }
    uint64_t observed_id = 0;
    uint32_t observed_major = 0;
    uint32_t observed_minor = 0;
    uint64_t observed_capacity = 0;
    bool observed_uuid_present = false;
    bool observed_whole = false;
    bool observed_ejectable = false;
    bool observed_removable = false;
    char observed_uuid[RDX_MACOS_UUID_BYTES] = {0};
    DADiskRef fresh_disk = DADiskCreateFromIOMedia(
        kCFAllocatorDefault, device->session, matched
    );
    if (fresh_disk != NULL) {
        rdx_track_cf_acquire();
    }
    io_service_t retained_da_media = DADiskCopyIOMedia(device->whole_disk);
    if (retained_da_media != IO_OBJECT_NULL) {
        rdx_track_io_acquire();
    }
    uint64_t retained_da_id = 0;
    bool valid = fresh_disk != NULL && retained_da_media != IO_OBJECT_NULL &&
        rdx_authority_registry_id(matched, &observed_id) &&
        rdx_authority_registry_id(retained_da_media, &retained_da_id) &&
        retained_da_id == device->whole_registry_entry_id &&
        rdx_copy_whole_media_authority(matched, observed_uuid,
            &observed_uuid_present, &observed_major, &observed_minor,
            &observed_capacity, &observed_whole, &observed_ejectable,
            &observed_removable) &&
        rdx_authority_values_match(device, observed_id, observed_uuid,
            observed_uuid_present, observed_major, observed_minor,
            observed_capacity, observed_whole, observed_ejectable,
            observed_removable) &&
        rdx_authority_descendant(matched, device->expected.registry_entry_id);
    rdx_release_io(retained_da_media);
    rdx_release_cf(fresh_disk);
    rdx_release_io(matched);
    return valid;
}

bool rdx_validate_mounted_fd(rdx_macos_device *device, int descriptor,
    uint64_t expected_device_id) {
    struct stat mounted = {0};
    if (device == NULL || descriptor < 0 || expected_device_id == 0 ||
        fstat(descriptor, &mounted) != 0 ||
        (uint64_t)mounted.st_dev != expected_device_id) {
        return false;
    }
    uint32_t mounted_major = (uint32_t)major(mounted.st_dev);
    uint32_t mounted_minor = (uint32_t)minor(mounted.st_dev);
    uint32_t retained_index = UINT32_MAX;
    for (uint32_t index = 0; index < device->media_count; ++index) {
        uint64_t media_id = 0;
        uint32_t media_major = 0;
        uint32_t media_minor = 0;
        bool media_uuid_present = false;
        char media_uuid[RDX_MACOS_UUID_BYTES] = {0};
        if (rdx_copy_media_authority(
                device->media_services[index],
                media_uuid,
                &media_uuid_present,
                &media_major, &media_minor) &&
            rdx_authority_registry_id(
                device->media_services[index],
                &media_id
            ) &&
            media_major == mounted_major && media_minor == mounted_minor &&
            rdx_partition_authority_matches(
                device->media_registry_entry_ids[index],
                device->media_uuids[index],
                media_id,
                media_uuid,
                media_uuid_present
            )) {
            if (retained_index != UINT32_MAX) {
                return false;
            }
            retained_index = index;
        }
    }
    if (retained_index == UINT32_MAX) {
        return false;
    }
    CFMutableDictionaryRef matching = IOServiceMatching(kIOMediaClass);
    io_iterator_t iterator = IO_OBJECT_NULL;
    if (matching == NULL || IOServiceGetMatchingServices(
            kIOMainPortDefault, matching, &iterator
        ) != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        return false;
    }
    rdx_track_io_acquire();
    io_service_t entry = IO_OBJECT_NULL;
    uint32_t matches = 0;
    bool valid = false;
    while ((entry = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        rdx_track_io_acquire();
        uint64_t media_id = 0;
        uint32_t media_major = 0;
        uint32_t media_minor = 0;
        bool media_uuid_present = false;
        char media_uuid[RDX_MACOS_UUID_BYTES] = {0};
        if (rdx_copy_media_authority(
                entry,
                media_uuid,
                &media_uuid_present,
                &media_major,
                &media_minor
            ) &&
            rdx_authority_registry_id(entry, &media_id) &&
            media_major == mounted_major && media_minor == mounted_minor) {
            matches += 1;
            valid = matches == 1 &&
                rdx_partition_authority_matches(
                    device->media_registry_entry_ids[retained_index],
                    device->media_uuids[retained_index],
                    media_id,
                    media_uuid,
                    media_uuid_present
                ) &&
                rdx_authority_descendant(entry, device->expected.registry_entry_id);
        }
        rdx_release_io(entry);
    }
    rdx_release_io(iterator);
    return matches == 1 && valid;
}

#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_macos_test_raw_media_authority_contract(void) {
    int read_only = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int read_write = open("/dev/null", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    bool descriptor_modes =
        (rdx_raw_open_flags(false) & O_ACCMODE) == O_RDONLY &&
        (rdx_raw_open_flags(true) & O_ACCMODE) == O_RDWR &&
        read_only >= 0 && read_write >= 0 &&
        !rdx_descriptor_is_writable(read_only) &&
        rdx_descriptor_is_writable(read_write);
    if (read_only >= 0) {
        (void)close(read_only);
    }
    if (read_write >= 0) {
        (void)close(read_write);
    }
    const char *stable_identity = "01234567-89AB-CDEF-0123-456789ABCDEF";
    bool partition_identity_modes =
        rdx_partition_authority_matches(42, stable_identity, 42, "", false) &&
        !rdx_partition_authority_matches(42, stable_identity, 43, "", false) &&
        rdx_partition_authority_matches(
            42,
            stable_identity,
            42,
            stable_identity,
            true
        ) &&
        !rdx_partition_authority_matches(
            42,
            stable_identity,
            42,
            "FEDCBA98-7654-3210-FEDC-BA9876543210",
            true
        );
    rdx_macos_device device = {
        .whole_registry_entry_id = 41,
        .whole_capacity_bytes = UINT64_C(1000000),
        .whole_bsd_major = 1,
        .whole_bsd_minor = 7,
        .whole_media_uuid_present = true,
        .whole_media_is_whole = true,
        .whole_media_ejectable = true,
        .whole_media_removable = true
    };
    memcpy(device.whole_media_uuid,
        "01234567-89AB-CDEF-0123-456789ABCDEF", RDX_MACOS_UUID_BYTES);
    bool required_identity_matches =
        rdx_authority_values_match(&device, 41, device.whole_media_uuid, true,
            1, 7, UINT64_C(1000000), true, true, true) &&
        !rdx_authority_values_match(&device, 42, device.whole_media_uuid, true,
            1, 7, UINT64_C(1000000), true, true, true) &&
        !rdx_authority_values_match(&device, 41,
            "FEDCBA98-7654-3210-FEDC-BA9876543210", true,
            1, 7, UINT64_C(1000000), true, true, true) &&
        !rdx_authority_values_match(&device, 41, device.whole_media_uuid, true,
            1, 8, UINT64_C(1000000), true, true, true) &&
        !rdx_authority_values_match(&device, 41, device.whole_media_uuid, true,
            1, 7, UINT64_C(999999), true, true, true) &&
        !rdx_authority_values_match(&device, 41, device.whole_media_uuid, true,
            1, 7, UINT64_C(1000000), true, true, false);
    memset(device.whole_media_uuid, 0, sizeof(device.whole_media_uuid));
    device.whole_media_uuid_present = false;
    return descriptor_modes && partition_identity_modes &&
        required_identity_matches &&
        rdx_authority_values_match(&device, 41, "", false,
            1, 7, UINT64_C(1000000), true, true, true) &&
        !rdx_authority_values_match(&device, 41,
            "01234567-89AB-CDEF-0123-456789ABCDEF", true,
            1, 7, UINT64_C(1000000), true, true, true);
}
#endif

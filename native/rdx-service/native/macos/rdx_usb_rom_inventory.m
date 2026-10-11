// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_usb_rom_internal.h"
#include "rdx_iokit_internal.h"
#import <Foundation/Foundation.h>

/** Stack-bounded inventory owns each deduplicated parent until explicit release. */
typedef struct rdx_rom_inventory {
    rdx_macos_rom_candidate candidates[RDX_MACOS_MAX_ROM_CANDIDATES];
    io_service_t services[RDX_MACOS_MAX_ROM_CANDIDATES];
    uint32_t count;
} rdx_rom_inventory;

/** Rejects malformed fixed-width snapshot records before selection or native open. */
static bool rdx_rom_candidate_valid(const rdx_macos_rom_candidate *candidate) {
    return candidate != NULL && candidate->registry_id != 0 && candidate->location_id != 0 &&
           candidate->reserved == 0;
}

/** Deduplicates the same parent exposed by both USB classes without hiding ambiguity. */
static rdx_macos_status rdx_rom_add_candidate(rdx_rom_inventory *inventory,
                                              rdx_macos_rom_candidate candidate, bool *added) {
    *added = false;
    if (!rdx_rom_candidate_valid(&candidate)) { return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE; }
    for (uint32_t index = 0; index < inventory->count; index++) {
        rdx_macos_rom_candidate previous = inventory->candidates[index];
        if (previous.registry_id == candidate.registry_id) {
            return previous.location_id == candidate.location_id
                       ? RDX_MACOS_STATUS_OK
                       : RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        }
        if (previous.location_id == candidate.location_id) {
            return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        }
    }
    if (inventory->count >= RDX_MACOS_MAX_ROM_CANDIDATES) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    inventory->candidates[inventory->count++] = candidate;
    *added = true;
    return RDX_MACOS_STATUS_OK;
}

/** Selects the full observed epoch and location, never a first match or a ROM serial. */
static rdx_macos_status rdx_rom_select_candidate(const rdx_rom_inventory *inventory,
                                                 const rdx_macos_rom_candidate *candidate,
                                                 uint32_t *index) {
    if (!rdx_rom_candidate_valid(candidate)) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    if (inventory->count > RDX_MACOS_MAX_ROM_CANDIDATES) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    for (uint32_t current = 0; current < inventory->count; current++) {
        const rdx_macos_rom_candidate *actual = &inventory->candidates[current];
        if (actual->registry_id == candidate->registry_id &&
            actual->location_id == candidate->location_id) {
            *index = current;
            return RDX_MACOS_STATUS_OK;
        }
    }
    return RDX_MACOS_STATUS_DEVICE_REMOVED;
}

/** Reads integer registry properties without opening any IOService user client. */
static bool rdx_rom_inventory_number(io_service_t service, CFStringRef key, bool location,
                                      uint32_t *output) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
    if (property == NULL) { return false; }
    int64_t value = 0;
    bool valid = CFGetTypeID(property) == CFNumberGetTypeID() &&
                 CFNumberGetValue((CFNumberRef)property, kCFNumberSInt64Type, &value) &&
                 value >= (location ? INT32_MIN : 0) && value <= UINT32_MAX;
    CFRelease(property);
    if (valid) { *output = (uint32_t)value; }
    return valid;
}

/** Copies only VID/PID, location and registry epoch; no generic ROM serial is read. */
static bool rdx_rom_inventory_record(io_service_t service, rdx_macos_rom_candidate *output) {
    uint32_t vendor = 0, product = 0;
    *output = (rdx_macos_rom_candidate){0};
    return rdx_rom_inventory_number(service, CFSTR("idVendor"), false, &vendor) &&
           vendor == 0x0451 &&
           rdx_rom_inventory_number(service, CFSTR("idProduct"), false, &product) &&
           product == 0x926b &&
           IORegistryEntryGetRegistryEntryID(service, &output->registry_id) == kIOReturnSuccess &&
           rdx_rom_inventory_number(service, CFSTR("locationID"), true, &output->location_id) &&
           rdx_rom_candidate_valid(output);
}

/** Releases every retained parent, including partially completed enumerations. */
static void rdx_rom_inventory_release(rdx_rom_inventory *inventory) {
    for (uint32_t index = 0; index < inventory->count; index++) {
        if (inventory->services[index] != IO_OBJECT_NULL) {
            IOObjectRelease(inventory->services[index]);
            inventory->services[index] = IO_OBJECT_NULL;
        }
    }
}

/** Enumerates at most128 entries per class and preserves only sixteen unique parents. */
static rdx_macos_status rdx_rom_inventory_scan_class(const char *name,
                                                     rdx_rom_inventory *inventory) {
    CFMutableDictionaryRef matching = IOServiceMatching(name);
    if (matching == NULL) { return RDX_MACOS_STATUS_RESOURCE_LIMIT; }
    CFDictionarySetValue(matching, CFSTR("IOPropertyMatch"),
                         (__bridge CFDictionaryRef)@{@"idVendor" : @0x0451,
                                                     @"idProduct" : @0x926b});
    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn io_status = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (io_status != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        if (iterator != IO_OBJECT_NULL) { IOObjectRelease(iterator); }
        return io_status == kIOReturnSuccess
                   ? RDX_MACOS_STATUS_ENUMERATION_FAILED
                   : rdx_status_from_io(io_status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    uint32_t visited = 0;
    rdx_macos_status status = RDX_MACOS_STATUS_OK;
    io_service_t service = IO_OBJECT_NULL;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        rdx_macos_rom_candidate candidate = {0};
        bool added = false;
        if (++visited > 128) {
            status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        } else if (!rdx_rom_inventory_record(service, &candidate)) {
            status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        } else {
            status = rdx_rom_add_candidate(inventory, candidate, &added);
        }
        if (added) {
            inventory->services[inventory->count - 1] = service;
        } else {
            IOObjectRelease(service);
        }
        if (status != RDX_MACOS_STATUS_OK) { break; }
    }
    if (status == RDX_MACOS_STATUS_OK && !IOIteratorIsValid(iterator)) {
        status = RDX_MACOS_STATUS_ENUMERATION_FAILED;
    }
    IOObjectRelease(iterator);
    return status;
}

/** Includes legacy-class aliases so an incomplete inventory never selects arbitrarily. */
static rdx_macos_status rdx_rom_inventory_scan(rdx_rom_inventory *inventory) {
    rdx_macos_status status = rdx_rom_inventory_scan_class("IOUSBHostDevice", inventory);
    if (status == RDX_MACOS_STATUS_OK) {
        status = rdx_rom_inventory_scan_class("IOUSBDevice", inventory);
    }
    return status;
}

/** Publishes an all-or-nothing read-only snapshot; opening interfaces is a separate API. */
rdx_macos_status rdx_macos_rom_enumerate(rdx_macos_rom_candidate *output, uint32_t capacity,
                                       uint32_t *count) {
    if (count == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    *count = 0;
    if (output == NULL || capacity == 0 || capacity > RDX_MACOS_MAX_ROM_CANDIDATES) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    memset(output, 0, capacity * sizeof(*output));
    rdx_rom_inventory inventory = {0};
    rdx_macos_status status = RDX_MACOS_STATUS_NATIVE_FAILURE;
    @try {
        @autoreleasepool {
            status = rdx_rom_inventory_scan(&inventory);
            if (status == RDX_MACOS_STATUS_OK && inventory.count > capacity) {
                status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
            }
            if (status == RDX_MACOS_STATUS_OK) {
                memcpy(output, inventory.candidates, inventory.count * sizeof(*output));
                *count = inventory.count;
            }
        }
    } @catch (__unused NSException *exception) { status = RDX_MACOS_STATUS_NATIVE_FAILURE; }
    rdx_rom_inventory_release(&inventory);
    return status;
}

/** Re-enumerates and transfers one retained parent only when the selected epoch survives. */
rdx_macos_status rdx_rom_find_selected_parent(const rdx_macos_rom_candidate *candidate,
                                              io_service_t *output) {
    if (output == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    *output = IO_OBJECT_NULL;
    if (!rdx_rom_candidate_valid(candidate)) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    rdx_rom_inventory inventory = {0};
    rdx_macos_status status = RDX_MACOS_STATUS_NATIVE_FAILURE;
    @try {
        @autoreleasepool {
            status = rdx_rom_inventory_scan(&inventory);
            uint32_t index = 0;
            if (status == RDX_MACOS_STATUS_OK) {
                status = rdx_rom_select_candidate(&inventory, candidate, &index);
            }
            if (status == RDX_MACOS_STATUS_OK) {
                *output = inventory.services[index];
                inventory.services[index] = IO_OBJECT_NULL;
            }
        }
    } @catch (__unused NSException *exception) { status = RDX_MACOS_STATUS_NATIVE_FAILURE; }
    rdx_rom_inventory_release(&inventory);
    return status;
}

#if defined(RDX_MACOS_TEST_HOOKS)
/** Literal records cover multi-device selection, replacement, aliasing and finite bounds. */
bool rdx_macos_rom_inventory_test_contract(void) {
    rdx_rom_inventory inventory = {0};
    bool added = false;
    uint32_t selected = UINT32_MAX;
    rdx_macos_rom_candidate first = {11, 0x81200000, 0}, second = {22, 0x81300000, 0};
    if (rdx_rom_select_candidate(&inventory, &first, &selected) != RDX_MACOS_STATUS_DEVICE_REMOVED ||
        rdx_rom_add_candidate(&inventory, first, &added) != RDX_MACOS_STATUS_OK || !added ||
        rdx_rom_add_candidate(&inventory, second, &added) != RDX_MACOS_STATUS_OK || !added ||
        rdx_rom_select_candidate(&inventory, &second, &selected) != RDX_MACOS_STATUS_OK ||
        selected != 1 ||
        rdx_rom_add_candidate(&inventory, first, &added) != RDX_MACOS_STATUS_OK || added ||
        inventory.count != 2) {
        return false;
    }
    rdx_macos_rom_candidate stale = {23, second.location_id, 0};
    rdx_macos_rom_candidate moved = {second.registry_id, first.location_id, 0};
    rdx_macos_rom_candidate malformed = {0, second.location_id, 0};
    if (rdx_rom_select_candidate(&inventory, &stale, &selected) != RDX_MACOS_STATUS_DEVICE_REMOVED ||
        rdx_rom_select_candidate(&inventory, &moved, &selected) != RDX_MACOS_STATUS_DEVICE_REMOVED ||
        rdx_rom_select_candidate(&inventory, &malformed, &selected) != RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        rdx_rom_add_candidate(&inventory, stale, &added) != RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE ||
        rdx_rom_add_candidate(&inventory, moved, &added) != RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE) {
        return false;
    }
    for (uint32_t index = inventory.count; index <= RDX_MACOS_MAX_ROM_CANDIDATES; index++) {
        rdx_macos_rom_candidate next = {100 + index, 100 + index, 0};
        rdx_macos_status expected = index < RDX_MACOS_MAX_ROM_CANDIDATES
                                       ? RDX_MACOS_STATUS_OK : RDX_MACOS_STATUS_RESOURCE_LIMIT;
        if (rdx_rom_add_candidate(&inventory, next, &added) != expected) { return false; }
    }
    return inventory.count == RDX_MACOS_MAX_ROM_CANDIDATES;
}
#endif

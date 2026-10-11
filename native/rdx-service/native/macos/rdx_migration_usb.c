// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_migration_usb.h"
#include "rdx_iokit_internal.h"
#include <string.h>

/** Minimal registry facts; no serial or location ever enters error text. */
typedef struct rdx_migration_usb_fact {
    uint64_t registry_id;
    uint32_t location;
    uint16_t vendor;
    uint16_t product;
    bool serial_matches;
} rdx_migration_usb_fact;

/** Selects the exact port while rejecting an already attached saved unit elsewhere. */
static rdx_macos_status rdx_select_migration_usb(const rdx_migration_usb_fact *facts, size_t count,
                                                 uint32_t location, uint64_t *epoch) {
    *epoch = 0;
    size_t at_location = 0;
    const rdx_migration_usb_fact *selected = NULL;
    for (size_t index = 0; index < count; index++) {
        /* Both the source PID0006 and returned PID0005 are normal RDX parents.
         * A matching unit on another port is a collision even before this ROM
         * target is erased, or while the selected port is temporarily absent. */
        if (facts[index].vendor == 0x1a5a &&
            (facts[index].product == 5 || facts[index].product == 6) &&
            facts[index].serial_matches && facts[index].location != location) {
            return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        }
        if (facts[index].location == location) {
            at_location++;
            selected = &facts[index];
        }
    }
    if (at_location == 0) { return RDX_MACOS_STATUS_OK; }
    if (at_location != 1 || selected->registry_id == 0) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    if (selected->vendor == 0x0451 && selected->product == 0x926b) { return RDX_MACOS_STATUS_OK; }
    if (selected->vendor != 0x1a5a || selected->product != 5 || !selected->serial_matches) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    *epoch = selected->registry_id;
    return RDX_MACOS_STATUS_OK;
}

/** Copies observed numeric properties without opening a USB device client. */
static bool rdx_migration_usb_number(io_service_t service, CFStringRef key, bool location,
                                     uint32_t maximum, uint32_t *output) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
    if (property == NULL) { return false; }
    int64_t number = 0;
    bool valid = CFGetTypeID(property) == CFNumberGetTypeID() &&
                 CFNumberGetValue((CFNumberRef)property, kCFNumberSInt64Type, &number) &&
                 number >= (location ? INT32_MIN : 0) && number <= maximum;
    CFRelease(property);
    if (valid) { *output = (uint32_t)number; }
    return valid;
}

/** Requires consistent aliases at the target; any matching alias elsewhere is a collision. */
static bool rdx_migration_usb_serial_matches(io_service_t service, const uint8_t *serial,
                                             bool require_consistent_aliases) {
    const CFStringRef keys[] = {CFSTR("kUSBSerialNumberString"), CFSTR("USB Serial Number")};
    bool found = false, consistent = true;
    for (size_t index = 0; index < 2; index++) {
        CFTypeRef property =
            IORegistryEntryCreateCFProperty(service, keys[index], kCFAllocatorDefault, 0);
        if (property == NULL) { continue; }
        char value[13] = {0};
        bool matches = CFGetTypeID(property) == CFStringGetTypeID() &&
                       CFStringGetLength((CFStringRef)property) == 12 &&
                       CFStringGetCString((CFStringRef)property, value, sizeof(value),
                                          kCFStringEncodingASCII) &&
                       value[12] == '\0' && memcmp(value, serial, 12) == 0;
        CFRelease(property);
        consistent = consistent && matches;
        found = found || matches;
    }
    return found && (!require_consistent_aliases || consistent);
}

/** Adds bounded parent facts, deduplicating modern/legacy registry aliases. */
static rdx_macos_status rdx_migration_usb_inventory(const char *class_name,
                                                    uint32_t selected_location,
                                                    const uint8_t *serial,
                                                    rdx_migration_usb_fact facts[128],
                                                    size_t *count) {
    CFMutableDictionaryRef matching = IOServiceMatching(class_name);
    if (matching == NULL) { return RDX_MACOS_STATUS_RESOURCE_LIMIT; }
    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn status = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (status != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        if (iterator != IO_OBJECT_NULL) { IOObjectRelease(iterator); }
        return status == kIOReturnSuccess
                   ? RDX_MACOS_STATUS_ENUMERATION_FAILED
                   : rdx_status_from_io(status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    rdx_macos_status result = RDX_MACOS_STATUS_OK;
    io_service_t service = IO_OBJECT_NULL;
    size_t visited = 0;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        rdx_migration_usb_fact fact = {0};
        if (++visited > 128) {
            IOObjectRelease(service);
            result = RDX_MACOS_STATUS_RESOURCE_LIMIT;
            break;
        }
        if (IORegistryEntryGetRegistryEntryID(service, &fact.registry_id) != kIOReturnSuccess ||
            fact.registry_id == 0) {
            IOObjectRelease(service);
            result = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            break;
        }
        bool duplicate = false;
        for (size_t index = 0; index < *count; index++) {
            if (facts[index].registry_id == fact.registry_id) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            IOObjectRelease(service);
            continue;
        }
        if (*count == 128) {
            IOObjectRelease(service);
            result = RDX_MACOS_STATUS_RESOURCE_LIMIT;
            break;
        }
        uint32_t vendor = 0, product = 0;
        bool valid =
            rdx_migration_usb_number(service, CFSTR("locationID"), true, UINT32_MAX,
                                     &fact.location) &&
            rdx_migration_usb_number(service, CFSTR("idVendor"), false, UINT16_MAX, &vendor) &&
            rdx_migration_usb_number(service, CFSTR("idProduct"), false, UINT16_MAX, &product);
        if (valid && vendor == 0x1a5a && (product == 5 || product == 6)) {
            fact.serial_matches = rdx_migration_usb_serial_matches(
                service, serial, fact.location == selected_location);
        }
        IOObjectRelease(service);
        if (!valid) {
            result = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            break;
        }
        fact.vendor = (uint16_t)vendor;
        fact.product = (uint16_t)product;
        facts[(*count)++] = fact;
    }
    if (result == RDX_MACOS_STATUS_OK && !IOIteratorIsValid(iterator)) {
        result = RDX_MACOS_STATUS_ENUMERATION_FAILED;
    }
    IOObjectRelease(iterator);
    return result;
}

/** Observes current USB parents without creating any device, HID, or SCSI client. */
rdx_macos_status rdx_macos_observe_migration_usb(uint32_t location_id, const uint8_t *serial,
                                                 uint32_t length, uint64_t *epoch) {
    if (epoch == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    *epoch = 0;
    if (location_id == 0 || serial == NULL || length != 12) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    for (size_t index = 0; index < 12; index++) {
        if (serial[index] < '0' || serial[index] > '9') {
            return RDX_MACOS_STATUS_INVALID_ARGUMENT;
        }
    }
    rdx_migration_usb_fact facts[128] = {0};
    size_t count = 0;
    rdx_macos_status status =
        rdx_migration_usb_inventory("IOUSBHostDevice", location_id, serial, facts, &count);
    if (status == RDX_MACOS_STATUS_OK) {
        status = rdx_migration_usb_inventory("IOUSBDevice", location_id, serial, facts, &count);
    }
    if (status != RDX_MACOS_STATUS_OK) { return status; }
    return rdx_select_migration_usb(facts, count, location_id, epoch);
}

#if defined(RDX_MACOS_TEST_HOOKS)
/** Literal snapshots check port identity, ROM waiting, ambiguity and epoch changes. */
bool rdx_macos_test_migration_usb_observation_contract(void) {
    uint64_t epoch = 99;
    if (rdx_select_migration_usb(NULL, 0, 0x02100000, &epoch) != 0 || epoch != 0) { return false; }
    rdx_migration_usb_fact facts[2] = {{17, 0x02100000, 0x1a5a, 5, true}};
    if (rdx_select_migration_usb(facts, 1, 0x02100000, &epoch) != 0 || epoch != 17) {
        return false;
    }
    facts[0].registry_id = 18;
    if (rdx_select_migration_usb(facts, 1, 0x02100000, &epoch) != 0 || epoch != 18) {
        return false;
    }
    facts[0].serial_matches = false;
    if (rdx_select_migration_usb(facts, 1, 0x02100000, &epoch) == 0 || epoch != 0) { return false; }
    facts[0] = (rdx_migration_usb_fact){19, 0x02100000, 0x0451, 0x926b, false};
    if (rdx_select_migration_usb(facts, 1, 0x02100000, &epoch) != 0 || epoch != 0) { return false; }
    facts[0] = (rdx_migration_usb_fact){20, 0x02100000, 0x1a5a, 6, true};
    if (rdx_select_migration_usb(facts, 1, 0x02100000, &epoch) == 0) { return false; }
    facts[0].product = 5;
    facts[1] = (rdx_migration_usb_fact){21, 0x02100000, 0x1234, 1, false};
    if (rdx_select_migration_usb(facts, 2, 0x02100000, &epoch) == 0) { return false; }
    facts[1] = (rdx_migration_usb_fact){21, 0x02200000, 0x1a5a, 5, false};
    if (rdx_select_migration_usb(facts, 2, 0x02100000, &epoch) != 0 || epoch != 20) { return false; }
    facts[1].serial_matches = true;
    if (rdx_select_migration_usb(facts, 2, 0x02100000, &epoch) == 0 || epoch != 0) { return false; }
    facts[0] = (rdx_migration_usb_fact){22, 0x02100000, 0x0451, 0x926b, false};
    if (rdx_select_migration_usb(facts, 2, 0x02100000, &epoch) == 0 || epoch != 0) { return false; }
    if (rdx_select_migration_usb(facts + 1, 1, 0x02100000, &epoch) == 0 || epoch != 0) { return false; }
    facts[1].product = 6;
    if (rdx_select_migration_usb(facts, 2, 0x02100000, &epoch) == 0 || epoch != 0) { return false; }
    if (rdx_select_migration_usb(facts + 1, 1, 0x02100000, &epoch) == 0 || epoch != 0) { return false; }
    facts[1].serial_matches = false;
    if (rdx_select_migration_usb(facts, 2, 0x02100000, &epoch) != 0 || epoch != 0) { return false; }
    return true;
}
#endif

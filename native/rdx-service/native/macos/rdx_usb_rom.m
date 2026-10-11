// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_usb_rom.h"
#include "rdx_usb_rom_internal.h"
#include "rdx_iokit_internal.h"

#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDDevice.h>
#import <IOUSBHost/IOUSBHost.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

/* Protocol evidence: analysis/prototype/README.md, TI utility 2.10's ordinary
 * ProgramFromBootLoader sequence. No RAM mode, status probes, or vendor bypass.
 * SDK IOUSBHostDefinitions.h documents capture's reset-on-destroy behavior;
 * this bridge therefore uses only IOUSBHostInterface OptionsNone and IOHID. */
enum { RDX_ROM_IDENTIFY = 1, RDX_ROM_SETUP = 2, RDX_ROM_PROGRAM = 3, RDX_ROM_RESET = 4 };
static const CFStringRef rdx_rom_run_loop_mode = CFSTR("OpenRDX-ROM-completion");
static atomic_bool rdx_rom_active = false;
static atomic_bool rdx_rom_quarantined = false;

/** Retained USB-parent snapshot; location continuity is not authentication. */
typedef struct rdx_rom_identity {
    uint64_t registry_id;
    uint32_t location;
    uint32_t address;
    uint32_t configuration;
} rdx_rom_identity;

/** Heap storage survives a missing/late callback until process exit if needed. */
typedef struct rdx_rom_report {
    uint8_t bytes[9];
    CFIndex length;
    CFIndex actual;
    IOHIDDeviceRef sender;
    IOHIDReportType type;
    IOReturn status;
    bool valid_metadata;
    atomic_bool completed;
} rdx_rom_report;

@interface RDXROMSession : NSObject {
  @public
    io_service_t parent;
    io_service_t hid_interface;
    io_service_t hid_service;
    io_service_t bulk_service;
    rdx_rom_identity identity;
    uint64_t selected_epoch;
    uint8_t hid_number;
    uint8_t bulk_number;
    IOHIDDeviceRef hid;
    CFRunLoopRef run_loop;
    bool hid_open;
    bool scheduled;
    pthread_t thread;
    rdx_rom_report *pending;
    bool program_in_flight;
    uint32_t next_command;
}
@property(nonatomic, strong) IOUSBHostInterface *bulk;
@property(nonatomic, strong) IOUSBHostPipe *pipe;
@property(nonatomic, strong) NSMutableData *programData;
/** Closes child ownership, returning false if callback lifetime is unresolved. */
- (bool)close;
@end

/** Drops an owned registry reference once and clears the caller's slot. */
static void rdx_rom_release_service(io_service_t *service) {
    if (*service != IO_OBJECT_NULL) {
        IOObjectRelease(*service);
        *service = IO_OBJECT_NULL;
    }
}

@implementation RDXROMSession
/** Never resets, reconfigures, clears stalls, or sends any report during cleanup. */
- (bool)close {
    @try {
        if (scheduled) {
            IOHIDDeviceUnscheduleFromRunLoop(hid, run_loop, rdx_rom_run_loop_mode);
            scheduled = false;
        }
        if (hid_open) {
            IOHIDDeviceClose(hid, kIOHIDOptionsTypeNone);
            hid_open = false;
        }
        _pipe = nil;
        [_bulk destroy];
        _bulk = nil;
        /* Neither callback context nor its report buffer may be freed while the
         * SDK could still call it. One quarantined owner blocks future sessions. */
        if (program_in_flight ||
            (pending != NULL && !atomic_load_explicit(&pending->completed, memory_order_acquire))) {
            return false;
        }
        _programData = nil;
        free(pending);
        pending = NULL;
        if (hid != NULL) {
            CFRelease(hid);
            hid = NULL;
        }
        if (run_loop != NULL) {
            CFRelease(run_loop);
            run_loop = NULL;
        }
        rdx_rom_release_service(&bulk_service);
        rdx_rom_release_service(&hid_service);
        rdx_rom_release_service(&hid_interface);
        rdx_rom_release_service(&parent);
        return true;
    } @catch (__unused NSException *exception) { return false; }
}

/** Handles partially initialized owners; live unknown callbacks are retained. */
- (void)dealloc {
    [self close];
}
@end

struct rdx_macos_rom_session {
    void *retained_owner;
};

/** Reads exact numeric registry properties, including signed locationID bits. */
static bool rdx_rom_number(io_service_t service, CFStringRef key, bool location, uint32_t *output) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(service, key, kCFAllocatorDefault, 0);
    if (property == NULL) { return false; }
    int64_t value = 0;
    bool valid = CFGetTypeID(property) == CFNumberGetTypeID() &&
                 CFNumberGetValue((CFNumberRef)property, kCFNumberSInt64Type, &value) &&
                 value <= UINT32_MAX && value >= (location ? INT32_MIN : 0);
    CFRelease(property);
    if (valid) { *output = (uint32_t)value; }
    return valid;
}

/** Requires the actual modern TI ROM parent and complete current registry facts. */
static bool rdx_rom_copy_identity(io_service_t service, rdx_rom_identity *output) {
    uint32_t vendor = 0, product = 0;
    return IOObjectConformsTo(service, "IOUSBHostDevice") &&
           rdx_rom_number(service, CFSTR("idVendor"), false, &vendor) && vendor == 0x0451 &&
           rdx_rom_number(service, CFSTR("idProduct"), false, &product) && product == 0x926b &&
           IORegistryEntryGetRegistryEntryID(service, &output->registry_id) == kIOReturnSuccess &&
           output->registry_id != 0 &&
           rdx_rom_number(service, CFSTR("locationID"), true, &output->location) &&
           output->location != 0 &&
           rdx_rom_number(service, CFSTR("kUSBAddress"), false, &output->address) &&
           output->address > 0 && output->address <= 127 &&
           rdx_rom_number(service, CFSTR("kUSBCurrentConfiguration"), false,
                          &output->configuration) &&
           output->configuration > 0 && output->configuration <= 255;
}

/** Rejects global ambiguity even when exactly one of several ROMs is at the port. */
static bool rdx_rom_unique_location(uint32_t count, uint32_t actual, uint32_t expected) {
    return count == 1 && expected != 0 && actual == expected;
}

/** Counts exact VID/PID parents, deduplicating a service exposed under both classes. */
static rdx_macos_status rdx_rom_inventory_class(const char *name, io_service_t *output,
                                                uint32_t *count) {
    CFMutableDictionaryRef matching = IOServiceMatching(name);
    if (matching == NULL) { return RDX_MACOS_STATUS_RESOURCE_LIMIT; }
    CFDictionarySetValue(
        matching, CFSTR("IOPropertyMatch"),
        (__bridge CFDictionaryRef)
            @{@"idVendor" : @0x0451,
              @"idProduct" : @0x926b});
    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn status = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (status != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        if (iterator != IO_OBJECT_NULL) { IOObjectRelease(iterator); }
        return rdx_status_from_io(status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    io_service_t candidate = IO_OBJECT_NULL;
    uint32_t visited = 0;
    while ((candidate = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        if (++visited > 128) {
            IOObjectRelease(candidate);
            IOObjectRelease(iterator);
            return RDX_MACOS_STATUS_RESOURCE_LIMIT;
        }
        if (*output != IO_OBJECT_NULL && IOObjectIsEqualTo(*output, candidate)) {
            IOObjectRelease(candidate);
            continue;
        }
        (*count)++;
        if (*count == 1) {
            *output = candidate;
        } else {
            IOObjectRelease(candidate);
            break;
        }
    }
    bool valid_iterator = IOIteratorIsValid(iterator);
    IOObjectRelease(iterator);
    return valid_iterator ? RDX_MACOS_STATUS_OK : RDX_MACOS_STATUS_ENUMERATION_FAILED;
}

/** Copies the sole global ROM; a legacy parent still counts toward ambiguity. */
static rdx_macos_status rdx_rom_find_parent(uint32_t location, io_service_t *output,
                                            rdx_rom_identity *identity) {
    *output = IO_OBJECT_NULL;
    uint32_t count = 0;
    rdx_macos_status status = rdx_rom_inventory_class("IOUSBHostDevice", output, &count);
    if (status == RDX_MACOS_STATUS_OK && count <= 1) {
        status = rdx_rom_inventory_class("IOUSBDevice", output, &count);
    }
    if (status != RDX_MACOS_STATUS_OK) {
        rdx_rom_release_service(output);
        return status;
    }
    bool valid = count == 1 && rdx_rom_copy_identity(*output, identity) &&
                 rdx_rom_unique_location(count, identity->location, location);
    if (!valid) {
        rdx_rom_release_service(output);
        return count == 0 ? RDX_MACOS_STATUS_DEVICE_REMOVED : RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    return RDX_MACOS_STATUS_OK;
}

/** Confirms the nearest USB parent directly, never a matching ancestor elsewhere. */
static bool rdx_rom_direct_parent(io_service_t service, io_service_t expected) {
    io_service_t actual = IO_OBJECT_NULL;
    IOReturn status = IORegistryEntryGetParentEntry(service, kIOServicePlane, &actual);
    bool matches = status == kIOReturnSuccess && actual != IO_OBJECT_NULL &&
                   IOObjectIsEqualTo(actual, expected);
    rdx_rom_release_service(&actual);
    return matches;
}

/** Requires observed active alternate zero on the selected configured interface. */
static bool rdx_rom_interface_facts(io_service_t service, RDXROMSession *owner,
                                    uint32_t expected_class, uint8_t *number) {
    uint32_t interface_class = 0, alternate = 0, configuration = 0, interface_number = 0;
    bool valid = IOObjectConformsTo(service, "IOUSBHostInterface") &&
                 rdx_rom_direct_parent(service, owner->parent) &&
                 rdx_rom_number(service, CFSTR("bInterfaceClass"), false, &interface_class) &&
                 interface_class == expected_class &&
                 rdx_rom_number(service, CFSTR("bAlternateSetting"), false, &alternate) &&
                 alternate == 0 &&
                 rdx_rom_number(service, CFSTR("bConfigurationValue"), false, &configuration) &&
                 configuration == owner->identity.configuration &&
                 rdx_rom_number(service, CFSTR("bInterfaceNumber"), false, &interface_number) &&
                 interface_number <= 255;
    if (valid) { *number = (uint8_t)interface_number; }
    return valid;
}

/** Finds one active HID and one active vendor interface before either is opened. */
static rdx_macos_status rdx_rom_find_interfaces(RDXROMSession *owner) {
    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn status = IORegistryEntryGetChildIterator(owner->parent, kIOServicePlane, &iterator);
    if (status != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        if (iterator != IO_OBJECT_NULL) { IOObjectRelease(iterator); }
        return rdx_status_from_io(status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    io_service_t candidate = IO_OBJECT_NULL;
    uint32_t hid_count = 0, bulk_count = 0, visited = 0;
    bool valid = true;
    while ((candidate = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        uint32_t interface_class = 0;
        if (++visited > 128) {
            IOObjectRelease(candidate);
            valid = false;
            break;
        }
        if (IOObjectConformsTo(candidate, "IOUSBHostInterface")) {
            if (!rdx_rom_number(candidate, CFSTR("bInterfaceClass"), false, &interface_class)) {
                valid = false;
            }
            if (interface_class == 3) {
                hid_count++;
                if (hid_count == 1 &&
                    rdx_rom_interface_facts(candidate, owner, 3, &owner->hid_number)) {
                    owner->hid_interface = candidate;
                    candidate = IO_OBJECT_NULL;
                } else {
                    valid = false;
                }
            } else if (interface_class == 255) {
                bulk_count++;
                if (bulk_count == 1 &&
                    rdx_rom_interface_facts(candidate, owner, 255, &owner->bulk_number)) {
                    owner->bulk_service = candidate;
                    candidate = IO_OBJECT_NULL;
                } else {
                    valid = false;
                }
            }
        }
        rdx_rom_release_service(&candidate);
    }
    valid = valid && IOIteratorIsValid(iterator);
    IOObjectRelease(iterator);
    return valid && hid_count == 1 && bulk_count == 1 && owner->hid_number != owner->bulk_number
               ? RDX_MACOS_STATUS_OK
               : RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
}

/** Requires HID ancestry to reach the exact HID interface before any USB parent. */
static bool rdx_rom_hid_parent(io_service_t service, RDXROMSession *owner) {
    io_service_t current = service;
    IOObjectRetain(current);
    bool matches = false;
    for (uint32_t depth = 0; depth < 16; depth++) {
        io_service_t next = IO_OBJECT_NULL;
        IOReturn status = IORegistryEntryGetParentEntry(current, kIOServicePlane, &next);
        rdx_rom_release_service(&current);
        current = next;
        if (status != kIOReturnSuccess || current == IO_OBJECT_NULL) { break; }
        if (IOObjectConformsTo(current, "IOUSBHostInterface")) {
            matches = IOObjectIsEqualTo(current, owner->hid_interface) &&
                      rdx_rom_direct_parent(current, owner->parent);
            break;
        }
        if (IOObjectConformsTo(current, "IOUSBHostDevice")) { break; }
    }
    rdx_rom_release_service(&current);
    return matches;
}

/** Selects the only IOHID service underneath the retained active HID interface. */
static rdx_macos_status rdx_rom_find_hid(RDXROMSession *owner) {
    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn status = IORegistryEntryCreateIterator(owner->hid_interface, kIOServicePlane,
                                                    kIORegistryIterateRecursively, &iterator);
    if (status != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        if (iterator != IO_OBJECT_NULL) { IOObjectRelease(iterator); }
        return rdx_status_from_io(status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    io_service_t candidate = IO_OBJECT_NULL;
    uint32_t count = 0, visited = 0;
    bool valid = true;
    while ((candidate = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        if (++visited > 128) {
            IOObjectRelease(candidate);
            valid = false;
            break;
        }
        if (IOObjectConformsTo(candidate, "IOHIDDevice")) {
            count++;
            if (count == 1 && rdx_rom_hid_parent(candidate, owner)) {
                owner->hid_service = candidate;
                candidate = IO_OBJECT_NULL;
            } else {
                valid = false;
            }
        }
        rdx_rom_release_service(&candidate);
    }
    valid = valid && IOIteratorIsValid(iterator);
    IOObjectRelease(iterator);
    return valid && count == 1 ? RDX_MACOS_STATUS_OK : RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
}

/** Validates cached active descriptors and the sole vendor bulk OUT endpoint 02. */
static bool rdx_rom_descriptors(const IOUSBConfigurationDescriptor *configuration,
                                const IOUSBInterfaceDescriptor *active, uint8_t hid_number,
                                uint8_t bulk_number, uint32_t value) {
    if (configuration == NULL || active == NULL || configuration->bLength != 9 ||
        configuration->bDescriptorType != 2 || configuration->bConfigurationValue != value ||
        active->bLength != 9 || active->bDescriptorType != 4 || active->bInterfaceClass != 255 ||
        active->bInterfaceNumber != bulk_number || active->bAlternateSetting != 0) {
        return false;
    }
    /* Check the entire cached stream before using SDK iterators, which stop at
     * malformed descriptors and could otherwise turn a bad tail into success. */
    const uint8_t *raw = (const uint8_t *)configuration;
    uint32_t total = (uint32_t)raw[2] | ((uint32_t)raw[3] << 8);
    if (total < 9 || total > 4096) { return false; }
    for (uint32_t offset = 9; offset < total;) {
        if (total - offset < 2 || raw[offset] < 2 || raw[offset] > total - offset ||
            (raw[offset + 1] == 4 && raw[offset] != 9) ||
            (raw[offset + 1] == 5 && raw[offset] < 7)) {
            return false;
        }
        offset += raw[offset];
    }
    uint32_t hid_count = 0, bulk_count = 0, visited = 0;
    const IOUSBInterfaceDescriptor *interface = NULL;
    const IOUSBDescriptorHeader *cursor = NULL;
    while ((interface = IOUSBGetNextInterfaceDescriptor(configuration, cursor)) != NULL) {
        cursor = (const IOUSBDescriptorHeader *)interface;
        if (++visited > 128) { return false; }
        if (interface->bInterfaceNumber == hid_number && interface->bAlternateSetting == 0) {
            if (interface->bInterfaceClass != 3) { return false; }
            hid_count++;
        }
        if (interface->bInterfaceNumber == bulk_number && interface->bAlternateSetting == 0) {
            if (memcmp(interface, active, sizeof(*active)) != 0) { return false; }
            bulk_count++;
        }
    }
    if (hid_count != 1 || bulk_count != 1) { return false; }
    uint32_t output_count = 0, endpoint_count = 0;
    const IOUSBEndpointDescriptor *endpoint = NULL;
    cursor = NULL;
    while ((endpoint = IOUSBGetNextEndpointDescriptor(configuration, active, cursor)) != NULL) {
        cursor = (const IOUSBDescriptorHeader *)endpoint;
        if (++endpoint_count > 32) { return false; }
        if (IOUSBGetEndpointAddress(endpoint) == 0x02) {
            if (IOUSBGetEndpointType(endpoint) != 2) { return false; }
            output_count++;
        }
    }
    return output_count == 1 && endpoint_count == active->bNumEndpoints;
}

/** Finds either the legacy sole global ROM or one explicitly selected parent epoch. */
static rdx_macos_status rdx_rom_find_bound_parent(uint32_t location, uint64_t selected_epoch,
                                                 io_service_t *output, rdx_rom_identity *identity) {
    if (selected_epoch == 0) { return rdx_rom_find_parent(location, output, identity); }
    rdx_macos_rom_candidate candidate = {selected_epoch, location, 0};
    rdx_macos_status status = rdx_rom_find_selected_parent(&candidate, output);
    if (status != RDX_MACOS_STATUS_OK) { return status; }
    if (!rdx_rom_copy_identity(*output, identity) || identity->registry_id != selected_epoch ||
        identity->location != location) {
        rdx_rom_release_service(output);
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    return RDX_MACOS_STATUS_OK;
}

/** Revalidates selected/legacy presence, registry generation and both exact parents. */
static rdx_macos_status rdx_rom_revalidate(RDXROMSession *owner) {
    io_service_t current = IO_OBJECT_NULL;
    rdx_rom_identity identity = {0};
    rdx_macos_status status = rdx_rom_find_bound_parent(owner->identity.location, owner->selected_epoch,
                                                       &current, &identity);
    if (status != RDX_MACOS_STATUS_OK) { return status; }
    bool matches = IOObjectIsEqualTo(current, owner->parent) &&
                   identity.registry_id == owner->identity.registry_id &&
                   identity.address == owner->identity.address &&
                   identity.configuration == owner->identity.configuration;
    rdx_rom_release_service(&current);
    uint8_t hid_number = 0, bulk_number = 0;
    io_service_t opened_hid = IOHIDDeviceGetService(owner->hid);
    matches =
        matches && opened_hid != IO_OBJECT_NULL &&
        IOObjectIsEqualTo(opened_hid, owner->hid_service) &&
        rdx_rom_hid_parent(opened_hid, owner) &&
        rdx_rom_interface_facts(owner->hid_interface, owner, 3, &hid_number) &&
        hid_number == owner->hid_number &&
        rdx_rom_interface_facts(owner.bulk.ioService, owner, 255, &bulk_number) &&
        bulk_number == owner->bulk_number &&
        IOObjectIsEqualTo(owner.bulk.ioService, owner->bulk_service) &&
        rdx_rom_descriptors(owner.bulk.configurationDescriptor, owner.bulk.interfaceDescriptor,
                            owner->hid_number, owner->bulk_number, owner->identity.configuration);
    return matches ? RDX_MACOS_STATUS_OK : RDX_MACOS_STATUS_DEVICE_REMOVED;
}

/** Maps only bounded native error codes; no hardware identity enters diagnostics. */
static rdx_macos_status rdx_rom_error(NSError *error, rdx_macos_status fallback) {
    rdx_macos_status status =
        error == nil ? fallback : rdx_status_from_io((IOReturn)(uint32_t)error.code, fallback);
    return status == RDX_MACOS_STATUS_OK ? fallback : status;
}

/** Opens exact active interfaces without firmware reports or configuration IO. */
static rdx_macos_status rdx_rom_open_owner(RDXROMSession *owner, uint32_t location,
                                          uint64_t selected_epoch) {
    owner->selected_epoch = selected_epoch;
    rdx_macos_status status = rdx_rom_find_bound_parent(location, selected_epoch,
                                                       &owner->parent, &owner->identity);
    if (status != RDX_MACOS_STATUS_OK) { return status; }
    status = rdx_rom_find_interfaces(owner);
    if (status != RDX_MACOS_STATUS_OK) { return status; }
    status = rdx_rom_find_hid(owner);
    if (status != RDX_MACOS_STATUS_OK) { return status; }
    NSError *error = nil;
    owner.bulk = [[IOUSBHostInterface alloc] initWithIOService:owner->bulk_service
                                                       options:IOUSBHostObjectInitOptionsNone
                                                         queue:nil
                                                         error:&error
                                               interestHandler:nil];
    if (owner.bulk == nil) { return rdx_rom_error(error, RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE); }
    if (!rdx_rom_descriptors(owner.bulk.configurationDescriptor, owner.bulk.interfaceDescriptor,
                             owner->hid_number, owner->bulk_number,
                             owner->identity.configuration)) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    owner.pipe = [owner.bulk copyPipeWithAddress:0x02 error:&error];
    if (owner.pipe == nil) { return rdx_rom_error(error, RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE); }
    owner->hid = IOHIDDeviceCreate(kCFAllocatorDefault, owner->hid_service);
    if (owner->hid == NULL) { return RDX_MACOS_STATUS_RESOURCE_LIMIT; }
    IOReturn io_status = IOHIDDeviceOpen(owner->hid, kIOHIDOptionsTypeNone);
    if (io_status != kIOReturnSuccess) {
        return rdx_status_from_io(io_status, RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE);
    }
    owner->hid_open = true;
    owner->run_loop = CFRunLoopGetCurrent();
    CFRetain(owner->run_loop);
    IOHIDDeviceScheduleWithRunLoop(owner->hid, owner->run_loop, rdx_rom_run_loop_mode);
    owner->scheduled = true;
    owner->thread = pthread_self();
    owner->next_command = RDX_ROM_IDENTIFY;
    return rdx_rom_revalidate(owner);
}

/** Owns one process-local ROM lease, blocking new leases after unknown callbacks. */
static rdx_macos_status rdx_rom_open_bound(uint32_t location_id, uint64_t selected_epoch,
                                           rdx_macos_rom_session **output) {
    if (output == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    *output = NULL;
    if (location_id == 0) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    bool expected = false;
    if (atomic_load(&rdx_rom_quarantined) ||
        !atomic_compare_exchange_strong(&rdx_rom_active, &expected, true)) {
        return RDX_MACOS_STATUS_BUSY;
    }
    /* A preceding owner may have quarantined between our first load and CAS. */
    if (atomic_load(&rdx_rom_quarantined)) {
        atomic_store(&rdx_rom_active, false);
        return RDX_MACOS_STATUS_BUSY;
    }
    rdx_macos_status status = RDX_MACOS_STATUS_NATIVE_FAILURE;
    @try {
        @autoreleasepool {
            RDXROMSession *owner = [[RDXROMSession alloc] init];
            if (owner == nil) {
                status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
            } else {
                status = rdx_rom_open_owner(owner, location_id, selected_epoch);
                if (status == RDX_MACOS_STATUS_OK) {
                    rdx_macos_rom_session *session = calloc(1, sizeof(*session));
                    if (session == NULL) {
                        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
                    } else {
                        session->retained_owner = (__bridge_retained void *)owner;
                        *output = session;
                    }
                }
                if (status != RDX_MACOS_STATUS_OK) { [owner close]; }
            }
        }
    } @catch (__unused NSException *exception) { status = RDX_MACOS_STATUS_NATIVE_FAILURE; }
    if (status != RDX_MACOS_STATUS_OK) { atomic_store(&rdx_rom_active, false); }
    return status;
}

/** Preserves the legacy sole-global-ROM boundary for existing location-only callers. */
rdx_macos_status rdx_macos_rom_open(uint32_t location_id, rdx_macos_rom_session **output) {
    return rdx_rom_open_bound(location_id, 0, output);
}

/** Opens only a complete previously observed candidate, never an unbound first match. */
rdx_macos_status rdx_macos_rom_open_selected(const rdx_macos_rom_candidate *candidate,
                                           rdx_macos_rom_session **output) {
    if (output == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    *output = NULL;
    if (candidate == NULL || candidate->location_id == 0 || candidate->registry_id == 0 ||
        candidate->reserved != 0) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    return rdx_rom_open_bound(candidate->location_id, candidate->registry_id, output);
}

/** Delivers native callback metadata without throwing or accessing caller buffers. */
static void rdx_rom_report_completed(void *context, IOReturn status, void *sender,
                                     IOHIDReportType type, uint32_t report_id, uint8_t *bytes,
                                     CFIndex length) {
    rdx_rom_report *report = context;
    report->status = status;
    report->actual = length;
    report->valid_metadata = sender == report->sender && type == report->type && report_id == 0 &&
                             bytes == report->bytes && length >= 0 &&
                             length <= (report->type == kIOHIDReportTypeFeature ? 2 : 9);
    atomic_store_explicit(&report->completed, true, memory_order_release);
}

/** Returns seconds from a monotonic clock so wall-time changes cannot extend IO. */
static double rdx_rom_now(void) {
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) { return -1; }
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

/** Admits only zero-ID feature GET or nine-byte ordinary setup/reset output. */
static bool rdx_rom_prepare_report(uint32_t command, IOHIDDeviceRef sender,
                                   rdx_rom_report *report) {
    memset(report, 0, sizeof(*report));
    atomic_init(&report->completed, false);
    report->sender = sender;
    if (command == RDX_ROM_IDENTIFY) {
        report->type = kIOHIDReportTypeFeature;
        report->length = 2;
        return true;
    }
    if (command != RDX_ROM_SETUP && command != RDX_ROM_RESET) { return false; }
    report->type = kIOHIDReportTypeOutput;
    report->length = 9;
    report->bytes[0] = command == RDX_ROM_SETUP ? 1 : 2;
    return true;
}

/** Checks exact response/report metadata; output success has no native byte count. */
static void rdx_rom_finish_report(const rdx_rom_report *report, rdx_macos_rom_result *result) {
    if (!report->valid_metadata) {
        result->status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        return;
    }
    result->status = rdx_status_from_io(report->status, RDX_MACOS_STATUS_NATIVE_FAILURE);
    if (report->type == kIOHIDReportTypeFeature) {
        result->transferred_known = 1;
        result->transferred = (uint32_t)report->actual;
        if (result->status == RDX_MACOS_STATUS_OK &&
            (report->actual != 2 || report->bytes[0] != 0x60 || report->bytes[1] != 0x92)) {
            result->status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        }
    } else if (result->status == RDX_MACOS_STATUS_OK) {
        /* IOHID output completion normally reports zero; as with HIDAPI, a
         * successful callback accepts the complete requested nine-byte report. */
        if (report->actual != 0 && report->actual != 9) {
            result->status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            return;
        }
        result->transferred_known = 1;
        result->transferred = 9;
    }
}

/** Performs one finite asynchronous IOHID request on the lease's private mode. */
static void rdx_rom_report_io(RDXROMSession *owner, uint32_t command, uint32_t timeout_ms,
                              rdx_macos_rom_result *result) {
    double now = rdx_rom_now();
    if (now < 0) {
        result->status = RDX_MACOS_STATUS_NATIVE_FAILURE;
        return;
    }
    owner->pending = calloc(1, sizeof(*owner->pending));
    if (owner->pending == NULL) {
        result->status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        return;
    }
    rdx_rom_report *report = owner->pending;
    if (!rdx_rom_prepare_report(command, owner->hid, report)) {
        result->status = RDX_MACOS_STATUS_INVALID_ARGUMENT;
        return;
    }
    double deadline = now + (double)timeout_ms / 1000.0;
    result->attempted = 1;
    result->transferred_known = 0;
    IOReturn status =
        command == RDX_ROM_IDENTIFY
            ? IOHIDDeviceGetReportWithCallback(
                  owner->hid, kIOHIDReportTypeFeature, 0, report->bytes, &report->length,
                  (CFTimeInterval)timeout_ms, rdx_rom_report_completed, report)
            : IOHIDDeviceSetReportWithCallback(owner->hid, kIOHIDReportTypeOutput, 0, report->bytes,
                                               9, (CFTimeInterval)timeout_ms,
                                               rdx_rom_report_completed, report);
    if (status != kIOReturnSuccess) {
        /* Conservatively retain even rejected submission storage; no callback
         * cancellation assumption is needed at this boundary. */
        result->status = rdx_status_from_io(status, RDX_MACOS_STATUS_NATIVE_FAILURE);
        return;
    }
    while (!atomic_load_explicit(&report->completed, memory_order_acquire)) {
        now = rdx_rom_now();
        double remaining = deadline - now;
        if (now < 0 || remaining <= 0) {
            result->status = RDX_MACOS_STATUS_TIMED_OUT;
            return;
        }
        SInt32 state =
            CFRunLoopRunInMode(rdx_rom_run_loop_mode, remaining < 0.05 ? remaining : 0.05, true);
        if ((state == kCFRunLoopRunFinished || state == kCFRunLoopRunStopped) &&
            !atomic_load_explicit(&report->completed, memory_order_acquire)) {
            result->status = RDX_MACOS_STATUS_NATIVE_FAILURE;
            return;
        }
    }
    rdx_rom_finish_report(report, result);
    free(report);
    owner->pending = NULL;
}

/** Preserves an OS-reported partial count on failure, rejecting impossible counts. */
static void rdx_rom_finish_bulk(bool succeeded, NSUInteger actual, uint32_t length,
                                rdx_macos_status failure, rdx_macos_rom_result *result) {
    result->status =
        succeeded ? RDX_MACOS_STATUS_OK
                  : (failure == RDX_MACOS_STATUS_OK ? RDX_MACOS_STATUS_NATIVE_FAILURE : failure);
    if (actual <= length) {
        result->transferred_known = 1;
        result->transferred = (uint32_t)actual;
    }
    if (succeeded && (actual != length || result->transferred_known != 1)) {
        result->status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
}

/** Sends one complete immutable image; never chunks, retries, or clears a stall. */
static void rdx_rom_program_io(RDXROMSession *owner, const uint8_t *bytes, uint32_t length,
                               uint32_t timeout_ms, rdx_macos_rom_result *result) {
    NSError *error = nil;
    NSMutableData *data = [owner.bulk ioDataWithCapacity:length error:&error];
    /* SDK IOUSBHostObject.h: IO-buffer length and capacity are immutable. */
    if (data == nil || data.length != length || data.mutableBytes == NULL) {
        result->status = rdx_rom_error(error, RDX_MACOS_STATUS_RESOURCE_LIMIT);
        return;
    }
    memcpy(data.mutableBytes, bytes, length);
    owner.programData = data;
    /* Sentinel distinguishes an absent count from a documented count of zero. */
    NSUInteger actual = NSUIntegerMax;
    result->attempted = 1;
    result->transferred_known = 0;
    /* Retain DMA storage if an exception prevents synchronous completion from
     * returning; close cannot infer that the underlying IO has stopped. */
    owner->program_in_flight = true;
    BOOL succeeded = [owner.pipe sendIORequestWithData:data
                                      bytesTransferred:&actual
                                     completionTimeout:(NSTimeInterval)timeout_ms / 1000.0
                                                 error:&error];
    owner->program_in_flight = false;
    owner.programData = nil;
    rdx_rom_finish_bulk(succeeded, actual, length,
                        rdx_rom_error(error, RDX_MACOS_STATUS_NATIVE_FAILURE), result);
}

/** Enforces state, bounded arguments and fresh exact-parent evidence for each IO. */
void rdx_macos_rom_execute(rdx_macos_rom_session *session, uint32_t command, const uint8_t *bytes,
                           uint32_t length, uint32_t timeout_ms, rdx_macos_rom_result *result) {
    if (result == NULL) { return; }
    *result = (rdx_macos_rom_result){RDX_MACOS_STATUS_INVALID_ARGUMENT, 0, 1, 0};
    if (session == NULL || session->retained_owner == NULL || timeout_ms == 0 ||
        timeout_ms > 120000 || command < RDX_ROM_IDENTIFY || command > RDX_ROM_RESET ||
        (command == RDX_ROM_PROGRAM && (bytes == NULL || length < 22 || length > 65535)) ||
        (command != RDX_ROM_PROGRAM && length != 0)) {
        return;
    }
    @try {
        @autoreleasepool {
            RDXROMSession *owner = (__bridge RDXROMSession *)session->retained_owner;
            if (!pthread_equal(owner->thread, pthread_self()) || owner->next_command != command ||
                owner->pending != NULL) {
                return;
            }
            owner->next_command = 0;
            result->status = rdx_rom_revalidate(owner);
            if (result->status != RDX_MACOS_STATUS_OK) { return; }
            if (command == RDX_ROM_PROGRAM) {
                rdx_rom_program_io(owner, bytes, length, timeout_ms, result);
            } else {
                rdx_rom_report_io(owner, command, timeout_ms, result);
            }
            if (result->status == RDX_MACOS_STATUS_OK) {
                owner->next_command = command == RDX_ROM_RESET ? 0 : command + 1;
            }
        }
    } @catch (__unused NSException *exception) { result->status = RDX_MACOS_STATUS_NATIVE_FAILURE; }
}

/** Releases without any implicit device IO; an unresolved callback keeps its owner. */
void rdx_macos_rom_release(rdx_macos_rom_session *session) {
    if (session == NULL) { return; }
    bool released = false;
    @try {
        @autoreleasepool {
            RDXROMSession *owner = (__bridge RDXROMSession *)session->retained_owner;
            if (owner == nil || (pthread_equal(owner->thread, pthread_self()) && [owner close])) {
                if (session->retained_owner != NULL) { CFRelease(session->retained_owner); }
                released = true;
            }
        }
    } @catch (__unused NSException *exception) {}
    if (!released) { atomic_store(&rdx_rom_quarantined, true); }
    free(session);
    atomic_store(&rdx_rom_active, false);
}

#if defined(RDX_MACOS_TEST_HOOKS)
/** Literal offline USB/HID fixtures exercise the production validation helpers. */
bool rdx_macos_rom_test_contract(void) {
    /* Deliberately varied interface numbers prove they are discovered, not fixed. */
    uint8_t descriptors[] = {9, 2, 41,  0, 2, 1, 0,    0x80, 50, 9, 4,  4, 0, 1,
                             3, 0, 0,   0, 7, 5, 0x81, 3,    8,  0, 1,  9, 4, 7,
                             0, 1, 255, 0, 0, 0, 7,    5,    2,  2, 64, 0, 0};
    const IOUSBConfigurationDescriptor *configuration = (const void *)descriptors;
    const IOUSBInterfaceDescriptor *interface = (const void *)(descriptors + 25);
    if (!rdx_rom_unique_location(1, 0x81200000, 0x81200000) ||
        rdx_rom_unique_location(2, 0x81200000, 0x81200000) ||
        rdx_rom_unique_location(0, 0x81200000, 0x81200000) ||
        rdx_rom_unique_location(1, 0x81200000, 0x81300000) ||
        !rdx_rom_descriptors(configuration, interface, 4, 7, 1)) {
        return false;
    }
    descriptors[36] = 0x82;
    if (rdx_rom_descriptors(configuration, interface, 4, 7, 1)) { return false; }
    descriptors[36] = 2;
    descriptors[37] = 3;
    if (rdx_rom_descriptors(configuration, interface, 4, 7, 1)) { return false; }
    descriptors[37] = 2;
    descriptors[28] = 1;
    if (rdx_rom_descriptors(configuration, interface, 4, 7, 1)) { return false; }
    descriptors[28] = 0;
    if (rdx_rom_descriptors(configuration, interface, 3, 7, 1) ||
        rdx_rom_descriptors(configuration, interface, 4, 7, 2)) {
        return false;
    }
    descriptors[18] = 0;
    if (rdx_rom_descriptors(configuration, interface, 4, 7, 1)) { return false; }
    descriptors[18] = 7;
    rdx_rom_report report;
    IOHIDDeviceRef sender = (IOHIDDeviceRef)(uintptr_t)1;
    for (uint32_t command = 1; command <= 4; command++) {
        bool accepted = rdx_rom_prepare_report(command, sender, &report);
        if (accepted != (command != 3)) { return false; }
        if (!accepted) { continue; }
        if (command == 1) {
            if (report.type != kIOHIDReportTypeFeature || report.length != 2) { return false; }
            report.bytes[0] = 0x60;
            report.bytes[1] = 0x92;
        } else {
            if (report.type != kIOHIDReportTypeOutput || report.length != 9 ||
                report.bytes[0] != (command == 2 ? 1 : 2)) {
                return false;
            }
            for (size_t index = 1; index < 9; index++) {
                if (report.bytes[index] != 0) { return false; }
            }
        }
        rdx_rom_report_completed(&report, kIOReturnSuccess, (void *)sender, report.type, 0,
                                 report.bytes, command == 1 ? 2 : 0);
        rdx_macos_rom_result result = {0, 1, 0, 0};
        rdx_rom_finish_report(&report, &result);
        if (!atomic_load(&report.completed) || result.status != 0 ||
            result.transferred_known != 1 || result.transferred != (command == 1 ? 2U : 9U)) {
            return false;
        }
        rdx_rom_report_completed(&report, kIOReturnSuccess, (void *)sender, report.type, 1,
                                 report.bytes, 2);
        result = (rdx_macos_rom_result){0, 1, 0, 0};
        rdx_rom_finish_report(&report, &result);
        if (result.status == 0) { return false; }
    }
    rdx_macos_rom_result partial = {0, 1, 0, 0};
    rdx_rom_finish_bulk(false, 7, 22, RDX_MACOS_STATUS_TIMED_OUT, &partial);
    if (partial.status != RDX_MACOS_STATUS_TIMED_OUT || partial.transferred_known != 1 ||
        partial.transferred != 7) {
        return false;
    }
    rdx_macos_rom_result missing = {0, 1, 0, 0};
    rdx_rom_finish_bulk(false, NSUIntegerMax, 22, RDX_MACOS_STATUS_TIMED_OUT, &missing);
    if (missing.transferred_known != 0) { return false; }
    rdx_macos_rom_result short_result = {0, 1, 0, 0};
    rdx_rom_finish_bulk(true, 21, 22, RDX_MACOS_STATUS_NATIVE_FAILURE, &short_result);
    if (short_result.status == 0 || short_result.transferred != 21) { return false; }
    /* A foreign feature identifier or a short report can never open the gate. */
    rdx_rom_prepare_report(RDX_ROM_IDENTIFY, sender, &report);
    report.bytes[0] = 0x60;
    report.bytes[1] = 0x93;
    rdx_rom_report_completed(&report, kIOReturnSuccess, (void *)sender, kIOHIDReportTypeFeature, 0,
                             report.bytes, 2);
    rdx_macos_rom_result foreign = {0, 1, 0, 0};
    rdx_rom_finish_report(&report, &foreign);
    if (foreign.status == 0) { return false; }
    report.bytes[1] = 0x92;
    rdx_rom_report_completed(&report, kIOReturnSuccess, (void *)sender, kIOHIDReportTypeFeature, 0,
                             report.bytes, 1);
    foreign = (rdx_macos_rom_result){0, 1, 0, 0};
    rdx_rom_finish_report(&report, &foreign);
    if (foreign.status == 0) { return false; }
    rdx_rom_prepare_report(RDX_ROM_SETUP, sender, &report);
    rdx_rom_report_completed(&report, kIOReturnSuccess, (void *)sender, kIOHIDReportTypeOutput, 0,
                             report.bytes, 8);
    rdx_macos_rom_result short_report = {0, 1, 0, 0};
    rdx_rom_finish_report(&report, &short_report);
    if (short_report.status == 0 || short_report.transferred_known != 0) { return false; }
    /* Exercise actual close policy with a late callback but no native handles. */
    @autoreleasepool {
        RDXROMSession *owner = [[RDXROMSession alloc] init];
        owner->pending = calloc(1, sizeof(*owner->pending));
        if (owner->pending == NULL) { return false; }
        rdx_rom_report *late = owner->pending;
        rdx_rom_prepare_report(RDX_ROM_SETUP, sender, late);
        if ([owner close] || owner->pending != late) { return false; }
        rdx_rom_report_completed(late, kIOReturnSuccess, (void *)sender, kIOHIDReportTypeOutput, 0,
                                 late->bytes, 0);
        if (![owner close] || owner->pending != NULL) { return false; }
        owner.programData = [NSMutableData dataWithLength:22];
        owner->program_in_flight = true;
        if ([owner close] || owner.programData.length != 22) { return false; }
        owner->program_in_flight = false;
        if (![owner close] || owner.programData != nil) { return false; }
    }
    return true;
}
#endif

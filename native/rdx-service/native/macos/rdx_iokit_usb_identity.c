// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

/** Reads one actual integral property with an explicit native width bound. */
static bool rdx_copy_usb_integer_property(
    io_service_t service,
    CFStringRef key,
    uint32_t maximum,
    uint32_t *output
) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0
    );
    int64_t value = 0;
    bool valid = property != NULL &&
        CFGetTypeID(property) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)property, kCFNumberSInt64Type, &value) &&
        value >= 0 && (uint64_t)value <= maximum;
    if (property != NULL) {
        CFRelease(property);
    }
    if (valid) {
        *output = (uint32_t)value;
    }
    return valid;
}

/** Reads a selected retained service's USB location and IDs without rematching. */
rdx_macos_status rdx_macos_copy_usb_identity(
    rdx_macos_device *device,
    uint32_t *location_id,
    uint16_t *vendor_id,
    uint16_t *product_id,
    char serial[RDX_MACOS_MAX_TEXT_BYTES + 1]
) {
    if (device == NULL || location_id == NULL || vendor_id == NULL ||
        product_id == NULL || serial == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *location_id = 0;
    *vendor_id = 0;
    *product_id = 0;
    serial[0] = '\0';
    rdx_macos_status status = rdx_revalidate_service(
        device->service, &device->expected
    );
    if (status != RDX_MACOS_STATUS_OK) {
        return status;
    }
    if (!rdx_copy_usb_ancestor_serial(device->service, serial)) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    io_registry_entry_t current = device->service;
    if (IOObjectRetain(current) != kIOReturnSuccess) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    while (current != IO_OBJECT_NULL) {
        if (IOObjectConformsTo(current, "IOUSBHostDevice")) {
            uint32_t location = 0, vendor = 0, product = 0;
            bool valid = rdx_copy_usb_integer_property(
                current, CFSTR("locationID"), UINT32_MAX, &location
            ) && rdx_copy_usb_integer_property(
                current, CFSTR("idVendor"), UINT16_MAX, &vendor
            ) && rdx_copy_usb_integer_property(
                current, CFSTR("idProduct"), UINT16_MAX, &product
            );
            IOObjectRelease(current);
            if (!valid) {
                return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
            }
            *location_id = location;
            *vendor_id = (uint16_t)vendor;
            *product_id = (uint16_t)product;
            return RDX_MACOS_STATUS_OK;
        }
        io_registry_entry_t parent = IO_OBJECT_NULL;
        IOReturn parent_status = IORegistryEntryGetParentEntry(
            current, kIOServicePlane, &parent
        );
        IOObjectRelease(current);
        current = parent_status == kIOReturnSuccess ? parent : IO_OBJECT_NULL;
    }
    return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
}

/** Copies a bounded printable serial property from one USB ancestor. */
static bool rdx_copy_usb_serial_property(
    io_service_t service,
    CFStringRef key,
    char output[RDX_MACOS_MAX_TEXT_BYTES + 1]
) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service,
        key,
        kCFAllocatorDefault,
        0
    );
    if (property == NULL || CFGetTypeID(property) != CFStringGetTypeID()) {
        if (property != NULL) {
            CFRelease(property);
        }
        return false;
    }
    bool valid = CFStringGetCString(
        (CFStringRef)property,
        output,
        RDX_MACOS_MAX_TEXT_BYTES + 1,
        kCFStringEncodingUTF8
    );
    CFRelease(property);
    if (!valid || output[0] == '\0') {
        return false;
    }
    for (size_t index = 0; output[index] != '\0'; ++index) {
        unsigned char value = (unsigned char)output[index];
        if (value < 0x20U || value > 0x7EU) {
            return false;
        }
    }
    return true;
}

/** Finds the selected SCSI service's unique USB-device ancestor serial. */
bool rdx_copy_usb_ancestor_serial(
    io_service_t service,
    char output[RDX_MACOS_MAX_TEXT_BYTES + 1]
) {
    output[0] = '\0';
    io_registry_entry_t current = service;
    if (current == IO_OBJECT_NULL ||
        IOObjectRetain(current) != kIOReturnSuccess) {
        return false;
    }
    while (current != IO_OBJECT_NULL) {
        if (IOObjectConformsTo(current, "IOUSBHostDevice")) {
            bool valid = rdx_copy_usb_serial_property(
                current,
                CFSTR("kUSBSerialNumberString"),
                output
            ) || rdx_copy_usb_serial_property(
                current,
                CFSTR("USB Serial Number"),
                output
            );
            IOObjectRelease(current);
            return valid;
        }
        io_registry_entry_t parent = IO_OBJECT_NULL;
        IOReturn status = IORegistryEntryGetParentEntry(
            current,
            kIOServicePlane,
            &parent
        );
        IOObjectRelease(current);
        current = status == kIOReturnSuccess ? parent : IO_OBJECT_NULL;
    }
    return false;
}

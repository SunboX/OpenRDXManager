// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#import <Foundation/Foundation.h>
#import <IOKit/usb/USBSpec.h>
#import <IOUSBHost/IOUSBHost.h>
#include <stdio.h>
#include <errno.h>
#import <unistd.h>

@interface RDXUSBHostLease : NSObject
@property(nonatomic, strong) IOUSBHostDevice *device;
@property(nonatomic, strong) IOUSBHostInterface *interface;
@property(nonatomic, strong) IOUSBHostPipe *bulkIn;
@property(nonatomic, strong) IOUSBHostPipe *bulkOut;
- (void)destroyWithDiagnostics:(BOOL)diagnostics;
@end

#if defined(RDX_MACOS_TEST_HOOKS)
enum {
    RDX_USB_RELEASE_BULK_IN = 1,
    RDX_USB_RELEASE_BULK_OUT = 2,
    RDX_USB_RELEASE_INTERFACE = 3,
    RDX_USB_RELEASE_DEVICE = 4
};
static _Thread_local uint8_t rdx_usb_release_events[4] = {0};
static _Thread_local uint8_t rdx_usb_release_event_count = 0;

/** Records one bounded synthetic USB-host release event. */
static void rdx_usb_record_release_event(uint8_t event) {
    if (rdx_usb_release_event_count < sizeof(rdx_usb_release_events)) {
        rdx_usb_release_events[rdx_usb_release_event_count++] = event;
    }
}
#else
#define rdx_usb_record_release_event(event) ((void)0)
#endif

@implementation RDXUSBHostLease

/** Destroys captured user clients in child-before-parent order. */
- (void)destroy {
    [self destroyWithDiagnostics:NO];
}

/** Destroys captured user clients with optional closed release breadcrumbs. */
- (void)destroyWithDiagnostics:(BOOL)diagnostics {
#if defined(RDX_MACOS_TEST_HOOKS)
    extern bool rdx_macos_test_raise_on_usb_host_destroy;
    if (rdx_macos_test_raise_on_usb_host_destroy) {
        rdx_macos_test_raise_on_usb_host_destroy = false;
        [NSException raise:@"OpenRDXBoundaryTest"
                    format:@"expected lease-release exception"];
    }
#endif
    rdx_usb_record_release_event(RDX_USB_RELEASE_BULK_IN);
    _bulkIn = nil;
    rdx_usb_record_release_event(RDX_USB_RELEASE_BULK_OUT);
    _bulkOut = nil;
    if (diagnostics) {
        fputs("openrdx-hardware: trace usb-release-pipes-return\n", stderr);
    }
    rdx_usb_record_release_event(RDX_USB_RELEASE_INTERFACE);
    if (diagnostics) {
        fputs("openrdx-hardware: trace usb-release-interface-enter\n", stderr);
    }
    @try {
        [_interface destroy];
    } @catch (__unused NSException *exception) {
    }
    _interface = nil;
    if (diagnostics) {
        fputs("openrdx-hardware: trace usb-release-interface-return\n", stderr);
    }
    rdx_usb_record_release_event(RDX_USB_RELEASE_DEVICE);
    if (diagnostics) {
        fputs("openrdx-hardware: trace usb-release-device-enter\n", stderr);
    }
    @try {
        [_device destroy];
    } @catch (__unused NSException *exception) {
    }
    _device = nil;
    if (diagnostics) {
        fputs("openrdx-hardware: trace usb-release-device-return\n", stderr);
    }
}

/** Preserves the reset-and-rematch contract if a caller misses explicit release. */
- (void)dealloc {
    [self destroy];
}

@end

struct rdx_macos_usb_bot_lease {
    void *retained_owner;
};

/** Converts an IOUSBHost NSError into the bridge's bounded status vocabulary. */
static rdx_macos_status rdx_usb_status_from_error(
    NSError *error,
    rdx_macos_status fallback
) {
    if (error == nil) {
        return fallback;
    }
    return rdx_status_from_io((IOReturn)(uint32_t)error.code, fallback);
}

/** Classifies only exact SDK domains, without exposing an NSError string. */
static uint8_t rdx_interface_error_domain(NSError *error) {
    if (error == nil) { return 0; }
    if (![(id)error isKindOfClass:[NSError class]]) { return 5; }
    NSString *domain = error.domain;
    if (![(id)domain isKindOfClass:[NSString class]] || domain.length > 64) { return 4; }
    if ([domain isEqualToString:IOUSBHostErrorDomain]) { return 1; }
    if ([domain isEqualToString:NSPOSIXErrorDomain]) { return 2; }
    if ([domain isEqualToString:NSCocoaErrorDomain]) { return 3; }
    if ([domain isEqualToString:NSMachErrorDomain]) { return 6; }
    return 4;
}

/** Maps numeric values only in their recognized namespace; unknown/Mach/Cocoa stay unknown. */
static uint8_t rdx_interface_error_code(NSError *error, uint8_t domain) {
    if (domain == 0) { return 0; }
    if (domain == 2) {
        switch (error.code) {
            case EACCES: case EPERM: return 21;
            case ENOENT: return 22;
            case EBADF: return 23;
            default: return 1;
        }
    }
    if (domain != 1 || error.code < INT32_MIN || ((uint64_t)error.code > UINT32_MAX && error.code >= 0)) { return 1; }
    switch ((uint32_t)error.code) {
        case (uint32_t)kIOReturnNotReady: return 2;
        case (uint32_t)kIOReturnNotAttached: return 3;
        case (uint32_t)kIOReturnNotFound: return 4;
        case (uint32_t)kIOReturnOffline: return 5;
        case (uint32_t)kIOReturnBadArgument: return 6;
        case (uint32_t)kIOReturnNoResources: return 7;
        case (uint32_t)kIOReturnIPCError: return 8;
        case (uint32_t)kIOReturnInternalError: return 9;
        case (uint32_t)kIOReturnIOError: return 10;
        case (uint32_t)kIOReturnError: return 11;
        case (uint32_t)kIOReturnNotPrivileged: return 12;
        case (uint32_t)kIOReturnBusy: return 13;
        case (uint32_t)kIOReturnExclusiveAccess: return 14;
        case (uint32_t)kIOReturnTimeout: return 15;
        case (uint32_t)kIOReturnNoDevice: return 16;
        case (uint32_t)kIOReturnNotOpen: return 17;
        case (uint32_t)kIOReturnUnsupported: return 18;
        case (uint32_t)kIOReturnNotPermitted: return 19;
        case (uint32_t)kIOReturnNoMemory: return 20;
        default: return 1;
    }
}

/** Reads only one bounded reason string and one underlying object; never traverses recursively. */
static rdx_interface_error_evidence rdx_interface_evidence(NSError *error) {
    rdx_interface_error_evidence evidence = {0};
    @try {
    evidence.domain = rdx_interface_error_domain(error);
    evidence.code = rdx_interface_error_code(error, evidence.domain);
    if (evidence.domain == 0) { return evidence; }
    if (evidence.domain == 5) { evidence.reason = 4; return evidence; }
    id reason = error.userInfo[NSLocalizedFailureReasonErrorKey];
    if (reason == nil) { evidence.reason = 0; }
    else if (![reason isKindOfClass:[NSString class]] || [(NSString *)reason length] > 128) { evidence.reason = 4; }
    else if ([(NSString *)reason isEqualToString:@"Failed [super init]"]) { evidence.reason = 1; }
    else if ([(NSString *)reason isEqualToString:@"IOServiceOpen failed"] ||
             [(NSString *)reason isEqualToString:@"IOServiceOpen failed."]) { evidence.reason = 2; }
    else { evidence.reason = 3; }
    id underlying = error.userInfo[NSUnderlyingErrorKey];
    evidence.under_domain = rdx_interface_error_domain(underlying);
    evidence.under_code = rdx_interface_error_code(underlying, evidence.under_domain);
    return evidence;
    } @catch (__unused NSException *exception) {
        // Diagnostic extraction cannot replace the already-computed transport result.
        return (rdx_interface_error_evidence){.domain = 5, .code = 1, .reason = 4};
    }
}

/** Calls the single fixed interface initializer through a private class seam for native tests. */
static rdx_macos_status rdx_usb_initialize_interface(
    RDXUSBHostLease *owner, io_service_t service, Class interface_class, NSError **shared_error,
    rdx_interface_error_evidence *out_evidence
) {
    NSError *fresh_error = nil;
    owner.interface = [[interface_class alloc]
        initWithIOService:service options:IOUSBHostObjectInitOptionsNone
        queue:nil error:&fresh_error interestHandler:nil];
    // Preserve the legacy shared-slot fallback independently from current-call evidence.
    if (fresh_error != nil) { *shared_error = fresh_error; }
    rdx_macos_status status = owner.interface == nil ?
        rdx_usb_status_from_error(*shared_error, RDX_MACOS_STATUS_NATIVE_FAILURE) :
        RDX_MACOS_STATUS_OK;
    if (owner.interface == nil) {
        *out_evidence = rdx_interface_evidence(fresh_error);
        out_evidence->status = status;
        rdx_record_interface_error_evidence(out_evidence);
    }
    return status;
}

/** Copies one exact CFNumber property from an IOKit service. */
static bool rdx_usb_copy_u32(
    io_service_t service,
    CFStringRef key,
    uint32_t *output
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
    int32_t value = -1;
    bool valid = CFGetTypeID(property) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)property, kCFNumberSInt32Type, &value) &&
        value >= 0;
    CFRelease(property);
    if (valid) {
        *output = (uint32_t)value;
    }
    return valid;
}

/** Copies one printable, bounded IOKit string property. */
static bool rdx_usb_copy_text(
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

/** Finds the single USB device ancestor retained by the selected SCSI service. */
static rdx_macos_status rdx_usb_find_device_ancestor(
    io_service_t scsi_service,
    io_service_t *out_device
) {
    *out_device = IO_OBJECT_NULL;
    io_registry_entry_t current = scsi_service;
    if (IOObjectRetain(current) != kIOReturnSuccess) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    while (current != IO_OBJECT_NULL) {
        if (IOObjectConformsTo(current, "IOUSBHostDevice")) {
            *out_device = current;
            return RDX_MACOS_STATUS_OK;
        }
        io_registry_entry_t parent = IO_OBJECT_NULL;
        IOReturn status = IORegistryEntryGetParentEntry(
            current,
            kIOServicePlane,
            &parent
        );
        IOObjectRelease(current);
        current = IO_OBJECT_NULL;
        if (status != kIOReturnSuccess || parent == IO_OBJECT_NULL) {
            return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        }
        current = parent;
    }
    return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
}

/** Validates the stable USB identity before terminating the storage driver. */
static bool rdx_usb_identity_matches(
    io_service_t usb_service,
    const rdx_macos_candidate_record *expected
) {
    uint32_t vendor_id = 0;
    uint32_t product_id = 0;
    char serial[RDX_MACOS_MAX_TEXT_BYTES + 1] = {0};
    char vendor[RDX_MACOS_MAX_TEXT_BYTES + 1] = {0};
    char product[RDX_MACOS_MAX_TEXT_BYTES + 1] = {0};
    if (!rdx_usb_copy_u32(usb_service, CFSTR(kUSBVendorID), &vendor_id) ||
        !rdx_usb_copy_u32(usb_service, CFSTR(kUSBProductID), &product_id) ||
        vendor_id == 0 || product_id == 0 ||
        !rdx_usb_copy_text(usb_service, CFSTR(kUSBSerialNumberString), serial) ||
        !rdx_usb_copy_text(usb_service, CFSTR("kUSBVendorString"), vendor) ||
        !rdx_usb_copy_text(usb_service, CFSTR("kUSBProductString"), product)) {
        return false;
    }
    if (expected->has_vendor != 0 && strcasecmp(vendor, expected->vendor) != 0) {
        return false;
    }
    if (expected->has_product != 0 && strcasecmp(product, expected->product) != 0) {
        return false;
    }
    return expected->has_serial == 0 || strcasecmp(serial, expected->serial) == 0;
}

/** Finds exactly one configured mass-storage BOT interface below the capture. */
static rdx_macos_status rdx_usb_find_bot_interface(
    io_service_t usb_service,
    io_service_t *out_interface
) {
    *out_interface = IO_OBJECT_NULL;
    io_iterator_t iterator = IO_OBJECT_NULL;
    kern_return_t status = IORegistryEntryCreateIterator(
        usb_service,
        kIOServicePlane,
        kIORegistryIterateRecursively,
        &iterator
    );
    if (status != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        return rdx_status_from_io(status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    io_service_t candidate = IO_OBJECT_NULL;
    uint32_t count = 0;
    while ((candidate = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        uint32_t interface_class = 0;
        uint32_t interface_subclass = 0;
        uint32_t interface_protocol = 0;
        bool matches = IOObjectConformsTo(candidate, "IOUSBHostInterface") &&
            rdx_usb_copy_u32(candidate, CFSTR("bInterfaceClass"), &interface_class) &&
            rdx_usb_copy_u32(candidate, CFSTR("bInterfaceSubClass"), &interface_subclass) &&
            rdx_usb_copy_u32(candidate, CFSTR("bInterfaceProtocol"), &interface_protocol) &&
            interface_class == 8 && interface_subclass == 6 &&
            interface_protocol == 0x50;
        if (matches) {
            count += 1;
            if (count == 1) {
                *out_interface = candidate;
                candidate = IO_OBJECT_NULL;
            }
        }
        if (candidate != IO_OBJECT_NULL) {
            IOObjectRelease(candidate);
        }
    }
    IOObjectRelease(iterator);
    if (count != 1) {
        if (*out_interface != IO_OBJECT_NULL) {
            IOObjectRelease(*out_interface);
            *out_interface = IO_OBJECT_NULL;
        }
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    return RDX_MACOS_STATUS_OK;
}

/** Opens exactly one bulk-IN and one bulk-OUT endpoint from the BOT interface. */
static rdx_macos_status rdx_usb_open_bulk_pipes(
    RDXUSBHostLease *owner,
    NSError **out_error,
    rdx_acquisition_stage *stage
) {
    *stage = RDX_ACQUIRE_USB_PIPE_DESCRIPTORS;
    const IOUSBConfigurationDescriptor *configuration =
        owner.interface.configurationDescriptor;
    const IOUSBInterfaceDescriptor *interface = owner.interface.interfaceDescriptor;
    if (configuration == NULL || interface == NULL ||
        interface->bInterfaceClass != 8 || interface->bInterfaceSubClass != 6 ||
        interface->bInterfaceProtocol != 0x50) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    uint8_t input_address = 0;
    uint8_t output_address = 0;
    uint32_t input_count = 0;
    uint32_t output_count = 0;
    const IOUSBDescriptorHeader *cursor = NULL;
    const IOUSBEndpointDescriptor *endpoint = NULL;
    while ((endpoint = IOUSBGetNextEndpointDescriptor(
                configuration,
                interface,
                cursor
            )) != NULL) {
        cursor = (const IOUSBDescriptorHeader *)endpoint;
        if (IOUSBGetEndpointType(endpoint) != 2) {
            continue;
        }
        uint8_t address = IOUSBGetEndpointAddress(endpoint);
        if ((address & 0x80U) != 0) {
            input_count += 1;
            input_address = address;
        } else {
            output_count += 1;
            output_address = address;
        }
    }
    *stage = RDX_ACQUIRE_USB_PIPE_ENDPOINTS;
    if (input_count != 1 || output_count != 1) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    *stage = RDX_ACQUIRE_USB_PIPE_IN;
    owner.bulkIn = [owner.interface copyPipeWithAddress:input_address error:out_error];
    if (owner.bulkIn == nil) {
        return rdx_usb_status_from_error(*out_error, RDX_MACOS_STATUS_NATIVE_FAILURE);
    }
    *stage = RDX_ACQUIRE_USB_PIPE_OUT;
    owner.bulkOut = [owner.interface copyPipeWithAddress:output_address error:out_error];
    if (owner.bulkOut == nil) {
        return rdx_usb_status_from_error(*out_error, RDX_MACOS_STATUS_NATIVE_FAILURE);
    }
    return RDX_MACOS_STATUS_OK;
}

/** Captures the exact USB ancestor and opens its only BOT transport. */
rdx_macos_status rdx_macos_usb_bot_acquire(
    io_service_t scsi_service,
    const rdx_macos_candidate_record *expected,
    rdx_macos_usb_bot_lease **out_lease
) {
    if (expected == NULL || out_lease == NULL || scsi_service == IO_OBJECT_NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_lease = NULL;
    if (geteuid() != 0) {
        rdx_record_acquisition_diagnostic(RDX_ACQUIRE_USB_AUTHORITY,
            RDX_MACOS_STATUS_ACCESS_DENIED, RDX_ACQUIRE_CODE_NONE, 0);
        return RDX_MACOS_STATUS_ACCESS_DENIED;
    }
    @autoreleasepool {
        rdx_macos_status status = RDX_MACOS_STATUS_NATIVE_FAILURE;
        io_service_t usb_service = IO_OBJECT_NULL;
        io_service_t interface_service = IO_OBJECT_NULL;
        RDXUSBHostLease *owner = [[RDXUSBHostLease alloc] init];
        NSError *error = nil;
        rdx_interface_error_evidence interface_evidence = {0};
        rdx_acquisition_stage stage = RDX_ACQUIRE_USB_ANCESTOR;
        @try {
            status = rdx_usb_find_device_ancestor(scsi_service, &usb_service);
            if (status != RDX_MACOS_STATUS_OK) {
                goto cleanup;
            }
            stage = RDX_ACQUIRE_USB_IDENTITY;
            if (!rdx_usb_identity_matches(usb_service, expected)) {
                status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
                goto cleanup;
            }
            stage = RDX_ACQUIRE_USB_CAPTURE;
            owner.device = [[IOUSBHostDevice alloc]
                initWithIOService:usb_service
                            options:IOUSBHostObjectInitOptionsDeviceCapture
                              queue:nil
                              error:&error
                    interestHandler:nil];
            if (owner.device == nil) {
                status = rdx_usb_status_from_error(
                    error,
                    RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE
                );
                goto cleanup;
            }
            stage = RDX_ACQUIRE_USB_CONFIGURE;
            if (![owner.device configureWithValue:1 matchInterfaces:NO error:&error]) {
                status = rdx_usb_status_from_error(error, RDX_MACOS_STATUS_NATIVE_FAILURE);
                goto cleanup;
            }
            stage = RDX_ACQUIRE_USB_FIND_INTERFACE;
            status = rdx_usb_find_bot_interface(usb_service, &interface_service);
            if (status != RDX_MACOS_STATUS_OK) {
                goto cleanup;
            }
            stage = RDX_ACQUIRE_USB_OPEN_INTERFACE;
            status = rdx_usb_initialize_interface(owner, interface_service, [IOUSBHostInterface class],
                &error, &interface_evidence);
            if (owner.interface == nil) {
                goto cleanup;
            }
            status = rdx_usb_open_bulk_pipes(owner, &error, &stage);
            if (status != RDX_MACOS_STATUS_OK) {
                goto cleanup;
            }
            stage = RDX_ACQUIRE_USB_ALLOCATION;
            rdx_macos_usb_bot_lease *lease = calloc(1, sizeof(*lease));
            if (lease == NULL) {
                status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
                goto cleanup;
            }
            lease->retained_owner = (__bridge_retained void *)owner;
            *out_lease = lease;
            owner = nil;
            status = RDX_MACOS_STATUS_OK;

    cleanup:
            if (status != RDX_MACOS_STATUS_OK) {
                /* Record before capture destruction can terminate the process. */
                bool has_error = error != nil &&
                    (stage == RDX_ACQUIRE_USB_CAPTURE || stage == RDX_ACQUIRE_USB_CONFIGURE ||
                     stage == RDX_ACQUIRE_USB_OPEN_INTERFACE || stage == RDX_ACQUIRE_USB_PIPE_IN ||
                     stage == RDX_ACQUIRE_USB_PIPE_OUT);
                rdx_record_acquisition_diagnostic(stage, status,
                    has_error ? RDX_ACQUIRE_CODE_NSERROR : RDX_ACQUIRE_CODE_NONE,
                    has_error ? (int64_t)error.code : 0);
            }
            if (interface_service != IO_OBJECT_NULL) {
                IOObjectRelease(interface_service);
            }
            if (usb_service != IO_OBJECT_NULL) {
                IOObjectRelease(usb_service);
            }
            [owner destroy];
            return status;
        } @catch (__unused NSException *exception) {
            rdx_record_acquisition_diagnostic(RDX_ACQUIRE_USB_EXCEPTION,
                RDX_MACOS_STATUS_NATIVE_FAILURE, RDX_ACQUIRE_CODE_NONE, 0);
            if (interface_service != IO_OBJECT_NULL) {
                IOObjectRelease(interface_service);
            }
            if (usb_service != IO_OBJECT_NULL) {
                IOObjectRelease(usb_service);
            }
            [owner destroy];
            return RDX_MACOS_STATUS_NATIVE_FAILURE;
        }
    }
}

/** Releases capture and triggers Apple's storage-driver reset and rematch. */
void rdx_macos_usb_bot_release(rdx_macos_usb_bot_lease *lease) {
    if (lease == NULL) {
        return;
    }
    void *retained_owner = lease->retained_owner;
    lease->retained_owner = NULL;
    @try {
        @autoreleasepool {
            fputs("openrdx-hardware: trace usb-release-bridge-enter\n", stderr);
            RDXUSBHostLease *owner =
                (__bridge_transfer RDXUSBHostLease *)retained_owner;
            fputs("openrdx-hardware: trace usb-release-bridge-return\n", stderr);
            [owner destroyWithDiagnostics:YES];
        }
        fputs("openrdx-hardware: trace usb-release-pool-return\n", stderr);
    } @catch (__unused NSException *exception) {
        /* Neither explicit IOUSBHost teardown nor autorelease-pool cleanup may
         * unwind through the C ABI into Rust. Process exit remains the final
         * release for a framework object that rejected deterministic teardown. */
    }
    fputs("openrdx-hardware: trace usb-release-lease-free-enter\n", stderr);
    free(lease);
    fputs("openrdx-hardware: trace usb-release-lease-free-return\n", stderr);
}

/** Performs one bounded synchronous transfer through the selected bulk pipe. */
rdx_macos_status rdx_macos_usb_bot_transfer(
    rdx_macos_usb_bot_lease *lease,
    bool input,
    uint8_t *bytes,
    uint32_t length,
    uint32_t timeout_ms,
    uint32_t *transferred,
    bool *stalled
) {
    if (lease == NULL || lease->retained_owner == NULL || bytes == NULL ||
        length == 0 || length > RDX_MACOS_MAX_TRANSFER_BYTES ||
        timeout_ms == 0 || timeout_ms > 300000 || transferred == NULL ||
        stalled == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *transferred = 0;
    *stalled = false;
    @try {
        @autoreleasepool {
#if defined(RDX_MACOS_TEST_HOOKS)
            extern bool rdx_macos_test_raise_before_usb_transfer_try;
            if (rdx_macos_test_raise_before_usb_transfer_try) {
                rdx_macos_test_raise_before_usb_transfer_try = false;
                [NSException raise:@"OpenRDXBoundaryTest"
                            format:@"expected transfer exception"];
            }
#endif
            @try {
                RDXUSBHostLease *owner = (__bridge RDXUSBHostLease *)lease->retained_owner;
                NSError *error = nil;
                NSMutableData *data = [owner.interface ioDataWithCapacity:length error:&error];
                if (data == nil) {
                    return rdx_usb_status_from_error(error, RDX_MACOS_STATUS_RESOURCE_LIMIT);
                }
                if (!input) {
                    memcpy(data.mutableBytes, bytes, length);
                }
                NSUInteger actual = 0;
                IOUSBHostPipe *pipe = input ? owner.bulkIn : owner.bulkOut;
                BOOL succeeded = [pipe
                    sendIORequestWithData:data
                         bytesTransferred:&actual
                        completionTimeout:(NSTimeInterval)timeout_ms / 1000.0
                                    error:&error];
                if (!succeeded) {
                    IOReturn io_status = (IOReturn)(uint32_t)error.code;
                    *stalled = io_status == kUSBHostReturnPipeStalled;
                    return rdx_status_from_io(io_status, RDX_MACOS_STATUS_NATIVE_FAILURE);
                }
                if (actual > length || actual > UINT32_MAX) {
                    return RDX_MACOS_STATUS_NATIVE_FAILURE;
                }
                if (input && actual > 0) {
                    memcpy(bytes, data.bytes, actual);
                }
                *transferred = (uint32_t)actual;
                return RDX_MACOS_STATUS_OK;
            } @catch (__unused NSException *exception) {
                return RDX_MACOS_STATUS_NATIVE_FAILURE;
            }
        }
    } @catch (__unused NSException *exception) {
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
}

/** Clears one halted bulk-IN endpoint for the BOT CSW recovery rule. */
rdx_macos_status rdx_macos_usb_bot_clear_in_stall(
    rdx_macos_usb_bot_lease *lease
) {
    if (lease == NULL || lease->retained_owner == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    @try {
        @autoreleasepool {
#if defined(RDX_MACOS_TEST_HOOKS)
            extern bool rdx_macos_test_raise_before_usb_clear_stall_try;
            if (rdx_macos_test_raise_before_usb_clear_stall_try) {
                rdx_macos_test_raise_before_usb_clear_stall_try = false;
                [NSException raise:@"OpenRDXBoundaryTest"
                            format:@"expected clear-stall exception"];
            }
#endif
            @try {
                RDXUSBHostLease *owner = (__bridge RDXUSBHostLease *)lease->retained_owner;
                NSError *error = nil;
                if (![owner.bulkIn clearStallWithError:&error]) {
                    return rdx_usb_status_from_error(error, RDX_MACOS_STATUS_NATIVE_FAILURE);
                }
                return RDX_MACOS_STATUS_OK;
            } @catch (__unused NSException *exception) {
                return RDX_MACOS_STATUS_NATIVE_FAILURE;
            }
        }
    } @catch (__unused NSException *exception) {
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
}

#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_macos_test_raise_on_usb_host_destroy = false;
bool rdx_macos_test_raise_before_usb_transfer_try = false;
bool rdx_macos_test_raise_before_usb_clear_stall_try = false;

bool rdx_macos_test_usb_host_exception_contract(void) {
    rdx_macos_usb_bot_lease *lease = calloc(1, sizeof(*lease));
    if (lease == NULL) {
        return false;
    }
    @autoreleasepool {
        RDXUSBHostLease *owner = [[RDXUSBHostLease alloc] init];
        lease->retained_owner = (__bridge_retained void *)owner;
    }
    rdx_macos_test_raise_on_usb_host_destroy = true;
    rdx_macos_usb_bot_release(lease);
    bool release_contained = !rdx_macos_test_raise_on_usb_host_destroy;

    rdx_macos_usb_bot_lease transfer_lease = {
        .retained_owner = (void *)(uintptr_t)1
    };
    uint8_t byte = 0;
    uint32_t transferred = 0;
    bool stalled = false;
    bool transfer_exception_crossed = false;
    rdx_macos_status transfer_status = RDX_MACOS_STATUS_OK;
    rdx_macos_test_raise_before_usb_transfer_try = true;
    @try {
        transfer_status = rdx_macos_usb_bot_transfer(
            &transfer_lease,
            true,
            &byte,
            1,
            1000,
            &transferred,
            &stalled
        );
    } @catch (__unused NSException *exception) {
        transfer_exception_crossed = true;
    }

    bool clear_exception_crossed = false;
    rdx_macos_status clear_status = RDX_MACOS_STATUS_OK;
    rdx_macos_test_raise_before_usb_clear_stall_try = true;
    @try {
        clear_status = rdx_macos_usb_bot_clear_in_stall(&transfer_lease);
    } @catch (__unused NSException *exception) {
        clear_exception_crossed = true;
    }
    return release_contained && !rdx_macos_test_raise_before_usb_transfer_try &&
        !rdx_macos_test_raise_before_usb_clear_stall_try &&
        !transfer_exception_crossed && !clear_exception_crossed &&
        transfer_status == RDX_MACOS_STATUS_NATIVE_FAILURE &&
        clear_status == RDX_MACOS_STATUS_NATIVE_FAILURE;
}

bool rdx_macos_test_usb_host_release_order_contract(void) {
    rdx_usb_release_event_count = 0;
    memset(rdx_usb_release_events, 0, sizeof(rdx_usb_release_events));
    @autoreleasepool {
        RDXUSBHostLease *owner = [[RDXUSBHostLease alloc] init];
        [owner destroy];
    }
    return rdx_usb_release_event_count == 4 &&
        rdx_usb_release_events[0] == RDX_USB_RELEASE_BULK_IN &&
        rdx_usb_release_events[1] == RDX_USB_RELEASE_BULK_OUT &&
        rdx_usb_release_events[2] == RDX_USB_RELEASE_INTERFACE &&
        rdx_usb_release_events[3] == RDX_USB_RELEASE_DEVICE;
}
#endif

#if defined(RDX_MACOS_TEST_HOOKS)
static _Thread_local unsigned int rdx_interface_stub_calls;
static _Thread_local bool rdx_interface_stub_fresh_slot;
static _Thread_local unsigned int rdx_interface_stub_mode;
static _Thread_local unsigned int rdx_interface_lifetime_tick;
static _Thread_local unsigned int rdx_interface_destroy_tick;
static _Thread_local unsigned int rdx_interface_dealloc_tick;
static _Thread_local unsigned int rdx_parent_destroy_tick;
static _Thread_local unsigned int rdx_parent_dealloc_tick;

/** Test-only NSError whose metadata throws after its legacy numeric status is computed. */
@interface RDXInterfaceMetadataException : NSError
@end
@implementation RDXInterfaceMetadataException
/** Exercises evidence isolation without touching a native user client. */
- (NSString *)domain {
    @throw [NSException exceptionWithName:NSInternalInconsistencyException reason:@"test-only" userInfo:nil];
}
@end

@interface RDXInterfaceConstructorStub : NSObject
- (instancetype)initWithIOService:(io_service_t)service options:(IOUSBHostObjectInitOptions)options
    queue:(dispatch_queue_t)queue error:(NSError **)error
    interestHandler:(IOUSBHostInterestHandler)interest_handler;
@end
@implementation RDXInterfaceConstructorStub
/** Returns nil without supplying an error, matching a hardware-free failure boundary. */
- (instancetype)initWithIOService:(io_service_t)service options:(IOUSBHostObjectInitOptions)options
    queue:(dispatch_queue_t)queue error:(NSError **)error
    interestHandler:(IOUSBHostInterestHandler)interest_handler {
    rdx_interface_stub_calls += 1;
    rdx_interface_stub_fresh_slot = service == IO_OBJECT_NULL &&
        options == IOUSBHostObjectInitOptionsNone && queue == nil && interest_handler == nil &&
        error != NULL && *error == nil;
    if (rdx_interface_stub_mode == 1) {
        NSError *under = [NSError errorWithDomain:NSPOSIXErrorDomain code:EACCES userInfo:nil];
        *error = [NSError errorWithDomain:IOUSBHostErrorDomain code:(NSInteger)kIOReturnInternalError
            userInfo:@{NSLocalizedFailureReasonErrorKey: @"Failed [super init]", NSUnderlyingErrorKey: under}];
    }
    if (rdx_interface_stub_mode >= 3) {
        NSDictionary *info = nil;
        NSString *domain = IOUSBHostErrorDomain;
        if (rdx_interface_stub_mode == 3) { info = @{NSLocalizedFailureReasonErrorKey: @42}; }
        if (rdx_interface_stub_mode == 4) { info = @{NSLocalizedFailureReasonErrorKey:
            [@"x" stringByPaddingToLength:129 withString:@"x" startingAtIndex:0]}; }
        if (rdx_interface_stub_mode == 5) { info = @{NSUnderlyingErrorKey: @42}; }
        if (rdx_interface_stub_mode == 6) { info = @{NSUnderlyingErrorKey:
            [NSError errorWithDomain:IOUSBHostErrorDomain code:(NSInteger)kIOReturnNotReady
                userInfo:@{NSUnderlyingErrorKey: @42}]}; }
        if (rdx_interface_stub_mode == 7) { domain = NSPOSIXErrorDomain; }
        if (rdx_interface_stub_mode == 8) { domain = NSMachErrorDomain; }
        if (rdx_interface_stub_mode == 9) { domain = NSCocoaErrorDomain; }
        if (rdx_interface_stub_mode == 10) { domain = @"/private/do-not-export";
            info = @{NSLocalizedFailureReasonErrorKey: @"/private/do-not-export"}; }
        *error = rdx_interface_stub_mode == 11 ?
            [[RDXInterfaceMetadataException alloc] initWithDomain:IOUSBHostErrorDomain
                code:(NSInteger)kIOReturnInternalError userInfo:nil] :
            [NSError errorWithDomain:domain code:(NSInteger)kIOReturnInternalError userInfo:info];
    }
    if (rdx_interface_stub_mode == 2) { return [super init]; }
    return nil;
}
/** Records destruction without touching a USB user client. */
- (void)destroy { rdx_interface_destroy_tick = ++rdx_interface_lifetime_tick; }
/** Proves lease ownership drops the child before invoking the parent destroy. */
- (void)dealloc { rdx_interface_dealloc_tick = ++rdx_interface_lifetime_tick; }
@end

@interface RDXInterfaceParentStub : NSObject
- (void)destroy;
@end
@implementation RDXInterfaceParentStub
/** Records only the hardware-free parent's destroy event. */
- (void)destroy { rdx_parent_destroy_tick = ++rdx_interface_lifetime_tick; }
/** Records only the hardware-free parent's final release event. */
- (void)dealloc { rdx_parent_dealloc_tick = ++rdx_interface_lifetime_tick; }
@end

/** Proves one constructor, fresh current-call input, preserved legacy status and release order. */
bool rdx_macos_test_interface_error_provenance_contract(void) {
    @autoreleasepool {
        NSError *previous = [NSError errorWithDomain:IOUSBHostErrorDomain
            code:(NSInteger)kIOReturnNotPrivileged userInfo:nil];
        NSError *shared = previous;
        RDXUSBHostLease *owner = [[RDXUSBHostLease alloc] init];
        rdx_interface_stub_mode = 0;
        rdx_interface_stub_calls = 0;
        rdx_interface_stub_fresh_slot = false;
        rdx_interface_error_evidence evidence = {0};
        rdx_macos_status status = rdx_usb_initialize_interface(owner, IO_OBJECT_NULL,
            [RDXInterfaceConstructorStub class], &shared, &evidence);
        rdx_usb_release_event_count = 0;
        memset(rdx_usb_release_events, 0, sizeof(rdx_usb_release_events));
        [owner destroy];
        bool missing_correct = rdx_interface_stub_calls == 1 && rdx_interface_stub_fresh_slot &&
            status == RDX_MACOS_STATUS_ACCESS_DENIED && shared == previous && owner.interface == nil &&
            evidence.status == status && evidence.domain == 0 && evidence.code == 0 &&
            evidence.reason == 0 && evidence.under_domain == 0 && evidence.under_code == 0 &&
            rdx_usb_release_event_count == 4 &&
            rdx_usb_release_events[0] == RDX_USB_RELEASE_BULK_IN &&
            rdx_usb_release_events[1] == RDX_USB_RELEASE_BULK_OUT &&
            rdx_usb_release_events[2] == RDX_USB_RELEASE_INTERFACE &&
            rdx_usb_release_events[3] == RDX_USB_RELEASE_DEVICE;
        rdx_interface_stub_mode = 1;
        rdx_interface_stub_calls = 0;
        status = rdx_usb_initialize_interface(owner, IO_OBJECT_NULL,
            [RDXInterfaceConstructorStub class], &shared, &evidence);
        bool genuine_correct = rdx_interface_stub_calls == 1 && rdx_interface_stub_fresh_slot &&
            status == RDX_MACOS_STATUS_NATIVE_FAILURE && evidence.status == status &&
            evidence.domain == 1 && evidence.code == 9 && evidence.reason == 1 &&
            evidence.under_domain == 2 && evidence.under_code == 21 && shared != previous;
        bool classes_correct = true;
        const uint8_t expected[][5] = {
            {1, 9, 4, 0, 0}, {1, 9, 4, 0, 0}, {1, 9, 0, 5, 1},
            {1, 9, 0, 1, 2}, {2, 1, 0, 0, 0}, {6, 1, 0, 0, 0},
            {3, 1, 0, 0, 0}, {4, 1, 3, 0, 0}, {5, 1, 4, 0, 0}
        };
        for (unsigned int mode = 3; mode <= 11; ++mode) {
            rdx_interface_stub_mode = mode;
            rdx_interface_stub_calls = 0;
            status = rdx_usb_initialize_interface(owner, IO_OBJECT_NULL,
                [RDXInterfaceConstructorStub class], &shared, &evidence);
            const uint8_t *wanted = expected[mode - 3];
            classes_correct = classes_correct && rdx_interface_stub_calls == 1 &&
                rdx_interface_stub_fresh_slot && status == RDX_MACOS_STATUS_NATIVE_FAILURE &&
                evidence.status == status && evidence.domain == wanted[0] &&
                evidence.code == wanted[1] && evidence.reason == wanted[2] &&
                evidence.under_domain == wanted[3] && evidence.under_code == wanted[4];
        }
        NSError *signed_error = [NSError errorWithDomain:IOUSBHostErrorDomain
            code:(NSInteger)(int32_t)kIOReturnInternalError userInfo:nil];
        NSError *unsigned_error = [NSError errorWithDomain:IOUSBHostErrorDomain
            code:(NSInteger)(uint32_t)kIOReturnInternalError userInfo:nil];
        classes_correct = classes_correct && rdx_interface_evidence(signed_error).code == 9 &&
            rdx_interface_evidence(unsigned_error).code == 9;
        rdx_interface_stub_mode = 2;
        rdx_interface_stub_calls = 0;
        rdx_interface_lifetime_tick = rdx_interface_destroy_tick = rdx_interface_dealloc_tick = 0;
        rdx_parent_destroy_tick = rdx_parent_dealloc_tick = 0;
        owner.device = (IOUSBHostDevice *)(id)[[RDXInterfaceParentStub alloc] init];
        status = rdx_usb_initialize_interface(owner, IO_OBJECT_NULL,
            [RDXInterfaceConstructorStub class], &shared, &evidence);
        bool success_correct = status == RDX_MACOS_STATUS_OK && owner.interface != nil &&
            rdx_interface_stub_calls == 1 && rdx_interface_stub_fresh_slot;
        [owner destroy];
        return missing_correct && genuine_correct && classes_correct && success_correct &&
            rdx_interface_destroy_tick == 1 && rdx_interface_dealloc_tick == 2 &&
            rdx_parent_destroy_tick == 3 && rdx_parent_dealloc_tick == 4;

    }
}
#endif

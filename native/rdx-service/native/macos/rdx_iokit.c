// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Atomic uint64_t rdx_result_allocations = 0;
_Atomic uint64_t rdx_result_frees = 0;
_Atomic uint64_t rdx_io_acquisitions = 0;
_Atomic uint64_t rdx_io_releases = 0;
_Atomic uint64_t rdx_cf_acquisitions = 0;
_Atomic uint64_t rdx_cf_releases = 0;
_Atomic uint64_t rdx_plugin_acquisitions = 0;
_Atomic uint64_t rdx_plugin_releases = 0;
_Atomic uint64_t rdx_interface_acquisitions = 0;
_Atomic uint64_t rdx_interface_releases = 0;
_Atomic uint64_t rdx_exclusive_acquisitions = 0;
_Atomic uint64_t rdx_exclusive_releases = 0;
_Atomic uint64_t rdx_task_acquisitions = 0;
_Atomic uint64_t rdx_task_releases = 0;
_Atomic uint64_t rdx_device_allocations = 0;
_Atomic uint64_t rdx_device_frees = 0;
_Atomic uint64_t rdx_scsi_lease_allocations = 0;
_Atomic uint64_t rdx_scsi_lease_frees = 0;
_Atomic uint64_t rdx_da_registry_allocations = 0;
_Atomic uint64_t rdx_da_registry_frees = 0;
_Atomic uint64_t rdx_da_context_allocations = 0;
_Atomic uint64_t rdx_da_context_frees = 0;
_Atomic uint64_t rdx_da_contexts_outstanding = 0;

#if defined(RDX_MACOS_TEST_HOOKS)
_Atomic uint32_t rdx_test_failure = RDX_TEST_FAIL_NONE;

bool rdx_test_failure_injected(rdx_test_failure_point point) {
    uint32_t expected = (uint32_t)point;
    return atomic_compare_exchange_strong_explicit(
        &rdx_test_failure,
        &expected,
        RDX_TEST_FAIL_NONE,
        memory_order_acq_rel,
        memory_order_acquire
    );
}

void rdx_test_inject_failure(rdx_test_failure_point point) {
    atomic_store_explicit(
        &rdx_test_failure,
        (uint32_t)point,
        memory_order_release
    );
}
#endif

typedef enum rdx_property_state {
    RDX_PROPERTY_MISSING = 0,
    RDX_PROPERTY_VALID = 1,
    RDX_PROPERTY_INVALID = 2
} rdx_property_state;

#if defined(RDX_MACOS_TEST_HOOKS)
void rdx_test_record_event(rdx_macos_device *device, uint8_t event) {
    if (device != NULL && device->test_event_count < sizeof(device->test_events)) {
        device->test_events[device->test_event_count++] = event;
    }
}
#endif

void *rdx_allocate_result(size_t size, rdx_macos_result_kind kind) {
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_RESULT_ALLOCATION)) {
        return NULL;
    }
    rdx_macos_result_header *header = calloc(1, size);
    if (header == NULL) {
        return NULL;
    }
    header->abi_version = RDX_MACOS_ABI_VERSION;
    header->kind = kind;
    header->status = RDX_MACOS_STATUS_OK;
    atomic_fetch_add_explicit(&rdx_result_allocations, 1, memory_order_relaxed);
    return header;
}

void rdx_macos_free_result(void *result) {
    if (result == NULL) {
        return;
    }
    atomic_fetch_add_explicit(&rdx_result_frees, 1, memory_order_relaxed);
    free(result);
}

void rdx_track_io_acquire(void) {
    atomic_fetch_add_explicit(&rdx_io_acquisitions, 1, memory_order_relaxed);
}

void rdx_release_io(io_object_t object) {
    if (object != IO_OBJECT_NULL) {
        IOObjectRelease(object);
        atomic_fetch_add_explicit(&rdx_io_releases, 1, memory_order_relaxed);
    }
}

void rdx_track_cf_acquire(void) {
    atomic_fetch_add_explicit(&rdx_cf_acquisitions, 1, memory_order_relaxed);
}

void rdx_release_cf(CFTypeRef CF_RELEASES_ARGUMENT object) {
    if (object != NULL) {
        CFRelease(object);
        atomic_fetch_add_explicit(&rdx_cf_releases, 1, memory_order_relaxed);
    }
}

void rdx_track_plugin_acquire(void) {
    atomic_fetch_add_explicit(&rdx_plugin_acquisitions, 1, memory_order_relaxed);
}

void rdx_release_plugin(IOCFPlugInInterface **plugin) {
    if (plugin != NULL) {
        IODestroyPlugInInterface(plugin);
        atomic_fetch_add_explicit(&rdx_plugin_releases, 1, memory_order_relaxed);
    }
}

void rdx_track_interface_acquire(void) {
    atomic_fetch_add_explicit(&rdx_interface_acquisitions, 1, memory_order_relaxed);
}

void rdx_release_interface(SCSITaskDeviceInterface **interface) {
    if (interface != NULL) {
        (*interface)->Release(interface);
        atomic_fetch_add_explicit(&rdx_interface_releases, 1, memory_order_relaxed);
    }
}

void rdx_track_exclusive_acquire(void) {
    atomic_fetch_add_explicit(&rdx_exclusive_acquisitions, 1, memory_order_relaxed);
}

void rdx_track_exclusive_release(void) {
    atomic_fetch_add_explicit(&rdx_exclusive_releases, 1, memory_order_relaxed);
}

void rdx_track_task_acquire(void) {
    atomic_fetch_add_explicit(&rdx_task_acquisitions, 1, memory_order_relaxed);
}

void rdx_release_task(SCSITaskInterface **task) {
    if (task != NULL) {
        (*task)->Release(task);
        atomic_fetch_add_explicit(&rdx_task_releases, 1, memory_order_relaxed);
    }
}

rdx_macos_status rdx_status_from_io(IOReturn status, rdx_macos_status fallback) {
    if (status == kIOReturnSuccess) {
        return RDX_MACOS_STATUS_OK;
    }
    if (status == kIOReturnNotPrivileged) {
        return RDX_MACOS_STATUS_ACCESS_DENIED;
    }
    if (status == kIOReturnBusy || status == kIOReturnExclusiveAccess) {
        return RDX_MACOS_STATUS_BUSY;
    }
    if (status == kIOReturnTimeout) {
        return RDX_MACOS_STATUS_TIMED_OUT;
    }
    if (status == kIOReturnNoDevice || status == kIOReturnNotOpen) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    if (status == kIOReturnUnsupported || status == kIOReturnNotPermitted) {
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    if (status == kIOReturnNoMemory) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    return fallback;
}

static bool rdx_ascii_text_is_valid(const char *text, size_t capacity) {
    size_t length = strnlen(text, capacity);
    if (length == capacity) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        unsigned char value = (unsigned char)text[index];
        if (value < 0x20U || value > 0x7EU) {
            return false;
        }
    }
    return true;
}

bool rdx_candidate_record_is_valid(const rdx_macos_candidate_record *candidate) {
    if (candidate == NULL || candidate->registry_entry_id == 0 ||
        candidate->peripheral_type != 0) {
        return false;
    }
    const uint8_t flags[] = {
        candidate->has_vendor,
        candidate->has_product,
        candidate->has_revision,
        candidate->has_serial
    };
    const char *texts[] = {
        candidate->vendor,
        candidate->product,
        candidate->revision,
        candidate->serial
    };
    for (size_t index = 0; index < 4; ++index) {
        if (flags[index] > 1 ||
            !rdx_ascii_text_is_valid(texts[index], RDX_MACOS_MAX_TEXT_BYTES + 1)) {
            return false;
        }
        if (flags[index] == 0 && texts[index][0] != '\0') {
            return false;
        }
    }
    return true;
}

static rdx_property_state rdx_copy_string_property(
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
    if (property == NULL) {
        output[0] = '\0';
        return RDX_PROPERTY_MISSING;
    }
    rdx_track_cf_acquire();
    rdx_property_state state = RDX_PROPERTY_INVALID;
    if (CFGetTypeID(property) == CFStringGetTypeID() &&
        CFStringGetCString(
            (CFStringRef)property,
            output,
            RDX_MACOS_MAX_TEXT_BYTES + 1,
            kCFStringEncodingUTF8
        ) &&
        rdx_ascii_text_is_valid(output, RDX_MACOS_MAX_TEXT_BYTES + 1)) {
        state = RDX_PROPERTY_VALID;
    }
    rdx_release_cf(property);
    return state;
}

static bool rdx_copy_peripheral_type(io_service_t service, uint32_t *output) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service,
        CFSTR(kIOPropertySCSIPeripheralDeviceType),
        kCFAllocatorDefault,
        0
    );
    if (property == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    int32_t value = -1;
    bool valid = CFGetTypeID(property) == CFNumberGetTypeID() &&
        CFNumberGetValue((CFNumberRef)property, kCFNumberSInt32Type, &value) &&
        value >= 0;
    rdx_release_cf(property);
    if (!valid) {
        return false;
    }
    *output = (uint32_t)value;
    return true;
}

bool rdx_fill_candidate(
    io_service_t service,
    rdx_macos_candidate_record *candidate
) {
    memset(candidate, 0, sizeof(*candidate));
    if (!rdx_is_scsi_candidate_service(service) ||
        IORegistryEntryGetRegistryEntryID(service, &candidate->registry_entry_id) !=
            kIOReturnSuccess ||
        candidate->registry_entry_id == 0 ||
        !rdx_copy_peripheral_type(service, &candidate->peripheral_type) ||
        candidate->peripheral_type != 0) {
        return false;
    }

    rdx_property_state states[] = {
        rdx_copy_string_property(
            service,
            CFSTR(kIOPropertySCSIVendorIdentification),
            candidate->vendor
        ),
        rdx_copy_string_property(
            service,
            CFSTR(kIOPropertySCSIProductIdentification),
            candidate->product
        ),
        rdx_copy_string_property(
            service,
            CFSTR(kIOPropertySCSIProductRevisionLevel),
            candidate->revision
        ),
        rdx_copy_string_property(
            service,
            CFSTR(kIOPropertySCSIINQUIRYUnitSerialNumber),
            candidate->serial
        )
    };
    if (states[3] == RDX_PROPERTY_MISSING &&
        rdx_copy_usb_ancestor_serial(service, candidate->serial)) {
        states[3] = RDX_PROPERTY_VALID;
    }
    for (size_t index = 0; index < 4; ++index) {
        if (states[index] == RDX_PROPERTY_INVALID) {
            return false;
        }
    }
    candidate->has_vendor = states[0] == RDX_PROPERTY_VALID;
    candidate->has_product = states[1] == RDX_PROPERTY_VALID;
    candidate->has_revision = states[2] == RDX_PROPERTY_VALID;
    candidate->has_serial = states[3] == RDX_PROPERTY_VALID;
    return rdx_candidate_record_is_valid(candidate);
}

/** Accepts the two direct-access SCSI classes macOS uses across USB rematch. */
bool rdx_is_scsi_candidate_service(io_service_t service) {
    return service != IO_OBJECT_NULL &&
        (IOObjectConformsTo(service, "IOSCSIPeripheralDeviceNub") ||
         IOObjectConformsTo(service, "IOSCSILogicalUnitNub"));
}

/** Compares complete registry-generation-independent candidate identity. */
bool rdx_stable_candidate_identity_matches(
    const rdx_macos_candidate_record *left,
    const rdx_macos_candidate_record *right
) {
    return left != NULL && right != NULL && left->has_serial == 1 &&
        right->has_serial == 1 && left->peripheral_type == right->peripheral_type &&
        left->has_vendor == right->has_vendor &&
        left->has_product == right->has_product &&
        left->has_revision == right->has_revision &&
        strcmp(left->vendor, right->vendor) == 0 &&
        strcmp(left->product, right->product) == 0 &&
        strcmp(left->revision, right->revision) == 0 &&
        strcmp(left->serial, right->serial) == 0;
}

bool rdx_records_match(
    const rdx_macos_candidate_record *left,
    const rdx_macos_candidate_record *right
) {
    return left->registry_entry_id == right->registry_entry_id &&
        left->peripheral_type == right->peripheral_type &&
        left->has_vendor == right->has_vendor &&
        left->has_product == right->has_product &&
        left->has_revision == right->has_revision &&
        left->has_serial == right->has_serial &&
        strcmp(left->vendor, right->vendor) == 0 &&
        strcmp(left->product, right->product) == 0 &&
        strcmp(left->revision, right->revision) == 0 &&
        strcmp(left->serial, right->serial) == 0;
}

static rdx_macos_status rdx_open_service(
    const rdx_macos_candidate_record *candidate,
    io_service_t *out_service
) {
    if (candidate == NULL || out_service == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_service = IO_OBJECT_NULL;
    CFMutableDictionaryRef matching = IORegistryEntryIDMatching(
        candidate->registry_entry_id
    );
    if (matching == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service == IO_OBJECT_NULL) {
        rdx_macos_candidate_record observed;
        return rdx_find_rebound_service(candidate, out_service, &observed);
    }
    rdx_track_io_acquire();
    if (!rdx_is_scsi_candidate_service(service)) {
        rdx_release_io(service);
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    rdx_macos_candidate_record observed;
    if (!rdx_fill_candidate(service, &observed) ||
        !rdx_records_match(candidate, &observed)) {
        rdx_release_io(service);
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    *out_service = service;
    return RDX_MACOS_STATUS_OK;
}

rdx_macos_status rdx_macos_open_candidate(
    const rdx_macos_candidate_record *candidate,
    rdx_macos_device **out_device
) {
    rdx_macos_status status = RDX_MACOS_STATUS_INVALID_ARGUMENT;
    rdx_macos_device *device = NULL;
    io_service_t service = IO_OBJECT_NULL;
    if (out_device == NULL) {
        return status;
    }
    *out_device = NULL;
    if (!rdx_candidate_record_is_valid(candidate)) {
        return status;
    }
    if (!rdx_macos_candidate_matches_rdx_hint(candidate)) {
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    status = rdx_open_service(candidate, &service);
    if (status != RDX_MACOS_STATUS_OK) {
        goto cleanup;
    }

    device = calloc(1, sizeof(*device));
    if (device == NULL) {
        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        goto cleanup;
    }
    atomic_fetch_add_explicit(&rdx_device_allocations, 1, memory_order_relaxed);
    device->whole_raw_fd = -1;
    device->service = service;
    if (!rdx_fill_candidate(service, &device->expected)) {
        status = RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
        goto cleanup;
    }
    service = IO_OBJECT_NULL;
    status = rdx_revalidate_device(device);
    if (status != RDX_MACOS_STATUS_OK) {
        goto cleanup;
    }
    *out_device = device;
    return RDX_MACOS_STATUS_OK;

cleanup:
    if (device != NULL) {
        rdx_macos_release_device(device);
    }
    rdx_release_io(service);
    return status;
}

void rdx_macos_release_device(rdx_macos_device *device) {
    if (device == NULL) {
        return;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        if ((device->fake_mask & RDX_FAKE_TASK) != 0) {
            atomic_fetch_add_explicit(&rdx_task_releases, 1, memory_order_relaxed);
        }
        if ((device->fake_mask & RDX_FAKE_EXCLUSIVE) != 0) {
            rdx_track_exclusive_release();
        }
        if ((device->fake_mask & RDX_FAKE_INTERFACE) != 0) {
            atomic_fetch_add_explicit(&rdx_interface_releases, 1, memory_order_relaxed);
        }
        if ((device->fake_mask & RDX_FAKE_PLUGIN) != 0) {
            atomic_fetch_add_explicit(&rdx_plugin_releases, 1, memory_order_relaxed);
        }
        if ((device->fake_mask & RDX_FAKE_CF) != 0) {
            atomic_fetch_add_explicit(&rdx_cf_releases, 1, memory_order_relaxed);
        }
        if ((device->fake_mask & RDX_FAKE_IO) != 0) {
            atomic_fetch_add_explicit(&rdx_io_releases, 1, memory_order_relaxed);
        }
    } else
#endif
    {
        rdx_clear_mapping(device);
        rdx_release_io(device->service);
    }
    atomic_fetch_add_explicit(&rdx_device_frees, 1, memory_order_relaxed);
    free(device);
}

static rdx_macos_status rdx_create_scsi_plugin(
    rdx_macos_device *device,
    IOCFPlugInInterface ***out_plugin,
    uint32_t *acquired_mask
) {
    *out_plugin = NULL;
#if defined(RDX_MACOS_TEST_HOOKS)
    rdx_test_record_event(device, RDX_TEST_EVENT_CREATE_PLUGIN);
#endif
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_PLUGIN_CREATE)) {
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        rdx_track_plugin_acquire();
        *acquired_mask |= RDX_FAKE_PLUGIN;
        return RDX_MACOS_STATUS_OK;
    }
#endif
    SInt32 score = 0;
    IOReturn io_status = IOCreatePlugInInterfaceForService(
        device->service,
        kIOSCSITaskDeviceUserClientTypeID,
        kIOCFPlugInInterfaceID,
        out_plugin,
        &score
    );
    if (io_status != kIOReturnSuccess || *out_plugin == NULL) {
        rdx_record_acquisition_diagnostic(RDX_ACQUIRE_LEGACY_PLUGIN,
            rdx_status_from_io(io_status, RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE),
            RDX_ACQUIRE_CODE_IORETURN, (int64_t)io_status);
        return rdx_status_from_io(
            io_status,
            RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE
        );
    }
    rdx_track_plugin_acquire();
    *acquired_mask |= RDX_FAKE_PLUGIN;
    return RDX_MACOS_STATUS_OK;
}

static rdx_macos_status rdx_query_scsi_interface(
    rdx_macos_device *device,
    IOCFPlugInInterface **plugin,
    SCSITaskDeviceInterface ***out_interface,
    uint32_t *acquired_mask
) {
    (void)device;
    *out_interface = NULL;
#if defined(RDX_MACOS_TEST_HOOKS)
    rdx_test_record_event(device, RDX_TEST_EVENT_QUERY_INTERFACE);
#endif
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_QUERY_INTERFACE)) {
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        rdx_track_interface_acquire();
        *acquired_mask |= RDX_FAKE_INTERFACE;
        return RDX_MACOS_STATUS_OK;
    }
#endif
    HRESULT query_status = (*plugin)->QueryInterface(
        plugin,
        CFUUIDGetUUIDBytes(kIOSCSITaskDeviceInterfaceID),
        (LPVOID *)out_interface
    );
    if (FAILED(query_status) || *out_interface == NULL) {
        rdx_record_acquisition_diagnostic(RDX_ACQUIRE_LEGACY_INTERFACE,
            RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE, RDX_ACQUIRE_CODE_HRESULT,
            (int64_t)query_status);
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    rdx_track_interface_acquire();
    *acquired_mask |= RDX_FAKE_INTERFACE;
    return RDX_MACOS_STATUS_OK;
}

static rdx_macos_status rdx_obtain_scsi_exclusive(
    rdx_macos_device *device,
    SCSITaskDeviceInterface **interface,
    bool *out_exclusive,
    uint32_t *acquired_mask
) {
    (void)device;
    *out_exclusive = false;
#if defined(RDX_MACOS_TEST_HOOKS)
    rdx_test_record_event(device, RDX_TEST_EVENT_OBTAIN_EXCLUSIVE);
#endif
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_OBTAIN_EXCLUSIVE)) {
        return RDX_MACOS_STATUS_BUSY;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        rdx_track_exclusive_acquire();
        *out_exclusive = true;
        *acquired_mask |= RDX_FAKE_EXCLUSIVE;
        return RDX_MACOS_STATUS_OK;
    }
#endif
    if (!(*interface)->IsExclusiveAccessAvailable(interface)) {
        rdx_record_acquisition_diagnostic(RDX_ACQUIRE_LEGACY_EXCLUSIVE,
            RDX_MACOS_STATUS_BUSY, RDX_ACQUIRE_CODE_NONE, 0);
        return RDX_MACOS_STATUS_BUSY;
    }
    IOReturn io_status = (*interface)->ObtainExclusiveAccess(interface);
    if (io_status != kIOReturnSuccess) {
        rdx_record_acquisition_diagnostic(RDX_ACQUIRE_LEGACY_EXCLUSIVE,
            rdx_status_from_io(io_status, RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE),
            RDX_ACQUIRE_CODE_IORETURN, (int64_t)io_status);
        return rdx_status_from_io(
            io_status,
            RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE
        );
    }
    rdx_track_exclusive_acquire();
    *out_exclusive = true;
    *acquired_mask |= RDX_FAKE_EXCLUSIVE;
    return RDX_MACOS_STATUS_OK;
}

static void rdx_release_scsi_parts(
    bool test_fake,
    uint32_t acquired_mask,
    io_service_t service,
    IOCFPlugInInterface **plugin,
    SCSITaskDeviceInterface **interface,
    bool exclusive
) {
#if defined(RDX_MACOS_TEST_HOOKS)
    if (test_fake) {
        if ((acquired_mask & RDX_FAKE_EXCLUSIVE) != 0) {
            rdx_track_exclusive_release();
        }
        if ((acquired_mask & RDX_FAKE_INTERFACE) != 0) {
            atomic_fetch_add_explicit(
                &rdx_interface_releases,
                1,
                memory_order_relaxed
            );
        }
        if ((acquired_mask & RDX_FAKE_PLUGIN) != 0) {
            atomic_fetch_add_explicit(
                &rdx_plugin_releases,
                1,
                memory_order_relaxed
            );
        }
        return;
    }
#else
    (void)test_fake;
    (void)acquired_mask;
#endif
    rdx_release_io(service);
    if (exclusive && interface != NULL) {
        (void)(*interface)->ReleaseExclusiveAccess(interface);
        rdx_track_exclusive_release();
    }
    rdx_release_interface(interface);
    rdx_release_plugin(plugin);
}

rdx_macos_status rdx_macos_acquire_scsi(
    rdx_macos_device *device,
    rdx_macos_scsi_lease **out_lease
) {
    rdx_macos_status status = RDX_MACOS_STATUS_INVALID_ARGUMENT;
    rdx_macos_scsi_lease *lease = NULL;
    IOCFPlugInInterface **plugin = NULL;
    SCSITaskDeviceInterface **interface = NULL;
    io_service_t retained_service = IO_OBJECT_NULL;
    bool exclusive = false;
    bool test_fake = false;
    uint32_t acquired_mask = 0;
    rdx_macos_usb_bot_lease *usb_bot = NULL;
    if (out_lease == NULL) {
        return status;
    }
    *out_lease = NULL;
    if (device == NULL || !device->mapping_pinned) {
        return status;
    }
    status = rdx_revalidate_mapping(device);
    if (status != RDX_MACOS_STATUS_OK) {
        goto cleanup;
    }
    if (rdx_mapping_has_mounted_media(device)) {
        status = RDX_MACOS_STATUS_BUSY;
        goto cleanup;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    test_fake = device->test_fake;
#endif
    status = rdx_create_scsi_plugin(device, &plugin, &acquired_mask);
    if (status == RDX_MACOS_STATUS_OK) {
        status = rdx_query_scsi_interface(
            device,
            plugin,
            &interface,
            &acquired_mask
        );
    }
    if (status == RDX_MACOS_STATUS_OK) {
        status = rdx_obtain_scsi_exclusive(
            device,
            interface,
            &exclusive,
            &acquired_mask
        );
    }
    if (status == RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE) {
        rdx_release_scsi_parts(
            test_fake,
            acquired_mask,
            retained_service,
            plugin,
            interface,
            exclusive
        );
        retained_service = IO_OBJECT_NULL;
        plugin = NULL;
        interface = NULL;
        exclusive = false;
        acquired_mask = 0;
#if defined(RDX_MACOS_TEST_HOOKS)
        if (!test_fake)
#endif
        {
            /* A retained raw disk descriptor can keep the storage stack busy.
             * Identity was revalidated above and capture owns the USB ancestor
             * from this point until its reset-and-rematch release. */
            rdx_clear_mapping(device);
            status = rdx_macos_usb_bot_acquire(
                device->service,
                &device->expected,
                &usb_bot
            );
        }
    }
    if (status != RDX_MACOS_STATUS_OK) {
        goto cleanup;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (!test_fake && usb_bot == NULL)
#endif
    {
        if (IOObjectRetain(device->service) != kIOReturnSuccess) {
            status = RDX_MACOS_STATUS_DEVICE_REMOVED;
            goto cleanup;
        }
        retained_service = device->service;
        rdx_track_io_acquire();
    }

    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_SCSI_LEASE_ALLOCATION)) {
        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        goto cleanup;
    }
    lease = calloc(1, sizeof(*lease));
    if (lease == NULL) {
        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        goto cleanup;
    }
    atomic_fetch_add_explicit(
        &rdx_scsi_lease_allocations,
        1,
        memory_order_relaxed
    );
    lease->service = retained_service;
    lease->plugin = plugin;
    lease->interface = interface;
    lease->exclusive = exclusive;
    lease->usb_bot = usb_bot;
    lease->expected = device->expected;
#if defined(RDX_MACOS_TEST_HOOKS)
    lease->test_fake = test_fake;
    lease->fake_mask = acquired_mask;
#endif
    retained_service = IO_OBJECT_NULL;
    plugin = NULL;
    interface = NULL;
    exclusive = false;
    usb_bot = NULL;
    acquired_mask = 0;
    status = rdx_revalidate_scsi_lease(lease);
    if (status != RDX_MACOS_STATUS_OK) {
        goto cleanup;
    }
    *out_lease = lease;
    return RDX_MACOS_STATUS_OK;

cleanup:
    rdx_macos_release_scsi(lease);
    rdx_release_scsi_parts(
        test_fake,
        acquired_mask,
        retained_service,
        plugin,
        interface,
        exclusive
    );
    rdx_macos_usb_bot_release(usb_bot);
    return status;
}

void rdx_macos_release_scsi(rdx_macos_scsi_lease *lease) {
    if (lease == NULL) {
        return;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (lease->test_fake) {
        rdx_release_scsi_parts(
            true,
            lease->fake_mask,
            IO_OBJECT_NULL,
            NULL,
            NULL,
            lease->exclusive
        );
    } else {
#endif
        rdx_release_scsi_parts(
            false,
            0,
            lease->service,
            lease->plugin,
            lease->interface,
            lease->exclusive
        );
#if defined(RDX_MACOS_TEST_HOOKS)
    }
#endif
    rdx_macos_usb_bot_release(lease->usb_bot);
    fputs("openrdx-hardware: trace scsi-release-usb-return\n", stderr);
    atomic_fetch_add_explicit(&rdx_scsi_lease_frees, 1, memory_order_relaxed);
    fputs("openrdx-hardware: trace scsi-release-lease-free-enter\n", stderr);
    free(lease);
    fputs("openrdx-hardware: trace scsi-release-lease-free-return\n", stderr);
}

rdx_macos_status rdx_macos_probe_readiness(rdx_macos_readiness *out_readiness) {
    if (out_readiness == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    memset(out_readiness, 0, sizeof(*out_readiness));
    out_readiness->abi_version = RDX_MACOS_ABI_VERSION;
    /* This bridge compiled and linked against IOKit, so discovery API support
     * is static. Only an explicit scan may allocate a matching dictionary and
     * report transient enumeration failures. */
    out_readiness->discovery_available = 1;
    /* The bridge compiled and linked the documented user SCSI task API. This is
     * static source readiness only; exact candidate usability is still proven
     * by the later scan without allocating any IOKit object here. */
    out_readiness->safe_transport_available = 1;
    out_readiness->status = RDX_MACOS_STATUS_OK;
    return RDX_MACOS_STATUS_OK;
}

void rdx_macos_get_abi_layout(rdx_macos_abi_layout *out_layout) {
    if (out_layout == NULL) {
        return;
    }
    memset(out_layout, 0, sizeof(*out_layout));
    out_layout->abi_version = RDX_MACOS_ABI_VERSION;
    out_layout->result_header_size = sizeof(rdx_macos_result_header);
    out_layout->result_header_status_offset =
        offsetof(rdx_macos_result_header, status);
    out_layout->candidate_size = sizeof(rdx_macos_candidate_record);
    out_layout->candidate_registry_entry_id_offset =
        offsetof(rdx_macos_candidate_record, registry_entry_id);
    out_layout->candidate_vendor_offset =
        offsetof(rdx_macos_candidate_record, vendor);
    out_layout->candidate_serial_offset =
        offsetof(rdx_macos_candidate_record, serial);
    out_layout->enumeration_size = sizeof(rdx_macos_enumeration_result);
    out_layout->enumeration_count_offset =
        offsetof(rdx_macos_enumeration_result, count);
    out_layout->enumeration_candidates_offset =
        offsetof(rdx_macos_enumeration_result, candidates);
    out_layout->readiness_size = sizeof(rdx_macos_readiness);
    out_layout->readiness_candidate_count_offset =
        offsetof(rdx_macos_readiness, candidate_count);
    out_layout->scsi_request_size = sizeof(rdx_macos_scsi_request);
    out_layout->scsi_request_data_offset = offsetof(rdx_macos_scsi_request, data);
    out_layout->scsi_result_size = sizeof(rdx_macos_scsi_result);
    out_layout->scsi_result_realized_transfer_offset =
        offsetof(rdx_macos_scsi_result, realized_transfer_count);
    out_layout->scsi_result_data_offset = offsetof(rdx_macos_scsi_result, data);
    out_layout->scsi_result_sense_offset = offsetof(rdx_macos_scsi_result, sense);
    out_layout->media_record_size = sizeof(rdx_macos_media_record);
    out_layout->media_record_uuid_offset =
        offsetof(rdx_macos_media_record, uuid);
    out_layout->mapping_result_size = sizeof(rdx_macos_mapping_result);
    out_layout->mapping_result_media_offset =
        offsetof(rdx_macos_mapping_result, media);
    out_layout->host_operation_result_size =
        sizeof(rdx_macos_host_operation_result);
    out_layout->host_operation_dissenter_offset =
        offsetof(rdx_macos_host_operation_result, dissenter_status);
    out_layout->resource_counters_size =
        sizeof(rdx_macos_resource_counters);
    out_layout->resource_counters_device_frees_offset =
        offsetof(rdx_macos_resource_counters, device_frees);
    out_layout->abi_layout_size = sizeof(rdx_macos_abi_layout);
}

void rdx_macos_get_resource_counters(rdx_macos_resource_counters *out_counters) {
    if (out_counters == NULL) {
        return;
    }
    *out_counters = (rdx_macos_resource_counters){
        .result_allocations = atomic_load_explicit(&rdx_result_allocations, memory_order_relaxed),
        .result_frees = atomic_load_explicit(&rdx_result_frees, memory_order_relaxed),
        .io_acquisitions = atomic_load_explicit(&rdx_io_acquisitions, memory_order_relaxed),
        .io_releases = atomic_load_explicit(&rdx_io_releases, memory_order_relaxed),
        .cf_acquisitions = atomic_load_explicit(&rdx_cf_acquisitions, memory_order_relaxed),
        .cf_releases = atomic_load_explicit(&rdx_cf_releases, memory_order_relaxed),
        .plugin_acquisitions = atomic_load_explicit(&rdx_plugin_acquisitions, memory_order_relaxed),
        .plugin_releases = atomic_load_explicit(&rdx_plugin_releases, memory_order_relaxed),
        .interface_acquisitions = atomic_load_explicit(&rdx_interface_acquisitions, memory_order_relaxed),
        .interface_releases = atomic_load_explicit(&rdx_interface_releases, memory_order_relaxed),
        .exclusive_acquisitions = atomic_load_explicit(&rdx_exclusive_acquisitions, memory_order_relaxed),
        .exclusive_releases = atomic_load_explicit(&rdx_exclusive_releases, memory_order_relaxed),
        .task_acquisitions = atomic_load_explicit(&rdx_task_acquisitions, memory_order_relaxed),
        .task_releases = atomic_load_explicit(&rdx_task_releases, memory_order_relaxed),
        .device_allocations = atomic_load_explicit(&rdx_device_allocations, memory_order_relaxed),
        .device_frees = atomic_load_explicit(&rdx_device_frees, memory_order_relaxed),
        .scsi_lease_allocations = atomic_load_explicit(
            &rdx_scsi_lease_allocations,
            memory_order_relaxed
        ),
        .scsi_lease_frees = atomic_load_explicit(
            &rdx_scsi_lease_frees,
            memory_order_relaxed
        ),
        .da_registry_allocations = atomic_load_explicit(
            &rdx_da_registry_allocations,
            memory_order_relaxed
        ),
        .da_registry_frees = atomic_load_explicit(
            &rdx_da_registry_frees,
            memory_order_relaxed
        ),
        .da_context_allocations = atomic_load_explicit(
            &rdx_da_context_allocations,
            memory_order_relaxed
        ),
        .da_context_frees = atomic_load_explicit(
            &rdx_da_context_frees,
            memory_order_relaxed
        ),
        .da_contexts_outstanding = atomic_load_explicit(
            &rdx_da_contexts_outstanding,
            memory_order_relaxed
        )
    };
}

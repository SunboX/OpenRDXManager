// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <string.h>

/** Proves the retained registry object is still the currently registered entry. */
rdx_macos_status rdx_revalidate_service(
    io_service_t service,
    const rdx_macos_candidate_record *expected
) {
    if (service == IO_OBJECT_NULL || expected == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    CFMutableDictionaryRef matching = IORegistryEntryIDMatching(
        expected->registry_entry_id
    );
    if (matching == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    io_service_t current = IOServiceGetMatchingService(
        kIOMainPortDefault,
        matching
    );
    if (current == IO_OBJECT_NULL) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    bool same_service = IOObjectIsEqualTo(current, service);
    IOObjectRelease(current);
    rdx_macos_candidate_record observed;
    uint64_t registry_entry_id = 0;
    if (!same_service ||
        IORegistryEntryGetRegistryEntryID(service, &registry_entry_id) !=
            kIOReturnSuccess ||
        registry_entry_id != expected->registry_entry_id ||
        !rdx_fill_candidate(service, &observed) ||
        !rdx_records_match(expected, &observed)) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    return RDX_MACOS_STATUS_OK;
}

/** Rebinds one disappeared registry entry by unique stable USB serial evidence. */
rdx_macos_status rdx_find_rebound_service(
    const rdx_macos_candidate_record *expected,
    io_service_t *out_service,
    rdx_macos_candidate_record *out_observed
) {
    if (expected == NULL || out_service == NULL || out_observed == NULL ||
        expected->has_serial != 1 || expected->serial[0] == '\0') {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    *out_service = IO_OBJECT_NULL;
    memset(out_observed, 0, sizeof(*out_observed));
    rdx_macos_enumeration_result *enumeration = NULL;
    rdx_macos_status status = rdx_macos_enumerate(&enumeration);
    if (status != RDX_MACOS_STATUS_OK || enumeration == NULL) {
        rdx_macos_free_result(enumeration);
        return status;
    }
    rdx_macos_candidate_record selected = {0};
    uint32_t count = 0;
    for (uint32_t index = 0; index < enumeration->count; ++index) {
        if (rdx_stable_candidate_identity_matches(
                expected,
                &enumeration->candidates[index]
            )) {
            count += 1;
            if (count == 1) {
                selected = enumeration->candidates[index];
            }
        }
    }
    rdx_macos_free_result(enumeration);
    if (count != 1) {
        return count == 0
            ? RDX_MACOS_STATUS_DEVICE_REMOVED
            : RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    CFMutableDictionaryRef matching = IORegistryEntryIDMatching(
        selected.registry_entry_id
    );
    if (matching == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    io_service_t match = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (match == IO_OBJECT_NULL) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    rdx_track_io_acquire();
    rdx_macos_candidate_record observed = {0};
    if (!rdx_fill_candidate(match, &observed) ||
        !rdx_records_match(&selected, &observed)) {
        rdx_release_io(match);
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    *out_observed = observed;
    *out_service = match;
    return RDX_MACOS_STATUS_OK;
}

/** Revalidates the exact retained nonexclusive candidate authority. */
rdx_macos_status rdx_revalidate_device(rdx_macos_device *device) {
    if (device == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        return device->test_revalidate_status;
    }
#endif
    rdx_macos_status status = rdx_revalidate_service(
        device->service,
        &device->expected
    );
    if (status != RDX_MACOS_STATUS_DEVICE_REMOVED) {
        return status;
    }
    io_service_t rebound = IO_OBJECT_NULL;
    rdx_macos_candidate_record observed;
    status = rdx_find_rebound_service(&device->expected, &rebound, &observed);
    if (status != RDX_MACOS_STATUS_OK) {
        return status;
    }
    rdx_release_io(device->service);
    device->service = rebound;
    device->expected = observed;
    return RDX_MACOS_STATUS_OK;
}

/** Revalidates either a legacy exclusive task lease or live USB capture. */
rdx_macos_status rdx_revalidate_scsi_lease(rdx_macos_scsi_lease *lease) {
#if defined(RDX_MACOS_TEST_HOOKS)
    if (lease != NULL && lease->test_fake) {
        return RDX_MACOS_STATUS_OK;
    }
#endif
    if (lease != NULL && lease->usb_bot != NULL) {
        return RDX_MACOS_STATUS_OK;
    }
    if (lease == NULL || lease->interface == NULL || !lease->exclusive) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    return rdx_revalidate_service(lease->service, &lease->expected);
}

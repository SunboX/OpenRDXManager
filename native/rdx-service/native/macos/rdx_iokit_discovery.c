// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

/** Returns whether this result already owns the exact or stable candidate. */
static bool rdx_result_contains_candidate(
    const rdx_macos_enumeration_result *result,
    const rdx_macos_candidate_record *candidate
) {
    for (uint32_t index = 0; index < result->count; ++index) {
        const rdx_macos_candidate_record *existing = &result->candidates[index];
        if (existing->registry_entry_id == candidate->registry_entry_id ||
            rdx_stable_candidate_identity_matches(existing, candidate)) {
            return true;
        }
    }
    return false;
}

/** Appends one IOKit class while retaining the preferred first-class record. */
static rdx_macos_status rdx_append_matching_candidates(
    rdx_macos_enumeration_result *result,
    const char *class_name
) {
    CFMutableDictionaryRef matching = NULL;
    io_iterator_t iterator = IO_OBJECT_NULL;
    io_service_t service = IO_OBJECT_NULL;
    rdx_macos_status status = RDX_MACOS_STATUS_ENUMERATION_FAILED;
    if (!RDX_TEST_INJECTED(RDX_TEST_FAIL_MATCHING_DICTIONARY_CREATE)) {
        matching = IOServiceMatching(class_name);
    }
    if (matching == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    IOReturn io_status = IOServiceGetMatchingServices(
        kIOMainPortDefault,
        matching,
        &iterator
    );
    if (io_status != kIOReturnSuccess) {
        return rdx_status_from_io(io_status, RDX_MACOS_STATUS_ENUMERATION_FAILED);
    }
    if (iterator == IO_OBJECT_NULL) {
        return RDX_MACOS_STATUS_OK;
    }
    rdx_track_io_acquire();
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        rdx_track_io_acquire();
        rdx_macos_candidate_record candidate;
        if (rdx_fill_candidate(service, &candidate) &&
            !rdx_result_contains_candidate(result, &candidate)) {
            if (result->count == RDX_MACOS_MAX_CANDIDATES) {
                status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
                goto cleanup;
            }
            result->candidates[result->count] = candidate;
            result->count += 1;
        }
        rdx_release_io(service);
        service = IO_OBJECT_NULL;
    }
    status = RDX_MACOS_STATUS_OK;

cleanup:
    rdx_release_io(service);
    rdx_release_io(iterator);
    return status;
}

/** Enumerates both direct-access registry generations and deduplicates identity. */
rdx_macos_status rdx_macos_enumerate(rdx_macos_enumeration_result **out_result) {
    if (out_result == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_result = NULL;
    rdx_macos_enumeration_result *result = rdx_allocate_result(
        sizeof(*result),
        RDX_MACOS_RESULT_ENUMERATION
    );
    if (result == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    rdx_macos_status status = RDX_MACOS_STATUS_OK;
    if (!RDX_TEST_INJECTED(RDX_TEST_MATCHING_SUCCESS_WITHOUT_ITERATOR)) {
        status = rdx_append_matching_candidates(
            result,
            "IOSCSIPeripheralDeviceNub"
        );
        if (status == RDX_MACOS_STATUS_OK) {
            status = rdx_append_matching_candidates(
                result,
                "IOSCSILogicalUnitNub"
            );
        }
    }
    if (status != RDX_MACOS_STATUS_OK) {
        rdx_macos_free_result(result);
        return status;
    }
    result->header.status = status;
    *out_result = result;
    return status;
}

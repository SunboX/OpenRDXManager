// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <string.h>

#if defined(RDX_MACOS_TEST_HOOKS)
bool rdx_macos_test_hostile_inputs(void) {
    rdx_macos_device *device = NULL;
    rdx_macos_device fake_device = {0};
    rdx_macos_scsi_lease fake_scsi = {0};
    rdx_macos_scsi_result *scsi = NULL;
    rdx_macos_mapping_result *mapping = NULL;
    rdx_macos_host_operation_result *host = NULL;
    rdx_macos_candidate_record invalid = {0};
    rdx_macos_scsi_request request = {0};
    request.abi_version = RDX_MACOS_ABI_VERSION;
    request.operation = RDX_MACOS_OPERATION_SELF_TEST;
    request.timeout_ms = 1;
    request.data_length = RDX_MACOS_MAX_TRANSFER_BYTES + 1;
    if (rdx_macos_enumerate(NULL) != RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        rdx_macos_open_candidate(NULL, &device) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        device != NULL) {
        rdx_macos_release_device(device);
        return false;
    }
    if (rdx_macos_open_candidate(&invalid, &device) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        device != NULL) {
        rdx_macos_release_device(device);
        return false;
    }
    if (rdx_macos_execute_scsi(&fake_scsi, &request, &scsi) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        scsi != NULL) {
        rdx_macos_free_result(scsi);
        return false;
    }
    request.reserved[0] = 0;
    request.data_length = 0;
    request.offset = 1;
    if (rdx_macos_execute_scsi(&fake_scsi, &request, &scsi) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        scsi != NULL) {
        rdx_macos_free_result(scsi);
        return false;
    }
    request.offset = 0;
    request.operation = UINT32_MAX;
    if (rdx_macos_execute_scsi(&fake_scsi, &request, &scsi) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        scsi != NULL) {
        rdx_macos_free_result(scsi);
        return false;
    }
    request.operation = RDX_MACOS_OPERATION_SELF_TEST;
    request.data_length = 1;
    if (rdx_macos_execute_scsi(&fake_scsi, &request, &scsi) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        scsi != NULL) {
        rdx_macos_free_result(scsi);
        return false;
    }
    request.data_length = 0;
    request.reserved[0] = 1;
    if (rdx_macos_execute_scsi(&fake_scsi, &request, &scsi) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        scsi != NULL) {
        rdx_macos_free_result(scsi);
        return false;
    }
    if (rdx_macos_execute_scsi(NULL, NULL, NULL) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        rdx_macos_map_media(NULL, &mapping) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        mapping != NULL ||
        rdx_macos_unmount(NULL, 1, &host) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        host != NULL ||
        rdx_macos_unmount_for_eject(NULL, 1, &host) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        host != NULL ||
        rdx_macos_eject(&fake_device, 0, &host) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT ||
        host != NULL) {
        rdx_macos_free_result(mapping);
        rdx_macos_free_result(host);
        return false;
    }
    return true;
}

static bool rdx_test_acquisition_failure(
    rdx_test_failure_point point,
    rdx_macos_status expected_status
) {
    rdx_macos_device device = {
        .mapping_pinned = true,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false
    };
    rdx_macos_scsi_lease *lease = NULL;
    rdx_test_inject_failure(point);
    rdx_macos_status status = rdx_macos_acquire_scsi(&device, &lease);
    rdx_macos_release_scsi(lease);
    return status == expected_status && lease == NULL &&
        atomic_load_explicit(&rdx_test_failure, memory_order_acquire) ==
            RDX_TEST_FAIL_NONE;
}

bool rdx_macos_test_exercise_failure_injections(void) {
    rdx_test_inject_failure(RDX_TEST_FAIL_RESULT_ALLOCATION);
    if (rdx_allocate_result(sizeof(rdx_macos_result_header), RDX_MACOS_RESULT_SCSI) !=
        NULL) {
        return false;
    }
    rdx_macos_result_header *result = rdx_allocate_result(
        sizeof(*result),
        RDX_MACOS_RESULT_SCSI
    );
    if (result == NULL) {
        return false;
    }
    rdx_macos_free_result(result);

    if (!rdx_test_acquisition_failure(
            RDX_TEST_FAIL_PLUGIN_CREATE,
            RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE
        ) ||
        !rdx_test_acquisition_failure(
            RDX_TEST_FAIL_QUERY_INTERFACE,
            RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE
        ) ||
        !rdx_test_acquisition_failure(
            RDX_TEST_FAIL_OBTAIN_EXCLUSIVE,
            RDX_MACOS_STATUS_BUSY
        ) ||
        !rdx_test_acquisition_failure(
            RDX_TEST_FAIL_SCSI_LEASE_ALLOCATION,
            RDX_MACOS_STATUS_RESOURCE_LIMIT
        )) {
        return false;
    }

    rdx_macos_device device = {
        .mapping_pinned = true,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false
    };
    rdx_macos_scsi_lease *lease = NULL;
    if (rdx_macos_acquire_scsi(&device, &lease) != RDX_MACOS_STATUS_OK ||
        lease == NULL) {
        rdx_macos_release_scsi(lease);
        return false;
    }
    rdx_macos_scsi_request request = {
        .abi_version = RDX_MACOS_ABI_VERSION,
        .operation = RDX_MACOS_OPERATION_INQUIRY_STANDARD,
        .timeout_ms = 1
    };
    rdx_macos_scsi_result *scsi_result = NULL;
    rdx_test_inject_failure(RDX_TEST_FAIL_TASK_CREATE);
    rdx_macos_status scsi_status = rdx_macos_execute_scsi(
        lease,
        &request,
        &scsi_result
    );
    rdx_macos_release_scsi(lease);
    if (scsi_status != RDX_MACOS_STATUS_RESOURCE_LIMIT || scsi_result == NULL ||
        scsi_result->attempted != 0 ||
        atomic_load_explicit(&rdx_test_failure, memory_order_acquire) !=
            RDX_TEST_FAIL_NONE) {
        rdx_macos_free_result(scsi_result);
        return false;
    }
    rdx_macos_free_result(scsi_result);

    return rdx_test_exercise_da_failure_injections();
}

rdx_macos_status rdx_macos_test_probe_known_non_scsi(void) {
    CFMutableDictionaryRef matching = IOServiceMatching("IOPlatformExpertDevice");
    if (matching == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service == IO_OBJECT_NULL) {
        return RDX_MACOS_STATUS_ENUMERATION_FAILED;
    }
    rdx_track_io_acquire();
    rdx_macos_candidate_record candidate = {0};
    IOReturn status = IORegistryEntryGetRegistryEntryID(
        service,
        &candidate.registry_entry_id
    );
    rdx_release_io(service);
    if (status != kIOReturnSuccess || candidate.registry_entry_id == 0) {
        return RDX_MACOS_STATUS_ENUMERATION_FAILED;
    }
    candidate.peripheral_type = 0;
    candidate.has_vendor = 1;
    candidate.has_product = 1;
    memcpy(candidate.vendor, "TANDBERG", sizeof("TANDBERG"));
    memcpy(candidate.product, "RDX", sizeof("RDX"));
    rdx_macos_device *device = NULL;
    rdx_macos_status probe = rdx_macos_open_candidate(&candidate, &device);
    rdx_macos_release_device(device);
    return probe;
}

static rdx_macos_candidate_record rdx_test_candidate_hint(
    const char *vendor,
    const char *product
) {
    rdx_macos_candidate_record candidate = {
        .registry_entry_id = 1,
        .peripheral_type = 0,
        .has_vendor = 1,
        .has_product = 1
    };
    size_t vendor_length = strlen(vendor);
    size_t product_length = strlen(product);
    if (vendor_length <= RDX_MACOS_MAX_TEXT_BYTES &&
        product_length <= RDX_MACOS_MAX_TEXT_BYTES) {
        memcpy(candidate.vendor, vendor, vendor_length + 1);
        memcpy(candidate.product, product, product_length + 1);
    }
    return candidate;
}

bool rdx_macos_test_candidate_prefilter_contract(void) {
    uint64_t plugins_before = atomic_load_explicit(
        &rdx_plugin_acquisitions,
        memory_order_relaxed
    );
    uint64_t interfaces_before = atomic_load_explicit(
        &rdx_interface_acquisitions,
        memory_order_relaxed
    );
    uint64_t exclusive_before = atomic_load_explicit(
        &rdx_exclusive_acquisitions,
        memory_order_relaxed
    );
    rdx_macos_candidate_record unrelated = rdx_test_candidate_hint(
        "Generic",
        "STORAGE DEVICE"
    );
    rdx_macos_candidate_record leading = rdx_test_candidate_hint(
        " TANDBERG",
        "RDX"
    );
    rdx_macos_candidate_record suffix = rdx_test_candidate_hint(
        "TANDBERG",
        "RDX USB"
    );
    rdx_macos_device *unexpected_device = NULL;
    if (rdx_macos_candidate_matches_rdx_hint(&unrelated) ||
        rdx_macos_candidate_matches_rdx_hint(&leading) ||
        rdx_macos_candidate_matches_rdx_hint(&suffix) ||
        rdx_macos_open_candidate(&unrelated, &unexpected_device) !=
            RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE ||
        unexpected_device != NULL ||
        rdx_macos_open_candidate(&leading, &unexpected_device) !=
            RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE ||
        unexpected_device != NULL ||
        rdx_macos_open_candidate(&suffix, &unexpected_device) !=
            RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE ||
        unexpected_device != NULL ||
        atomic_load_explicit(&rdx_plugin_acquisitions, memory_order_relaxed) !=
            plugins_before ||
        atomic_load_explicit(&rdx_interface_acquisitions, memory_order_relaxed) !=
            interfaces_before ||
        atomic_load_explicit(&rdx_exclusive_acquisitions, memory_order_relaxed) !=
            exclusive_before) {
        return false;
    }

    rdx_macos_candidate_record known = rdx_test_candidate_hint(
        "tandberg",
        "rDx             "
    );
    if (!rdx_macos_candidate_matches_rdx_hint(&known)) {
        return false;
    }
    rdx_macos_device device = {
        .mapping_pinned = true,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false
    };
    rdx_macos_scsi_lease *lease = NULL;
    if (rdx_macos_acquire_scsi(&device, &lease) != RDX_MACOS_STATUS_OK ||
        lease == NULL) {
        rdx_macos_release_scsi(lease);
        return false;
    }
    rdx_macos_scsi_request request = {
        .abi_version = RDX_MACOS_ABI_VERSION,
        .operation = RDX_MACOS_OPERATION_INQUIRY_STANDARD,
        .timeout_ms = 1
    };
    rdx_macos_scsi_result *result = NULL;
    rdx_macos_status status = rdx_macos_execute_scsi(
        lease,
        &request,
        &result
    );
    bool passed = status == RDX_MACOS_STATUS_RESOURCE_LIMIT &&
        result != NULL && result->attempted == 0 &&
        device.test_event_count == 5 &&
        device.test_events[0] == RDX_TEST_EVENT_REVALIDATE_MAPPING &&
        device.test_events[1] == RDX_TEST_EVENT_CHECK_MOUNTED &&
        device.test_events[2] == RDX_TEST_EVENT_CREATE_PLUGIN &&
        device.test_events[3] == RDX_TEST_EVENT_QUERY_INTERFACE &&
        device.test_events[4] == RDX_TEST_EVENT_OBTAIN_EXCLUSIVE;
    rdx_macos_free_result(result);
    rdx_macos_release_scsi(lease);
    return passed;
}

void rdx_macos_test_fail_next_matching_dictionary(void) {
    rdx_test_inject_failure(RDX_TEST_FAIL_MATCHING_DICTIONARY_CREATE);
}

void rdx_macos_test_succeed_next_matching_without_iterator(void) {
    rdx_test_inject_failure(RDX_TEST_MATCHING_SUCCESS_WITHOUT_ITERATOR);
}

bool rdx_macos_test_scsi_authority_order(void) {
    bool passed = false;
    rdx_macos_host_operation_result *unmount_result = NULL;
    rdx_macos_scsi_lease *lease = NULL;
    DASessionRef session = rdx_da_session_create();
    if (session == NULL) {
        return false;
    }
    rdx_track_cf_acquire();
    rdx_da_registry *registry = rdx_da_registry_create();
    if (registry == NULL) {
        rdx_release_cf(session);
        return false;
    }
    rdx_macos_device mounted = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = true
    };
    if (rdx_macos_acquire_scsi(&mounted, &lease) != RDX_MACOS_STATUS_BUSY ||
        lease != NULL || mounted.test_event_count != 2 ||
        mounted.test_events[0] != RDX_TEST_EVENT_REVALIDATE_MAPPING ||
        mounted.test_events[1] != RDX_TEST_EVENT_CHECK_MOUNTED) {
        goto cleanup;
    }
    mounted.test_event_count = 0;
    if (rdx_macos_unmount(&mounted, 1, &unmount_result) !=
            RDX_MACOS_STATUS_OK ||
        unmount_result == NULL || unmount_result->attempted != 1 ||
        unmount_result->completed != 1 ||
        unmount_result->rejection != RDX_MACOS_HOST_REJECTION_NONE ||
        unmount_result->dissenter_status != kDAReturnSuccess ||
        mounted.test_mounted || mounted.test_event_count != 2 ||
        mounted.test_events[0] != RDX_TEST_EVENT_UNMOUNT_COMPLETED ||
        mounted.test_events[1] != RDX_TEST_EVENT_CLAIM_COMPLETED) {
        goto cleanup;
    }
    rdx_macos_free_result(unmount_result);
    unmount_result = NULL;
    if (rdx_macos_acquire_scsi(&mounted, &lease) != RDX_MACOS_STATUS_OK ||
        lease == NULL || mounted.test_event_count != 7 ||
        mounted.test_events[2] != RDX_TEST_EVENT_REVALIDATE_MAPPING ||
        mounted.test_events[3] != RDX_TEST_EVENT_CHECK_MOUNTED ||
        mounted.test_events[4] != RDX_TEST_EVENT_CREATE_PLUGIN ||
        mounted.test_events[5] != RDX_TEST_EVENT_QUERY_INTERFACE ||
        mounted.test_events[6] != RDX_TEST_EVENT_OBTAIN_EXCLUSIVE) {
        goto cleanup;
    }
    rdx_macos_release_scsi(lease);
    lease = NULL;

    rdx_macos_device eject_unmount = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = true
    };
    if (rdx_macos_unmount_for_eject(&eject_unmount, 1, &unmount_result) !=
            RDX_MACOS_STATUS_OK ||
        unmount_result == NULL || unmount_result->attempted != 1 ||
        unmount_result->completed != 1 ||
        unmount_result->rejection != RDX_MACOS_HOST_REJECTION_NONE ||
        unmount_result->dissenter_status != kDAReturnSuccess ||
        eject_unmount.test_mounted || eject_unmount.whole_claimed ||
        eject_unmount.test_event_count != 1 ||
        eject_unmount.test_events[0] != RDX_TEST_EVENT_UNMOUNT_COMPLETED) {
        goto cleanup;
    }
    rdx_macos_free_result(unmount_result);
    unmount_result = NULL;

    rdx_macos_device already_unmounted = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false,
        .test_da_status = kDAReturnNotMounted,
        .whole_bsd_name = "disk14"
    };
    if (rdx_macos_unmount_for_eject(
            &already_unmounted,
            1,
            &unmount_result
        ) != RDX_MACOS_STATUS_OK ||
        unmount_result == NULL || unmount_result->attempted != 1 ||
        unmount_result->completed != 1 ||
        unmount_result->rejection != RDX_MACOS_HOST_REJECTION_NONE ||
        unmount_result->dissenter_status != kDAReturnSuccess ||
        already_unmounted.test_event_count != 1 ||
        already_unmounted.test_events[0] !=
            RDX_TEST_EVENT_UNMOUNT_COMPLETED) {
        goto cleanup;
    }
    rdx_macos_free_result(unmount_result);
    unmount_result = NULL;

    /* A generic DA unmount error is recoverable only through a successful,
     * non-forced Apple unmount of the freshly revalidated exact target. */
    for (uint32_t scenario = 0; scenario < 4; ++scenario) {
        rdx_macos_device generic_unmount = {
            .mapping_pinned = true,
            .session = session,
            .da_registry = registry,
            .test_fake = true,
            .test_revalidate_status = scenario == 1 ?
                RDX_MACOS_STATUS_DEVICE_REMOVED : RDX_MACOS_STATUS_OK,
            .test_mounted = true,
            .test_da_status = scenario == 3 ? kDAReturnBusy : kDAReturnError,
            .test_diskutil_status = scenario == 2 ?
                RDX_MACOS_STATUS_NATIVE_FAILURE : RDX_MACOS_STATUS_OK,
            .whole_bsd_name = "disk14"
        };
        const rdx_macos_status expected[] = {
            RDX_MACOS_STATUS_OK, RDX_MACOS_STATUS_DEVICE_REMOVED,
            RDX_MACOS_STATUS_NATIVE_FAILURE, RDX_MACOS_STATUS_BUSY
        };
        const uint32_t events[] = {4, 2, 3, 1};
        rdx_macos_status actual = rdx_macos_unmount(
            &generic_unmount, 1, &unmount_result
        );
        if (actual != expected[scenario] || unmount_result == NULL ||
            unmount_result->attempted != 1 || unmount_result->completed != 1 ||
            generic_unmount.test_event_count != events[scenario] ||
            generic_unmount.whole_claimed != (scenario == 0) ||
            generic_unmount.test_mounted != (scenario != 0) ||
            generic_unmount.test_events[0] != RDX_TEST_EVENT_UNMOUNT_COMPLETED ||
            (scenario != 3 && generic_unmount.test_events[1] !=
                RDX_TEST_EVENT_REVALIDATE_DISKUTIL_TARGET) ||
            ((scenario == 0 || scenario == 2) &&
                generic_unmount.test_events[2] !=
                    RDX_TEST_EVENT_DISKUTIL_UNMOUNT_COMPLETED) ||
            (scenario == 0 && generic_unmount.test_events[3] !=
                RDX_TEST_EVENT_CLAIM_COMPLETED)) {
            goto cleanup;
        }
        rdx_macos_free_result(unmount_result);
        unmount_result = NULL;
    }

    rdx_macos_device entitled_fallback = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = true,
        .test_da_status = kDAReturnNotPrivileged,
        .test_diskutil_status = RDX_MACOS_STATUS_OK,
        .whole_bsd_name = "disk14"
    };
    if (rdx_macos_unmount_for_eject(
            &entitled_fallback,
            1,
            &unmount_result
        ) != RDX_MACOS_STATUS_OK ||
        unmount_result == NULL || unmount_result->attempted != 1 ||
        unmount_result->completed != 1 ||
        unmount_result->rejection != RDX_MACOS_HOST_REJECTION_NONE ||
        unmount_result->dissenter_status != kDAReturnSuccess ||
        entitled_fallback.test_mounted || entitled_fallback.whole_claimed ||
        entitled_fallback.test_event_count != 3 ||
        entitled_fallback.test_events[0] != RDX_TEST_EVENT_UNMOUNT_COMPLETED ||
        entitled_fallback.test_events[1] !=
            RDX_TEST_EVENT_REVALIDATE_DISKUTIL_TARGET ||
        entitled_fallback.test_events[2] !=
            RDX_TEST_EVENT_DISKUTIL_UNMOUNT_COMPLETED) {
        goto cleanup;
    }
    rdx_macos_free_result(unmount_result);
    unmount_result = NULL;

    rdx_macos_host_operation_result *eject_result = NULL;
    rdx_macos_device eject_context_unavailable = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false,
        .test_da_status = kDAReturnSuccess,
        .whole_bsd_name = "disk14"
    };
    rdx_test_inject_failure(RDX_TEST_FAIL_DA_CONTEXT_CREATE);
    if (rdx_macos_eject(
            &eject_context_unavailable,
            1,
            &eject_result
        ) != RDX_MACOS_STATUS_RESOURCE_LIMIT || eject_result == NULL ||
        eject_result->attempted != 0 || eject_result->completed != 0 ||
        !eject_context_unavailable.mapping_pinned ||
        eject_context_unavailable.test_event_count != 0) {
        rdx_macos_free_result(eject_result);
        goto cleanup;
    }
    rdx_macos_free_result(eject_result);
    eject_result = NULL;

    rdx_macos_device rejected_eject = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false,
        .test_da_status = kDAReturnBusy,
        .whole_bsd_name = "disk14"
    };
    if (rdx_macos_eject(&rejected_eject, 1, &eject_result) !=
            RDX_MACOS_STATUS_BUSY || eject_result == NULL ||
        eject_result->attempted != 1 || eject_result->completed != 1 ||
        eject_result->rejection != RDX_MACOS_HOST_REJECTION_BUSY ||
        rejected_eject.mapping_pinned || rejected_eject.test_event_count != 1 ||
        rejected_eject.test_events[0] !=
            RDX_TEST_EVENT_EJECT_RAW_AUTHORITY_RELEASED) {
        rdx_macos_free_result(eject_result);
        goto cleanup;
    }
    rdx_macos_free_result(eject_result);
    eject_result = NULL;

    rdx_macos_device entitled_eject_fallback = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false,
        .test_da_status = kDAReturnNotPrivileged,
        .test_diskutil_status = RDX_MACOS_STATUS_OK,
        .whole_bsd_name = "disk14"
    };
    if (rdx_macos_eject(&entitled_eject_fallback, 1, &eject_result) !=
            RDX_MACOS_STATUS_OK ||
        eject_result == NULL || eject_result->attempted != 1 ||
        eject_result->completed != 1 ||
        eject_result->rejection != RDX_MACOS_HOST_REJECTION_NONE ||
        eject_result->dissenter_status != kDAReturnSuccess ||
        entitled_eject_fallback.mapping_pinned ||
        entitled_eject_fallback.test_event_count != 3 ||
        entitled_eject_fallback.test_events[0] !=
            RDX_TEST_EVENT_EJECT_RAW_AUTHORITY_RELEASED ||
        entitled_eject_fallback.test_events[1] !=
            RDX_TEST_EVENT_REVALIDATE_DISKUTIL_TARGET ||
        entitled_eject_fallback.test_events[2] !=
            RDX_TEST_EVENT_DISKUTIL_EJECT_COMPLETED) {
        rdx_macos_free_result(eject_result);
        goto cleanup;
    }
    rdx_macos_free_result(eject_result);
    eject_result = NULL;

    rdx_macos_device generic_eject_fallback = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK,
        .test_mounted = false,
        .test_da_status = kDAReturnError,
        .test_diskutil_status = RDX_MACOS_STATUS_OK,
        .whole_bsd_name = "disk14"
    };
    if (rdx_macos_eject(&generic_eject_fallback, 1, &eject_result) !=
            RDX_MACOS_STATUS_OK ||
        eject_result == NULL || eject_result->attempted != 1 ||
        eject_result->completed != 1 ||
        eject_result->rejection != RDX_MACOS_HOST_REJECTION_NONE ||
        eject_result->dissenter_status != kDAReturnSuccess ||
        generic_eject_fallback.mapping_pinned ||
        generic_eject_fallback.test_event_count != 3 ||
        generic_eject_fallback.test_events[0] !=
            RDX_TEST_EVENT_EJECT_RAW_AUTHORITY_RELEASED ||
        generic_eject_fallback.test_events[1] !=
            RDX_TEST_EVENT_REVALIDATE_DISKUTIL_TARGET ||
        generic_eject_fallback.test_events[2] !=
            RDX_TEST_EVENT_DISKUTIL_EJECT_COMPLETED) {
        rdx_macos_free_result(eject_result);
        goto cleanup;
    }
    rdx_macos_free_result(eject_result);
    eject_result = NULL;

    rdx_macos_device drifted_eject_fallback = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_DEVICE_REMOVED,
        .test_mounted = false,
        .test_da_status = kDAReturnError,
        .test_diskutil_status = RDX_MACOS_STATUS_OK,
        .whole_bsd_name = "disk14"
    };
    if (rdx_macos_eject(&drifted_eject_fallback, 1, &eject_result) !=
            RDX_MACOS_STATUS_DEVICE_REMOVED ||
        eject_result == NULL || eject_result->attempted != 1 ||
        eject_result->completed != 1 ||
        eject_result->dissenter_status != kDAReturnError ||
        drifted_eject_fallback.mapping_pinned ||
        drifted_eject_fallback.test_event_count != 2 ||
        drifted_eject_fallback.test_events[0] !=
            RDX_TEST_EVENT_EJECT_RAW_AUTHORITY_RELEASED ||
        drifted_eject_fallback.test_events[1] !=
            RDX_TEST_EVENT_REVALIDATE_DISKUTIL_TARGET) {
        rdx_macos_free_result(eject_result);
        goto cleanup;
    }
    rdx_macos_free_result(eject_result);

    rdx_macos_device pinned_during_transient_rematch = {
        .mapping_pinned = true,
        .session = session,
        .da_registry = registry,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_DEVICE_REMOVED,
        .test_mounted = true,
        .test_da_status = kDAReturnSuccess
    };
    if (rdx_macos_unmount_for_eject(
            &pinned_during_transient_rematch,
            1,
            &unmount_result
        ) != RDX_MACOS_STATUS_OK ||
        unmount_result == NULL || unmount_result->attempted != 1 ||
        unmount_result->completed != 1 ||
        unmount_result->rejection != RDX_MACOS_HOST_REJECTION_NONE ||
        unmount_result->dissenter_status != kDAReturnSuccess ||
        pinned_during_transient_rematch.test_mounted ||
        pinned_during_transient_rematch.test_event_count != 1 ||
        pinned_during_transient_rematch.test_events[0] !=
            RDX_TEST_EVENT_UNMOUNT_COMPLETED) {
        goto cleanup;
    }
    rdx_macos_free_result(unmount_result);
    unmount_result = NULL;

    rdx_macos_device externally_unmounted = {
        .mapping_pinned = true,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_DEVICE_REMOVED,
        .test_mounted = false,
        .whole_mounted = true
    };
    if (rdx_macos_confirm_unmounted_mapping(&externally_unmounted) !=
            RDX_MACOS_STATUS_OK || externally_unmounted.whole_mounted ||
        rdx_macos_acquire_scsi(&externally_unmounted, &lease) !=
            RDX_MACOS_STATUS_OK || lease == NULL) {
        goto cleanup;
    }
    rdx_macos_release_scsi(lease);
    lease = NULL;

    rdx_macos_device drifted = {
        .mapping_pinned = true,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_DEVICE_REMOVED,
        .test_mounted = false
    };
    passed = rdx_macos_acquire_scsi(&drifted, &lease) ==
            RDX_MACOS_STATUS_DEVICE_REMOVED &&
        lease == NULL && drifted.test_event_count == 1 &&
        drifted.test_events[0] == RDX_TEST_EVENT_REVALIDATE_MAPPING;

cleanup:
    rdx_macos_release_scsi(lease);
    rdx_macos_free_result(unmount_result);
    rdx_da_registry_shutdown(registry, session);
    rdx_release_cf(session);
    return passed;
}

bool rdx_macos_test_usb_bot_wire_contract(void) {
    const uint8_t inquiry[6] = {0x12, 0, 0, 0, 0x60, 0};
    const uint8_t expected_cbw[RDX_USB_BOT_CBW_LENGTH] = {
        0x55, 0x53, 0x42, 0x43,
        0x31, 0x58, 0x44, 0x52,
        0x60, 0, 0, 0,
        0x80, 0, 6,
        0x12, 0, 0, 0, 0x60, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    uint8_t cbw[RDX_USB_BOT_CBW_LENGTH] = {0};
    if (!rdx_usb_bot_build_cbw(inquiry, sizeof(inquiry), RDX_USB_BOT_DATA_IN,
            96, UINT32_C(0x52445831), cbw) ||
        memcmp(cbw, expected_cbw, sizeof(cbw)) != 0 ||
        rdx_usb_bot_build_cbw(inquiry, 0, RDX_USB_BOT_DATA_IN, 96, 1, cbw) ||
        rdx_usb_bot_build_cbw(inquiry, sizeof(inquiry), RDX_USB_BOT_NO_DATA,
            96, 1, cbw)) {
        return false;
    }
    uint8_t csw[RDX_USB_BOT_CSW_LENGTH] = {
        0x55, 0x53, 0x42, 0x53,
        0x31, 0x58, 0x44, 0x52,
        0x20, 0, 0, 0,
        RDX_USB_BOT_COMMAND_PASSED
    };
    uint32_t transferred = 0;
    rdx_usb_bot_csw_status status = RDX_USB_BOT_PHASE_ERROR;
    if (!rdx_usb_bot_parse_csw(csw, sizeof(csw), UINT32_C(0x52445831), 96,
            &transferred, &status) || transferred != 64 ||
        status != RDX_USB_BOT_COMMAND_PASSED) {
        return false;
    }
    uint8_t corrupted[RDX_USB_BOT_CSW_LENGTH];
    memcpy(corrupted, csw, sizeof(corrupted));
    corrupted[0] ^= 1U;
    if (rdx_usb_bot_parse_csw(corrupted, sizeof(corrupted), UINT32_C(0x52445831),
            96, &transferred, &status)) {
        return false;
    }
    memcpy(corrupted, csw, sizeof(corrupted));
    corrupted[4] ^= 1U;
    if (rdx_usb_bot_parse_csw(corrupted, sizeof(corrupted), UINT32_C(0x52445831),
            96, &transferred, &status)) {
        return false;
    }
    memcpy(corrupted, csw, sizeof(corrupted));
    corrupted[8] = 97;
    if (rdx_usb_bot_parse_csw(corrupted, sizeof(corrupted), UINT32_C(0x52445831),
            96, &transferred, &status)) {
        return false;
    }
    memcpy(corrupted, csw, sizeof(corrupted));
    corrupted[12] = 3;
    return !rdx_usb_bot_parse_csw(corrupted, sizeof(corrupted),
        UINT32_C(0x52445831), 96, &transferred, &status);
}

bool rdx_macos_test_transport_release_mapping_invalidation(void) {
    rdx_macos_device device = {
        .expected = {
            .registry_entry_id = 77,
            .peripheral_type = 0,
            .has_vendor = 1,
            .has_product = 1,
            .has_revision = 1,
            .has_serial = 1
        },
        .whole_registry_entry_id = 88,
        .whole_capacity_bytes = UINT64_C(320000000000),
        .whole_bsd_major = 1,
        .whole_bsd_minor = 2,
        .whole_media_uuid_present = true,
        .whole_media_is_whole = true,
        .whole_media_ejectable = true,
        .whole_media_removable = true,
        .whole_raw_fd = -1,
        .media_count = 1,
        .whole_mounted = true,
        .mapping_pinned = true,
        .test_fake = true
    };
    memcpy(device.expected.vendor, "TANDBERG", 8);
    memcpy(device.expected.product, "RDX", 3);
    memcpy(device.expected.revision, "0227", 4);
    memcpy(device.expected.serial, "7820746632", 10);
    memcpy(device.whole_media_uuid, "whole-media-generation", 22);
    memcpy(device.whole_bsd_name, "disk14", 6);
    rdx_macos_candidate_record expected = device.expected;

    rdx_macos_invalidate_media_mapping(NULL);
    rdx_macos_invalidate_media_mapping(&device);

    return !device.mapping_pinned && device.media_count == 0 &&
        !device.whole_mounted && device.whole_registry_entry_id == 0 &&
        device.whole_capacity_bytes == 0 && device.whole_bsd_major == 0 &&
        device.whole_bsd_minor == 0 && !device.whole_media_uuid_present &&
        !device.whole_media_is_whole && !device.whole_media_ejectable &&
        !device.whole_media_removable && device.whole_bsd_name[0] == '\0' &&
        device.whole_media_uuid[0] == '\0' &&
        rdx_records_match(&device.expected, &expected);
}

bool rdx_macos_test_media_presence_without_mapping_contract(void) {
    uint8_t present = UINT8_MAX;
    if (rdx_macos_media_present_without_mapping(NULL, &present) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT || present != 0 ||
        rdx_macos_media_present_without_mapping(NULL, NULL) !=
            RDX_MACOS_STATUS_INVALID_ARGUMENT) {
        return false;
    }

    rdx_macos_device absent = {
        .whole_raw_fd = -1,
        .test_fake = true,
        .test_revalidate_status = RDX_MACOS_STATUS_OK
    };
    present = UINT8_MAX;
    if (rdx_macos_media_present_without_mapping(&absent, &present) !=
            RDX_MACOS_STATUS_OK || present != 0 || absent.mapping_pinned ||
        absent.whole_raw_fd != -1) {
        return false;
    }

    rdx_macos_device present_device = absent;
    present_device.whole_registry_entry_id = UINT64_C(88);
    present = 0;
    if (rdx_macos_media_present_without_mapping(&present_device, &present) !=
            RDX_MACOS_STATUS_OK || present != 1 ||
        present_device.mapping_pinned || present_device.whole_raw_fd != -1 ||
        present_device.whole_registry_entry_id != UINT64_C(88)) {
        return false;
    }

    rdx_macos_device transient = absent;
    transient.test_revalidate_status = RDX_MACOS_STATUS_ENUMERATION_FAILED;
    present = UINT8_MAX;
    if (rdx_macos_media_present_without_mapping(&transient, &present) !=
            RDX_MACOS_STATUS_ENUMERATION_FAILED || present != 0 ||
        transient.mapping_pinned || transient.whole_raw_fd != -1) {
        return false;
    }

    rdx_macos_device pinned = present_device;
    pinned.mapping_pinned = true;
    present = UINT8_MAX;
    if (rdx_macos_media_present_without_mapping(&pinned, &present) !=
            RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE || present != 0 ||
        !pinned.mapping_pinned || pinned.whole_raw_fd != -1) {
        return false;
    }

    rdx_macos_device raw = present_device;
    raw.whole_raw_fd = 31;
    present = UINT8_MAX;
    return rdx_macos_media_present_without_mapping(&raw, &present) ==
            RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE && present == 0 &&
        !raw.mapping_pinned && raw.whole_raw_fd == 31 &&
        rdx_macos_media_present_without_mapping(&absent, NULL) ==
            RDX_MACOS_STATUS_INVALID_ARGUMENT;
}
#endif

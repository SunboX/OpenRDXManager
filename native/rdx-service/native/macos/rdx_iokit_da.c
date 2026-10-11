// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef enum rdx_da_terminal {
    RDX_DA_PENDING = 0,
    RDX_DA_COMPLETED = 1,
    RDX_DA_ABANDONED = 2
} rdx_da_terminal;

typedef struct rdx_da_callback_context rdx_da_callback_context;

struct rdx_da_registry {
    _Atomic uint32_t references;
    _Atomic bool shutdown;
    dispatch_queue_t queue;
    _Atomic(rdx_da_callback_context *) slots[RDX_MACOS_MAX_DA_CONTEXTS];
};

struct rdx_da_callback_context {
    _Atomic uint32_t references;
    _Atomic uint32_t terminal;
    _Atomic int64_t dissenter_status;
    rdx_da_registry *registry;
    DASessionRef session;
    dispatch_semaphore_t semaphore;
    uint32_t slot;
    bool unclaim_if_abandoned;
#if defined(RDX_MACOS_TEST_HOOKS)
    _Atomic bool test_pause_after_signal;
    _Atomic bool test_continue_after_signal;
#endif
};

static void rdx_da_context_detach(rdx_da_callback_context *context);
static bool rdx_da_context_abandon(rdx_da_callback_context *context);
static rdx_macos_status rdx_status_from_da(DAReturn status);
static void rdx_emit_fixed_trace(const char *code);

/*
 * Validates only the authority retained by the immediately preceding media
 * pin. A second global IOMedia snapshot here can observe the storage-rematch
 * generation in transition and reject the exact DADiskRef that the caller has
 * already authorized. The Disk Arbitration callback remains responsible for
 * reporting a device that genuinely departed before dispatch.
 */
static rdx_macos_status rdx_validate_pinned_da_authority(
    rdx_macos_device *device
) {
    if (device == NULL || !device->mapping_pinned || device->session == NULL ||
        device->da_registry == NULL) {
        rdx_emit_fixed_trace("macos-da-pinned-authority-missing");
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        rdx_emit_fixed_trace("macos-da-pinned-authority-succeeded");
        return RDX_MACOS_STATUS_OK;
    }
#endif
    if (device->whole_disk == NULL || device->whole_media == IO_OBJECT_NULL ||
        device->whole_registry_entry_id == 0 || device->whole_raw_fd < 0) {
        rdx_emit_fixed_trace("macos-da-pinned-authority-missing");
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    if (!rdx_raw_fd_matches_disk(device->whole_raw_fd, device->whole_disk)) {
        rdx_emit_fixed_trace("macos-da-pinned-raw-disk-mismatch");
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    struct stat raw_identity = {0};
    if (fstat(device->whole_raw_fd, &raw_identity) != 0 ||
        !S_ISCHR(raw_identity.st_mode) ||
        (uint32_t)major(raw_identity.st_rdev) != device->whole_bsd_major ||
        (uint32_t)minor(raw_identity.st_rdev) != device->whole_bsd_minor) {
        rdx_emit_fixed_trace("macos-da-pinned-raw-identity-mismatch");
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    io_service_t disk_media = DADiskCopyIOMedia(device->whole_disk);
    if (disk_media == IO_OBJECT_NULL) {
        rdx_emit_fixed_trace("macos-da-pinned-media-missing");
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    rdx_track_io_acquire();
    if (!IOObjectIsEqualTo(disk_media, device->whole_media)) {
        rdx_release_io(disk_media);
        rdx_emit_fixed_trace("macos-da-pinned-media-object-mismatch");
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    uint64_t disk_media_id = 0;
    if (IORegistryEntryGetRegistryEntryID(disk_media, &disk_media_id) !=
            kIOReturnSuccess ||
        disk_media_id == 0) {
        rdx_release_io(disk_media);
        rdx_emit_fixed_trace("macos-da-pinned-media-id-unavailable");
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    rdx_release_io(disk_media);
    if (disk_media_id != device->whole_registry_entry_id) {
        rdx_emit_fixed_trace("macos-da-pinned-media-id-mismatch");
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    rdx_emit_fixed_trace("macos-da-pinned-authority-succeeded");
    return RDX_MACOS_STATUS_OK;
}

/* Releases the retained raw device only after exact eject authority is proven. */
static void rdx_release_raw_authority_for_eject(rdx_macos_device *device) {
    if (device == NULL) {
        return;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        rdx_test_record_event(
            device,
            RDX_TEST_EVENT_EJECT_RAW_AUTHORITY_RELEASED
        );
        rdx_emit_fixed_trace("macos-eject-raw-authority-released");
        return;
    }
#endif
    int descriptor = device->whole_raw_fd;
    device->whole_raw_fd = -1;
    if (descriptor >= 0) {
        (void)close(descriptor);
    }
    rdx_emit_fixed_trace("macos-eject-raw-authority-released");
}

static bool rdx_da_context_reserve_global_slot(void) {
    uint64_t current = atomic_load_explicit(
        &rdx_da_contexts_outstanding,
        memory_order_acquire
    );
    while (current < RDX_MACOS_MAX_DA_CONTEXTS) {
        if (atomic_compare_exchange_weak_explicit(
                &rdx_da_contexts_outstanding,
                &current,
                current + 1,
                memory_order_acq_rel,
                memory_order_acquire
            )) {
            return true;
        }
    }
    return false;
}

static void rdx_release_dispatch_queue(dispatch_queue_t queue) {
    if (queue == NULL) {
        return;
    }
#if !OS_OBJECT_USE_OBJC
    dispatch_release(queue);
#else
    (void)queue;
#endif
}

static void rdx_release_dispatch_semaphore(dispatch_semaphore_t semaphore) {
    if (semaphore == NULL) {
        return;
    }
#if !OS_OBJECT_USE_OBJC
    dispatch_release(semaphore);
#else
    (void)semaphore;
#endif
}

static void rdx_da_registry_retain(rdx_da_registry *registry) {
    atomic_fetch_add_explicit(&registry->references, 1, memory_order_relaxed);
}

static void rdx_da_registry_release(rdx_da_registry *registry) {
    if (registry == NULL ||
        atomic_fetch_sub_explicit(
            &registry->references,
            1,
            memory_order_acq_rel
        ) != 1) {
        return;
    }
    rdx_release_dispatch_queue(registry->queue);
    atomic_fetch_add_explicit(
        &rdx_da_registry_frees,
        1,
        memory_order_relaxed
    );
    free(registry);
}

rdx_da_registry *rdx_da_registry_create(void) {
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_DA_REGISTRY_CREATE)) {
        return NULL;
    }
    rdx_da_registry *registry = calloc(1, sizeof(*registry));
    if (registry == NULL) {
        return NULL;
    }
    registry->queue = dispatch_queue_create(
        "com.openrdx.hardware.disk-arbitration",
        DISPATCH_QUEUE_SERIAL
    );
    if (registry->queue == NULL) {
        free(registry);
        return NULL;
    }
    atomic_init(&registry->references, 1);
    atomic_init(&registry->shutdown, false);
    for (uint32_t index = 0; index < RDX_MACOS_MAX_DA_CONTEXTS; ++index) {
        atomic_init(&registry->slots[index], NULL);
    }
    atomic_fetch_add_explicit(
        &rdx_da_registry_allocations,
        1,
        memory_order_relaxed
    );
    return registry;
}

dispatch_queue_t rdx_da_registry_queue(rdx_da_registry *registry) {
    return registry == NULL ? NULL : registry->queue;
}

static void rdx_da_context_release(rdx_da_callback_context *context) {
    if (context == NULL ||
        atomic_fetch_sub_explicit(
            &context->references,
            1,
            memory_order_acq_rel
        ) != 1) {
        return;
    }
    rdx_da_registry *registry = context->registry;
    DASessionRef session = context->session;
    rdx_release_dispatch_semaphore(context->semaphore);
    rdx_release_cf(session);
    atomic_fetch_add_explicit(&rdx_da_context_frees, 1, memory_order_relaxed);
    atomic_fetch_sub_explicit(
        &rdx_da_contexts_outstanding,
        1,
        memory_order_relaxed
    );
    free(context);
    rdx_da_registry_release(registry);
}

static rdx_da_callback_context *rdx_da_context_create(
    rdx_da_registry *registry,
    DASessionRef session
) {
    if (registry == NULL || session == NULL ||
        atomic_load_explicit(&registry->shutdown, memory_order_acquire)) {
        return NULL;
    }
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_DA_CONTEXT_CREATE)) {
        return NULL;
    }
    if (!rdx_da_context_reserve_global_slot()) {
        return NULL;
    }
    rdx_da_callback_context *context = calloc(1, sizeof(*context));
    if (context == NULL) {
        atomic_fetch_sub_explicit(
            &rdx_da_contexts_outstanding,
            1,
            memory_order_relaxed
        );
        return NULL;
    }
    context->semaphore = dispatch_semaphore_create(0);
    if (context->semaphore == NULL) {
        free(context);
        atomic_fetch_sub_explicit(
            &rdx_da_contexts_outstanding,
            1,
            memory_order_relaxed
        );
        return NULL;
    }
    atomic_init(&context->references, 3);
    atomic_init(&context->terminal, RDX_DA_PENDING);
    atomic_init(&context->dissenter_status, kDAReturnSuccess);
#if defined(RDX_MACOS_TEST_HOOKS)
    atomic_init(&context->test_pause_after_signal, false);
    atomic_init(&context->test_continue_after_signal, false);
#endif
    context->registry = registry;
    rdx_da_registry_retain(registry);
    context->session = session;
    CFRetain(session);
    rdx_track_cf_acquire();
    if (atomic_load_explicit(&registry->shutdown, memory_order_acquire)) {
        rdx_release_dispatch_semaphore(context->semaphore);
        rdx_release_cf(context->session);
        rdx_da_registry_release(registry);
        free(context);
        atomic_fetch_sub_explicit(
            &rdx_da_contexts_outstanding,
            1,
            memory_order_relaxed
        );
        return NULL;
    }
    for (uint32_t index = 0; index < RDX_MACOS_MAX_DA_CONTEXTS; ++index) {
        rdx_da_callback_context *expected = NULL;
        if (atomic_compare_exchange_strong_explicit(
                &registry->slots[index],
                &expected,
                context,
                memory_order_release,
                memory_order_relaxed
            )) {
            context->slot = index;
            atomic_fetch_add_explicit(
                &rdx_da_context_allocations,
                1,
                memory_order_relaxed
            );
            if (atomic_load_explicit(
                    &registry->shutdown,
                    memory_order_acquire
                )) {
                (void)rdx_da_context_abandon(context);
                rdx_da_context_detach(context);
                /* No API submission occurred, so creation still owns both the
                 * prospective caller and callback refs. */
                rdx_da_context_release(context);
                rdx_da_context_release(context);
                return NULL;
            }
            return context;
        }
    }
    rdx_release_dispatch_semaphore(context->semaphore);
    rdx_release_cf(context->session);
    rdx_da_registry_release(registry);
    free(context);
    atomic_fetch_sub_explicit(
        &rdx_da_contexts_outstanding,
        1,
        memory_order_relaxed
    );
    return NULL;
}

static void rdx_da_context_detach(rdx_da_callback_context *context) {
    rdx_da_callback_context *expected = context;
    if (atomic_compare_exchange_strong_explicit(
        &context->registry->slots[context->slot],
        &expected,
        NULL,
        memory_order_acq_rel,
        memory_order_acquire
    )) {
        /* The registry slot owns a ref distinct from caller and callback. */
        rdx_da_context_release(context);
    }
}

static bool rdx_da_context_abandon(rdx_da_callback_context *context) {
    uint32_t expected = RDX_DA_PENDING;
    return atomic_compare_exchange_strong_explicit(
        &context->terminal,
        &expected,
        RDX_DA_ABANDONED,
        memory_order_acq_rel,
        memory_order_acquire
    );
}

static bool rdx_da_registry_has_outstanding(rdx_da_registry *registry) {
    if (registry == NULL) {
        return false;
    }
    for (uint32_t index = 0; index < RDX_MACOS_MAX_DA_CONTEXTS; ++index) {
        if (atomic_load_explicit(
                &registry->slots[index],
                memory_order_acquire
            ) != NULL) {
            return true;
        }
    }
    return false;
}

static void rdx_da_queue_barrier(void *context) {
    (void)context;
}

void rdx_da_registry_shutdown(
    rdx_da_registry *registry,
    DASessionRef session
) {
    if (registry == NULL) {
        return;
    }
    bool already_shutdown = atomic_exchange_explicit(
        &registry->shutdown,
        true,
        memory_order_acq_rel
    );
    if (!already_shutdown) {
        if (session != NULL) {
            DASessionSetDispatchQueue(session, NULL);
        }
        dispatch_sync_f(registry->queue, NULL, rdx_da_queue_barrier);
        for (uint32_t index = 0; index < RDX_MACOS_MAX_DA_CONTEXTS; ++index) {
            rdx_da_callback_context *context = atomic_exchange_explicit(
                &registry->slots[index],
                NULL,
                memory_order_acq_rel
            );
            if (context != NULL) {
                (void)rdx_da_context_abandon(context);
                /* Release only registry-slot ownership. The callback ref keeps
                 * its context, session, registry, and queue in a process-lifetime
                 * bounded quarantine until a late callback consumes it. */
                rdx_da_context_release(context);
            }
        }
    }
    rdx_da_registry_release(registry);
}

DASessionRef rdx_da_session_create(void) {
    if (RDX_TEST_INJECTED(RDX_TEST_FAIL_DA_SESSION_CREATE)) {
        return NULL;
    }
    return DASessionCreate(kCFAllocatorDefault);
}

static void rdx_da_operation_complete(
    DADiskRef disk,
    DAReturn status,
    void *context
) {
    rdx_da_callback_context *state = context;
    if (state == NULL) {
        return;
    }
    atomic_store_explicit(
        &state->dissenter_status,
        status,
        memory_order_relaxed
    );
    uint32_t expected = RDX_DA_PENDING;
    bool completed = atomic_compare_exchange_strong_explicit(
        &state->terminal,
        &expected,
        RDX_DA_COMPLETED,
        memory_order_release,
        memory_order_acquire
    );
    if (!completed && expected == RDX_DA_ABANDONED &&
        state->unclaim_if_abandoned && status == kDAReturnSuccess &&
        disk != NULL) {
        DADiskUnclaim(disk);
    }
    /* Retire the completed registry slot before waking the caller. Safe Eject
     * immediately dispatches eject after unmount; waking first exposed this
     * completed callback as a false outstanding operation. Caller and callback
     * references keep the context and semaphore alive after detachment. */
    rdx_da_context_detach(state);
    (void)dispatch_semaphore_signal(state->semaphore);
#if defined(RDX_MACOS_TEST_HOOKS)
        if (atomic_load_explicit(
            &state->test_pause_after_signal,
            memory_order_acquire
        )) {
        while (!atomic_load_explicit(
                &state->test_continue_after_signal,
                memory_order_acquire
            )) {
        }
    }
#endif
    rdx_da_context_release(state);
}

static void rdx_da_operation_callback(
    DADiskRef disk,
    DADissenterRef dissenter,
    void *context
) {
    DAReturn status = dissenter == NULL ?
        kDAReturnSuccess : DADissenterGetStatus(dissenter);
    rdx_da_operation_complete(disk, status, context);
}

static DADissenterRef rdx_da_claim_release_callback(
    DADiskRef disk,
    void *context
) {
    (void)disk;
    (void)context;
    return DADissenterCreate(kCFAllocatorDefault, kDAReturnBusy, NULL);
}

static rdx_macos_status rdx_claim_whole_disk(
    rdx_macos_device *device,
    uint32_t timeout_ms
) {
    if (device->whole_claimed) {
        return RDX_MACOS_STATUS_OK;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        device->whole_claimed = true;
        rdx_test_record_event(device, RDX_TEST_EVENT_CLAIM_COMPLETED);
        return RDX_MACOS_STATUS_OK;
    }
#endif
    rdx_da_callback_context *context = rdx_da_context_create(
        device->da_registry,
        device->session
    );
    if (context == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    context->unclaim_if_abandoned = true;
    DADiskClaim(
        device->whole_disk,
        kDADiskClaimOptionDefault,
        rdx_da_claim_release_callback,
        NULL,
        rdx_da_operation_callback,
        context
    );
    dispatch_time_t deadline = dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)timeout_ms * NSEC_PER_MSEC
    );
    long wait_status = dispatch_semaphore_wait(context->semaphore, deadline);
    if (wait_status != 0) {
        (void)rdx_da_context_abandon(context);
    }
    uint32_t terminal = atomic_load_explicit(
        &context->terminal,
        memory_order_acquire
    );
    rdx_macos_status status = RDX_MACOS_STATUS_TIMED_OUT;
    if (terminal == RDX_DA_COMPLETED) {
        DAReturn claim_status = (DAReturn)atomic_load_explicit(
            &context->dissenter_status,
            memory_order_acquire
        );
        status = rdx_status_from_da(claim_status);
        if (status == RDX_MACOS_STATUS_OK) {
            device->whole_claimed = true;
        }
    }
    rdx_da_context_release(context);
    return status;
}

static rdx_macos_status rdx_status_from_da(DAReturn status) {
    if (status == kDAReturnSuccess) {
        return RDX_MACOS_STATUS_OK;
    }
    if (status == kDAReturnBusy || status == kDAReturnExclusiveAccess) {
        return RDX_MACOS_STATUS_BUSY;
    }
    if (status == kDAReturnNotPermitted || status == kDAReturnNotPrivileged) {
        return RDX_MACOS_STATUS_ACCESS_DENIED;
    }
    if (status == kDAReturnNotFound || status == kDAReturnNotReady) {
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    if (status == kDAReturnNoResources) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    return RDX_MACOS_STATUS_NATIVE_FAILURE;
}

/* Emits only compile-time diagnostic tokens accepted by the parent process. */
static void rdx_emit_fixed_trace(const char *code) {
    if (code == NULL) {
        return;
    }
    (void)fprintf(stderr, "openrdx-hardware: trace %s\n", code);
    (void)fflush(stderr);
}

/* Classifies the direct callback result without exposing native status data. */
static void rdx_trace_da_outcome(rdx_macos_status status) {
    switch (status) {
        case RDX_MACOS_STATUS_OK:
            rdx_emit_fixed_trace("macos-da-direct-succeeded");
            return;
        case RDX_MACOS_STATUS_ACCESS_DENIED:
            rdx_emit_fixed_trace("macos-da-direct-access-denied");
            return;
        case RDX_MACOS_STATUS_BUSY:
            rdx_emit_fixed_trace("macos-da-direct-busy");
            return;
        case RDX_MACOS_STATUS_DEVICE_REMOVED:
            rdx_emit_fixed_trace("macos-da-direct-device-removed");
            return;
        case RDX_MACOS_STATUS_RESOURCE_LIMIT:
            rdx_emit_fixed_trace("macos-da-direct-resource-limit");
            return;
        case RDX_MACOS_STATUS_TIMED_OUT:
            rdx_emit_fixed_trace("macos-da-direct-timed-out");
            return;
        default:
            rdx_emit_fixed_trace("macos-da-direct-failed");
            return;
    }
}

static uint8_t rdx_rejection_from_da(DAReturn status) {
    if (status == kDAReturnBusy || status == kDAReturnExclusiveAccess) {
        return RDX_MACOS_HOST_REJECTION_BUSY;
    }
    if (status == kDAReturnNotPermitted || status == kDAReturnNotPrivileged) {
        return RDX_MACOS_HOST_REJECTION_ACCESS_DENIED;
    }
    return RDX_MACOS_HOST_REJECTION_NONE;
}

#include "rdx_iokit_da_fallback.inc"

static rdx_macos_status rdx_run_da_operation(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    bool eject,
    bool claim_after_unmount,
    rdx_macos_host_operation_result **out_result
) {
    if (out_result == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_result = NULL;
    if (device == NULL || timeout_ms == 0 || timeout_ms > 30000U) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    rdx_macos_host_operation_result *result = rdx_allocate_result(
        sizeof(*result),
        RDX_MACOS_RESULT_HOST_OPERATION
    );
    if (result == NULL) {
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    rdx_macos_status status = rdx_validate_pinned_da_authority(device);
    if (status != RDX_MACOS_STATUS_OK) {
        result->header.status = status;
        *out_result = result;
        return status;
    }
    if (device->da_registry == NULL ||
        rdx_da_registry_has_outstanding(device->da_registry)) {
        rdx_emit_fixed_trace("macos-da-registry-busy");
        status = RDX_MACOS_STATUS_BUSY;
        result->header.status = status;
        *out_result = result;
        return status;
    }
    rdx_da_callback_context *context = rdx_da_context_create(
        device->da_registry,
        device->session
    );
    if (context == NULL) {
        rdx_emit_fixed_trace("macos-da-context-unavailable");
        status = RDX_MACOS_STATUS_RESOURCE_LIMIT;
        result->header.status = status;
        *out_result = result;
        return status;
    }
    result->attempted = 1;
    if (eject) {
        /* Release only after every non-dispatch gate succeeds. The retained
         * descriptor proves exact identity up to this boundary, while keeping
         * it open across DADiskEject would make this process an eject blocker. */
        rdx_release_raw_authority_for_eject(device);
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        if (!eject) {
            rdx_test_record_event(device, RDX_TEST_EVENT_UNMOUNT_COMPLETED);
        }
        rdx_da_operation_complete(NULL, device->test_da_status, context);
    } else
#endif
    if (eject) {
        DADiskEject(
            device->whole_disk,
            kDADiskEjectOptionDefault,
            rdx_da_operation_callback,
            context
        );
    } else {
        DADiskUnmount(
            device->whole_disk,
            kDADiskUnmountOptionWhole,
            rdx_da_operation_callback,
            context
        );
    }
    dispatch_time_t deadline = dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)timeout_ms * NSEC_PER_MSEC
    );
    long wait_status = dispatch_semaphore_wait(context->semaphore, deadline);
    if (wait_status != 0) {
        (void)rdx_da_context_abandon(context);
    }
    uint32_t terminal = atomic_load_explicit(
        &context->terminal,
        memory_order_acquire
    );
    if (terminal != RDX_DA_COMPLETED) {
        status = RDX_MACOS_STATUS_TIMED_OUT;
    } else {
        result->completed = 1;
        result->dissenter_status = atomic_load_explicit(
            &context->dissenter_status,
            memory_order_acquire
        );
        DAReturn direct_status = (DAReturn)result->dissenter_status;
        result->rejection = rdx_rejection_from_da(direct_status);
        if (!eject && direct_status == kDAReturnNotMounted) {
            /* The transport handoff can leave the exact disk already
             * unmounted. That satisfies only this unmount postcondition; it
             * does not make an eject callback successful. */
            rdx_emit_fixed_trace("macos-da-direct-already-unmounted");
            status = RDX_MACOS_STATUS_OK;
            result->dissenter_status = kDAReturnSuccess;
            result->rejection = RDX_MACOS_HOST_REJECTION_NONE;
        } else {
            status = rdx_status_from_da(direct_status);
            rdx_trace_da_outcome(status);
            bool entitlement_denied =
                status == RDX_MACOS_STATUS_ACCESS_DENIED &&
                (direct_status == kDAReturnNotPrivileged ||
                    direct_status == kDAReturnNotPermitted);
            bool generic_da_failure = status == RDX_MACOS_STATUS_NATIVE_FAILURE;
            if (entitlement_denied || generic_da_failure) {
                /* RDX can return a generic DA error for unmount as well as
                 * eject. Never promote that callback to success: revalidate
                 * the exact target and require Apple's non-forced tool to
                 * succeed. Busy, removed, and timed-out callbacks stay closed. */
                status = rdx_revalidate_diskutil_target(device, eject);
                if (status == RDX_MACOS_STATUS_OK) {
                    status = rdx_run_diskutil_operation(
                        device,
                        timeout_ms,
                        eject
                    );
                }
                if (status == RDX_MACOS_STATUS_OK) {
                    result->dissenter_status = kDAReturnSuccess;
                    result->rejection = RDX_MACOS_HOST_REJECTION_NONE;
                }
            }
        }
        if (!eject && status == RDX_MACOS_STATUS_OK) {
            device->whole_mounted = false;
            for (uint32_t index = 0; index < device->media_count; ++index) {
                device->media_mounted[index] = false;
            }
            if (claim_after_unmount) {
                /* A mounted filesystem owns the disk and can reject an early
                 * exclusive claim. Unmount first, then claim the now-idle exact
                 * whole disk so automount cannot race the following SCSI lease. */
                status = rdx_claim_whole_disk(device, timeout_ms);
            }
        }
    }
    if (claim_after_unmount && status != RDX_MACOS_STATUS_OK &&
        device->whole_claimed) {
#if defined(RDX_MACOS_TEST_HOOKS)
        if (!device->test_fake)
#endif
        {
            DADiskUnclaim(device->whole_disk);
        }
        device->whole_claimed = false;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake && !eject && status == RDX_MACOS_STATUS_OK) {
        device->test_mounted = false;
    }
#endif
    bool clear_after_eject = eject && result->attempted != 0;
    rdx_da_context_release(context);
    if (clear_after_eject) {
        /* Eject dispatch closes the retained raw descriptor before submission,
         * so this media generation cannot be safely reused after any callback
         * outcome. Retire it before either retry or non-owning readback. */
#if defined(RDX_MACOS_TEST_HOOKS)
        if (device->test_fake) {
            /* Synthetic cases share one test session and registry; production
             * mapping-release ownership is covered by the invalidation hook. */
            device->mapping_pinned = false;
        } else
#endif
        {
            rdx_clear_mapping(device);
        }
    }
    result->header.status = status;
    *out_result = result;
    return status;
}

rdx_macos_status rdx_macos_unmount(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    rdx_macos_host_operation_result **out_result
) {
    return rdx_run_da_operation(device, timeout_ms, false, true, out_result);
}

rdx_macos_status rdx_macos_unmount_for_eject(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    rdx_macos_host_operation_result **out_result
) {
    return rdx_run_da_operation(device, timeout_ms, false, false, out_result);
}

rdx_macos_status rdx_macos_eject(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    rdx_macos_host_operation_result **out_result
) {
    return rdx_run_da_operation(device, timeout_ms, true, false, out_result);
}

#include "rdx_iokit_da_tests.inc"

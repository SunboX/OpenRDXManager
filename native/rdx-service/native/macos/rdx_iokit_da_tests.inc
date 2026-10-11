// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/* Private callback lifetime fixtures; compiled only with test hooks. */
#if defined(RDX_MACOS_TEST_HOOKS)
static DASessionRef rdx_da_test_session(void) {
    DASessionRef session = rdx_da_session_create();
    if (session != NULL) {
        rdx_track_cf_acquire();
    }
    return session;
}

static bool rdx_da_test_reentrant_and_late(void) {
    DASessionRef session = rdx_da_test_session();
    rdx_da_registry *registry = rdx_da_registry_create();
    if (session == NULL || registry == NULL) {
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }

    rdx_da_callback_context *reentrant = rdx_da_context_create(
        registry,
        session
    );
    if (reentrant == NULL) {
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }
    rdx_da_operation_callback(NULL, NULL, reentrant);
    if (atomic_load_explicit(&reentrant->terminal, memory_order_acquire) !=
            RDX_DA_COMPLETED) {
        rdx_da_context_release(reentrant);
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }
    rdx_da_context_release(reentrant);

    rdx_da_callback_context *late = rdx_da_context_create(registry, session);
    if (late == NULL || !rdx_da_context_abandon(late)) {
        rdx_da_context_release(late);
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }
    rdx_da_context_release(late);
    rdx_da_operation_callback(NULL, NULL, late);

    rdx_da_registry_shutdown(registry, session);
    rdx_release_cf(session);
    return true;
}

static bool rdx_da_test_post_shutdown_delivery(void) {
    DASessionRef session = rdx_da_test_session();
    rdx_da_registry *registry = rdx_da_registry_create();
    if (session == NULL || registry == NULL) {
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }
    rdx_da_callback_context *context = rdx_da_context_create(
        registry,
        session
    );
    if (context == NULL) {
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }
    rdx_da_context_release(context);
    rdx_da_registry_shutdown(registry, session);
    rdx_release_cf(session);
    /* The submitted callback owns the final ref after shutdown. */
    rdx_da_operation_callback(NULL, NULL, context);
    return true;
}

static void rdx_da_test_deliver_callback(void *opaque) {
    rdx_da_operation_callback(NULL, NULL, opaque);
}

/* Proves a waiter cannot start the next DA operation while the completed
 * callback still occupies its registry slot. */
static bool rdx_da_test_detaches_before_waiter_wakes(void) {
    DASessionRef session = rdx_da_test_session();
    rdx_da_registry *registry = rdx_da_registry_create();
    dispatch_queue_t delivery_queue = dispatch_queue_create(
        "com.openrdx.hardware.disk-arbitration-wake-test",
        DISPATCH_QUEUE_SERIAL
    );
    if (session == NULL || registry == NULL || delivery_queue == NULL) {
        rdx_release_dispatch_queue(delivery_queue);
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }
    rdx_da_callback_context *context = rdx_da_context_create(
        registry,
        session
    );
    if (context == NULL) {
        rdx_release_dispatch_queue(delivery_queue);
        rdx_da_registry_shutdown(registry, session);
        rdx_release_cf(session);
        return false;
    }
    atomic_store_explicit(
        &context->test_pause_after_signal,
        true,
        memory_order_release
    );
    dispatch_async_f(
        delivery_queue,
        context,
        rdx_da_test_deliver_callback
    );
    dispatch_time_t deadline = dispatch_time(
        DISPATCH_TIME_NOW,
        (int64_t)NSEC_PER_SEC
    );
    long wait_status = dispatch_semaphore_wait(context->semaphore, deadline);
    bool detached_before_wake = !rdx_da_registry_has_outstanding(registry);
    atomic_store_explicit(
        &context->test_continue_after_signal,
        true,
        memory_order_release
    );
    dispatch_sync_f(delivery_queue, NULL, rdx_da_queue_barrier);
    rdx_da_context_release(context);
    rdx_release_dispatch_queue(delivery_queue);
    rdx_da_registry_shutdown(registry, session);
    rdx_release_cf(session);
    return wait_status == 0 && detached_before_wake;
}

typedef struct rdx_da_test_delivery {
    rdx_da_callback_context *context;
    _Atomic bool ready;
    _Atomic bool deliver;
} rdx_da_test_delivery;

static void rdx_da_test_deliver_concurrently(void *opaque) {
    rdx_da_test_delivery *delivery = opaque;
    atomic_store_explicit(&delivery->ready, true, memory_order_release);
    while (!atomic_load_explicit(&delivery->deliver, memory_order_acquire)) {
    }
    rdx_da_operation_callback(NULL, NULL, delivery->context);
}

static bool rdx_da_test_concurrent_shutdown(void) {
    for (uint32_t iteration = 0; iteration < 32; ++iteration) {
        DASessionRef session = rdx_da_test_session();
        rdx_da_registry *registry = rdx_da_registry_create();
        dispatch_queue_t delivery_queue = dispatch_queue_create(
            "com.openrdx.hardware.disk-arbitration-test-delivery",
            DISPATCH_QUEUE_SERIAL
        );
        if (session == NULL || registry == NULL || delivery_queue == NULL) {
            rdx_release_dispatch_queue(delivery_queue);
            rdx_da_registry_shutdown(registry, session);
            rdx_release_cf(session);
            return false;
        }
        rdx_da_callback_context *context = rdx_da_context_create(
            registry,
            session
        );
        if (context == NULL) {
            rdx_release_dispatch_queue(delivery_queue);
            rdx_da_registry_shutdown(registry, session);
            rdx_release_cf(session);
            return false;
        }
        rdx_da_test_delivery delivery = {
            .context = context,
            .ready = false,
            .deliver = false
        };
        dispatch_async_f(
            delivery_queue,
            &delivery,
            rdx_da_test_deliver_concurrently
        );
        while (!atomic_load_explicit(&delivery.ready, memory_order_acquire)) {
        }
        atomic_store_explicit(&delivery.deliver, true, memory_order_release);
        rdx_da_registry_shutdown(registry, session);
        dispatch_sync_f(delivery_queue, NULL, rdx_da_queue_barrier);
        rdx_da_context_release(context);
        rdx_release_dispatch_queue(delivery_queue);
        rdx_release_cf(session);
    }
    return true;
}

static bool rdx_da_test_global_quarantine_bound(void) {
    DASessionRef first_session = rdx_da_test_session();
    DASessionRef second_session = rdx_da_test_session();
    rdx_da_registry *first = rdx_da_registry_create();
    rdx_da_registry *second = rdx_da_registry_create();
    if (first_session == NULL || second_session == NULL ||
        first == NULL || second == NULL) {
        rdx_da_registry_shutdown(first, first_session);
        rdx_da_registry_shutdown(second, second_session);
        rdx_release_cf(first_session);
        rdx_release_cf(second_session);
        return false;
    }
    rdx_da_callback_context *contexts[RDX_MACOS_MAX_DA_CONTEXTS] = {0};
    bool passed = true;
    for (uint32_t index = 0; index < RDX_MACOS_MAX_DA_CONTEXTS; ++index) {
        contexts[index] = rdx_da_context_create(first, first_session);
        if (contexts[index] == NULL) {
            passed = false;
            break;
        }
    }
    rdx_da_callback_context *overflow = rdx_da_context_create(
        second,
        second_session
    );
    if (overflow != NULL ||
        atomic_load_explicit(
            &rdx_da_contexts_outstanding,
            memory_order_acquire
        ) != RDX_MACOS_MAX_DA_CONTEXTS) {
        passed = false;
    }
    for (uint32_t index = 0; index < RDX_MACOS_MAX_DA_CONTEXTS; ++index) {
        rdx_da_context_release(contexts[index]);
    }
    rdx_da_context_release(overflow);
    rdx_da_registry_shutdown(first, first_session);
    rdx_da_registry_shutdown(second, second_session);
    rdx_release_cf(first_session);
    rdx_release_cf(second_session);
    for (uint32_t index = 0; index < RDX_MACOS_MAX_DA_CONTEXTS; ++index) {
        if (contexts[index] != NULL) {
            rdx_da_operation_callback(NULL, NULL, contexts[index]);
        }
    }
    if (overflow != NULL) {
        rdx_da_operation_callback(NULL, NULL, overflow);
    }
    return passed && atomic_load_explicit(
        &rdx_da_contexts_outstanding,
        memory_order_acquire
    ) == 0;
}

bool rdx_macos_test_da_callback_lifecycle(void) {
    if (rdx_classify_diskutil_failure(RDX_MACOS_STATUS_NATIVE_FAILURE, false,
            "Unmount was dissented by PID 1234 (example application)") !=
            RDX_MACOS_STATUS_BUSY ||
        rdx_classify_diskutil_failure(RDX_MACOS_STATUS_NATIVE_FAILURE, false,
            "Unmount of disk14 failed: unknown failure") !=
            RDX_MACOS_STATUS_NATIVE_FAILURE ||
        rdx_classify_diskutil_failure(RDX_MACOS_STATUS_TIMED_OUT, false,
            "Unmount was dissented by PID 1234") != RDX_MACOS_STATUS_TIMED_OUT ||
        rdx_classify_diskutil_failure(RDX_MACOS_STATUS_OK, false,
            "Unmount was dissented by PID 1234") != RDX_MACOS_STATUS_OK ||
        rdx_classify_diskutil_failure(RDX_MACOS_STATUS_NATIVE_FAILURE, true,
            "Unmount was dissented by PID 1234") !=
            RDX_MACOS_STATUS_NATIVE_FAILURE) {
        return false;
    }
    return rdx_da_test_reentrant_and_late() &&
        rdx_da_test_post_shutdown_delivery() &&
        rdx_da_test_detaches_before_waiter_wakes() &&
        rdx_da_test_concurrent_shutdown() &&
        rdx_da_test_global_quarantine_bound();
}

bool rdx_test_exercise_da_failure_injections(void) {
    rdx_test_inject_failure(RDX_TEST_FAIL_DA_REGISTRY_CREATE);
    if (rdx_da_registry_create() != NULL) {
        return false;
    }

    DASessionRef context_session = rdx_da_test_session();
    rdx_da_registry *registry = rdx_da_registry_create();
    if (context_session == NULL || registry == NULL) {
        rdx_da_registry_shutdown(registry, context_session);
        rdx_release_cf(context_session);
        return false;
    }
    rdx_test_inject_failure(RDX_TEST_FAIL_DA_CONTEXT_CREATE);
    rdx_da_callback_context *context = rdx_da_context_create(
        registry,
        context_session
    );
    if (context != NULL) {
        rdx_da_context_release(context);
        rdx_da_registry_shutdown(registry, context_session);
        rdx_release_cf(context_session);
        return false;
    }
    rdx_da_registry_shutdown(registry, context_session);
    rdx_release_cf(context_session);

    rdx_test_inject_failure(RDX_TEST_FAIL_DA_SESSION_CREATE);
    DASessionRef session = rdx_da_session_create();
    if (session != NULL) {
        rdx_track_cf_acquire();
        rdx_release_cf(session);
        return false;
    }
    return atomic_load_explicit(&rdx_test_failure, memory_order_acquire) ==
        RDX_TEST_FAIL_NONE;
}
#endif

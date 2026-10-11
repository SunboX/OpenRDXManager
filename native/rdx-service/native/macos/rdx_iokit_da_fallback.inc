// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/* Private identity-checked Apple disk utility fallback. */
/* Keeps bounded tool diagnostics private while recognizing an explicit veto. */
static rdx_macos_status rdx_classify_diskutil_failure(
    rdx_macos_status status,
    bool eject,
    const char *diagnostic
) {
    if (status != RDX_MACOS_STATUS_NATIVE_FAILURE || eject || diagnostic == NULL) {
        return status;
    }
    const char *prefix = "Unmount was dissented by PID ";
    const char *veto = strstr(diagnostic, prefix);
    if (veto != NULL) {
        char first_pid_digit = veto[strlen(prefix)];
        if (first_pid_digit >= '0' && first_pid_digit <= '9') {
            return RDX_MACOS_STATUS_BUSY;
        }
    }
    return status;
}

/* Accepts only an exact whole-disk BSD name before constructing argv. */
static bool rdx_diskutil_target_is_valid(const char *bsd_name) {
    if (bsd_name == NULL || strncmp(bsd_name, "disk", 4) != 0) {
        return false;
    }
    size_t length = strlen(bsd_name);
    if (length < 5 || length >= RDX_MACOS_MAX_BSD_NAME_BYTES) {
        return false;
    }
    for (size_t index = 4; index < length; ++index) {
        if (bsd_name[index] < '0' || bsd_name[index] > '9') {
            return false;
        }
    }
    return true;
}

/*
 * Revalidates the exact retained IOMedia generation after a failed DA
 * callback and immediately before a diskutil fallback. The raw descriptor is
 * intentionally closed before DADiskEject and retained for unmount. The object, registry
 * identity, complete media authority, and current BSD name must all still
 * agree before the cached name may cross the process boundary.
 */
static rdx_macos_status rdx_revalidate_diskutil_target(
    rdx_macos_device *device,
    bool eject
) {
    if (device == NULL || !device->mapping_pinned ||
        !rdx_diskutil_target_is_valid(device->whole_bsd_name)) {
        rdx_emit_fixed_trace(eject ? "macos-diskutil-eject-target-identity-changed" :
            "macos-diskutil-unmount-target-identity-changed");
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device->test_fake) {
        rdx_test_record_event(
            device,
            RDX_TEST_EVENT_REVALIDATE_DISKUTIL_TARGET
        );
        if (device->test_revalidate_status == RDX_MACOS_STATUS_OK) {
            rdx_emit_fixed_trace(eject ? "macos-diskutil-eject-target-revalidated" :
                "macos-diskutil-unmount-target-revalidated");
        } else {
            rdx_emit_fixed_trace(
                eject ? "macos-diskutil-eject-target-identity-changed" :
                    "macos-diskutil-unmount-target-identity-changed"
            );
        }
        return device->test_revalidate_status;
    }
#endif
    if (device->session == NULL || device->whole_disk == NULL ||
        device->whole_media == IO_OBJECT_NULL ||
        device->whole_registry_entry_id == 0 ||
        (!eject && !rdx_raw_fd_matches_disk(device->whole_raw_fd, device->whole_disk))) {
        rdx_emit_fixed_trace(eject ? "macos-diskutil-eject-target-identity-changed" :
            "macos-diskutil-unmount-target-identity-changed");
        return RDX_MACOS_STATUS_EVIDENCE_INCOMPLETE;
    }
    const char *current_bsd_name = DADiskGetBSDName(device->whole_disk);
    io_service_t disk_media = DADiskCopyIOMedia(device->whole_disk);
    if (disk_media == IO_OBJECT_NULL) {
        rdx_emit_fixed_trace(eject ? "macos-diskutil-eject-target-identity-changed" :
            "macos-diskutil-unmount-target-identity-changed");
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    rdx_track_io_acquire();
    uint64_t disk_media_id = 0;
    bool exact = current_bsd_name != NULL &&
        rdx_diskutil_target_is_valid(current_bsd_name) &&
        strcmp(current_bsd_name, device->whole_bsd_name) == 0 &&
        IOObjectIsEqualTo(disk_media, device->whole_media) &&
        IORegistryEntryGetRegistryEntryID(disk_media, &disk_media_id) ==
            kIOReturnSuccess &&
        disk_media_id == device->whole_registry_entry_id &&
        rdx_fresh_whole_media_matches(device, eject ? -1 : device->whole_raw_fd);
    rdx_release_io(disk_media);
    if (!exact) {
        rdx_emit_fixed_trace(eject ? "macos-diskutil-eject-target-identity-changed" :
            "macos-diskutil-unmount-target-identity-changed");
        return RDX_MACOS_STATUS_DEVICE_REMOVED;
    }
    rdx_emit_fixed_trace(eject ? "macos-diskutil-eject-target-revalidated" :
                "macos-diskutil-unmount-target-revalidated");
    return RDX_MACOS_STATUS_OK;
}

/* Reads a monotonic millisecond clock for bounded child-process waits. */
static bool rdx_monotonic_milliseconds(uint64_t *output) {
    if (output == NULL) {
        return false;
    }
    struct timespec now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0 ||
        now.tv_nsec < 0) {
        return false;
    }
    *output = (uint64_t)now.tv_sec * UINT64_C(1000) +
        (uint64_t)now.tv_nsec / UINT64_C(1000000);
    return true;
}

/* Reaps a terminated diskutil child without leaking a zombie on interruption. */
static void rdx_reap_spawned_process(pid_t child) {
    int child_status = 0;
    while (waitpid(child, &child_status, 0) < 0 && errno == EINTR) {
    }
}

/* Waits for the exact Apple utility process and enforces the caller's bound. */
static rdx_macos_status rdx_wait_for_diskutil(
    pid_t child,
    uint32_t timeout_ms
) {
    uint64_t started_ms = 0;
    if (!rdx_monotonic_milliseconds(&started_ms)) {
        (void)kill(child, SIGKILL);
        rdx_reap_spawned_process(child);
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    const struct timespec interval = {
        .tv_sec = 0,
        .tv_nsec = 10 * 1000 * 1000
    };
    for (;;) {
        int child_status = 0;
        pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            return WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 ?
                RDX_MACOS_STATUS_OK : RDX_MACOS_STATUS_NATIVE_FAILURE;
        }
        if (waited < 0 && errno != EINTR) {
            (void)kill(child, SIGKILL);
            rdx_reap_spawned_process(child);
            return RDX_MACOS_STATUS_NATIVE_FAILURE;
        }
        uint64_t now_ms = 0;
        if (!rdx_monotonic_milliseconds(&now_ms)) {
            (void)kill(child, SIGKILL);
            rdx_reap_spawned_process(child);
            return RDX_MACOS_STATUS_NATIVE_FAILURE;
        }
        if (now_ms - started_ms >= timeout_ms) {
            (void)kill(child, SIGTERM);
            (void)nanosleep(&interval, NULL);
            (void)kill(child, SIGKILL);
            rdx_reap_spawned_process(child);
            return RDX_MACOS_STATUS_TIMED_OUT;
        }
        (void)nanosleep(&interval, NULL);
    }
}

/* Uses Apple's entitled utility only when direct Disk Arbitration is denied. */
static rdx_macos_status rdx_run_diskutil_operation(
    rdx_macos_device *device,
    uint32_t timeout_ms,
    bool eject
) {
#if defined(RDX_MACOS_TEST_HOOKS)
    if (device != NULL && device->test_fake) {
        rdx_test_record_event(
            device,
            eject ? RDX_TEST_EVENT_DISKUTIL_EJECT_COMPLETED :
                RDX_TEST_EVENT_DISKUTIL_UNMOUNT_COMPLETED
        );
        return device->test_diskutil_status;
    }
#endif
    if (device == NULL || timeout_ms == 0 ||
        !rdx_diskutil_target_is_valid(device->whole_bsd_name)) {
        rdx_emit_fixed_trace(eject ?
            "macos-diskutil-eject-target-invalid" :
            "macos-diskutil-unmount-target-invalid");
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    const char *enter_code = eject ?
        "macos-diskutil-eject-enter" :
        "macos-diskutil-unmount-enter";
    const char *succeeded_code = eject ?
        "macos-diskutil-eject-succeeded" :
        "macos-diskutil-unmount-succeeded";
    const char *nonzero_code = eject ?
        "macos-diskutil-eject-exit-nonzero" :
        "macos-diskutil-unmount-exit-nonzero";
    const char *spawn_failed_code = eject ?
        "macos-diskutil-eject-spawn-failed" :
        "macos-diskutil-unmount-spawn-failed";
    const char *timed_out_code = eject ?
        "macos-diskutil-eject-timed-out" :
        "macos-diskutil-unmount-timed-out";
    rdx_emit_fixed_trace(enter_code);
    char target[RDX_MACOS_MAX_BSD_NAME_BYTES + 6] = {0};
    int target_length = snprintf(
        target,
        sizeof(target),
        "/dev/%s",
        device->whole_bsd_name
    );
    if (target_length <= 0 || (size_t)target_length >= sizeof(target)) {
        rdx_emit_fixed_trace(spawn_failed_code);
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        rdx_emit_fixed_trace(spawn_failed_code);
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    /* tmpfile is private and unlinked. Never publish the utility's volume
     * names, process paths, or arbitrary text through the diagnostic channel. */
    FILE *diagnostics = tmpfile();
    if (diagnostics == NULL ||
        fcntl(fileno(diagnostics), F_SETFD, FD_CLOEXEC) != 0) {
        if (diagnostics != NULL) (void)fclose(diagnostics);
        (void)posix_spawn_file_actions_destroy(&actions);
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    int action_status = posix_spawn_file_actions_addopen(
        &actions,
        STDIN_FILENO,
        "/dev/null",
        O_RDONLY,
        0
    );
    if (action_status == 0) {
        action_status = posix_spawn_file_actions_addopen(
            &actions,
            STDOUT_FILENO,
            "/dev/null",
            O_WRONLY,
            0
        );
    }
    if (action_status == 0) {
        action_status = posix_spawn_file_actions_adddup2(
            &actions,
            fileno(diagnostics),
            STDERR_FILENO
        );
    }
    if (action_status != 0) {
        (void)fclose(diagnostics);
        (void)posix_spawn_file_actions_destroy(&actions);
        rdx_emit_fixed_trace(spawn_failed_code);
        return RDX_MACOS_STATUS_RESOURCE_LIMIT;
    }
    char *arguments[] = {
        "/usr/sbin/diskutil",
        eject ? "eject" : "unmountDisk",
        target,
        NULL
    };
    char *environment[] = {
        "LANG=C",
        "LC_ALL=C",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL
    };
    pid_t child = -1;
    int spawn_status = posix_spawn(
        &child,
        "/usr/sbin/diskutil",
        &actions,
        NULL,
        arguments,
        environment
    );
    (void)posix_spawn_file_actions_destroy(&actions);
    if (spawn_status != 0 || child <= 0) {
        (void)fclose(diagnostics);
        rdx_emit_fixed_trace(spawn_failed_code);
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    rdx_macos_status status = rdx_wait_for_diskutil(child, timeout_ms);
    char diagnostic[4096] = {0};
    ssize_t diagnostic_length = pread(
        fileno(diagnostics), diagnostic, sizeof(diagnostic) - 1, 0
    );
    (void)fclose(diagnostics);
    if (diagnostic_length > 0) {
        status = rdx_classify_diskutil_failure(status, eject, diagnostic);
    }
    if (status == RDX_MACOS_STATUS_OK) {
        rdx_emit_fixed_trace(succeeded_code);
    } else if (status == RDX_MACOS_STATUS_TIMED_OUT) {
        rdx_emit_fixed_trace(timed_out_code);
    } else if (status == RDX_MACOS_STATUS_BUSY) {
        rdx_emit_fixed_trace("macos-diskutil-unmount-busy");
    } else {
        rdx_emit_fixed_trace(nonzero_code);
    }
    return status;
}

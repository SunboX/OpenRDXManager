/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "rdx_worker_spawn.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

_Static_assert(sizeof(rdx_macos_worker_process) == 24, "private process output layout");
_Static_assert(offsetof(rdx_macos_worker_process, pid) == 8, "private process identity layout");
_Static_assert(offsetof(rdx_macos_worker_process, error_fd) == 20, "private pipe output layout");

/** Test injection is local to one call and cannot introduce cross-test global state. */
static int rdx_spawn_step(uint32_t *step, uint32_t fail_step) {
    *step += 1;
    return *step == fail_step ? EIO : 0;
}

/** Closes only six owned originals; none is a parent standard descriptor after normalization. */
static void rdx_close_pipe_ends(int ends[6]) {
    for (size_t index = 0; index < 6; index++) {
        if (ends[index] >= 0) { (void)close(ends[index]); ends[index] = -1; }
    }
}

/** Public spawn primitive; no allocation/library callback ever runs in a forked child. */
static rdx_macos_status rdx_spawn_worker(const char *program, char *const argv[],
    char *const environment[], uint32_t fail_step, rdx_macos_worker_process *output) {
    if (output == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    *output = (rdx_macos_worker_process){ .version = 1, .size = sizeof(*output),
        .pid = -1, .input_fd = -1, .output_fd = -1, .error_fd = -1 };
    int ends[6] = {-1, -1, -1, -1, -1, -1};
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;
    bool has_actions = false, has_attributes = false;
    uint32_t step = 0;
    int error = 0;
    for (size_t index = 0; index < 6; index += 2) {
        error = rdx_spawn_step(&step, fail_step);
        if (error != 0) { goto failed; }
        if (pipe(&ends[index]) != 0) { error = errno; goto failed; }
    }
    // Every source must be >=3: dup2(0/1/2) followed by close must never alias another source,
    // including when the parent's original standard slots were absent.
    for (size_t index = 0; index < 6; index++) {
        error = rdx_spawn_step(&step, fail_step);
        if (error != 0) { goto failed; }
        int normalized = fcntl(ends[index], F_DUPFD_CLOEXEC, 3);
        if (normalized < 0) { error = errno; goto failed; }
        (void)close(ends[index]);
        ends[index] = normalized;
    }
    error = rdx_spawn_step(&step, fail_step);
    if (error == 0) { error = posix_spawn_file_actions_init(&actions); }
    if (error != 0) { goto failed; }
    has_actions = true;
    error = rdx_spawn_step(&step, fail_step);
    if (error == 0) { error = posix_spawnattr_init(&attributes); }
    if (error != 0) { goto failed; }
    has_attributes = true;
    const int sources[3] = {ends[0], ends[3], ends[5]};
    for (int index = 0; index < 3; index++) {
        error = rdx_spawn_step(&step, fail_step);
        if (error == 0) { error = posix_spawn_file_actions_adddup2(&actions, sources[index], index); }
        if (error != 0) { goto failed; }
    }
    for (size_t index = 0; index < 6; index++) {
        error = rdx_spawn_step(&step, fail_step);
        if (error == 0) { error = posix_spawn_file_actions_addclose(&actions, ends[index]); }
        if (error != 0) { goto failed; }
    }
    sigset_t mask, defaults;
    if (sigemptyset(&mask) != 0 || sigemptyset(&defaults) != 0 || sigaddset(&defaults, SIGPIPE) != 0) {
        error = errno; goto failed;
    }
    error = rdx_spawn_step(&step, fail_step);
    if (error == 0) { error = posix_spawnattr_setsigmask(&attributes, &mask); }
    if (error != 0) { goto failed; }
    error = rdx_spawn_step(&step, fail_step);
    if (error == 0) { error = posix_spawnattr_setsigdefault(&attributes, &defaults); }
    if (error != 0) { goto failed; }
    error = rdx_spawn_step(&step, fail_step);
    if (error == 0) { error = posix_spawnattr_setflags(&attributes,
        POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF); }
    if (error != 0) { goto failed; }
    pid_t pid;
    error = rdx_spawn_step(&step, fail_step);
    if (error == 0) { error = posix_spawn(&pid, program, &actions, &attributes, argv, environment); }
    if (error != 0) { goto failed; } // pid is undefined on error: never inspect or signal it.
    output->pid = pid;
    output->input_fd = ends[1]; ends[1] = -1;
    output->output_fd = ends[2]; ends[2] = -1;
    output->error_fd = ends[4]; ends[4] = -1;
    (void)posix_spawnattr_destroy(&attributes);
    (void)posix_spawn_file_actions_destroy(&actions);
    rdx_close_pipe_ends(ends);
    return RDX_MACOS_STATUS_OK;
failed:
    if (has_attributes) { (void)posix_spawnattr_destroy(&attributes); }
    if (has_actions) { (void)posix_spawn_file_actions_destroy(&actions); }
    rdx_close_pipe_ends(ends);
    errno = error;
    return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
}

rdx_macos_status rdx_macos_spawn_gui_worker(const rdx_macos_peer_session *verified_peer,
    rdx_macos_worker_process *output) {
    if (output == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    *output = (rdx_macos_worker_process){ .version = 1, .size = sizeof(*output),
        .pid = -1, .input_fd = -1, .output_fd = -1, .error_fd = -1 };
    if (getuid() != 0 || geteuid() != 0 || !rdx_macos_peer_session_record_is_valid(verified_peer)) {
        return RDX_MACOS_STATUS_ACCESS_DENIED;
    }
    char uid[11];
    const int count = snprintf(uid, sizeof(uid), "%u", rdx_macos_peer_session_user_id(verified_peer));
    if (count <= 0 || (size_t)count >= sizeof(uid)) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    char *const argv[] = {"/bin/launchctl", "asuser", uid,
        "/Library/PrivilegedHelperTools/openrdx-hardware", "--openrdx-internal-macos-scsi-worker", NULL};
    char *const environment[] = {"LANG=C", NULL};
    return rdx_spawn_worker("/bin/launchctl", argv, environment, 0, output);
}

#if defined(RDX_MACOS_TEST_HOOKS)
rdx_macos_status rdx_macos_test_spawn_worker(const char *program, char *const argv[],
    char *const environment[], uint32_t fail_step, rdx_macos_worker_process *output) {
    return rdx_spawn_worker(program, argv, environment, fail_step, output);
}
#endif

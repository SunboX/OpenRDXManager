/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "rdx_worker_spawn.h"
#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *observed, *selected;
static unsigned calls;
static int query_fails, resolution_fails;

/** Synthetic privileged/peer metadata is confined to this standalone fixture, never a native factory. */
static uid_t fixture_getuid(void) { return 0; }
static uid_t fixture_geteuid(void) { return 0; }
bool rdx_macos_peer_session_record_is_valid(const rdx_macos_peer_session *peer) { return peer != NULL; }
uint32_t rdx_macos_peer_session_user_id(const rdx_macos_peer_session *peer) { (void)peer; return 502; }

/** Supplies only a bounded fixed fixture path; production uses the real public dyld and realpath APIs. */
static int fixture_executable(char *buffer, uint32_t *capacity) {
    size_t n = strlen(observed) + 1; if (query_fails || *capacity < n) { return -1; }
    memcpy(buffer, observed, n); return 0;
}
/** Models unavailable selected executable resolution, without consulting any host filesystem. */
static char *fixture_realpath(const char *path, char *resolved) {
    if (resolution_fails) { return NULL; } strcpy(resolved, path); return resolved;
}

/** A rejected spawn records the actual consumed argv; it never creates or owns any OS child. */
static int fixture_spawn(pid_t *pid, const char *program, const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attributes, char *const argv[], char *const environment[]) {
    (void)pid; (void)actions; (void)attributes; calls++;
    if (strcmp(program, "/bin/launchctl") || strcmp(argv[0], "/bin/launchctl") || strcmp(argv[1], "asuser") ||
        strcmp(argv[2], "502") || strcmp(argv[3], selected) ||
        strcmp(argv[4], "--openrdx-internal-macos-scsi-worker") || argv[5] != NULL ||
        strcmp(environment[0], "LANG=C") || environment[1] != NULL) { return EINVAL; }
    return EIO;
}

#define getuid fixture_getuid
#define geteuid fixture_geteuid
#define _NSGetExecutablePath fixture_executable
#define realpath fixture_realpath
#define posix_spawn fixture_spawn
#include "rdx_worker_spawn.c"
#undef getuid
#undef geteuid
#undef _NSGetExecutablePath
#undef realpath
#undef posix_spawn

/** Both real compiled wrappers must refuse the cross-mode current path before any attempted spawn. */
int main(void) {
    const char *local = "/Library/PrivilegedHelperTools/openrdx-hardware";
    const char *signed_path = "/Applications/OpenRDXManager.app/Contents/Library/LaunchServices/openrdx-hardware";
    rdx_macos_peer_session peer = {0}; rdx_macos_worker_process output;
    for (unsigned mode = 0; mode < 2; mode++) {
        selected = mode ? signed_path : local;
        observed = mode ? local : signed_path;
        calls = 0;
        rdx_macos_status status = mode ? rdx_macos_spawn_signed_gui_worker(&peer, &output) : rdx_macos_spawn_gui_worker(&peer, &output);
        if (status != RDX_MACOS_STATUS_ACCESS_DENIED || calls != 0) { return 81 + (int)mode; }
        observed = selected;
        for (unsigned fault = 0; fault < 2; fault++) {
            query_fails = fault == 0; resolution_fails = fault == 1; calls = 0;
            status = mode ? rdx_macos_spawn_signed_gui_worker(&peer, &output) : rdx_macos_spawn_gui_worker(&peer, &output);
            if (status != RDX_MACOS_STATUS_ACCESS_DENIED || calls != 0) { return 85 + (int)mode; }
        }
        query_fails = 0; resolution_fails = 0;
        calls = 0; errno = 0;
        status = mode ? rdx_macos_spawn_signed_gui_worker(&peer, &output) : rdx_macos_spawn_gui_worker(&peer, &output);
        if (status != RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE || calls != 1 || errno != EIO || output.pid != -1 ||
            output.input_fd != -1 || output.output_fd != -1 || output.error_fd != -1) { return 83 + (int)mode; }
    }
    puts("fixed-local-and-signed-targets cross-mode-denial argv-env no-fallback no-child");
    return 0;
}

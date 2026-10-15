/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef OPENRDX_WORKER_SPAWN_H
#define OPENRDX_WORKER_SPAWN_H
#include "rdx_endpoint_identity.h"

/** Independent private output, transferred only after a successful actual posix_spawn. */
typedef struct {
    uint32_t version, size;
    int32_t pid, input_fd, output_fd, error_fd;
} rdx_macos_worker_process;

/** Starts only the fixed local standalone helper via public launchctl asuser; no selectors. */
rdx_macos_status rdx_macos_spawn_gui_worker(const rdx_macos_peer_session *verified_peer,
    rdx_macos_worker_process *output);

/** Starts only the fixed signed bundled helper via public launchctl asuser; no selectors. */
rdx_macos_status rdx_macos_spawn_signed_gui_worker(const rdx_macos_peer_session *verified_peer,
    rdx_macos_worker_process *output);

/** Starts only this native process executable and the fixed internal role, never launchctl/asuser. */
rdx_macos_status rdx_macos_spawn_direct_worker(rdx_macos_worker_process *output);

#if defined(RDX_MACOS_TEST_HOOKS)
/** Ordinary-process fixture for the exact same current-executable resolver and fixed argv builder. */
rdx_macos_status rdx_macos_test_spawn_current_worker(rdx_macos_worker_process *output);
/** Native fixtures only: same private primitive with injected target/setup failures, never a factory. */
rdx_macos_status rdx_macos_test_spawn_worker(const char *program, char *const argv[],
    char *const environment[], uint32_t fail_step, rdx_macos_worker_process *output);
#endif
#endif

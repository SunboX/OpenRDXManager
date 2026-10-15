/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef OPENRDX_WORKER_CONTEXT_H
#define OPENRDX_WORKER_CONTEXT_H
#include "rdx_iokit.h"

/** Private self-only observations derived through supported public APIs, independent of ABI four. */
typedef struct {
    uint32_t version, size;
    uint32_t uid, euid, gid, egid, pid, ppid;
    uint32_t auid, audit_euid, audit_egid, audit_ruid, audit_rgid, audit_pid, asid, pid_version;
    uint32_t session, attributes;
} rdx_macos_worker_context;

/** Copies this actual process's credentials/audit/session metadata without IOKit or device IO. */
rdx_macos_status rdx_macos_copy_worker_context(rdx_macos_worker_context *output);
#endif

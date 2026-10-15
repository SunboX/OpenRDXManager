/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "rdx_worker_context.h"
#include <Security/AuthSession.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

_Static_assert(sizeof(rdx_macos_worker_context) == 72, "private worker context layout");
_Static_assert(offsetof(rdx_macos_worker_context, auid) == 32, "private audit fields layout");
_Static_assert(offsetof(rdx_macos_worker_context, attributes) == 68, "private session layout");

rdx_macos_status rdx_macos_copy_worker_context(rdx_macos_worker_context *output) {
    if (output == NULL) { return RDX_MACOS_STATUS_INVALID_ARGUMENT; }
    memset(output, 0, sizeof(*output));
    audit_token_t token = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    SecuritySessionId session = noSecuritySession;
    SessionAttributeBits attributes = 0;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) != KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT ||
        SessionGetInfo(callerSecuritySession, &session, &attributes) != errSessionSuccess) {
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    const rdx_macos_worker_context observed = {
        .version = 1, .size = sizeof(observed),
        .uid = getuid(), .euid = geteuid(), .gid = getgid(), .egid = getegid(),
        .pid = (uint32_t)getpid(), .ppid = (uint32_t)getppid(),
        .auid = audit_token_to_auid(token), .audit_euid = audit_token_to_euid(token),
        .audit_egid = audit_token_to_egid(token), .audit_ruid = audit_token_to_ruid(token),
        .audit_rgid = audit_token_to_rgid(token), .audit_pid = (uint32_t)audit_token_to_pid(token),
        .asid = audit_token_to_asid(token), .pid_version = (uint32_t)audit_token_to_pidversion(token),
        .session = session, .attributes = attributes,
    };
    *output = observed;
    return RDX_MACOS_STATUS_OK;
}

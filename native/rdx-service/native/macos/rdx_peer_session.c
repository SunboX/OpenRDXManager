// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_endpoint_identity.h"
#include <Security/AuthSession.h>
#include <bsm/libbsm.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

_Static_assert(sizeof(audit_token_t) == sizeof(((rdx_macos_peer_session *)0)->audit_token),
    "the complete kernel token must fit the private record");
_Static_assert(sizeof(rdx_macos_peer_session) == 40, "private session record layout");

/** Copies bytes instead of aliasing a uint32_t array as a system token structure. */
static audit_token_t rdx_session_token(const rdx_macos_peer_session *record) {
    audit_token_t token;
    memcpy(&token, record->audit_token, sizeof(token));
    return token;
}

bool rdx_macos_peer_session_record_is_valid(const rdx_macos_peer_session *record) {
    if (record == NULL || record->version != RDX_MACOS_PEER_SESSION_VERSION ||
        record->size != sizeof(*record)) { return false; }
    const audit_token_t token = rdx_session_token(record);
    const uid_t uid = audit_token_to_euid(token);
    const uint32_t asid = audit_token_to_asid(token);
    return uid != 0 && uid < UINT32_MAX - 1 &&
        audit_token_to_auid(token) == uid && audit_token_to_ruid(token) == uid &&
        audit_token_to_pid(token) > 0 && audit_token_to_pidversion(token) != 0 &&
        asid != noSecuritySession && asid != callerSecuritySession && asid != UINT32_MAX - 1;
}

bool rdx_macos_peer_session_metadata_matches(const rdx_macos_peer_session *record,
    uint32_t expected_uid, uint32_t session_id, uint32_t attributes, uint32_t console_uid_after) {
    if (!rdx_macos_peer_session_record_is_valid(record)) { return false; }
    const audit_token_t token = rdx_session_token(record);
    return audit_token_to_euid(token) == expected_uid && console_uid_after == expected_uid &&
        session_id == (uint32_t)audit_token_to_asid(token) &&
        (attributes & sessionHasGraphicAccess) != 0 &&
        (attributes & (sessionIsRoot | sessionIsRemote)) == 0;
}

bool rdx_macos_peer_session_same_token(const rdx_macos_peer_session *left,
    const rdx_macos_peer_session *right) {
    return rdx_macos_peer_session_record_is_valid(left) &&
        rdx_macos_peer_session_record_is_valid(right) &&
        memcmp(left->audit_token, right->audit_token, sizeof(left->audit_token)) == 0;
}

uint32_t rdx_macos_peer_session_user_id(const rdx_macos_peer_session *record) {
    return rdx_macos_peer_session_record_is_valid(record)
        ? audit_token_to_euid(rdx_session_token(record)) : 0;
}

bool rdx_macos_copy_manager_peer_session(int peer, const char *requirement_text,
    rdx_macos_peer_session *out_session) {
    if (out_session == NULL) { return false; }
    memset(out_session, 0, sizeof(*out_session));
    rdx_macos_identity_note_session_failure();
    struct stat before, after;
    rdx_macos_peer_session candidate = {
        .version = RDX_MACOS_PEER_SESSION_VERSION, .size = sizeof(candidate)
    };
    if (stat("/dev/console", &before) != 0 || before.st_uid == 0 ||
        !rdx_macos_peer_identity_token(peer, requirement_text,
            "/Applications/OpenRDXManager.app/Contents/MacOS/OpenRDXManager",
            before.st_uid, candidate.audit_token)) { return false; }
    // The socket token can outlive its sender. The shared verifier above repeats
    // a fresh SecCode lookup bound to the full token/PID version on every call.
    SecuritySessionId session_id = 0;
    SessionAttributeBits attributes = 0;
    if (!rdx_macos_peer_session_record_is_valid(&candidate) ||
        SessionGetInfo(audit_token_to_asid(rdx_session_token(&candidate)),
            &session_id, &attributes) != errSessionSuccess ||
        stat("/dev/console", &after) != 0 ||
        !rdx_macos_peer_session_metadata_matches(&candidate, before.st_uid,
            session_id, attributes, after.st_uid)) {
        rdx_macos_identity_note_session_failure();
        return false;
    }
    *out_session = candidate;
    return true;
}

rdx_macos_status rdx_macos_revalidate_manager_session(int socket,
    const char *requirement_text, const rdx_macos_peer_session *expected) {
    if (socket < 0 || requirement_text == NULL ||
        !rdx_macos_peer_session_record_is_valid(expected) ||
        rdx_macos_requirement_installation_mode(requirement_text) == RDX_INSTALLATION_DENIED) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    rdx_macos_peer_session current;
    if (!rdx_macos_copy_manager_peer_session(socket, requirement_text, &current) ||
        !rdx_macos_peer_session_same_token(&current, expected)) {
        rdx_macos_identity_note_session_failure();
        return RDX_MACOS_STATUS_ACCESS_DENIED;
    }
    return RDX_MACOS_STATUS_OK;
}

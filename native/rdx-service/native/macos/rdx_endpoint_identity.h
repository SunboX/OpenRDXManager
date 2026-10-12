/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef OPENRDX_ENDPOINT_IDENTITY_H
#define OPENRDX_ENDPOINT_IDENTITY_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/** Bounded native-only failure evidence, with no path/hash/enrollment contents. */
typedef struct { const char *stage; int32_t code; int32_t peer_pid; uint32_t peer_uid; } rdx_macos_identity_diagnostic;
/** Return the calling native worker's most recent fixed-stage evidence. */
rdx_macos_identity_diagnostic rdx_macos_last_identity_diagnostic(void);
/** Checks current kernel credentials/audit token and strict code seal on one retained socket. */
bool rdx_macos_peer_identity_matches(int peer, const char *requirement_text,
    const char *executable_path, uint32_t expected_uid, uint32_t *out_user_id);
/** Verifies current process occupies the fixed installed Manager executable path. */
bool rdx_macos_current_process_is_installed_manager(void);
/** Verifies current Manager dynamic/static code against the administrator-enrolled generation. */
bool rdx_macos_current_manager_matches(const char *requirement_text);
/** Closed sealed installation mode: denied, explicit local, or compiled Apple team. */
typedef enum { RDX_INSTALLATION_DENIED = 0, RDX_INSTALLATION_LOCAL = 1, RDX_INSTALLATION_SIGNED = 2 } rdx_macos_installation_mode;
rdx_macos_installation_mode rdx_macos_current_installation_mode(void);
/** Internal native verifier dispatch: local failures cannot invoke signed proof. */
typedef bool (*rdx_macos_policy_verifier)(void *context);
bool rdx_macos_verify_selected_mode(rdx_macos_installation_mode mode, bool local_only,
    rdx_macos_policy_verifier local, rdx_macos_policy_verifier signed_policy, void *context);
/** Returns a canonical compiled-team helper requirement, never runtime-supplied authority. */
bool rdx_macos_signed_helper_requirement(char *output, uint32_t capacity);
/** Verifies canonical retained-lease ancestor policy without requiring a socket. */
bool rdx_macos_run_directory_is_protected(void);
/** Checks root ownership, fixed endpoint address/mode and restrictive socket-parent ACLs. */
bool rdx_macos_endpoint_path_is_protected(void);
#if defined(RDX_MACOS_ENDPOINT_TEST_HOOKS)
/** Test-only ACL predicate; never exposed by the production addon. */
bool rdx_macos_test_path_acl_is_empty(const char *path);
/** Test-only exact root/daemon run ancestor tuple policy. */
bool rdx_macos_test_ancestor_owner_mode_is_protected(const char *path, uint32_t uid, uint32_t gid, uint32_t mode);
/** Test-only root/staff exact socket permission tuple. */
bool rdx_macos_test_socket_owner_mode_is_protected(uint32_t uid, uint32_t gid, uint32_t mode);
/** Exercises the closed mode grammar without bypassing production code proof. */
rdx_macos_installation_mode rdx_macos_test_select_mode(const char *marker, const char *team);
#endif
#ifdef __cplusplus
}
#endif
#endif

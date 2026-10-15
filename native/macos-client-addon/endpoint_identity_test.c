// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Hardware-free native audit-token/code/path rejection tests; never uses system enrollment. */
#include "rdx_endpoint_identity.h"
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/acl.h>
#include <membership.h>
#include <stdlib.h>

/** Check actual filesystem ACLs with the Darwin zero-on-entry API contract. */
static int filesystem_acl_test(void) {
    char path[] = "/tmp/openrdx-native-acl-XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) { return 20; }
    (void)close(fd);
    acl_t empty = acl_init(0);
    acl_t allow = acl_init(1);
    acl_entry_t entry;
    acl_permset_t permissions;
    uuid_t qualifier;
    int result = 0;
    if (empty == NULL || allow == NULL || acl_valid(empty) != 0 ||
        acl_set_file(path, ACL_TYPE_EXTENDED, empty) != 0) { result = 21; goto cleanup; }
    if (!rdx_macos_test_path_acl_is_empty(path)) { result = 22; goto cleanup; }
    if (mbr_uid_to_uuid(getuid(), qualifier) != 0 || acl_create_entry(&allow, &entry) != 0 ||
        acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) != 0 || acl_set_qualifier(entry, qualifier) != 0 ||
        acl_get_permset(entry, &permissions) != 0 || acl_add_perm(permissions, ACL_WRITE_DATA) != 0 ||
        acl_set_permset(entry, permissions) != 0 || acl_valid(allow) != 0 ||
        acl_set_file(path, ACL_TYPE_EXTENDED, allow) != 0) { result = 23; goto cleanup; }
    if (rdx_macos_test_path_acl_is_empty(path)) { result = 24; }
cleanup:
    if (empty != NULL) { (void)acl_free(empty); }
    if (allow != NULL) { (void)acl_free(allow); }
    (void)unlink(path);
    return result;
}

/** Missing local enrollment/hash stands for a failed local verifier. */
static bool deny_local_hash(void *context) { (*(int *)context) += 1; return false; }
/** A valid signed proof must remain unreachable after a local failure. */
static bool accept_signed_proof(void *context) { (*(int *)context) += 100; return true; }

/** Authenticate the actual retained socketpair against this ad-hoc sealed test generation. */
int main(void) {
    const char *local = "identifier \"com.openrdx.manager\" and cdhash H\"0123456789abcdef0123456789abcdef01234567\"";
    const char *signed_policy = "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCD123456\"";
    if (strcmp(rdx_macos_endpoint_path(RDX_INSTALLATION_LOCAL), "/var/run/openrdx-hardware-local.sock") != 0 ||
        strcmp(rdx_macos_endpoint_path(RDX_INSTALLATION_SIGNED), "/var/run/openrdx-hardware.sock") != 0 ||
        rdx_macos_endpoint_path(RDX_INSTALLATION_DENIED) != NULL ||
        rdx_macos_requirement_installation_mode(local) != RDX_INSTALLATION_LOCAL ||
        rdx_macos_requirement_installation_mode(signed_policy) != RDX_INSTALLATION_SIGNED ||
        rdx_macos_requirement_installation_mode("identifier \"com.openrdx.manager\" and cdhash H\"0000\" or true") != RDX_INSTALLATION_DENIED ||
        rdx_macos_requirement_installation_mode("identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"abcd123456\"") != RDX_INSTALLATION_DENIED) { return 39; }
    if (!rdx_macos_test_listener_mode_address_is_valid(RDX_INSTALLATION_LOCAL, "/var/run/openrdx-hardware-local.sock") ||
        rdx_macos_test_listener_mode_address_is_valid(RDX_INSTALLATION_LOCAL, "/var/run/openrdx-hardware.sock") ||
        !rdx_macos_test_listener_mode_address_is_valid(RDX_INSTALLATION_SIGNED, "/var/run/openrdx-hardware.sock") ||
        rdx_macos_test_listener_mode_address_is_valid(RDX_INSTALLATION_SIGNED, "/var/run/openrdx-hardware-local.sock") ||
        rdx_macos_test_listener_mode_address_is_valid(RDX_INSTALLATION_DENIED, "/var/run/com.apple.launchd.Pm7rWcU5b7/Listener")) { return 40; }
    const int acl_result = filesystem_acl_test();
    if (acl_result != 0) { (void)fprintf(stderr, "native ACL test failed: %d\n", acl_result); return acl_result; }
    // Mode selection cannot use missing local hashes as a reason to enter the
    // signed branch; the native policy selects one closed mode before lookup.
    if (rdx_macos_test_select_mode("local", "ABCD123456") != RDX_INSTALLATION_LOCAL ||
        rdx_macos_test_select_mode("local", "") != RDX_INSTALLATION_LOCAL ||
        rdx_macos_test_select_mode(NULL, "ABCD123456") != RDX_INSTALLATION_SIGNED ||
        rdx_macos_test_select_mode(NULL, "") != RDX_INSTALLATION_DENIED ||
        rdx_macos_test_select_mode("signed", "ABCD123456") != RDX_INSTALLATION_DENIED ||
        rdx_macos_test_select_mode("local", "BAD") != RDX_INSTALLATION_DENIED ||
        rdx_macos_test_select_mode(NULL, "abcd123456") != RDX_INSTALLATION_DENIED) { return 25; }
    if (!rdx_macos_test_ancestor_owner_mode_is_protected("/private/var/run", 0, 1, 0775) ||
        !rdx_macos_test_ancestor_owner_mode_is_protected("/private/var/run", 0, 1, 0755) ||
        rdx_macos_test_ancestor_owner_mode_is_protected("/private/var/run", 501, 1, 0775) ||
        rdx_macos_test_ancestor_owner_mode_is_protected("/private/var/run", 0, 20, 0775) ||
        rdx_macos_test_ancestor_owner_mode_is_protected("/private/var/run", 0, 1, 0777) ||
        rdx_macos_test_ancestor_owner_mode_is_protected("/private/var/run", 0, 1, 02775) ||
        rdx_macos_test_ancestor_owner_mode_is_protected("/tmp", 0, 1, 0775)) { return 31; }
    if (!rdx_macos_run_directory_is_protected() ||
        !rdx_macos_test_socket_owner_mode_is_protected(0, 20, 0660) ||
        rdx_macos_test_socket_owner_mode_is_protected(0, 1, 0660) ||
        rdx_macos_test_socket_owner_mode_is_protected(501, 20, 0660) ||
        rdx_macos_test_socket_owner_mode_is_protected(0, 20, 0666) ||
        rdx_macos_test_socket_owner_mode_is_protected(0, 20, 01660)) { return 32; }
    if (!rdx_macos_test_listener_address_is_valid("/var/run/openrdx-hardware.sock") ||
        !rdx_macos_test_listener_address_is_valid("/var/run/com.apple.launchd.Pm7rWcU5b7/Listener")) { return 35; }
    const char *bad_addresses[] = {"/tmp/openrdx-hardware.sock", "/var/run/com.apple.launchd.Pm7rWcU5b7/WrongLabel", "/var/run/com.apple.launchd.Pm7rWcU5b/Listener", "/var/run/com.apple.launchd.Pm7rWcU5b77/Listener", "/var/run/com.apple.launchd.Pm7rWcU5../Listener", "/var/run/com.apple.launchd.Pm7rWcU5b7/Listener/extra"};
    for (size_t index = 0; index < sizeof(bad_addresses) / sizeof(bad_addresses[0]); index += 1) {
        if (rdx_macos_test_listener_address_is_valid(bad_addresses[index])) { return 36; }
    }
    if (!rdx_macos_test_listener_state_is_valid(AF_UNIX, SOCK_STREAM, SO_ACCEPTCONN) ||
        rdx_macos_test_listener_state_is_valid(AF_INET, SOCK_STREAM, SO_ACCEPTCONN) ||
        rdx_macos_test_listener_state_is_valid(AF_UNIX, SOCK_DGRAM, SO_ACCEPTCONN) ||
        rdx_macos_test_listener_state_is_valid(AF_UNIX, SOCK_STREAM, 0)) { return 38; }
    // A matching-looking address cannot admit a datagram or non-listener.
    int datagram = socket(AF_UNIX, SOCK_DGRAM, 0);
    int stream = socket(AF_UNIX, SOCK_STREAM, 0);
    if (datagram < 0 || stream < 0 || rdx_macos_test_listener_descriptor_is_valid(datagram) ||
        rdx_macos_test_listener_descriptor_is_valid(stream)) { return 37; }
    close(datagram); close(stream);
    int dispatched = 0;
    if (rdx_macos_verify_selected_mode(RDX_INSTALLATION_LOCAL, false, deny_local_hash, accept_signed_proof, &dispatched) || dispatched != 1) { return 28; }
    dispatched = 0;
    if (rdx_macos_verify_selected_mode(RDX_INSTALLATION_SIGNED, true, deny_local_hash, accept_signed_proof, &dispatched) || dispatched != 0) { return 29; }
    if (!rdx_macos_verify_selected_mode(RDX_INSTALLATION_SIGNED, false, deny_local_hash, accept_signed_proof, &dispatched) || dispatched != 100) { return 30; }
    char compiled_requirement[256];
    if (!rdx_macos_signed_helper_requirement(compiled_requirement, sizeof(compiled_requirement)) ||
        strcmp(compiled_requirement, "identifier \"com.openrdx.hardware\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCD123456\"") != 0) { return 27; }
    SecCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information) != errSecSuccess) { return 1; }
    CFDataRef hash = (CFDataRef)CFDictionaryGetValue(information, kSecCodeInfoUnique);
    CFURLRef executable = (CFURLRef)CFDictionaryGetValue(information, kSecCodeInfoMainExecutable);
    unsigned char path[4096];
    if (hash == NULL || CFDataGetLength(hash) != 20 || executable == NULL ||
        !CFURLGetFileSystemRepresentation(executable, true, path, sizeof(path))) { return 2; }
    char hexadecimal[41];
    for (size_t index = 0; index < 20; index += 1) {
        (void)snprintf(&hexadecimal[index * 2], 3, "%02x", CFDataGetBytePtr(hash)[index]);
    }
    char requirement[256];
    (void)snprintf(requirement, sizeof(requirement), "identifier \"com.openrdx.manager\" and cdhash H\"%s\"", hexadecimal);
    int descriptors[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) != 0) { return 3; }
    uint32_t uid = 0;
    int result = 0;
    if (!rdx_macos_peer_identity_matches(descriptors[0], requirement, (const char *)path, getuid(), &uid)) { result = 4; }
    if (uid != getuid()) { result = 5; }
    const rdx_macos_identity_diagnostic verified = rdx_macos_last_identity_diagnostic();
    if (strcmp(verified.stage, "verified") != 0 || verified.code != 0 || verified.peer_uid != getuid() || verified.peer_pid != getpid()) { result = 33; }
    audit_token_t actual_token = {{0}};
    socklen_t token_size = sizeof(actual_token);
    uint32_t retained_token[8] = {0};
    if (getsockopt(descriptors[0], SOL_LOCAL, LOCAL_PEERTOKEN, &actual_token, &token_size) != 0 ||
        token_size != sizeof(actual_token) ||
        !rdx_macos_peer_identity_token(descriptors[0], requirement, (const char *)path,
            getuid(), retained_token) || memcmp(retained_token, &actual_token, sizeof(actual_token)) != 0) { result = 41; }
    if (rdx_macos_peer_identity_matches(descriptors[0], requirement, "/Applications/OpenRDXManager.app/Contents/MacOS/OpenRDXManager", getuid(), &uid)) { result = 6; }
    if (rdx_macos_peer_identity_matches(descriptors[0], requirement, (const char *)path, getuid() + 1, &uid)) { result = 7; }
    const char *signed_requirement = "identifier \"com.openrdx.manager\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCD123456\"";
    if (rdx_macos_peer_identity_matches(descriptors[0], signed_requirement, (const char *)path, getuid(), &uid) ||
        rdx_macos_current_installation_mode() != RDX_INSTALLATION_DENIED) { result = 26; }
    const char *wrong = "identifier \"com.openrdx.manager\" and cdhash H\"0000000000000000000000000000000000000000\"";
    if (rdx_macos_peer_identity_matches(descriptors[0], wrong, (const char *)path, getuid(), &uid)) { result = 8; }
    const rdx_macos_identity_diagnostic denied = rdx_macos_last_identity_diagnostic();
    if (strcmp(denied.stage, "peer-dynamic-seal") != 0 || denied.code == 0) { result = 34; }
    // Full-token output must be cleared even after a previous successful seal proof.
    const uint32_t zero_token[8] = {0};
    if (rdx_macos_peer_identity_token(descriptors[0], wrong, (const char *)path, getuid(), retained_token) ||
        memcmp(retained_token, zero_token, sizeof(retained_token)) != 0) { result = 42; }
    if (rdx_macos_current_process_is_installed_manager() || rdx_macos_current_manager_matches(requirement)) { result = 9; }
    (void)close(descriptors[0]); (void)close(descriptors[1]);
    CFRelease(information); CFRelease(code);
    if (result == 0) { (void)puts("native mode: explicit local never downgrades, malformed team and ad-hoc signed authority denied; ACL: empty accepted, mutable allow denied; audit-token identity: valid seal accepted; wrong path, uid, cdhash and portable self rejected"); }
    else { (void)fprintf(stderr, "native audit-token test failed: %d\n", result); }
    return result;
}

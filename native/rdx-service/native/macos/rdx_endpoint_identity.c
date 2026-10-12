// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
#include "rdx_endpoint_identity.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <string.h>
#include <stdio.h>
#include <grp.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ucred.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <unistd.h>

/** Denies ACL-bearing paths; installer strips inherited mutable permissions. */
static bool rdx_acl_is_empty(const char *path) {
    acl_t acl = acl_get_file(path, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        // Darwin reports ENOENT for an existing object without an extended ACL.
        // Independently require the path still exists and is not a link so this
        // absence cannot turn a removed socket or ancestor into accepted policy.
        if (errno != ENOENT) { return false; }
        struct stat status;
        return lstat(path, &status) == 0 && !S_ISLNK(status.st_mode);
    }
    // Darwin returns zero when it found an entry. A validated empty ACL
    // reports -1/EINVAL with this fixed first-entry selector (man acl_get_entry).
    if (acl_valid(acl) != 0) { (void)acl_free(acl); return false; }
    acl_entry_t entry;
    errno = 0;
    const int first = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    const int error = errno;
    (void)acl_free(acl);
    return first == -1 && error == EINVAL;
}

#if defined(RDX_MACOS_ENDPOINT_TEST_HOOKS)
bool rdx_macos_test_path_acl_is_empty(const char *path) { return rdx_acl_is_empty(path); }
#endif

/** Allow only Darwin's exact root:daemon 0775 run ancestor, not writable app inputs. */
static bool rdx_ancestor_owner_mode_is_protected(const char *path, uint32_t uid, uint32_t gid, uint32_t mode) {
    if (uid != 0) { return false; }
    if ((mode & 0022) == 0) { return true; }
    if (strcmp(path, "/private/var/run") != 0 || gid != 1 || (mode & 07777) != 0775) { return false; }
    // Resolve the actual OS group rather than treating any arbitrary group
    // numbered one as the approved daemon authority. It is not the logged-in
    // staff group; file and peer identity proofs remain independently strict.
    struct group group;
    struct group *resolved = NULL;
    char storage[4096];
    return getgrgid_r(1, &group, storage, sizeof(storage), &resolved) == 0 &&
        resolved != NULL && strcmp(resolved->gr_name, "daemon") == 0;
}
#if defined(RDX_MACOS_ENDPOINT_TEST_HOOKS)
bool rdx_macos_test_ancestor_owner_mode_is_protected(const char *path, uint32_t uid, uint32_t gid, uint32_t mode) {
    return rdx_ancestor_owner_mode_is_protected(path, uid, gid, mode);
}
#endif

bool rdx_macos_run_directory_is_protected(void) {
    const char *ancestors[] = {"/", "/private", "/private/var", "/private/var/run"};
    for (size_t index = 0; index < sizeof(ancestors) / sizeof(ancestors[0]); index += 1) {
        struct stat status;
        if (lstat(ancestors[index], &status) != 0 || !S_ISDIR(status.st_mode) ||
            !rdx_ancestor_owner_mode_is_protected(ancestors[index], status.st_uid, status.st_gid, status.st_mode) || !rdx_acl_is_empty(ancestors[index])) { return false; }
    }
    return true;
}

/** The socket grants console users through staff; daemon's directory authority is separate. */
static bool rdx_socket_owner_mode_is_protected(uint32_t uid, uint32_t gid, uint32_t mode) {
    return uid == 0 && gid == 20 && (mode & 07777) == 0660;
}
#if defined(RDX_MACOS_ENDPOINT_TEST_HOOKS)
bool rdx_macos_test_socket_owner_mode_is_protected(uint32_t uid, uint32_t gid, uint32_t mode) {
    return rdx_socket_owner_mode_is_protected(uid, gid, mode);
}
#endif

bool rdx_macos_endpoint_path_is_protected(void) {
    if (!rdx_macos_run_directory_is_protected()) { return false; }
    struct stat status;
    return lstat("/private/var/run/openrdx-hardware.sock", &status) == 0 &&
        S_ISSOCK(status.st_mode) && rdx_socket_owner_mode_is_protected(status.st_uid, status.st_gid, status.st_mode) && rdx_acl_is_empty("/private/var/run/openrdx-hardware.sock");
}

/** Sealed local metadata cannot be admitted through the signed server policy. */
static bool rdx_manager_marker_matches(CFDictionaryRef information, const char *requirement) {
    CFDictionaryRef plist = (CFDictionaryRef)CFDictionaryGetValue(information, kSecCodeInfoPList);
    if (plist == NULL || CFGetTypeID(plist) != CFDictionaryGetTypeID()) { return false; }
    CFTypeRef marker = CFDictionaryGetValue(plist, CFSTR("OpenRDXInstallationMode"));
    const char *local_prefix = "identifier \"com.openrdx.manager\" and cdhash ";
    if (strncmp(requirement, local_prefix, strlen(local_prefix)) == 0) {
        return marker != NULL && CFGetTypeID(marker) == CFStringGetTypeID() &&
            CFEqual(marker, CFSTR("local"));
    }
    return marker == NULL;
}

bool rdx_macos_peer_identity_matches(
    int peer,
    const char *requirement_text,
    const char *executable_path,
    uint32_t expected_uid,
    uint32_t *out_user_id
) {
    struct xucred credentials;
    socklen_t credentials_length = (socklen_t)sizeof(credentials);
    memset(&credentials, 0, sizeof(credentials));
    if (getsockopt(
            peer,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            &credentials,
            &credentials_length
        ) != 0 || credentials_length != sizeof(credentials) ||
        credentials.cr_version != XUCRED_VERSION) {
        return false;
    }
    if (credentials.cr_uid != expected_uid) { return false; }

    audit_token_t audit_token;
    socklen_t token_length = (socklen_t)sizeof(audit_token);
    memset(&audit_token, 0, sizeof(audit_token));
    if (getsockopt(
            peer,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &audit_token,
            &token_length
        ) != 0 || token_length != sizeof(audit_token) ||
        audit_token_to_euid(audit_token) != expected_uid || audit_token_to_pid(audit_token) <= 0) {
        return false;
    }

    CFStringRef requirement_string = CFStringCreateWithCString(
        kCFAllocatorDefault,
        requirement_text,
        kCFStringEncodingUTF8
    );
    SecRequirementRef requirement = NULL;
    CFDataRef audit_data = NULL;
    CFDictionaryRef attributes = NULL;
    SecCodeRef guest = NULL;
    CFDictionaryRef information = NULL;
    SecStaticCodeRef static_code = NULL;
    bool authorized = false;
    if (requirement_string == NULL ||
        SecRequirementCreateWithString(
            requirement_string,
            kSecCSDefaultFlags,
            &requirement
        ) != errSecSuccess) {
        goto cleanup;
    }
    audit_data = CFDataCreate(
        kCFAllocatorDefault,
        (const UInt8 *)&audit_token,
        (CFIndex)sizeof(audit_token)
    );
    if (audit_data == NULL) {
        goto cleanup;
    }
    const void *keys[] = {kSecGuestAttributeAudit};
    const void *values[] = {audit_data};
    attributes = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        values,
        1,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    if (attributes == NULL ||
        SecCodeCopyGuestWithAttributes(
            NULL,
            attributes,
            kSecCSDefaultFlags,
            &guest
        ) != errSecSuccess) {
        goto cleanup;
    }
    authorized = SecCodeCheckValidity(
        guest,
        kSecCSStrictValidate,
        requirement
    ) == errSecSuccess;
    if (authorized) {
        authorized = SecCodeCopySigningInformation(guest, kSecCSSigningInformation, &information) == errSecSuccess;
        CFURLRef executable = information == NULL ? NULL : (CFURLRef)CFDictionaryGetValue(information, kSecCodeInfoMainExecutable);
        UInt8 path[4096];
        authorized = authorized && executable != NULL && CFGetTypeID(executable) == CFURLGetTypeID() &&
            CFURLGetFileSystemRepresentation(executable, true, path, sizeof(path)) &&
            strcmp((const char *)path, executable_path) == 0;
        if (authorized && strcmp(executable_path, "/Applications/OpenRDXManager.app/Contents/MacOS/OpenRDXManager") == 0) {
            authorized = rdx_manager_marker_matches(information, requirement_text);
        }
        // Dynamic validation authenticates the process; static validation also
        // rejects resource/seal tampering on disk before a session is admitted.
        authorized = authorized && SecCodeCopyStaticCode(guest, kSecCSDefaultFlags, &static_code) == errSecSuccess &&
            SecStaticCodeCheckValidity(static_code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement) == errSecSuccess;
    }
    if (authorized) {
        *out_user_id = credentials.cr_uid;
    }

cleanup:
    if (static_code != NULL) { CFRelease(static_code); }
    if (information != NULL) { CFRelease(information); }
    if (guest != NULL) {
        CFRelease(guest);
    }
    if (attributes != NULL) {
        CFRelease(attributes);
    }
    if (audit_data != NULL) {
        CFRelease(audit_data);
    }
    if (requirement != NULL) {
        CFRelease(requirement);
    }
    if (requirement_string != NULL) {
        CFRelease(requirement_string);
    }
    return authorized;
}

/** Compare Security's own main executable URL, never a user-authored argv value. */
bool rdx_macos_current_process_is_installed_manager(void) {
    SecCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    bool matches = false;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information) != errSecSuccess) { goto cleanup; }
    CFURLRef executable = (CFURLRef)CFDictionaryGetValue(information, kSecCodeInfoMainExecutable);
    UInt8 path[4096];
    matches = executable != NULL && CFGetTypeID(executable) == CFURLGetTypeID() &&
        CFURLGetFileSystemRepresentation(executable, true, path, sizeof(path)) &&
        strcmp((const char *)path, "/Applications/OpenRDXManager.app/Contents/MacOS/OpenRDXManager") == 0;
cleanup:
    if (information != NULL) { CFRelease(information); }
    if (code != NULL) { CFRelease(code); }
    return matches;
}

bool rdx_macos_current_manager_matches(const char *requirement_text) {
    if (!rdx_macos_current_process_is_installed_manager()) { return false; }
    SecCodeRef code = NULL;
    SecStaticCodeRef static_code = NULL;
    SecRequirementRef requirement = NULL;
    CFStringRef text = CFStringCreateWithCString(kCFAllocatorDefault, requirement_text, kCFStringEncodingUTF8);
    bool matches = false;
    if (text == NULL || SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement) != errSecSuccess ||
        SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &static_code) != errSecSuccess) { goto cleanup; }
    matches = SecCodeCheckValidity(code, kSecCSStrictValidate, requirement) == errSecSuccess &&
        SecStaticCodeCheckValidity(static_code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement) == errSecSuccess;
cleanup:
    if (static_code != NULL) { CFRelease(static_code); }
    if (code != NULL) { CFRelease(code); }
    if (requirement != NULL) { CFRelease(requirement); }
    if (text != NULL) { CFRelease(text); }
    return matches;
}

#ifndef OPENRDX_MACOS_TEAM_ID
#define OPENRDX_MACOS_TEAM_ID ""
#endif

/** Validate compile-time authority before constructing Security requirement text. */
static bool rdx_team_is_valid(const char *team) {
    if (team == NULL || strlen(team) != 10) { return false; }
    for (size_t index = 0; index < 10; index += 1) {
        if (!((team[index] >= 'A' && team[index] <= 'Z') || (team[index] >= '0' && team[index] <= '9'))) { return false; }
    }
    return true;
}

/** A local marker is authoritative selection even when a team is compiled in. */
static rdx_macos_installation_mode rdx_select_mode(const char *marker, const char *team) {
    if (team == NULL || (team[0] != '\0' && !rdx_team_is_valid(team))) { return RDX_INSTALLATION_DENIED; }
    if (marker != NULL) { return strcmp(marker, "local") == 0 ? RDX_INSTALLATION_LOCAL : RDX_INSTALLATION_DENIED; }
    return rdx_team_is_valid(team) ? RDX_INSTALLATION_SIGNED : RDX_INSTALLATION_DENIED;
}

/** Construct only the compile-time team and one hard-coded application identifier. */
static bool rdx_signed_requirement(const char *identifier, char *output, uint32_t capacity) {
    if (output == NULL || !rdx_team_is_valid(OPENRDX_MACOS_TEAM_ID)) { return false; }
    const int length = snprintf(output, capacity,
        "identifier \"%s\" and anchor apple generic and certificate leaf[subject.OU] = \"%s\"",
        identifier, OPENRDX_MACOS_TEAM_ID);
    return length > 0 && (uint32_t)length < capacity;
}

bool rdx_macos_signed_helper_requirement(char *output, uint32_t capacity) {
    return rdx_signed_requirement("com.openrdx.hardware", output, capacity);
}

rdx_macos_installation_mode rdx_macos_current_installation_mode(void) {
    // This validates the actual app seal before reading its authenticated plist.
    // Metadata alone cannot grant signed mode; its Apple/team requirement is
    // checked below. Unknown/non-string values deny both modes.
    if (!rdx_macos_current_manager_matches("identifier \"com.openrdx.manager\"")) { return RDX_INSTALLATION_DENIED; }
    SecCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    rdx_macos_installation_mode mode = RDX_INSTALLATION_DENIED;
    if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information) != errSecSuccess) { goto cleanup; }
    CFDictionaryRef plist = (CFDictionaryRef)CFDictionaryGetValue(information, kSecCodeInfoPList);
    if (plist == NULL || CFGetTypeID(plist) != CFDictionaryGetTypeID()) { goto cleanup; }
    CFTypeRef marker = CFDictionaryGetValue(plist, CFSTR("OpenRDXInstallationMode"));
    if (marker != NULL && (CFGetTypeID(marker) != CFStringGetTypeID() ||
        !CFEqual(marker, CFSTR("local")))) { goto cleanup; }
    // CFEqual preserves the complete value, including embedded NULs; converting
    // to a C string before comparison could truncate an unknown sealed marker.
    mode = rdx_select_mode(marker == NULL ? NULL : "local", OPENRDX_MACOS_TEAM_ID);
    if (mode == RDX_INSTALLATION_SIGNED) {
        char requirement[256];
        if (!rdx_signed_requirement("com.openrdx.manager", requirement, sizeof(requirement)) ||
            !rdx_macos_current_manager_matches(requirement)) { mode = RDX_INSTALLATION_DENIED; }
    }
cleanup:
    if (information != NULL) { CFRelease(information); }
    if (code != NULL) { CFRelease(code); }
    return mode;
}

#if defined(RDX_MACOS_ENDPOINT_TEST_HOOKS)
rdx_macos_installation_mode rdx_macos_test_select_mode(const char *marker, const char *team) { return rdx_select_mode(marker, team); }
#endif

/** Dispatch exactly one already selected sealed mode, never a failure fallback. */
bool rdx_macos_verify_selected_mode(rdx_macos_installation_mode mode, bool local_only,
    rdx_macos_policy_verifier local, rdx_macos_policy_verifier signed_policy, void *context) {
    if (mode == RDX_INSTALLATION_LOCAL) { return local != NULL && local(context); }
    if (!local_only && mode == RDX_INSTALLATION_SIGNED) { return signed_policy != NULL && signed_policy(context); }
    return false;
}

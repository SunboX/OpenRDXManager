// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <launch.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define RDX_ENDPOINT_PATH "/var/run/openrdx-hardware.sock"
#define RDX_ACCEPT_TIMEOUT_MS 10000

static void rdx_close_activated_sockets(int *sockets, size_t count) {
    if (sockets == NULL) {
        return;
    }
    for (size_t index = 0; index < count; index += 1) {
        if (sockets[index] >= 0) {
            (void)close(sockets[index]);
        }
    }
    free(sockets);
}

static bool rdx_listener_is_exact(int listener) {
    struct sockaddr_un address;
    socklen_t address_length = (socklen_t)sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname(listener, (struct sockaddr *)&address, &address_length) != 0 ||
        address.sun_family != AF_UNIX ||
        strncmp(address.sun_path, RDX_ENDPOINT_PATH, sizeof(address.sun_path)) != 0) {
        return false;
    }
    struct stat path_status;
    if (lstat(RDX_ENDPOINT_PATH, &path_status) != 0 ||
        !S_ISSOCK(path_status.st_mode) || path_status.st_uid != 0) {
        return false;
    }
    const mode_t permissions = path_status.st_mode & (mode_t)0777;
    return permissions == (mode_t)0660;
}

static bool rdx_monotonic_milliseconds(int64_t *out_milliseconds) {
    struct timespec current;
    memset(&current, 0, sizeof(current));
    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
        return false;
    }
    *out_milliseconds = ((int64_t)current.tv_sec * 1000) +
        ((int64_t)current.tv_nsec / 1000000);
    return true;
}

static int rdx_accept_bounded(int listener) {
    int64_t started = 0;
    if (!rdx_monotonic_milliseconds(&started)) {
        return -1;
    }
    const int64_t deadline = started + RDX_ACCEPT_TIMEOUT_MS;
    for (;;) {
        int64_t current = 0;
        if (!rdx_monotonic_milliseconds(&current) || current >= deadline) {
            return -1;
        }
        const int remaining = (int)(deadline - current);
        struct pollfd descriptor = {
            .fd = listener,
            .events = POLLIN,
            .revents = 0,
        };
        const int ready = poll(&descriptor, 1, remaining);
        if (ready == 0) {
            return -1;
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if ((descriptor.revents & POLLIN) == 0) {
            return -1;
        }
        const int peer = accept(listener, NULL, NULL);
        if (peer >= 0) {
            return peer;
        }
        if (errno != EINTR && errno != EAGAIN) {
            return -1;
        }
    }
}

static bool rdx_peer_matches_requirement(
    int peer,
    const char *requirement_text,
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
    struct stat console_status;
    memset(&console_status, 0, sizeof(console_status));
    if (stat("/dev/console", &console_status) != 0 ||
        console_status.st_uid == 0 ||
        credentials.cr_uid != console_status.st_uid) {
        return false;
    }

    audit_token_t audit_token;
    socklen_t token_length = (socklen_t)sizeof(audit_token);
    memset(&audit_token, 0, sizeof(audit_token));
    if (getsockopt(
            peer,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &audit_token,
            &token_length
        ) != 0 || token_length != sizeof(audit_token)) {
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
        *out_user_id = credentials.cr_uid;
    }

cleanup:
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

rdx_macos_status rdx_macos_activate_launchd_listener(int *out_listener) {
    if (out_listener == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_listener = -1;
    int *listeners = NULL;
    size_t listener_count = 0;
    if (launch_activate_socket("Listener", &listeners, &listener_count) != 0 ||
        listeners == NULL || listener_count != 1 ||
        !rdx_listener_is_exact(listeners[0])) {
        rdx_close_activated_sockets(listeners, listener_count);
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    const int listener = listeners[0];
    listeners[0] = -1;
    rdx_close_activated_sockets(listeners, listener_count);
    if (fcntl(listener, F_SETFD, FD_CLOEXEC) != 0) {
        (void)close(listener);
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    *out_listener = listener;
    return RDX_MACOS_STATUS_OK;
}

rdx_macos_status rdx_macos_accept_launchd_manager_from_listener(
    int listener,
    const char *requirement_text,
    int *out_socket,
    uint32_t *out_user_id
) {
    if (listener < 0 || requirement_text == NULL || out_socket == NULL ||
        out_user_id == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_socket = -1;
    *out_user_id = 0;
    if (!rdx_listener_is_exact(listener)) {
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    const int peer = rdx_accept_bounded(listener);
    if (peer < 0) {
        return RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    if (fcntl(peer, F_SETFD, FD_CLOEXEC) != 0) {
        (void)close(peer);
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    int enabled = 1;
    if (setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        (void)close(peer);
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    if (!rdx_peer_matches_requirement(peer, requirement_text, out_user_id)) {
        (void)close(peer);
        return RDX_MACOS_STATUS_ACCESS_DENIED;
    }
    *out_socket = peer;
    return RDX_MACOS_STATUS_OK;
}

rdx_macos_status rdx_macos_accept_launchd_manager(
    const char *requirement_text,
    int *out_socket,
    uint32_t *out_user_id
) {
    int listener = -1;
    const rdx_macos_status activation =
        rdx_macos_activate_launchd_listener(&listener);
    if (activation != RDX_MACOS_STATUS_OK) {
        return activation;
    }
    const rdx_macos_status accepted =
        rdx_macos_accept_launchd_manager_from_listener(
            listener,
            requirement_text,
            out_socket,
            out_user_id
        );
    (void)close(listener);
    return accepted;
}

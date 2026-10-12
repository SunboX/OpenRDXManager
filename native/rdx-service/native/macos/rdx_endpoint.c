// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#include "rdx_iokit.h"
#include "rdx_endpoint_identity.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <launch.h>
#include <poll.h>
#include <os/log.h>
#include <libproc.h>
#include <sys/proc_info.h>
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

/** The kernel retains launchd's pre-rename bind name, not SockPathName's alias. */
static bool rdx_listener_address_is_valid(const char *address) {
    if (strcmp(address, RDX_ENDPOINT_PATH) == 0) { return true; }
    const char *prefix = "/var/run/com.apple.launchd.";
    const size_t prefix_length = strlen(prefix);
    if (strncmp(address, prefix, prefix_length) != 0) { return false; }
    const char *token = address + prefix_length;
    // Actual launchd creates one ten-character base62 directory for this job.
    // No separators, dot components, arbitrary key or caller namespace qualify.
    if (strlen(token) != 10 + strlen("/Listener") || strcmp(token + 10, "/Listener") != 0) { return false; }
    for (size_t index = 0; index < 10; index += 1) {
        const char byte = token[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z'))) { return false; }
    }
    return true;
}

/** Exact kernel protocol/state contract, independent of address namespace. */
static bool rdx_listener_state_is_valid(int family, int type, int options) {
    return family == AF_UNIX && type == SOCK_STREAM && (options & SO_ACCEPTCONN) != 0;
}

/** Validate only a retained listening Unix stream returned by own-job activation. */
static bool rdx_listener_descriptor_is_valid(int listener) {
    struct sockaddr_un address;
    socklen_t address_length = (socklen_t)sizeof(address);
    memset(&address, 0, sizeof(address));
    int type = 0;
    socklen_t type_length = sizeof(type);
    struct socket_fdinfo information;
    memset(&information, 0, sizeof(information));
    return getsockname(listener, (struct sockaddr *)&address, &address_length) == 0 &&
        address_length <= sizeof(address) && address_length > offsetof(struct sockaddr_un, sun_path) &&
        address.sun_family == AF_UNIX && memchr(address.sun_path, '\0', sizeof(address.sun_path)) != NULL &&
        rdx_listener_address_is_valid(address.sun_path) &&
        getsockopt(listener, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 &&
        type_length == sizeof(type) && type == SOCK_STREAM &&
        // Darwin does not implement getsockopt(SO_ACCEPTCONN). Read the same
        // kernel option bit from our own retained descriptor via public libproc.
        proc_pidfdinfo(getpid(), listener, PROC_PIDFDSOCKETINFO, &information, sizeof(information)) == (int)sizeof(information) &&
        rdx_listener_state_is_valid(information.psi.soi_family, information.psi.soi_type, information.psi.soi_options);
}

static bool rdx_listener_is_exact(int listener) {
    // Provenance is established exclusively by launch_activate_socket("Listener")
    // below. Its private kernel bind name can survive launchd renaming the vnode
    // to the protected public alias. Namespace trust remains a separate proof.
    return rdx_listener_descriptor_is_valid(listener) && rdx_macos_endpoint_path_is_protected();
}

#if defined(RDX_MACOS_ENDPOINT_TEST_HOOKS)
bool rdx_macos_test_listener_address_is_valid(const char *address) { return rdx_listener_address_is_valid(address); }
bool rdx_macos_test_listener_descriptor_is_valid(int listener) { return rdx_listener_descriptor_is_valid(listener); }
bool rdx_macos_test_listener_state_is_valid(int family, int type, int options) { return rdx_listener_state_is_valid(family, type, options); }
#endif

void rdx_macos_log_endpoint_phase(const char *phase, const char *result) {
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT,
        "OpenRDXManager service endpoint: phase=%{public}s result=%{public}s", phase, result);
}

void rdx_macos_log_endpoint_native_code(const char *phase, int32_t code) {
    os_log_error(OS_LOG_DEFAULT,
        "OpenRDXManager service native failure: phase=%{public}s code=%{public}d", phase, code);
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

static int rdx_accept_bounded(int listener, bool *out_idle_timeout) {
    *out_idle_timeout = false;
    int64_t started = 0;
    if (!rdx_monotonic_milliseconds(&started)) {
        return -1;
    }
    const int64_t deadline = started + RDX_ACCEPT_TIMEOUT_MS;
    for (;;) {
        int64_t current = 0;
        if (!rdx_monotonic_milliseconds(&current)) { return -1; }
        if (current >= deadline) { *out_idle_timeout = true; return -1; }
        const int remaining = (int)(deadline - current);
        struct pollfd descriptor = {
            .fd = listener,
            .events = POLLIN,
            .revents = 0,
        };
        const int ready = poll(&descriptor, 1, remaining);
        if (ready == 0) { *out_idle_timeout = true; return -1; }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if ((descriptor.revents & POLLIN) == 0) {
            errno = EIO;
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

rdx_macos_status rdx_macos_activate_launchd_listener(int *out_listener) {
    if (out_listener == NULL) {
        return RDX_MACOS_STATUS_INVALID_ARGUMENT;
    }
    *out_listener = -1;
    int *listeners = NULL;
    size_t listener_count = 0;
    const int activation = launch_activate_socket("Listener", &listeners, &listener_count);
    if (activation != 0) { os_log_error(OS_LOG_DEFAULT, "OpenRDXManager listener activation failed: code=%{public}d", activation); }
    if (activation != 0 ||
        listeners == NULL || listener_count != 1 ||
        !rdx_listener_is_exact(listeners[0])) {
        rdx_macos_log_endpoint_phase("listener-validation", "denied");
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
    bool idle_timeout = false;
    const int peer = rdx_accept_bounded(listener, &idle_timeout);
    if (peer < 0) {
        return idle_timeout ? RDX_MACOS_STATUS_TIMED_OUT : RDX_MACOS_STATUS_TRANSPORT_UNAVAILABLE;
    }
    if (fcntl(peer, F_SETFD, FD_CLOEXEC) != 0) {
        rdx_macos_log_endpoint_native_code("accepted-peer-cloexec", errno);
        (void)close(peer);
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    int enabled = 1;
    if (setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        rdx_macos_log_endpoint_native_code("accepted-peer-nosigpipe", errno);
        (void)close(peer);
        return RDX_MACOS_STATUS_NATIVE_FAILURE;
    }
    struct stat console_status;
    if (stat("/dev/console", &console_status) != 0 || console_status.st_uid == 0 ||
        !rdx_macos_peer_identity_matches(peer, requirement_text,
            "/Applications/OpenRDXManager.app/Contents/MacOS/OpenRDXManager",
            console_status.st_uid, out_user_id)) {
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

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Reproduce launchd-style listener inheritance without service registration or root. */
#include "rdx_endpoint_identity.h"
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/** Obtain fixture helper identity from its actual ad-hoc signature. */
static bool helper_requirement(const char *path, char requirement[256]) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
    SecStaticCodeRef code = NULL;
    CFDictionaryRef info = NULL;
    bool valid = url != NULL && SecStaticCodeCreateWithPath(url, 0, &code) == errSecSuccess &&
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess;
    CFDataRef hash = info == NULL ? NULL : CFDictionaryGetValue(info, kSecCodeInfoUnique);
    if (valid && hash != NULL && CFDataGetLength(hash) == 20) {
        char hexadecimal[41];
        for (size_t index = 0; index < 20; index += 1) { snprintf(&hexadecimal[index * 2], 3, "%02x", CFDataGetBytePtr(hash)[index]); }
        snprintf(requirement, 256, "identifier \"com.openrdx.hardware\" and cdhash H\"%s\"", hexadecimal);
    } else { valid = false; }
    if (info != NULL) { CFRelease(info); } if (code != NULL) { CFRelease(code); } if (url != NULL) { CFRelease(url); }
    return valid;
}

/** Verify peer identity becomes the actual accepting child before any protocol bytes. */
int main(int argc, char **argv) {
    if (argc != 2) { return 1; }
    char requirement[256];
    if (!helper_requirement(argv[1], requirement)) { return 2; }
    char directory[] = "/tmp/openrdx-inherited-XXXXXX";
    if (mkdtemp(directory) == NULL) { return 3; }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", directory);
    int control[2], ready[2];
    const int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 1) != 0 ||
        pipe(control) != 0 || pipe(ready) != 0) { return 4; }
    const pid_t child = fork();
    if (child == 0) {
        close(control[1]); close(ready[0]);
        char listener_text[32], control_text[32], ready_text[32];
        snprintf(listener_text, sizeof(listener_text), "%d", listener);
        snprintf(control_text, sizeof(control_text), "%d", control[0]);
        snprintf(ready_text, sizeof(ready_text), "%d", ready[1]);
        execl(argv[1], argv[1], listener_text, control_text, ready_text, NULL);
        _exit(5);
    }
    close(control[0]); close(ready[1]);
    const int client = socket(AF_UNIX, SOCK_STREAM, 0);
    int result = 0;
    uint32_t uid = 0;
    if (child < 0 || client < 0 || connect(client, (struct sockaddr *)&address, sizeof(address)) != 0) { result = 6; goto cleanup; }
    // While the connection is queued, the helper has not accepted this socket.
    if (rdx_macos_peer_identity_matches(client, requirement, argv[1], getuid(), &uid)) { result = 7; goto cleanup; }
    const rdx_macos_identity_diagnostic queued = rdx_macos_last_identity_diagnostic();
    if (queued.stage == NULL || strcmp(queued.stage, "verified") == 0) { result = 13; goto cleanup; }
    if (write(control[1], "a", 1) != 1) { result = 8; goto cleanup; }
    struct pollfd wait = {.fd = ready[0], .events = POLLIN};
    char signal;
    if (poll(&wait, 1, 3000) != 1 || read(ready[0], &signal, 1) != 1) { result = 9; goto cleanup; }
    audit_token_t token = {{0}};
    socklen_t size = sizeof(token);
    const int token_result = getsockopt(client, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size);
    if (token_result != 0 || audit_token_to_pid(token) != child ||
        !rdx_macos_peer_identity_matches(client, requirement, argv[1], getuid(), &uid)) { result = 10; goto cleanup; }
    // Expected code, uid and path continue to be enforced after activation.
    if (rdx_macos_peer_identity_matches(client, requirement, argv[1], getuid() + 1, &uid) ||
        rdx_macos_peer_identity_matches(client, requirement, "/tmp/wrong-helper", getuid(), &uid)) { result = 11; goto cleanup; }
cleanup:
    if (result != 0) { const rdx_macos_identity_diagnostic detail = rdx_macos_last_identity_diagnostic(); fprintf(stderr, "identity stage=%s code=%d pid=%d uid=%u\n", detail.stage, detail.code, detail.peer_pid, detail.peer_uid); }
    (void)write(control[1], "q", 1);
    if (client >= 0) { close(client); } close(listener); close(control[1]); close(ready[0]);
    if (child > 0) { int status; if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) { result = result == 0 ? 12 : result; } }
    unlink(address.sun_path); rmdir(directory);
    if (result == 0) { puts("inherited listener: queued peer denied; accepted helper audit token/code verified before protocol bytes"); }
    else { fprintf(stderr, "inherited listener test failed: %d errno=%d\n", result, errno); }
    return result;
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Actual user-domain launchd fixture; never applies production namespace authority. */
#include "rdx_endpoint_identity.h"
#include <launch.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/** Prove own-job activation's generated bind name is a valid listening stream. */
int main(void) {
    int *listeners = NULL;
    size_t count = 0;
    const int activation = launch_activate_socket("Listener", &listeners, &count);
    if (activation != 0 || listeners == NULL || count != 1) { return 1; }
    const bool valid = rdx_macos_test_listener_descriptor_is_valid(listeners[0]);
    (void)fprintf(stderr, "launchd listener descriptor: valid=%s\n", valid ? "true" : "false");
    if (!valid) { close(listeners[0]); free(listeners); return 2; }
    const int peer = accept(listeners[0], NULL, NULL);
    if (peer >= 0) { (void)fprintf(stderr, "launchd listener accepted before protocol bytes\n"); close(peer); }
    close(listeners[0]); free(listeners);
    return peer < 0 ? 3 : 0;
}

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
/** No-device inherited-listener fixture; all descriptors are temporary test IO. */
#include <poll.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/** Accept only after the parent tested the queued connection's unauthenticated peer. */
int main(int argc, char **argv) {
    if (argc != 4) { return 1; }
    const int listener = atoi(argv[1]), control = atoi(argv[2]), ready = atoi(argv[3]);
    char signal;
    struct pollfd wait = {.fd = control, .events = POLLIN};
    if (poll(&wait, 1, 3000) != 1 || read(control, &signal, 1) != 1) { return 2; }
    const int peer = accept(listener, NULL, NULL);
    if (peer < 0 || write(ready, "a", 1) != 1) { return 3; }
    wait.revents = 0;
    if (poll(&wait, 1, 3000) != 1 || read(control, &signal, 1) != 1) { return 4; }
    // No protocol byte is ever read or sent through the authenticated socket.
    close(peer); close(listener); close(control); close(ready);
    return 0;
}

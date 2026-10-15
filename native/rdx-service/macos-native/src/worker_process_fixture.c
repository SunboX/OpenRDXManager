/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

/** Fixed test-only pipe read; parent owns the short deadline and exact child cleanup. */
static int read_exact(int fd, void *output, size_t size) {
    size_t got = 0;
    while (got < size) {
        ssize_t count = read(fd, (char *)output + got, size - got);
        if (count <= 0) { return 1; } got += (size_t)count;
    }
    return 0;
}

/** Synthetic credential/session fields test parent framing; actual PID/PPID remain kernel-derived. */
static int context_contract(int bad) {
    unsigned char header[16]; uint32_t expected[10];
    if (read_exact(0, header, sizeof(header)) || memcmp(header, "RDXSCSI1", 8) || header[8] != 10 ||
        read_exact(0, expected, sizeof(expected))) { return 90; }
    uint32_t context[18] = {1, 72, 0, 0, expected[7], expected[8], (uint32_t)getpid(), (uint32_t)getppid(),
        expected[4], 0, expected[8], 0, expected[7], (uint32_t)getpid(), expected[5], 7, expected[5], 0x6030};
    if (bad) { context[6] += 1; }
    memset(header, 0, sizeof(header)); memcpy(header, "RDXSCSI1", 8); header[8] = 11; header[12] = 72;
    if (write(1, header, sizeof(header)) != sizeof(header) || write(1, context, sizeof(context)) != sizeof(context)) { return 91; }
    if (read_exact(0, header, sizeof(header)) || header[8] != 12) { return 92; }
    if (read_exact(0, header, sizeof(header)) || header[8] != 1) { return 93; }
    uint32_t size = 0; memcpy(&size, header + 12, sizeof(size));
    char payload[1024]; if (size > sizeof(payload) || read_exact(0, payload, size)) { return 94; }
    memset(header, 0, sizeof(header)); memcpy(header, "RDXSCSI1", 8); header[8] = 2;
    if (write(1, header, sizeof(header)) != sizeof(header)) { return 95; }
    return 37;
}

/** Harmless ordinary child only: proves real pipe/FD/environment/signal semantics, no session claim. */
int main(int argc, char **argv, char **environment) {
    if (argc != 3 || (strcmp(argv[1], "contract") != 0 && strcmp(argv[1], "signals") != 0 &&
        strcmp(argv[1], "context") != 0 && strcmp(argv[1], "badcontext") != 0)) { return 80; }
    const int forbidden = atoi(argv[2]);
    if (forbidden >= 0 && fcntl(forbidden, F_GETFD) != -1) { return 81; }
    for (int fd = 3; fd < 256; fd++) { if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) { return 82; } }
    struct sigaction action;
    sigset_t mask;
    if (sigaction(SIGPIPE, NULL, &action) != 0 || action.sa_handler != SIG_DFL ||
        sigprocmask(SIG_SETMASK, NULL, &mask) != 0) { return 83; }
    if (strcmp(argv[1], "signals") == 0 &&
        (sigaction(SIGTERM, NULL, &action) != 0 || action.sa_handler != SIG_IGN)) { return 89; }
    for (int signal = 1; signal < NSIG; signal++) { if (sigismember(&mask, signal) == 1) { return 84; } }
    if (environment[0] == NULL || strcmp(environment[0], "LANG=C") || environment[1] != NULL) { return 85; }
    if (strcmp(argv[1], "context") == 0 || strcmp(argv[1], "badcontext") == 0) {
        return context_contract(strcmp(argv[1], "badcontext") == 0);
    }
    char input[8]; size_t got = 0;
    while (got < sizeof(input)) {
        ssize_t length = read(0, input + got, sizeof(input) - got);
        if (length <= 0) { return 86; } got += (size_t)length;
    }
    if (memcmp(input, "pipe-ok\n", sizeof(input))) { return 87; }
    if (printf("pid=%d pipe-ok sigpipe-default mask-empty env-exact\n", getpid()) < 0 || fflush(stdout) ||
        fputs("stderr-ok\n", stderr) == EOF || fflush(stderr)) { return 88; }
    return 37;
}

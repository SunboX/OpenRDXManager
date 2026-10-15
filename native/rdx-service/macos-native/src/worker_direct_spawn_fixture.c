/* SPDX-FileCopyrightText: 2026 André Fiedler */
/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "rdx_worker_spawn.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Link-only unavailable GUI symbols: the direct fixture must never enter their code path. */
bool rdx_macos_peer_session_record_is_valid(const rdx_macos_peer_session *peer) {
    (void)peer; _exit(90);
}
uint32_t rdx_macos_peer_session_user_id(const rdx_macos_peer_session *peer) {
    (void)peer; _exit(91);
}

/** Harmless actual child proves fixed same-executable role, clean env, descriptors and signal setup. */
static int child(char **environment) {
    for (int fd = 3; fd < 256; fd++) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) { return 92; }
    }
    struct sigaction action; sigset_t mask;
    if (sigaction(SIGPIPE, NULL, &action) != 0 || action.sa_handler != SIG_DFL ||
        sigprocmask(SIG_SETMASK, NULL, &mask) != 0) { return 93; }
    for (int signal = 1; signal < NSIG; signal++) {
        if (sigismember(&mask, signal) == 1) { return 94; }
    }
    if (!environment[0] || strcmp(environment[0], "LANG=C") || environment[1]) { return 95; }
    char bytes[8]; size_t got = 0;
    while (got < sizeof(bytes)) {
        ssize_t n = read(0, bytes + got, sizeof(bytes) - got);
        if (n <= 0) { return 96; } got += (size_t)n;
    }
    if (memcmp(bytes, "pipe-ok\n", sizeof(bytes))) { return 97; }
    if (printf("%d", getpid()) < 0 || fflush(stdout) || fputs("stderr-ok", stderr) == EOF) { return 98; }
    return 37;
}

/** No root/device work: test-only entry calls the same consumed resolver and owned spawn primitive. */
int main(int argc, char **argv, char **environment) {
    alarm(3);
    if (argc == 2 && !strcmp(argv[1], "--openrdx-internal-macos-scsi-worker")) {
        return child(environment);
    }
    if (argc != 1) { return 80; }
    int token = open("/dev/null", O_RDONLY); if (token < 3) { return 81; }
    if (fcntl(token, F_SETFD, 0)) { return 82; }
    rdx_macos_worker_process process;
    if (rdx_macos_test_spawn_current_worker(&process) != RDX_MACOS_STATUS_OK) { return 83; }
    if (write(process.input_fd, "pipe-ok\n", 8) != 8) { (void)kill(process.pid, SIGKILL); }
    close(process.input_fd);
    char pid[32] = {0}, error[32] = {0};
    ssize_t pn = read(process.output_fd, pid, sizeof(pid) - 1);
    ssize_t en = read(process.error_fd, error, sizeof(error) - 1);
    close(process.output_fd); close(process.error_fd); close(token);
    int status;
    if (waitpid(process.pid, &status, 0) != process.pid || !WIFEXITED(status) || WEXITSTATUS(status) != 37 ||
        pn <= 0 || en != 9 || strcmp(error, "stderr-ok")) { return 84; }
    char expected[32]; (void)snprintf(expected, sizeof(expected), "%d", process.pid);
    if (strcmp(pid, expected)) { return 85; }
    puts("fixed-current-exe direct-role exact-pid pipes env fd signal exit37 reaped");
    return 0;
}

<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Linux device-access resources

`70-openrdx.rules` is an active, exact rule for the documented Tandberg RDX USB
identity `1a5a:0006`. It reserves only the matching `scsi_generic` node as
root:root mode `0600` for the privileged daemon. Never replace it with a rule
covering every `scsi_generic` node, `uaccess`, the interactive `openrdx` group,
or world/group-writable permissions.

`org.openrdx.hardware.policy` declares the single
`org.openrdx.hardware.manage` action. It denies arbitrary and inactive callers,
requires administrator authentication for each active request, carries no
credentials, and does not by itself make the Task 5 privileged service present
or active. Runtime readiness distinguishes the rule, configured IPC group,
inherited IPC membership, exact service descriptor access, installed policy,
installed unit, running socket, and exact service-process authority.

`openrdx-hardware.socket` is the only production IPC listener. It is created by
systemd as root:`openrdx` with mode `0660`, accepts no TCP or remote transport,
bounds concurrent connections to eight, and activates exactly
`openrdx-hardware.service`. The service receives no stdio protocol, runs with an
explicitly bounded capability set, and must authenticate kernel peer credentials
at accept time. The `openrdx` group is an IPC-only group: membership permits
connection but grants no raw SG device access and does not bypass the
service's exact peer/handshake policy or device identity registry. These files
are packaging resources and are not installed or enabled by repository tests.
`openrdx.conf` declares only the dedicated system group through sysusers.
`openrdx-tmpfiles.conf` declares the root-owned runtime directory and its
root:root mode-`0600` `openrdx-hardware.lock`. The daemon and administrator-run
`rdxctl` take the same nonblocking kernel lock before constructing a hardware
registry; the daemon retains it for the complete authenticated client session.
The lock file is not an authorization token: its open rejects symlinks and its
already-open inode must remain regular, root-owned, single-link, and exactly
mode `0600`. Neither resource adds users to the group; membership remains an
explicit administrator decision. The packaged polkit action is the narrow
authorization identifier for an installer or administration frontend and is
not treated as runtime peer evidence by the daemon.

## Native Linux CI

Run the Linux-only compilation and static verification on an `ubuntu-latest`
runner with Rust 1.85 or newer:

```sh
cargo fmt --manifest-path native/rdx-service/linux-native/Cargo.toml -- --check
cargo check --manifest-path native/rdx-service/linux-native/Cargo.toml --all-targets
cargo clippy --manifest-path native/rdx-service/linux-native/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path native/rdx-service/linux-native/Cargo.toml --all-targets
cargo check --manifest-path native/rdx-service/Cargo.toml --all-targets --all-features
cargo clippy --manifest-path native/rdx-service/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --manifest-path native/rdx-service/Cargo.toml --all-targets --all-features
```

On a dedicated Linux acceptance host with the selected SG node idle, the
ignored exact-contention check may be run using only its enumerated safe token:

```sh
OPENRDX_TEST_SG_TOKEN=linux-sg-2 cargo test \
  --manifest-path native/rdx-service/linux-native/Cargo.toml \
  native::tests::exclusive_sg_open_contention_reports_busy -- --ignored --exact
```

Do not run that check against an SG node owned by another application. It opens
the selected node read/write, exclusively, nonblocking, close-on-exec, and with
final-component symlink following disabled; it sends no CDB.

Linux runtime acceptance must additionally exercise no-device startup,
permission-denied readiness, exact candidate hotplug/replacement rejection, and
service start/stop transitions. A physical-device matrix must separately cover
successful read-only commands, CHECK CONDITION sense, host/driver failures,
timeouts, removal during I/O, mutating-command ambiguity, block ancestry, and
retained mounted-volume leases.

No physical RDX hardware verification was performed for this implementation.
Portable tests and static source review are not Linux native compilation or
runtime proof. In particular, `SG_IO` is not retried after `EINTR`: the Linux
kernel may already have queued and orphaned the request while its synchronous
wait was interrupted. See the upstream Linux
[`sg.c`](https://github.com/torvalds/linux/blob/master/drivers/scsi/sg.c)
implementation for that completion-uncertainty boundary.

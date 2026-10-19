<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows service handshake

SCM `RUNNING` means that startup authority and the protected first pipe are established. It does not mean that per-client authentication and backend preparation have finished.

The native client first verifies its enrolled runtime, starts or queries the fixed service and proves the connected server's executable, process, account and SCM identity. The service independently verifies the client's session, process, executable, identification token and user, explicitly reverts identification impersonation, and rechecks its running authority. It retains the protected pipe namespace throughout this admission.

After acquiring hardware ownership and preparing the backend, the service arms the existing two-second first-frame reader, checks for STOP and writes the fixed 16-byte ASCII prelude `OpenRDX:ready:1\n`. The native client consumes exactly those bytes before publishing `connect` to the main process. Framed protocol version 1 then begins with the existing Manager handshake. The prelude is readiness evidence on an already authenticated pipe; it does not replace authentication.

All marker fragments share the original seven-second native activation deadline. The client checks deadline and cancellation after synchronous and asynchronous completion. Missing, malformed, truncated, cancelled and late markers close the connection. There is no fallback to an older wire sequence. Client and service must be installed together. Extra bytes remain in the pipe for the existing frame decoder. The main process allows 53 seconds for the connection: a 45-second allowance for complete runtime verification, followed by seven seconds for native activation and one second of watchdog margin. This is an outer watchdog, not a separately enforced native verification deadline. The framed handshake retains its two-second bound and starts only after verified readiness.

Native reads retain operation-owned handles, events, storage and their aggregate reservations until exact terminal completion is observed. Cancellation uses the original bounded drain; unresolved operations retain storage and budget until process teardown.

Complete runtime verification rereads and hashes every listed file. On Windows, a fresh fixed SHA-256 CNG state computes each file digest. Other platforms retain the portable SHA-256 implementation. There is no content cache or relaxed length, topology, enrollment or protection check.

The implementation is in `native/windows-client-addon/{service_ready.h,windows_pipe_io.h,openrdx_windows_client.cc}` and `native/rdx-service/src/bin/openrdx-hardware/windows_session.rs`. The portable parser fixture and Windows private-pipe fixture use no installed service or device. Installed authentication and read-only dock access remain separate acceptance gates.

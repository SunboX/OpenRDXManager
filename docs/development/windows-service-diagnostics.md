<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Windows service failure diagnostics

A completed installer verifies protected enrollment. Installed app-to-service authentication and physical device access require separate checks.

If `OpenRDXHardwareService` stops with Windows error 1066, inspect its service-specific exit code from a normal PowerShell session:

```powershell
$service = Get-CimInstance Win32_Service -Filter "Name='OpenRDXHardwareService'"
$service | Select-Object State, ExitCode, ServiceSpecificExitCode
'{0:X8}' -f [uint32]$service.ServiceSpecificExitCode
```

Codes in the `5244SSRR` hexadecimal format identify the first failed instrumented boundary in the current service startup or connection attempt. `SS` is the stage byte and `RR` is the sanitized native error byte. They contain no device identities, filesystem paths, security descriptors, credentials or protocol data. Earlier packages reported only the generic service-specific value `1`.

| Stage byte | Boundary |
| --- | --- |
| `01` | Startup enrolled runtime verification |
| `02` | Startup service authority |
| `03` | Current service executable identity |
| `04` | Current service metadata query grants |
| `05` | Active console pipe authority |
| `06` | First protected pipe creation |
| `07` | Per-connection enrolled runtime verification |
| `08` | Waiting for a connected Manager |
| `09` | Client console session |
| `0A` | Client process and executable identity |
| `0B` | Identification impersonation |
| `0C` | Identification token query |
| `0D` | Client user identity |
| `0F` | Independent running-service authority after reversion |
| `10` | Next protected pipe creation |
| `11` | Retained pipe namespace ownership |
| `12` | Authenticated pipe handle duplication |
| `13` | Authenticated pipe read mode |
| `14` | Uninstrumented service runner failure |

| Error byte | Sanitized native error |
| --- | --- |
| `01` | UnsupportedPlatform |
| `02` | InvalidRequest |
| `03` | AccessDenied |
| `04` | Busy |
| `05` | ReadOnly |
| `06` | Cancelled |
| `07` | TimedOut |
| `08` | DeviceRemoved |
| `09` | NoMedia |
| `0A` | EnumerationFailed |
| `0B` | EvidenceIncomplete |
| `0C` | ResourceLimit |
| `0D` | Other |

For example, `52440B03` means identification impersonation returned `AccessDenied`. A clean retirement reports zero. The service preserves its original failure, authentication checks, timeouts and cleanup order; the code is diagnostic evidence, not a replacement acceptance result. Failure capture belongs to the registered callback thread and is cleared before each accept attempt, so an earlier idle poll cannot label the next connection. The handled `ConnectionWait/TimedOut` result is never retained, including when STOP races before the next accept.

The implementation is in `native/rdx-service/windows-native/src/service/diagnostics.rs`, with native call sites in `service.rs`, `native/readiness.rs` and `endpoint.rs`. A runner fallback can identify only the broader boundary; it does not prove a particular failed Windows API.

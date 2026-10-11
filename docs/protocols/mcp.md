<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# MCP interface

OpenRDXManager includes an opt-in Model Context Protocol (MCP) server. An agent connects to the **running desktop application** and uses its existing device service, current inventory, operation coordinator, and safety policy. Opening an agent connection does not start a second hardware service.

## Connection contract

Use the [client setup guide](../ai-agent-access.md) to enable the endpoint and copy the configuration. The client needs Node.js 22.12.0 or newer to run the stdio bridge.

The copied configuration contains the absolute bridge script and credential-file paths for this installation. It does not contain the credential itself. A representative configuration is:

```json
{
    "mcpServers": {
        "OpenRDXManager": {
            "command": "node",
            "args": ["/absolute/path/to/OpenRDXManager/scripts/mcp-stdio.mjs"],
            "env": {
                "OPENRDX_MCP_URL": "http://127.0.0.1:48170/mcp",
                "OPENRDX_MCP_TOKEN_FILE": "/absolute/path/to/application-user-data/mcp/token"
            }
        }
    }
}
```

The bridge speaks MCP over stdio, attaches to the authenticated HTTP endpoint, and supports resource updates for both legacy and modern stdio clients. It emits only protocol data on stdout. Clients may also connect directly using Streamable HTTP with an `Authorization: Bearer <token>` header on every request. Direct legacy HTTP clients can call tools and read resources but must poll; modern HTTP clients can subscribe to resource updates. The stdio bridge negotiates the modern upstream connection automatically.

`npm run mcp` starts only the bridge; set `OPENRDX_MCP_URL` and `OPENRDX_MCP_TOKEN_FILE` in its environment first. `OPENRDX_MCP_TOKEN` can supply the token directly where a client's secret environment storage is preferred. Do not put real credentials in command arguments or repository files.

## Tools and values

Start with `rdx_capabilities`, `rdx_service_status`, and `rdx_devices_list`. Tool discovery provides strict input schemas. Device identities are opaque `rdx:` IDs, not operating-system paths. Device operations require the current `deviceRevision`; refresh the inventory after a stale-revision rejection.

| Function                             | Tools                                                                                                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| App and service state                | `rdx_app_info`, `rdx_mcp_status`, `rdx_service_status`, `rdx_service_setup`, `rdx_capabilities`, `rdx_help`                                                              |
| Discovery and values                 | `rdx_scan`, `rdx_devices_list`, `rdx_device_get`, `rdx_status_refresh`                                                                                                   |
| Operation progress                   | `rdx_operations_list`, `rdx_operation_get`, `rdx_operation_cancel`                                                                                                       |
| Diagnostics                          | `rdx_self_test`, `rdx_led_test`, `rdx_write_read_test`                                                                                                                   |
| Firmware                             | `rdx_firmware_register`, `rdx_firmware_update`                                                                                                                           |
| Drive configuration                  | `rdx_drive_letter_set`, `rdx_drive_letter_reset`, `rdx_drive_mode_set`, `rdx_sata_mode_set`                                                                              |
| Cartridge actions                    | `rdx_confirm_format`, `rdx_format`, `rdx_eject_safe`, `rdx_confirm_eject_force`, `rdx_eject_force`                                                                       |
| Security operations, where supported | `rdx_access_enable`, `rdx_access_disable`, `rdx_credential_create`, `rdx_credential_change`, `rdx_credential_delete`, `rdx_credential_reset`, `rdx_credential_configure` |
| Settings and logging                 | `rdx_settings_get`, `rdx_settings_update`, `rdx_logging_set`, `rdx_logs_list`                                                                                            |
| Diagnostic reports                   | `rdx_summary_read`, `rdx_activity_read`, `rdx_summary_export`, `rdx_activity_export`                                                                                     |
| Service setup and updates            | `rdx_service_register`, `rdx_service_open_approval`, `rdx_service_retry`, `rdx_updates_check`                                                                            |
| Desktop actions                      | `rdx_device_select` (tray selection), `rdx_app_show`, `rdx_app_exit`                                                                                                     |

The inventory and device tools return the complete public drive and cartridge snapshots, including typed status details, capability states, and unavailable reasons. Cached state remains cached until a scan or status refresh completes. A missing or unavailable value is never converted to zero or guessed. Discovery diagnostics are preserved where the normal public service response supplies them.

All 20 current operation kinds and all 25 documented feature groups are discoverable. Availability is determined by the **same current platform, native implementation, privilege, device, and media checks** as the desktop application. In particular, existing `evidence-incomplete` security/AES behavior and `legacy-bip-format-unproven` firmware restrictions remain in force. Listing a tool does not claim that an unsupported device can perform it. Secrets, stored passwords, encryption keys, internal transport endpoints, raw CDBs, arbitrary shell commands, and unrestricted file reads are outside the interface.

Endpoint enablement, its port, and copying client configuration are local desktop controls. `rdx_mcp_status` reports their non-secret state. The agent controls public desktop preferences through `rdx_settings_update`; presentation-only navigation is represented by the corresponding data/action tools.

## Resources and progress

The server exposes JSON resources:

```text
openrdx://app
openrdx://devices
openrdx://capabilities
openrdx://operations
openrdx://settings
openrdx://activity
openrdx://support-summary
openrdx://help
openrdx://service
openrdx://mcp
openrdx://devices/{deviceId}
openrdx://operations/{operationId}
```

Encode IDs as URI path components: `op:example` becomes `openrdx://operations/op%3Aexample`. Collection resources announce relevant accepted application changes; subscribers then read the latest value. Clients should also refresh state after reconnecting.

An accepted device operation returns `{ "ok": true, "operationId": "op:…" }`. This means the operation was admitted, **not that it completed**. Read `rdx_operation_get` until a terminal state is reported. Operation history retains up to 128 most recently updated operations for the current application session, and `rdx_operations_list` also reports the active operation or scan reservation. A scan completes through `rdx_scan` and the refreshed inventory rather than creating a device-operation history entry.

GUI and MCP actions share one exclusive operation coordinator. Closing a client or disabling MCP does not cancel hardware work. Cancellation is an explicit request and can be rejected after its safe boundary. Application exit is rejected while a device operation is active; an accepted exit response is sent before normal shutdown starts.

## Firmware, formatting, and reports

Firmware registration accepts an explicit absolute local `.BIN` or `.BIP` path and returns an opaque, one-use file token valid for five minutes. The application checks file type, size, symlink status, identity, and exact contents again when claiming it. Pass the token to `rdx_firmware_update` with the current device ID and revision. Native image validation and device compatibility still decide whether the update can start.

Formatting and forced eject each require a separate explicit confirmation tool call. The returned token is bound to the exact action, device revision, service generation, and (for formatting) filesystem; it expires after 60 seconds and is consumed once. The agent must obtain the user's authorization for the actual destructive action before requesting it. A token proves an explicit protocol step, not human approval. Ordinary start calls never obtain confirmation tokens implicitly.

Report reads return sanitized text without a dialog. Exports create new UUID-named files in the application's user-data `exports` directory and return `savedPath`; they do not overwrite existing files or upload reports. OS helper registration may still require the operating system's approval interface. MCP cannot supply that approval.

## Endpoint behavior and failures

The listener binds only to `127.0.0.1`, checks Host and Origin, and authenticates every request with a generated 256-bit token. Requests have bounded body sizes and concurrency. Settings and token files are separate; POSIX installations restrict the MCP directory to `0700` and files to `0600`. Windows requires the native client addon and verifies a protected current-user-only DACL on the exact directory and files. Every ancestor is pinned on a local ACL-capable volume; reparse points and multiply linked files are rejected. Settings use flushed/read-back exclusive temporary files and same-directory atomic replacement. Token creation never overwrites an existing token, and an exposed or otherwise unverified credential is rejected rather than silently repaired. Native operations are limited to the fixed settings/token names. Tokens are excluded from public settings, logs, reports, and renderer state.

A Windows bridge using `OPENRDX_MCP_TOKEN_FILE` needs the same rebuilt addon beside the application, plus an already-private local token file. An absent addon or failed owner, ACL, type, size or token-format check fails closed. The bridge does not harden an untrusted credential or opt the application in. These checks do not certify old tokens as private; investigate rejected credentials before enabling access.

The default is disabled. Enabled state and port persist across application restarts. A bind failure is shown in settings and does not stop the desktop application. After resolving a port conflict, apply the settings again. Disabling the server closes its protocol connections while the device runtime continues.

Tool failures use `isError: true` and a structured `{ "ok": false, "reason": "…" }` result. Common reasons include `service-unavailable`, `operation-in-progress`, `stale-device-revision`, `device-not-found`, and the native capability reason. Re-read state before retrying; do not blindly repeat a destructive action after an ambiguous transport failure. Authentication failures are HTTP 401, and invalid Host/Origin requests are HTTP 403. Exceptions and rejected inputs are not echoed into responses.

See [MCP interface implementation](../development/mcp-interface.md) for source ownership and test commands.

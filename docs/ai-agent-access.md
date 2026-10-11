<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# AI agent access

OpenRDXManager includes an opt-in MCP server. An agent connects to the running desktop application and shares its device service, inventory and operation coordinator. Keep the application running while the agent is connected.

## Connect a client

1. Open **MCP settings** from the top bar.
2. Enable the server, keep port `48170` or choose another local port, and apply. Check that the status shows it is listening.
3. Choose **Copy agent configuration** and add the copied `mcpServers` entry to the client's configuration.
4. Ensure the client can run Node.js 22.12.0 or newer. If needed, replace `node` with the absolute path to its Node executable.
5. Restart the agent connection after changing the port or restarting the endpoint.

The configuration uses absolute bridge-script and private credential-file paths for this installation. It does not contain the credential itself. Do not put real tokens into repository files or command arguments.

## Read state and follow operations

Start with `rdx_capabilities`, `rdx_service_status` and `rdx_devices_list`. Availability uses the same platform, service, privilege, dock and media checks as the desktop application. A listed tool does not establish that the selected device can perform it.

Use the current opaque device ID and `deviceRevision` returned by the inventory. Refresh after a stale-revision rejection. An accepted operation returns an `operationId`; read `rdx_operation_get` until a final state is reported. Acceptance is not completion.

GUI and agent actions share one exclusive coordinator. Formatting and forced eject require separate explicit confirmations. Closing a client or disabling MCP does not cancel device work; cancellation must be requested while the operation is still within its safe boundary.

Firmware, migration and factory-data requirements also apply to agent requests. Unsupported security operations remain unavailable. Never blindly repeat a destructive action after an ambiguous transport failure.

## Endpoint problems

MCP is disabled by default. Enabled state and port persist across application restarts. If the port is busy, resolve the conflict and apply settings again; a bind failure does not stop the application. Disabling MCP closes its protocol connections while the device runtime continues.

See [troubleshooting](troubleshooting.md) for service or device failures. The full tool inventory, resource URIs, connection formats and error contract are in the [MCP interface reference](protocols/mcp.md). Maintainers can use [MCP verification](verification/mcp-verification.md) and the [MCP specification](specs/mcp-2026-09-10.md).

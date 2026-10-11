<!-- SPDX-FileCopyrightText: 2026 André Fiedler -->
<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# MCP interface implementation

The shared dispatcher is in `src/main/application-dispatcher.mjs`; explicit route/operation coverage and strict tool schemas are in `src/main/mcp/tool-registry.mjs`. The HTTP adapter, settings controller, credential files, accepted event publication, and stdio bridge live beside it. This implementation uses the official MCP SDK packages pinned to `2.0.0` in the lockfile. See the [official SDK documentation](https://github.com/modelcontextprotocol/typescript-sdk) for client protocol details.

Run `npm run test:mcp` for focused boundaries and actual HTTP/stdio clients. Run `env -u ELECTRON_RUN_AS_NODE npm run test:mcp:electron` for the production main/preload/renderer flow with isolated preferences, UI enable/copy/disable, a local agent connection, and screenshots under `test-results/mcp/`. The latter checks local application integration; it does not perform destructive device operations or prove packaging. Full project verification remains `npm test`, `npm run smoke`, and `npm run format:check`.

See the [MCP interface reference](../protocols/mcp.md), [client setup](../ai-agent-access.md) and [MCP verification](../verification/mcp-verification.md).

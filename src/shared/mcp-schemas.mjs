// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { z } from '../../node_modules/zod/index.js'

const portSchema = z.number().int().min(1024).max(65535)
const failureSchema = z.object({ ok: z.literal(false), reason: z.string().regex(/^[a-z][a-z0-9-]{0,127}$/) }).strict()

/** Strict local MCP configuration; network interfaces and credentials cannot be supplied by the renderer. */
export const mcpSettingsUpdateSchema = z
    .object({ enabled: z.boolean().optional(), port: portSchema.optional() })
    .strict()
    .refine((request) => Object.keys(request).length > 0)

/** Complete non-secret persisted MCP preferences. */
export const mcpSettingsSchema = z.object({ enabled: z.boolean(), port: portSchema }).strict()

/** Renderer-visible MCP state; tokens and credential paths never cross this boundary. */
export const mcpStatusResponseSchema = z.union([
    z
        .object({
            ok: z.literal(true),
            enabled: z.boolean(),
            port: portSchema,
            status: z.enum(['disabled', 'listening', 'error']),
            endpoint: z
                .string()
                .regex(/^http:\/\/127\.0\.0\.1:\d{4,5}\/mcp$/)
                .nullable(),
            reason: z
                .string()
                .regex(/^[a-z][a-z0-9-]{0,127}$/)
                .optional()
        })
        .strict()
        .refine((value) => (value.status === 'listening' ? value.enabled && value.endpoint === `http://127.0.0.1:${value.port}/mcp` : value.endpoint === null)),
    failureSchema
])

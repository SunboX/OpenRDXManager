// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { z } from '../../node_modules/zod/index.js'

const deviceId = z
    .string()
    .max(128)
    .regex(/^rdx:[a-z0-9:-]+$/iu)
const backupId = z.string().regex(/^record-(?:0|[1-9a-f][0-9a-f]{0,31})-(?:0|[1-9a-f][0-9a-f]{0,15})$/u)
const serial = z.string().regex(/^[0-9]{10}$/u)
const target = { deviceId, deviceRevision: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) }

/** Exact current dock selection, never a path or raw flash command. */
export const manufacturingRequestSchema = z.object({ ...target, page: z.number().int().min(0).max(31).optional(), reconcile: z.boolean().optional() }).strict()

/** Explicit association of the selected backup's original serial with the physical dock. */
export const manufacturingRestoreRequestSchema = z.object({ ...target, backupId, confirmationSerial: serial, acknowledged: z.literal(true), allowIdentityChange: z.boolean().optional() }).strict()

/** Verified saved metadata; opaque manufacturing bytes remain inside the native service. */
export const manufacturingResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), page: z.number().int().min(0).max(31).optional(), hasMore: z.boolean().optional(), backupSupported: z.boolean(), restoreSupported: z.boolean(), backups: z.array(z.object({ backupId, deviceId, serial: serial.nullable(), createdAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER), state: z.enum(['valid', 'erased', 'corrupt']) }).strict()).max(128) }).strict(), z.object({ ok: z.literal(false), reason: z.string().regex(/^[a-z][a-z0-9-]{0,127}$/u) }).strict()])

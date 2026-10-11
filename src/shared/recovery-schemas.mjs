// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { z } from '../../node_modules/zod/index.js'

const reason = z.string().regex(/^[a-z][a-z0-9-]{0,127}$/u)
const opaqueId = z.string().regex(/^[a-z0-9][a-z0-9:-]{0,127}$/u)
const bundleId = z.string().regex(/^migration-(?:0|[1-9a-f][0-9a-f]{0,31})-(?:0|[1-9a-f][0-9a-f]{0,15})$/u)
const revision = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const failure = z.object({ ok: z.literal(false), reason }).strict()

/** Closed controller stages; neither commands nor private native data cross IPC. */
export const recoveryStageSchema = z.enum(['recovery-preparing', 'recovery-identifying-rom', 'recovery-setting-up-rom', 'recovery-programming-bootstrap', 'recovery-resetting-rom', 'recovery-awaiting-power-cycle', 'recovery-verifying-bootstrap', 'recovery-transferring-final-release', 'recovery-activating-final-release', 'recovery-verifying-final-release'])

const activeFields = { revision, attemptId: opaqueId, stage: recoveryStageSchema }

/** Session-owned progress survives renderer replacement and has a monotonic revision. */
export const recoveryStateSchema = z.discriminatedUnion('state', [
    z.object({ state: z.literal('idle'), revision }).strict(),
    z
        .object({ state: z.literal('running'), ...activeFields, awaitingAcknowledgment: z.boolean() })
        .strict()
        .refine((value) => !value.awaitingAcknowledgment || value.stage === 'recovery-awaiting-power-cycle'),
    z.object({ state: z.literal('succeeded'), ...activeFields, stage: z.literal('recovery-verifying-final-release'), awaitingAcknowledgment: z.literal(false) }).strict(),
    z.object({ state: z.literal('failed'), ...activeFields, awaitingAcknowledgment: z.literal(false), reason }).strict()
])

/** User association of saved records with one currently observed physical loader. */
export const recoveryStartRequestSchema = z.object({ bundleId, targetToken: opaqueId, acknowledged: z.literal(true) }).strict()

/** One fresh acknowledgment of the current attempt's visible power-cycle gate. */
export const recoveryContinueRequestSchema = z.object({ attemptId: opaqueId, stage: z.literal('recovery-awaiting-power-cycle'), acknowledged: z.literal(true) }).strict()

/** Fixed status or safe failure, independent of normal storage-device discovery. */
export const recoveryStatusResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), status: recoveryStateSchema }).strict(), failure])

/** Read-only safe inventory; original flash records, hashes and paths remain private. */
export const recoveryListResponseSchema = z.discriminatedUnion('ok', [
    z
        .object({
            ok: z.literal(true),
            targets: z
                .array(
                    z
                        .object({
                            token: opaqueId,
                            label: z
                                .string()
                                .min(1)
                                .max(128)
                                .regex(/^[^\x00-\x1f\x7f]+$/u)
                        })
                        .strict()
                )
                .max(16),
            bundles: z.array(z.object({ bundleId, serial: z.string().regex(/^[0-9]{10,12}$/u), sourceVersion: z.literal('2.83'), targetVersion: z.literal('1.07'), recoveryNeeded: z.boolean() }).strict()).max(128),
            status: recoveryStateSchema
        })
        .strict(),
    failure
])

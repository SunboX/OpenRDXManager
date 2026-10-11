// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { z } from '../../node_modules/zod/index.js'
import { deviceSnapshotSchema, discoveryDiagnosticsSchema, operationEventSchema } from '../shared/schemas.mjs'
import { SERVICE_PROTOCOL_VERSION } from './device-service-transport.mjs'

const reasonSchema = z.string().regex(/^[a-z][a-z0-9-]{0,127}$/)

/** @param {object} capability - Strict capability. @param {object} context - Zod issue sink. @returns {void} Adds a cross-field issue. */
function validateCapabilityReason(capability, context) {
    if ((capability.state === 'available') !== (capability.reason === undefined)) context.addIssue({ code: z.ZodIssueCode.custom, message: 'platform-capability-reason-inconsistent' })
}

const platformCapabilitySchema = z
    .object({ state: z.enum(['available', 'unsupported-platform', 'insufficient-permission', 'host-dependency-missing', 'transport-unavailable', 'hardware-unverified']), reason: reasonSchema.optional() })
    .strict()
    .superRefine(validateCapabilityReason)

/** @param {object} handshake - Strict handshake. @param {object} context - Zod issue sink. @returns {void} Adds any mode contradiction. */
function validateHandshakeCrossFields(handshake, context) {
    if (handshake.mode === 'no-device' && (handshake.privileged || handshake.platformCapability.state !== 'transport-unavailable')) context.addIssue({ code: z.ZodIssueCode.custom, message: 'no-device-handshake-inconsistent' })
    if (handshake.mode === 'native' && handshake.platformCapability.state === 'available' && !handshake.privileged) context.addIssue({ code: z.ZodIssueCode.custom, message: 'native-handshake-inconsistent' })
}

/** Strict native handshake schema. */
export const handshakeSchema = z
    .object({ type: z.literal('handshake'), protocolVersion: z.literal(SERVICE_PROTOCOL_VERSION), serviceVersion: z.string().trim().min(1).max(64), platform: z.enum(['darwin', 'win32', 'linux']), mode: z.enum(['native', 'no-device']), privileged: z.boolean(), hardwareVerified: z.boolean().optional(), platformCapability: platformCapabilitySchema })
    .strict()
    .superRefine(validateHandshakeCrossFields)

const successResponseSchema = z.object({ type: z.literal('response'), requestId: z.string().regex(/^request:[1-9]\d{0,15}$/), ok: z.literal(true), result: z.unknown() }).strict()
const failureResponseSchema = z.object({ type: z.literal('response'), requestId: z.string().regex(/^request:[1-9]\d{0,15}$/), ok: z.literal(false), reason: reasonSchema }).strict()
/** Strict correlated wire response. */
export const wireResponseSchema = z.discriminatedUnion('ok', [successResponseSchema, failureResponseSchema])

const wireDeviceEventSchema = z.discriminatedUnion('type', [z.object({ type: z.literal('snapshot'), listRevision: z.number().int().nonnegative(), device: deviceSnapshotSchema }).strict(), z.object({ type: z.literal('removed'), listRevision: z.number().int().nonnegative(), deviceId: z.string().regex(/^rdx:[a-z0-9:-]+$/i), deviceRevision: z.number().int().nonnegative() }).strict(), z.object({ type: z.literal('list'), listRevision: z.number().int().nonnegative(), devices: z.array(deviceSnapshotSchema).max(128), diagnostics: discoveryDiagnosticsSchema.optional() }).strict()])
const publicationSequenceSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER)
/** Strict device or operation event envelope. */
export const wireEventSchema = z.discriminatedUnion('channel', [z.object({ type: z.literal('event'), channel: z.literal('device'), event: wireDeviceEventSchema }).strict(), z.object({ type: z.literal('event'), channel: z.literal('operation'), publicationSequence: publicationSequenceSchema, event: operationEventSchema }).strict()])

/** Strict initial/list response. */
export const wireDeviceListResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), listRevision: z.number().int().nonnegative(), devices: z.array(deviceSnapshotSchema).max(128), diagnostics: discoveryDiagnosticsSchema.optional() }).strict(), z.object({ ok: z.literal(false), reason: reasonSchema }).strict()])

/** Strict cancellation response carrying its private FIFO cutover. */
export const wireCancellationResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), cancellationCutover: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) }).strict(), z.object({ ok: z.literal(false), reason: reasonSchema }).strict()])

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { z } from '../../node_modules/zod/index.js'

/** Stable renderer-visible capability states. */
export const CapabilityState = Object.freeze({
    AVAILABLE: 'available',
    BUSY: 'busy',
    UNSUPPORTED_PRODUCT: 'unsupported-product',
    UNSUPPORTED_PLATFORM: 'unsupported-platform',
    WRONG_MEDIA_STATE: 'wrong-media-state',
    AUTHENTICATION_REQUIRED: 'authentication-required',
    INSUFFICIENT_PERMISSION: 'insufficient-permission',
    HOST_DEPENDENCY_MISSING: 'host-dependency-missing',
    EVIDENCE_INCOMPLETE: 'evidence-incomplete',
    TRANSPORT_UNAVAILABLE: 'transport-unavailable',
    HARDWARE_UNVERIFIED: 'hardware-unverified'
})

/** Stable high-level operations accepted across the Electron boundary. */
export const OperationKind = Object.freeze({
    SCAN: 'scan',
    STATUS_REFRESH: 'status-refresh',
    ACCESS_ENABLE: 'access-enable',
    ACCESS_DISABLE: 'access-disable',
    CREDENTIAL_CREATE: 'credential-create',
    CREDENTIAL_CHANGE: 'credential-change',
    CREDENTIAL_DELETE: 'credential-delete',
    CREDENTIAL_RESET: 'credential-reset',
    CREDENTIAL_CONFIGURE: 'credential-configure',
    SELF_TEST: 'self-test',
    LED_TEST: 'led-test',
    WRITE_READ_TEST: 'write-read-test',
    FIRMWARE_UPDATE: 'firmware-update',
    VOLUME_LABEL_SET: 'volume-label-set',
    DRIVE_LETTER_SET: 'drive-letter-set',
    DRIVE_LETTER_RESET: 'drive-letter-reset',
    FORMAT: 'format',
    DRIVE_MODE_SET: 'drive-mode-set',
    SATA_MODE_SET: 'sata-mode-set',
    EJECT_SAFE: 'eject-safe',
    EJECT_FORCE: 'eject-force'
})

/** Stable operation risk classifications used by main-process safety policy. */
export const RiskClass = Object.freeze({
    READ_ONLY: 'read-only',
    ROUTINE: 'routine',
    CONFIGURATION: 'configuration',
    CRITICAL: 'critical',
    DESTRUCTIVE: 'destructive'
})

const boundedIdentifierSchema = z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[a-z][a-z0-9:-]*$/i)
const boundedDisplayTextSchema = z.string().trim().min(1).max(128)
const boundedReasonSchema = z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[a-z][a-z0-9-]*$/)
const boundedMessageKeySchema = z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/i)
const deviceIdSchema = boundedIdentifierSchema.regex(/^rdx:[a-z0-9:-]+$/i)
const deviceRevisionSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const operationKindSchema = z.enum(Object.values(OperationKind))
/** Exact cross-language operation identity: case-insensitive `op:` plus a 1..60 character suffix. */
export const operationIdSchema = z.string().regex(/^op:[a-z0-9:-]{1,60}$/i)

export const platformCapabilitySchema = z
    .object({
        state: z.enum(Object.values(CapabilityState)),
        reason: boundedReasonSchema.optional()
    })
    .strict()

const capabilitySchema = platformCapabilitySchema

/**
 * Checks whether a string is a published high-level operation kind.
 * @param {string} key - Candidate capability key.
 * @returns {boolean} True when the key names a known operation.
 */
function isKnownOperationKey(key) {
    return Object.values(OperationKind).includes(key)
}

/**
 * Checks that a sparse capability map contains only known high-level operations.
 * @param {Record<string, unknown>} capabilities - Capability values keyed by operation.
 * @returns {boolean} True when every key is a published operation kind.
 */
function hasOnlyKnownCapabilityKeys(capabilities) {
    return Object.keys(capabilities).every(isKnownOperationKey)
}

/**
 * Checks that normalized media state agrees with whether media is present.
 * @param {{media: object|null, mediaState: string}} snapshot - Snapshot to validate.
 * @returns {boolean} True when media and media state are consistent.
 */
function hasConsistentMediaState(snapshot) {
    return (snapshot.media === null && snapshot.mediaState === 'no-media') || (snapshot.media !== null && snapshot.mediaState === 'present')
}

/**
 * Builds the strict discriminated availability union for one typed status field.
 * @param {import('zod').ZodType} valueSchema - Schema for a reported field value.
 * @returns {import('zod').ZodType} Strict reported-or-unavailable field schema.
 */
function statusFieldSchema(valueSchema) {
    return z.discriminatedUnion('availability', [z.object({ availability: z.literal('reported'), value: valueSchema }).strict(), z.object({ availability: z.literal('unavailable'), reason: boundedReasonSchema }).strict()])
}

const statusTextSchema = statusFieldSchema(boundedDisplayTextSchema)
const statusNumberSchema = statusFieldSchema(z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER))
const statusBooleanSchema = statusFieldSchema(z.boolean())
const statusReasonSchema = statusFieldSchema(boundedReasonSchema)

/** Complete path-free cartridge field availability emitted by hardware discovery. */
const mediaStatusDetailsSchema = z
    .object({
        vendor: statusTextSchema,
        model: statusTextSchema,
        serialNumber: statusTextSchema,
        status: statusTextSchema,
        loadCount: statusNumberSchema,
        hddFirmware: statusTextSchema,
        cartridgeType: statusTextSchema,
        writeProtected: statusBooleanSchema,
        temperatureCelsius: statusNumberSchema,
        capacityBytes: statusNumberSchema,
        usedBytes: statusNumberSchema,
        freeBytes: statusNumberSchema,
        mounted: statusBooleanSchema,
        bytesRead: statusNumberSchema,
        bytesWritten: statusNumberSchema,
        encrypted: statusBooleanSchema,
        supportStatus: statusReasonSchema,
        senseSummary: statusReasonSchema
    })
    .strict()

const fixtureMediaSchema = z
    .object({
        id: boundedIdentifierSchema,
        serial: boundedDisplayTextSchema.optional(),
        label: z
            .string()
            .max(32)
            .refine((value) => value.isWellFormed())
            .regex(/^[^\u0000-\u001f\u007f-\u009f]*$/u)
            .optional(),
        capacityBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
        usedBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
        writable: z.boolean().optional(),
        encrypted: z.boolean().optional(),
        mounted: z.boolean().optional(),
        filesystem: boundedDisplayTextSchema.optional(),
        status: boundedReasonSchema.optional(),
        details: mediaStatusDetailsSchema.optional()
    })
    .strict()

/** @param {unknown} legacy - Optional duplicate. @param {object} field - Canonical field. @returns {boolean} Whether both carry the same availability and value. */
function optionalDuplicateMatches(legacy, field) {
    return field.availability === 'reported' ? legacy === field.value : legacy === undefined
}

/**
 * Compares the machine-readable legacy cartridge status with the equivalent
 * human-readable typed status emitted by the native service.
 * @param {unknown} legacy - Optional machine-readable status reason.
 * @param {object} field - Canonical display-status field.
 * @returns {boolean} Whether both fields describe the same status.
 */
function optionalStatusDuplicateMatches(legacy, field) {
    return field.availability === 'reported' ? legacy === field.value.toLowerCase().replaceAll(' ', '-') : legacy === undefined
}

/** Adds strict cartridge duplicate and capacity-consistency issues. @param {object} media - Parsed media. @param {import('zod').RefinementCtx} context - Zod issue sink. @returns {void} */
function validateMediaStatusConsistency(media, context) {
    const details = media.details
    const consistent = optionalDuplicateMatches(media.serial, details.serialNumber) && optionalStatusDuplicateMatches(media.status, details.status) && optionalDuplicateMatches(media.capacityBytes, details.capacityBytes) && optionalDuplicateMatches(media.usedBytes, details.usedBytes) && optionalDuplicateMatches(media.encrypted, details.encrypted) && (details.writeProtected.availability === 'reported' ? media.writable === !details.writeProtected.value : media.writable === undefined)
    if (!consistent) context.addIssue({ code: z.ZodIssueCode.custom, message: 'Media legacy fields must match typed details' })
    if (details.capacityBytes.availability === 'reported' && details.usedBytes.availability === 'reported' && details.freeBytes.availability === 'reported' && details.capacityBytes.value - details.usedBytes.value !== details.freeBytes.value) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'Media capacity fields must balance' })
    }
}

const mediaSchema = z
    .object({
        id: boundedIdentifierSchema,
        serial: boundedDisplayTextSchema.optional(),
        label: z
            .string()
            .max(32)
            .refine((value) => value.isWellFormed())
            .regex(/^[^\u0000-\u001f\u007f-\u009f]*$/u)
            .optional(),
        capacityBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
        usedBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
        writable: z.boolean().optional(),
        encrypted: z.boolean().optional(),
        filesystem: boundedDisplayTextSchema.optional(),
        status: boundedReasonSchema.optional(),
        details: mediaStatusDetailsSchema
    })
    .strict()
    .superRefine(validateMediaStatusConsistency)

/** Complete path-free drive field availability emitted by hardware discovery. */
const driveStatusDetailsSchema = z
    .object({
        oemName: statusTextSchema,
        serialNumber: statusTextSchema,
        product: statusTextSchema,
        vendor: statusTextSchema,
        firmwareRevision: statusTextSchema,
        bornOnDate: statusTextSchema,
        productType: statusTextSchema,
        connectionType: statusTextSchema,
        operationMode: statusTextSchema,
        sataMode: statusTextSchema,
        status: statusTextSchema,
        loadCount: statusNumberSchema,
        errors: statusTextSchema,
        camState: statusTextSchema,
        policy: statusTextSchema,
        powerSource: statusTextSchema,
        supportStatus: statusReasonSchema,
        senseSummary: statusReasonSchema
    })
    .strict()

/** Sorted unique renderer-safe Windows letters; A-C and path syntax are excluded. */
const availableDriveLettersSchema = z
    .array(z.string().regex(/^[D-Z]$/u))
    .max(23)
    .refine((letters) => letters.every((letter, index) => index === 0 || letters[index - 1] < letter), 'Available drive letters must be sorted and unique')

/** Strict path-free drive status emitted by the native discovery service. */
const fixtureDriveStatusSchema = z
    .object({
        availableDriveLetters: availableDriveLettersSchema.optional(),
        firmwareRevision: boundedDisplayTextSchema.optional(),
        productType: boundedDisplayTextSchema.optional(),
        connectionType: boundedDisplayTextSchema.optional(),
        operationMode: boundedDisplayTextSchema.optional(),
        sataMode: boundedDisplayTextSchema.optional(),
        powerSource: boundedDisplayTextSchema.optional(),
        details: driveStatusDetailsSchema.optional()
    })
    .strict()

/** Adds strict drive duplicate issues. @param {object} drive - Parsed drive. @param {import('zod').RefinementCtx} context - Zod issue sink. @returns {void} */
function validateDriveStatusConsistency(drive, context) {
    const details = drive.details
    const consistent = optionalDuplicateMatches(drive.firmwareRevision, details.firmwareRevision) && optionalDuplicateMatches(drive.productType, details.productType) && optionalDuplicateMatches(drive.connectionType, details.connectionType) && optionalDuplicateMatches(drive.operationMode, details.operationMode) && optionalDuplicateMatches(drive.sataMode, details.sataMode) && optionalDuplicateMatches(drive.powerSource, details.powerSource)
    if (!consistent) context.addIssue({ code: z.ZodIssueCode.custom, message: 'Drive legacy fields must match typed details' })
}

const driveStatusSchema = z
    .object({
        availableDriveLetters: availableDriveLettersSchema.optional(),
        firmwareRevision: boundedDisplayTextSchema.optional(),
        productType: boundedDisplayTextSchema.optional(),
        connectionType: boundedDisplayTextSchema.optional(),
        operationMode: boundedDisplayTextSchema.optional(),
        sataMode: boundedDisplayTextSchema.optional(),
        powerSource: boundedDisplayTextSchema.optional(),
        details: driveStatusDetailsSchema
    })
    .strict()
    .superRefine(validateDriveStatusConsistency)

/** Adds root identity/detail consistency issues. @param {object} snapshot - Parsed snapshot. @param {import('zod').RefinementCtx} context - Zod issue sink. @returns {void} */
function validateDeviceStatusConsistency(snapshot, context) {
    const details = snapshot.drive.details
    const consistent = details.vendor.availability === 'reported' && details.vendor.value === snapshot.vendor && details.product.availability === 'reported' && details.product.value === snapshot.product && details.serialNumber.availability === 'reported' && details.serialNumber.value === snapshot.serial
    if (!consistent) context.addIssue({ code: z.ZodIssueCode.custom, message: 'Device identity must match typed drive details' })
}

/**
 * Validates trusted discovery data before media state is normalized for the
 * renderer. Unlike `deviceSnapshotSchema`, this input has no media-state field.
 */
export const fixtureDeviceSnapshotInputSchema = z
    .object({
        id: deviceIdSchema,
        revision: deviceRevisionSchema,
        vendor: boundedDisplayTextSchema,
        product: boundedDisplayTextSchema,
        serial: boundedDisplayTextSchema,
        drive: fixtureDriveStatusSchema.optional(),
        media: fixtureMediaSchema.nullable(),
        capabilities: z.record(z.string(), capabilitySchema).refine(hasOnlyKnownCapabilityKeys, 'Unknown capability operation')
    })
    .strict()

const serviceDeviceSnapshotBaseSchema = z
    .object({
        id: deviceIdSchema,
        revision: deviceRevisionSchema,
        vendor: boundedDisplayTextSchema,
        product: boundedDisplayTextSchema,
        serial: boundedDisplayTextSchema,
        drive: driveStatusSchema,
        media: mediaSchema.nullable(),
        capabilities: z.record(z.string(), capabilitySchema).refine(hasOnlyKnownCapabilityKeys, 'Unknown capability operation')
    })
    .strict()

export const deviceSnapshotInputSchema = serviceDeviceSnapshotBaseSchema.superRefine(validateDeviceStatusConsistency)

/**
 * Validates the renderer-visible, normalized device state. It deliberately
 * excludes every operating-system path and transport detail.
 */
export const deviceSnapshotSchema = serviceDeviceSnapshotBaseSchema
    .extend({
        mediaState: z.enum(['no-media', 'present'])
    })
    .strict()
    .refine(hasConsistentMediaState, 'Media state must match media presence')
    .superRefine(validateDeviceStatusConsistency)

const candidateRejectionSchema = z.object({ reason: boundedReasonSchema, count: z.number().int().positive().max(128) }).strict()

/** @param {object} diagnostics - Candidate accounting. @returns {boolean} True when every enumerated candidate is accounted for. */
function candidateCountsAreComplete(diagnostics) {
    let rejected = 0
    const reasons = new Set()
    for (const rejection of diagnostics.rejections) {
        if (reasons.has(rejection.reason)) return false
        reasons.add(rejection.reason)
        rejected += rejection.count
    }
    return diagnostics.acceptedCount + rejected === diagnostics.candidateCount
}

/** Path-free aggregate diagnostics from one authoritative discovery pass. */
export const discoveryDiagnosticsSchema = z
    .object({ candidateCount: z.number().int().nonnegative().max(128), acceptedCount: z.number().int().nonnegative().max(128), rejections: z.array(candidateRejectionSchema).max(32) })
    .strict()
    .refine(candidateCountsAreComplete, 'Discovery candidate counts must be complete')

const targetOperationSchema = z.object({
    deviceId: deviceIdSchema,
    deviceRevision: deviceRevisionSchema
})
const confirmationTokenSchema = boundedIdentifierSchema.max(64)
const credentialHandleSchema = boundedIdentifierSchema.max(64)
const credentialIdSchema = boundedIdentifierSchema.max(64)

/**
 * Validates a complete high-level operation request from the renderer.
 * Variant-specific strict objects prevent paths, commands, and arbitrary
 * parameter bags from reaching privileged code.
 */
const formatFilesystemSchema = z.enum(['ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'ntfs', 'exfat', 'fat', 'fat12', 'fat16', 'fat32', 'hfs', 'hfs-case-sensitive', 'hfs-journaled', 'hfs-case-sensitive-journaled', 'apfs', 'apfs-case-sensitive', 'apfs-encrypted', 'apfs-case-sensitive-encrypted'])
const formatPassphraseSchema = z
    .string()
    .min(1)
    .refine((value) => new TextEncoder().encode(value).length <= 512 && !/[\r\n\0]/.test(value))
export const volumeLabelRequestSchema = z
    .object({
        kind: z.literal(OperationKind.VOLUME_LABEL_SET),
        ...targetOperationSchema.shape,
        label: z
            .string()
            .max(32)
            .refine((value) => value.isWellFormed())
            .regex(/^[^\u0000-\u001f\u007f-\u009f\\/:*?"<>|]*$/u)
    })
    .strict()

const formatOperationSchema = z.object({ kind: z.literal(OperationKind.FORMAT), ...targetOperationSchema.shape, filesystem: formatFilesystemSchema, passphrase: formatPassphraseSchema.optional(), confirmationToken: confirmationTokenSchema }).strict()

export const operationRequestSchema = z
    .discriminatedUnion('kind', [
        z.object({ kind: z.literal(OperationKind.SCAN) }).strict(),
        z.object({ kind: z.literal(OperationKind.STATUS_REFRESH), ...targetOperationSchema.shape }).strict(),
        z.object({ kind: z.literal(OperationKind.ACCESS_ENABLE), ...targetOperationSchema.shape, credentialHandle: credentialHandleSchema }).strict(),
        z.object({ kind: z.literal(OperationKind.ACCESS_DISABLE), ...targetOperationSchema.shape }).strict(),
        z.object({ kind: z.literal(OperationKind.CREDENTIAL_CREATE), ...targetOperationSchema.shape, credentialHandle: credentialHandleSchema, confirmationToken: confirmationTokenSchema }).strict(),
        z.object({ kind: z.literal(OperationKind.CREDENTIAL_CHANGE), ...targetOperationSchema.shape, credentialId: credentialIdSchema, credentialHandle: credentialHandleSchema, confirmationToken: confirmationTokenSchema }).strict(),
        z.object({ kind: z.literal(OperationKind.CREDENTIAL_DELETE), ...targetOperationSchema.shape, credentialId: credentialIdSchema, confirmationToken: confirmationTokenSchema }).strict(),
        z.object({ kind: z.literal(OperationKind.CREDENTIAL_RESET), ...targetOperationSchema.shape, confirmationToken: confirmationTokenSchema }).strict(),
        z.object({ kind: z.literal(OperationKind.CREDENTIAL_CONFIGURE), ...targetOperationSchema.shape, confirmationToken: confirmationTokenSchema }).strict(),
        z.object({ kind: z.literal(OperationKind.SELF_TEST), ...targetOperationSchema.shape }).strict(),
        z.object({ kind: z.literal(OperationKind.LED_TEST), ...targetOperationSchema.shape }).strict(),
        z.object({ kind: z.literal(OperationKind.WRITE_READ_TEST), ...targetOperationSchema.shape }).strict(),
        z.object({ kind: z.literal(OperationKind.FIRMWARE_UPDATE), ...targetOperationSchema.shape, firmwareFileToken: boundedIdentifierSchema.max(64) }).strict(),
        z.object({ kind: z.literal(OperationKind.DRIVE_LETTER_SET), ...targetOperationSchema.shape, letter: z.string().regex(/^[A-Z]$/) }).strict(),
        z.object({ kind: z.literal(OperationKind.DRIVE_LETTER_RESET), ...targetOperationSchema.shape }).strict(),
        volumeLabelRequestSchema,
        formatOperationSchema,
        z.object({ kind: z.literal(OperationKind.DRIVE_MODE_SET), ...targetOperationSchema.shape, mode: z.enum(['fixed', 'removable']) }).strict(),
        z.object({ kind: z.literal(OperationKind.SATA_MODE_SET), ...targetOperationSchema.shape, mode: z.enum(['1.5g-3g', '3g-6g']) }).strict(),
        z.object({ kind: z.literal(OperationKind.EJECT_SAFE), ...targetOperationSchema.shape }).strict(),
        z.object({ kind: z.literal(OperationKind.EJECT_FORCE), ...targetOperationSchema.shape, confirmationToken: confirmationTokenSchema }).strict()
    ])
    .refine((request) => request.kind !== OperationKind.FORMAT || request.filesystem.endsWith('-encrypted') === (request.passphrase !== undefined))

/**
 * Validates the only destructive confirmations the native service can issue.
 * Tokens and all host paths are deliberately absent from this request.
 */
export const operationConfirmationRequestSchema = z.discriminatedUnion('kind', [z.object({ kind: z.literal(OperationKind.FORMAT), ...targetOperationSchema.shape, filesystem: formatFilesystemSchema }).strict(), z.object({ kind: z.literal(OperationKind.EJECT_FORCE), ...targetOperationSchema.shape }).strict()])

const operationEventBaseSchema = z
    .object({
        operationId: operationIdSchema,
        kind: operationKindSchema,
        deviceId: deviceIdSchema,
        deviceRevision: deviceRevisionSchema
    })
    .strict()

const cancellationStateSchema = z.enum(['cancellable', 'requested', 'closed'])

const safeSenseSummarySchema = z
    .object({
        key: boundedReasonSchema,
        asc: z.number().int().min(0).max(255).optional(),
        ascq: z.number().int().min(0).max(255).optional(),
        messageKey: boundedMessageKeySchema
    })
    .strict()

const failureDispatchCertaintySchema = z.enum(['not-sent', 'definitely-rejected', 'completion-unknown'])

const operationFailureEvidenceSchema = z
    .object({
        stage: boundedReasonSchema,
        code: boundedReasonSchema,
        dispatchCertainty: failureDispatchCertaintySchema.optional(),
        senseSummary: safeSenseSummarySchema.optional()
    })
    .strict()

const operationAttemptEvidenceSchema = operationFailureEvidenceSchema
    .extend({
        attempt: z.literal(1),
        stage: z.enum(['firmware-writing', 'firmware-finalizing'])
    })
    .strict()

const operationFailureSchema = z
    .object({
        code: boundedReasonSchema,
        messageKey: boundedMessageKeySchema,
        stage: boundedReasonSchema,
        category: z.enum(['platform', 'transport']),
        retryable: z.boolean(),
        dispatchCertainty: failureDispatchCertaintySchema.optional(),
        senseSummary: safeSenseSummarySchema.optional(),
        supportCorrelationId: boundedIdentifierSchema.max(128),
        cleanupEvidence: z.array(operationFailureEvidenceSchema).max(16),
        attemptHistory: z.array(operationAttemptEvidenceSchema).max(1)
    })
    .strict()

/**
 * Validates an operation event before it reaches renderer state. Failed events
 * contain a complete safe error contract; non-failed events cannot carry one.
 */
export const operationEventSchema = z.discriminatedUnion('state', [
    operationEventBaseSchema
        .extend({
            state: z.literal('queued'),
            stage: boundedReasonSchema,
            messageKey: boundedMessageKeySchema.optional()
        })
        .strict(),
    operationEventBaseSchema
        .extend({
            state: z.literal('started'),
            stage: boundedReasonSchema,
            messageKey: boundedMessageKeySchema.optional()
        })
        .strict(),
    operationEventBaseSchema
        .extend({
            state: z.literal('progress'),
            stage: boundedReasonSchema,
            progress: z.number().min(0).max(1),
            attempt: z.number().int().min(1).max(2).optional(),
            cancellationState: cancellationStateSchema,
            messageKey: boundedMessageKeySchema.optional()
        })
        .strict(),
    operationEventBaseSchema
        .extend({
            state: z.literal('succeeded'),
            stage: boundedReasonSchema,
            messageKey: boundedMessageKeySchema.optional()
        })
        .strict(),
    operationEventBaseSchema
        .extend({
            state: z.literal('failed'),
            stage: boundedReasonSchema,
            error: operationFailureSchema
        })
        .strict(),
    operationEventBaseSchema
        .extend({
            state: z.literal('cancelled'),
            stage: boundedReasonSchema,
            reason: boundedReasonSchema.optional(),
            messageKey: boundedMessageKeySchema.optional()
        })
        .strict()
])

/** Strict payload for named bridge methods that accept no renderer data. */
export const emptyRequestSchema = z.object({}).strict()

/** Strict manual discovery request with no renderer-controlled parameters. */
export const scanRequestSchema = z.object({ kind: z.literal(OperationKind.SCAN) }).strict()

/** Strict opaque cancellation request; cancellation policy remains main-owned. */
export const operationCancelRequestSchema = z
    .object({
        operationId: operationIdSchema
    })
    .strict()

/** Exact operator acknowledgement for one of the two first-install power cycles. */
export const operationContinueRequestSchema = z.object({ operationId: operationIdSchema, stage: z.enum(['firmware-awaiting-bootloader', 'firmware-awaiting-bootstrap']) }).strict()

/** Strict export-destination request without a renderer-supplied filesystem path. */
export const exportDestinationRequestSchema = z
    .object({
        purpose: z.enum(['logs', 'support-summary'])
    })
    .strict()

/** Strict event-logging setting request. */
export const logSettingRequestSchema = z
    .object({
        enabled: z.boolean()
    })
    .strict()

/** Strict update-check intent; the renderer cannot supply a URL or version. */
export const updateCheckRequestSchema = z
    .object({
        silent: z.boolean()
    })
    .strict()

/** Renderer-safe persisted settings shared by get and update responses. */
export const settingsSchema = z
    .object({
        autoScan: z.boolean(),
        eventLogging: z.boolean(),
        language: z.enum(['en', 'zh', 'de', 'fr', 'it', 'pt', 'es', 'ja']),
        lastSafeView: z.enum(['status', 'encryption', 'tests', 'utilities']),
        updateChecks: z.boolean()
    })
    .strict()

/**
 * Checks that a settings update changes at least one published field.
 * @param {object} request - Strict partial settings request.
 * @returns {boolean} True when the request is non-empty.
 */
function hasAtLeastOneSetting(request) {
    return Object.keys(request).length > 0
}

/** Strict partial settings update; empty or unknown changes are rejected. */
export const settingsUpdateRequestSchema = settingsSchema.partial().refine(hasAtLeastOneSetting, 'At least one setting is required')

/** Reports only the renderer's bounded current device identity to main-owned tray policy. */
export const traySelectionRequestSchema = z
    .object({
        deviceId: deviceIdSchema.nullable()
    })
    .strict()

const discoveryEpochSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER)
const listRevisionSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
const serviceEventSchema = z.discriminatedUnion('status', [z.object({ type: z.literal('service'), status: z.enum(['starting', 'restarting', 'recovering', 'reconciling']) }).strict(), z.object({ type: z.literal('service'), status: z.literal('ready'), epoch: discoveryEpochSchema, listRevision: listRevisionSchema, mode: z.enum(['native', 'no-device']), privileged: z.boolean(), hardwareReady: z.boolean(), hardwareVerified: z.boolean(), platformCapability: platformCapabilitySchema }).strict(), z.object({ type: z.literal('service'), status: z.literal('unavailable'), reason: boundedReasonSchema }).strict()])

/** Renderer-safe service/discovery events; OS paths never cross this schema. */
export const deviceEventSchema = z.union([serviceEventSchema, z.object({ type: z.literal('snapshot'), epoch: discoveryEpochSchema, listRevision: listRevisionSchema, device: deviceSnapshotSchema }).strict(), z.object({ type: z.literal('removed'), epoch: discoveryEpochSchema, listRevision: listRevisionSchema, deviceId: deviceIdSchema, deviceRevision: deviceRevisionSchema }).strict(), z.object({ type: z.literal('list'), epoch: discoveryEpochSchema, listRevision: listRevisionSchema, devices: z.array(deviceSnapshotSchema).max(128), diagnostics: discoveryDiagnosticsSchema.optional() }).strict()])

const bridgeFailureSchema = z
    .object({
        ok: z.literal(false),
        reason: boundedReasonSchema
    })
    .strict()

/** Safe result for application-owned actions without renderer payload data. */
export const actionResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true) }).strict(), bridgeFailureSchema])

/** Closed renderer-safe setup states for the packaged macOS launch daemon. */
export const privilegedServiceSetupStateSchema = z.enum(['not-applicable', 'not-registered', 'enabled', 'requires-approval', 'not-found', 'invalid-signature', 'registration-failed'])

/** Safe current privileged-service setup result without native error details. */
export const privilegedServiceSetupResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), state: privilegedServiceSetupStateSchema, reason: boundedReasonSchema.optional() }).strict(), bridgeFailureSchema])

/** Strict response carrying only a service-issued opaque one-shot token. */
export const operationConfirmationResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), confirmationToken: confirmationTokenSchema }).strict(), bridgeFailureSchema])

/** Safe result for a newly accepted high-level operation. */
export const operationStartResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), operationId: operationIdSchema }).strict(), bridgeFailureSchema])

/** Safe application metadata response. */
export const appInfoResponseSchema = z.discriminatedUnion('ok', [
    z
        .object({
            ok: z.literal(true),
            app: z
                .object({
                    name: boundedDisplayTextSchema,
                    version: z.string().trim().min(1).max(64),
                    platform: z.enum(['darwin', 'win32', 'linux'])
                })
                .strict()
        })
        .strict(),
    bridgeFailureSchema
])

/** Safe discovered-device list response. */
export const deviceListResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), status: z.literal('ready'), mode: z.enum(['native', 'no-device']), privileged: z.boolean(), hardwareReady: z.boolean(), hardwareVerified: z.boolean(), platformCapability: platformCapabilitySchema, epoch: discoveryEpochSchema, listRevision: listRevisionSchema, devices: z.array(deviceSnapshotSchema).max(128), diagnostics: discoveryDiagnosticsSchema.optional() }).strict(), bridgeFailureSchema])

/** Opaque file selection result; renderer code never receives a path. */
export const fileTokenResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), fileToken: boundedIdentifierSchema.max(64) }).strict(), bridgeFailureSchema])

const activityEntrySchema = z
    .object({
        id: boundedIdentifierSchema.max(64),
        occurredAt: z.string().datetime({ offset: true }),
        severity: z.enum(['info', 'warning', 'error']),
        messageKey: boundedMessageKeySchema,
        supportCorrelationId: boundedIdentifierSchema.max(128).optional()
    })
    .strict()

/** Redacted, bounded event-log response. */
export const logListResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), entries: z.array(activityEntrySchema).max(500) }).strict(), bridgeFailureSchema])

const savedPathSchema = z
    .string()
    .trim()
    .min(1)
    .max(1024)
    .refine((value) => !/[\u0000-\u001f\u007f-\u009f]/.test(value), 'Saved path contains control characters')

/** Main-selected local export destination returned only after a successful save. */
export const localExportResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), savedPath: savedPathSchema }).strict(), bridgeFailureSchema])

/** Safe settings response returned after reads and accepted updates. */
export const settingsResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), settings: settingsSchema }).strict(), bridgeFailureSchema])

/** Saved support-summary result with the user-selected display path. */
export const supportSummaryResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), savedPath: savedPathSchema, deviceCount: z.number().int().nonnegative().max(128) }).strict(), bridgeFailureSchema])

const versionSchema = z.string().trim().min(1).max(64)
const managerUpdateSchema = z.discriminatedUnion('status', [z.object({ status: z.literal('current'), currentVersion: versionSchema }).strict(), z.object({ status: z.literal('available'), currentVersion: versionSchema, availableVersion: versionSchema }).strict()])
const firmwareUpdateEntrySchema = z.object({ product: boundedDisplayTextSchema, currentRevision: versionSchema, availableRevision: versionSchema }).strict()

/** @param {{status: string, updates: object[]}} result - Parsed firmware availability. @returns {boolean} True when status agrees with update count. */
function firmwareAvailabilityIsConsistent(result) {
    return (result.status === 'available') === result.updates.length > 0
}

const firmwareUpdateSchema = z
    .object({ status: z.enum(['current', 'available', 'not-applicable']), updates: z.array(firmwareUpdateEntrySchema).max(128) })
    .strict()
    .refine(firmwareAvailabilityIsConsistent, 'Firmware availability must match update count')

/** Bounded, read-only update availability separated by Manager and firmware. */
export const updateCheckResponseSchema = z.discriminatedUnion('ok', [z.object({ ok: z.literal(true), silent: z.boolean(), manager: managerUpdateSchema, firmware: firmwareUpdateSchema }).strict(), bridgeFailureSchema])

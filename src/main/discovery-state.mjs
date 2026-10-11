// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Owns one service-generation discovery baseline with monotonic list revisions
 * and per-device tombstones.
 */
export class DiscoveryState {
    #devices = new Map()
    #epoch = 0
    #listRevision = -1
    #tombstones = new Map()

    /**
     * Starts one fresh main-owned generation epoch.
     * @param {number} epoch - Positive monotonic service epoch.
     * @returns {void} Completes after clearing the prior baseline.
     */
    reset(epoch) {
        this.#epoch = epoch
        this.#listRevision = -1
        this.#devices.clear()
        this.#tombstones.clear()
    }

    /** @returns {number} Current main-owned epoch. */
    getEpoch() {
        return this.#epoch
    }

    /** @returns {number} Last accepted service list revision. */
    getListRevision() {
        return this.#listRevision
    }

    /** @param {string} deviceId - Opaque device ID. @returns {object|null} Current snapshot. */
    getDevice(deviceId) {
        return this.#devices.get(deviceId) ?? null
    }

    /** @returns {object[]} Current devices in stable insertion order. */
    getDevices() {
        return [...this.#devices.values()]
    }

    /**
     * Applies one complete list only when its global and per-device revisions advance.
     * @param {number} listRevision - Service-owned global discovery revision.
     * @param {object[]} devices - Complete strict device list.
     * @param {object} [diagnostics] - Optional strict candidate accounting.
     * @returns {object|null} Versioned public event or null when stale.
     */
    applyList(listRevision, devices, diagnostics = undefined) {
        if (!this.#canAdvance(listRevision)) {
            return null
        }
        const incoming = new Map()
        for (const device of devices) {
            const current = this.#devices.get(device.id)
            const tombstoneRevision = this.#tombstones.get(device.id)
            if ((current !== undefined && device.revision < current.revision) || (tombstoneRevision !== undefined && device.revision <= tombstoneRevision)) {
                return null
            }
            incoming.set(device.id, device)
        }
        for (const [deviceId, current] of this.#devices) {
            if (!incoming.has(deviceId)) {
                this.#recordTombstone(deviceId, current.revision)
            }
        }
        this.#devices = incoming
        this.#listRevision = listRevision
        return { type: 'list', epoch: this.#epoch, listRevision, devices: this.getDevices(), ...(diagnostics === undefined ? {} : { diagnostics }) }
    }

    /**
     * Applies one device snapshot only after the global revision advances.
     * @param {number} listRevision - Service-owned global discovery revision.
     * @param {object} device - Strict device snapshot.
     * @returns {object|null} Versioned public event or null when stale.
     */
    applySnapshot(listRevision, device) {
        const current = this.#devices.get(device.id)
        const tombstoneRevision = this.#tombstones.get(device.id)
        if (!this.#canAdvance(listRevision) || (current !== undefined && device.revision < current.revision) || (tombstoneRevision !== undefined && device.revision <= tombstoneRevision)) {
            return null
        }
        this.#devices.set(device.id, device)
        this.#listRevision = listRevision
        return { type: 'snapshot', epoch: this.#epoch, listRevision, device }
    }

    /**
     * Applies one removal and records its revision tombstone.
     * @param {number} listRevision - Service-owned global discovery revision.
     * @param {string} deviceId - Removed opaque device ID.
     * @param {number} deviceRevision - Removed identity revision.
     * @returns {object|null} Versioned public event or null when stale.
     */
    applyRemoval(listRevision, deviceId, deviceRevision) {
        const current = this.#devices.get(deviceId)
        const tombstoneRevision = this.#tombstones.get(deviceId)
        if (!this.#canAdvance(listRevision) || (current !== undefined && deviceRevision < current.revision) || (tombstoneRevision !== undefined && deviceRevision < tombstoneRevision)) {
            return null
        }
        this.#recordTombstone(deviceId, deviceRevision)
        this.#devices.delete(deviceId)
        this.#listRevision = listRevision
        return { type: 'removed', epoch: this.#epoch, listRevision, deviceId, deviceRevision }
    }

    /** @param {number} revision - Candidate global revision. @returns {boolean} True when strictly newer. */
    #canAdvance(revision) {
        return Number.isSafeInteger(revision) && revision >= 0 && revision > this.#listRevision
    }

    /**
     * Records the greatest known removed identity revision.
     * @param {string} deviceId - Opaque device ID.
     * @param {number} revision - Removed identity revision.
     * @returns {void} Completes after monotonic update.
     */
    #recordTombstone(deviceId, revision) {
        const current = this.#tombstones.get(deviceId) ?? -1
        this.#tombstones.set(deviceId, Math.max(current, revision))
    }
}

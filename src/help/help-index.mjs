// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Immutable local help content curated from the numbered feature evidence.
 * Historical network locations are intentionally plain text, never live links.
 */
export const HELP_TOPICS = Object.freeze([
    Object.freeze({
        id: 'getting-started',
        icon: 'ph-hard-drives',
        source: '01-drive-discovery-and-auto-scan.md',
        titleKey: 'help.topic.gettingStarted.title',
        summaryKey: 'help.topic.gettingStarted.summary',
        paragraphKeys: Object.freeze(['help.topic.gettingStarted.paragraph1', 'help.topic.gettingStarted.paragraph2'])
    }),
    Object.freeze({
        id: 'activity',
        icon: 'ph-clock-counter-clockwise',
        source: '03-event-logging.md',
        titleKey: 'help.topic.activity.title',
        summaryKey: 'help.topic.activity.summary',
        paragraphKeys: Object.freeze(['help.topic.activity.paragraph1', 'help.topic.activity.paragraph2'])
    }),
    Object.freeze({
        id: 'system-summary',
        icon: 'ph-file-text',
        source: '04-system-summary.md',
        titleKey: 'help.topic.systemSummary.title',
        summaryKey: 'help.topic.systemSummary.summary',
        paragraphKeys: Object.freeze(['help.topic.systemSummary.paragraph1', 'help.topic.systemSummary.paragraph2'])
    }),
    Object.freeze({
        id: 'updates',
        icon: 'ph-arrows-clockwise',
        source: '05-help-and-update-checking.md',
        titleKey: 'help.topic.updates.title',
        summaryKey: 'help.topic.updates.summary',
        paragraphKeys: Object.freeze(['help.topic.updates.paragraph1', 'help.topic.updates.paragraph2', 'help.topic.updates.paragraph3'])
    }),
    Object.freeze({
        id: 'troubleshooting',
        icon: 'ph-lifebuoy',
        source: '25-support-troubleshooting-and-known-limitations.md',
        titleKey: 'help.topic.troubleshooting.title',
        summaryKey: 'help.topic.troubleshooting.summary',
        paragraphKeys: Object.freeze(['help.topic.troubleshooting.paragraph1', 'help.topic.troubleshooting.paragraph2', 'help.topic.troubleshooting.paragraph3', 'help.topic.troubleshooting.paragraph4', 'help.topic.troubleshooting.paragraph5']),
        contactKeys: Object.freeze(['help.contact.emea', 'help.contact.apac', 'help.contact.americas'])
    })
])

/**
 * Resolves one bundled topic without accepting a path or network location.
 * @param {unknown} topicId - Candidate local topic identifier.
 * @returns {object|null} Frozen local topic or null.
 */
export function findHelpTopic(topicId) {
    for (const topic of HELP_TOPICS) {
        if (topic.id === topicId) return topic
    }
    return null
}

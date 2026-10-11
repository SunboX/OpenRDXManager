// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** German manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': 'Ich verstehe, dass die aktuelle Identität des Docks durch die Seriennummer {serial} aus der ausgewählten Originalsicherung ersetzt wird.',
    'manufacturing.openFolder': 'Sicherungsordner öffnen',
    'manufacturing.openingFolder': 'Ordner wird geöffnet…',
    'manufacturing.folderDescription': 'Öffnet den Ordner, in dem Sicherungen der Fertigungsdaten gespeichert werden.',
    'manufacturing.error.openFolder': 'Der Sicherungsordner konnte nicht im Dateimanager geöffnet werden.',

    'manufacturing.page': 'Seite {page}',
    'manufacturing.next': 'Ältere Sicherungen',
    'manufacturing.previous': 'Vorherige Sicherungen',
    'manufacturing.eyebrow': 'Private Gerätesicherung',
    'manufacturing.title': 'Fertigungsdaten',
    'manufacturing.description': 'Speichern Sie eine geprüfte private Kopie des Werksdatensatzes der ausgewählten Dockingstation.',
    'manufacturing.automaticBackup': 'Vor jedem Firmware-Update wird eine geprüfte private Sicherung gespeichert. Schlägt die Sicherung fehl, wird das Update gestoppt.',
    'manufacturing.backup': 'Fertigungsdaten sichern',
    'manufacturing.restore': 'Fertigungsdaten wiederherstellen',
    'manufacturing.refresh': 'Gespeicherte Sicherungen aktualisieren',
    'manufacturing.pending': 'Vorgang läuft…',
    'manufacturing.loading': 'Gespeicherte Sicherungen werden geladen…',
    'manufacturing.removeMedia': 'Entfernen Sie die Kassette, bevor Sie Fertigungsdaten sichern oder wiederherstellen.',
    'manufacturing.restoreDescription': 'Die Wiederherstellung überschreibt nur den Werksdatensatz und erhält benachbarte Daten. Zuvor wird eine private Sicherung des aktuellen Zustands gespeichert. Schalten Sie die Dockingstation nach geprüftem Erfolg manuell aus und wieder ein.',
    'manufacturing.savedBackups': 'Gespeicherte Sicherungen · 128 pro Seite',
    'manufacturing.choose': 'Sicherung ausdrücklich auswählen',
    'manufacturing.empty': 'Es sind keine gespeicherten Sicherungen der Fertigungsdaten verfügbar.',
    'manufacturing.backupLabel': '{date} · Seriennummer {serial} · {state}',
    'manufacturing.serialUnavailable': 'nicht verfügbar',
    'manufacturing.state.valid': 'Gültiger Datensatz',
    'manufacturing.state.erased': 'Gelöschter Datensatz · nur als Nachweis',
    'manufacturing.state.corrupt': 'Beschädigter Datensatz · nur als Nachweis',
    'manufacturing.confirmSerial': 'Ursprüngliche Seriennummer aus der ausgewählten Sicherung eingeben',
    'manufacturing.target': 'Ziel der Wiederherstellung: {product} · {serial}',
    'manufacturing.acknowledge': 'Ich habe diese Dockingstation physisch identifiziert und bestätige, dass die ausgewählte Sicherung zu ihr gehört.',
    'manufacturing.backupSucceeded': 'Die Fertigungsdaten wurden gesichert und geprüft.',
    'manufacturing.restoreSucceeded': 'Die Fertigungsdaten wurden wiederhergestellt und geprüft. Schalten Sie die Dockingstation vor dem Fortfahren manuell aus und wieder ein.',
    'manufacturing.error.restoreUnsupported': 'Die aktuelle Firmware dieser Dockingstation unterstützt die Wiederherstellung von Fertigungsdaten nicht.',
    'manufacturing.error.unavailable': 'Die Sicherung von Fertigungsdaten erfordert eine unterstützte OpenRDX-Dockingstation mit leerem Kassettenfach.',
    'manufacturing.error.uncertain': 'Das Ergebnis ist nicht bestätigt. Aktionen bleiben gesperrt. Aktualisieren Sie die gespeicherten Sicherungen zum Abgleich mit dem Dienststatus; wiederholen Sie den Schreibvorgang nicht.',
    'manufacturing.error.failed': 'Der Vorgang für die Fertigungsdaten konnte nicht abgeschlossen werden. Aktualisieren Sie die gespeicherten Sicherungen und prüfen Sie die Dockingstation vor dem Fortfahren.',
    'reason.firmwareManufacturingRestoreUnsupported': 'die aktuelle Firmware der Dockingstation unterstützt die Wiederherstellung von Fertigungsdaten nicht'
})

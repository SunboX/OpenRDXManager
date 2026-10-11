// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** English manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': 'I understand this replaces the dock’s current identity with serial {serial} from the selected original backup.',
    'manufacturing.openFolder': 'Open backup folder',
    'manufacturing.openingFolder': 'Opening folder…',
    'manufacturing.folderDescription': 'Opens the folder where manufacturing backups are saved.',
    'manufacturing.error.openFolder': 'Could not open the backup folder in the system file manager.',

    'manufacturing.page': 'Page {page}',
    'manufacturing.next': 'Older backups',
    'manufacturing.previous': 'Previous backups',
    'manufacturing.eyebrow': 'Private device backup',
    'manufacturing.title': 'Manufacturing data',
    'manufacturing.description': 'Save a verified private copy of the selected dock’s factory record.',
    'manufacturing.automaticBackup': 'Every firmware update saves a verified private backup first. If the backup fails, the update stops.',
    'manufacturing.backup': 'Backup manufacturing data',
    'manufacturing.restore': 'Restore manufacturing data',
    'manufacturing.refresh': 'Refresh saved backups',
    'manufacturing.pending': 'Working…',
    'manufacturing.loading': 'Loading saved backups…',
    'manufacturing.removeMedia': 'Remove the cartridge before backing up or restoring manufacturing data.',
    'manufacturing.restoreDescription': 'Restore overwrites only the factory record and preserves neighboring data. A private snapshot is saved before restoring. After verified success, manually power the dock off and on.',
    'manufacturing.savedBackups': 'Saved backups · 128 per page',
    'manufacturing.choose': 'Choose a backup explicitly',
    'manufacturing.empty': 'No saved manufacturing backups are available.',
    'manufacturing.backupLabel': '{date} · Serial {serial} · {state}',
    'manufacturing.serialUnavailable': 'unavailable',
    'manufacturing.state.valid': 'Valid record',
    'manufacturing.state.erased': 'Erased record · evidence only',
    'manufacturing.state.corrupt': 'Corrupt record · evidence only',
    'manufacturing.confirmSerial': 'Type the original serial shown in the selected backup',
    'manufacturing.target': 'Restore target: {product} · {serial}',
    'manufacturing.acknowledge': 'I have physically identified this dock and confirm that the selected backup belongs to it.',
    'manufacturing.backupSucceeded': 'Manufacturing data was backed up and verified.',
    'manufacturing.restoreSucceeded': 'Manufacturing data was restored and verified. Manually power the dock off and on before continuing.',
    'manufacturing.error.restoreUnsupported': 'This dock’s current firmware does not support manufacturing-data restore.',
    'manufacturing.error.unavailable': 'Manufacturing backup requires a supported OpenRDX dock with an empty cartridge bay.',
    'manufacturing.error.uncertain': 'The operation result is not confirmed. Actions remain locked. Refresh saved backups to reconcile the service state; do not repeat the write.',
    'manufacturing.error.failed': 'The manufacturing operation could not be completed. Refresh saved backups and check the dock before continuing.',
    'reason.firmwareManufacturingRestoreUnsupported': 'the current dock firmware does not support manufacturing-data restore'
})

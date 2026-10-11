// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** French manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': 'Je comprends que cette opération remplace l’identité actuelle du dock par le numéro de série {serial} de la sauvegarde d’origine sélectionnée.',
    'manufacturing.openFolder': 'Ouvrir le dossier des sauvegardes',
    'manufacturing.openingFolder': 'Ouverture du dossier…',
    'manufacturing.folderDescription': 'Ouvre le dossier où sont enregistrées les sauvegardes des données de fabrication.',
    'manufacturing.error.openFolder': 'Impossible d’ouvrir le dossier des sauvegardes dans le gestionnaire de fichiers.',

    'manufacturing.page': 'Page n° {page}',
    'manufacturing.next': 'Sauvegardes plus anciennes',
    'manufacturing.previous': 'Sauvegardes précédentes',
    'manufacturing.eyebrow': 'Sauvegarde privée de l’appareil',
    'manufacturing.title': 'Données de fabrication',
    'manufacturing.description': 'Enregistrez une copie privée vérifiée des données d’usine de la station sélectionnée.',
    'manufacturing.automaticBackup': 'Chaque mise à jour du firmware enregistre d’abord une sauvegarde privée vérifiée. Si la sauvegarde échoue, la mise à jour s’arrête.',
    'manufacturing.backup': 'Sauvegarder les données de fabrication',
    'manufacturing.restore': 'Restaurer les données de fabrication',
    'manufacturing.refresh': 'Actualiser les sauvegardes',
    'manufacturing.pending': 'Opération en cours…',
    'manufacturing.loading': 'Chargement des sauvegardes…',
    'manufacturing.removeMedia': 'Retirez la cartouche avant de sauvegarder ou de restaurer les données de fabrication.',
    'manufacturing.restoreDescription': 'La restauration remplace uniquement les données d’usine et préserve les données voisines. Une copie privée de l’état actuel est enregistrée au préalable. Après vérification du succès, éteignez puis rallumez manuellement la station.',
    'manufacturing.savedBackups': 'Sauvegardes enregistrées · 128 par page',
    'manufacturing.choose': 'Choisir explicitement une sauvegarde',
    'manufacturing.empty': 'Aucune sauvegarde des données de fabrication n’est disponible.',
    'manufacturing.backupLabel': '{date} · Numéro de série {serial} · {state}',
    'manufacturing.serialUnavailable': 'indisponible',
    'manufacturing.state.valid': 'Données valides',
    'manufacturing.state.erased': 'Données effacées · preuve uniquement',
    'manufacturing.state.corrupt': 'Données corrompues · preuve uniquement',
    'manufacturing.confirmSerial': 'Saisir le numéro de série d’origine indiqué dans la sauvegarde choisie',
    'manufacturing.target': 'Cible de la restauration : {product} · {serial}',
    'manufacturing.acknowledge': 'J’ai identifié physiquement cette station et je confirme que la sauvegarde choisie lui appartient.',
    'manufacturing.backupSucceeded': 'Les données de fabrication ont été sauvegardées et vérifiées.',
    'manufacturing.restoreSucceeded': 'Les données de fabrication ont été restaurées et vérifiées. Éteignez puis rallumez manuellement la station avant de continuer.',
    'manufacturing.error.restoreUnsupported': 'Le firmware actuel de cette station ne permet pas de restaurer les données de fabrication.',
    'manufacturing.error.unavailable': 'La sauvegarde des données de fabrication nécessite une station OpenRDX compatible dont la baie de cartouche est vide.',
    'manufacturing.error.uncertain': 'Le résultat de l’opération n’est pas confirmé. Les actions restent verrouillées. Actualisez les sauvegardes pour vérifier l’état du service ; ne répétez pas l’écriture.',
    'manufacturing.error.failed': 'L’opération sur les données de fabrication n’a pas pu aboutir. Actualisez les sauvegardes et vérifiez la station avant de continuer.',
    'reason.firmwareManufacturingRestoreUnsupported': 'le firmware actuel de la station ne permet pas de restaurer les données de fabrication'
})

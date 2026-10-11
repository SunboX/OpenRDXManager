// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Italian manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': 'Comprendo che questa operazione sostituisce l’identità attuale del dock con il numero di serie {serial} del backup originale selezionato.',
    'manufacturing.openFolder': 'Apri cartella dei backup',
    'manufacturing.openingFolder': 'Apertura della cartella…',
    'manufacturing.folderDescription': 'Apre la cartella in cui vengono salvati i backup dei dati di fabbricazione.',
    'manufacturing.error.openFolder': 'Impossibile aprire la cartella dei backup nel gestore di file.',

    'manufacturing.page': 'Pagina {page}',
    'manufacturing.next': 'Backup più vecchi',
    'manufacturing.previous': 'Backup precedenti',
    'manufacturing.eyebrow': 'Backup privato del dispositivo',
    'manufacturing.title': 'Dati di produzione',
    'manufacturing.description': 'Salva una copia privata verificata del record di fabbrica del dock selezionato.',
    'manufacturing.automaticBackup': 'Ogni aggiornamento del firmware salva prima un backup privato verificato. Se il backup non riesce, l’aggiornamento si interrompe.',
    'manufacturing.backup': 'Salva i dati di produzione',
    'manufacturing.restore': 'Ripristina i dati di produzione',
    'manufacturing.refresh': 'Aggiorna i backup salvati',
    'manufacturing.pending': 'Operazione in corso…',
    'manufacturing.loading': 'Caricamento dei backup salvati…',
    'manufacturing.removeMedia': 'Rimuovi la cartuccia prima di salvare o ripristinare i dati di produzione.',
    'manufacturing.restoreDescription': 'Il ripristino sovrascrive solo il record di fabbrica e conserva i dati adiacenti. Prima viene salvata una copia privata dello stato attuale. Dopo aver verificato il successo, spegni e riaccendi manualmente il dock.',
    'manufacturing.savedBackups': 'Backup salvati · 128 per pagina',
    'manufacturing.choose': 'Scegli esplicitamente un backup',
    'manufacturing.empty': 'Non sono disponibili backup salvati dei dati di produzione.',
    'manufacturing.backupLabel': '{date} · Numero di serie {serial} · {state}',
    'manufacturing.serialUnavailable': 'non disponibile',
    'manufacturing.state.valid': 'Record valido',
    'manufacturing.state.erased': 'Record cancellato · solo come evidenza',
    'manufacturing.state.corrupt': 'Record danneggiato · solo come evidenza',
    'manufacturing.confirmSerial': 'Digita il numero di serie originale riportato nel backup selezionato',
    'manufacturing.target': 'Destinazione del ripristino: {product} · {serial}',
    'manufacturing.acknowledge': 'Ho identificato fisicamente questo dock e confermo che il backup selezionato gli appartiene.',
    'manufacturing.backupSucceeded': 'I dati di produzione sono stati salvati e verificati.',
    'manufacturing.restoreSucceeded': 'I dati di produzione sono stati ripristinati e verificati. Spegni e riaccendi manualmente il dock prima di continuare.',
    'manufacturing.error.restoreUnsupported': 'Il firmware attuale di questo dock non supporta il ripristino dei dati di produzione.',
    'manufacturing.error.unavailable': 'Il backup dei dati di produzione richiede un dock OpenRDX supportato con il vano cartuccia vuoto.',
    'manufacturing.error.uncertain': 'Il risultato dell’operazione non è confermato. Le azioni restano bloccate. Aggiorna i backup salvati per verificare lo stato del servizio; non ripetere la scrittura.',
    'manufacturing.error.failed': 'Non è stato possibile completare l’operazione sui dati di produzione. Aggiorna i backup salvati e controlla il dock prima di continuare.',
    'reason.firmwareManufacturingRestoreUnsupported': 'il firmware attuale del dock non supporta il ripristino dei dati di produzione'
})

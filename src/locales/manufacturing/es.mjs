// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Spanish manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': 'Entiendo que esto sustituye la identidad actual de la base por el número de serie {serial} de la copia original seleccionada.',
    'manufacturing.openFolder': 'Abrir carpeta de copias',
    'manufacturing.openingFolder': 'Abriendo carpeta…',
    'manufacturing.folderDescription': 'Abre la carpeta donde se guardan las copias de los datos de fabricación.',
    'manufacturing.error.openFolder': 'No se pudo abrir la carpeta de copias en el administrador de archivos.',

    'manufacturing.page': 'Página {page}',
    'manufacturing.next': 'Copias más antiguas',
    'manufacturing.previous': 'Copias anteriores',
    'manufacturing.eyebrow': 'Copia privada del dispositivo',
    'manufacturing.title': 'Datos de fabricación',
    'manufacturing.description': 'Guarde una copia privada verificada del registro de fábrica de la base seleccionada.',
    'manufacturing.automaticBackup': 'Cada actualización de firmware guarda primero una copia privada verificada. Si la copia falla, la actualización se detiene.',
    'manufacturing.backup': 'Respaldar datos de fabricación',
    'manufacturing.restore': 'Restaurar datos de fabricación',
    'manufacturing.refresh': 'Actualizar copias guardadas',
    'manufacturing.pending': 'Operación en curso…',
    'manufacturing.loading': 'Cargando copias guardadas…',
    'manufacturing.removeMedia': 'Retire el cartucho antes de respaldar o restaurar los datos de fabricación.',
    'manufacturing.restoreDescription': 'La restauración sobrescribe solo el registro de fábrica y conserva los datos adyacentes. Antes se guarda una copia privada del estado actual. Tras verificar el éxito, apague y encienda la base manualmente.',
    'manufacturing.savedBackups': 'Copias guardadas · 128 por página',
    'manufacturing.choose': 'Seleccione una copia explícitamente',
    'manufacturing.empty': 'No hay copias guardadas de los datos de fabricación.',
    'manufacturing.backupLabel': '{date} · Número de serie {serial} · {state}',
    'manufacturing.serialUnavailable': 'no disponible',
    'manufacturing.state.valid': 'Registro válido',
    'manufacturing.state.erased': 'Registro borrado · solo evidencia',
    'manufacturing.state.corrupt': 'Registro dañado · solo evidencia',
    'manufacturing.confirmSerial': 'Escriba el número de serie original de la copia seleccionada',
    'manufacturing.target': 'Destino de la restauración: {product} · {serial}',
    'manufacturing.acknowledge': 'He identificado físicamente esta base y confirmo que la copia seleccionada le pertenece.',
    'manufacturing.backupSucceeded': 'Se guardó y verificó la copia de los datos de fabricación.',
    'manufacturing.restoreSucceeded': 'Los datos de fabricación se restauraron y verificaron. Apague y encienda la base manualmente antes de continuar.',
    'manufacturing.error.restoreUnsupported': 'El firmware actual de esta base no admite restaurar los datos de fabricación.',
    'manufacturing.error.unavailable': 'La copia de los datos de fabricación requiere una base OpenRDX compatible con la bahía del cartucho vacía.',
    'manufacturing.error.uncertain': 'El resultado de la operación no está confirmado. Las acciones siguen bloqueadas. Actualice las copias guardadas para comprobar el estado del servicio; no repita la escritura.',
    'manufacturing.error.failed': 'No se pudo completar la operación de datos de fabricación. Actualice las copias guardadas y compruebe la base antes de continuar.',
    'reason.firmwareManufacturingRestoreUnsupported': 'el firmware actual de la base no admite restaurar los datos de fabricación'
})

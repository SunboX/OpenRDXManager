// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Portuguese manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': 'Compreendo que isto substitui a identidade atual da base pelo número de série {serial} da cópia de segurança original selecionada.',
    'manufacturing.openFolder': 'Abrir pasta de backups',
    'manufacturing.openingFolder': 'Abrindo pasta…',
    'manufacturing.folderDescription': 'Abre a pasta onde são salvos os backups dos dados de fabricação.',
    'manufacturing.error.openFolder': 'Não foi possível abrir a pasta de backups no gerenciador de arquivos.',

    'manufacturing.page': 'Página nº {page}',
    'manufacturing.next': 'Cópias mais antigas',
    'manufacturing.previous': 'Cópias anteriores',
    'manufacturing.eyebrow': 'Cópia privada do dispositivo',
    'manufacturing.title': 'Dados de fabricação',
    'manufacturing.description': 'Salve uma cópia privada verificada do registro de fábrica da base selecionada.',
    'manufacturing.automaticBackup': 'Cada atualização de firmware salva primeiro uma cópia privada verificada. Se a cópia falhar, a atualização é interrompida.',
    'manufacturing.backup': 'Salvar dados de fabricação',
    'manufacturing.restore': 'Restaurar dados de fabricação',
    'manufacturing.refresh': 'Atualizar cópias salvas',
    'manufacturing.pending': 'Operação em andamento…',
    'manufacturing.loading': 'Carregando cópias salvas…',
    'manufacturing.removeMedia': 'Remova o cartucho antes de salvar ou restaurar os dados de fabricação.',
    'manufacturing.restoreDescription': 'A restauração sobrescreve apenas o registro de fábrica e preserva os dados vizinhos. Uma cópia privada do estado atual é salva antes. Após a confirmação do sucesso, desligue e ligue a base manualmente.',
    'manufacturing.savedBackups': 'Cópias salvas · 128 por página',
    'manufacturing.choose': 'Escolha uma cópia explicitamente',
    'manufacturing.empty': 'Não há cópias salvas dos dados de fabricação disponíveis.',
    'manufacturing.backupLabel': '{date} · Número de série {serial} · {state}',
    'manufacturing.serialUnavailable': 'indisponível',
    'manufacturing.state.valid': 'Registro válido',
    'manufacturing.state.erased': 'Registro apagado · apenas evidência',
    'manufacturing.state.corrupt': 'Registro corrompido · apenas evidência',
    'manufacturing.confirmSerial': 'Digite o número de série original mostrado na cópia selecionada',
    'manufacturing.target': 'Destino da restauração: {product} · {serial}',
    'manufacturing.acknowledge': 'Identifiquei fisicamente esta base e confirmo que a cópia selecionada pertence a ela.',
    'manufacturing.backupSucceeded': 'Os dados de fabricação foram salvos e verificados.',
    'manufacturing.restoreSucceeded': 'Os dados de fabricação foram restaurados e verificados. Desligue e ligue a base manualmente antes de continuar.',
    'manufacturing.error.restoreUnsupported': 'O firmware atual desta base não permite restaurar os dados de fabricação.',
    'manufacturing.error.unavailable': 'A cópia dos dados de fabricação requer uma base OpenRDX compatível com o compartimento do cartucho vazio.',
    'manufacturing.error.uncertain': 'O resultado da operação não está confirmado. As ações permanecem bloqueadas. Atualize as cópias salvas para verificar o estado do serviço; não repita a gravação.',
    'manufacturing.error.failed': 'Não foi possível concluir a operação dos dados de fabricação. Atualize as cópias salvas e verifique a base antes de continuar.',
    'reason.firmwareManufacturingRestoreUnsupported': 'o firmware atual da base não permite restaurar os dados de fabricação'
})

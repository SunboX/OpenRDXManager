// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { germanCatalog } from '../src/locales/de.mjs'
import { englishCatalog } from '../src/locales/en.mjs'
import { spanishCatalog } from '../src/locales/es.mjs'
import { frenchCatalog } from '../src/locales/fr.mjs'
import { italianCatalog } from '../src/locales/it.mjs'
import { japaneseCatalog } from '../src/locales/ja.mjs'
import { portugueseCatalog } from '../src/locales/pt.mjs'
import { chineseCatalog } from '../src/locales/zh.mjs'
import { SettingsService, resolveStartupLanguage } from '../src/main/settings-service.mjs'

const catalogs = Object.freeze([
    ['zh', chineseCatalog],
    ['de', germanCatalog],
    ['fr', frenchCatalog],
    ['it', italianCatalog],
    ['pt', portugueseCatalog],
    ['es', spanishCatalog],
    ['ja', japaneseCatalog]
])
// Filesystem and product names remain invariant across localized host menus.
const intentionallyInvariantKeys = new Set([
    'utilities.format.filesystem.ext2',
    'utilities.format.filesystem.ext3',
    'utilities.format.filesystem.ext4',
    'utilities.format.filesystem.xfs',
    'utilities.format.filesystem.btrfs',
    'utilities.format.filesystem.f2fs',
    'utilities.format.filesystem.ntfs.linux',
    'utilities.format.filesystem.fat',
    'utilities.format.filesystem.fat12',
    'utilities.format.filesystem.fat16',
    'utilities.format.filesystem.fat32',
    'utilities.format.filesystem.apfs',
    'utilities.format.filesystem.hfs',
    'utilities.format.filesystem.hfs-journaled',
    'activity.filter.error',
    'activity.filter.info',
    'activity.filter.label',
    'app.brand.open',
    'app.brand.rdx',
    'areas.status',
    'areas.tests',
    'compatibility.fact.firmware',
    'help.about.appFallback',
    'help.about.versionPlatform',
    'help.contact.apac',
    'help.contact.emea',
    'operation.progressAnnouncement',
    'operation.progressAnnouncementStage',
    'status.status',
    'update.result'
])

/** @param {string} message - Catalog message. @returns {string[]} Sorted placeholder names. */
function placeholders(message) {
    return [...message.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)].map((match) => match[1]).sort()
}

/** @returns {void} Verifies complete catalogs cannot silently fall back to English. */
function testCatalogParityAndPlaceholders() {
    const englishKeys = Object.keys(englishCatalog).sort()
    for (const [code, catalog] of catalogs) {
        assert.deepEqual(Object.keys(catalog).sort(), englishKeys, `${code} catalog keys`)
        for (const key of englishKeys) {
            assert.equal(typeof catalog[key], 'string', `${code}:${key} must be a string`)
            assert.deepEqual(placeholders(catalog[key]), placeholders(englishCatalog[key]), `${code}:${key} placeholders`)
        }
    }
}

/** @returns {void} Verifies each catalog contains natural localized navigation and status copy. */
function testRepresentativeTranslations() {
    assert.equal(chineseCatalog['devices.scan'], '扫描设备')
    assert.equal(germanCatalog['operation.failed'], 'Vorgang fehlgeschlagen')
    assert.equal(frenchCatalog['action.eject'], 'Éjecter')
    assert.equal(italianCatalog['service.unavailable'], 'Servizio non disponibile')
    assert.equal(portugueseCatalog['areas.utilities'], 'Utilitários')
    assert.equal(spanishCatalog['status.serialNumber'], 'Número de serie')
    assert.equal(japaneseCatalog['devices.noCartridge'], 'カートリッジなし')
}

/** @returns {void} Guards domain terms and invariant product tokens against literal machine-translation drift. */
function testSemanticDomainTranslations() {
    assert.equal(germanCatalog['status.drivePolicy'], 'Laufwerksrichtlinie')
    assert.equal(spanishCatalog['status.fixtureReported'], 'Según los datos de prueba del soporte')
    assert.equal(frenchCatalog['compatibility.fact.selectedDock'], 'Station d’accueil sélectionnée')
    assert.equal(italianCatalog['status.driveData'], 'Dati dell’unità')
    assert.equal(portugueseCatalog['status.camState'], 'Estado do came')
    assert.equal(japaneseCatalog['intent.operation'], '操作')
    assert.equal(chineseCatalog['intent.operation'], '操作')
    assert.equal(germanCatalog['topbar.openCompatibility'], 'Kompatibilität und Freigaben öffnen')
    assert.equal(germanCatalog['service.supportGuidance'], 'Support-Anleitung öffnen')
    assert.equal(germanCatalog['action.openTests'], 'Tests öffnen')
    assert.equal(frenchCatalog['tests.description'], 'Exécutez un diagnostic guidé à la fois. Les étapes actives et défaillantes restent en gris neutre ; le vert est réservé à une réussite entièrement confirmée.')
    assert.equal(japaneseCatalog['help.eyebrow.support'], 'ガイド付きローカル診断')
    assert.equal(japaneseCatalog['activity.eyebrow'], 'ローカル診断エビデンス')
    assert.equal(chineseCatalog['help.eyebrow.support'], '引导式本地诊断')
    assert.equal(chineseCatalog['status.status'], '状态')
    assert.equal(italianCatalog['encryption.workflow.description.configureAes'], 'Scegli una password principale, una politica di reimpostazione e NTFS o exFAT prima della conferma distruttiva esatta.')
    assert.equal(italianCatalog['encryption.workflow.description.configureBasic'], 'Scegli una password principale e una politica di reimpostazione dopo aver riconosciuto che la protezione di base non crittografa i dati del payload.')
    assert.equal(chineseCatalog['encryption.workflow.description.configureBasic'], '在确认基本保护不会加密有效负载数据后，选择主密码和重置策略。')
    assert.equal(frenchCatalog['compatibility.feature.01'], 'Découverte des lecteurs RDX et analyse automatique')
    assert.equal(portugueseCatalog['compatibility.feature.01'], 'Descoberta de unidades RDX e varredura automática')
    assert.equal(germanCatalog['utilities.prerequisite.productFamily.label'], 'Kompatible Firmware-Abbildfamilie')
    assert.equal(germanCatalog['utilities.prerequisite.productFamily.unmatched'], 'Die ausgewählte Produktfamilie kann keiner Dateierweiterung für Firmware-Abbilder zugeordnet werden.')
    assert.equal(chineseCatalog['utilities.stage.firmwareWriting'], '固件镜像传输（如有必要，完整重试一次）')
    assert.equal(chineseCatalog['utilities.prerequisite.productFamily.label'], '兼容的固件镜像系列')
    assert.equal(germanCatalog['status.freeSpace'], 'Freier Speicherplatz')
    assert.equal(germanCatalog['tests.prerequisite.freeSpace.label'], 'Freier Speicherplatz')
    for (const key of ['compatibility.limits.item5', 'compatibility.history.item2', 'compatibility.feature.24']) assert.doesNotMatch(chineseCatalog[key], /媒体/u, `zh:${key} must use storage-media terminology`)

    const fixtureProvenance = Object.freeze({
        de: ['Deterministische Testdaten-Vorschau', 'Diese Vorschau verwendet gebündelte Testdaten; es wird kein Ergebnis von echter RDX-Hardware gemeldet.'],
        es: ['Vista previa determinista con datos de prueba', 'Esta vista previa utiliza datos de prueba incluidos; no muestra ningún resultado de hardware RDX real.'],
        fr: ['Aperçu déterministe avec données de test', 'Cet aperçu utilise les données de test intégrées ; aucun résultat provenant de matériel RDX réel n’est présenté.'],
        it: ['Anteprima deterministica con dati di test', 'Questa anteprima usa dati di test inclusi; non riporta risultati provenienti da hardware RDX reale.'],
        ja: ['再現可能なテストデータのプレビュー', 'このプレビューでは同梱のテストデータを使用しており、実際の RDX ハードウェアの結果は表示しません。'],
        pt: ['Prévia determinística com dados de teste', 'Esta prévia usa dados de teste incluídos; nenhum resultado de hardware RDX real é apresentado.'],
        zh: ['可重复的测试数据预览', '此预览使用随附的测试数据，不会显示真实 RDX 硬件的结果。']
    })
    assert.deepEqual([englishCatalog['rail.servicePending'], englishCatalog['rail.servicePendingDescription']], ['Deterministic fixture preview', 'This preview uses bundled test data; no live RDX hardware result is reported.'])
    for (const [code, catalog] of catalogs) assert.deepEqual([catalog['rail.servicePending'], catalog['rail.servicePendingDescription']], fixtureProvenance[code], `${code}: fixture provenance`)

    const liveStorageTerms = Object.freeze({
        de: ['Hersteller', 'Status', 'SCSI-Sense-Zusammenfassung', 'Zugriff', 'Leeren Sie den Schreibcache und hängen Sie den Datenträger aus, bevor Sie den mechanischen Auswurf anfordern.'],
        es: ['Proveedor', 'Estado', 'Resumen de datos SCSI Sense', 'Acceso', 'Vacíe la caché de escritura y desmonte el medio antes de solicitar la expulsión mecánica.'],
        fr: ['Fournisseur', 'Statut', 'Résumé des données SCSI Sense', 'Accès', 'Videz le cache d’écriture et démontez le support avant de demander son éjection mécanique.'],
        it: ['Produttore', 'Stato', 'Riepilogo dei dati SCSI Sense', 'Accesso', "Svuotare la cache di scrittura e smontare il supporto prima di richiedere l'espulsione meccanica."],
        ja: ['ベンダー', '状態', 'SCSI センス概要', 'アクセス', '機械的な取り出しを要求する前に、書き込みキャッシュをフラッシュしてメディアをアンマウントしてください。'],
        pt: ['Fornecedor', 'Estado', 'Resumo dos dados SCSI Sense', 'Acesso', 'Sincronize a cache de escrita e desmonte a mídia antes de solicitar a ejeção mecânica.'],
        zh: ['供应商', '状态', 'SCSI Sense 摘要', '访问权限', '在请求机械弹出之前，请先刷新写入缓存并卸载介质。']
    })
    for (const [code, catalog] of catalogs) {
        assert.deepEqual([catalog['status.vendor'], catalog['status.status'], catalog['status.senseSummary'], catalog['status.access'], catalog['action.ejectDescription']], liveStorageTerms[code], `${code}: vendor, status, SCSI sense, access, and filesystem eject terminology`)
    }
    assert.doesNotMatch(Object.values(germanCatalog).join('\n'), /Patron/u, 'de catalog must use consistent RDX cassette terminology')
    assert.doesNotMatch(Object.values(chineseCatalog).join('\n'), /磁带|墨盒/u, 'zh catalog must use consistent RDX media-cartridge terminology')

    const workflowSemantics = Object.freeze({
        de: ['{stage}. Gerätewechsel und widersprüchliche Aktionen sind bis zu einem sicheren Endzustand gesperrt.', 'Überprüfen Sie das abschließende Vorgangsergebnis.', 'Sichere Endphase', 'Endphase'],
        es: ['{stage}. La conmutación de dispositivos y las acciones conflictivas se bloquean hasta alcanzar un estado final seguro.', 'Revise el resultado final de la operación.', 'Etapa final segura', 'Etapa final'],
        fr: ['{stage}. La commutation d’appareil et les actions conflictuelles restent verrouillées jusqu’à ce que l’opération atteigne un état final sûr.', 'Examinez le résultat final de l’opération.', 'Étape finale sécurisée', 'Étape finale'],
        it: ['{stage}. La commutazione del dispositivo e le azioni in conflitto restano bloccate fino al raggiungimento di uno stato finale sicuro.', "Esaminare il risultato finale dell'operazione.", 'Fase finale sicura', 'Fase finale'],
        ja: ['{stage}。デバイスの切り替えと競合するアクションは、安全な終了状態になるまでロックされます。', '操作の最終結果を確認します。', '安全な終了ステージ', '終了ステージ'],
        pt: ['{stage}. A troca de dispositivo e as ações conflitantes ficam bloqueadas até que a operação atinja um estado final seguro.', 'Revise o resultado final da operação.', 'Etapa final segura', 'Etapa final'],
        zh: ['{stage}。设备切换和冲突操作将保持锁定，直到操作达到安全终止状态。', '查看操作的最终结果。', '安全终止阶段', '终止阶段']
    })
    for (const [code, catalog] of catalogs) {
        assert.deepEqual([catalog['operation.lockBannerDescription'], catalog['operation.resultSummary'], catalog['utilities.result.safeTerminalStage'], catalog['tests.result.terminalStage']], workflowSemantics[code], `${code}: final operation-state terminology`)
        const actions = [catalog['topbar.openCompatibility'], catalog['service.supportGuidance'], catalog['intent.openSupport'], catalog['intent.openEventLog']].join(' ')
        assert.doesNotMatch(actions, /Offene|ouvert(?:es)?|abiert[oa]s?|apert[eo]|オープン/u, `${code}: open controls must use action verbs`)
        const storage = [catalog['status.capacityFree'], catalog['status.loadCount'], catalog['status.driveErrors'], catalog['status.mediaState'], catalog['utilities.stage.hostEjecting']].join(' ')
        assert.doesNotMatch(storage, /gratuit|免费的|負荷数|负载计数|Conteggio del carico|Errori di guida|départ|出発|退去/u, `${code}: storage terms must not use cost, workload, driving, or departure meanings`)
    }
    const candidateDiagnostics = [japaneseCatalog['empty.candidateDiagnostics'], japaneseCatalog['empty.candidateRejected'], japaneseCatalog['empty.candidatesRejected'], chineseCatalog['empty.candidateDiagnostics'], chineseCatalog['empty.candidateRejected'], chineseCatalog['empty.candidatesRejected']].join(' ')
    assert.doesNotMatch(candidateDiagnostics, /候補者|候选人|\{count\} 人|身份/u, 'ja/zh discovery copy must describe device candidates')
    const safeEjectGuidance = catalogs.map(([, catalog]) => catalog['utilities.eject.safeGuidance']).join(' ')
    assert.doesNotMatch(safeEjectGuidance, /gespült|retirer le montage|deve liberar|メディアの終了/u, 'safe eject guidance must describe cache flush, unmount, and removal')
    const chineseStorageMedia = ['help.topic.gettingStarted.paragraph1', 'compatibility.live.description', 'compatibility.historical.productsCaption', 'compatibility.product.protectedInterchange', 'compatibility.troubleshooting.step3', 'compatibility.limits.description', 'token.noMedia', 'token.wrongMediaState'].map((key) => chineseCatalog[key]).join(' ')
    assert.doesNotMatch(chineseStorageMedia, /媒体/u, 'zh storage copy must not use mass-media terminology')

    const sentinels = Object.freeze({
        de: ['Dienstprogrammvorgang', 'Hardware- und Datenträgertests', 'Validierte RDX-Dockingstation', 'Keine Kassette'],
        es: ['Operación de utilidad', 'Pruebas de hardware y del soporte', 'Base RDX validada', 'No hay cartucho'],
        fr: ['Opération d’utilitaire', 'Tests matériels et supports de données', "Station d'accueil RDX validée", 'Aucune cartouche'],
        it: ['Operazione di utilità', 'Test hardware e del supporto', 'Dock RDX convalidato', 'Nessuna cartuccia'],
        ja: ['ユーティリティ操作', 'ハードウェアとメディアテスト', '検証済みの RDX ドック', 'カートリッジなし'],
        pt: ['Operação de utilitário', 'Testes de hardware e suporte', 'Base RDX validada', 'Nenhum cartucho'],
        zh: ['实用程序操作', '硬件和介质测试', '已验证的 RDX 扩展坞', '无介质盒']
    })

    for (const [code, catalog] of catalogs) {
        assert.deepEqual([catalog['utilities.operation.generic'], catalog['tests.title'], catalog['tests.prerequisite.validatedDock.label'], catalog['encryption.noCartridge']], sentinels[code], `${code}: operation, media, dock, and cartridge terminology`)
        assert.match(catalog['help.about.copyright'], /Phosphor Icons/, `${code}: icon brand`)
        assert.match(catalog['help.topic.systemSummary.paragraph1'], /RdxSystemSummary\.txt/, `${code}: summary filename`)
        assert.match(catalog['compatibility.product.firmwareImagesQualification'], /\.BIP.*\.BIN/, `${code}: firmware extensions`)
        const fixtureCopy = [catalog['topbar.fixturePreview'], catalog['rail.fixtureLoaded'], catalog['status.fixtureReported']].join(' ')
        assert.doesNotMatch(fixtureCopy, /Spielmedien|partido|luminaire|incontro|jogo|報道|媒体报道/i, `${code}: test-data terminology`)
        for (const [key, value] of Object.entries(catalog)) {
            // Missing-manifest recovery gives several complete file-placement steps.
            if (key.startsWith('reason.') && key !== 'reason.firmwareOpenRdxManifestMissing') assert.doesNotMatch(value, /[.!?。！？]$/, `${code}:${key} must remain a sentence fragment`)
        }
    }
}

/** @returns {void} Verifies no user-facing guidance silently remains English. */
function testNoUnintendedEnglishFallback() {
    for (const [code, catalog] of catalogs) {
        for (const key of Object.keys(englishCatalog)) {
            if (!intentionallyInvariantKeys.has(key)) assert.notEqual(catalog[key], englishCatalog[key], `${code}:${key} must be localized`)
        }
    }
}

/** @returns {Promise<void>} Verifies safe settings persistence and strict rejection. */
async function testSettingsPersistenceWhitelist() {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-settings-'))
    const filePath = join(directory, 'settings.json')
    try {
        const service = new SettingsService({ filePath })
        assert.deepEqual(await service.load(), {
            autoScan: true,
            eventLogging: true,
            language: 'en',
            lastSafeView: 'status',
            updateChecks: true,
            windowBounds: null
        })

        assert.deepEqual(await service.update({ autoScan: false, eventLogging: false, language: 'de', updateChecks: false }), {
            ok: true,
            settings: { autoScan: false, eventLogging: false, language: 'de', lastSafeView: 'status', updateChecks: false }
        })
        assert.equal(await service.updateDesktopState({ lastSafeView: 'utilities', windowBounds: { height: 768, width: 1024, x: 12, y: 24 } }), true)
        assert.deepEqual(service.getDesktopState(), {
            autoScan: false,
            eventLogging: false,
            language: 'de',
            lastSafeView: 'utilities',
            updateChecks: false,
            windowBounds: { height: 768, width: 1024, x: 12, y: 24 }
        })
        assert.deepEqual(await service.update({ password: 'not-persisted' }), { ok: false, reason: 'invalid-request' })
        assert.equal(await service.updateDesktopState({ lastSafeView: 'encryption', rawFirmwareData: 'not-persisted' }), false)

        const persisted = await readFile(filePath, 'utf8')
        assert.doesNotMatch(persisted, /password|rawFirmwareData|not-persisted/)
        const reloaded = new SettingsService({ filePath })
        await reloaded.load()
        assert.deepEqual(reloaded.getDesktopState(), service.getDesktopState())
        assert.equal(reloaded.setSessionLanguage('ja'), true)
        assert.deepEqual(await reloaded.get(), { ok: true, settings: { autoScan: false, eventLogging: false, language: 'ja', lastSafeView: 'utilities', updateChecks: false } })
        assert.equal((await reloaded.update({ autoScan: true })).ok, true)
        assert.equal(JSON.parse(await readFile(filePath, 'utf8')).language, 'de')
        assert.equal(reloaded.setSessionLanguage('xx'), false)
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
}

/** @returns {Promise<void>} Verifies malformed persisted data fails closed to defaults. */
async function testMalformedSettingsFallback() {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-settings-invalid-'))
    const filePath = join(directory, 'settings.json')
    try {
        await writeFile(filePath, JSON.stringify({ language: 'xx', password: 'secret' }), 'utf8')
        const service = new SettingsService({ filePath })
        assert.deepEqual(await service.load(), {
            autoScan: true,
            eventLogging: true,
            language: 'en',
            lastSafeView: 'status',
            updateChecks: true,
            windowBounds: null
        })
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
}

/** @returns {void} Verifies CLI language precedence and invalid-code warning. */
function testStartupLanguageResolution() {
    const warnings = []
    assert.deepEqual(resolveStartupLanguage({ argv: ['electron', '.', '-l', 'ja'], persistedLanguage: 'de', warn: (warning) => warnings.push(warning) }), { language: 'ja', source: 'command-line' })
    assert.deepEqual(resolveStartupLanguage({ argv: ['electron', '.'], persistedLanguage: 'fr', warn: (warning) => warnings.push(warning) }), { language: 'fr', source: 'settings' })
    assert.deepEqual(resolveStartupLanguage({ argv: ['electron', '.', '-l', 'invalid'], persistedLanguage: 'fr', warn: (warning) => warnings.push(warning) }), { language: 'en', source: 'invalid-command-line' })
    assert.deepEqual(warnings, ['Unsupported language code; using English.'])
}

test('all supported catalogs have exactly the English keys and placeholders', testCatalogParityAndPlaceholders)
test('all supported catalogs contain reviewed representative translations', testRepresentativeTranslations)
test('all supported catalogs preserve reviewed RDX domain terminology', testSemanticDomainTranslations)
test('non-English catalogs contain no unintended English fallback', testNoUnintendedEnglishFallback)
test('settings persist only the strict safe whitelist', testSettingsPersistenceWhitelist)
test('malformed settings fall back without importing unknown fields', testMalformedSettingsFallback)
test('startup language accepts -l and warns on invalid codes', testStartupLanguageResolution)

// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Japanese manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': 'ドックの現在の識別情報が、選択した元のバックアップのシリアル番号 {serial} に置き換わることを理解しています。',
    'manufacturing.openFolder': 'バックアップフォルダーを開く',
    'manufacturing.openingFolder': 'フォルダーを開いています…',
    'manufacturing.folderDescription': '製造データのバックアップが保存されているフォルダーを開きます。',
    'manufacturing.error.openFolder': 'ファイルマネージャーでバックアップフォルダーを開けませんでした。',

    'manufacturing.page': '{page}ページ',
    'manufacturing.next': '古いバックアップ',
    'manufacturing.previous': '前のバックアップ',
    'manufacturing.eyebrow': 'デバイスの非公開バックアップ',
    'manufacturing.title': '製造データ',
    'manufacturing.description': '選択したドックの工場記録を検証し、非公開のコピーとして保存します。',
    'manufacturing.automaticBackup': 'ファームウェアを更新するたびに、検証済みの非公開バックアップを先に保存します。バックアップに失敗した場合、更新は停止します。',
    'manufacturing.backup': '製造データをバックアップ',
    'manufacturing.restore': '製造データを復元',
    'manufacturing.refresh': '保存済みバックアップを再読み込み',
    'manufacturing.pending': '処理中…',
    'manufacturing.loading': '保存済みバックアップを読み込み中…',
    'manufacturing.removeMedia': '製造データのバックアップや復元を行う前に、カートリッジを取り出してください。',
    'manufacturing.restoreDescription': '復元では工場記録のみを上書きし、隣接するデータを保持します。復元前に現在の状態を非公開のコピーとして保存します。成功が検証されたら、ドックの電源を手動で切り、再び入れてください。',
    'manufacturing.savedBackups': '保存済みバックアップ · 1ページ128件',
    'manufacturing.choose': 'バックアップを明示的に選択',
    'manufacturing.empty': '保存済みの製造データのバックアップはありません。',
    'manufacturing.backupLabel': '{date} · シリアル番号 {serial} · {state}',
    'manufacturing.serialUnavailable': '取得不可',
    'manufacturing.state.valid': '有効な記録',
    'manufacturing.state.erased': '消去された記録 · 証拠のみ',
    'manufacturing.state.corrupt': '破損した記録 · 証拠のみ',
    'manufacturing.confirmSerial': '選択したバックアップに表示された元のシリアル番号を入力',
    'manufacturing.target': '復元先: {product} · {serial}',
    'manufacturing.acknowledge': '実機を確認し、選択したバックアップがこのドックのものであることを確認しました。',
    'manufacturing.backupSucceeded': '製造データのバックアップと検証が完了しました。',
    'manufacturing.restoreSucceeded': '製造データの復元と検証が完了しました。続行する前にドックの電源を手動で切り、再び入れてください。',
    'manufacturing.error.restoreUnsupported': 'このドックの現在のファームウェアは製造データの復元に対応していません。',
    'manufacturing.error.unavailable': '製造データのバックアップには、カートリッジベイが空の対応するOpenRDXドックが必要です。',
    'manufacturing.error.uncertain': '操作の結果が確認されていません。操作はロックされたままです。保存済みバックアップを再読み込みしてサービスの状態を確認してください。書き込みを繰り返さないでください。',
    'manufacturing.error.failed': '製造データの操作を完了できませんでした。続行する前に保存済みバックアップを再読み込みし、ドックを確認してください。',
    'reason.firmwareManufacturingRestoreUnsupported': 'ドックの現在のファームウェアは製造データの復元に対応していません'
})

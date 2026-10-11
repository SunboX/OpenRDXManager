// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Chinese manufacturing backup and explicit restore controls. */
export const manufacturingCatalog = Object.freeze({
    'manufacturing.acknowledgeIdentityChange': '我了解此操作会将底座当前的身份信息替换为所选原始备份中的序列号 {serial}。',
    'manufacturing.openFolder': '打开备份文件夹',
    'manufacturing.openingFolder': '正在打开文件夹…',
    'manufacturing.folderDescription': '打开保存制造数据备份的文件夹。',
    'manufacturing.error.openFolder': '无法在系统文件管理器中打开备份文件夹。',

    'manufacturing.page': '第{page}页',
    'manufacturing.next': '较早的备份',
    'manufacturing.previous': '上一页备份',
    'manufacturing.eyebrow': '设备私有备份',
    'manufacturing.title': '制造数据',
    'manufacturing.description': '保存所选扩展坞出厂记录的已验证私有副本。',
    'manufacturing.automaticBackup': '每次更新固件之前都会先保存已验证的私有备份。如果备份失败，更新将停止。',
    'manufacturing.backup': '备份制造数据',
    'manufacturing.restore': '恢复制造数据',
    'manufacturing.refresh': '刷新已保存的备份',
    'manufacturing.pending': '正在处理…',
    'manufacturing.loading': '正在加载已保存的备份…',
    'manufacturing.removeMedia': '备份或恢复制造数据之前，请取出介质盒。',
    'manufacturing.restoreDescription': '恢复操作只会覆盖出厂记录，并保留相邻数据。恢复前会保存当前状态的私有副本。验证成功后，请手动关闭扩展坞电源，然后重新开启。',
    'manufacturing.savedBackups': '已保存的备份 · 每页128份',
    'manufacturing.choose': '明确选择一份备份',
    'manufacturing.empty': '没有可用的已保存制造数据备份。',
    'manufacturing.backupLabel': '{date} · 序列号 {serial} · {state}',
    'manufacturing.serialUnavailable': '不可用',
    'manufacturing.state.valid': '有效记录',
    'manufacturing.state.erased': '已擦除记录 · 仅作为证据',
    'manufacturing.state.corrupt': '损坏记录 · 仅作为证据',
    'manufacturing.confirmSerial': '输入所选备份中显示的原始序列号',
    'manufacturing.target': '恢复目标：{product} · {serial}',
    'manufacturing.acknowledge': '我已在现场确认此扩展坞，并确认所选备份属于它。',
    'manufacturing.backupSucceeded': '制造数据已备份并验证。',
    'manufacturing.restoreSucceeded': '制造数据已恢复并验证。继续之前，请手动关闭扩展坞电源，然后重新开启。',
    'manufacturing.error.restoreUnsupported': '此扩展坞的当前固件不支持恢复制造数据。',
    'manufacturing.error.unavailable': '备份制造数据需要受支持的OpenRDX扩展坞，且介质盒插槽必须为空。',
    'manufacturing.error.uncertain': '操作结果尚未确认。操作将保持锁定。请刷新已保存的备份以核对服务状态；请勿重复写入。',
    'manufacturing.error.failed': '无法完成制造数据操作。继续之前，请刷新已保存的备份并检查扩展坞。',
    'reason.firmwareManufacturingRestoreUnsupported': '扩展坞的当前固件不支持恢复制造数据'
})

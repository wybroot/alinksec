const issues = {
  clamav_disabled: '本机未启用 ClamAV', clamav_invalid_config: '本机连接配置无效',
  clamav_timeout: '等待或扫描超时', clamav_unavailable: '引擎连接或文件读取失败',
  clamav_tls_identity: '引擎证书校验失败', clamav_protocol: '引擎响应无效',
  clamav_version_changed: '引擎版本发生变化，请重新创建任务',
  clamav_file_limit: '文件超过 20 MiB 上限', clamav_incomplete: '引擎报告内容未完整检查',
  clamav_scan_error: '引擎返回扫描错误',
}
export const clamavIssueLabel = code => issues[code] || code

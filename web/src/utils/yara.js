const issues = {
  yara_read_failed_or_changed: '文件读取失败或读取期间已变化',
  yara_not_built: '当前 Agent 未编译原生 YARA 支持', yara_disabled: '本机未启用 YARA',
  yara_invalid_config: '本机规则配置无效', yara_rules_unavailable: '规则文件不可用或超过上限',
  yara_rules_changed: '规则源码与固定摘要不同', yara_version_changed: '执行版本已变化，请重新创建任务',
  yara_compile_error: '规则编译失败，请检查语法、模块和规则元数据', yara_empty_rules: '没有可执行规则',
  yara_rule_limit: '规则数量超过上限', yara_match_limit: '扫描匹配超过限制，结果未接受',
  yara_timeout: '等待、编译或扫描超时', yara_scan_error: '原生扫描失败',
  yara_worker_failed: '原生进程异常或达到资源限制', yara_worker_protocol: '原生进程响应无效',
  yara_resource_limit: '无法设置进程资源限制', yara_file_limit: '文件超过 20 MiB 上限',
}
export const yaraIssueLabel = code => issues[code] || code

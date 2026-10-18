<template>
  <el-alert type="info" :closable="false" show-icon title="仅核对 Linux 本地 shadow 的有限内置字典；未命中不代表口令安全。锁定账户及已知非登录 shell 排除，LDAP/AD 等外部身份源不在范围内。" />
  <div style="display:flex;justify-content:space-between;align-items:center;margin:12px 0">
    <span>逐主机检测覆盖（保留每次任务的首份结果）</span><el-button @click="load" :loading="loading">刷新覆盖</el-button>
  </div>
  <el-table :data="rows" stripe>
    <el-table-column label="主机 / 任务" min-width="180"><template #default="{ row }">{{ row.hostname || row.agent_id }}<br /><span class="mono">{{ row.task_no }}</span></template></el-table-column>
    <el-table-column label="弱口令覆盖" min-width="160"><template #default="{ row }"><el-tag :type="row.weak_status === 'complete' ? 'info' : 'warning'">{{ label(row.weak_status) }}</el-tag><br /><small v-if="row.state === 'failed' || row.state === 'timeout'">任务执行失败或超时</small><small v-if="row.late">晚到证据，保留原任务终态</small></template></el-table-column>
    <el-table-column label="已核对 / 排除 / 未支持 / 失败" min-width="220"><template #default="{ row }">{{ row.coverage?.accounts_seen != null ? `${row.coverage.accounts_checked} / ${row.coverage.accounts_excluded} / ${row.coverage.accounts_unsupported} / ${row.coverage.accounts_failed}` : '尚无检测证据' }}</template></el-table-column>
    <el-table-column label="字典 / 尝试次数" min-width="165"><template #default="{ row }">{{ row.coverage?.dictionary_version || '—' }}<br />{{ row.coverage?.candidates_tested ?? '—' }}</template></el-table-column>
    <el-table-column label="接收时间" min-width="170"><template #default="{ row }">{{ row.received_at || '等待回报' }}</template></el-table-column>
    <el-table-column label="说明" width="85"><template #default="{ row }"><el-button link @click="selected = row">详情</el-button></template></el-table-column>
  </el-table>
  <el-pagination v-model:current-page="page" :page-size="20" :total="total" layout="prev, pager, next, total" @current-change="load" style="margin-top:12px" />
  <el-dialog :model-value="!!selected" @close="selected = null" title="本地口令检测覆盖" width="min(680px, calc(100% - 24px))">
    <template v-if="selected">
      <p>{{ selected.hostname || selected.agent_id }} · {{ selected.task_no }} · {{ label(selected.weak_status) }}</p>
      <p v-if="selected.weak_status === 'unsupported'">该目标的系统或 Agent 不支持本次离线字典检测；同一目标的 Agent 扫描未下发。请更新 Linux Agent 后重新扫描，其他系统需人工核查。</p>
      <p v-if="selected.weak_status === 'pending'">尚未收到结果，请稍后刷新。任务超时或执行失败会保留明确状态。</p>
      <p v-if="selected.coverage?.accounts_seen != null">本地账户 {{ selected.coverage.accounts_seen }} 个；已核对 {{ selected.coverage.accounts_checked }} 个（含空口令），排除 {{ selected.coverage.accounts_excluded }} 个。命中后停止该账户比对，未命中仅说明未命中本次字典。</p>
      <p v-for="issue in selected.coverage?.issues || []" :key="issue">{{ reason(issue) }}</p>
      <p v-if="selected.late">结果晚于任务失败、超时或完成状态到达；证据保留，原任务终态保持。</p>
      <p>口令及 shadow 哈希不会回传。历史风险发现需结合检测时间和最新覆盖人工核对。</p>
    </template>
  </el-dialog>
</template>
<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchScanCoverage } from '../api'
const rows = ref([]), page = ref(1), total = ref(0), selected = ref(null), loading = ref(false)
const label = status => ({ complete:'有限字典核对完成',partial:'部分覆盖',failed:'检测失败',unsupported:'未支持 / 未覆盖',not_requested:'未选择弱口令',pending:'等待检测' }[status] || '状态未知')
const reason = issue => ({ legacy_agent:'Agent 使用旧扫描协议，结果无法验证；请更新 Agent 后重新扫描。',identity_read_failed:'无法完整读取本地身份文件，请检查权限。',identity_metadata_invalid:'本地身份文件类型、所有者或权限不受支持。',identity_parse_failed:'本地身份文件格式异常。',identity_duplicate:'本地账户存在重复声明。',passwd_credential_source_unsupported:'账户凭据不在受支持的本地 shadow 中。',account_limit:'本地账户数量超过本次上限。',identity_account_mismatch:'passwd 与 shadow 的账户清单不一致。',hash_invalid:'存在无法解析的哈希。',hash_unsupported:'存在未支持的哈希算法。',hash_cost_exceeded:'哈希计算成本超过本次上限。',hash_cost_unsupported:'哈希成本参数不在当前支持范围。',hash_verification_failed:'哈希核对执行失败。',scan_budget_exhausted:'已达到本次时间或尝试次数上限。',identity_changed:'扫描期间本地身份文件变化，本次发现已丢弃，请重新检测。',platform_unsupported:'该系统不支持本地字典检测。' }[issue] || '检测未完整完成，请重新扫描或人工核对。')
async function load() { loading.value = true; try { const data = await fetchScanCoverage(page.value); rows.value = data.list || []; total.value = Number(data.total || 0) } catch (e) { ElMessage.error(e.message || '检测覆盖加载失败') } finally { loading.value = false } }
onMounted(load)
</script>

<template>
  <div>
    <div style="display:flex;gap:16px;margin-bottom:16px">
      <div class="chip"><span class="dot" style="background:#dc2626"></span><span class="n">{{ sevCount.c }}</span><span class="l">严重</span></div>
      <div class="chip"><span class="dot" style="background:#f59e0b"></span><span class="n">{{ sevCount.h }}</span><span class="l">高危</span></div>
      <div class="chip"><span class="dot" style="background:#2563eb"></span><span class="n">{{ sevCount.m }}</span><span class="l">中危</span></div>
      <div class="chip"><span class="dot" style="background:#94a3b8"></span><span class="n">{{ sevCount.l }}</span><span class="l">低危</span></div>
      <div class="chip" style="background:#ecfdf5"><span class="dot" style="background:#16a34a"></span><span class="n" style="color:#16a34a">{{ fixRate }}%</span><span class="l">修复率</span></div>
    </div>
    <el-alert type="info" :closable="false" show-icon title="漏洞清单只显示已匹配结果，没有告警不代表安全；请在“比对覆盖”核对采集状态、未知信息及适用声明。" style="margin-bottom:12px" />
    <div class="panel">
      <div class="toolbar">
        <el-select v-model="sevFilter" placeholder="级别" clearable style="width:120px">
          <el-option label="严重" value="c" /><el-option label="高危" value="h" /><el-option label="中危" value="m" /><el-option label="低危" value="l" /></el-select>
        <div class="spacer"></div>
        <el-button type="primary" plain :disabled="!selVulns.length" @click="openBatchFix">批量修复（{{ selVulns.length }}）</el-button>
        <el-button type="primary" @click="openScan">发起扫描</el-button>
      </div>

      <el-tabs v-model="tab">
        <el-tab-pane label="处置历史" name="history" lazy><VulnerabilityHistory v-if="tab === 'history'" /></el-tab-pane>
        <el-tab-pane label="比对覆盖" name="coverage" lazy><VulnerabilityCoverage v-if="tab === 'coverage'" /></el-tab-pane>
        <el-tab-pane label="漏洞清单" name="vuln">
          <el-table :data="filteredVulns" stripe @selection-change="s => selVulns = s">
            <el-table-column type="selection" width="42" />
            <el-table-column label="漏洞" min-width="200">
              <template #default="{ row }"><span class="mono" style="color:#2563eb;font-weight:600">{{ row.cve }}</span><br /><span style="font-size:12px;color:#64748b">{{ row.desc }}</span></template>
            </el-table-column>
            <el-table-column label="软件 / 版本" width="180">
              <template #default="{ row }">{{ row.pkg }}<br /><span class="mono" style="color:#94a3b8;font-size:11px">{{ row.cur }} → {{ row.target }}</span></template>
            </el-table-column>
            <el-table-column label="匹配时身份" min-width="180">
              <template #default="{ row }">
                <span>{{ row.distroId ? `${row.distroId} ${row.distroVersion}` : row.osVersion || '发行版未知' }}</span><br />
                <span class="mono" style="font-size:11px;color:#64748b">{{ row.source || '来源未知' }} · {{ row.architecture || '架构未知' }}</span><br />
                <span v-if="row.identityStatus !== 'complete'" style="font-size:11px;color:#b45309">历史结果，请重新扫描</span>
                <span v-else-if="row.blocked" style="font-size:11px;color:#b45309">{{ row.blocked }} 项需重新采集/扫描或人工处理</span>
              </template>
            </el-table-column>
            <el-table-column label="级别" width="80">
              <template #default="{ row }"><el-tag size="small" :type="sevType(row.sev)" :effect="row.sev === 'critical' ? 'dark' : 'light'">{{ sevLabel(row.sev) }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="cvss" label="CVSS" width="70" />
            <el-table-column label="修复方式" width="110">
              <template #default="{ row }"><el-tag size="small" :type="row.fixType === 'config' ? 'success' : 'warning'" effect="plain">{{ row.fixType === 'config' ? '配置类' : '软件包类' }}</el-tag></template>
            </el-table-column>
            <el-table-column label="影响主机" width="80"><template #default="{ row }">{{ row.hosts }} 台</template></el-table-column>
            <el-table-column label="状态" width="90">
              <template #default="{ row }"><el-tag size="small" :type="row.status === 'fixed' ? 'success' : row.status === 'fixing' ? 'primary' : 'info'" effect="plain">{{ row.status === 'fixed' ? '已修复' : row.status === 'fixing' ? '修复中' : '待修复' }}</el-tag></template>
            </el-table-column>
            <el-table-column label="操作" width="110" fixed="right">
              <template #default="{ row }">
                <el-button v-if="row.status === 'todo' && row.findings.length" link :type="row.fixType === 'config' ? 'success' : 'warning'" size="small" @click="openFix(row)">一键修复</el-button>
                <el-button v-else link size="small" @click="detailRow = row; detailDlg = true">详情</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="Windows 更新" name="windows-update">
          <WindowsUpdates v-if="tab === 'windows-update'" />
        </el-tab-pane>
        <el-tab-pane label="弱口令" name="weakpwd">
          <WeakPasswordCoverage v-if="tab === 'weakpwd'" />
          <p style="margin-top:20px">历史风险发现（不代表当前口令状态）</p>
          <el-table :data="weakpwds" stripe>
            <el-table-column prop="host" label="主机" width="160" />
            <el-table-column prop="account" label="账户" width="140" />
            <el-table-column label="类型" width="160">
              <template #default="{ row }"><el-tag size="small" :type="row.type === 'system_empty' ? 'danger' : row.type === 'uid0_nonroot' ? 'warning' : 'info'" effect="plain">{{ row.typeLabel }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="remark" label="说明" min-width="180" />
            <el-table-column prop="time" label="发现时间" width="170" />
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="端口服务" name="port">
          <div style="margin-bottom:12px">
            <el-checkbox v-model="riskyOnly" label="仅看高危端口" @change="loadPorts" />
          </div>
          <el-table :data="ports" stripe>
            <el-table-column prop="host" label="主机" width="150" />
            <el-table-column label="端口" width="110">
              <template #default="{ row }"><span class="mono">{{ row.port }}/{{ row.protocol }}</span></template>
            </el-table-column>
            <el-table-column prop="service" label="服务" width="120" />
            <el-table-column prop="process" label="进程" min-width="140" />
            <el-table-column label="风险" min-width="220">
              <template #default="{ row }">
                <el-tag v-if="row.risky" size="small" type="danger" effect="dark">高危</el-tag>
                <span style="font-size:12px;color:#64748b;margin-left:6px">{{ row.risky_reason || '' }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>

  <!-- 发起扫描对话框 -->
  <el-dialog v-model="scanDlg" title="发起安全扫描" width="560px">
    <el-form label-width="96px">
      <el-form-item label="目标主机">
        <el-select v-model="scanForm.agentIds" multiple filterable placeholder="选择主机（可多选）" style="width:100%">
          <el-option v-for="a in agents" :key="a.id" :label="a.name + '（' + a.ip + '）'" :value="a.id" />
        </el-select>
      </el-form-item>
      <el-form-item label="扫描内容">
        <el-checkbox v-model="scanForm.includeVuln">漏洞比对（服务端 CVE 库 × 软件快照）</el-checkbox><br />
        <el-checkbox v-model="scanForm.includeWeakPassword">Linux 弱口令（本地有限字典离线核对）</el-checkbox><br />
        <el-checkbox v-model="scanForm.includePortService">端口服务识别（高危端口标记）</el-checkbox>
      </el-form-item>
      <el-alert type="info" :closable="false" show-icon
        title="Linux 弱口令仅核对本地 shadow 的 100 项内置字典，不回传口令。不支持的目标会显示未覆盖，该目标的 Agent 扫描不下发；请到弱口令页核对逐主机覆盖。" />
    </el-form>
    <template #footer>
      <el-button @click="scanDlg = false">取消</el-button>
      <el-button type="primary" :loading="scanSubmitting" @click="submitScan">开始扫描</el-button>
    </template>
  </el-dialog>

  <!-- 一键修复对话框 -->
  <el-dialog v-model="fixDlg" :title="'一键修复 · ' + fixRow.cve" width="min(560px, calc(100% - 24px))">
    <template v-if="fixRow.cve">
      <el-alert v-if="fixRow.fixType === 'config'" type="success" :closable="false" show-icon
        title="配置类修复：Agent 将自动执行，改前备份 → 执行 → 复核，失败自动回滚" />
      <el-alert v-else type="warning" :closable="false" show-icon
        title="软件包类修复：由指定账号审批，可设置维护窗口；修复后自动复核，需重启时仅标记不自动重启" />
      <el-form label-width="96px" style="margin-top:16px">
        <el-form-item label="影响范围">{{ fixRow.hosts }} 台主机</el-form-item>
        <el-form-item v-if="fixRow.identityStatus" label="匹配时身份">{{ fixRow.distroId }} {{ fixRow.distroVersion }} · {{ fixRow.source || '未知' }} · {{ fixRow.architecture || '架构未知' }}</el-form-item>
        <el-form-item v-if="fixRow.ruleSourceId" label="规则依据"><VulnerabilityEvidence :snapshot="fixRow.ruleEvidence" :source-id="fixRow.ruleSourceId" :digest="fixRow.ruleDigest" :status="fixRow.evidenceStatus" /></el-form-item>
        <el-alert v-if="fixRow.repairUnreviewed" type="warning" :closable="false" :title="`${fixRow.repairUnreviewed} 项缺少对应当前规则与包范围的补丁人工复核，请先到基线核查的离线补丁仓库复核`" />
        <el-alert v-if="fixRow.executionUnsupported" type="warning" :closable="false" :title="`${fixRow.executionUnsupported} 项未声明受支持的执行校验能力，请更新支持该系统的 Agent 或人工处理`" />
        <el-alert v-if="fixRow.blocked" type="warning" :closable="false" :title="`${fixRow.blocked} 项缺少当前身份、执行能力、规则依据、修复版本或补丁复核证据，仅提交符合条件的检测项`" />
        <template v-if="fixRow.fixType === 'config'">
          <el-form-item label="修复步骤">
            <div class="mono" style="font-size:12px;color:#475569;line-height:1.9">
              1. 备份 /etc/pam.d/sshd<br />2. file_line_ensure: pam_faillock preauth<br />3. service_restart: sshd（可关）
            </div>
          </el-form-item>
        </template>
        <template v-else>
          <el-form-item label="目标版本">
            <span class="mono">{{ fixRow.target }}（漏洞库 fixed_version，逐主机按已装版本升级）</span>
          </el-form-item>
          <el-form-item label="审批人" required>
            <el-select v-model="fixForm.approver" filterable placeholder="选择已启用的审批账号" style="width:100%;max-width:320px"><el-option v-for="user in approvers" :key="user.id" :value="user.username" :label="user.real_name ? `${user.username}（${user.real_name}）` : user.username" /></el-select>
            <p style="color:#64748b;font-size:12px">由所选账号登录后审批，审批记录使用已验证身份。</p>
          </el-form-item>
          <el-form-item label="维护窗口">
            <el-date-picker v-model="fixForm.win" type="datetimerange" start-placeholder="开始（本地时间）" end-placeholder="结束（本地时间）" />
          </el-form-item>
          <p style="color:#64748b;font-size:12px">不填窗口则审批后排队；设置时起止必须齐全。截止后停止新安装和重推，已经开始的安装需查看结果，不承诺自动回滚。</p>
          <el-alert type="info" :closable="false" show-icon style="margin-bottom:12px"
            title="创建时校验补丁仓库覆盖率：任一主机无对应补丁包将阻断提交" />
        </template>
      </el-form>
    </template>
    <template #footer>
      <el-button @click="fixDlg = false">取消</el-button>
      <el-button type="primary" :loading="fixSubmitting" @click="submitFix">{{ fixRow.fixType === 'config' ? '确认执行' : '提交审批' }}</el-button>
    </template>
  </el-dialog>

  <!-- 漏洞详情（数据来自漏洞明细按 CVE 聚合） -->
  <el-dialog v-model="detailDlg" :title="detailRow?.cve" width="min(560px, calc(100% - 24px))">
    <template v-if="detailRow?.cve">
      <el-descriptions :column="1" border size="small">
        <el-descriptions-item label="描述">{{ detailRow.desc }}</el-descriptions-item>
        <el-descriptions-item label="软件 / 版本">
          <span class="mono">{{ detailRow.pkg }} {{ detailRow.cur }} → {{ detailRow.target }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="级别 / CVSS">{{ sevLabel(detailRow.sev) }} · {{ detailRow.cvss }}</el-descriptions-item>
        <el-descriptions-item label="匹配时身份">{{ detailRow.distroId }} {{ detailRow.distroVersion }} · {{ detailRow.source || '来源未知' }} · {{ detailRow.architecture || '架构未知' }}</el-descriptions-item>
        <el-descriptions-item label="规则依据"><VulnerabilityEvidence :snapshot="detailRow.ruleEvidence" :source-id="detailRow.ruleSourceId" :digest="detailRow.ruleDigest" :status="detailRow.evidenceStatus" /></el-descriptions-item>
        <el-descriptions-item v-if="detailRow.repairUnreviewed" label="补丁复核">{{ detailRow.repairUnreviewed }} 项缺少对应当前规则与包范围的补丁人工复核</el-descriptions-item>
        <el-descriptions-item v-if="detailRow.executionUnsupported" label="执行限制">{{ detailRow.executionUnsupported }} 项未声明受支持的执行校验能力，请更新支持该系统的 Agent 或人工处理</el-descriptions-item>
        <el-descriptions-item v-if="detailRow.blocked" label="修复限制">{{ detailRow.blocked }} 项缺少当前身份、执行能力、规则依据、修复版本或补丁复核证据，请重新采集、扫描或人工处理</el-descriptions-item>
        <el-descriptions-item label="修复方式">{{ detailRow.fixType === 'config' ? '配置类' : '软件包类' }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ detailRow.status === 'fixed' ? '已修复' : detailRow.status === 'fixing' ? '修复中' : '待修复' }}</el-descriptions-item>
        <el-descriptions-item :label="`影响主机（${detailRow.hosts} 台）`">
          <div><el-tag v-for="h in detailRow.hostList" :key="h" size="small" effect="plain" style="margin:2px">{{ h }}</el-tag></div>
        </el-descriptions-item>
      </el-descriptions>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchVulns, fetchVulnStats, fetchWeakpwds, fetchPortFindings, createScanTask, fetchAgentsForSelect, createPackageFixTask, fetchFixApprovers } from '../api'
import { sevType, sevLabel } from '../utils/format'
import VulnerabilityEvidence from '../components/VulnerabilityEvidence.vue'
import VulnerabilityHistory from '../components/VulnerabilityHistory.vue'
import WeakPasswordCoverage from '../components/WeakPasswordCoverage.vue'
import VulnerabilityCoverage from '../components/VulnerabilityCoverage.vue'
import WindowsUpdates from '../components/WindowsUpdates.vue'

const tab = ref('vuln')
const vulns = ref([])
const selVulns = ref([])
const detailDlg = ref(false)
const detailRow = ref(null)
const sevFilter = ref('')
const weakpwds = ref([])
const ports = ref([])
const riskyOnly = ref(false)
const agents = ref([])
const approvers = ref([])
const vulnStats = ref({ bySeverity: [], pending: 0, fixed: 0, total: 0 })

// 发起扫描
const scanDlg = ref(false)
const scanSubmitting = ref(false)
const scanForm = ref({ agentIds: [], includeVuln: true, includeWeakPassword: true, includePortService: true })

// 一键修复
const fixDlg = ref(false)
const fixSubmitting = ref(false)
const fixRow = ref({})
const fixForm = ref({ version: '9.8p1', approver: '', win: [] })

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

const filteredVulns = computed(() =>
  sevFilter.value ? vulns.value.filter(v => v.sev === sevFilter.value) : vulns.value)

const sevCount = computed(() => {
  const c = { c: 0, h: 0, m: 0, l: 0 }
  const keys = { 4: 'c', 3: 'h', 2: 'm', 1: 'l' }
  for (const row of vulnStats.value.bySeverity || []) {
    const key = keys[Number(row.severity)]
    if (key) c[key] = Number(row.count || 0)
  }
  return c
})
const fixRate = computed(() => {
  const total = Number(vulnStats.value.total || 0)
  return total ? Math.round((Number(vulnStats.value.fixed || 0) / total) * 100) : 0
})

const weakTypeLabel = {
  system_empty: '空密码',
  system_weak: '弱口令',
  uid0_nonroot: 'UID=0 非 root',
  pwd_stale: '密码长期未改',
}

const openScan = async () => {
  if (!agents.value.length) agents.value = await fetchAgentsForSelect()
  scanDlg.value = true
}
const submitScan = async () => {
  if (!scanForm.value.agentIds.length) return ElMessage({ message: '请选择目标主机', type: 'warning' })
  scanSubmitting.value = true
  try {
    await createScanTask(scanForm.value.agentIds, scanForm.value)
    scanDlg.value = false
    msg('扫描任务已下发')
    setTimeout(loadAll, 3000)
  } catch (e) {
    ElMessage({ message: e?.message || '任务创建失败', type: 'error' })
  } finally {
    scanSubmitting.value = false
  }
}

const openFix = row => {
  if (row.fixType === 'pkg' && !row.findings?.length) {
    return ElMessage({ message: '该漏洞暂无可自动修复项', type: 'info' })
  }
  fixRow.value = row
  fixDlg.value = true
  loadApprovers()
}
const openBatchFix = () => {
  const rows = selVulns.value.filter(v => v.fixType === 'pkg' && v.findings?.length)
  if (!rows.length) {
    return ElMessage({ message: '所选漏洞无可修复项（均无待修复主机）', type: 'warning' })
  }
  // 合并为一个“批量”伪行：标题展示条数，findings 全量拼接
  fixRow.value = {
    cve: `${rows.length} 项漏洞批量修复`,
    desc: rows.map(r => r.cve).join('、'),
    fixType: 'pkg',
    hosts: new Set(rows.flatMap(r => r.findings.map(f => f.agentId))).size,
    blocked: rows.reduce((n, r) => n + r.blocked, 0),
    repairUnreviewed: rows.reduce((n, r) => n + (r.repairUnreviewed || 0), 0),
    executionUnsupported: rows.reduce((n, r) => n + (r.executionUnsupported || 0), 0),
    target: '按漏洞库 fixed_version 逐项升级',
    findings: [...new Map(rows.flatMap(r => r.findings).map(f => [`${f.agentId}:${f.findingId}`, f])).values()],
  }
  fixDlg.value = true
  loadApprovers()
}
async function loadApprovers() {
  try { approvers.value = await fetchFixApprovers(); if (!approvers.value.some(user => user.username === fixForm.value.approver)) fixForm.value.approver = '' }
  catch (error) { ElMessage.error(error.message || '审批账号加载失败') }
}
const iso = d => (d instanceof Date ? d.toISOString() : (d || ''))
const submitFix = async () => {
  if (fixRow.value.fixType === 'config') {
    fixDlg.value = false
    fixRow.value.status = 'fixing'
    return msg('配置类修复任务已下发，Agent 自动执行')
  }
  if (!fixForm.value.approver.trim()) {
    return ElMessage({ message: '请填写审批人', type: 'warning' })
  }
  fixSubmitting.value = true
  try {
    const [ws, we] = fixForm.value.win || []
    const res = await createPackageFixTask(fixRow.value.findings, {
      approver: fixForm.value.approver.trim(),
      windowStart: iso(ws) || undefined,
      windowEnd: iso(we) || undefined,
    })
    fixDlg.value = false
    fixRow.value.status = 'fixing'
    msg(`软件包修复任务 ${res?.taskNo || res?.taskId} 已提交审批，审批通过后进入维护窗口执行`)
    setTimeout(loadAll, 3000)
  } catch (e) {
    ElMessage({ message: e?.message || '任务创建失败', type: 'error', duration: 5000 })
  } finally {
    fixSubmitting.value = false
  }
}

const loadPorts = async () => {
  const data = await fetchPortFindings(riskyOnly.value)
  ports.value = (data?.list || []).map(p => ({
    host: p.hostname || p.agent_id,
    port: p.port,
    protocol: p.protocol,
    service: p.service || '—',
    process: p.process || '—',
    risky: p.risky,
    risky_reason: p.risky_reason,
  }))
}

const loadAll = async () => {
  const [v, stats, w] = await Promise.all([fetchVulns(), fetchVulnStats(), fetchWeakpwds()])
  vulns.value = v
  vulnStats.value = stats || vulnStats.value
  weakpwds.value = (w?.list || []).map(x => ({
    host: x.hostname || x.agent_id,
    account: x.account,
    type: x.type,
    typeLabel: weakTypeLabel[x.type] || x.type,
    remark: x.remark || '',
    time: x.created_at ? String(x.created_at).replace('T', ' ').slice(0, 19) : '—',
  }))
  loadPorts()
}

onMounted(loadAll)
</script>

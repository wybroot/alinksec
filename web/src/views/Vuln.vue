<template>
  <div>
    <div style="display:flex;gap:16px;margin-bottom:16px">
      <div class="chip"><span class="dot" style="background:#dc2626"></span><span class="n">{{ sevCount.c }}</span><span class="l">严重</span></div>
      <div class="chip"><span class="dot" style="background:#f59e0b"></span><span class="n">{{ sevCount.h }}</span><span class="l">高危</span></div>
      <div class="chip"><span class="dot" style="background:#2563eb"></span><span class="n">{{ sevCount.m }}</span><span class="l">中危</span></div>
      <div class="chip"><span class="dot" style="background:#94a3b8"></span><span class="n">{{ sevCount.l }}</span><span class="l">低危</span></div>
      <div class="chip" style="background:#ecfdf5"><span class="dot" style="background:#16a34a"></span><span class="n" style="color:#16a34a">{{ fixRate }}%</span><span class="l">修复率</span></div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <el-select v-model="sevFilter" placeholder="级别" clearable style="width:120px">
          <el-option label="严重" value="c" /><el-option label="高危" value="h" /><el-option label="中危" value="m" /><el-option label="低危" value="l" /></el-select>
        <div class="spacer"></div>
        <el-button type="primary" plain :disabled="!selVulns.length" @click="openBatchFix">批量修复（{{ selVulns.length }}）</el-button>
        <el-button type="primary" @click="openScan">发起扫描</el-button>
      </div>

      <el-tabs v-model="tab">
        <el-tab-pane label="漏洞清单" name="vuln">
          <el-table :data="filteredVulns" stripe @selection-change="s => selVulns = s">
            <el-table-column type="selection" width="42" />
            <el-table-column label="漏洞" min-width="200">
              <template #default="{ row }"><span class="mono" style="color:#2563eb;font-weight:600">{{ row.cve }}</span><br /><span style="font-size:12px;color:#64748b">{{ row.desc }}</span></template>
            </el-table-column>
            <el-table-column label="软件 / 版本" width="180">
              <template #default="{ row }">{{ row.pkg }}<br /><span class="mono" style="color:#94a3b8;font-size:11px">{{ row.cur }} → {{ row.target }}</span></template>
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
                <el-button v-if="row.status === 'todo'" link :type="row.fixType === 'config' ? 'success' : 'warning'" size="small" @click="openFix(row)">一键修复</el-button>
                <el-button v-else link size="small" @click="detailRow = row; detailDlg = true">详情</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="弱口令" name="weakpwd">
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
        <el-checkbox v-model="scanForm.includeWeakPassword">弱口令检测（本机离线，无在线爆破）</el-checkbox><br />
        <el-checkbox v-model="scanForm.includePortService">端口服务识别（高危端口标记）</el-checkbox>
      </el-form-item>
      <el-alert type="info" :closable="false" show-icon
        title="漏洞比对即时完成；弱口令与端口服务由 Agent 执行后自动上报，稍候刷新查看结果" />
    </el-form>
    <template #footer>
      <el-button @click="scanDlg = false">取消</el-button>
      <el-button type="primary" :loading="scanSubmitting" @click="submitScan">开始扫描</el-button>
    </template>
  </el-dialog>

  <!-- 一键修复对话框 -->
  <el-dialog v-model="fixDlg" :title="'一键修复 · ' + fixRow.cve" width="560px">
    <template v-if="fixRow.cve">
      <el-alert v-if="fixRow.fixType === 'config'" type="success" :closable="false" show-icon
        title="配置类修复：Agent 将自动执行，改前备份 → 执行 → 复核，失败自动回滚" />
      <el-alert v-else type="warning" :closable="false" show-icon
        title="软件包类修复：需审批并限定维护窗口；修复后自动复核，需重启时仅标记不自动重启" />
      <el-form label-width="96px" style="margin-top:16px">
        <el-form-item label="影响范围">{{ fixRow.hosts }} 台主机</el-form-item>
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
            <el-input v-model="fixForm.approver" placeholder="必填（提交后由该人员审批放行）" style="width:260px" />
          </el-form-item>
          <el-form-item label="维护窗口">
            <el-date-picker v-model="fixForm.win" type="datetimerange" start-placeholder="开始（可空=审批后立即执行）" end-placeholder="结束" />
          </el-form-item>
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
  <el-dialog v-model="detailDlg" :title="detailRow?.cve" width="560px">
    <template v-if="detailRow?.cve">
      <el-descriptions :column="1" border size="small">
        <el-descriptions-item label="描述">{{ detailRow.desc }}</el-descriptions-item>
        <el-descriptions-item label="软件 / 版本">
          <span class="mono">{{ detailRow.pkg }} {{ detailRow.cur }} → {{ detailRow.target }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="级别 / CVSS">{{ sevLabel(detailRow.sev) }} · {{ detailRow.cvss }}</el-descriptions-item>
        <el-descriptions-item label="修复方式">{{ detailRow.fixType === 'config' ? '配置类' : '软件包类' }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ detailRow.status === 'fixed' ? '已修复' : detailRow.status === 'fixing' ? '修复中' : '待修复' }}</el-descriptions-item>
        <el-descriptions-item label="影响主机（{{ detailRow.hosts }} 台）">
          <el-tag v-for="h in detailRow.hostList" :key="h" size="small" effect="plain" style="margin:2px">{{ h }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchVulns, fetchWeakpwds, fetchPortFindings, createScanTask, fetchAgentsForSelect, createPackageFixTask } from '../api'
import { sevType, sevLabel } from '../utils/format'

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

// 发起扫描
const scanDlg = ref(false)
const scanSubmitting = ref(false)
const scanForm = ref({ agentIds: [], includeVuln: true, includeWeakPassword: true, includePortService: true })

// 一键修复
const fixDlg = ref(false)
const fixRow = ref({})
const fixForm = ref({ version: '9.8p1', approver: '', win: [] })

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

const filteredVulns = computed(() =>
  sevFilter.value ? vulns.value.filter(v => v.sev === sevFilter.value) : vulns.value)

const sevCount = computed(() => {
  const c = { c: 0, h: 0, m: 0, l: 0 }
  for (const v of vulns.value) c[v.sev] = (c[v.sev] || 0) + 1
  return c
})
const fixRate = computed(() => {
  if (!vulns.value.length) return 0
  const fixed = vulns.value.filter(v => v.status === 'fixed').length
  return Math.round((fixed / vulns.value.length) * 100)
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
    return ElMessage({ message: '该漏洞各主机均已修复', type: 'info' })
  }
  fixRow.value = row
  fixDlg.value = true
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
    hosts: rows.reduce((n, r) => n + r.hosts, 0),
    target: '按漏洞库 fixed_version 逐项升级',
    findings: rows.flatMap(r => r.findings),
  }
  fixDlg.value = true
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
  const [v, w] = await Promise.all([fetchVulns(), fetchWeakpwds()])
  vulns.value = v
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

<template>
  <div>
    <div class="grid-2">
      <div class="panel"><h4>等保 2.0 服务器基线 · 合规得分</h4><div ref="scoreEl" class="chart"></div></div>
      <div class="panel"><h4>各检查领域通过率</h4><div ref="catEl" class="chart"></div></div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <el-button type="primary" @click="openCreate">+ 发起核查</el-button>
        <div class="spacer"></div>
        <span style="font-size:12px;color:#94a3b8">{{ lastSummary }}</span>
      </div>
      <el-table :data="rows" stripe>
        <el-table-column prop="host" label="主机" width="170" />
        <el-table-column prop="tpl" label="模板" width="220" />
        <el-table-column label="合规率" width="200">
          <template #default="{ row }"><el-progress :percentage="row.rate" :stroke-width="8" :color="row.rate > 80 ? '#16a34a' : row.rate > 60 ? '#f59e0b' : '#dc2626'" /></template>
        </el-table-column>
        <el-table-column label="不合规（严重/高/中/低）" width="180">
          <template #default="{ row }"><span class="mono" style="color:#dc2626">{{ row.c }}</span> / {{ row.h }} / {{ row.m }} / {{ row.l }}</template>
        </el-table-column>
        <el-table-column prop="time" label="核查时间" width="150" />
        <el-table-column label="操作" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="viewDetail(row)">明细</el-button>
            <el-button link type="warning" size="small" @click="viewDetail(row, true)">修复不合规项</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="toolbar" style="margin-top:0">
      <el-button plain @click="openFixTasks">修复任务记录</el-button>
    </div>

    <!-- 发起核查 -->
    <el-dialog v-model="dlg.visible" title="发起基线核查" width="640px">
      <el-form label-width="90px">
        <el-form-item label="任务名称">
          <el-input v-model="dlg.name" placeholder="留空自动生成" maxlength="64" />
        </el-form-item>
        <el-form-item label="基线模板">
          <el-select v-model="dlg.templateIds" multiple placeholder="选择基线模板（可多选）" style="width:100%">
            <el-option v-for="t in templates" :key="t.id" :label="`${t.name}（${t.item_count} 项）`" :value="t.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="目标主机">
          <el-select v-model="dlg.agentIds" multiple filterable placeholder="选择主机（按 OS 自动过滤适用项）" style="width:100%">
            <el-option v-for="h in hosts" :key="h.agentId" :label="`${h.host} · ${h.ip} · ${h.os}`" :value="h.agentId" />
          </el-select>
          <div style="font-size:12px;color:#94a3b8;margin-top:4px">离线主机将在上线后收到指令（指令 30 分钟超时兜底）</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dlg.visible = false">取消</el-button>
        <el-button type="primary" :loading="dlg.loading" @click="submit">下发核查</el-button>
      </template>
    </el-dialog>

    <!-- 单机明细 -->
    <el-dialog v-model="detail.visible" :title="`${detail.host} · 核查明细`" width="920px">
      <div class="toolbar">
        <span style="font-size:12px;color:#94a3b8">未通过且支持自动修复的项可勾选提交：Agent 将 备份 → 执行 → 复核 → 失败自动回滚</span>
        <div class="spacer"></div>
        <el-button type="warning" :disabled="!fixSel.length" :loading="fixLoading" @click="submitFix">一键修复所选（{{ fixSel.length }}）</el-button>
      </div>
      <el-table :data="detail.items" stripe max-height="440" @selection-change="(s) => (fixSel = s)">
        <el-table-column type="selection" width="42" :selectable="(r) => !r.passed && r.fixable" />
        <el-table-column prop="code" label="编号" width="130" />
        <el-table-column prop="name" label="检查项" min-width="200" />
        <el-table-column prop="category" label="类别" width="100" />
        <el-table-column label="严重度" width="80">
          <template #default="{ row }">
            <span :class="['sev', `sev-${sevClass(row.severity)}`]">{{ sevText(row.severity) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="结果" width="70">
          <template #default="{ row }">
            <span :style="{ color: row.passed ? '#16a34a' : '#dc2626', fontWeight: 600 }">{{ row.passed ? '通过' : '未通过' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="actual" label="实测值 / 失败原因" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ row.message || row.actual || '—' }}</template>
        </el-table-column>
        <el-table-column label="可修复" width="70">
          <template #default="{ row }">
            <span v-if="row.passed" style="color:#94a3b8">—</span>
            <span v-else-if="row.fixable" style="color:#16a34a">支持</span>
            <span v-else style="color:#94a3b8" title="无修复脚本或需人工处理">人工</span>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- 修复任务记录 -->
    <el-dialog v-model="fixTasks.visible" title="修复任务记录" width="860px">
      <el-table :data="fixTasks.list" stripe max-height="440">
        <el-table-column prop="task_no" label="任务号" width="160" />
        <el-table-column label="类型" width="86">
          <template #default="{ row }">
            <el-tag size="small" :type="Number(row.type) === 2 ? 'warning' : 'success'" effect="plain">{{ Number(row.type) === 2 ? '软件包' : '配置类' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="140" show-overflow-tooltip />
        <el-table-column label="进度（成功/失败/总数）" width="140">
          <template #default="{ row }">{{ row.ok_records }} / {{ row.failed_records }} / {{ row.total_records }}</template>
        </el-table-column>
        <el-table-column label="审批" width="150">
          <template #default="{ row }">
            <span v-if="Number(row.type) !== 2" style="color:#94a3b8">—</span>
            <span v-else-if="row.approved" style="color:#16a34a">{{ row.approver || '已审批' }}</span>
            <el-button v-else link type="warning" size="small" @click="approveTask(row)">审批放行</el-button>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <span :style="{ color: fixStatusColor(row) }">{{ fixStatusText(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="150">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" fixed="right" width="80">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="viewFixRecords(row)">明细</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- 修复明细 -->
    <el-dialog v-model="fixRecDlg.visible" :title="`修复明细 · ${fixRecDlg.name}`" width="960px">
      <el-table :data="fixRecDlg.list" stripe max-height="480">
        <el-table-column prop="hostname" label="主机" width="130" />
        <el-table-column prop="code" label="基线项" width="130" />
        <el-table-column prop="name" label="检查项" min-width="180" show-overflow-tooltip />
        <el-table-column label="结果" width="100">
          <template #default="{ row }">
            <span :style="{ color: FIX_REC_COLOR[Number(row.status)] || '#64748b', fontWeight: 600 }">{{ FIX_REC_STATUS[Number(row.status)] || '未知' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="log" label="执行日志（备份/执行/复核/回滚）" min-width="320">
          <template #default="{ row }"><pre class="mono" style="white-space:pre-wrap;margin:0;font-size:11px">{{ row.log || '—' }}</pre></template>
        </el-table-column>
      </el-table>
    </el-dialog>
    <!-- 补丁仓库 -->
    <el-dialog v-model="patchDlg.visible" title="离线补丁仓库" width="920px">
      <div class="toolbar">
        <el-select v-model="patchDlg.osType" clearable placeholder="系统" style="width:120px" @change="loadPatches">
          <el-option label="Linux" :value="1" /><el-option label="Windows" :value="2" />
        </el-select>
        <el-input v-model="patchDlg.keyword" placeholder="包名/版本" clearable style="width:180px" @keyup.enter="loadPatches" />
        <div class="spacer"></div>
        <el-button type="primary" plain @click="patchImport.visible = true">导入补丁包</el-button>
      </div>
      <el-table :data="patchDlg.list" stripe max-height="380">
        <el-table-column label="系统" width="110">
          <template #default="{ row }">{{ row.os_type === 1 ? 'Linux' : 'Windows' }}{{ row.os_version ? ' / ' + row.os_version : '' }}</template>
        </el-table-column>
        <el-table-column prop="pkg_name" label="包名" min-width="140" />
        <el-table-column prop="target_version" label="目标版本" min-width="140" />
        <el-table-column label="类型" width="70">
          <template #default="{ row }"><el-tag size="small" effect="plain">{{ row.repo_type }}</el-tag></template>
        </el-table-column>
        <el-table-column label="大小" width="90">
          <template #default="{ row }">{{ (row.size / 1048576).toFixed(1) }} MB</template>
        </el-table-column>
        <el-table-column prop="sha256" label="SHA256" width="120" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono" style="font-size:11px">{{ String(row.sha256 || '').slice(0, 16) }}…</span></template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- 导入补丁 -->
    <el-dialog v-model="patchImport.visible" title="导入补丁包" width="520px">
      <el-form label-width="96px">
        <el-form-item label="补丁文件">
          <input type="file" @change="e => (patchImport.file = e.target.files[0])" />
        </el-form-item>
        <el-form-item label="系统" required>
          <el-select v-model="patchImport.osType" style="width:160px">
            <el-option label="Linux" :value="1" /><el-option label="Windows" :value="2" />
          </el-select>
        </el-form-item>
        <el-form-item label="系统版本">
          <el-input v-model="patchImport.osVersion" placeholder="centos7 / ubuntu2204 / win2019（空=通用）" style="width:240px" />
        </el-form-item>
        <el-form-item label="包名" required>
          <el-input v-model="patchImport.pkgName" placeholder="openssl / KB5034441" style="width:240px" />
        </el-form-item>
        <el-form-item label="目标版本" required>
          <el-input v-model="patchImport.targetVersion" placeholder="1.1.1k-26.el7_9" style="width:240px" />
        </el-form-item>
        <el-form-item label="包类型">
          <el-select v-model="patchImport.repoType" clearable placeholder="按扩展名自动识别" style="width:160px">
            <el-option label="rpm" value="rpm" /><el-option label="deb" value="deb" /><el-option label="msu" value="msu" />
          </el-select>
        </el-form-item>
        <el-alert type="info" :closable="false" show-icon
          title="导入后 sha256 入库；Agent 修复时经 filename+key 双因子校验下载" />
      </el-form>
      <template #footer>
        <el-button @click="patchImport.visible = false">取消</el-button>
        <el-button type="primary" :loading="patchImport.loading" @click="submitPatchImport">导入</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import {
  createBaselineTask, createFixTask, fetchBaseline, fetchBaselineCategoryStats, approveFixTask, fetchPatches, importPatch,
  fetchBaselineTaskDetail, fetchBaselineTemplates, fetchFixTaskRecords, fetchFixTasks, fetchHosts,
} from '../api'
import { useChart } from '../composables/useChart'

const fmtTime = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  const p = (x) => String(x).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

const msg = (t, type = 'success') => ElMessage({ message: t, type, duration: 2200 })
const rows = ref([])
const templates = ref([])
const hosts = ref([])
const catStats = ref([])

/* ---------------- 发起核查 ---------------- */

const dlg = reactive({ visible: false, loading: false, name: '', templateIds: [], agentIds: [] })

async function openCreate() {
  dlg.visible = true
  dlg.name = ''
  dlg.templateIds = []
  dlg.agentIds = []
  try {
    const [tpls, list] = await Promise.all([fetchBaselineTemplates(), fetchHosts()])
    templates.value = (tpls || []).filter((t) => t.enabled !== false)
    hosts.value = list
  } catch (e) {
    msg(e.message || '基础数据加载失败', 'error')
  }
}

async function submit() {
  if (!dlg.templateIds.length) return msg('请选择基线模板', 'warning')
  if (!dlg.agentIds.length) return msg('请选择目标主机', 'warning')
  dlg.loading = true
  try {
    await createBaselineTask(dlg.agentIds, dlg.templateIds, dlg.name || null)
    dlg.visible = false
    msg(`核查任务已下发：${dlg.agentIds.length} 台主机`)
    await load()
  } catch (e) {
    msg(e.message || '任务创建失败', 'error')
  } finally {
    dlg.loading = false
  }
}

/* ---------------- 明细 + 一键修复 ---------------- */

const detail = reactive({ visible: false, host: '', items: [], agentId: '', taskId: null })
const fixSel = ref([])
const fixLoading = ref(false)

async function viewDetail(row, onlyFailed = false) {
  detail.host = row.host
  detail.agentId = row.agentId
  detail.taskId = row.taskId
  detail.items = []
  fixSel.value = []
  detail.visible = true
  try {
    // onlyFailed = 修复入口：只拉失败项（passed=false）
    const items = await fetchBaselineTaskDetail(row.taskId, row.agentId, onlyFailed ? false : undefined)
    detail.items = items || []
  } catch (e) {
    msg(e.message || '明细加载失败', 'error')
  }
}

/** 提交修复：Agent 端 备份 → 执行 → 复核 → 失败回滚 */
async function submitFix() {
  if (!fixSel.value.length) return
  if (fixSel.value.length > 50) return msg('单次最多修复 50 项，请分批提交', 'warning')
  fixLoading.value = true
  try {
    const items = fixSel.value.map((r) => ({ agentId: detail.agentId, itemId: r.item_id }))
    const res = await createFixTask(items)
    detail.visible = false
    msg(`修复任务已下发（任务号 ${res?.taskId ?? ''}）：Agent 执行中，完成后可在「修复任务记录」查看结果`)
  } catch (e) {
    msg(e.message || '修复任务创建失败', 'error')
  } finally {
    fixLoading.value = false
  }
}

/* ---------------- 修复任务记录 ---------------- */

const FIX_STATUS = { 0: '待执行', 1: '执行中', 2: '已完成', 3: '部分失败' }
const FIX_STATUS_COLOR = { 0: '#94a3b8', 1: '#2563eb', 2: '#16a34a', 3: '#dc2626' }
const fixStatusText = (row) => (Number(row.type) === 2 && !row.approved && Number(row.status) === 0
  ? '待审批' : FIX_STATUS[Number(row.status)] || '未知')
const fixStatusColor = (row) => (Number(row.type) === 2 && !row.approved && Number(row.status) === 0
  ? '#f59e0b' : FIX_STATUS_COLOR[Number(row.status)] || '#64748b')
const FIX_REC_STATUS = { 0: '待执行', 1: '修复成功', 2: '失败已回滚', 3: '失败未回滚', 5: '复核未通过' }
const FIX_REC_COLOR = { 0: '#94a3b8', 1: '#16a34a', 2: '#f59e0b', 3: '#dc2626', 5: '#f59e0b' }

async function approveTask(row) {
  try {
    const res = await approveFixTask(row.id, row.approver || 'admin')
    const state = res?.state === 'waiting_window' ? '已审批，等待维护窗口自动派发' : '已审批并立即派发'
    msg(`任务 ${row.task_no} ${state}`)
    openFixTasks()
  } catch (e) {
    msg(e.message || '审批失败', 'error')
  }
}

/* ---------------- 补丁仓库 ---------------- */

const patchDlg = reactive({ visible: false, list: [], osType: null, keyword: '' })
const patchImport = reactive({ visible: false, loading: false, file: null, osType: 1, osVersion: '', pkgName: '', targetVersion: '', repoType: '' })

async function openPatchRepo() {
  patchDlg.visible = true
  loadPatches()
}

async function loadPatches() {
  try {
    const res = await fetchPatches({ osType: patchDlg.osType, keyword: patchDlg.keyword })
    patchDlg.list = res?.list || []
  } catch (e) {
    msg(e.message || '补丁清单加载失败', 'error')
  }
}

async function submitPatchImport() {
  if (!patchImport.file || !patchImport.pkgName.trim() || !patchImport.targetVersion.trim()) {
    return msg('请补全文件、包名与目标版本', 'warning')
  }
  patchImport.loading = true
  try {
    const fd = new FormData()
    fd.append('file', patchImport.file)
    fd.append('osType', patchImport.osType)
    fd.append('osVersion', patchImport.osVersion)
    fd.append('pkgName', patchImport.pkgName.trim())
    fd.append('targetVersion', patchImport.targetVersion.trim())
    if (patchImport.repoType) fd.append('repoType', patchImport.repoType)
    await importPatch(fd)
    patchImport.visible = false
    msg('补丁包导入成功')
    loadPatches()
  } catch (e) {
    msg(e.message || '导入失败', 'error')
  } finally {
    patchImport.loading = false
  }
}

const fixTasks = reactive({ visible: false, list: [] })
const fixRecDlg = reactive({ visible: false, name: '', list: [] })

async function openFixTasks() {
  fixTasks.visible = true
  fixTasks.list = []
  try {
    const res = await fetchFixTasks()
    fixTasks.list = res?.list || []
  } catch (e) {
    msg(e.message || '修复任务加载失败', 'error')
  }
}

async function viewFixRecords(row) {
  fixRecDlg.name = `${row.task_no} ${row.name || ''}`
  fixRecDlg.list = []
  fixRecDlg.visible = true
  try {
    const res = await fetchFixTaskRecords(row.id)
    fixRecDlg.list = res?.list || []
  } catch (e) {
    msg(e.message || '修复明细加载失败', 'error')
  }
}

const SEV_TEXT = { 4: '严重', 3: '高', 2: '中', 1: '低' }
const SEV_CLASS = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' }
const sevText = (n) => SEV_TEXT[Number(n)] || '低'
const sevClass = (n) => SEV_CLASS[Number(n)] || 'low'

/* ---------------- 图表（真实数据） ---------------- */

const avgScore = computed(() => rows.value.length
  ? Math.round(rows.value.reduce((s, r) => s + r.rate, 0) / rows.value.length)
  : null)

const scoreEl = ref(null)
const { render: renderScore } = useChart(scoreEl, () => ({
  tooltip: { formatter: '{b}: {c} 分' },
  series: [{
    type: 'gauge', startAngle: 210, endAngle: -30, min: 0, max: 100,
    progress: { show: true, width: 14, roundCap: true, itemStyle: { color: '#2563eb' } },
    axisLine: { lineStyle: { width: 14, color: [[1, '#e4ecfd']] } },
    pointer: { show: false }, axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
    title: { offsetCenter: [0, '30%'], fontSize: 13, color: '#64748b' },
    detail: { valueAnimation: true, fontSize: 40, fontWeight: 700, offsetCenter: [0, '-5%'], color: '#0f172a', formatter: (v) => (v == null ? '—' : v) },
    data: [{ value: avgScore.value ?? 0, name: rows.value.length ? `平均合规得分（${rows.value.length} 台）` : '暂无核查数据' }],
  }],
}))

const catEl = ref(null)
const { render: renderCat } = useChart(catEl, () => ({
  grid: { left: 40, right: 16, top: 30, bottom: 26 },
  tooltip: { trigger: 'axis', formatter: (ps) => `${ps[0].name}：通过率 ${ps[0].value}%` },
  xAxis: { type: 'category', data: catStats.value.map((c) => c.category), axisLabel: { color: '#64748b', fontSize: 11 }, axisLine: { lineStyle: { color: '#e2e8f0' } } },
  yAxis: { type: 'value', max: 100, splitLine: { lineStyle: { color: '#eef2f7' } }, axisLabel: { color: '#64748b', fontSize: 11 } },
  series: [{
    type: 'bar', barWidth: 26,
    data: catStats.value.map((c) => (c.total ? Math.round((c.passed / c.total) * 100) : 0)),
    itemStyle: { color: '#2563eb', borderRadius: [4, 4, 0, 0] },
    label: { show: true, position: 'top', color: '#475569', fontSize: 11, formatter: '{c}%' },
  }],
}))

const lastSummary = computed(() => {
  if (!rows.value.length) return '暂无核查数据：点击「发起核查」创建首个任务'
  const failed = rows.value.reduce((s, r) => s + r.c + r.h + r.m + r.l, 0)
  const time = rows.value.map((r) => r.time).sort().pop()
  return `最近核查：${time} · 覆盖 ${rows.value.length} 台 · 不合规项 ${failed}`
})

/* ---------------- 加载 ---------------- */

async function load() {
  try {
    rows.value = await fetchBaseline()
    renderScore()
    if (rows.value.length && rows.value[0].taskId) {
      catStats.value = await fetchBaselineCategoryStats(rows.value[0].taskId)
    } else {
      catStats.value = []
    }
    renderCat()
  } catch (e) {
    msg(e.message || '基线数据加载失败', 'error')
  }
}

onMounted(load)
</script>

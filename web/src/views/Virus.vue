<template>
  <div>
    <div style="display:flex;gap:16px;margin-bottom:16px">
      <div class="chip"><span class="dot" style="background:#dc2626"></span><span class="n">{{ stats.findings30d }}</span><span class="l">近30日检出</span></div>
      <div class="chip"><span class="dot" style="background:#f59e0b"></span><span class="n">{{ stats.quarantined }}</span><span class="l">已隔离/删除</span></div>
      <div class="chip" style="background:#fef2f2"><span class="dot" style="background:#dc2626"></span><span class="n" style="color:#dc2626">{{ stats.todo }}</span><span class="l">待处置</span></div>
      <div class="chip"><span class="dot" style="background:#2563eb"></span><span class="n">{{ db.version }}</span><span class="l">特征库版本</span></div>
    </div>
    <div class="grid-2">
      <div class="panel">
        <h4>特征库
          <span style="float:right;display:flex;gap:8px">
            <el-button size="small" plain type="primary" :loading="pushing" @click="pushDb">推送全部 Agent</el-button>
            <el-button size="small" type="primary" :loading="importing" @click="pickFile">导入特征包</el-button>
          </span></h4>
        <el-descriptions :column="2" size="small" border>
          <el-descriptions-item label="当前版本">{{ db.version }}</el-descriptions-item>
          <el-descriptions-item label="最近更新">{{ db.updated }}</el-descriptions-item>
          <el-descriptions-item label="哈希情报">{{ db.hashCount }} 条</el-descriptions-item>
          <el-descriptions-item label="YARA 规则">{{ db.yaraCount }} 条</el-descriptions-item>
        </el-descriptions>
        <p style="font-size:12px;color:#94a3b8;line-height:1.8;margin-top:10px">特征包为 zip（manifest.json + hashes.txt），导入校验通过后自动推送全部 Agent；Agent 限速下载并原子替换，失败沿用本地旧库。</p>
        <input ref="fileInput" type="file" accept=".zip" style="display:none" @change="onFileChange" />
      </div>
      <div class="panel">
        <h4>发起扫描</h4>
        <div style="display:flex;gap:10px;margin-bottom:10px">
          <el-button type="primary" @click="openScan(1)">快速扫描</el-button>
          <el-button type="warning" plain @click="openScan(2)">全盘扫描</el-button>
          <el-button plain @click="openScan(3)">自定义路径</el-button>
        </div>
        <p style="font-size:12px;color:#94a3b8;line-height:1.8">快速扫描覆盖关键路径（/tmp、启动项、下载目录等），分钟级完成；全盘扫描默认 IO 限速 10MB/s，建议在维护窗口执行；实时防护随文件事件自动触发。</p>
      </div>
    </div>
    <div class="panel">
      <el-tabs v-model="tab" @tab-change="onTabChange">
        <el-tab-pane label="检出处置" name="findings">
          <div class="toolbar">
            <el-select v-model="statusFilter" placeholder="处置状态" clearable style="width:130px" @change="loadFindings">
              <el-option label="待处置" value="0" /><el-option label="已隔离" value="1" /><el-option label="已删除" value="2" /><el-option label="已恢复" value="3" /></el-select>
            <div class="spacer"></div>
            <el-button type="danger" plain :disabled="!canBatch('todo')" @click="act(selIds(), 'quarantine')">批量隔离（{{ selFindings.length }}）</el-button>
            <el-button type="danger" plain :disabled="!canBatch('todo')" @click="act(selIds(), 'delete')">批量删除</el-button>
            <el-button plain :disabled="!selFindings.length" @click="act(selIds(), 'whitelist')">批量加白</el-button>
          </div>
          <el-table :data="findings" stripe @selection-change="s => selFindings = s">
            <el-table-column type="selection" width="42" />
            <el-table-column label="文件路径" min-width="230">
              <template #default="{ row }">
                <span class="mono">{{ row.path }}</span>
                <div v-if="row.sha256" class="mono" style="font-size:11px;color:#94a3b8">{{ row.sha256 }}</div>
              </template>
            </el-table-column>
            <el-table-column prop="name" label="检出名" width="200" />
            <el-table-column label="引擎" width="90">
              <template #default="{ row }"><el-tag size="small" effect="plain" type="info">{{ row.engine }}</el-tag></template>
            </el-table-column>
            <el-table-column label="级别" width="80">
              <template #default="{ row }"><el-tag size="small" :type="sevType(row.sev)" :effect="row.sev === 'critical' ? 'dark' : 'light'">{{ sevLabel(row.sev) }}</el-tag></template>
            </el-table-column>
            <el-table-column prop="host" label="主机" width="130" />
            <el-table-column label="状态" width="90">
              <template #default="{ row }">
                <el-tag size="small" :type="statusTag(row.status).type" effect="plain">{{ statusTag(row.status).label }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="time" label="发现时间" width="120" />
            <el-table-column label="操作" width="180" fixed="right">
              <template #default="{ row }">
                <template v-if="row.status === 'todo'">
                  <el-button link type="danger" size="small" @click="act([row.id], 'quarantine')">隔离</el-button>
                  <el-button link type="danger" size="small" @click="act([row.id], 'delete')">删除</el-button>
                  <el-button link size="small" @click="act([row.id], 'whitelist')">加白</el-button>
                </template>
                <template v-else-if="row.status === 'quarantined'">
                  <el-button link type="success" size="small" @click="act([row.id], 'restore')">恢复</el-button>
                  <el-button link type="danger" size="small" @click="act([row.id], 'delete')">删除</el-button>
                </template>
                <span v-else style="font-size:12px;color:#94a3b8">—</span>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="扫描任务" name="tasks">
          <el-table :data="tasks" stripe>
            <el-table-column prop="taskNo" label="任务号" width="180"><template #default="{ row }"><span class="mono">{{ row.taskNo }}</span></template></el-table-column>
            <el-table-column prop="name" label="任务名" min-width="160" />
            <el-table-column label="模式" width="90">
              <template #default="{ row }">
                <el-tag size="small" effect="plain" :type="row.mode === 2 ? 'warning' : row.mode === 3 ? 'primary' : 'success'">{{ modeLabel(row.mode) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="进度" width="180">
              <template #default="{ row }"><el-progress :percentage="row.progress" :status="row.status === 3 ? 'exception' : row.status === 2 ? 'success' : undefined" /></template>
            </el-table-column>
            <el-table-column label="检出" width="70">
              <template #default="{ row }"><span :style="row.findings > 0 ? 'color:#dc2626;font-weight:600' : ''">{{ row.findings }}</span></template>
            </el-table-column>
            <el-table-column label="状态" width="90">
              <template #default="{ row }">
                <el-tag size="small" effect="plain" :type="row.status === 2 ? 'success' : row.status === 3 ? 'danger' : 'primary'">{{ taskStatusLabel(row.status) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="createdAt" label="创建时间" width="120" />
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="白名单" name="whitelist">
          <div class="toolbar">
            <span style="font-size:12px;color:#94a3b8">hash 型全局生效（跨路径），path 型按路径前缀匹配；加白后扫描结果落库自动过滤</span>
            <div class="spacer"></div>
            <el-button type="primary" plain @click="wlDlg = true">新增白名单</el-button>
          </div>
          <el-table :data="whitelist" stripe>
            <el-table-column label="类型" width="90">
              <template #default="{ row }"><el-tag size="small" effect="plain" :type="row.type === 'hash' ? 'info' : 'primary'">{{ row.type === 'hash' ? '哈希' : '路径' }}</el-tag></template>
            </el-table-column>
            <el-table-column label="内容" min-width="260"><template #default="{ row }"><span class="mono">{{ row.value }}</span></template></el-table-column>
            <el-table-column prop="remark" label="备注" min-width="180" />
            <el-table-column prop="createdAt" label="创建时间" width="120" />
            <el-table-column label="操作" width="90" fixed="right">
              <template #default="{ row }">
                <el-button link type="danger" size="small" @click="removeWl(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>

  <!-- 发起扫描对话框 -->
  <el-dialog v-model="scanDlg" :title="'发起' + modeLabel(scanForm.mode) + '扫描'" width="560px">
    <el-form label-width="96px">
      <el-form-item label="目标主机">
        <el-select v-model="scanForm.agentIds" multiple filterable placeholder="选择主机（可多选）" style="width:100%">
          <el-option v-for="a in agents" :key="a.id" :label="a.name + '（' + a.ip + '）'" :value="a.id" />
        </el-select>
      </el-form-item>
      <el-form-item label="扫描模式">
        <el-radio-group v-model="scanForm.mode">
          <el-radio-button :value="1">快速</el-radio-button>
          <el-radio-button :value="2">全盘</el-radio-button>
          <el-radio-button :value="3">自定义</el-radio-button>
        </el-radio-group>
      </el-form-item>
      <el-form-item v-if="scanForm.mode === 3" label="扫描路径">
        <el-input v-model="scanForm.pathsText" type="textarea" :rows="3" placeholder="每行一个绝对路径，如 /tmp 或 D:\home" />
      </el-form-item>
      <el-alert v-if="scanForm.mode === 2" type="warning" :closable="false" show-icon
        title="全盘扫描 IO 限速 10MB/s，大主机可能耗时小时级，建议在维护窗口执行" />
      <el-alert v-else type="info" :closable="false" show-icon
        title="扫描在 Agent 后台执行，结果实时上报；检出默认自动隔离" />
    </el-form>
    <template #footer>
      <el-button @click="scanDlg = false">取消</el-button>
      <el-button type="primary" :loading="scanSubmitting" @click="submitScan">开始扫描</el-button>
    </template>
  </el-dialog>

  <!-- 新增白名单对话框 -->
  <el-dialog v-model="wlDlg" title="新增白名单" width="520px">
    <el-form label-width="96px">
      <el-form-item label="类型">
        <el-radio-group v-model="wlForm.type">
          <el-radio-button value="hash">哈希（SHA256）</el-radio-button>
          <el-radio-button value="path">路径</el-radio-button>
        </el-radio-group>
      </el-form-item>
      <el-form-item :label="wlForm.type === 'hash' ? 'SHA256' : '路径'">
        <el-input v-model="wlForm.value" :placeholder="wlForm.type === 'hash' ? '64 位十六进制 SHA256' : '如 /opt/business/bin'" />
      </el-form-item>
      <el-form-item label="备注">
        <el-input v-model="wlForm.remark" placeholder="选填，如业务自研程序误报" />
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button @click="wlDlg = false">取消</el-button>
      <el-button type="primary" :loading="wlSubmitting" @click="submitWl">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  fetchVirus, fetchVirusTasks, fetchVirusWhitelist, createVirusTask, virusAct,
  importVirusDb, pushVirusDb, addVirusWhitelist, removeVirusWhitelist, fetchAgentsForSelect,
} from '../api'
import { sevType, sevLabel } from '../utils/format'

const tab = ref('findings')
const db = reactive({ version: '—', updated: '—', hashCount: '—', yaraCount: '—' })
const stats = reactive({ findings30d: 0, quarantined: 0, todo: 0 })
const findings = ref([])
const selFindings = ref([])
const statusFilter = ref('')
const tasks = ref([])
const whitelist = ref([])
const agents = ref([])

const scanDlg = ref(false)
const scanSubmitting = ref(false)
const scanForm = ref({ agentIds: [], mode: 1, pathsText: '' })

const wlDlg = ref(false)
const wlSubmitting = ref(false)
const wlForm = ref({ type: 'hash', value: '', remark: '' })

const fileInput = ref(null)
const importing = ref(false)
const pushing = ref(false)

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

const selIds = () => selFindings.value.map(f => f.id)
const canBatch = (st) => selFindings.value.length && selFindings.value.every(f => f.status === st)

const statusTag = (s) => ({
  todo: { type: 'danger', label: '待处置' },
  quarantined: { type: 'success', label: '已隔离' },
  deleted: { type: 'info', label: '已删除' },
  restored: { type: 'info', label: '已恢复' },
}[s] || { type: 'info', label: s })

const modeLabel = (m) => ({ 1: '快速', 2: '全盘', 3: '自定义' }[m] || '未知')
const taskStatusLabel = (s) => ({ 1: '执行中', 2: '已完成', 3: '部分失败' }[s] || '未知')

const fmt = (iso) => iso ? String(iso).replace('T', ' ').slice(0, 16) : '—'

/* ---------- 数据加载 ---------- */

const loadFindings = async () => {
  const res = await fetchVirus(statusFilter.value)
  Object.assign(db, res.db)
  if (statusFilter.value === '' || statusFilter.value == null) Object.assign(stats, res.stats)
  findings.value = res.findings
  selFindings.value = []
}

const loadTasks = async () => {
  const data = await fetchVirusTasks()
  tasks.value = (data?.list || []).map(t => ({
    taskNo: t.task_no,
    name: t.name,
    mode: Number(t.mode),
    progress: Number(t.progress || 0),
    findings: Number(t.findings || 0),
    status: Number(t.status),
    createdAt: fmt(t.created_at),
  }))
}

const loadWhitelist = async () => {
  const list = await fetchVirusWhitelist()
  whitelist.value = (list || []).map(w => ({
    id: w.id, type: w.type, value: w.value, remark: w.remark || '', createdAt: fmt(w.created_at),
  }))
}

const onTabChange = (name) => {
  if (name === 'tasks') loadTasks()
  else if (name === 'whitelist') loadWhitelist()
  else loadFindings()
}

/* ---------- 扫描任务 ---------- */

const openScan = async (mode) => {
  if (!agents.value.length) agents.value = await fetchAgentsForSelect()
  scanForm.value = { agentIds: [], mode, pathsText: '' }
  scanDlg.value = true
}

const submitScan = async () => {
  const form = scanForm.value
  if (!form.agentIds.length) return ElMessage({ message: '请选择目标主机', type: 'warning' })
  const paths = form.pathsText.split('\n').map(p => p.trim()).filter(Boolean)
  if (form.mode === 3 && !paths.length) return ElMessage({ message: '自定义扫描需填写路径', type: 'warning' })
  scanSubmitting.value = true
  try {
    await createVirusTask(form.agentIds, form.mode, paths)
    scanDlg.value = false
    msg('扫描任务已下发，结果将实时上报')
    tab.value = 'tasks'
    setTimeout(loadTasks, 3000)
  } catch (e) {
    ElMessage({ message: e?.message || '任务创建失败', type: 'error' })
  } finally {
    scanSubmitting.value = false
  }
}

/* ---------- 检出处置 ---------- */

const act = async (ids, action) => {
  if (!ids || !ids.length) return
  const labels = {
    quarantine: '隔离', delete: '删除', restore: '恢复', whitelist: '加白',
  }
  const warnings = {
    delete: '删除不可恢复，将直接移除源文件，确定继续？',
    whitelist: '加白后该哈希全局生效（跨路径），后续扫描自动过滤，确定继续？',
  }
  try {
    if (warnings[action]) await ElMessageBox.confirm(warnings[action], `确认${labels[action]}`, { type: 'warning' })
    await virusAct(ids, action)
    msg(`已下发${labels[action]}指令（${ids.length} 项）`)
    loadFindings()
  } catch (e) {
    if (e !== 'cancel' && e?.message) ElMessage({ message: e.message, type: 'error' })
  }
}

/* ---------- 特征库 ---------- */

const pickFile = () => fileInput.value?.click()

const onFileChange = async (e) => {
  const file = e.target.files?.[0]
  e.target.value = ''
  if (!file) return
  importing.value = true
  try {
    const res = await importVirusDb(file)
    msg(`特征库 ${res?.db_version || ''} 导入成功：哈希 ${res?.hash_count || 0} 条 / YARA ${res?.rule_count || 0} 条，已推送全部 Agent`)
    loadFindings()
  } catch (err) {
    ElMessage({ message: err?.message || '导入失败', type: 'error' })
  } finally {
    importing.value = false
  }
}

const pushDb = async () => {
  pushing.value = true
  try {
    await pushVirusDb()
    msg('特征库推送指令已下发，Agent 将限速下载并原子替换')
  } catch (e) {
    ElMessage({ message: e?.message || '推送失败', type: 'error' })
  } finally {
    pushing.value = false
  }
}

/* ---------- 白名单 ---------- */

const submitWl = async () => {
  if (!wlForm.value.value.trim()) return ElMessage({ message: '请填写白名单内容', type: 'warning' })
  wlSubmitting.value = true
  try {
    await addVirusWhitelist(wlForm.value.type, wlForm.value.value.trim(), wlForm.value.remark.trim() || null)
    wlDlg.value = false
    wlForm.value = { type: 'hash', value: '', remark: '' }
    msg('白名单已保存')
    loadWhitelist()
  } catch (e) {
    ElMessage({ message: e?.message || '保存失败', type: 'error' })
  } finally {
    wlSubmitting.value = false
  }
}

const removeWl = async (row) => {
  try {
    await ElMessageBox.confirm(`删除后该${row.type === 'hash' ? '哈希' : '路径'}将恢复检测，确定删除？`, '删除白名单', { type: 'warning' })
    await removeVirusWhitelist(row.id)
    msg('白名单已删除')
    loadWhitelist()
  } catch (e) {
    if (e !== 'cancel' && e?.message) ElMessage({ message: e.message, type: 'error' })
  }
}

onMounted(loadFindings)
</script>

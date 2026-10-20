<template>
  <div>
    <el-alert v-if="loadError" :title="loadError" type="error" :closable="false" show-icon style="margin-bottom:12px" />
    <div style="display:flex;flex-wrap:wrap;gap:16px;margin-bottom:16px">
      <div class="chip"><span class="dot" style="background:#dc2626"></span><span class="n">{{ stats.findings30d }}</span><span class="l">近30日检出</span></div>
      <div class="chip"><span class="dot" style="background:#f59e0b"></span><span class="n">{{ stats.quarantined }}</span><span class="l">已隔离/删除</span></div>
      <div class="chip" style="background:#fef2f2"><span class="dot" style="background:#dc2626"></span><span class="n" style="color:#dc2626">{{ stats.todo }}</span><span class="l">待处置</span></div>
      <div class="chip version-chip"><span class="l">特征库版本</span><span class="n">{{ db.version }}</span></div>
    </div>
    <div class="grid-2">
      <div class="panel">
        <h4>内置特征库
          <span v-if="canWrite" style="float:right;display:flex;flex-wrap:wrap;gap:8px">
            <el-button size="small" plain type="primary" :loading="pushing" @click="pushDb">推送全部 Agent</el-button>
            <el-button size="small" type="primary" :loading="importing" @click="pickFile">导入特征包</el-button>
          </span></h4>
        <el-descriptions :column="2" size="small" border>
          <el-descriptions-item label="当前版本">{{ db.version }}</el-descriptions-item>
          <el-descriptions-item label="最近更新">{{ db.updated }}</el-descriptions-item>
          <el-descriptions-item label="哈希情报">{{ db.hashCount }} 条</el-descriptions-item>
          <el-descriptions-item label="内部检测规则">{{ db.ruleCount }} 条</el-descriptions-item>
        </el-descriptions>
        <p style="font-size:12px;color:#94a3b8;line-height:1.8;margin-top:10px">特征包为 zip（manifest.json + hashes.txt），导入校验通过后自动推送全部 Agent；Agent 限速下载并原子替换，失败沿用本地旧库。</p>
        <input ref="fileInput" type="file" accept=".zip" style="display:none" @change="onFileChange" />
      </div>
      <div class="panel">
        <h4>发起扫描</h4>
        <div v-if="canWrite" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px">
          <el-button type="primary" @click="openScan(1)">快速扫描</el-button>
          <el-button type="warning" plain @click="openScan(2)">全盘扫描</el-button>
          <el-button plain @click="openScan(3)">自定义路径</el-button>
        </div>
        <p class="coverage-note">扫描有时间、文件数和读取总量上限。SHA256 检查不超过 500 MiB 的普通文件；内部规则只检查符合规则范围文件的前 2 MiB，不解包压缩档案。符号链接、特殊文件、虚拟文件系统和 Agent 自身工作目录被排除。零检出不代表安全。</p>
      </div>
    </div>
    <ClamavStatus />
    <div class="panel">
      <h4>周期病毒检测</h4>
      <div class="toolbar">
        <el-switch v-model="realtime.enabled" :disabled="!canWrite || realtime.saving" active-text="启用" />
        <el-select v-model="realtime.action" :disabled="!canWrite || realtime.saving" style="width:150px"><el-option label="仅告警" value="alert_only" /><el-option label="检出后隔离" value="quarantine" /></el-select>
        <el-button v-if="canWrite" type="primary" :loading="realtime.saving" @click="saveRealtime">保存周期策略</el-button>
      </div>
      <p class="coverage-note">独立于勒索诱饵开关，支持文件事件监控的 Agent 根据原生事件检查新增或修改文件，并周期补查。监听覆盖、积压和中断请查看实时防护页；短暂文件和超出预算的内容可能未检查。策略收到后生效，离线和旧 Agent 不保证已切换。</p>
    </div>
    <div class="panel">
      <el-tabs v-model="tab" @tab-change="onTabChange">
        <el-tab-pane label="检出处置" name="findings">
          <div class="toolbar">
            <el-select v-model="statusFilter" placeholder="处置状态" clearable style="width:130px" @change="loadFindings">
              <el-option label="待处置" value="0" /><el-option label="已隔离" value="1" /><el-option label="已删除" value="2" /><el-option label="已恢复" value="3" /></el-select>
            <div class="spacer"></div>
            <el-button v-if="canWrite" type="danger" plain :disabled="!canBatch('todo')" @click="act(selIds(), 'quarantine')">批量隔离（{{ selFindings.length }}）</el-button>
            <el-button v-if="canWrite" type="danger" plain :disabled="!canBatch('todo')" @click="act(selIds(), 'delete')">批量删除</el-button>
            <el-button v-if="canWrite" plain :disabled="!selFindings.length || selFindings.length > 32 || selFindings.some(f => f.pending)" @click="act(selIds(), 'whitelist')">批量加白</el-button>
          </div>
          <el-table :data="findings" stripe @selection-change="s => selFindings = s">
            <el-table-column type="selection" width="42" />
            <el-table-column label="文件路径" min-width="230">
              <template #default="{ row }">
                <span class="mono">{{ row.path }}</span>
                <div v-if="row.sha256" class="mono digest">{{ row.sha256 }}</div>
                <div v-if="row.quarantineId" class="digest">隔离编号：{{ row.quarantineId }}</div>
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
            <el-table-column label="状态" width="180">
              <template #default="{ row }">
                <el-tag size="small" :type="statusTag(row.status).type" effect="plain">{{ statusTag(row.status).label }}</el-tag>
                <div v-if="row.pending">处置待确认</div>
                <div v-if="['failed','timeout'].includes(row.lastActionState)" class="action-failure">{{ row.lastActionState === 'timeout' ? '处置超时，结果未确认' : '处置失败，请查看历史' }}</div>
                <div v-if="row.whitelisted">当前哈希已加白</div>
                <div v-if="row.actionError" class="action-failure">文件处置未完成：{{ row.actionError }}</div>
              </template>
            </el-table-column>
            <el-table-column prop="time" label="发现时间" width="120" />
            <el-table-column label="操作" width="180" fixed="right">
              <template #default="{ row }">
                <el-button link size="small" @click="showHistory(row)">处置历史</el-button>
                <template v-if="canWrite && !row.pending && row.executionSupported && row.status === 'todo'">
                  <el-button v-if="!row.quarantineId" link type="danger" size="small" @click="act([row.id], 'quarantine')">隔离</el-button>
                  <el-button v-else link type="success" size="small" @click="act([row.id], 'restore')">复核恢复</el-button>
                  <el-button link type="danger" size="small" @click="act([row.id], 'delete')">删除</el-button>
                  <el-button link size="small" @click="act([row.id], 'whitelist')">加白</el-button>
                </template>
                <template v-else-if="canWrite && !row.pending && row.executionSupported && row.status === 'quarantined' && row.quarantineId">
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
            <el-table-column label="引擎" width="100"><template #default="{ row }">{{ engineLabel(row.engine) }}</template></el-table-column>
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
            <el-table-column label="覆盖与证据" width="150" fixed="right"><template #default="{ row }"><el-button link type="primary" @click="showEvidence(row)">逐主机证据</el-button><div>{{ row.completeHosts }}/{{ row.totalHosts }} 台完成</div></template></el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane label="白名单" name="whitelist">
          <div class="toolbar">
            <span class="coverage-note">哈希按内容放行，路径放行该目录及子路径。Agent 收到策略后应用；已有检出和处置证据保留，加白不自动恢复隔离文件。</span>
            <div class="spacer"></div>
            <el-button v-if="canWrite" type="primary" plain @click="wlDlg = true">新增白名单</el-button>
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
                <el-button v-if="canWrite" link type="danger" size="small" @click="removeWl(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>

  <!-- 发起扫描对话框 -->
  <el-dialog v-model="scanDlg" :title="'发起' + modeLabel(scanForm.mode) + '扫描'" width="min(560px, calc(100vw - 24px))">
    <el-form label-width="96px">
      <el-form-item label="扫描引擎"><el-select v-model="scanForm.engine" @change="changeEngine" style="width:100%"><el-option label="内置特征库" value="builtin" /><el-option label="ClamAV" value="clamav" /></el-select></el-form-item>
      <p v-if="scanForm.engine === 'clamav'" class="coverage-note">仅可选择 ClamAV 就绪的主机；单文件最多 20 MiB，压缩内容受引擎配置限制。引擎状态在提交时重新检查。</p>
      <el-alert v-if="clamavError && scanForm.engine === 'clamav'" :title="clamavError" type="error" :closable="false"><el-button size="small" @click="changeEngine">重试</el-button></el-alert>
      <el-form-item label="目标主机">
        <el-select v-model="scanForm.agentIds" multiple :multiple-limit="500" filterable placeholder="选择主机（可多选）" style="width:100%">
          <el-option v-for="a in agents" :key="a.id" :label="a.name + '（' + a.ip + '）' + (eligible(a) ? '' : scanForm.engine === 'clamav' ? ' · ClamAV 未就绪' : ' · 需更新 Agent')" :value="a.id" :disabled="!eligible(a)" />
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
        title="扫描源文件读取限速 10 MiB/s，隔离另有验证和复制开销；最多执行 2 小时，建议在维护窗口执行" />
      <el-alert v-else type="info" :closable="false" show-icon
        title="扫描在 Agent 后台执行，结果实时上报；检出默认自动隔离" />
    </el-form>
    <template #footer>
      <el-button @click="scanDlg = false">取消</el-button>
      <el-button type="primary" :loading="scanSubmitting || clamavLoading" :disabled="scanForm.engine === 'clamav' && !!clamavError" @click="submitScan">开始扫描</el-button>
    </template>
  </el-dialog>

  <!-- 新增白名单对话框 -->
  <el-dialog v-model="wlDlg" title="新增白名单" width="min(520px, calc(100vw - 24px))">
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

  <el-dialog v-model="detail.visible" :title="detail.kind === 'evidence' ? '逐主机扫描证据' : '文件处置历史'" width="min(860px, calc(100vw - 24px))">
    <el-alert v-if="detail.error" :title="detail.error" type="error" :closable="false" />
    <p v-if="detail.loading">正在读取证据…</p>
    <template v-else-if="detail.kind === 'evidence'">
      <p class="coverage-note">完成仅表示声明范围内的扫描结束。未检查、读取错误和预算限制请逐项核对；迟到回报保留原任务状态。</p>
      <div v-for="item in detail.rows" :key="item.agent_id" class="evidence-item">
        <strong>{{ item.agent_id }}</strong> · {{ evidenceLabel(item.state) }} <el-tag v-if="Number(item.late) === 1" size="small" type="warning">迟到证据</el-tag>
        <p class="digest">固定版本：{{ item.expected_engine_version || '旧任务未记录' }}</p>
        <template v-if="item.evidence && typeof item.evidence === 'object'">
          <p>已扫描 {{ item.evidence.files_scanned || 0 }}，跳过 {{ item.evidence.files_skipped || 0 }}，失败 {{ item.evidence.files_failed || 0 }}；读取 {{ item.evidence.bytes_read || 0 }} 字节。</p>
          <p class="digest">{{ engineLabel(item.evidence.scan_engine || 'builtin') }} · 执行版本 {{ item.evidence.db_version || '未报告' }}；证据摘要 {{ item.evidence_sha256 || '未收到回报' }}</p>
          <p v-if="item.evidence.error" class="action-failure">{{ item.evidence.error }}</p>
          <p v-for="(issue, index) in item.evidence.issues || []" :key="index" class="digest">{{ issue.path || '任务范围' }}：{{ issueLabel(issue.code) }}</p>
        </template>
      </div>
      <el-empty v-if="!detail.rows.length" description="此任务没有可复核的逐主机证据，旧任务覆盖未知" />
    </template>
    <template v-else>
      <p class="coverage-note">状态按每个文件的回执更新。失败或超时保留上次确认状态，可能已有部分本机操作；复核后再重试。</p>
      <div v-for="item in detail.rows" :key="item.id" class="evidence-item">
        <strong>{{ actionLabel(item.action) }}</strong> · {{ actionStateLabel(item.state) }} · {{ item.username || item.actor || '系统' }}
        <p>{{ fmt(item.created_at) }} <span v-if="item.finished_at">→ {{ fmt(item.finished_at) }}</span></p>
        <p v-if="item.error" class="action-failure">{{ item.error }}</p>
        <p v-if="item.evidence" class="digest">首次检出：{{ item.evidence.source }}；SHA256 {{ item.evidence.sha256 }}；隔离编号 {{ item.evidence.quarantine_id || '未隔离' }}</p>
        <p v-if="item.request_evidence" class="digest">操作对象：{{ item.request_evidence.path }}；SHA256 {{ item.request_evidence.sha256 }}；请求隔离编号 {{ item.request_evidence.quarantine_id || '无' }}</p>
        <p v-if="item.receipt?.target?.quarantine_id" class="digest">回执隔离编号 {{ item.receipt.target.quarantine_id }}</p>
      </div>
      <el-empty v-if="!detail.rows.length" description="此记录没有可复核的处置历史，旧文件状态未知" />
    </template>
  </el-dialog>
</template>

<script setup>
import { onMounted, onUnmounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  fetchVirus, fetchVirusTasks, fetchVirusWhitelist, createVirusTask, virusAct,
  importVirusDb, pushVirusDb, addVirusWhitelist, removeVirusWhitelist, fetchAgentsForSelect,
  fetchClamavStatus, getUser, fetchVirusTaskEvidence, fetchVirusActionHistory, updateVirusRealtime,
} from '../api'
import ClamavStatus from '../components/ClamavStatus.vue'
import { clamavIssueLabel } from '../utils/clamav'
import { sevType, sevLabel } from '../utils/format'

const tab = ref('findings')
const role = getUser()?.role ?? getUser()?.roleName
const canWrite = role === 'admin' || role === 'operator'
const loadError = ref('')
const realtime = reactive({ enabled: true, action: 'quarantine', saving: false })
const detail = reactive({ visible: false, kind: '', loading: false, rows: [], error: '', serial: 0 })
const db = reactive({ version: '—', updated: '—', hashCount: '—', ruleCount: '—' })
const stats = reactive({ findings30d: 0, quarantined: 0, todo: 0 })
const findings = ref([])
const selFindings = ref([])
const statusFilter = ref('')
const tasks = ref([])
const whitelist = ref([])
const agents = ref([])
const clamavReady = ref(new Set())
const clamavLoading = ref(false), clamavError = ref('')
let clamavSerial = 0
const engineLabel = engine => engine === 'clamav' ? 'ClamAV' : '内置特征库'
const eligible = a => a.virusExecutionContract === 2 && (scanForm.value.engine !== 'clamav' || clamavReady.value.has(a.id))

const scanDlg = ref(false)
const scanSubmitting = ref(false)
const scanForm = ref({ agentIds: [], mode: 1, pathsText: '', engine: 'builtin' })

const wlDlg = ref(false)
const wlSubmitting = ref(false)
const wlForm = ref({ type: 'hash', value: '', remark: '' })

const fileInput = ref(null)
const importing = ref(false)
const pushing = ref(false)

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

const selIds = () => selFindings.value.map(f => f.id)
const canBatch = (st) => selFindings.value.length && selFindings.value.length <= 32 && selFindings.value.every(f => f.status === st && !f.pending && f.executionSupported)

const statusTag = (s) => ({
  todo: { type: 'danger', label: '待处置' },
  quarantined: { type: 'success', label: '已隔离' },
  deleted: { type: 'info', label: '已删除' },
  restored: { type: 'info', label: '已恢复' },
  whitelisted: { type: 'info', label: '旧加白，文件状态未知' },
}[s] || { type: 'info', label: s })

const modeLabel = (m) => ({ 1: '快速', 2: '全盘', 3: '自定义' }[m] || '未知')
const taskStatusLabel = (s) => ({ 1: '执行中', 2: '限定范围完成', 3: '未完整完成' }[s] || '覆盖未知')
const evidenceLabel = s => ({ pending: '待回报', complete: '限定范围完成', partial: '部分覆盖', failed: '失败', timeout: '超时' }[s] || '覆盖未知')
const actionLabel = s => ({ quarantine: '隔离', quarantined: '自动隔离', alert_only: '检出告警', delete: '删除', restore: '恢复', whitelist: '加白' }[s] || s)
const actionStateLabel = s => ({ observed: '首次检出证据', pending: '待确认', succeeded: '已确认成功', failed: '失败', timeout: '超时，结果未确认', committed: '策略已保存' }[s] || s)
const issueLabel = s => ({ unreadable: '无法读取', root_unavailable: '扫描路径不可用', read_failed_or_changed: '读取失败或文件发生变化', budget_exhausted: '达到扫描预算', no_signatures: '没有有效特征', signature_version_changed: '特征库版本已变化', depth_limit: '目录深度超过上限', oversize: '文件超过大小上限', report_path_limit: '路径超过报告长度上限' }[s] || clamavIssueLabel(s))

const fmt = (iso) => iso ? String(iso).replace('T', ' ').slice(0, 16) : '—'

/* ---------- 数据加载 ---------- */

const loadFindings = async (refreshPolicy = true) => {
  try {
  const res = await fetchVirus(statusFilter.value)
  Object.assign(db, res.db)
  if (statusFilter.value === '' || statusFilter.value == null) Object.assign(stats, res.stats)
  findings.value = res.findings
  selFindings.value = []
  if (refreshPolicy === true) {
    realtime.enabled = Number(res.stats.realtime.realtime_enabled) === 1
    realtime.action = res.stats.realtime.realtime_action || 'quarantine'
  }
  loadError.value = ''
  } catch (e) { loadError.value = e?.message || '读取检测数据失败' }
}

const loadTasks = async () => {
  try {
  const data = await fetchVirusTasks()
  tasks.value = (data?.list || []).map(t => ({
    id: t.id, totalHosts: Number(t.total_hosts || 0), completeHosts: Number(t.complete_hosts || 0),
    taskNo: t.task_no,
    name: t.name,
    mode: Number(t.mode), engine: t.scan_engine || 'builtin',
    progress: Number(t.progress || 0),
    findings: Number(t.findings || 0),
    status: Number(t.status),
    createdAt: fmt(t.created_at),
  }))
  } catch (e) { loadError.value = e?.message || '读取任务失败' }
}

const loadWhitelist = async () => {
  try {
  const list = await fetchVirusWhitelist()
  whitelist.value = (list || []).map(w => ({
    id: w.id, type: w.type, value: w.value, remark: w.remark || '', createdAt: fmt(w.created_at),
  }))
  } catch (e) { loadError.value = e?.message || '读取白名单失败' }
}

const onTabChange = (name) => {
  if (name === 'tasks') loadTasks()
  else if (name === 'whitelist') loadWhitelist()
  else loadFindings()
}

/* ---------- 扫描任务 ---------- */

const changeEngine = async () => {
  const serial = ++clamavSerial
  scanForm.value.agentIds = []
  clamavReady.value = new Set(); clamavError.value = ''; clamavLoading.value = false
  if (scanForm.value.engine !== 'clamav') return
  clamavLoading.value = true
  try {
    const ready = new Set()
    for (let page = 1, total = 1; (page - 1) * 100 < total; page++) {
      const data = await fetchClamavStatus(page, 100)
      if (serial !== clamavSerial) return
      total = Number(data.total || 0)
      for (const row of data.items || []) if (row.state === 'ready') ready.add(row.agent_id)
      if (!data.items?.length || page >= 1000) break
    }
    if (serial === clamavSerial) clamavReady.value = ready
  } catch (e) { if (serial === clamavSerial) clamavError.value = e.message || 'ClamAV 状态加载失败' }
  finally { if (serial === clamavSerial) clamavLoading.value = false }
}
const openScan = async (mode) => {
  try {
    agents.value = await fetchAgentsForSelect()
    scanForm.value = { agentIds: [], mode, pathsText: '', engine: 'builtin' }
    changeEngine()
    scanDlg.value = true
  } catch (e) { ElMessage.error(e.message || '主机状态加载失败') }
}

const submitScan = async () => {
  const form = scanForm.value
  if (clamavLoading.value) return
  if (form.agentIds.some(id => !agents.value.some(a => a.id === id && eligible(a)))) return ElMessage.warning('目标主机当前不可用，请重新选择')
  if (!form.agentIds.length) return ElMessage({ message: '请选择目标主机', type: 'warning' })
  const paths = form.pathsText.split('\n').map(p => p.trim()).filter(Boolean)
  if (form.mode === 3 && !paths.length) return ElMessage({ message: '自定义扫描需填写路径', type: 'warning' })
  scanSubmitting.value = true
  try {
    await createVirusTask(form.agentIds, form.mode, paths, undefined, form.engine)
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
    delete: '删除会永久移除经摘要校验的文件或隔离对象，确定继续？',
    whitelist: '加白后该哈希全局生效（跨路径），后续扫描自动过滤，确定继续？',
  }
  try {
    if (warnings[action]) await ElMessageBox.confirm(warnings[action], `确认${labels[action]}`, { type: 'warning' })
    await virusAct(ids, action)
    msg(action === 'whitelist' ? '白名单策略已保存，已有证据保留' : `已提交${labels[action]}（${ids.length} 项），等待每个文件的回执`)
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
    msg(`特征库 ${res?.dbVersion || ''} 导入成功：哈希 ${res?.hashCount || 0} 条 / 内部规则 ${res?.ruleCount || 0} 条，已提交推送`)
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

const saveRealtime = async () => {
  realtime.saving = true
  try { await updateVirusRealtime(realtime.enabled, realtime.action); msg('周期策略已保存，Agent 收到后生效') }
  catch (e) { ElMessage.error(e?.message || '保存周期策略失败') }
  finally { realtime.saving = false }
}
const showDetail = async (kind, id) => {
  const serial = ++detail.serial
  Object.assign(detail, { visible: true, kind, loading: true, rows: [], error: '' })
  try { const rows = await (kind === 'evidence' ? fetchVirusTaskEvidence(id) : fetchVirusActionHistory(id)); if (serial === detail.serial) detail.rows = rows || [] }
  catch (e) { if (serial === detail.serial) detail.error = e?.message || '读取证据失败' }
  finally { if (serial === detail.serial) detail.loading = false }
}
const showEvidence = row => showDetail('evidence', row.id)
const showHistory = row => showDetail('history', row.id)
let poll
onMounted(() => {
  loadFindings()
  poll = setInterval(() => {
    if (tab.value === 'tasks' && tasks.value.some(t => t.status === 1)) loadTasks()
    if (tab.value === 'findings' && findings.value.some(f => f.pending)) loadFindings(false)
  }, 5000)
})
onUnmounted(() => { clearInterval(poll); ++detail.serial; ++clamavSerial })
</script>

<style scoped>
.coverage-note { font-size: 12px; color: #64748b; line-height: 1.8; }
.digest { font-size: 11px; color: #64748b; overflow-wrap: anywhere; white-space: normal; }
.action-failure { color: #b91c1c; font-size: 12px; }
.evidence-item { padding: 12px 0; border-bottom: 1px solid #e2e8f0; overflow-wrap: anywhere; }
.toolbar { flex-wrap: wrap; }
.version-chip { flex-direction: column; align-items: flex-start; gap: 4px; }
.version-chip .n { font-size: 14px; line-height: 1.5; overflow-wrap: anywhere; }
:deep(.el-tag) { white-space: normal; height: auto; min-height: 20px; }
</style>

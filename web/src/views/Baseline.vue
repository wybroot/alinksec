<template>
  <div class="baseline-page">
    <div class="grid-2">
      <div class="panel"><h4>基线核查 · 自动检查得分</h4><div ref="scoreEl" class="chart"></div></div>
      <div class="panel"><h4>各检查领域通过率</h4><div ref="catEl" class="chart"></div></div>
    </div>
    <div class="panel">
      <div class="toolbar">
        <el-button type="primary" @click="openCreate">+ 发起核查</el-button>
        <el-button plain @click="$router.push('/baseline-templates')">基线模板</el-button>
        <el-button plain @click="openPatchRepo">离线补丁仓库</el-button>
        <div class="spacer"></div>
        <span style="font-size:12px;color:#94a3b8">{{ lastSummary }}</span>
      </div>
      <el-table :data="rows" stripe>
        <el-table-column prop="host" label="主机" width="170" />
        <el-table-column prop="tpl" label="模板" width="220" />
        <el-table-column label="自动检查通过率" width="200">
          <template #default="{ row }"><span v-if="row.legacy" style="color:#b45309">旧结果待重新核查</span><el-progress v-else :percentage="row.rate" :stroke-width="8" :color="row.rate > 80 ? '#16a34a' : row.rate > 60 ? '#f59e0b' : '#dc2626'" /></template>
        </el-table-column>
        <el-table-column label="不合规（严重/高/中/低）" width="180">
          <template #default="{ row }"><span class="mono" style="color:#dc2626">{{ row.c }}</span> / {{ row.h }} / {{ row.m }} / {{ row.l }}</template>
        </el-table-column>
        <el-table-column label="异常 / 旧结果" width="120"><template #default="{ row }">{{ row.errors }} / {{ row.legacy }}</template></el-table-column>
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
    <el-dialog v-model="dlg.visible" title="发起基线核查" width="min(640px, calc(100vw - 32px))">
      <el-form label-width="90px">
        <el-form-item label="任务名称">
          <el-input v-model="dlg.name" placeholder="留空自动生成" maxlength="64" />
        </el-form-item>
        <el-form-item label="基线模板">
          <el-switch v-model="dlg.automatic" active-text="按 Agent 系统自动选择" style="margin-bottom:8px" />
          <el-select v-if="!dlg.automatic" v-model="dlg.templateIds" multiple placeholder="选择基线模板（可多选）" style="width:100%">
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
    <el-dialog v-model="detail.visible" :title="`${detail.host} · 核查明细`" width="min(920px, calc(100vw - 32px))">
      <div class="toolbar">
        <el-button @click="complianceVisible = true">等保条款与证据</el-button>
        <span style="font-size:12px;color:#94a3b8">未通过且支持自动修复的项可勾选提交：Agent 将 备份 → 执行 → 复核 → 失败自动回滚</span>
        <div class="spacer"></div>
        <el-button type="warning" :disabled="!fixSel.length" :loading="fixLoading" @click="submitFix">一键修复所选（{{ fixSel.length }}）</el-button>
      </div>
      <el-table :data="detail.items" stripe max-height="440" @selection-change="(s) => (fixSel = s)">
        <el-table-column type="selection" width="42" :selectable="(r) => !r.passed && r.fixable" />
        <el-table-column prop="code" label="编号" width="130" />
        <el-table-column prop="template_version" label="模板版本" width="100" />
        <el-table-column prop="name" label="检查项" min-width="200" />
        <el-table-column prop="category" label="类别" width="100" />
        <el-table-column label="严重度" width="80">
          <template #default="{ row }">
            <span :class="['sev', `sev-${sevClass(row.severity)}`]">{{ sevText(row.severity) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="结果" width="100">
          <template #default="{ row }">
            <span :style="{ color: row.passed ? '#16a34a' : '#dc2626', fontWeight: 600 }">{{ row.execution_status === 'error' ? '执行异常' : row.execution_status === 'legacy' ? (row.passed ? '通过（旧）' : '未通过（旧）') : row.passed ? '通过' : '不合规' }}</span>
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
      <template #footer><el-button @click="detail.visible = false">关闭</el-button></template>
    </el-dialog>

    <el-dialog v-model="complianceVisible" title="等保条款与证据" width="min(1100px, calc(100vw - 24px))" destroy-on-close>
      <BaselineCompliance v-if="complianceVisible && detail.taskId" :key="`${detail.taskId}:${detail.agentId}`" :task-id="detail.taskId" :agent-id="detail.agentId" />
    </el-dialog>

    <!-- 修复任务记录 -->
    <el-dialog v-model="fixTasks.visible" title="修复任务记录" width="min(1100px, calc(100% - 24px))">
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
            <el-button v-else-if="Number(row.status) === 0 && canApprove(row)" link type="warning" size="small" @click="approveTask(row)">审批放行</el-button>
            <span v-else>{{ row.approver_id ? row.approver : '旧任务，请重建' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="维护窗口 / 停止原因" min-width="190"><template #default="{ row }">{{ row.window_start ? `${fmtTime(row.window_start)} 至 ${fmtTime(row.window_end)}` : '审批后立即进入派发' }}<br /><span style="color:#b45309">{{ row.failure_reason }}</span></template></el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <span :style="{ color: fixStatusColor(row) }">{{ fixStatusText(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="150">
          <template #default="{ row }">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" fixed="right" width="130">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click="viewFixRecords(row)">明细</el-button>
            <el-button v-if="Number(row.type) === 2 && Number(row.status) <= 1 && canCancel(row)" link type="warning" size="small" @click="cancelTask(row)">取消</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- 修复明细 -->
    <el-dialog v-model="fixRecDlg.visible" :title="`修复明细 · ${fixRecDlg.name}`" width="min(1100px, calc(100% - 24px))">
      <p v-if="Number(fixRecDlg.task?.type) === 2">审批账号：{{ fixRecDlg.task.approver }} · 指定账号 ID {{ fixRecDlg.task.approver_id || '旧任务未知' }} · 实际审批 ID {{ fixRecDlg.task.approved_by || '尚未审批' }}</p>
      <p v-if="fixRecDlg.task?.failure_reason" style="color:#b45309">{{ fixRecDlg.task.failure_reason }}</p>
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
    <el-dialog v-model="patchDlg.visible" title="离线补丁仓库" width="min(1100px, calc(100vw - 24px))">
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
        <el-table-column label="包范围" min-width="180">
          <template #default="{ row }">{{ row.distro_id || '未声明' }} / {{ row.distro_version || '未声明' }} / {{ row.architecture || '未声明' }}</template>
        </el-table-column>
        <el-table-column prop="pkg_name" label="包名" min-width="140" />
        <el-table-column prop="target_version" label="目标版本" min-width="140" />
        <el-table-column label="类型" width="70">
          <template #default="{ row }"><el-tag size="small" effect="plain">{{ row.repo_type }}</el-tag></template>
        </el-table-column>
        <el-table-column label="验证与复核" min-width="170">
          <template #default="{ row }">
            <div>{{ row.metadata_status === 'validated' ? '包头已核验' : '历史包，需重新导入' }}</div>
            <div>{{ (row.reviews || []).filter(r => !r.revoked_at).length }} 条未撤销人工复核</div>
            <el-button v-if="row.metadata_status === 'validated'" link type="primary" @click="openPatchReview(row)">查看并复核</el-button>
          </template>
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
    <el-dialog v-model="patchImport.visible" title="导入补丁包" width="min(520px, calc(100vw - 24px))">
      <el-form label-width="96px">
        <el-form-item label="补丁文件">
          <input type="file" @change="e => (patchImport.file = e.target.files[0])" />
        </el-form-item>
        <el-form-item label="系统" required>
          <el-select v-model="patchImport.osType" style="width:160px">
            <el-option label="Linux" :value="1" />
          </el-select>
        </el-form-item>
        <el-form-item label="系统版本">
          <el-input v-model="patchImport.osVersion" placeholder="仅作显示，例如 Ubuntu 24.04" style="width:240px" />
        </el-form-item>
        <el-form-item label="发行版标识" required><el-input v-model="patchImport.distroId" placeholder="ubuntu / debian / rhel（精确标识）" /></el-form-item>
        <el-form-item label="发行版版本" required><el-input v-model="patchImport.distroVersion" placeholder="24.04 / 12 / 9（精确版本）" /></el-form-item>
        <el-form-item label="包架构" required><el-input v-model="patchImport.architecture" placeholder="amd64 / arm64 / all / x86_64 / noarch" /></el-form-item>
        <el-form-item label="包名" required>
          <el-input v-model="patchImport.pkgName" placeholder="实际二进制包名，例如 openssl" style="width:240px" />
        </el-form-item>
        <el-form-item label="目标版本" required>
          <el-input v-model="patchImport.targetVersion" placeholder="1.1.1k-26.el7_9" style="width:240px" />
        </el-form-item>
        <el-form-item label="包类型">
          <el-select v-model="patchImport.repoType" clearable placeholder="按扩展名自动识别" style="width:160px">
            <el-option label="rpm" value="rpm" /><el-option label="deb" value="deb" />
          </el-select>
        </el-form-item>
        <el-alert type="info" :closable="false" show-icon
          title="平台核验实际包名、完整版本和架构；发行版适用性及 CVE 修复目标需另行人工复核。Windows 补丁请人工处理。" />
      </el-form>
      <template #footer>
        <el-button @click="patchImport.visible = false">取消</el-button>
        <el-button type="primary" :loading="patchImport.loading" @click="submitPatchImport">导入</el-button>
      </template>
    </el-dialog>
    <el-dialog v-model="patchReview.visible" title="补丁适用性与修复目标复核" width="min(780px, calc(100vw - 24px))">
      <el-alert type="warning" :closable="false" title="包头核验仅确认包内信息。发行版适用性及该版本修复 CVE 的结论由复核人负责；平台未认证厂商声明。规则或补丁变化后需重新复核。" />
      <p v-if="patchReview.patch">{{ patchReview.patch.pkg_name }} · {{ patchReview.patch.target_version }} · {{ patchReview.patch.distro_id }} {{ patchReview.patch.distro_version }} · {{ patchReview.patch.architecture }}</p>
      <el-form label-width="96px">
        <el-form-item label="CVE 编号"><el-input v-model="patchReview.cveId" placeholder="CVE-2026-12345" /><el-button @click="loadPatchReviewContext">查看当前依据</el-button></el-form-item>
      </el-form>
      <template v-if="patchReview.context">
        <p>正在复核：{{ patchReview.context.cve.cve_id }}</p>
        <p class="mono" style="overflow-wrap:anywhere">补丁 SHA256：{{ patchReview.context.patch.sha256 }}</p>
        <p>规则来源：{{ patchReview.context.cve.rule_source_id }}</p>
        <p class="mono" style="overflow-wrap:anywhere">规则指纹：{{ patchReview.context.cve.rule_digest }}</p>
        <pre style="white-space:pre-wrap;max-height:220px;overflow:auto;font-size:12px">{{ formatReviewEvidence(patchReview.context.cve) }}</pre>
        <el-input v-model="patchReview.notes" type="textarea" :rows="3" maxlength="2048" placeholder="填写发行版适用性、二进制包修复目标及来源依据，至少 10 字" />
        <el-checkbox v-model="patchReview.acknowledged" style="white-space:normal;height:auto">我已核对上述具体补丁、系统范围和当前 CVE 修复目标</el-checkbox>
      </template>
      <el-table :data="patchReview.patch?.reviews || []" max-height="180">
        <el-table-column prop="cve_id" label="历史复核" /><el-table-column prop="reviewed_by" label="复核人 ID" width="100" />
        <el-table-column prop="notes" label="依据" show-overflow-tooltip />
        <el-table-column label="状态" width="100"><template #default="{ row }"><span v-if="row.revoked_at">已撤销</span><el-button v-else link type="danger" @click="revokeReview(row)">撤销</el-button></template></el-table-column>
      </el-table>
      <template #footer><el-button @click="patchReview.visible = false">关闭</el-button><el-button type="primary" :disabled="!patchReview.context || !patchReview.acknowledged" :loading="patchReview.loading" @click="submitPatchReview">确认人工复核</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as echarts from 'echarts'
import {
  fetchPatchReviewContext, reviewPatch, revokePatchReview, createBaselineTask, createFixTask, fetchBaseline, fetchBaselineCategoryStats, approveFixTask, fetchPatches, importPatch,
  fetchBaselineTaskDetail, fetchBaselineTemplates, fetchBaselineCoverage, fetchFixTaskRecords, fetchFixTasks, fetchAllHosts, cancelFixTask, getUser,
} from '../api'
import { useChart } from '../composables/useChart'
import BaselineCompliance from '../components/BaselineCompliance.vue'
const complianceVisible = ref(false)

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

const dlg = reactive({ visible: false, loading: false, name: '', automatic: true, templateIds: [], agentIds: [] })

async function openCreate() {
  dlg.visible = true
  dlg.name = ''
  dlg.automatic = true
  dlg.templateIds = []
  dlg.agentIds = []
  try {
    const [tpls, list] = await Promise.all([fetchBaselineTemplates(), fetchAllHosts()])
    templates.value = (tpls || []).filter((t) => t.enabled === true || t.enabled === 1)
    hosts.value = list
  } catch (e) {
    msg(e.message || '基础数据加载失败', 'error')
  }
}

async function submit() {
  if (!dlg.automatic && !dlg.templateIds.length) return msg('请选择基线模板', 'warning')
  if (!dlg.agentIds.length) return msg('请选择目标主机', 'warning')
  dlg.loading = true
  try {
    const selected = dlg.automatic ? [] : dlg.templateIds
    const coverage = await fetchBaselineCoverage(dlg.agentIds, selected)
    const uncovered = coverage.filter((row) => !row.covered)
    if (uncovered.length) throw new Error(`以下主机没有适用模板：${uncovered.map((row) => row.agent_id).join('、')}。请先在基线模板页发布相应系统的模板。`)
    await createBaselineTask(dlg.agentIds, selected, dlg.name || null)
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

const FIX_STATUS = { 0: '待执行', 1: '执行中', 2: '已完成', 3: '部分失败', 4: '已取消', 5: '待重启或复核' }
const FIX_STATUS_COLOR = { 0: '#94a3b8', 1: '#2563eb', 2: '#16a34a', 3: '#dc2626', 4: '#64748b' }
const fixStatusText = (row) => (Number(row.type) === 2 && !row.approved && Number(row.status) === 0
  ? '待审批' : FIX_STATUS[Number(row.status)] || '未知')
const fixStatusColor = (row) => (Number(row.type) === 2 && !row.approved && Number(row.status) === 0
  ? '#f59e0b' : FIX_STATUS_COLOR[Number(row.status)] || '#64748b')
const FIX_REC_STATUS = { 0: '待执行', 1: '修复成功', 2: '失败已回滚', 3: '失败未回滚', 5: '未完成', 6: '等待重启复核', 7: '安装状态待复核', 8: '人工结束复核' }
const FIX_REC_COLOR = { 0: '#94a3b8', 1: '#16a34a', 2: '#f59e0b', 3: '#dc2626', 5: '#f59e0b' }

async function approveTask(row) {
  try {
    const res = await approveFixTask(row.id)
    const state = res?.state === 'waiting_window' ? '已审批，等待维护窗口自动派发' : '已审批并加入派发队列'
    msg(`任务 ${row.task_no} ${state}`)
    openFixTasks()
  } catch (e) {
    msg(e.message || '审批失败', 'error')
  }
}
const actorId = () => Number(getUser()?.id || 0)
const canWriteFix = () => ['admin', 'operator'].includes(getUser()?.role)
const canApprove = row => canWriteFix() && actorId() > 0 && actorId() === Number(row.approver_id)
const canCancel = row => canWriteFix() && actorId() > 0 && [Number(row.approver_id), Number(row.created_by)].includes(actorId())
async function cancelTask(row) {
  try {
    const { value } = await ElMessageBox.prompt('填写原因。仅能取消尚未送出的任务；已开始的安装需要查看结果并人工处理。', '取消软件包修复', { inputValidator: value => value?.trim()?.length >= 2 || '请填写至少 2 字原因' })
    await cancelFixTask(row.id, value); msg('任务已取消，待推指令和下载凭证已停止'); await openFixTasks()
  } catch (error) { if (error !== 'cancel' && error !== 'close') msg(error.message || '取消失败', 'error') }
}

/* ---------------- 补丁仓库 ---------------- */

const patchDlg = reactive({ visible: false, list: [], osType: null, keyword: '' })
const patchImport = reactive({ visible: false, loading: false, file: null, osType: 1, osVersion: '', pkgName: '', targetVersion: '', repoType: '', distroId: '', distroVersion: '', architecture: '' })

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
  if (!patchImport.file || !patchImport.pkgName.trim() || !patchImport.targetVersion.trim() || !patchImport.distroId.trim() || !patchImport.distroVersion.trim() || !patchImport.architecture.trim()) {
    return msg('请补全文件、包名、完整版本、发行版与包架构', 'warning')
  }
  patchImport.loading = true
  try {
    const fd = new FormData()
    fd.append('file', patchImport.file)
    fd.append('osType', patchImport.osType)
    fd.append('osVersion', patchImport.osVersion)
    fd.append('pkgName', patchImport.pkgName.trim())
    fd.append('targetVersion', patchImport.targetVersion.trim())
    for (const field of ['distroId', 'distroVersion', 'architecture']) fd.append(field, patchImport[field].trim())
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

const patchReview = reactive({ visible: false, loading: false, patch: null, cveId: '', context: null, notes: '', acknowledged: false })
watch(() => patchReview.cveId, () => { patchReview.context = null; patchReview.acknowledged = false })
function openPatchReview(row) { Object.assign(patchReview, { visible: true, patch: row, cveId: '', context: null, notes: '', acknowledged: false }) }
function formatReviewEvidence(cve) {
  try { return JSON.stringify({ provenance: JSON.parse(cve.provenance), affected: JSON.parse(cve.affected) }, null, 2) }
  catch { return '依据无法读取，请重新核对' }
}
async function loadPatchReviewContext() {
  patchReview.context = null; patchReview.acknowledged = false
  const id = patchReview.patch.id, cveId = patchReview.cveId.trim()
  try {
    const context = await fetchPatchReviewContext(id, cveId)
    if (patchReview.patch?.id === id && patchReview.cveId.trim() === cveId) patchReview.context = context
  }
  catch (e) { msg(e.message || '当前复核依据不可用', 'error') }
}
async function submitPatchReview() {
  if (patchReview.notes.trim().length < 10) return msg('请填写至少 10 字的复核依据', 'warning')
  patchReview.loading = true
  try {
    const ctx = patchReview.context
    await reviewPatch(patchReview.patch.id, { cveId: ctx.cve.cve_id, ruleDigest: ctx.cve.rule_digest, patchDigest: ctx.patchDigest, notes: patchReview.notes, acknowledged: patchReview.acknowledged })
    patchReview.visible = false; msg('人工复核已记录；创建与派发时会再次核对'); await loadPatches()
  } catch (e) { patchReview.context = null; patchReview.acknowledged = false; msg(e.message || '复核失败，请重新查看依据', 'error') }
  finally { patchReview.loading = false }
}
async function revokeReview(row) {
  try {
    const { value } = await ElMessageBox.prompt('填写撤销原因。引用这条复核的待派发任务将被阻断。', '撤销人工复核', { inputValidator: v => !!v?.trim() || '请填写撤销原因' })
    await revokePatchReview(patchReview.patch.id, row.id, value); await loadPatches()
    patchReview.patch = patchDlg.list.find(p => p.id === patchReview.patch.id); patchReview.context = null; patchReview.acknowledged = false
    msg('复核已撤销')
  } catch (e) { if (e !== 'cancel' && e !== 'close') msg(e.message || '撤销失败', 'error') }
}

const fixTasks = reactive({ visible: false, list: [] })
const fixRecDlg = reactive({ visible: false, name: '', list: [], task: null })

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
  fixRecDlg.task = null
  fixRecDlg.visible = true
  try {
    const res = await fetchFixTaskRecords(row.id)
    fixRecDlg.list = res?.list || []
    fixRecDlg.task = res?.task || null
  } catch (e) {
    msg(e.message || '修复明细加载失败', 'error')
  }
}

const SEV_TEXT = { 4: '严重', 3: '高', 2: '中', 1: '低' }
const SEV_CLASS = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' }
const sevText = (n) => SEV_TEXT[Number(n)] || '低'
const sevClass = (n) => SEV_CLASS[Number(n)] || 'low'

/* ---------------- 图表（真实数据） ---------------- */

const avgScore = computed(() => rows.value.length && !rows.value.some((r) => r.legacy)
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
    detail: { valueAnimation: true, fontSize: 40, fontWeight: 700, offsetCenter: [0, '-5%'], color: '#0f172a', formatter: (v) => (avgScore.value == null ? '—' : v) },
    data: [{ value: avgScore.value ?? 0, name: rows.value.some((r) => r.legacy) ? '旧结果待重新核查' : rows.value.length ? `平均自动检查得分（${rows.value.length} 台）` : '暂无核查数据' }],
  }],
}))

const catEl = ref(null)
const { render: renderCat } = useChart(catEl, () => ({
  grid: { left: 40, right: 16, top: 30, bottom: 26 },
  tooltip: { trigger: 'axis', formatter: (ps) => `${echarts.format.encodeHTML(ps[0].name)}：通过率 ${ps[0].value}%` },
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
  const errors = rows.value.reduce((s, r) => s + r.errors, 0)
  const legacy = rows.value.reduce((s, r) => s + r.legacy, 0)
  return `最近核查：${time} · 覆盖 ${rows.value.length} 台 · 不合规项 ${failed} · 执行异常 ${errors} · 旧结果 ${legacy}`
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

<style scoped>
.baseline-page,.baseline-page .panel{min-width:0}
</style>

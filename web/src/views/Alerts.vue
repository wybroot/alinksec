<template>
  <div class="panel">
    <p v-if="loadError" role="alert">{{ loadError }} <el-button size="small" @click="load">重试</el-button></p>
    <el-alert title="确认或忽略仅关闭告警记录，不会终止进程或隔离主机。安全动作结果需单独核实。" type="info" :closable="false" />
    <el-tabs v-model="tab">
      <el-tab-pane label="全部" name="all" />
      <el-tab-pane label="严重" name="critical" />
      <el-tab-pane label="高危" name="high" />
      <el-tab-pane label="待确认／跟进中" name="open" />
    </el-tabs>
    <el-table :data="alerts" v-loading="loading" stripe>
      <el-table-column label="级别" width="80">
        <template #default="{ row }"><el-tag size="small" :type="sevType(row.sev)" :effect="row.sev === 'critical' ? 'dark' : 'light'">{{ sevLabel(row.sev) }}</el-tag></template>
      </el-table-column>
      <el-table-column label="类型" width="130"><template #default="{ row }"><span class="mono">{{ row.type }}</span></template></el-table-column>
      <el-table-column label="内容" min-width="260"><template #default="{ row }">
        {{ row.text }}
        <el-tag v-if="row.legacySeverity" size="small" type="info">历史等级，沿用旧含义</el-tag>
        <el-button v-if="row.detail?.attribution?.source === 'windows_kernel_file_etw'" link type="primary" size="small" @click="evidence = row">查看归因证据</el-button>
      </template></el-table-column>
      <el-table-column prop="host" label="主机" width="130" />
      <el-table-column prop="time" label="时间" width="150" />
      <el-table-column label="状态" width="120">
        <template #default="{ row }"><el-tag size="small" :type="row.done ? 'success' : 'danger'" effect="plain">{{ row.statusLabel }}</el-tag></template>
      </el-table-column>
      <el-table-column label="操作" width="240" fixed="right">
        <template #default="{ row }">
          <el-button v-if="!row.done && !readOnly" link type="primary" size="small" :loading="row._busy" @click="handle(row, 'acknowledge')">确认记录</el-button>
          <el-button v-if="!row.done && !readOnly" link size="small" :loading="row._busy" @click="handle(row, 'ignore')">忽略</el-button>
          <span v-else style="font-size:12px;color:#94a3b8">{{ row.handler }}</span>
          <el-button link size="small" @click="openResponses(row)">安全响应</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-pagination v-model:current-page="page" :page-size="20" :total="total" layout="total, prev, pager, next" @current-change="load" />
    <el-dialog :model-value="!!responseAlert" title="告警关联主机响应" width="min(900px, 94vw)" @close="responseAlert = null">
      <template v-if="responseAlert">
        <p>告警 #{{ responseAlert.id }} · {{ responseAlert.text }} · 主机 {{ responseAlert.host }}（{{ responseAlert.agentId }}）</p>
        <p>隔离影响该主机的业务网络。记录确认、指令发送、Agent 回执和当前主机状态分别显示，不代表风险已经消除。</p>
        <el-button v-if="!readOnly" type="danger" :loading="responseBusy" @click="respond('isolate')">隔离此主机</el-button>
        <el-button v-if="!readOnly" :loading="responseBusy" @click="respond('restore')">解除此主机隔离</el-button>
        <el-button @click="loadResponses">刷新回执</el-button>
        <el-alert v-if="responseError" :title="responseError" type="error" :closable="false" />
        <el-table :data="responses">
          <el-table-column prop="command_id" label="指令编号" min-width="190" />
          <el-table-column label="动作" width="100"><template #default="{ row }">{{ row.action === 'isolate' ? '隔离主机' : '解除隔离' }}</template></el-table-column>
          <el-table-column label="回执" min-width="150"><template #default="{ row }">{{ responseStatus(row.command_status) }}</template></el-table-column>
          <el-table-column label="当前主机状态" min-width="140"><template #default="{ row }">{{ Number(row.host_status) !== 1 ? '离线，状态待确认' : isolationState(row.isolation_status) }}</template></el-table-column>
          <el-table-column label="详情／失败原因" min-width="200"><template #default="{ row }">{{ row.isolation_error || row.result || '等待执行信息' }}<details><summary>提交时告警证据</summary><pre style="white-space:pre-wrap">{{ row.evidence }}</pre></details></template></el-table-column>
        </el-table>
        <el-pagination v-model:current-page="responsePage" :total="responseTotal" :page-size="20" layout="total, prev, pager, next" @current-change="loadResponses" />
      </template>
    </el-dialog>
    <el-dialog :model-value="!!evidence" title="Windows 勒索进程归因证据" width="min(680px, 94vw)" top="5vh" style="max-height:90vh;overflow-y:auto" @close="evidence = null">
      <RansomAttribution v-if="evidence" :detail="evidence.detail" :action="evidence.action" />
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { fetchAlertResponses, createAlertResponse, fetchAlertPage, getUser, handleAlert } from '../api'
import { sevType, sevLabel } from '../utils/format'
import RansomAttribution from '../components/RansomAttribution.vue'

const responseAlert = ref(null), responses = ref([]), responsePage = ref(1), responseTotal = ref(0), responseError = ref(''), responseBusy = ref(false)
const responseStatus = value => ({0:'排队中',1:'已发送，待回执',2:'已接收',3:'执行中',4:'Agent 已完成回执',5:'执行失败',6:'回执超时'}[value] || '未知')
const isolationState = value => ({0:'未隔离',1:'隔离中',2:'已隔离',3:'解除中',4:'隔离失败',5:'解除失败',6:'待确认'}[value] || '未知')
let responseSequence = 0
async function loadResponses() {
  if (!responseAlert.value) return
  const id = responseAlert.value.id, sequence = ++responseSequence
  try {
    const result = await fetchAlertResponses(id, responsePage.value)
    if (responseAlert.value?.id !== id || sequence !== responseSequence) return
    responses.value = result.list; responseTotal.value = result.total; responseError.value = ''
  } catch(e) { if (responseAlert.value?.id === id && sequence === responseSequence) { responses.value = []; responseError.value = e.message || '响应记录加载失败' } }
}
function openResponses(row) { responseAlert.value = row; responsePage.value = 1; responses.value = []; responseTotal.value = 0; responseError.value = ''; loadResponses() }
async function respond(action) {
  const alert = responseAlert.value
  if (!alert) return
  try {
    await ElMessageBox.confirm(`确认对告警 #${alert.id} 关联主机 ${alert.host}（${alert.agentId}）执行${action === 'isolate' ? '隔离，业务网络将受影响' : '解除隔离'}？`, '确认主机安全动作', { type:'warning' })
    responseBusy.value = true
    const result = await createAlertResponse(alert.id, action)
    ElMessage.success(`已创建指令 ${result.commandId}，请查看最终回执及主机状态`)
    await loadResponses()
  } catch(e) { if (e !== 'cancel' && e !== 'close') ElMessage.error(e.message || '响应创建失败') }
  finally { responseBusy.value = false }
}

const alerts = ref([])
const tab = ref('all')
const evidence = ref(null)
const page = ref(1)
const total = ref(0)
const loading = ref(false)
const readOnly = getUser()?.role === 'viewer'
const loadError = ref('')
let loadSequence = 0
async function load() {
  const sequence = ++loadSequence
  loading.value = true
  try {
    const result = await fetchAlertPage({ page: page.value, tab: tab.value })
    if (sequence !== loadSequence) return
    alerts.value = result.list; total.value = result.total; loadError.value = ''
    if (!result.list.length && page.value > 1) { page.value = Math.max(1, Math.ceil(result.total / 20)); return load() }
  } catch(e) {
    if (sequence !== loadSequence) return
    alerts.value = []; total.value = 0; loadError.value = e?.message || '告警加载失败'
  } finally { if (sequence === loadSequence) loading.value = false }
}
watch(tab, () => { page.value = 1; load() })

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

const handle = async (row, resolution) => {
  row._busy = true
  try {
    await handleAlert(row.id, resolution === 'ignore' ? '已忽略' : '已确认记录', resolution)
    msg('告警记录已更新，未执行主机安全动作')
    await load()
  } catch (e) {
    ElMessage({ message: e?.message || '操作失败', type: 'error' })
  } finally {
    row._busy = false
  }
}

onMounted(load)
</script>

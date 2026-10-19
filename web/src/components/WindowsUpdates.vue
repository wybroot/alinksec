<template>
  <section class="windows-updates" data-testid="windows-updates">
    <h3>Windows 更新发现与修复</h3>
    <p class="help">通过主机当前配置的 Windows Update 或 WSUS 发现适用更新。自动安装仅支持已接受许可、可静默执行的安全或关键更新；每台主机每次一项，由指定账号审批。系统重启由运维安排。</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon><el-button @click="refresh">重试</el-button></el-alert>
    <div class="toolbar"><el-button :loading="loading" @click="refresh">刷新状态</el-button><span role="status">{{ notice }}</span></div>
    <div class="table-wrap" v-loading="loading">
      <el-table :data="hosts" empty-text="暂无 Windows 主机" @row-click="selectHost">
        <el-table-column label="主机" min-width="170"><template #default="{ row }"><el-button link type="primary" @click.stop="selectHost(row)">{{ row.hostname }}</el-button><div class="help">{{ row.ip }}</div></template></el-table-column>
        <el-table-column label="发现状态" min-width="145"><template #default="{ row }"><el-tag :type="row.state === 'complete' ? 'success' : 'info'">{{ stateLabel[row.state] || '未知' }}</el-tag></template></el-table-column>
        <el-table-column label="最近结果" min-width="230"><template #default="{ row }"><span v-if="row.state === 'complete'">{{ row.coverage?.updates?.length || 0 }} 项更新{{ row.coverage?.reboot_required ? ' · 系统等待重启' : '' }}</span><span v-else>{{ row.error ? issueLabel[row.error] || '原生查询未完成，请检查主机更新服务和策略' : '尚无可用于审批的当前发现证据' }}</span><div class="help">{{ row.received_at || row.created_at || '尚未发现' }}</div></template></el-table-column>
        <el-table-column v-if="!readOnly" label="操作" width="120"><template #default="{ row }"><el-button size="small" :disabled="row.agent_status !== 1 || row.windows_update_contract !== 1 || row.state === 'pending' || busy" @click.stop="discover(row)">发现更新</el-button></template></el-table-column>
      </el-table>
    </div>
    <el-pagination v-if="total > 20" v-model:current-page="page" :page-size="20" :total="total" layout="prev, pager, next" @current-change="refresh" />

    <template v-if="selected">
      <h4>{{ selected.hostname }} · 最近发现的更新</h4>
      <el-alert v-if="selected.state !== 'complete' || selected.coverage?.reboot_required" type="warning" :closable="false" title="当前证据不可用于创建安装任务，请先完成更新发现并处理待重启状态。" />
      <el-alert v-if="candidateError" :title="candidateError" type="error" :closable="false"><el-button @click="loadCandidates">重试加载更新</el-button></el-alert>
      <div v-else class="table-wrap" v-loading="candidateLoading">
        <el-table :data="candidates" empty-text="该次发现未列出更新；不代表全部软件漏洞已修复">
          <el-table-column label="更新 / KB" min-width="300"><template #default="{ row }">{{ row.update.title }}<div class="help">{{ row.update.kb.map(k => `KB${k}`).join('、') || '无 KB' }}</div><div class="identity">{{ row.update.update_id }} · 修订 {{ row.update.revision }}</div></template></el-table-column>
          <el-table-column label="安装条件" min-width="205"><template #default="{ row }">{{ row.update.eligible ? '可提交审批' : issueLabel[row.update.reason] || '需要人工处理' }}<div class="help">最大下载 {{ Math.ceil(row.update.size / 1024 / 1024) }} MiB</div></template></el-table-column>
          <el-table-column v-if="!readOnly" label="操作" width="125"><template #default="{ row }"><el-button size="small" :disabled="!canCreate(row) || busy" @click="openTask(row)">提交安装审批</el-button></template></el-table-column>
        </el-table>
      </div>
    </template>

    <div class="toolbar"><h4>Windows 更新任务</h4><el-button @click="loadTasks">刷新任务</el-button></div>
    <p class="help">“等待重启复核”和“安装状态待复核”均未确认为完成。Agent 恢复后继续查询同一更新状态；安装结果不会直接关闭 CVE 漏洞记录。</p>
    <el-alert v-if="taskError" :title="taskError" type="error" :closable="false"><el-button @click="loadTasks">重试</el-button></el-alert>
    <div class="table-wrap"><el-table :data="tasks" empty-text="最近任务中没有 Windows 更新任务">
      <el-table-column prop="task_no" label="任务号" min-width="220" show-overflow-tooltip />
      <el-table-column label="状态" min-width="150"><template #default="{ row }">{{ taskState(row) }}</template></el-table-column>
      <el-table-column prop="approver" label="指定审批账号" min-width="140" />
      <el-table-column label="操作" width="220"><template #default="{ row }"><el-button link @click="details(row)">详情</el-button><el-button v-if="canApprove(row)" link type="warning" :disabled="busy" @click="approve(row)">审批安装</el-button><el-button v-if="canCancel(row)" link :disabled="busy" @click="cancel(row)">取消</el-button></template></el-table-column>
    </el-table></div>

    <el-dialog v-model="formVisible" title="Windows 更新安装审批" width="min(620px, calc(100% - 24px))">
      <p>{{ target?.update.title }}</p><p class="identity">{{ target?.update.update_id }} · 修订 {{ target?.update.revision }}</p>
      <el-alert type="warning" :closable="false" title="安装不自动回滚或重启。维护窗口结束后不开始新安装；已经开始的原生安装可能继续运行。" />
      <el-form label-position="top" class="task-form">
        <el-form-item label="指定审批账号" required><el-select v-model="approver" filterable><el-option v-for="u in approvers" :key="u.id" :label="u.username" :value="u.username" /></el-select></el-form-item>
        <el-form-item label="维护窗口（可选）"><el-date-picker v-model="window" type="datetimerange" start-placeholder="开始时间" end-placeholder="结束时间" /></el-form-item>
      </el-form>
      <p v-if="formError" role="alert" class="error">{{ formError }}</p>
      <template #footer><el-button @click="formVisible = false">关闭</el-button><el-button type="primary" :loading="busy" :disabled="!approver" @click="submit">提交审批</el-button></template>
    </el-dialog>
    <el-dialog v-model="detailVisible" title="Windows 更新执行记录" width="min(800px, calc(100% - 24px))">
      <p v-if="detailError" class="error" role="alert">{{ detailError }}</p>
      <article v-for="r in records" :key="r.id" class="record"><h4>{{ r.hostname }} · {{ recordState[r.status] || '未知' }}</h4><p>{{ r.name }}</p><p class="identity">{{ r.code }}</p><p v-if="r.reboot_required">需要人工安排系统重启；Agent 将继续复核。</p><pre>{{ r.log || '尚未回报执行结果' }}</pre></article>
    </el-dialog>
  </section>
</template>
<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { ElMessageBox } from 'element-plus'
import { getUser, fetchWindowsUpdateHosts, fetchWindowsUpdateCandidates, scanWindowsUpdates, createWindowsUpdateTask, fetchFixApprovers, fetchFixTasks, fetchFixTaskRecords, approveFixTask, cancelFixTask } from '../api'
const user = getUser(), readOnly = user?.role === 'viewer'
const hosts = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref(''), notice = ref(''), busy = ref(false)
const selected = ref(null), candidates = ref([]), candidateLoading = ref(false), candidateError = ref(''), tasks = ref([]), taskError = ref('')
const formVisible = ref(false), target = ref(null), targetAgent = ref(''), approvers = ref([]), approver = ref(''), window = ref([]), formError = ref('')
const detailVisible = ref(false), records = ref([]), detailError = ref('')
const stateLabel = { unknown: '尚未发现', unsupported: 'Agent 未支持', offline: '主机离线', pending: '发现中', complete: '发现完成', failed: '发现失败', stale: '发现已过期' }
const issueLabel = { unsupported_update: '更新类型不支持', not_security_or_critical: '属于其他更新类别，请人工处理', eula_not_accepted: '许可尚未由本机接受', interactive_or_source_required: '需要交互或安装源', download_size_limit: '超过下载容量上限', scan_expired: '发现任务已过期', command_failed: '指令失败或超时', wua_scan_failed: '原生查询未完成，请检查更新服务、权限和网络' }
const recordState = { 0: '待执行', 1: '复核成功', 3: '安装失败', 5: '未完成', 6: '等待重启复核', 7: '安装状态待复核' }
const taskState = row => Number(row.status) === 0 && !row.approved ? '待指定账号审批' : ({ 0: '等待维护窗口', 1: '执行中', 2: '复核完成', 3: '部分失败', 4: '已取消', 5: '待重启或复核' }[row.status] || '未知')
const canCreate = row => selected.value?.state === 'complete' && !selected.value?.coverage?.reboot_required && row.update.eligible && !readOnly
const canApprove = row => !readOnly && Number(row.status) === 0 && !row.approved && Number(row.approver_id) === Number(user?.id)
const canCancel = row => !readOnly && Number(row.status) <= 1 && [Number(row.created_by), Number(row.approver_id)].includes(Number(user?.id))
async function refresh() {
  if (loading.value) return
  loading.value = true; error.value = ''
  try { const data = await fetchWindowsUpdateHosts(page.value); hosts.value = data.items || []; total.value = data.total || 0; if (selected.value) { const host = hosts.value.find(h => h.agent_id === selected.value.agent_id); selected.value = host || null; if (host) await loadCandidates() } }
  catch (e) { error.value = e.message || '更新主机状态加载失败'; hosts.value = []; selected.value = null; candidates.value = [] }
  finally { loading.value = false }
}
function selectHost(row) { selected.value = row; loadCandidates() }
let candidateGeneration = 0
async function loadCandidates() {
  const generation = ++candidateGeneration, id = selected.value?.agent_id
  candidates.value = []; candidateError.value = ''; if (!id) return
  candidateLoading.value = true
  try { const data = await fetchWindowsUpdateCandidates(id); if (generation === candidateGeneration && selected.value?.agent_id === id) candidates.value = data || [] }
  catch (e) { if (generation === candidateGeneration) candidateError.value = e.message || '更新列表加载失败' }
  finally { if (generation === candidateGeneration) candidateLoading.value = false }
}
async function discover(row) { busy.value = true; error.value = ''; try { await scanWindowsUpdates([row.agent_id]); notice.value = '更新发现已排队，请稍后刷新结果'; await refresh() } catch (e) { error.value = e.message } finally { busy.value = false } }
async function openTask(row) {
  target.value = row; targetAgent.value = selected.value.agent_id; approver.value = ''; window.value = []; formError.value = ''; formVisible.value = true
  try { approvers.value = await fetchFixApprovers() } catch (e) { approvers.value = []; formError.value = e.message }
}
async function submit() {
  busy.value = true; formError.value = ''
  try { const [start, end] = window.value || []; await createWindowsUpdateTask({ items: [{ agentId: targetAgent.value, candidateId: target.value.id }], approver: approver.value, windowStart: start?.toISOString(), windowEnd: end?.toISOString() }); formVisible.value = false; notice.value = 'Windows 更新任务已提交指定账号审批'; await loadTasks() }
  catch (e) { formError.value = e.message || '任务创建失败' } finally { busy.value = false }
}
async function loadTasks() { taskError.value = ''; try { const data = await fetchFixTasks(); tasks.value = (data.list || []).filter(t => String(t.task_no).startsWith('WU')) } catch (e) { taskError.value = e.message || '任务列表加载失败'; tasks.value = [] } }
async function approve(row) { busy.value = true; taskError.value = ''; try { await ElMessageBox.confirm('确认批准该精确更新目标，进入维护窗口后执行安装？', '审批 Windows 更新'); await approveFixTask(row.id); notice.value = '已审批，等待派发或维护窗口'; await loadTasks() } catch (e) { if (e !== 'cancel' && e !== 'close') taskError.value = e.message || '审批失败' } finally { busy.value = false } }
async function cancel(row) { busy.value = true; taskError.value = ''; try { const { value } = await ElMessageBox.prompt('填写取消原因。已送出的安装指令不能撤回。', '取消更新任务', { inputValidator: v => v?.trim().length >= 2 || '至少填写两个字' }); await cancelFixTask(row.id, value); await loadTasks() } catch (e) { if (e !== 'cancel' && e !== 'close') taskError.value = e.message || '取消失败' } finally { busy.value = false } }
async function details(row) { detailVisible.value = true; records.value = []; detailError.value = ''; try { const data = await fetchFixTaskRecords(row.id); records.value = data.list || [] } catch (e) { detailError.value = e.message || '执行记录加载失败' } }
let timer
onMounted(() => { refresh(); loadTasks(); timer = setInterval(() => { refresh(); loadTasks() }, 15000) })
onUnmounted(() => { clearInterval(timer); candidateGeneration++ })
</script>
<style scoped>
.windows-updates { min-width: 0; }
.help { color: #64748b; font-size: 12px; line-height: 1.7; overflow-wrap: anywhere; }
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; margin: 12px 0; }
.table-wrap { overflow-x: auto; }
.identity, .record pre { white-space: pre-wrap; overflow-wrap: anywhere; font-family: monospace; font-size: 12px; }
.record { border-bottom: 1px solid #e2e8f0; padding: 10px 0; }
.task-form { margin-top: 16px; }
.task-form :deep(.el-select), .task-form :deep(.el-date-editor) { max-width: 100%; width: 100%; }
.error { color: #b91c1c; overflow-wrap: anywhere; }
</style>

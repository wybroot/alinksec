<template>
  <div class="report-panel">
    <div class="report-controls">
      <el-alert title="日期按北京时间计算，包含结束日；当前资产与区间事件分开统计。" type="info" :closable="false" />
      <div class="report-toolbar">
        <el-date-picker v-model="range" type="daterange" value-format="YYYY-MM-DD" range-separator="至" start-placeholder="开始日" end-placeholder="结束日" :disabled="busy || loading" @change="invalidate" />
        <el-select v-model="groupId" aria-label="报表分组" placeholder="全部分组" clearable :disabled="busy || loading || !!groupError" @change="invalidate"><el-option v-for="group in groups" :key="group.id" :label="group.name" :value="group.id" /></el-select>
        <el-select v-model="osType" aria-label="报表系统" placeholder="全部系统" clearable :disabled="busy || loading" @change="invalidate"><el-option label="Linux" :value="1" /><el-option label="Windows" :value="2" /></el-select>
        <el-button type="primary" :loading="loading" :disabled="busy" @click="preview">生成预览</el-button>
      </div>
      <p v-if="groupError" role="alert" class="report-error">{{ groupError }}；可先选择全部分组。</p>
      <p class="report-hint">不选日期时默认近 30 个自然日，最多 366 天。导出前会核对预览数据；数据已变化时须刷新。</p>
      <div class="report-toolbar">
        <el-input v-if="canWrite" v-model="title" maxlength="128" placeholder="快照名称" aria-label="快照名称" :disabled="busy" />
        <el-button v-if="canWrite" :disabled="!report || busy || loading || !title.trim()" @click="save">保存当前统计快照</el-button>
        <el-button v-for="[format, label] in formats" :key="format" :disabled="!report || busy || loading" @click="download(format)">{{ label }}</el-button>
        <el-button :disabled="!report || busy || loading" @click="printReport">打印／另存 PDF</el-button>
      </div>
      <p v-if="snapshotId" class="report-hint">正在查看历史快照，导出内容固定。保存期截至 {{ timestamp(snapshotExpiry) }}。</p>
      <p v-else-if="report" class="report-hint">当前为即时预览。保存快照可固定本次统计，供后续追溯。</p>
      <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
    </div>
    <ReportDocument v-if="report" :report="report" :digest="snapshotDigest" />
    <div v-else class="report-empty">{{ loading ? '正在读取统计…' : '选择范围后生成预览，或从历史中查看报表。' }}</div>
    <section class="report-history">
      <div class="report-toolbar"><h3>历史快照</h3><el-button :disabled="busy || loading" @click="loadHistory">刷新历史</el-button></div>
      <p class="report-hint">保留 30 天，全平台最多 200 份；管理员可提前删除。三种角色均可查看和导出。</p>
      <el-alert v-if="historyError" :title="historyError" type="error" :closable="false" />
      <el-table :data="history" size="small"><el-table-column prop="title" label="名称" min-width="180" /><el-table-column label="生成时间" min-width="165"><template #default="{ row }">{{ timestamp(row.generated_at) }}</template></el-table-column><el-table-column label="方式" width="80"><template #default="{ row }">{{ row.schedule_id ? '定时' : '手动' }}</template></el-table-column><el-table-column label="操作" width="125"><template #default="{ row }"><el-button link type="primary" :disabled="busy || loading" @click="openSnapshot(row.id)">查看</el-button><el-button v-if="isAdmin" link type="danger" :disabled="busy || loading" @click="deleteSnapshot(row)">删除</el-button></template></el-table-column></el-table>
      <el-pagination v-model:current-page="page" :total="historyTotal" :page-size="20" layout="prev, pager, next" @current-change="loadHistory" />
    </section>
    <section class="report-plans">
      <div class="report-toolbar"><h3>定时生成</h3><el-button :disabled="busy" @click="loadSchedules">刷新计划</el-button><el-button v-if="isAdmin" type="primary" :disabled="busy" @click="editSchedule()">新增报表计划</el-button></div>
      <p class="report-hint">北京时间每日、每周一或每月 1 日 09:00 生成，统计截至计划日的前一天。重启后合并错过的时段，保留一份；结果进入历史快照。失败五分钟后重试，连续三次失败停用。</p>
      <el-alert v-if="scheduleError" :title="scheduleError" type="error" :closable="false" />
      <el-table :data="schedules" size="small"><el-table-column prop="title" label="计划" min-width="150" /><el-table-column label="频率 / 窗口" min-width="120"><template #default="{ row }">{{ cadenceName[row.cadence] }} / {{ row.days }} 天</template></el-table-column><el-table-column label="状态" min-width="180"><template #default="{ row }">{{ row.enabled ? '启用' : '停用' }}<p v-if="row.last_error" class="report-error">{{ row.last_error }}</p></template></el-table-column><el-table-column label="下次生成" min-width="165"><template #default="{ row }">{{ row.enabled ? timestamp(row.next_run) : '—' }}</template></el-table-column><el-table-column label="操作" width="160"><template #default="{ row }"><el-button v-if="row.last_snapshot" link :disabled="busy || loading" @click="openSnapshot(row.last_snapshot)">上次结果</el-button><el-button v-if="isAdmin" link type="primary" :disabled="busy" @click="editSchedule(row)">编辑</el-button><el-button v-if="isAdmin" link type="danger" :disabled="busy" @click="deleteSchedule(row)">删除</el-button></template></el-table-column></el-table>
    </section>
    <el-dialog v-model="scheduleDialog" title="定时报表计划" width="min(560px, calc(100vw - 24px))" :close-on-click-modal="!busy" :close-on-press-escape="!busy" :show-close="!busy">
      <el-form label-position="top" :disabled="busy">
        <el-form-item label="计划名称"><el-input v-model="scheduleForm.title" maxlength="128" /></el-form-item>
        <el-form-item label="频率（北京时间 09:00）"><el-select v-model="scheduleForm.cadence"><el-option v-for="[key, label] in Object.entries(cadenceName)" :key="key" :label="label" :value="key" /></el-select></el-form-item>
        <el-form-item label="统计过去的完整自然日数"><el-input-number v-model="scheduleForm.days" :min="1" :max="366" :precision="0" /></el-form-item>
        <el-form-item label="分组"><el-select v-model="scheduleForm.groupId" placeholder="全部分组" clearable :disabled="!!groupError"><el-option v-for="group in groups" :key="group.id" :label="group.name" :value="group.id" /></el-select></el-form-item>
        <el-form-item label="系统"><el-select v-model="scheduleForm.osType" placeholder="全部系统" clearable><el-option label="Linux" :value="1" /><el-option label="Windows" :value="2" /></el-select></el-form-item>
        <el-form-item label="启用"><el-switch v-model="scheduleForm.enabled" /></el-form-item>
      </el-form>
      <p class="report-hint">计划所有者使用保存计划的当前管理员账号；账号停用或失去管理员权限后，计划停止生成。编辑会重新计算下一次执行时间。</p>
      <p v-if="scheduleSaveError" role="alert" class="report-error">{{ scheduleSaveError }}</p>
      <template #footer><el-button :disabled="busy" @click="scheduleDialog = false">取消</el-button><el-button type="primary" :loading="busy" :disabled="!scheduleForm.title?.trim()" @click="saveSchedule">保存计划</el-button></template>
    </el-dialog>
  </div>
</template>
<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import ReportDocument from './ReportDocument.vue'
import { getUser, fetchReportGroups, previewReport, saveReportSnapshot, fetchReportHistory, fetchReportSnapshot, removeReportSnapshot, fetchReportSchedules, saveReportSchedule, removeReportSchedule, downloadReport } from '../api'
const isAdmin = getUser()?.role === 'admin', canWrite = ['admin', 'operator'].includes(getUser()?.role)
const range = ref(null), groupId = ref(null), osType = ref(null), groups = ref([]), groupError = ref('')
const title = ref('安全运营报表'), report = ref(null), snapshotId = ref(null), snapshotDigest = ref(''), snapshotExpiry = ref(null)
const error = ref(''), busy = ref(false), loading = ref(false), page = ref(1), history = ref([]), historyTotal = ref(0), historyError = ref('')
const schedules = ref([]), scheduleError = ref(''), scheduleDialog = ref(false), scheduleForm = ref({}), scheduleId = ref(null), scheduleSaveError = ref('')
const formats = [['csv', '导出 CSV'], ['xlsx', '导出 Excel'], ['html', '打印版 HTML'], ['json', '导出 JSON']]
const cadenceName = { daily: '每日', weekly: '每周一', monthly: '每月 1 日' }
let alive = true, viewSequence = 0, historySequence = 0, scheduleSequence = 0
const timestamp = value => value ? new Date(value).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : '—'
const query = () => ({ from: range.value?.[0], to: range.value?.[1], groupId: groupId.value || null, osType: osType.value || null })
function invalidate() { viewSequence++; report.value = null; snapshotId.value = null; snapshotDigest.value = ''; snapshotExpiry.value = null; error.value = ''; loading.value = false }
async function preview() {
  invalidate(); const sequence = viewSequence; loading.value = true
  try { const data = await previewReport(query()); if (alive && sequence === viewSequence) report.value = data }
  catch (e) { if (alive && sequence === viewSequence) error.value = e.message || '报表预览失败' }
  finally { if (alive && sequence === viewSequence) loading.value = false }
}
function showSnapshot(data) { report.value = data.report; snapshotId.value = data.id; snapshotDigest.value = data.sha256; snapshotExpiry.value = data.expires_at }
async function openSnapshot(id) {
  invalidate(); const sequence = viewSequence; loading.value = true
  try { const data = await fetchReportSnapshot(id); if (alive && sequence === viewSequence) showSnapshot(data) }
  catch (e) { if (alive && sequence === viewSequence) error.value = e.message || '历史快照不可用' }
  finally { if (alive && sequence === viewSequence) loading.value = false }
}
async function save() {
  if (!report.value || !canWrite || busy.value) return
  busy.value = true; error.value = ''; const sequence = viewSequence
  try { const data = await saveReportSnapshot({ ...report.value.query, title: title.value }); if (alive && sequence === viewSequence) { showSnapshot(data); await loadHistory(); ElMessage.success('统计快照已保存') } }
  catch (e) { if (alive && sequence === viewSequence) error.value = e.message || '保存失败' }
  finally { if (alive) busy.value = false }
}
async function download(format) {
  if (!report.value || busy.value) return
  busy.value = true; error.value = ''
  try { await downloadReport(format, { ...report.value.query, expectedDataDigest: report.value.dataDigest }, snapshotId.value) }
  catch (e) { if (alive) error.value = e.message || '导出失败' }
  finally { if (alive) busy.value = false }
}
function printReport() { if (report.value) window.print() }
async function loadHistory() {
  const sequence = ++historySequence
  try { const data = await fetchReportHistory(page.value); if (alive && sequence === historySequence) { history.value = data.list; historyTotal.value = data.total; historyError.value = '' } }
  catch (e) { if (alive && sequence === historySequence) { history.value = []; historyTotal.value = 0; historyError.value = e.message || '历史列表不可用' } }
}
async function loadSchedules() {
  const sequence = ++scheduleSequence
  try { const data = await fetchReportSchedules(); if (alive && sequence === scheduleSequence) { schedules.value = data; scheduleError.value = '' } }
  catch (e) { if (alive && sequence === scheduleSequence) { schedules.value = []; scheduleError.value = e.message || '计划列表不可用' } }
}
async function deleteSnapshot(row) {
  try { await ElMessageBox.confirm(`删除“${row.title}”后将无法再查看该快照。`, '删除报表快照', { type: 'warning' }) }
  catch { return }
  busy.value = true
  try { await removeReportSnapshot(row.id); if (!alive) return; if (snapshotId.value === row.id) invalidate(); await loadHistory() }
  catch (e) { if (alive) historyError.value = e.message || '删除失败' }
  finally { if (alive) busy.value = false }
}
function editSchedule(row) {
  if (!isAdmin) return
  scheduleId.value = row?.id || null; scheduleSaveError.value = ''
  scheduleForm.value = row ? { title: row.title, cadence: row.cadence, days: row.days, groupId: row.group_id, osType: row.os_type, enabled: !!row.enabled, revision: row.revision } : { title: '安全运营周报', cadence: 'weekly', days: 7, groupId: groupId.value || null, osType: osType.value || null, enabled: true, revision: 0 }
  scheduleDialog.value = true
}
async function saveSchedule() {
  if (busy.value || !isAdmin) return
  busy.value = true; scheduleSaveError.value = ''
  try { await saveReportSchedule(scheduleId.value, { ...scheduleForm.value, groupId: scheduleForm.value.groupId || null, osType: scheduleForm.value.osType || null }); if (!alive) return; scheduleDialog.value = false; await loadSchedules() }
  catch (e) { if (alive) scheduleSaveError.value = e.message || '计划保存失败' }
  finally { if (alive) busy.value = false }
}
async function deleteSchedule(row) {
  try { await ElMessageBox.confirm(`删除计划“${row.title}”，已有历史快照仍保留至到期。`, '删除报表计划', { type: 'warning' }) }
  catch { return }
  busy.value = true
  try { await removeReportSchedule(row.id, row.revision); if (alive) await loadSchedules() }
  catch (e) { if (alive) scheduleError.value = e.message || '删除失败，请刷新计划' }
  finally { if (alive) busy.value = false }
}
onMounted(async () => {
  loadHistory(); loadSchedules()
  try { const data = await fetchReportGroups(); if (alive) groups.value = data || [] }
  catch (e) { if (alive) groupError.value = e.message || '分组列表不可用' }
})
onBeforeUnmount(() => { alive = false; viewSequence++; historySequence++; scheduleSequence++ })
</script>
<style scoped>
.report-panel{min-width:0}.report-controls{margin-bottom:18px}.report-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0}.report-toolbar :deep(.el-date-editor){width:280px;max-width:100%;flex-grow:0}.report-toolbar>.el-select{width:170px;max-width:100%}.report-toolbar>.el-input{width:220px;max-width:100%}.report-hint{font-size:12px;line-height:1.7;color:#64748b}.report-error{font-size:12px;color:#b42318;overflow-wrap:anywhere}.report-empty{padding:30px;text-align:center;color:#64748b;background:#f8fafc;border-radius:8px}.report-history,.report-plans{margin-top:24px}.report-toolbar h3{margin:0 12px 0 0;font-size:16px}.report-panel :deep(.el-pagination){margin-top:12px}.report-panel :deep(.el-button+.el-button){margin-left:0}@media(max-width:600px){.report-toolbar :deep(.el-date-editor){width:100%}.report-toolbar>.el-select{flex:1;min-width:110px}.report-toolbar>.el-input{width:100%}}@media print{.report-controls,.report-history,.report-plans,.report-empty{display:none!important}}
</style>
<style>
@media print{@page{size:A4 landscape;margin:12mm}html,body,#app,.layout{height:auto!important;min-height:0!important;background:white!important;overflow:visible!important}.layout>.sidebar,.layout .topbar,.el-tabs__header,.el-message,.el-overlay{display:none!important}.layout>.main{margin:0!important;padding:0!important;min-width:0!important}.content,.panel,.el-tabs__content,.el-tab-pane{overflow:visible!important;padding:0!important;box-shadow:none!important;background:white!important}.layout{display:block!important}.report-document{color:black!important}}
</style>

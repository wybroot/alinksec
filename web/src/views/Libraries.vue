<template>
  <div>
    <div class="panel">
      <div class="toolbar">
        <h4>安全库管理</h4>
        <div class="spacer"></div>
        <el-button :loading="loading" @click="load">刷新</el-button>
        <el-button v-if="canImport" type="primary" :loading="uploading" @click="signatureInput.click()">导入病毒特征库</el-button>
        <el-button v-if="canImport" type="primary" plain :loading="uploading" @click="cveInput.click()">导入漏洞库</el-button>
      </div>
      <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
      <el-descriptions :column="compact ? 1 : 2" :label-width="compact ? 110 : undefined" border style="margin-top:12px">
        <el-descriptions-item label="病毒库版本">{{ state.signature?.db_version || '尚无可用特征库' }}</el-descriptions-item>
        <el-descriptions-item label="病毒检测依据">{{ state.signature?.hash_count || 0 }} 条哈希 / {{ state.signature?.rule_count || 0 }} 条内部规则</el-descriptions-item>
        <el-descriptions-item label="已管理漏洞信息">{{ state.managedCveCount || 0 }} 条</el-descriptions-item>
        <el-descriptions-item label="含资产比对规则">{{ state.matchableCveCount || 0 }} 条</el-descriptions-item>
        <el-descriptions-item label="存储方式">{{ state.storage === 's3' ? '对象存储' : '本地持久化存储' }}</el-descriptions-item>
        <el-descriptions-item label="病毒库发布时间">{{ date(state.signature?.imported_at) }}</el-descriptions-item>
      </el-descriptions>
      <el-alert v-if="!state.signature?.db_version" title="请导入基础特征库或启用远端同步。当前缺少病毒识别依据。" type="warning" :closable="false" show-icon style="margin-top:12px" />
      <p class="hint">人工导入与远端同步可同时使用。远端不可用时，平台和 Agent 继续使用已有库；人工补充的规则优先保留。</p>
      <p class="hint">漏洞信息只有包含适用的软件和版本条件，才能参与资产比对。补丁包继续在漏洞修复流程中按需使用。</p>
      <input ref="signatureInput" type="file" accept=".zip" hidden @change="importFile($event, 'signature')" />
      <input ref="cveInput" type="file" accept=".json" hidden @change="importFile($event, 'cve')" />
    </div>
    <div class="panel" style="margin-top:16px">
      <h4>远端同步状态</h4>
      <p class="hint">数据源按计划串行检查。连续失败会延后重试，已有库继续可用。管理员可调整计划，设置保存后立即生效。</p>
      <el-empty v-if="!state.sources?.length" description="尚未配置远端数据源，可继续人工导入" />
      <el-table v-else :data="state.sources" stripe>
        <el-table-column prop="id" label="数据源" min-width="130" />
        <el-table-column label="内容" min-width="150">
          <template #default="{ row }">{{ types[row.type] || row.type }}<div v-if="row.coverage === 'recent-60m'" class="hint">最近 60 分钟新增情报</div><div v-if="row.coverage === 'modified-window'" class="hint">按修改日期增量同步</div><div v-if="row.coverage === 'curated-snapshot'" class="hint">已审核哈希的完整快照</div></template>
        </el-table-column>
        <el-table-column label="状态" width="140">
          <template #default="{ row }">
            <el-tag :type="!row.enabled ? 'info' : row.status === 'failed' ? 'danger' : row.status === 'running' ? 'primary' : row.stale ? 'warning' : 'success'">
              {{ !row.enabled ? '未启用' : row.status === 'running' ? '同步中' : row.status === 'failed' ? '同步失败' : row.status === 'never' ? '尚未同步' : row.stale ? '更新超时' : '检查正常' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="检查间隔" width="110"><template #default="{ row }">{{ Math.round(row.intervalMs / 60000) }} 分钟</template></el-table-column>
        <el-table-column label="最近成功检查" min-width="170"><template #default="{ row }">{{ date(row.success_at) }}</template></el-table-column>
        <el-table-column label="下次检查" min-width="170"><template #default="{ row }">{{ row.enabled && row.status === 'running' ? '本次执行中' : nextCheck(row.nextCheckAt) }}<div v-if="row.failure_count > 1 && row.enabled" class="hint">连续失败 {{ row.failure_count }} 次，已延后重试</div></template></el-table-column>
        <el-table-column prop="entry_count" label="当前条目" width="110" />
        <el-table-column label="说明" min-width="180"><template #default="{ row }">{{ row.configurationIssue || row.error || '—' }}</template></el-table-column>
        <el-table-column label="操作" :width="isAdmin ? 250 : 100" :fixed="compact ? false : 'right'">
          <template #default="{ row }">
            <el-button v-if="isAdmin" link type="primary" :disabled="!row.enabled || !!row.configurationIssue || state.running || syncing" @click="synchronize(row.id)">立即同步</el-button>
            <el-button v-if="isAdmin" link type="primary" @click="editSchedule(row)">同步计划</el-button>
            <el-button link type="primary" @click="showHistory(row.id)">执行记录</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
    <el-dialog v-model="schedule.visible" title="同步计划" :width="compact ? 'calc(100% - 24px)' : '540px'" :close-on-click-modal="!schedule.saving" :show-close="!schedule.saving">
      <el-form label-width="110px">
        <el-form-item label="数据源">{{ schedule.id }}</el-form-item>
        <el-form-item label="自动同步"><el-switch v-model="schedule.enabled" :disabled="schedule.saving || !!schedule.issue && !schedule.enabled" /></el-form-item>
        <el-form-item label="检查间隔">
          <el-input-number v-model="schedule.minutes" :min="schedule.minimum" :max="10080" :precision="0" :disabled="schedule.saving" />
          <span style="margin-left:8px">分钟</span>
        </el-form-item>
      </el-form>
      <el-alert v-if="schedule.issue" :title="schedule.issue" type="warning" :closable="false" show-icon />
      <el-alert v-if="schedule.type === 'malwarebazaar' && schedule.minutes > 60" title="该来源只覆盖最近 60 分钟，当前检查间隔可能遗漏情报。建议每 30 分钟检查。" type="warning" :closable="false" show-icon />
      <p class="hint">暂停后停止发起新任务，正在执行的任务会继续完成，已入库数据保留。控制台计划会保存在数据库中，重启后继续生效。</p>
      <template #footer>
        <el-button v-if="schedule.overridden" :disabled="schedule.saving" @click="saveSchedule(true)">恢复部署配置</el-button>
        <el-button :disabled="schedule.saving" @click="schedule.visible = false">取消</el-button>
        <el-button type="primary" :loading="schedule.saving" :disabled="!Number.isInteger(schedule.minutes) || schedule.enabled && !!schedule.issue" @click="saveSchedule(false)">保存</el-button>
      </template>
    </el-dialog>
    <el-dialog v-model="history.visible" :title="`${history.id} · 最近执行记录`" :width="compact ? 'calc(100% - 24px)' : '850px'">
      <el-button :loading="history.loading" @click="loadHistory">刷新记录</el-button>
      <el-alert v-if="history.error" :title="history.error" type="error" :closable="false" show-icon />
      <el-table v-loading="history.loading" :data="history.rows" stripe style="margin-top:12px" empty-text="暂无执行记录">
        <el-table-column label="触发方式" width="100"><template #default="{ row }">{{ row.trigger_type === 'scheduled' ? '定时' : '手动' }}</template></el-table-column>
        <el-table-column label="开始时间" min-width="170"><template #default="{ row }">{{ date(row.started_at) }}</template></el-table-column>
        <el-table-column label="结束时间" min-width="170"><template #default="{ row }">{{ date(row.finished_at) }}</template></el-table-column>
        <el-table-column label="结果" width="100"><template #default="{ row }">{{ runStatus[row.status] || row.status }}</template></el-table-column>
        <el-table-column prop="entry_count" label="有效条目" width="100" />
        <el-table-column prop="error" label="说明" min-width="220" />
      </el-table>
      <p class="hint">每个来源保留最近 50 次执行。成功检查表示本次同步完成，特征内容没有变化时不会重复发布。</p>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchLibraries, synchronizeLibrary, updateLibrarySchedule, resetLibrarySchedule, fetchLibraryRuns, importCveLibrary, importVirusDb, getUser } from '../api'

const state = ref({ sources: [], signature: {} })
const loading = ref(false), uploading = ref(false), syncing = ref(false), error = ref('')
const signatureInput = ref(), cveInput = ref()
const schedule = ref({ visible: false, saving: false })
const history = ref({ visible: false, id: '', rows: [], loading: false, error: '' })
const viewport = window.matchMedia('(max-width: 640px)')
const compact = ref(viewport.matches)
const updateViewport = () => { compact.value = viewport.matches }
const user = getUser()
const role = user?.role ?? user?.roleName
const isAdmin = role === 'admin'
const canImport = isAdmin || role === 'operator'
const types = { hashes: '恶意文件哈希', 'signature-zip': '病毒特征包', malwarebazaar: 'MalwareBazaar', misp: 'MISP 文件情报', 'cve-json': '漏洞比对规则', nvd: 'NVD 漏洞信息' }
const runStatus = { success: '成功', failed: '失败', running: '执行中', interrupted: '重启中断' }
const date = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
const nextCheck = value => !value ? '已暂停' : new Date(value).getTime() <= Date.now() ? '等待调度' : date(value)
let timer
function editSchedule(row) {
  schedule.value = { visible: true, saving: false, id: row.id, type: row.type, enabled: row.enabled, minutes: Math.ceil(row.intervalMs / 60000), minimum: row.minIntervalMs / 60000, overridden: row.scheduleOverridden, issue: row.configurationIssue }
}
async function saveSchedule(reset) {
  schedule.value.saving = true
  try {
    if (reset) await resetLibrarySchedule(schedule.value.id)
    else await updateLibrarySchedule(schedule.value.id, { enabled: schedule.value.enabled, intervalMs: schedule.value.minutes * 60000 })
    ElMessage.success(reset ? '已恢复部署配置中的同步计划' : '同步计划已保存')
    schedule.value.visible = false
    await load()
  } catch (e) { ElMessage.error(e.message) }
  finally { schedule.value.saving = false }
}
async function showHistory(id) {
  history.value = { visible: true, id, rows: [], loading: false, error: '' }
  await loadHistory()
}
async function loadHistory() {
  const id = history.value.id
  history.value.loading = true
  try {
    const rows = await fetchLibraryRuns(id)
    if (history.value.id === id) { history.value.rows = rows; history.value.error = '' }
  } catch (e) { if (history.value.id === id) history.value.error = e.message }
  finally { if (history.value.id === id) history.value.loading = false }
}
async function load() {
  if (loading.value) return
  loading.value = true
  try { state.value = await fetchLibraries(); error.value = '' }
  catch (e) { error.value = e.message }
  finally { loading.value = false }
}
async function synchronize(id) {
  syncing.value = true
  try {
    const result = await synchronizeLibrary(id)
    ElMessage({ message: result.accepted ? '同步任务已提交' : '已有同步任务正在执行', type: result.accepted ? 'success' : 'info' })
    await load()
  } catch (e) { ElMessage.error(e.message) }
  finally { syncing.value = false }
}
async function importFile(event, kind) {
  const file = event.target.files?.[0]
  if (!file) return
  uploading.value = true
  try {
    if (kind === 'signature') await importVirusDb(file)
    else await importCveLibrary(file)
    ElMessage.success('安全库已导入')
    await load()
  } catch (e) { ElMessage.error(e.message) }
  finally { uploading.value = false; event.target.value = '' }
}
onMounted(() => { load(); timer = setInterval(load, 5000); viewport.addEventListener('change', updateViewport) })
onUnmounted(() => { clearInterval(timer); viewport.removeEventListener('change', updateViewport) })
</script>

<style scoped>
.hint { color: #64748b; font-size: 12px; line-height: 1.8; }
</style>

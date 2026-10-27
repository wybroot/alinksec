<template>
  <el-dialog v-model="visible" :title="submitted ? '本次处置回执' : `确认${label}`" width="min(820px, calc(100vw - 24px))"
    :close-on-click-modal="!submitting" :close-on-press-escape="!submitting" :show-close="!submitting" @closed="invalidate">
    <template v-if="!submitted">
      <el-alert :title="warning" type="warning" :closable="false" show-icon />
      <p>本次{{ label }} {{ targets.length }} 个文件。提交时会重新检查文件状态；文件操作还需 Agent 按路径和摘要核验。</p>
      <div v-for="row in targets" :key="row.id" class="target">
        <strong>{{ row.host }}</strong> · 检出 #{{ row.id }}
        <p>{{ row.path }}</p><p class="digest">SHA256 {{ row.sha256 }}</p>
        <p v-if="row.quarantineId" class="digest">隔离编号 {{ row.quarantineId }}</p>
      </div>
      <el-checkbox v-model="confirmed" :disabled="submitting">我已核对以上主机和文件，确认{{ label }}</el-checkbox>
    </template>
    <template v-else>
      <div class="toolbar"><span>本次 {{ targets.length }} 项</span><el-button :loading="loading" @click="refresh">刷新本次回执</el-button></div>
      <p>成功 {{ summary.succeeded }} · 待确认 {{ summary.pending }} · 失败 {{ summary.failed }} · 超时 {{ summary.timeout }} · 策略已保存 {{ summary.committed }} · 未取得回执 {{ summary.unknown }}</p>
      <p class="digest">待确认时每 5 秒刷新。失败或超时可能已有部分本机操作，请复核当前状态后再处置；不会自动重试。加白不恢复文件，也不表示 Agent 已收到策略。</p>
      <div v-for="row in receipts" :key="row.id" class="target">
        <strong>{{ row.hostname || row.agent_id }}</strong> · 检出 #{{ row.finding_id }} · {{ stateLabel(row.state) }}
        <p>{{ row.request_evidence?.path || '未记录路径' }}</p>
        <p class="digest">SHA256 {{ row.request_evidence?.sha256 || '未知' }}</p>
        <p class="digest">{{ row.username || row.actor || '系统' }} · {{ fmt(row.created_at) }} → {{ fmt(row.finished_at) }}</p>
        <p v-if="row.error" class="failure">{{ row.error }}</p>
        <p v-if="row.receipt?.target?.quarantine_id" class="digest">回执隔离编号 {{ row.receipt.target.quarantine_id }}</p>
        <el-button link type="primary" @click="visible = false; emit('history', { id: row.finding_id })">查看文件完整历史</el-button>
      </div>
    </template>
    <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
    <template #footer>
      <el-button :disabled="submitting" @click="visible = false">{{ submitted ? '关闭' : '取消' }}</el-button>
      <el-button v-if="!submitted" type="danger" :disabled="!confirmed || submissionFailed" :loading="submitting" @click="submit">确认{{ label }} {{ targets.length }} 项</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { virusAct, fetchVirusActionReceipts } from '../api'
import { canDispose, dispositionSummary } from '../utils/virus'
const props = defineProps({ manageable: Boolean })
const emit = defineEmits(['updated', 'history'])
const visible = ref(false), targets = ref([]), action = ref(''), confirmed = ref(false)
const submitting = ref(false), submitted = ref(false), loading = ref(false), error = ref('')
const submissionFailed = ref(false)
const actionIds = ref([]), receipts = ref([])
let serial = 0, poll
const label = computed(() => ({ quarantine: '隔离', delete: '删除', restore: '恢复', whitelist: '加白' }[action.value] || '处置'))
const warning = computed(() => ({
  quarantine: '隔离会将匹配摘要的文件移入 Agent 隔离区，原路径将不可用。',
  delete: '删除会永久移除匹配摘要的文件或隔离对象，无法通过平台恢复。',
  restore: '恢复会将隔离对象放回原路径；请先确认误报或风险已消除，目标路径被占用时恢复会失败。',
  whitelist: '该 SHA256 将在全局放行，跨主机、跨路径生效。已有证据保留，隔离文件需另行恢复。',
}[action.value]))
const stateLabel = value => ({ pending: '待确认', succeeded: '已确认成功', failed: '失败', timeout: '超时，结果未确认', committed: '策略已保存' }[value] || '结果未知')
const fmt = value => value ? String(value).replace('T', ' ').slice(0, 19) : '—'
const summary = computed(() => dispositionSummary(actionIds.value, receipts.value))
const invalidate = () => { ++serial; loading.value = false }
const open = (rows, kind) => {
  if (!props.manageable || visible.value || submitting.value || !rows.length || rows.length > 32 || !rows.every(row => canDispose(row, kind))) return
  invalidate()
  targets.value = rows.map(row => ({ ...row })); action.value = kind
  confirmed.value = false; submitted.value = false; submissionFailed.value = false; error.value = ''; actionIds.value = []; receipts.value = []; visible.value = true
}
const refresh = async () => {
  if (!visible.value || !submitted.value || loading.value || !actionIds.value.length) return
  const current = ++serial
  loading.value = true
  try {
    const rows = await fetchVirusActionReceipts(actionIds.value)
    if (current === serial) { receipts.value = rows || []; error.value = '' }
  } catch (e) { if (current === serial) error.value = e?.message || '本次回执读取失败，请刷新重试' }
  finally { if (current === serial) loading.value = false }
}
const submit = async () => {
  if (!props.manageable || submitting.value || submitted.value || submissionFailed.value || !confirmed.value) return
  submitting.value = true; error.value = ''
  try {
    const accepted = await virusAct(targets.value.map(row => row.id), action.value)
    submitted.value = true
    actionIds.value = accepted?.actionIds || []
    emit('updated')
    if (actionIds.value.length !== targets.value.length) error.value = '请求已受理，但未取得完整处置编号。请关闭后查看每个文件的处置历史，勿重复提交。'
    else await refresh()
  } catch (e) {
    confirmed.value = false
    submissionFailed.value = true
    error.value = `${e?.message || '未收到提交结果'}。请关闭并刷新检出、查看处置历史，确认当前状态后再提交。`
    emit('updated')
  } finally { submitting.value = false }
}
onMounted(() => { poll = setInterval(() => { if (summary.value.pending || summary.value.unknown || error.value) refresh() }, 5000) })
onUnmounted(() => { clearInterval(poll); invalidate() })
defineExpose({ open })
</script>

<style scoped>
.target { padding: 10px 0; border-bottom: 1px solid #e2e8f0; overflow-wrap: anywhere; }
.target p { margin: 6px 0; }
.digest { font-size: 12px; color: #64748b; overflow-wrap: anywhere; }
.failure { color: #b91c1c; }
.toolbar { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
:deep(.el-checkbox) { white-space: normal; height: auto; max-width: 100%; align-items: flex-start; margin-top: 12px; }
:deep(.el-checkbox__label) { white-space: normal; line-height: 1.7; overflow-wrap: anywhere; }
:deep(.el-checkbox__input) { margin-top: 5px; }
</style>

<template>
  <div v-loading="loading" class="compliance-panel">
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <div class="toolbar"><el-button :disabled="busy" @click="load">刷新条款证据</el-button><el-button :disabled="!profiles.length || loading" @click="download">导出证据与复核记录</el-button></div>
    <el-empty v-if="!loading && !error && !profiles.length" description="该任务未使用带条款目录的合规包" />
    <section v-for="profile in profiles" :key="profile.templateId">
      <h3>{{ profile.scope }} · {{ profile.version }}</h3>
      <p>{{ profile.scopeNote }}</p>
      <p>条款 {{ profile.total }} · 已确认通过 {{ profile.counts.pass }} · 未通过 {{ profile.counts.fail }} · 异常 {{ profile.counts.error }} · 待核验 {{ profile.counts.pending }} · 不适用 {{ profile.counts.not_applicable }}</p>
      <p class="digest">快照 SHA256：{{ profile.contentSha256 }}</p>
      <el-table :data="profile.controls" row-key="id" max-height="520">
        <el-table-column type="expand"><template #default="{ row }">
          <div class="evidence"><p>核验要求：{{ row.evidence }}</p>
            <el-table :data="row.checks" empty-text="此条款需要人工收集现场证据"><el-table-column prop="name" label="自动证据检查" min-width="200" /><el-table-column label="结果" width="90"><template #default="{ row: check }">{{ state(check.execution_status || 'pending') }}</template></el-table-column><el-table-column label="实测值 / 原因" min-width="240"><template #default="{ row: check }">{{ check.actual || '—' }}<br />{{ check.message }}</template></el-table-column></el-table>
            <h4>复核历史</h4><el-table :data="row.history" empty-text="尚无人工复核"><el-table-column prop="revision" label="版本" width="65" /><el-table-column label="决定" width="100"><template #default="{ row: review }">{{ state(review.decision) }}</template></el-table-column><el-table-column prop="note" label="依据" min-width="220" /><el-table-column prop="evidence_ref" label="证据索引" min-width="180" /><el-table-column prop="reviewed_by" label="复核账号 ID" width="110" /><el-table-column prop="reviewed_at" label="时间" min-width="160" /></el-table>
          </div>
        </template></el-table-column>
        <el-table-column prop="id" label="条款" width="125" /><el-table-column prop="name" label="核验范围" min-width="190" />
        <el-table-column label="自动证据" width="115"><template #default="{ row }">{{ row.checks.length ? `${row.checks.length} 项 · ${state(row.automaticStatus)}` : '人工取证' }}</template></el-table-column>
        <el-table-column label="条款结论" width="110"><template #default="{ row }">{{ state(row.status) }}</template></el-table-column>
        <el-table-column v-if="admin" label="操作" width="85" fixed="right"><template #default="{ row }"><el-button link type="primary" :disabled="busy" @click="select(profile, row)">复核</el-button></template></el-table-column>
      </el-table>
    </section>
    <el-dialog v-model="form.visible" title="条款证据复核" append-to-body width="min(620px, calc(100vw - 32px))" :close-on-click-modal="!busy">
      <p>{{ form.control?.id }} · {{ form.control?.name }}</p><p>{{ form.control?.evidence }}</p>
      <el-form label-position="top"><el-form-item label="复核决定"><el-select v-model="form.decision" aria-label="条款复核决定"><el-option label="确认通过" value="pass" :disabled="!canConfirm" /><el-option label="确认未通过" value="fail" /><el-option label="确认不适用" value="not_applicable" :disabled="!canConfirm" /><el-option label="重新取证 / 待核验" value="pending" /></el-select></el-form-item>
        <el-form-item label="复核依据（不适用时须说明适用性判断）"><el-input v-model="form.note" type="textarea" :rows="4" maxlength="4000" aria-label="条款复核依据" /></el-form-item>
        <el-form-item label="证据索引（如工单编号、受控材料路径与 SHA256）"><el-input v-model="form.evidenceRef" maxlength="1024" aria-label="条款证据索引" /></el-form-item>
      </el-form><p v-if="!canConfirm">自动证据未完整通过，请先处理失败或异常并重新核查。</p>
      <template #footer><el-button :disabled="busy" @click="form.visible = false">取消</el-button><el-button type="primary" :loading="busy" @click="submit">保存复核记录</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchBaselineCompliance, reviewBaselineCompliance, getUser } from '../api'
const props = defineProps({ taskId: { type: [Number, String], required: true }, agentId: { type: String, required: true } })
const profiles = ref([]), loading = ref(false), busy = ref(false), error = ref('')
const admin = computed(() => getUser()?.role === 'admin')
const form = reactive({ visible: false, profile: null, control: null, decision: 'pending', note: '', evidenceRef: '' })
const canConfirm = computed(() => ['manual', 'pass'].includes(form.control?.automaticStatus))
const state = value => ({ pass: '通过', fail: '未通过', error: '执行异常', pending: '待核验', not_applicable: '不适用', manual: '人工取证', legacy: '旧结果' }[value] || value)
async function load() {
  loading.value = true; error.value = ''
  try { profiles.value = await fetchBaselineCompliance(props.taskId, props.agentId) }
  catch (e) { error.value = e.message; profiles.value = [] }
  finally { loading.value = false }
}
function select(profile, control) { Object.assign(form, { visible: true, profile, control, decision: 'pending', note: '', evidenceRef: '' }) }
async function submit() {
  if (form.note.trim().length < 10 || form.decision !== 'pending' && !form.evidenceRef.trim()) return ElMessage.warning('请填写至少 10 字的复核依据和证据索引')
  busy.value = true
  try {
    profiles.value = await reviewBaselineCompliance(props.taskId, props.agentId, { templateId: form.profile.templateId, controlId: form.control.id, revision: Number(form.control.revision), decision: form.decision, note: form.note, evidenceRef: form.evidenceRef })
    form.visible = false; ElMessage.success('复核记录已保存')
  } catch (e) { ElMessage.error(e.message) }
  finally { busy.value = false }
}
function download() {
  const url = URL.createObjectURL(new Blob([JSON.stringify({ taskId: props.taskId, agentId: props.agentId, exportedAt: new Date().toISOString(), profiles: profiles.value }, null, 2)], { type: 'application/json' }))
  const a = document.createElement('a'); a.href = url; a.download = `baseline-compliance-${props.taskId}.json`; a.click(); URL.revokeObjectURL(url)
}
onMounted(load)
</script>

<style scoped>
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px}.toolbar .el-button{margin:0}.evidence{padding:12px 20px}.compliance-panel p,.digest{overflow-wrap:anywhere}.digest{font:12px monospace;color:#64748b}section+section{margin-top:24px}.compliance-panel{min-width:0}
</style>

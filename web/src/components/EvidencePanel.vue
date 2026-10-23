<template>
  <div class="evidence-panel">
    <el-alert title="集中采集主机诊断包，或下载已隔离样本供分析。文件保留 30 天，单份最大 1 MiB。" type="info" :closable="false" />
    <el-form label-position="top" class="evidence-form" :disabled="busy">
      <el-form-item label="采集主机">
        <el-select v-model="form.agentId" filterable placeholder="选择在线主机" aria-label="取证主机" @change="changeTarget">
          <el-option v-for="host in targets" :key="host.agent_id" :value="host.agent_id" :label="host.hostname + (available(host) ? '' : '（离线或需升级 Agent）')" :disabled="!available(host)" />
        </el-select>
      </el-form-item>
      <el-form-item label="采集内容"><el-select v-model="form.kind" aria-label="采集内容" @change="form.findingId = null"><el-option label="主机诊断包" value="diagnostic" /><el-option label="已隔离样本" value="quarantine_sample" /></el-select></el-form-item>
      <el-form-item v-if="form.kind === 'quarantine_sample'" label="已隔离样本">
        <el-select v-model="form.findingId" :loading="sampleLoading" :disabled="sampleLoading || !!sampleError" placeholder="选择样本" aria-label="隔离样本"><el-option v-for="sample in samples" :key="sample.id" :value="sample.id" :label="`${sample.path} (${sample.size} 字节)`" :disabled="Number(sample.size) > 1048576" /></el-select>
        <p v-if="sampleError" class="evidence-error" role="alert">{{ sampleError }}</p>
        <p v-else-if="form.agentId && !sampleLoading && !samples.length" class="evidence-hint">该主机没有可导出的已隔离样本。</p>
      </el-form-item>
      <el-form-item label="用途说明"><el-input v-model="form.reason" maxlength="256" show-word-limit placeholder="如：排查防护覆盖异常，工单 SEC-123" aria-label="取证用途" /></el-form-item>
      <div><el-button type="primary" :loading="busy" :disabled="!canCollect" @click="collect">发起采集</el-button><el-button :disabled="busy || loading" @click="refresh">刷新状态</el-button></div>
    </el-form>
    <p class="evidence-hint">诊断包包含运行状态与资源计数。样本导出保留原隔离状态；只可在受控分析环境中处理。</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
    <div class="evidence-history-title"><h3>采集记录</h3><span class="evidence-hint">最多 200 条 / 文件总量 64 MiB</span></div>
    <p v-if="loading" role="status">正在读取采集记录…</p>
    <el-table v-else :data="rows" stripe size="small" empty-text="暂无采集记录">
      <el-table-column label="主机 / 用途" min-width="200"><template #default="{ row }"><strong>{{ hostName(row.agent_id) }}</strong><p>{{ row.reason }}</p><span class="evidence-hint">{{ timestamp(row.created_at) }}</span></template></el-table-column>
      <el-table-column label="内容" width="110"><template #default="{ row }">{{ row.kind === 'diagnostic' ? '诊断包' : '隔离样本' }}</template></el-table-column>
      <el-table-column label="状态" min-width="165"><template #default="{ row }"><el-tag :type="row.state === 'ready' ? 'success' : row.state === 'pending' ? 'warning' : 'danger'">{{ states[row.state] || row.state }}</el-tag><p v-if="row.error_code" class="evidence-error">{{ errors[row.error_code] || '采集未完成，请刷新或重新发起' }}</p><p v-if="row.state === 'pending'" class="evidence-hint">等待主机回传文件，刷新查看。</p></template></el-table-column>
      <el-table-column label="文件校验" min-width="230"><template #default="{ row }"><template v-if="row.state === 'ready'"><p>{{ row.size_bytes }} 字节 · {{ timestamp(row.collected_at) }}</p><code class="evidence-digest">{{ row.content_sha256 }}</code></template><span v-else>—</span></template></el-table-column>
      <el-table-column label="操作" width="130" fixed="right"><template #default="{ row }"><el-button link type="primary" :disabled="busy || row.state !== 'ready'" @click="download(row)">下载</el-button><el-button link type="danger" :disabled="busy || row.state === 'pending'" @click="remove(row)">删除</el-button></template></el-table-column>
    </el-table>
  </div>
</template>
<script setup>
import { computed, onMounted, onBeforeUnmount, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { fetchEvidence, fetchEvidenceTargets, fetchEvidenceSamples, collectEvidence, removeEvidence, downloadEvidence } from '../api'
const form = reactive({ agentId: '', kind: 'diagnostic', findingId: null, reason: '' })
const targets = ref([]), samples = ref([]), rows = ref([]), busy = ref(false), loading = ref(false), sampleLoading = ref(false), error = ref(''), sampleError = ref('')
let alive = true, targetSequence = 0, refreshSequence = 0
const states = { pending: '采集中', ready: '文件已就绪', failed: '采集失败', expired: '请求已超时' }
const errors = { request_expired: '十分钟内未收到文件', command_timeout: '主机未及时响应', command_failed: '主机未完成采集', collection_unavailable_or_limit_exceeded: '采集失败：文件不可用、身份变化或超过限制', storage_quota_exceeded: '存储已满，请清理旧文件' }
const available = host => host.status === 1 && host.evidence_contract === 1 && [1, 2].includes(host.os_type)
const canCollect = computed(() => !busy.value && !loading.value && !!form.reason.trim() && targets.value.some(host => host.agent_id === form.agentId && available(host)) && (form.kind === 'diagnostic' || (!!form.findingId && !sampleLoading.value && !sampleError.value)))
const timestamp = value => value ? new Date(Number(value)).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : '—'
const hostName = agent => targets.value.find(host => host.agent_id === agent)?.hostname || agent
async function refresh() {
  const sequence = ++refreshSequence; loading.value = true; error.value = ''
  const results = await Promise.allSettled([fetchEvidenceTargets(), fetchEvidence()])
  if (!alive || sequence !== refreshSequence) return
  if (results[0].status === 'fulfilled') targets.value = results[0].value
  if (results[1].status === 'fulfilled') rows.value = results[1].value
  error.value = results.filter(result => result.status === 'rejected').map(result => result.reason?.message || '读取失败').join('；')
  loading.value = false
}
async function changeTarget() {
  const sequence = ++targetSequence; form.findingId = null; samples.value = []; sampleError.value = ''; sampleLoading.value = true
  if (!form.agentId) { sampleLoading.value = false; return }
  try { const data = await fetchEvidenceSamples(form.agentId); if (alive && sequence === targetSequence) samples.value = data }
  catch (e) { if (alive && sequence === targetSequence) sampleError.value = e.message || '样本读取失败' }
  finally { if (alive && sequence === targetSequence) sampleLoading.value = false }
}
async function collect() {
  if (!canCollect.value) return
  busy.value = true; error.value = ''
  try { await collectEvidence({ ...form, findingId: form.kind === 'quarantine_sample' ? form.findingId : null }); if (alive) { ElMessage.success('采集请求已提交'); await refresh() } }
  catch (e) { if (alive) error.value = e.message || '采集请求失败' }
  finally { if (alive) busy.value = false }
}
async function download(row) {
  if (busy.value) return
  if (row.kind === 'quarantine_sample') {
    try { await ElMessageBox.confirm('该文件是已隔离样本，可能包含恶意内容。请仅在受控分析环境中处理。', '下载隔离样本', { type: 'warning', confirmButtonText: '下载样本', cancelButtonText: '取消' }) } catch { return }
  }
  busy.value = true; error.value = ''
  try { await downloadEvidence(row) }
  catch (e) { if (alive) error.value = e.message || '下载失败' }
  finally { if (alive) busy.value = false }
}
async function remove(row) {
  if (busy.value) return
  try { await ElMessageBox.confirm('删除集中保存的文件及记录？主机上的隔离样本将保留。', '删除采集记录', { type: 'warning', confirmButtonText: '删除记录', cancelButtonText: '取消' }) } catch { return }
  busy.value = true; error.value = ''
  try { await removeEvidence(row.id); if (alive) await refresh() }
  catch (e) { if (alive) error.value = e.message || '删除失败' }
  finally { if (alive) busy.value = false }
}
onMounted(refresh)
onBeforeUnmount(() => { alive = false; targetSequence++; refreshSequence++ })
</script>
<style scoped>
.evidence-form { display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 18px;max-width:900px;margin-top:18px }
.evidence-form .el-select { width:100% }.evidence-hint{color:var(--text-secondary,#74839d);font-size:12px;line-height:1.7}.evidence-error{color:var(--el-color-danger);font-size:12px;overflow-wrap:anywhere}.evidence-digest{font-size:11px;overflow-wrap:anywhere}.evidence-history-title{display:flex;align-items:center;gap:16px;margin-top:24px}.evidence-panel p{margin:6px 0}
@media(max-width:640px){.evidence-form{grid-template-columns:1fr}.evidence-history-title{display:block}.evidence-panel{min-width:0}}
</style>

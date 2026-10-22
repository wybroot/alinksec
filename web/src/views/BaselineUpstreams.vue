<template>
  <div class="upstreams-page">
    <div class="header"><div><h2>基线来源更新</h2><p>从已配置的签名来源发现新版本，导入后进入候选审核。</p></div><el-button :loading="loading" @click="refresh(true)">刷新</el-button></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" />
    <el-empty v-if="!loading && !sources.length && !error" description="尚未配置基线更新来源，请在服务器配置来源、公钥及允许的包编号。" />
    <el-table v-if="sources.length" :data="sources" stripe highlight-current-row @row-click="select">
      <el-table-column prop="name" label="来源" min-width="180" />
      <el-table-column label="更新计划" width="130"><template #default="{ row }">{{ !row.configured ? '配置已移除' : row.enabled ? '定时更新' : '已暂停' }}</template></el-table-column>
      <el-table-column label="签名序号" width="100"><template #default="{ row }">{{ row.sequence || '—' }}</template></el-table-column>
      <el-table-column label="最近结果" min-width="160"><template #default="{ row }">{{ label(row.last_outcome) }}</template></el-table-column>
      <el-table-column label="最近检查" min-width="180"><template #default="{ row }">{{ time(row.last_checked) }}</template></el-table-column>
      <el-table-column label="操作" width="90"><template #default="{ row }"><el-button link type="primary" @click.stop="select(row)">查看</el-button></template></el-table-column>
    </el-table>
    <section v-if="selected && detail" class="panel" v-loading="busy">
      <h3>{{ selected.name }}</h3>
      <el-descriptions :column="1" border>
        <el-descriptions-item label="索引来源"><span class="wrap">{{ selected.url || '配置已移除' }}</span></el-descriptions-item>
        <el-descriptions-item label="签名公钥指纹"><span class="digest">{{ selected.keySha256 || '—' }}</span></el-descriptions-item>
        <el-descriptions-item label="允许更新的包"><span class="wrap">{{ selected.scopes?.join('、') || '—' }}</span></el-descriptions-item>
        <el-descriptions-item label="当前签名索引">{{ detail.receipt ? `序号 ${detail.receipt.sequence} · 有效至 ${time(detail.receipt.expires_at)}` : '尚无已验证索引' }}</el-descriptions-item>
      </el-descriptions>
      <el-alert v-if="expired" title="签名索引已过期。候选版本需在来源恢复并同步有效索引后继续审核、测试或发布。" type="warning" :closable="false" />
      <el-alert v-if="detail.last_outcome && !['success','partial'].includes(detail.last_outcome)" :title="`最近更新：${label(detail.last_outcome)}`" type="warning" :closable="false" />
      <div v-if="admin && selected.configured" class="plan">
        <el-form label-position="top" @submit.prevent="save">
          <el-form-item label="定时更新"><el-switch v-model="enabled" aria-label="定时更新" /></el-form-item>
          <el-form-item label="更新间隔（小时）"><el-input-number v-model="hours" :min="1" :max="168" :precision="0" aria-label="更新间隔（小时）" /></el-form-item>
          <el-form-item label="调整说明"><el-input v-model="note" maxlength="2000" placeholder="填写本次调整原因" /></el-form-item>
          <div class="buttons"><el-button type="primary" :disabled="busy || !note.trim()" @click="save">保存更新计划</el-button><el-button :disabled="busy || !detail.enabled || running" @click="sync">立即同步</el-button></div>
        </el-form>
      </div>
      <div class="buttons"><el-button v-if="detail.receipt" @click="downloadReceipt(detail.receipt.id)">下载当前签名索引</el-button><span v-if="running">正在同步，结果将自动刷新。</span></div>
      <h3>发现的版本</h3>
      <p class="hint">上游撤回会阻止候选继续采用。已发布规则可在版本审核页人工撤回；历史任务保留原内容。</p>
      <el-table :data="detail.releases" stripe>
        <el-table-column label="内容" min-width="220"><template #default="{ row }">{{ row.code }} · {{ row.version }}<div class="hint">{{ row.kind === 'scap' ? 'SCAP' : '基线模板' }} · {{ row.os_type === 2 ? 'Windows' : 'Linux' }}</div></template></el-table-column>
        <el-table-column label="来源状态" min-width="140"><template #default="{ row }"><el-tag :type="row.remote_status === 'withdrawn' || row.expires_at <= Date.now() ? 'warning' : 'info'">{{ row.remote_status === 'withdrawn' ? '上游已撤回' : row.expires_at <= Date.now() ? '索引已过期' : '有效' }}</el-tag></template></el-table-column>
        <el-table-column label="导入结果" min-width="180"><template #default="{ row }">{{ label(row.state) }}<div class="hint" v-if="row.issue">{{ label(row.issue) }} · 已尝试 {{ row.attempts }} 次</div></template></el-table-column>
        <el-table-column label="操作" min-width="200"><template #default="{ row }"><div class="buttons">
          <el-button v-if="row.package_id" link type="primary" @click="candidate(row)">查看候选版本</el-button>
          <el-button v-if="admin && row.state === 'failed' && row.remote_status === 'active'" link :disabled="busy || !detail.enabled || running" @click="retry(row)">重新尝试</el-button>
          <el-button link @click="downloadReceipt(row.first_receipt)">首次签名凭据</el-button>
          <el-button v-if="row.import_receipt && row.import_receipt !== row.first_receipt && row.import_receipt !== row.current_receipt" link @click="downloadReceipt(row.import_receipt)">导入签名凭据</el-button>
          <el-button v-if="row.current_receipt !== row.first_receipt" link @click="downloadReceipt(row.current_receipt)">当前签名凭据</el-button>
          <el-button v-if="row.package_id" link @click="downloadArtifact(row)">下载原件</el-button>
        </div></template></el-table-column>
      </el-table>
      <h3>更新记录</h3><p class="hint">展示最近 100 条更新和计划操作；自动更新记为系统操作。</p>
      <el-table :data="detail.attempts" stripe>
        <el-table-column label="开始时间" min-width="175"><template #default="{ row }">{{ time(row.started_at) }}</template></el-table-column>
        <el-table-column label="触发方式" width="130"><template #default="{ row }">{{ label(row.trigger_type) }}</template></el-table-column>
        <el-table-column label="操作人" width="120"><template #default="{ row }">{{ row.actor ? `用户 ${row.actor}` : '系统' }}</template></el-table-column>
        <el-table-column label="结果" min-width="190"><template #default="{ row }">{{ label(row.outcome) }}{{ row.issue ? ` · ${label(row.issue)}` : '' }}</template></el-table-column>
        <el-table-column prop="imported" label="导入数量" width="100" />
        <el-table-column prop="note" label="操作说明" min-width="180" />
      </el-table>
    </section>
  </div>
</template>
<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getUser, fetchBaselineUpstreams, fetchBaselineUpstream, updateBaselineUpstream, syncBaselineUpstream, retryBaselineUpstream, downloadBaselineUpstream } from '../api'
const route = useRoute(), router = useRouter(), admin = computed(() => getUser()?.role === 'admin')
const sources = ref([]), selected = ref(null), detail = ref(null), loading = ref(false), busy = ref(false), error = ref('')
const enabled = ref(false), hours = ref(1), note = ref(''), planRevision = ref(null)
const expired = computed(() => detail.value?.receipt && detail.value.receipt.expires_at <= Date.now())
const running = computed(() => detail.value?.attempts?.some(a => ['queued','running'].includes(a.outcome)))
let timer, generation = 0, disposed = false
const time = n => n ? new Date(Number(n)).toLocaleString() : '—'
const label = value => ({ success: '成功', partial: '部分版本未导入', failed: '失败', imported: '已导入候选', pending: '等待导入', running: '执行中', queued: '等待执行', worker_busy: '其他服务器正在同步，等待下一轮', interrupted: '执行中断', manual: '手动同步', scheduled: '定时同步', schedule: '调整计划', retry: '重试版本', index_invalid: '签名、有效期或内容范围校验失败', index_expired: '签名索引已过期', index_rollback: '拒绝旧序号或同序号不同内容', index_new_sequence_required: '来源配置变更后需要新索引序号', release_changed: '同版本内容发生变更或尝试恢复已撤回版本', release_capacity: '版本记录已达容量上限', artifact_capacity: '原件存储已达容量上限', artifact_download: '原件下载失败', artifact_digest: '原件大小或摘要不匹配', artifact_identity: '包编号、版本或系统不匹配', artifact_invalid: '包内容或原生解析无效', artifact_import: '候选导入失败', package_already_adopted: '该版本已进入审核流程，无法重新绑定来源', package_already_bound: '该候选已绑定其他来源记录', source_changed: '来源计划或配置已变化', worker_interrupted: '更新中断，等待重试', release_unavailable: '版本已撤回或索引过期', sync_failed: '更新失败，请检查来源和服务器连接' }[value] || value || '尚未检查')
function applyPlan(value) { enabled.value = !!value.enabled; hours.value = value.interval_ms / 3600000; planRevision.value = value.revision }
async function refresh(resetPlan = false) {
  if (loading.value) return
  loading.value = true; error.value = ''
  const token = generation
  try {
    const list = await fetchBaselineUpstreams()
    if (disposed || token !== generation) return
    sources.value = list
    if (selected.value) {
      selected.value = list.find(s => s.id === selected.value.id) || null
      if (selected.value) { const value = await fetchBaselineUpstream(selected.value.id); if (!disposed && token === generation) { detail.value = value; if (resetPlan) { applyPlan(value); note.value = '' } } }
    }
  } catch (e) { if (!disposed && token === generation) error.value = e.message }
  finally { loading.value = false }
}
async function select(source) {
  if (busy.value) return
  const token = ++generation; selected.value = source; detail.value = null; note.value = ''; error.value = ''
  try { const value = await fetchBaselineUpstream(source.id); if (disposed || token !== generation) return; detail.value = value; applyPlan(value) }
  catch (e) { if (!disposed && token === generation) error.value = e.message }
}
async function act(action) {
  if (busy.value) return
  busy.value = true
  try { await action(); await refresh() } catch (e) { ElMessage.error(e.message) }
  finally { busy.value = false }
}
function save() { if (!detail.value || !note.value.trim()) return; const id = selected.value.id, plan = { revision: planRevision.value, enabled: enabled.value, intervalMs: hours.value * 3600000, note: note.value }; return act(async () => { const value = await updateBaselineUpstream(id, plan); if (selected.value?.id === id) { applyPlan(value); note.value = '' } ElMessage.success('更新计划已保存') }) }
function sync() { return act(async () => { await syncBaselineUpstream(selected.value.id); ElMessage.success('同步已提交，请查看更新记录') }) }
function retry(row) { return act(async () => { await retryBaselineUpstream(selected.value.id, row.id); ElMessage.success('版本已加入下一轮重试') }) }
function candidate(row) { router.push({ path: row.kind === 'scap' ? '/scap' : '/baseline-templates', query: { package: row.package_id } }) }
async function downloadReceipt(id) { try { await downloadBaselineUpstream(`/api/baseline/upstreams/${encodeURIComponent(selected.value.id)}/receipts/${encodeURIComponent(id)}`, 'signed-index.json') } catch (e) { ElMessage.error(e.message) } }
async function downloadArtifact(row) { try { await downloadBaselineUpstream(`/api/baseline/upstreams/${encodeURIComponent(selected.value.id)}/releases/${encodeURIComponent(row.id)}/artifact`, row.kind === 'scap' ? 'upstream-original.zip' : 'upstream-original.json') } catch (e) { ElMessage.error(e.message) } }
onMounted(async () => { await refresh(); if (sources.value.length) await select(sources.value.find(s => s.id === route.query.source) || sources.value[0]); if (!disposed) timer = setInterval(() => { if (!busy.value) refresh() }, 5000) })
onUnmounted(() => { disposed = true; generation++; clearInterval(timer) })
</script>
<style scoped>
.upstreams-page{display:flex;flex-direction:column;gap:16px;min-width:0}.header{display:flex;justify-content:space-between;gap:16px;align-items:center}.header h2{margin:0}.header p,.hint{color:#64748b;font-size:13px}.panel{min-width:0}.wrap,.digest{overflow-wrap:anywhere}.digest{font-family:monospace;font-size:12px}.buttons{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.buttons .el-button{margin:0}.plan{margin:20px 0;max-width:640px}.el-alert{margin-top:12px}h3{margin-top:24px}@media(max-width:600px){.header{align-items:flex-start}.plan{max-width:100%}}
</style>

<template>
  <section class="panel source-trust" style="margin-top:16px">
    <h4>来源信任与冲突</h4>
    <p class="hint">信任等级由管理员复核设置。先比较等级，再比较优先级；同级同优先级的内部规则或 CVE 适用范围不一致时暂停采用。哈希名称、严重程度和公告文字差异保留可查。</p>
    <p class="hint">隔离保留原始声明并允许继续同步，但不贡献当前检测依据。指定来源或暂停采用绑定本次候选摘要，候选或策略变化后须重新复核。离线 Agent 收到新库后生效。</p>
    <el-alert v-if="Number(delivery?.signature_pending) || Number(delivery?.match_pending)" type="warning" :closable="false" title="来源依据已保存，特征下发或资产重评仍待重试。已排队不代表所有 Agent 已应用。" />
    <el-table :data="sources" stripe>
      <el-table-column prop="id" label="来源" min-width="140" />
      <el-table-column label="信任等级" min-width="110"><template #default="{ row }">{{ tiers[row.policy?.tier || 'unreviewed'] }}</template></el-table-column>
      <el-table-column label="优先级" width="90"><template #default="{ row }">{{ row.policy?.priority ?? (row.id === 'manual' ? 100 : 0) }}</template></el-table-column>
      <el-table-column label="采用状态" min-width="100"><template #default="{ row }">{{ row.retired ? '已退役' : row.policy?.quarantined ? '已隔离' : '参与选择' }}</template></el-table-column>
      <el-table-column label="策略" min-width="120"><template #default="{ row }"><el-button link @click="openPolicy(row)">{{ isAdmin && !row.retired ? '管理策略' : '查看策略' }}</el-button></template></el-table-column>
    </el-table>
    <div class="selection-filters">
      <el-select v-model="filter.kind" aria-label="情报类型" @change="query"><el-option label="漏洞 CVE" value="cve" /><el-option label="恶意文件哈希" value="hash" /><el-option label="内部规则" value="rule" /></el-select>
      <el-input v-model="filter.keyword" placeholder="CVE、哈希或规则名" maxlength="255" @keyup.enter="query" />
      <el-checkbox v-model="filter.multiple" @change="query">仅多来源条目</el-checkbox>
      <el-button :loading="list.loading" @click="query">查询来源选择</el-button>
    </div>
    <el-alert v-if="list.error" :title="list.error" type="error" :closable="false" />
    <el-table :data="list.rows" v-loading="list.loading">
      <el-table-column prop="key" label="条目" min-width="180" show-overflow-tooltip />
      <el-table-column prop="candidateCount" label="来源数" width="90" />
      <el-table-column label="当前处理" min-width="140"><template #default="{ row }">{{ reasons[row.reason] || row.reason }}</template></el-table-column>
      <el-table-column label="采用来源" min-width="130"><template #default="{ row }">{{ row.effective ? row.selectedSource : '暂停采用' }}</template></el-table-column>
      <el-table-column label="差异" min-width="130"><template #default="{ row }">{{ row.applicabilityConflict ? '同级声明不一致' : row.documentConflict ? '内容有差异' : '一致' }}</template></el-table-column>
      <el-table-column label="依据" width="100"><template #default="{ row }"><el-button link @click="openSelection(row)">查看与复核</el-button></template></el-table-column>
    </el-table>
    <el-pagination v-model:current-page="filter.page" :total="list.total" :page-size="20" layout="prev, pager, next" @current-change="loadList" />
  </section>
  <el-dialog v-model="policy.visible" :title="`${policy.id} · 来源策略`" :width="dialogWidth" :close-on-click-modal="!policy.saving" :close-on-press-escape="!policy.saving" :show-close="!policy.saving" @closed="closePolicy">
    <el-alert v-if="policy.error" :title="policy.error" type="error" :closable="false" />
    <div v-loading="policy.loading">
      <el-form label-position="top" :disabled="policyDisabled">
        <el-form-item label="信任等级"><el-select v-model="policy.tier" aria-label="信任等级"><el-option v-for="(label, value) in tiers" :key="value" :label="label" :value="value" /></el-select></el-form-item>
        <!-- InputNumber snapshots aria-disabled on mount; keep it aligned with the form state. -->
        <el-form-item label="优先级（0 至 100，数字越大越优先）"><el-input-number :key="policyDisabled" v-model="policy.priority" :min="0" :max="100" :precision="0" /></el-form-item>
        <el-form-item label="隔离此来源"><el-switch v-model="policy.quarantined" /></el-form-item>
        <el-form-item label="变更原因"><el-input v-model="policy.note" type="textarea" maxlength="2000" show-word-limit /></el-form-item>
      </el-form>
      <p class="hint">当前修订 {{ policy.revision }}。策略变化将重新选择该来源的全部现有 CVE，并重新发布受影响的特征库。关联补丁复核可能失效。</p>
      <el-button :disabled="policy.saving" @click="reloadPolicy">刷新当前策略</el-button>
      <el-button v-if="isAdmin && !policy.retired" type="primary" :loading="policy.saving" :disabled="policy.loading || !policy.loaded || !policy.note?.trim()" @click="savePolicy">保存来源策略</el-button>
      <h4>最近策略记录</h4><p class="hint">每个来源最多保留 50 条；快照保留策略和统计，不复制全部历史公告。</p>
      <div v-for="event in policy.events" :key="event.id" class="selection-event"><p>{{ event.recorded_at }} · 账号 {{ event.actor }} · {{ event.note }}</p><details><summary>策略依据</summary><pre>{{ JSON.stringify(event.snapshot, null, 2) }}</pre></details></div>
    </div>
  </el-dialog>
  <el-dialog v-model="detail.visible" title="条目来源选择" :width="compact ? 'calc(100% - 24px)' : '900px'" :close-on-click-modal="!detail.saving" :close-on-press-escape="!detail.saving" :show-close="!detail.saving" @closed="closeDetail">
    <el-alert v-if="detail.error" :title="detail.error" type="error" :closable="false" />
    <div v-loading="detail.loading" v-if="detail.value">
      <p class="selection-key">{{ detail.value.key }}</p><p>{{ reasons[detail.value.reason] || detail.value.reason }} · 当前采用 {{ detail.value.selectedSource || '无' }}</p>
      <p class="hint selection-key">候选摘要 {{ detail.value.contextDigest }}</p>
      <el-table :data="detail.value.candidates">
        <el-table-column prop="sourceId" label="来源" min-width="140" />
        <el-table-column label="等级 / 优先级" min-width="145"><template #default="{ row }">{{ tiers[row.tier] }} / {{ row.priority }}</template></el-table-column>
        <el-table-column label="状态" min-width="110"><template #default="{ row }">{{ row.quarantined ? '已隔离' : row.withdrawn ? '撤销声明' : '可选择' }}</template></el-table-column>
        <el-table-column prop="documentDigest" label="内容摘要" min-width="160" show-overflow-tooltip />
        <el-table-column label="原始声明" width="100"><template #default="{ row }"><el-button link :disabled="detail.saving" @click="viewCandidate(row.sourceId)">查看内容</el-button></template></el-table-column>
      </el-table>
      <el-alert v-if="candidate.error" :title="candidate.error" type="error" :closable="false" />
      <div v-loading="candidate.loading" v-if="candidate.value"><h4>{{ candidate.source }} · 原始声明</h4><pre>{{ JSON.stringify(candidate.value.declaration, null, 2) }}</pre></div>
      <el-alert v-if="detail.value.contextComplete === false" type="warning" :closable="false" title="当前来源超过128个，条目暂停采用。请先退役多余来源，再刷新完整候选并复核。此处仅显示前128个候选，摘要不代表全部内容。" />
      <el-form v-if="isAdmin && detail.value.contextComplete !== false" label-position="top" :disabled="detail.saving || detail.loading">
        <el-form-item label="处理方式"><el-radio-group v-model="detail.action"><el-radio value="automatic">恢复自动选择</el-radio><el-radio value="select">指定来源</el-radio><el-radio value="suppress">暂停采用</el-radio></el-radio-group></el-form-item>
        <el-form-item v-if="detail.action === 'select'" label="采用来源"><el-select v-model="detail.source" aria-label="采用来源"><el-option v-for="item in eligible" :key="item.sourceId" :value="item.sourceId" :label="item.sourceId" /></el-select></el-form-item>
        <el-form-item label="复核原因"><el-input v-model="detail.note" type="textarea" maxlength="2000" show-word-limit /></el-form-item>
        <p class="hint">整条选择，不合并字段。暂停采用和指定来源只适用于此摘要下的候选；内容变化后暂停采用并等待复核。当前决定修订 {{ detail.value.decision?.revision || 0 }}。</p>
        <el-button type="primary" :loading="detail.saving" :disabled="!detail.note?.trim() || (detail.action === 'select' && !detail.source)" @click="saveDecision">提交处理决定</el-button>
      </el-form>
      <el-button style="margin-top:12px" :disabled="detail.saving" @click="reloadDetail">刷新候选与决定</el-button>
      <h4>最近处理记录</h4><p class="hint">每个条目最多 50 条；记录保存当时候选内容摘要和处理依据。当前原始声明可在上表查看。</p>
      <div v-for="event in detail.events" :key="event.id" class="selection-event"><p>{{ event.recorded_at }} · 账号 {{ event.actor }} · {{ event.note }}</p><details><summary>处理依据</summary><pre>{{ JSON.stringify(event.snapshot, null, 2) }}</pre></details></div>
    </div>
  </el-dialog>
</template>

<script setup>
import { computed, onUnmounted, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchSourcePolicy, updateSourcePolicy, fetchSourceSelections, fetchSourceSelection, fetchSelectionCandidate, fetchSelectionHistory, decideSourceSelection } from '../api'
const props = defineProps({ sources: { type: Array, default: () => [] }, delivery: Object, isAdmin: Boolean, compact: Boolean })
const emit = defineEmits(['changed'])
const tiers = { unreviewed: '未复核', reviewed: '已复核', preferred: '优先采用' }
const reasons = { ranked: '按等级与优先级选择', single_source: '单一来源', reviewed: '管理员指定来源', unresolved_conflict: '同级冲突，等待复核', stale_decision: '候选已变化，等待复核', suppressed: '管理员暂停采用', source_unavailable: '指定来源不可用', no_eligible_source: '没有可用来源', candidate_capacity: '来源超出上限，暂停采用' }
const dialogWidth = computed(() => props.compact ? 'calc(100% - 24px)' : '650px')
const filter = reactive({ kind: 'cve', keyword: '', multiple: true, page: 1 })
const list = reactive({ rows: [], total: 0, loading: false, error: '' })
const policy = reactive({ visible: false, loading: false, saving: false, id: '', events: [], error: '' })
const policyDisabled = computed(() => !props.isAdmin || policy.retired || policy.saving || policy.loading || !policy.loaded)
const detail = reactive({ visible: false, loading: false, saving: false, value: null, events: [], error: '', action: 'automatic', source: '', note: '' })
const candidate = reactive({ value: null, source: '', loading: false, error: '' })
const eligible = computed(() => detail.value?.candidates?.filter(item => !item.quarantined) || [])
let listRequest = 0, policyRequest = 0, detailRequest = 0, candidateRequest = 0
onUnmounted(() => { listRequest++; policyRequest++; detailRequest++; candidateRequest++ })
function query() { filter.page = 1; return loadList() }
async function loadList() {
  const request = ++listRequest; list.loading = true; list.error = ''
  try { const data = await fetchSourceSelections({ ...filter, size: 20 }); if (request === listRequest) { list.rows = data.list || []; list.total = data.total || 0 } }
  catch (e) { if (request === listRequest) { list.error = e.message; list.rows = []; list.total = 0 } }
  finally { if (request === listRequest) list.loading = false }
}
function closePolicy() { policyRequest++ }
async function openPolicy(row) {
  policyRequest++; Object.assign(policy, { visible: true, id: row.id, retired: row.retired, note: '', events: [], error: '', loaded: false, tier: 'unreviewed', priority: 0, quarantined: false, revision: 0 }); await reloadPolicy()
}
async function reloadPolicy() {
  const request = ++policyRequest, id = policy.id; policy.loading = true; policy.error = ''; policy.loaded = false
  try { const [value, history] = await Promise.all([fetchSourcePolicy(id), fetchSelectionHistory('source', id)]); if (request === policyRequest && policy.visible) Object.assign(policy, value, { note: '', loaded: true, events: history.list || [] }) }
  catch (e) { if (request === policyRequest) policy.error = e.message }
  finally { if (request === policyRequest) policy.loading = false }
}
async function savePolicy() {
  if (!props.isAdmin || policy.saving || policy.loading || !policy.loaded) return
  policy.saving = true; policy.error = ''; const id = policy.id, request = policyRequest
  try {
    await updateSourcePolicy(id, { tier: policy.tier, priority: policy.priority, quarantined: policy.quarantined, revision: policy.revision, note: policy.note.trim() })
    if (request === policyRequest) { policy.visible = false; ElMessage.success('来源策略已保存；下发和资产重评按队列执行') }
    emit('changed'); await loadList()
  } catch (e) { if (request === policyRequest) policy.error = e.message }
  finally { policy.saving = false }
}
function closeDetail() { detailRequest++; candidateRequest++; candidate.value = null }
async function openSelection(row) {
  closeDetail(); Object.assign(detail, { visible: true, kind: row.kind, key: row.key, value: null, events: [], error: '' }); await reloadDetail()
}
async function reloadDetail() {
  const request = ++detailRequest, { kind, key } = detail; candidateRequest++; candidate.value = null; candidate.error = ''; detail.loading = true; detail.error = ''
  try {
    const [value, history] = await Promise.all([fetchSourceSelection(kind, key), fetchSelectionHistory(kind, key)])
    if (request === detailRequest && detail.visible) Object.assign(detail, { value, events: history.list || [], action: value.decision?.action || 'automatic', source: value.decision?.selectedSource || '', note: '' })
  } catch (e) { if (request === detailRequest) { detail.error = e.message; detail.value = null } }
  finally { if (request === detailRequest) detail.loading = false }
}
async function viewCandidate(source) {
  const request = ++candidateRequest, context = detail.value.contextDigest; Object.assign(candidate, { loading: true, value: null, error: '', source })
  try {
    const value = await fetchSelectionCandidate(detail.kind, detail.key, source)
    if (request === candidateRequest && detail.visible) {
      if (value.contextDigest !== context) throw new Error('候选已变化，请刷新候选与决定后重新查看')
      candidate.value = value
    }
  } catch (e) { if (request === candidateRequest) candidate.error = e.message }
  finally { if (request === candidateRequest) candidate.loading = false }
}
async function saveDecision() {
  if (!props.isAdmin || detail.saving || detail.loading || !detail.value) return
  detail.saving = true; detail.error = ''; const request = detailRequest
  try {
    await decideSourceSelection({ kind: detail.kind, key: detail.key, action: detail.action, source: detail.action === 'select' ? detail.source : '', contextDigest: detail.value.contextDigest, revision: detail.value.decision?.revision || 0, note: detail.note.trim() })
    if (request === detailRequest && detail.visible) { ElMessage.success('条目处理决定已保存'); await reloadDetail() }
    emit('changed'); await loadList()
  } catch (e) { if (request === detailRequest) detail.error = e.message }
  finally { detail.saving = false }
}
</script>

<style scoped>
.selection-filters { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin:16px 0; }
.selection-filters .el-select { width:170px; }
.selection-filters .el-input { max-width:300px; }
.selection-key { overflow-wrap:anywhere; }
pre { white-space:pre-wrap; overflow-wrap:anywhere; max-height:360px; overflow:auto; padding:12px; background:var(--el-fill-color-light); }
.selection-event { border-top:1px solid var(--el-border-color); padding:8px 0; }
@media (max-width:640px) { .selection-filters .el-input,.selection-filters .el-select { width:100%; max-width:none; } }
</style>

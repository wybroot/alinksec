<template>
  <div class="template-page">
    <div class="page-header"><div><h2>基线模板</h2><p>依据 Agent 上报的系统选择已发布模板；候选版本需经审核和测试。</p></div><el-button :loading="loading" @click="load">刷新</el-button></div>
    <el-alert v-if="loadError" :title="loadError" type="error" :closable="false" />
    <el-alert v-if="legacyRetired" title="旧 Linux 参考模板已停用。历史核查保留；新核查请导入适用候选包，确认检查范围并完成审核、测试和发布。" type="info" :closable="false" />
    <div v-if="admin" class="panel import-panel">
      <label>候选模板包 <input type="file" accept=".json,application/json" @change="file = $event.target.files[0]" /></label>
      <el-button type="primary" :disabled="!file" :loading="busy" @click="importFile">导入候选版本</el-button>
      <p>导入只保存检查定义。审核、测试核查与发布分别执行。</p>
    </div>
    <div class="panel"><h3>已发布模板 · 系统覆盖</h3>
      <el-table :data="templates" stripe empty-text="尚无已发布模板，请导入并审核相应系统的模板包">
        <el-table-column prop="name" label="模板" min-width="230" />
        <el-table-column label="系统" width="100"><template #default="{ row }">{{ os(row.os_type) }}</template></el-table-column>
        <el-table-column prop="version" label="版本" width="90" />
        <el-table-column label="适用系统版本" min-width="180"><template #default="{ row }">{{ row.os_version_pattern || '该类型全部版本' }}</template></el-table-column>
        <el-table-column prop="item_count" label="检查项" width="90" />
      </el-table>
    </div>
    <div class="panel"><h3>候选与历史版本</h3>
      <el-table :data="packages" stripe>
        <el-table-column prop="name" label="模板" min-width="220" />
        <el-table-column label="系统" width="100"><template #default="{ row }">{{ os(row.os_type) }}</template></el-table-column>
        <el-table-column prop="version" label="版本" width="100" />
        <el-table-column prop="supported_count" label="可核查" width="85" />
        <el-table-column prop="unsupported_count" label="未支持" width="85" />
        <el-table-column label="状态" width="100"><template #default="{ row }">{{ status(row.status) }}</template></el-table-column>
        <el-table-column label="操作" width="100" fixed="right"><template #default="{ row }"><el-button link type="primary" @click="open(row.id)">查看版本</el-button></template></el-table-column>
      </el-table>
    </div>
    <el-dialog v-model="visible" title="基线模板版本" width="min(960px, calc(100vw - 32px))" class="package-dialog" style="margin-top:3vh" :close-on-click-modal="!busy">
      <div v-loading="detailLoading" style="max-height:calc(80vh - 130px);overflow-y:auto">
        <el-alert v-if="detailError" :title="detailError" type="error" :closable="false" />
        <template v-if="detail">
          <h3>{{ detail.document.name }} · {{ detail.version }} · {{ status(detail.status) }}</h3>
          <p>{{ os(detail.document.osType) }} · {{ detail.document.product }} · {{ detail.document.osVersionPattern }}</p>
          <p>来源：<a :href="detail.document.source.url" target="_blank" rel="noopener noreferrer">{{ detail.document.source.name }}</a> · {{ detail.document.source.version }}</p>
          <p class="digest">来源 SHA256：{{ detail.document.source.sha256 }}<br />模板内容 SHA256：{{ detail.content_sha256 }}</p>
          <p v-if="detail.review_note">审核说明：{{ detail.review_note }}</p><p v-if="detail.publication_note">发布 / 撤回说明：{{ detail.publication_note }}</p>
          <h4>来源与适用范围变更</h4>
          <el-table :data="detail.metadataDiff" max-height="220"><el-table-column prop="field" label="字段" width="140" /><el-table-column label="原版本" min-width="180"><template #default="{ row }"><pre>{{ json(row.before) }}</pre></template></el-table-column><el-table-column label="候选版本" min-width="180"><template #default="{ row }"><pre>{{ json(row.after) }}</pre></template></el-table-column></el-table>
          <h4>相对导入时发布版本的差异（{{ detail.diff.length }}）</h4>
          <el-table :data="detail.diff" max-height="300" empty-text="检查项内容未变化">
            <el-table-column prop="ruleId" label="原始规则编号" min-width="230" />
            <el-table-column label="变更" width="85"><template #default="{ row }">{{ change(row.change) }}</template></el-table-column>
            <el-table-column label="内容" min-width="200"><template #default="{ row }"><details><summary>查看前后内容</summary><pre>原版本：{{ json(row.before) }}
候选版本：{{ json(row.after) }}</pre></details></template></el-table-column>
          </el-table>
          <h4>检查项（{{ detail.document.items.length }}）</h4>
          <el-table :data="detail.document.items" max-height="260">
            <el-table-column prop="name" label="检查项" min-width="180" />
            <el-table-column prop="ruleId" label="原始规则" min-width="180" />
            <el-table-column label="检查定义" min-width="220"><template #default="{ row }"><pre>{{ json(row.check) }}</pre></template></el-table-column>
          </el-table>
          <h4>未支持规则（{{ detail.document.unsupported.length }}，不计入核查得分）</h4>
          <el-table :data="detail.document.unsupported" max-height="220" empty-text="没有标记为未支持的规则"><el-table-column prop="ruleId" label="原始规则" min-width="200" /><el-table-column prop="reason" label="原因" min-width="250" /></el-table>
          <template v-if="detail.testTask"><h4>测试核查 · 任务 {{ detail.testTask.task_no }} · {{ Number(detail.testTask.status) === 2 ? '已完成' : '尚未完整结束' }}</h4>
            <el-alert v-if="Number(detail.testTask.status) === 2 && !detail.testReady" title="测试存在执行异常或无法确认的旧 Agent 结果。请检查原因、更新 Agent 并重新测试后发布。" type="error" :closable="false" />
            <el-table :data="detail.testResults"><el-table-column type="expand"><template #default="{ row }"><el-table :data="row.items"><el-table-column prop="name" label="检查项" min-width="180" /><el-table-column label="结果" width="80"><template #default="{ row: item }">{{ outcome(item) }}</template></el-table-column><el-table-column label="实测值 / 原因" min-width="240"><template #default="{ row: item }"><div>{{ item.actual || '—' }}</div><div v-if="item.message">{{ item.message }}</div></template></el-table-column></el-table></template></el-table-column><el-table-column prop="agent_id" label="测试主机" min-width="180" /><el-table-column prop="passed_count" label="通过" /><el-table-column prop="failed_count" label="未通过" /><el-table-column prop="error_count" label="执行异常" /><el-table-column prop="legacy_count" label="旧结果" /><el-table-column prop="score" label="得分" /></el-table>
          </template>
          <div v-if="admin" class="actions">
            <el-input v-model="note" type="textarea" :rows="2" maxlength="2000" placeholder="审核、发布或撤回说明；发布时请说明测试结果及未通过项" aria-label="审核说明" />
            <div v-if="detail.status === 'candidate'" class="button-row"><el-button :loading="busy" @click="act('reject')">拒绝候选版本</el-button><el-button type="primary" :loading="busy" @click="act('approve')">审核通过</el-button></div>
            <template v-if="detail.status === 'approved'">
              <p>仅向所选测试主机下发核查，不执行修复。</p>
              <el-select v-model="testAgents" multiple filterable placeholder="选择 1 至 10 台适用测试主机" aria-label="测试主机" style="width:100%"><el-option v-for="host in detail.testTargets" :key="host.agent_id" :value="host.agent_id" :label="`${host.hostname} · ${host.os_version || os(host.os_type)}`" /></el-select>
              <div class="button-row"><el-button :disabled="!testAgents.length" :loading="busy" @click="act('test')">下发测试核查</el-button><el-button type="primary" :disabled="!detail.testReady" :loading="busy" @click="act('publish')">发布为可选模板</el-button><el-button type="warning" :loading="busy" @click="act('withdraw')">撤回版本</el-button></div>
            </template>
            <div v-if="detail.status === 'published'" class="button-row"><el-button type="warning" :loading="busy" @click="act('withdraw')">撤回版本</el-button></div>
          </div>
        </template>
      </div>
      <template #footer><el-button :disabled="busy" @click="open(detail.id)" v-if="detail">刷新版本</el-button><el-button :disabled="busy" @click="visible = false">关闭</el-button></template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getUser, fetchBaselineTemplates, fetchBaselinePackages, fetchBaselinePackage, importBaselinePackage, reviewBaselinePackage, testBaselinePackage, publishBaselinePackage, withdrawBaselinePackage } from '../api'
const admin = computed(() => getUser()?.role === 'admin')
const packages = ref([]), templates = ref([]), loading = ref(false), loadError = ref(''), file = ref(null), busy = ref(false)
const legacyRetired = ref(false)
const visible = ref(false), detail = ref(null), detailLoading = ref(false), detailError = ref(''), note = ref(''), testAgents = ref([])
const os = (type) => ({ 1: 'Linux', 2: 'Windows' }[Number(type)] || '未知系统')
const status = (value) => ({ candidate: '待审核', approved: '待测试 / 发布', published: '已发布', withdrawn: '已撤回', rejected: '已拒绝' }[value] || value)
const outcome = (item) => item.execution_status === 'error' ? '执行异常' : item.execution_status === 'legacy' ? '旧结果' : item.passed ? '通过' : '不合规'
const change = (value) => ({ added: '新增', changed: '修改', removed: '撤销' }[value] || value)
const json = (value) => value == null ? '无' : JSON.stringify(value, null, 2)
async function load() {
  loading.value = true; loadError.value = ''
  try { const [list, published] = await Promise.all([fetchBaselinePackages(), fetchBaselineTemplates()]); packages.value = list; templates.value = published.filter((t) => t.enabled === true || t.enabled === 1); legacyRetired.value = published.some((t) => t.code === 'DJBH2.0-LINUX' && !(t.enabled === true || t.enabled === 1)) }
  catch (e) { loadError.value = e.message }
  finally { loading.value = false }
}
async function open(id) {
  visible.value = true; detailLoading.value = true; detailError.value = ''; detail.value = null; note.value = ''; testAgents.value = []
  try { detail.value = await fetchBaselinePackage(id) }
  catch (e) { detailError.value = e.message }
  finally { detailLoading.value = false }
}
async function importFile() {
  if (!file.value || busy.value) return
  busy.value = true
  try { const result = await importBaselinePackage(file.value); await load(); await open(result.id); ElMessage.success('候选模板已导入，等待审核') }
  catch (e) { ElMessage.error(e.message) }
  finally { busy.value = false }
}
async function act(action) {
  if (busy.value) return
  if (action !== 'test' && !note.value.trim()) return ElMessage.warning('请填写说明')
  busy.value = true
  try {
    const id = detail.value.id
    const actions = { approve: () => reviewBaselinePackage(id, true, note.value), reject: () => reviewBaselinePackage(id, false, note.value), test: () => testBaselinePackage(id, testAgents.value), publish: () => publishBaselinePackage(id, note.value), withdraw: () => withdrawBaselinePackage(id, note.value) }
    detail.value = await actions[action](); note.value = ''; testAgents.value = []; await load(); ElMessage.success('版本状态已更新')
  } catch (e) { ElMessage.error(e.message) }
  finally { busy.value = false }
}
onMounted(load)
</script>

<style scoped>
.page-header{display:flex;justify-content:space-between;align-items:center;gap:16px}.page-header h2{margin:0}.page-header p,.import-panel p{color:#64748b;font-size:13px}.panel{margin-top:16px}.import-panel{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.import-panel p{width:100%;margin:0}.digest,pre{font-family:monospace;font-size:12px;overflow-wrap:anywhere;white-space:pre-wrap}pre{margin:8px 0;max-height:240px;overflow:auto}.actions{display:grid;gap:12px;margin-top:18px}.button-row{display:flex;gap:8px;flex-wrap:wrap}.button-row .el-button{margin:0}.package-dialog h4{margin:18px 0 8px}a{color:#2563eb}.template-page{min-width:0}.package-dialog p{overflow-wrap:anywhere}@media(max-width:600px){.page-header{align-items:flex-start}.package-dialog{--el-dialog-margin-top:3vh}.import-panel input{max-width:100%}}
</style>

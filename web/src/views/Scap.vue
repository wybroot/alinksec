<template>
  <div class="scap-page" v-loading="loading">
    <el-alert title="离线标准核查" description="导入内容后，先审核并在适用主机上完成测试，再发布使用。自动核查结果仍需结合现场证据作出合规判断。" type="info" :closable="false" />
    <div class="toolbar">
      <el-button @click="refresh">刷新</el-button>
      <el-button v-if="admin" type="primary" @click="fileInput.click()">导入 SCAP ZIP</el-button>
      <input ref="fileInput" type="file" accept=".zip" hidden @change="upload" />
      <el-button v-if="canRun" @click="openCreate">发起标准核查</el-button>
    </div>
    <el-tabs v-model="tab">
      <el-tab-pane label="内容与审核" name="packages">
        <el-table :data="packages" stripe @row-click="viewPackage">
          <el-table-column prop="name" label="内容" min-width="200" />
          <el-table-column prop="version" label="版本" width="100" />
          <el-table-column label="系统" width="100"><template #default="{ row }">{{ row.os_type === 2 ? 'Windows' : 'Linux' }}</template></el-table-column>
          <el-table-column label="状态" width="140"><template #default="{ row }">{{ label(row.status) }}</template></el-table-column>
          <el-table-column prop="code" label="内容编号" min-width="180" />
          <el-table-column label="操作" width="90"><template #default="{ row }"><el-button link type="primary" @click.stop="viewPackage(row)">查看</el-button></template></el-table-column>
        </el-table>
      </el-tab-pane>
      <el-tab-pane label="核查任务" name="tasks">
        <el-table :data="tasks.items" stripe @row-click="viewTask">
          <el-table-column prop="name" label="任务" min-width="220" />
          <el-table-column label="用途" width="100"><template #default="{ row }">{{ row.test_mode ? '内容测试' : '正式核查' }}</template></el-table-column>
          <el-table-column label="执行状态" width="140"><template #default="{ row }">{{ label(row.state) }}</template></el-table-column>
          <el-table-column prop="created_at" label="创建时间" min-width="180" />
          <el-table-column label="主机数" width="100"><template #default="{ row }">{{ row.hosts?.length || 0 }}</template></el-table-column>
        </el-table>
        <el-pagination :current-page="page" :page-size="20" :total="tasks.total || 0" layout="prev, pager, next" @current-change="changePage" />
      </el-tab-pane>
      <el-tab-pane label="引擎就绪状态" name="targets">
        <el-table :data="targets" stripe>
          <el-table-column prop="hostname" label="主机" min-width="180" />
          <el-table-column prop="os_version" label="系统" min-width="180" />
          <el-table-column label="就绪状态" width="140"><template #default="{ row }">{{ label(row.state) }}</template></el-table-column>
          <el-table-column label="引擎" width="110"><template #default="{ row }">{{ row.coverage?.version ? `SCC ${row.coverage.version}` : '—' }}</template></el-table-column>
          <el-table-column label="最近异常" min-width="180"><template #default="{ row }">{{ row.coverage?.last_issue || '—' }}</template></el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="packageVisible" title="SCAP 内容审核" width="min(960px, calc(100vw - 32px))">
      <template v-if="selected">
        <BaselineUpstreamProvenance :entries="selected.upstream" />
        <el-descriptions :column="1" border>
          <el-descriptions-item label="内容">{{ selected.name }} · {{ selected.version }} · {{ label(selected.status) }}</el-descriptions-item>
          <el-descriptions-item label="Benchmark">{{ selected.metadata.manifest.benchmarkId }}</el-descriptions-item>
          <el-descriptions-item label="Profile">{{ selected.metadata.manifest.profileId }}</el-descriptions-item>
          <el-descriptions-item label="适用系统">{{ selected.os_type === 2 ? 'Windows' : 'Linux' }} · {{ selected.os_version_pattern }}</el-descriptions-item>
          <el-descriptions-item label="导入文件 SHA256"><span class="hash">{{ selected.source_sha256 }}</span></el-descriptions-item>
          <el-descriptions-item label="下发内容 SHA256"><span class="hash">{{ selected.content_sha256 }}</span></el-descriptions-item>
          <el-descriptions-item label="标准解析">{{ selected.resolution?.resolver || '—' }} · 已解析 XCCDF 继承关系</el-descriptions-item>
        </el-descriptions>
        <div class="toolbar">
          <el-button @click="download(`/api/baseline/scap/packages/${selected.id}/source`, 'scap-original.zip')">下载原始内容</el-button>
          <el-button @click="download(`/api/baseline/scap/packages/${selected.id}/content`, 'scap-content.zip')">下载下发内容</el-button>
          <el-button v-if="selected.last_test_task" @click="viewTask({ id: selected.last_test_task })">查看最近测试</el-button>
        </div>
        <template v-if="admin && ['candidate', 'approved', 'published'].includes(selected.status)">
          <el-input v-model="note" type="textarea" maxlength="2000" show-word-limit placeholder="填写审核、测试或发布说明" />
          <el-select v-if="selected.status === 'approved'" v-model="testTargets" multiple filterable placeholder="选择适用且就绪的测试主机（最多 10 台）" style="width:100%;margin-top:12px">
            <el-option v-for="host in applicable(selected)" :key="host.agent_id" :label="`${host.hostname} · ${host.os_version}`" :value="host.agent_id" />
          </el-select>
          <div class="toolbar">
            <template v-if="selected.status === 'candidate'">
              <el-button type="primary" :loading="saving" @click="decide('approve')">批准测试</el-button><el-button type="danger" :loading="saving" @click="decide('reject')">拒绝内容</el-button>
            </template>
            <template v-if="selected.status === 'approved'">
              <el-button :loading="saving" @click="decide('test')">下发内容测试</el-button>
              <el-button type="primary" :disabled="!selected.testReady" :loading="saving" @click="decide('publish')">发布内容</el-button>
              <span class="hint">发布需要完整测试结果，且无 error／unknown。</span>
            </template>
            <el-button v-if="['approved', 'published'].includes(selected.status)" :loading="saving" @click="decide('withdraw')">撤回内容</el-button>
          </div>
        </template>
        <h4>规则清单（{{ selected.metadata.rules.length }}）</h4>
        <el-table :data="selected.metadata.rules" max-height="260"><el-table-column prop="id" label="规则标识" min-width="240" /><el-table-column prop="title" label="标题" min-width="200" /></el-table>
        <h4>审核记录</h4>
        <el-table :data="selected.reviews"><el-table-column prop="revision" label="修订" width="70" /><el-table-column prop="action" label="操作" width="110" /><el-table-column prop="note" label="说明" min-width="240" /><el-table-column prop="actor" label="操作人" width="90" /><el-table-column prop="created_at" label="时间" min-width="170" /></el-table>
      </template>
    </el-dialog>

    <el-dialog v-model="createVisible" title="发起标准核查" width="min(640px, calc(100vw - 32px))">
      <el-form label-width="90px">
        <el-form-item label="任务名称"><el-input v-model="form.name" maxlength="128" aria-label="任务名称" /></el-form-item>
        <el-form-item label="已发布内容"><el-select v-model="form.packageId" style="width:100%" @change="form.agentIds = []"><el-option v-for="item in packages.filter(p => p.status === 'published')" :key="item.id" :label="`${item.name} · ${item.version}`" :value="item.id" /></el-select></el-form-item>
        <el-form-item label="目标主机"><el-select v-model="form.agentIds" multiple filterable style="width:100%"><el-option v-for="host in applicable(packages.find(p => p.id === form.packageId))" :key="host.agent_id" :label="`${host.hostname} · ${host.os_version}`" :value="host.agent_id" /></el-select><span class="hint">仅显示系统类型匹配且原生引擎就绪的主机，最多 20 台；提交时检查系统版本。</span></el-form-item>
      </el-form>
      <template #footer><el-button @click="createVisible = false">取消</el-button><el-button type="primary" :loading="saving" @click="create">下发核查</el-button></template>
    </el-dialog>

    <el-dialog v-model="taskVisible" title="标准核查结果" width="min(1080px, calc(100vw - 32px))">
      <template v-if="task">
        <p>{{ task.name }} · {{ label(task.state) }} · {{ task.test_mode ? '内容测试' : '正式核查' }}</p>
        <p class="hint">执行完成表示结果完整。请分别查看失败、异常、未知、未检查和不适用项，再判断是否满足合规要求。</p>
        <p class="hash">内容 SHA256：{{ task.content_sha256 }}</p>
        <div class="toolbar"><el-button @click="viewTask(task)">刷新结果</el-button><el-button @click="download(`/api/baseline/scap/tasks/${task.id}/content`, 'scap-task-content.zip')">下载任务内容快照</el-button></div>
        <el-collapse v-model="expandedHosts">
          <el-collapse-item v-for="host in task.hosts" :key="host.agent_id" :name="host.agent_id" :title="`${host.agent_id} · ${label(host.state)}${host.issue ? ' · ' + host.issue : ''}`">
            <template v-if="host.evidence?.state">
              <p class="hash">证据 SHA256：{{ host.evidence_sha256 }}</p>
              <p class="hash">原生结果 SHA256：{{ host.evidence.sourceResultSha256 || '—' }}</p>
              <p class="hash">引擎 SHA256：{{ host.runtime_sha256 }}</p>
              <div class="outcomes"><el-tag v-for="(count, result) in host.evidence.counts" :key="result" :type="result === 'pass' ? 'success' : ['fail', 'error'].includes(result) ? 'danger' : 'info'">{{ outcome(result) }} {{ count }}</el-tag></div>
              <p v-for="score in host.evidence.scores" :key="score.system" class="hint">{{ score.system }}：{{ score.value }} / {{ score.maximum }}</p>
              <el-button @click="download(`/api/baseline/scap/tasks/${task.id}/agents/${host.agent_id}/evidence`, 'scap-evidence.json')">导出核查证据</el-button>
              <el-table :data="host.evidence.rules" max-height="360"><el-table-column prop="ruleId" label="规则" min-width="300" /><el-table-column label="标准结果" min-width="180"><template #default="{ row }">{{ outcome(row.result) }}</template></el-table-column><el-table-column prop="weight" label="权重" width="100" /></el-table>
            </template>
            <el-empty v-else description="尚无 Agent 原生结果；终态指令状态不能替代核查证据" :image-size="60" />
          </el-collapse-item>
        </el-collapse>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import BaselineUpstreamProvenance from '../components/BaselineUpstreamProvenance.vue'
const route = useRoute()
import { ElMessage } from 'element-plus'
import { getUser, fetchScapPackages, fetchScapPackage, importScapPackage, decideScapPackage, fetchScapTargets, fetchScapTasks, fetchScapTask, createScapTask, downloadScap } from '../api'

const admin = computed(() => getUser()?.role === 'admin')
const canRun = computed(() => ['admin', 'operator'].includes(getUser()?.role))
const loading = ref(false), saving = ref(false), packages = ref([]), targets = ref([]), tasks = ref({ items: [], total: 0 }), page = ref(1), tab = ref('packages')
const fileInput = ref(), selected = ref(null), task = ref(null), packageVisible = ref(false), taskVisible = ref(false), createVisible = ref(false)
const note = ref(''), testTargets = ref([]), expandedHosts = ref([]), form = ref({ name: '', packageId: '', agentIds: [] })
const labels = { candidate: '待审核', approved: '已审核待测试发布', rejected: '已拒绝', published: '已发布', withdrawn: '已撤回', starting: '引擎检查中', disabled: '未启用', ready: '就绪', running: '执行中', unavailable: '不可用', offline: '离线', unsupported: 'Agent 不支持', stale: '状态已过期', pending: '等待结果', complete: '执行完成', partial: '部分执行失败', failed: '执行失败', timeout: '已超时' }
const names = { pass: '通过', fail: '失败', error: '执行异常', unknown: '未知', notapplicable: '不适用', notchecked: '未检查', notselected: '未选择', informational: '信息项', fixed: '已修复' }
const label = value => labels[value] || value
const outcome = value => `${names[value] || value} (${value})`
const applicable = content => content ? targets.value.filter(h => h.state === 'ready' && Number(h.os_type) === Number(content.os_type)) : []
async function refresh() {
  loading.value = true
  try { packages.value = await fetchScapPackages(); targets.value = await fetchScapTargets(); tasks.value = await fetchScapTasks(page.value) } catch (e) { packages.value = []; targets.value = []; tasks.value = { items: [], total: 0 }; ElMessage.error(e.message) } finally { loading.value = false }
}
async function viewPackage(row) { selected.value = null; try { selected.value = await fetchScapPackage(row.id); note.value = ''; testTargets.value = []; packageVisible.value = true } catch (e) { ElMessage.error(e.message) } }
async function viewTask(row) { task.value = null; try { task.value = await fetchScapTask(row.id); expandedHosts.value = task.value.hosts.map(h => h.agent_id); taskVisible.value = true } catch (e) { ElMessage.error(e.message) } }
async function upload(event) {
  const file = event.target.files?.[0]; event.target.value = ''
  if (!file) return
  if (file.size > 2 * 1024 * 1024) return ElMessage.error('SCAP ZIP 最多 2 MiB')
  saving.value = true
  try { const value = await importScapPackage(file); await refresh(); await viewPackage(value); ElMessage.success('内容已导入，等待审核') } catch (e) { ElMessage.error(e.message) } finally { saving.value = false }
}
async function decide(action) {
  if (!note.value.trim()) return ElMessage.error('请填写操作说明')
  if (action === 'test' && (!testTargets.value.length || testTargets.value.length > 10)) return ElMessage.error('请选择 1 至 10 台测试主机')
  saving.value = true
  try { selected.value = await decideScapPackage(selected.value.id, { revision: selected.value.revision, action, note: note.value, agentIds: testTargets.value }); note.value = ''; await refresh(); ElMessage.success('内容状态已更新') } catch (e) { ElMessage.error(e.message) } finally { saving.value = false }
}
function openCreate() { form.value = { name: '', packageId: '', agentIds: [] }; createVisible.value = true }
async function create() {
  if (!form.value.packageId || !form.value.agentIds.length || form.value.agentIds.length > 20) return ElMessage.error('请选择已发布内容和 1 至 20 台主机')
  saving.value = true
  try { const value = await createScapTask(form.value); createVisible.value = false; tab.value = 'tasks'; await refresh(); await viewTask({ id: value.taskId }) } catch (e) { ElMessage.error(e.message) } finally { saving.value = false }
}
async function changePage(value) { page.value = value; await refresh() }
async function download(path, name) { try { await downloadScap(path, name) } catch (e) { ElMessage.error(e.message) } }
onMounted(async () => { await refresh(); if (typeof route.query.package === 'string') await viewPackage({ id: route.query.package }) })
watch(() => route.query.package, value => { if (typeof value === 'string') viewPackage({ id: value }) })
</script>

<style scoped>
.scap-page { display:flex; flex-direction:column; gap:16px; min-width:0; }
.toolbar { display:flex; flex-wrap:wrap; align-items:center; gap:10px; margin:12px 0; }
.hash { overflow-wrap:anywhere; font-family:monospace; font-size:12px; }
.hint { color:#64748b; font-size:12px; line-height:1.7; }
.outcomes { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }
:deep(.el-descriptions__content) { overflow-wrap:anywhere; }
</style>

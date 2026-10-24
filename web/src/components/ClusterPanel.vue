<template>
  <section class="cluster-panel" aria-label="服务集群">
    <div class="cluster-toolbar"><div><h3>服务集群</h3><p class="hint">查看服务副本与报告处理状态。</p></div><el-button :loading="loading" :disabled="busy" @click="refresh">刷新集群状态</el-button></div>
    <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
    <p v-if="loading && !data" role="status">正在读取集群状态…</p>
    <template v-if="data">
      <el-alert v-if="stale" title="下方保留上次读取结果，请刷新后再操作。" type="warning" :closable="false" />
      <el-alert v-if="data.mode === 'single'" title="单实例运行" description="当前部署使用单实例模式。" type="info" :closable="false" />
      <template v-else>
        <el-alert :title="data.ready ? '当前服务节点就绪' : '当前服务节点暂不可用'" :description="data.ready ? `节点 ${data.nodeId}` : issue(data.issue)" :type="data.ready ? 'success' : 'error'" :closable="false" />
        <div class="cluster-stats"><div><span>待处理报告</span><strong>{{ data.queue.pending }}</strong><small>上限 {{ data.limits.pendingReports }}</small></div><div><span>处理失败</span><strong>{{ data.queue.dead }}</strong><small>最近 100 条可在下方查看</small></div><div><span>报告存储</span><strong>{{ bytes(data.queue.stored_bytes) }}</strong><small>上限 {{ bytes(data.limits.storedBytes) }}</small></div><div><span>通知重试已用尽</span><strong>{{ data.failedNotifications }}</strong><small>请检查告警通道</small></div></div>
        <p class="hint">读取时间：{{ timestamp(data.observedAt) }}<span v-if="data.queue.oldest_pending_at"> · 最早等待：{{ timestamp(data.queue.oldest_pending_at) }}</span></p>
        <h4>服务节点</h4>
        <el-table :data="data.nodes" stripe size="small" empty-text="暂无节点记录">
          <el-table-column prop="node_id" label="节点" min-width="150" />
          <el-table-column label="状态" width="100"><template #default="{ row }"><el-tag :type="Number(row.lease_until) > Number(data.observedAt) ? 'success' : 'info'">{{ Number(row.lease_until) > Number(data.observedAt) ? '租约有效' : '租约已过期' }}</el-tag></template></el-table-column>
          <el-table-column label="路由记录" width="110"><template #default="{ row }">{{ row.sessions }}</template></el-table-column>
          <el-table-column label="租约截止" min-width="180"><template #default="{ row }">{{ timestamp(row.lease_until) }}</template></el-table-column>
          <el-table-column label="配置一致" width="110"><template #default="{ row }">{{ row.configuration_sha256 === data.configurationSha256 ? '一致' : '不一致' }}</template></el-table-column>
        </el-table>
        <h4>失败报告</h4>
        <p class="hint">恢复依赖或主机状态后可人工重试，最多三次。重试会重新处理该报告；请先核对主机与报告摘要。</p>
        <el-table :data="data.deadReports" stripe size="small" empty-text="暂无失败报告">
          <el-table-column label="主机 / 报告" min-width="220"><template #default="{ row }"><code>{{ row.agent_id }}</code><p class="hint">{{ kinds[row.payload_type] || row.payload_type }} · {{ timestamp(row.created_at) }}</p></template></el-table-column>
          <el-table-column label="失败原因" min-width="200"><template #default="{ row }">{{ reportIssues[row.error_code] || '报告处理失败，请检查服务状态' }}<p class="hint">已尝试 {{ row.attempts }} 次 · 人工重试 {{ row.replay_count }} / 3</p></template></el-table-column>
          <el-table-column label="报告摘要" min-width="230"><template #default="{ row }"><code class="digest">{{ row.content_sha256 }}</code><p class="hint">{{ bytes(row.size_bytes) }}</p></template></el-table-column>
          <el-table-column label="操作" width="110" fixed="right"><template #default="{ row }"><el-button link type="primary" :disabled="!canRetry(row)" @click="openRetry(row)">重试报告</el-button></template></el-table-column>
        </el-table>
      </template>
    </template>
    <el-dialog v-model="dialog" title="重试失败报告" width="min(520px, calc(100vw - 32px))" :close-on-click-modal="!busy" :close-on-press-escape="!busy" :show-close="!busy">
      <el-alert v-if="error" :title="error" type="error" :closable="false" role="alert" />
      <template v-if="selected"><p>主机：<code>{{ selected.agent_id }}</code></p><p>报告摘要：</p><code class="digest">{{ selected.content_sha256 }}</code><el-form label-position="top"><el-form-item label="重试说明"><el-input v-model="note" type="textarea" maxlength="500" show-word-limit :rows="3" :disabled="busy" aria-label="报告重试说明" /></el-form-item></el-form></template>
      <template #footer><el-button :disabled="busy" @click="dialog = false">取消</el-button><el-button type="primary" :loading="busy" :disabled="!note.trim() || stale || !data?.ready" @click="retry">确认重试</el-button></template>
    </el-dialog>
  </section>
</template>
<script setup>
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchClusterStatus, retryClusterReport } from '../api'
const data = ref(null), loading = ref(false), busy = ref(false), error = ref(''), stale = ref(false), dialog = ref(false), selected = ref(null), note = ref('')
let alive = true, sequence = 0
const kinds = { ASSET: '资产报告', BASELINE_RESULT: '基线结果', LOG_BATCH: '日志批次' }
const reportIssues = { report_rejected: '内容校验失败，无法重试', agent_revoked: '主机已停用或删除', processing_failed: '业务处理失败，请先恢复服务' }
const issues = { redis_unavailable: '会话协调服务暂不可用', rabbit_unavailable: '报告队列服务暂不可用', postgres_unavailable: '数据库暂不可用', cluster_shared_storage_mismatch: '节点无法读取一致的共享存储', cluster_material_changed: '共享证书或配置材料已变化', cluster_node_replaced: '节点身份已被其他进程接管', cluster_readiness_expired: '节点状态长时间未更新', cluster_redis_configuration_mismatch: '会话协调配置不一致' }
const issue = code => issues[code] || '节点协调状态异常，请检查部署与依赖服务'
const bytes = value => Number(value) < 1048576 ? `${Number(value).toLocaleString('zh-CN')} B` : `${(Number(value) / 1048576).toFixed(1)} MiB`
const timestamp = value => Number(value) > 0 ? new Date(Number(value)).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }) : '—'
const canRetry = row => !loading.value && !busy.value && !stale.value && !!data.value?.ready && Number(row.replay_count) < 3 && row.error_code !== 'report_rejected'
async function refresh() {
  const current = ++sequence; loading.value = true; error.value = ''
  try { const result = await fetchClusterStatus(); if (alive && current === sequence) { data.value = result; stale.value = false } }
  catch (e) { if (alive && current === sequence) { error.value = e.message || '读取集群状态失败'; stale.value = true } }
  finally { if (alive && current === sequence) loading.value = false }
}
function openRetry(row) { if (!canRetry(row)) return; selected.value = row; note.value = ''; dialog.value = true }
async function retry() {
  if (busy.value || stale.value || !note.value.trim() || !selected.value || !data.value?.ready) return
  busy.value = true; error.value = ''
  try { await retryClusterReport(selected.value.id, { sha256: selected.value.content_sha256, note: note.value.trim() }); if (alive) { dialog.value = false; ElMessage.success('报告已重新排队'); await refresh() } }
  catch (e) { if (alive) { error.value = e.message || '报告重试失败'; stale.value = true } }
  finally { if (alive) busy.value = false }
}
onMounted(refresh)
onBeforeUnmount(() => { alive = false; sequence++ })
</script>
<style scoped>
.cluster-panel { min-width:0 }.cluster-toolbar { display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:14px;flex-wrap:wrap }h3 { margin:0 }h4 { margin:24px 0 12px }.hint,small { color:#94a3b8;font-size:12px }.cluster-stats { display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:18px 0 }.cluster-stats>div { background:var(--el-fill-color-light);border:1px solid var(--el-border-color-lighter);padding:16px;border-radius:8px;display:grid;gap:8px }.cluster-stats strong { font-size:24px }.cluster-stats span { font-size:13px }.digest,code { overflow-wrap:anywhere;word-break:break-all;font-size:12px }.digest { display:block;line-height:1.7 }.el-alert+.el-alert { margin-top:12px }.el-form { margin-top:18px }@media(max-width:700px) { .cluster-stats { grid-template-columns:repeat(2,minmax(0,1fr)) }.cluster-stats>div { padding:12px }.cluster-stats strong { font-size:20px } }
</style>

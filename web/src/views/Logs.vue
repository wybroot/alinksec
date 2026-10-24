<template>
  <section class="log-search">
    <div class="log-heading"><div><h2>原始日志检索</h2><p>按服务端入库时间查找主机日志，保留原文和采集说明。</p></div><el-tag>仅管理员</el-tag></div>
    <el-alert v-if="!admin" title="原始日志可能含敏感信息，需要当前有效管理员账号。" type="info" :closable="false" />
    <template v-else>
      <el-card shadow="never">
        <form class="log-filters" @submit.prevent="runSearch(false)">
          <label>入库开始时间<input v-model="form.from" type="datetime-local" aria-label="入库开始时间" :disabled="busy || exporting" required /></label>
          <label>入库结束时间<input v-model="form.to" type="datetime-local" aria-label="入库结束时间" :disabled="busy || exporting" required /></label>
          <label>主机编号<input v-model="form.agent" aria-label="主机编号" maxlength="64" placeholder="全部主机" :disabled="busy || exporting" /></label>
          <label>日志来源<select v-model="form.source" aria-label="日志来源" :disabled="busy || exporting"><option value="">全部来源</option><option value="secure">Linux secure</option><option value="auth.log">Linux auth.log</option><option value="windows-security">Windows Security 4624 / 4625</option></select></label>
          <label class="log-keyword">原文字面关键词<input v-model="form.keyword" aria-label="原文字面关键词" maxlength="128" placeholder="区分大小写；% 和 _ 按原字符查找" :disabled="busy || exporting" /></label>
          <el-button type="primary" native-type="submit" :loading="busy" :disabled="exporting">检索</el-button>
        </form>
        <p class="log-help">单次时间范围最多 31 天。Linux 时间表示 Agent 观察时间；Windows 时间来自原生事件。保留目标 30 天，采集或传输中断可能造成缺口。</p>
      </el-card>
      <el-alert v-if="error" class="log-notice" :title="error" type="error" :closable="false" />
      <el-alert v-if="stale && result" class="log-notice" title="当前结果已过期，请重新检索后继续翻页或导出。" type="warning" :closable="false" />
      <el-card shadow="never" class="log-results" v-loading="busy">
        <div class="log-actions">
          <span v-if="result">本页 {{ result.items.length }} 条 · {{ result.scanComplete ? '本次扫描已完成' : '仍有记录待扫描' }}</span><span v-else>尚未检索</span>
          <div><el-button :disabled="!canExport" :loading="exporting" @click="save('ndjson')">导出本页 NDJSON</el-button><el-button :disabled="!canExport" :loading="exporting" @click="save('csv')">导出本页 CSV</el-button></div>
        </div>
        <div class="log-table-wrap">
          <el-table :data="result?.items || []" row-key="id" empty-text="" style="min-width:780px">
            <el-table-column label="入库时间" width="185"><template #default="{ row }">{{ stamp(row.receivedAt) }}</template></el-table-column>
            <el-table-column prop="agent_id" label="主机 / 来源" width="195"><template #default="{ row }"><span class="log-host">{{ row.agent_id }}</span><small>{{ row.source }}</small></template></el-table-column>
            <el-table-column label="原文预览" min-width="260"><template #default="{ row }"><span class="log-preview">{{ row.preview }}</span><div class="log-flags"><el-tag v-if="row.fields?.record_kind === 'collection_status'" type="info" size="small">采集状态</el-tag><el-tag v-if="row.fields?.truncated === 'true'" type="warning" size="small">原文已截断</el-tag><el-tag v-if="!row.raw_available" type="info" size="small">旧记录 · 完整性未知</el-tag></div></template></el-table-column>
            <el-table-column label="操作" width="92"><template #default="{ row }"><el-button link type="primary" :disabled="stale || busy || exporting" @click="openDetail(row)">查看原文</el-button></template></el-table-column>
          </el-table>
        </div>
        <p v-if="result && !result.items.length" class="log-empty">{{ result.scanComplete ? '本次检索范围内没有匹配日志。' : '本轮扫描没有匹配日志，仍可继续扫描较早记录。' }}</p>
        <p v-if="!result" class="log-empty">选择时间范围后检索 Linux 登录日志或 Windows Security 事件。</p>
        <div v-if="result" class="log-footer"><p>按入库编号倒序。每次最多扫描 {{ result.scanIdLimit }} 个编号、返回 {{ result.pageSize }} 条；翻页期间新增日志需重新检索。</p><el-button v-if="result.nextCursor" :disabled="stale || busy || exporting" @click="runSearch(true)">继续扫描</el-button></div>
        <p v-if="result" class="log-help">当前保留 {{ result.storage.retained_rows }} / {{ result.limits.rows }} 行，计费内容量 {{ mib(result.storage.retained_bytes) }} / {{ mib(result.limits.bytes) }} MiB。达到容量时新批次会被拒绝。</p>
      </el-card>
      <el-card v-if="detailOpen" shadow="never" class="log-detail" v-loading="detailBusy">
        <div class="log-heading"><h3>日志原文</h3><el-button @click="closeDetail">关闭原文</el-button></div>
        <el-alert v-if="detailError" :title="detailError" type="error" :closable="false" />
        <template v-if="detail">
          <dl><dt>主机 / 来源</dt><dd>{{ detail.agent_id }} / {{ detail.source }}</dd><dt>服务端入库时间</dt><dd>{{ stamp(detail.receivedAt) }}</dd><dt>{{ detail.time_kind === 'event' ? '事件时间（Agent 提供）' : detail.time_kind === 'observed' ? 'Agent 观察时间' : '旧 Agent 时间（语义未知）' }}</dt><dd>{{ stamp(detail.log_ts) }}</dd><dt>保留内容 SHA256</dt><dd>{{ detail.content_sha256 || '旧记录未保存摘要' }}</dd></dl>
          <el-alert v-if="detail.fields?.truncated === 'true'" title="此条为采集时保留的原文前缀，完整原文未上传。" type="warning" :closable="false" />
          <el-alert v-if="detail.fields?.record_kind === 'collection_status'" title="此条为 Agent 采集状态说明。" type="info" :closable="false" />
          <pre class="log-raw">{{ detail.content }}</pre><h4>结构化字段 / 采集说明</h4><pre class="log-fields">{{ JSON.stringify(detail.fields, null, 2) }}</pre>
        </template>
      </el-card>
      <p class="log-help">Linux 采集固定 secure / auth.log 文件；Windows 复用 Security 原生读取器，只采集安装后可读的 4624 / 4625，不主动开启系统审计。缺失文件、轮转与编码转换可在采集说明中查看。旧版本上报可能只保留截断内容。</p>
    </template>
  </section>
</template>

<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { getUser, fetchRawLogs, fetchRawLog, downloadRawLogs } from '../api'
const admin = computed(() => getUser()?.role === 'admin')
const localTime = value => { const d = new Date(value); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16) }
const now = Date.now(), form = reactive({ from: localTime(now - 3600000), to: localTime(now + 60000), agent: '', source: '', keyword: '' })
const busy = ref(false), exporting = ref(false), error = ref(''), result = ref(null), stale = ref(false)
const detailOpen = ref(false), detailBusy = ref(false), detail = ref(null), detailError = ref('')
let detailVersion = 0, acceptedQuery = null
const canExport = computed(() => result.value?.items.length > 0 && !busy.value && !stale.value && !exporting.value)
const stamp = value => { if (value === null || value === undefined || value === '' || value === 0) return '未提供'; const d = new Date(value); return Number.isNaN(d.getTime()) ? '时间无效' : d.toLocaleString('zh-CN', { hour12: false }) }
const mib = value => (Number(value || 0) / 1048576).toFixed(1)
const closeDetail = () => { detailVersion++; detailOpen.value = false; detail.value = null; detailBusy.value = false; detailError.value = '' }
watch(form, () => { if (result.value) stale.value = true; closeDetail() })
async function runSearch(next) {
  if (!admin.value || busy.value || exporting.value || (next && stale.value)) return
  const query = next ? { ...acceptedQuery, cursor: result.value.nextCursor } : { from: new Date(form.from).getTime(), to: new Date(form.to).getTime(), agent: form.agent, source: form.source, keyword: form.keyword }
  if (!Number.isFinite(query.from) || !Number.isFinite(query.to) || query.to <= query.from || query.to - query.from > 31 * 86400000) { error.value = '请选择不超过 31 天的有效时间范围'; return }
  busy.value = true; error.value = ''; closeDetail()
  try { result.value = await fetchRawLogs(query); acceptedQuery = { ...query }; delete acceptedQuery.cursor; stale.value = false }
  catch (e) { error.value = e.message; stale.value = true }
  finally { busy.value = false }
}
async function openDetail(row) {
  if (stale.value || busy.value || exporting.value) return
  const version = ++detailVersion; detailOpen.value = true; detailBusy.value = true; detail.value = null; detailError.value = ''
  try { const value = await fetchRawLog(row.id); if (version === detailVersion) detail.value = value }
  catch (e) { if (version === detailVersion) detailError.value = e.message }
  finally { if (version === detailVersion) detailBusy.value = false }
}
async function save(format) {
  if (!canExport.value) return
  exporting.value = true; error.value = ''
  try { await downloadRawLogs(result.value.items.map(row => row.id), format) }
  catch (e) { error.value = e.message }
  finally { exporting.value = false }
}
</script>

<style scoped>
.log-search{min-width:0;max-width:1500px;margin:auto}.log-heading,.log-actions,.log-footer{display:flex;justify-content:space-between;align-items:center;gap:16px}.log-heading h2{margin:0 0 6px}.log-heading p,.log-help,.log-footer p{font-size:13px;color:#64748b;line-height:1.7}.log-heading{margin-bottom:18px}.log-filters{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;align-items:end}.log-filters label{display:flex;flex-direction:column;gap:7px;font-size:13px;color:#334155}.log-filters input,.log-filters select{box-sizing:border-box;width:100%;min-width:0;padding:9px 10px;border:1px solid #cbd5e1;border-radius:5px;background:#fff;color:#0f172a;font:inherit}.log-keyword{grid-column:span 3}.log-results,.log-detail,.log-notice{margin-top:18px}.log-actions{margin-bottom:16px;flex-wrap:wrap;font-size:14px}.log-table-wrap{max-width:100%;overflow:auto}.log-preview{display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;white-space:pre-wrap;overflow-wrap:anywhere;font-family:ui-monospace,monospace;font-size:12px}.log-host{display:block;overflow-wrap:anywhere}small{color:#64748b}.log-flags{display:flex;gap:5px;flex-wrap:wrap;margin-top:5px}.log-empty{padding:32px 10px;text-align:center;color:#64748b}.log-raw,.log-fields{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;max-height:440px;overflow:auto;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:16px;font-size:12px;line-height:1.7}.log-detail dl{display:grid;grid-template-columns:180px minmax(0,1fr);gap:12px;font-size:13px}.log-detail dt{color:#64748b}.log-detail dd{margin:0;overflow-wrap:anywhere}@media(max-width:800px){.log-filters{grid-template-columns:repeat(2,minmax(0,1fr))}.log-keyword{grid-column:span 2}.log-actions>div{display:flex;gap:8px;flex-wrap:wrap}.log-actions .el-button+.el-button{margin-left:0}.log-footer{align-items:flex-start;flex-direction:column}.log-detail dl{grid-template-columns:1fr;gap:6px}.log-detail dd{margin-bottom:10px}}@media(max-width:440px){.log-filters{grid-template-columns:minmax(0,1fr)}.log-keyword{grid-column:span 1}.log-heading{align-items:flex-start}.log-heading h2{font-size:21px}}
</style>

<template>
  <section class="panel yara-status" data-testid="yara-status">
    <div class="heading"><h4>YARA 引擎状态</h4><el-button :loading="loading" @click="refresh">刷新状态</el-button></div>
    <p class="help">显示主机最近报告的引擎可用性。本机配置启用后可用于主动扫描，实时检测另需开启本机选项及周期策略。就绪不代表文件均已检查；版本包含原生引擎版本及完整规则源码摘要。</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false"><el-button size="small" @click="refresh">重试</el-button></el-alert>
    <div v-else v-loading="loading" class="hosts">
      <el-empty v-if="!items.length" description="暂无主机" :image-size="48" />
      <article v-for="row in items" :key="row.agent_id" class="host">
        <div class="heading"><b>{{ row.hostname }}</b><el-tag :type="row.state === 'ready' ? 'success' : ['disabled', 'offline'].includes(row.state) ? 'info' : 'warning'">{{ stateLabel(row.state) }}</el-tag></div>
        <p class="help">{{ row.ip }} · 实时检测{{ row.coverage?.realtime ? '已配置' : '未配置' }}</p>
        <p class="version">{{ row.coverage?.version || '尚未报告引擎版本' }}</p>
        <p>{{ issueLabel(row.coverage?.last_issue) }}</p>
        <p class="help">本次运行尝试 {{ row.coverage?.scans ?? '—' }} · 失败 {{ row.coverage?.failures ?? '—' }}<br />最近扫描：{{ scanTime(row) }}</p>
      </article>
    </div>
    <el-pagination v-if="total > 20" v-model:current-page="page" :page-size="20" :total="total" layout="prev, pager, next" @current-change="refresh" />
    <p class="help">单文件最多 20 MiB，不解包压缩内容。需使用原生 YARA 构建并配置本机规则文件及 SHA256。任务固定逐主机规则摘要；源码变化、编译失败、超限和超时均报告未完成。</p>
  </section>
</template>
<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { fetchYaraStatus } from '../api'
import { yaraIssueLabel } from '../utils/yara'
const items = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref('')
const states = { starting: '正在验证规则', disabled: '未配置启用', ready: '就绪', unavailable: '引擎不可用', unsupported: 'Agent 不支持', offline: '主机离线或禁用', stale: '状态已过期' }
const stateLabel = state => states[state] || '状态未知'
const issueLabel = issue => issue ? yaraIssueLabel(issue) : '未报告扫描问题'
const scanTime = row => row.coverage?.last_scan_at ? new Date(row.coverage.last_scan_at * 1000).toLocaleString() : '尚未扫描'
async function refresh() {
  if (loading.value) return
  loading.value = true; error.value = ''
  try { const data = await fetchYaraStatus(page.value); items.value = data.items || []; total.value = data.total || 0 }
  catch (e) { items.value = []; total.value = 0; error.value = e.message || 'YARA 状态加载失败' }
  finally { loading.value = false }
}
let timer
onMounted(() => { refresh(); timer = setInterval(refresh, 15000) })
onUnmounted(() => { clearInterval(timer) })
</script>
<style scoped>
.yara-status { min-width: 0; }
.heading { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; }
.hosts { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 290px), 1fr)); gap: 16px; }
.host { padding: 14px; border: 1px solid #e2e8f0; border-radius: 8px; min-width: 0; overflow-wrap: anywhere; }
.host p { font-size: 13px; line-height: 1.7; margin: 8px 0; }
.help { font-size: 12px; line-height: 1.7; color: #64748b; overflow-wrap: anywhere; }
.version { font-family: monospace; }
</style>

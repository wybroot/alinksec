<template>
  <section class="panel file-watch" data-testid="file-watch">
    <div class="heading"><h4>文件事件监控</h4><el-button :loading="loading" @click="refresh">刷新状态</el-button></div>
    <p class="help">Linux、Windows 文件事件触发病毒检查、关键文件和诱饵核验。监听失效或积压时补查，勒索行为按完整统计窗口判定。以下为最近心跳报告；监听正常不代表文件均已检查。</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false"><el-button size="small" @click="refresh">重试</el-button></el-alert>
    <div v-else class="table" v-loading="loading">
      <el-table :data="items" empty-text="暂无主机" size="small">
        <el-table-column label="主机" min-width="155"><template #default="{ row }">{{ row.hostname }}<div class="help">{{ row.ip }}</div></template></el-table-column>
        <el-table-column label="监控状态" min-width="145"><template #default="{ row }"><el-tag :type="row.state === 'watching' ? 'success' : ['disabled','offline'].includes(row.state) ? 'info' : 'warning'">{{ stateLabel(row.state) }}</el-tag></template></el-table-column>
        <el-table-column label="覆盖与问题" min-width="285"><template #default="{ row }"><div>{{ issueLabel(row.coverage?.issue || row.coverage?.recovery_issue) }}</div><span class="help">监听目录 {{ row.coverage?.watches ?? '—' }} · 待处理 {{ row.coverage?.pending ?? '—' }} · 累计丢弃 {{ row.coverage?.dropped ?? '—' }} · 覆盖中断 {{ row.coverage?.gaps ?? '—' }}</span></template></el-table-column>
        <el-table-column label="最近补查结束" min-width="170"><template #default="{ row }">{{ row.coverage?.last_sweep_at ? new Date(row.coverage.last_sweep_at).toLocaleString() : '尚未完成' }}</template></el-table-column>
      </el-table>
    </div>
    <el-pagination v-if="total > 20" v-model:current-page="page" :page-size="20" :total="total" layout="prev, pager, next" @current-change="refresh" />
    <p class="help">目录递归最多 5 层，隐藏子目录、符号链接和目录联接不跟随；单实例最多监听 1024 个目录、保留 2048 个待处理路径。网络文件系统可能不提供文件事件。周期补查也有读取与时间限制，短暂出现后消失的文件可能无法检查。</p>
  </section>
</template>
<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { fetchFileWatchStatus } from '../api'
const items = ref([]), total = ref(0), page = ref(1), loading = ref(false), error = ref('')
const states = { starting: '正在启动', disabled: '未启用文件监控', watching: '正在监听', recovering: '正在补查', degraded: '覆盖降级', unsupported: 'Agent 不支持', offline: '主机离线或禁用', stale: '状态已过期', stalled: '监听状态未推进' }
const issues = { path_limit: '路径超出监听长度上限', queue_overflow: '路径队列溢出，已请求补查', kernel_overflow_or_error: '系统事件丢失或读取失败，已请求补查', watcher_unavailable: '无法启动原生监听', watcher_closed: '原生监听已中断', root_limit: '配置目录超过监听范围', watch_budget: '目录数量或注册预算已达上限', unsafe_path: '路径含符号链接或目录联接', root_unavailable: '监控目录不存在或不可用', directory_unreadable: '目录无法读取', watch_add_failed: '目录监听注册失败', path_changed: '注册或补查时目录身份变化', unsupported: '当前系统不支持原生监听' }
const stateLabel = state => states[state] || '状态未知'
const issueLabel = issue => issue ? issues[issue] || '请检查 Agent 日志' : '未报告监听问题'
async function refresh() {
  if (loading.value) return
  loading.value = true; error.value = ''
  try { const data = await fetchFileWatchStatus(page.value); items.value = data.items || []; total.value = data.total || 0 }
  catch (e) { items.value = []; total.value = 0; error.value = e.message || '文件监控状态加载失败' }
  finally { loading.value = false }
}
let timer
onMounted(() => { refresh(); timer = setInterval(refresh, 15000) })
onUnmounted(() => clearInterval(timer))
</script>
<style scoped>
.file-watch { margin-top: 20px; min-width: 0; }
.heading { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.help { font-size: 12px; line-height: 1.7; color: #64748b; overflow-wrap: anywhere; }
.table { overflow-x: auto; }
</style>

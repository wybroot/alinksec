<template>
  <section class="component-health" v-loading="loading && !snapshot">
    <div class="health-toolbar">
      <div><h3>服务端组件健康</h3><p>检测当前服务端实例及其依赖，定位连接、存储和证书问题。</p></div>
      <el-button type="primary" :loading="loading" @click="load">刷新状态</el-button>
    </div>
    <el-alert v-if="error" type="error" :title="error" :closable="false" show-icon />
    <template v-if="snapshot">
      <div class="health-summary"><el-tag :type="statusType(error ? 'unknown' : snapshot.status)" size="large">{{ error ? '检测结果已过期' : statusLabel(snapshot.status) }}</el-tag>
        <span>最近检测 {{ formatDate(snapshot.checkedAt) }}</span><span>页面每 30 秒刷新</span></div>
      <div class="health-grid">
        <article v-for="component in snapshot.components" :key="component.id" class="health-card" :data-component="component.id">
          <div class="health-card-title"><h4>{{ component.name }}</h4><el-tag size="small" :type="statusType(component.status)">{{ statusLabel(component.status) }}</el-tag></div>
          <p>{{ component.message }}</p>
          <dl>
            <template v-for="[label, value] in details(component.details)" :key="label"><dt>{{ label }}</dt><dd>{{ value }}</dd></template>
          </dl>
          <small>{{ component.status === 'disabled' ? '未执行检测' : `检测耗时 ${component.durationMs} ms` }}</small>
        </article>
      </div>
      <p class="health-note">未启用的组件单独标记，不计为正常。状态来自当前服务端实例；多副本部署可结合服务集群页查看其他实例。</p>
    </template>
    <el-empty v-else-if="!loading" description="暂无组件状态，可重新刷新" />
  </section>
</template>

<script setup>
import { onMounted, onBeforeUnmount, ref } from 'vue'
import { fetchSystemHealth } from '../api'
import { bytesText, durationText, formatDate } from '../utils/host-detail'

const loading = ref(false)
const snapshot = ref(null)
const error = ref('')
let alive = true, timer
const statusLabel = status => ({ healthy: '正常', degraded: '需关注', down: '异常', disabled: '未启用', unknown: '未知' }[status] || '未知')
const statusType = status => ({ healthy: 'success', degraded: 'warning', down: 'danger', disabled: 'info', unknown: 'info' }[status] || 'info')
const details = value => Object.entries(value || {}).map(([key, item]) => {
  const names = { uptimeSeconds: '服务运行时长', heapUsedBytes: 'JVM 已用堆内存', heapMaxBytes: 'JVM 堆内存上限', type: '数据库类型', localConnections: '本实例 Agent 连接数', minimumFreeBytes: '最少可用磁盘', expiresAt: '证书到期时间', remainingDays: '剩余有效天数', mode: '运行模式' }
  const format = key.endsWith('Bytes') ? bytesText(item) : key === 'uptimeSeconds' ? durationText(item) : key === 'expiresAt' ? formatDate(item) : item === 'single' ? '单机' : item === 'cluster' ? '集群' : String(item)
  return [names[key] || key, format]
})
async function load() {
  if (loading.value) return
  loading.value = true
  try {
    const result = await fetchSystemHealth()
    if (alive) { snapshot.value = result; error.value = '' }
  } catch (e) { if (alive) error.value = e?.message || '组件健康状态加载失败' }
  finally { if (alive) loading.value = false }
}
onMounted(() => { load(); timer = setInterval(() => { if (document.visibilityState === 'visible') load() }, 30000) })
onBeforeUnmount(() => { alive = false; clearInterval(timer) })
</script>

<style scoped>
.health-toolbar, .health-card-title, .health-summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.health-toolbar { margin-bottom: 20px; }
h3, h4 { margin: 0; color: #0f172a; }
h3 { font-size: 18px; } h4 { font-size: 15px; }
.health-toolbar p, .health-card p, .health-note { color: #64748b; font-size: 13px; line-height: 1.7; }
.health-toolbar p { margin-bottom: 0; }
.health-summary { justify-content: flex-start; color: #64748b; font-size: 12px; margin: 18px 0; }
.health-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(min(100%,280px),1fr)); gap: 16px; }
.health-card { border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; min-width: 0; }
.health-card p { min-height: 44px; }
.health-card dl { display: grid; grid-template-columns: minmax(100px,1fr) minmax(0,1fr); gap: 10px; min-height: 44px; font-size: 12px; }
.health-card dt, .health-card small { color: #64748b; }
.health-card dd { margin: 0; color: #334155; text-align: right; overflow-wrap: anywhere; }
.health-card small { font-size: 11px; }
.health-note { margin-top: 20px; }
</style>

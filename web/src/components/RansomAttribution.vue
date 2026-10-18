<template>
  <section data-testid="ransom-attribution" class="ransom-evidence">
    <el-tag :type="attribution.status === 'attributed' ? 'warning' : 'info'">{{ statusLabel }}</el-tag>
    <p>{{ reasonLabel }}</p>
    <p class="muted">这是事件发生时的证据，并非当前主机监测状态。无法确认写入者时跳过进程终止；主机隔离仍按配置独立执行。</p>
    <dl v-if="attribution.process">
      <dt>写入进程</dt><dd>{{ attribution.process.image }}</dd>
      <dt>PID</dt><dd>{{ attribution.process.pid }}</dd>
      <dt>进程实例</dt><dd>{{ attribution.process.created_filetime }}</dd>
    </dl>
    <p>实际响应：{{ actionLabel(action) }}</p>
    <p v-if="detail.excluded_exe">进程命中排除清单，已降级为仅告警。</p>
    <p v-if="detail.kill_error">进程未被终止：{{ detail.kill_error }}</p>
    <details v-if="writes.length"><summary>文件操作证据（{{ writes.length }} 条）</summary>
      <ul><li v-for="(write, i) in writes" :key="i"><b>{{ write.operation === 'rename' ? '重命名' : '写入' }}</b> · PID {{ write.process?.pid || '身份未知' }} · {{ write.at }}<br />{{ write.path }}</li></ul>
    </details>
    <p v-else class="muted">没有可用的文件操作证据。</p>
    <p v-if="detail.process?.exe_sha256" class="muted">进程文件 SHA-256：{{ detail.process.exe_sha256 }}</p>
  </section>
</template>

<script setup>
import { computed } from 'vue'
import { actionLabel } from '../utils/format'
const props=defineProps({detail:{type:Object,required:true},action:{type:String,default:''}})
const attribution=computed(()=>props.detail.attribution || {})
const writes=computed(()=>Array.isArray(attribution.value.writes) ? attribution.value.writes.slice(0,100) : [])
const statusLabel=computed(()=>({attributed:'已关联文件操作进程',unattributed:'未确认写入者',ambiguous:'存在多个写入者',unavailable:'采集不可用',disabled:'采集已关闭',starting:'采集启动中',ready:'采集已运行'}[attribution.value.status] || '归因状态未知'))
const reasonLabel=computed(()=>{
 const reason=attribution.value.reason || ''
 if(attribution.value.status==='attributed')return '内核文件事件已关联到同一进程实例。终止前再次核对进程身份，并保护系统关键进程。'
 return ({no_observed_write:'未观察到全部受影响文件的成功写入或重命名操作。',multiple_writers:'检测窗口内存在不同写入进程，已跳过进程终止。',capture_gap:'检测窗口存在采集缺口或证据已过期。',writer_identity_unavailable:'文件操作的进程身份无法核实，可能已退出或无法访问。',writer_exited:'写入进程已退出或无法访问。',writer_identity_changed:'进程身份已变化。',capture_stopped:'采集已经停止，历史证据已失效。',window_exceeds_retention:'监测窗口超过归因证据保留范围，已跳过进程终止。',write_capacity_exceeded:'文件操作量超过采集容量，证据已失效。',file_object_capacity_exceeded:'打开文件数量超过采集容量，证据已失效。',pending_write_capacity_exceeded:'待确认文件操作超过采集容量，证据已失效。',etw_events_lost:'内核文件事件发生丢失，证据已失效。'}[reason] || (reason.startsWith('capture_start_failed') ? '无法启动内核文件采集，请检查 Agent 权限和系统支持。' : reason.startsWith('capture_health_failed') ? '内核文件采集已中断或出现事件丢失，已跳过进程终止。' : '当前没有足够的证据确认写入进程。'))
})
</script>

<style scoped>
.ransom-evidence{overflow-wrap:anywhere;line-height:1.65}.muted{color:#94a3b8;font-size:12px}.ransom-evidence dl{display:grid;grid-template-columns:80px minmax(0,1fr);gap:6px}.ransom-evidence dd{margin:0}.ransom-evidence ul{padding-left:20px}.ransom-evidence li{margin:8px 0}
</style>

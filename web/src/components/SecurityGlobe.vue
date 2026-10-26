<template>
  <div class="security-globe">
    <div class="situation-summary">
      <span>最新 <b>{{ events.length }}</b> 条告警</span><span>网络攻击 <b>{{ stats.attacks }}</b></span><span>有来源 IP <b>{{ stats.network }}</b></span>
      <span>本机事件 <b>{{ stats.local }}</b></span><span>可定位链路 <b>{{ stats.routes }}</b></span>
      <span class="snapshot-state" :class="{ stale }">{{ stale ? '数据更新失败 · 保留上次快照' : ready ? '30s 轮询 · 告警快照' : '正在读取真实数据' }}</span>
    </div>
    <div class="situation-body">
      <div ref="surface" class="globe-visual">
        <canvas ref="canvas" role="img" :aria-label="`地理态势：${stats.routes} 条可定位网络链路，展示前 ${Math.min(stats.routes, 10)} 条；${stats.network} 条带来源 IP 的网络告警`" @click="pickEvent"></canvas>
        <button class="rotation-toggle" type="button" :aria-pressed="paused" @click="paused = !paused">{{ paused ? '旋转地球' : '暂停旋转' }}</button>
        <div v-if="ready && !stats.routes" class="geo-empty">
          <strong>{{ !events.length ? '暂无安全告警' : stats.attacks && !stats.network ? '攻击来源 IP 未采集' : !stats.network ? '暂无带来源 IP 的网络告警' : '来源或目标地理位置不足' }}</strong>
          <span>{{ stats.attacks ? '保留攻击事件；已知位置单独标记，未知端点不生成连线' : '文件变更、进程及 Agent 状态事件按实际主机归属展示' }}</span>
        </div>
        <div class="geo-legend"><span><i></i>有定位依据的端点</span><span>IP 定位为近似区域</span></div>
      </div>
      <aside class="event-evidence" aria-label="真实事件归属与证据">
        <div class="evidence-title">真实事件归属<span>点击查看证据</span></div>
        <div class="event-relations">
          <button v-for="event in events" :key="event.id" class="event-relation" :class="{ selected: selectedId === event.id }" :aria-pressed="selectedId === event.id" @click="selectedId = event.id">
            <span class="relation-line"><b>{{ event.sourceIp || (event.network ? '来源 IP 未知' : '本机事件') }}</b><em>→</em><b :title="event.host">{{ event.host }}</b></span>
            <span class="relation-caption"><span>{{ event.attackLabel || event.type }}</span><span>{{ event.time }} · ×{{ event.count }}</span></span>
          </button>
          <div v-if="!events.length" class="no-relations">暂无事件记录</div>
        </div>
        <dl v-if="selected" class="evidence-detail">
          <dt>告警内容</dt><dd class="event-text" :title="selected.text">{{ selected.text }}</dd>
          <dt>来源</dt><dd>{{ selected.sourceIp || (selected.network ? '未采集到来源 IP' : '本机事件，未记录远端来源') }}</dd>
          <dt>来源位置</dt><dd>{{ locationText(selected.sourceLocation) }}</dd>
          <dt>目标主机</dt><dd :title="selected.agentId">{{ selected.host }}{{ selected.targetIp ? ' · ' + selected.targetIp : '' }}</dd>
          <dt>目标位置</dt><dd>{{ locationText(selected.targetLocation) }}</dd>
          <dt>最近发生</dt><dd>{{ selected.observedAt || '未知' }} · 累计 {{ selected.count }} 次</dd>
          <dt>响应动作</dt><dd>{{ selected.action || '未记录' }}</dd>
        </dl>
      </aside>
    </div>
    <div class="situation-footer"><span>{{ providerText }} <a v-if="usesDbip" href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a></span><span>IP 位置为近似区域 · 新观测事件更新触发流光</span></div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { createSecurityGlobe } from '../utils/securityGlobe'
import { located, LOCATION_REASONS, situationStats } from '../utils/securitySituation.js'

const props = defineProps({ events: { type: Array, default: () => [] }, ready: Boolean, stale: Boolean, providerStatus: { type: String, default: 'unavailable' }, providerInfo: { type: Object, default: null } })
const surface = ref(null), canvas = ref(null), paused = ref(false), selectedId = ref(null)
const stats = computed(() => situationStats(props.events))
const selected = computed(() => props.events.find(event => event.id === selectedId.value))
const offline = computed(() => props.providerInfo?.providers?.find(p => p.id === 'offline'))
const usesDbip = computed(() => offline.value?.databaseType?.toLowerCase().includes('dbip') || props.events.some(e => e.sourceLocation?.provider === 'dbip' || e.targetLocation?.provider === 'dbip'))
const providerText = computed(() => {
  if (props.providerStatus === 'configured' && offline.value?.status === 'configured') return `离线城市库 · ${offline.value.version?.slice(0, 10) || '版本未知'}${offline.value.stale ? ' · 建议更新' : ''}${['database_invalid', 'database_missing'].includes(offline.value.lastReload) ? ' · 更新失败，保留旧库' : ''}`
  return { configured: 'IPIP · 城市级近似定位', disabled: 'IP 定位未启用', credentials_missing: 'IPIP 凭据未配置', unavailable: 'IP 定位数据暂不可用', database_missing: '离线 IP 库未安装', database_invalid: '离线 IP 库无效' }[props.providerStatus] || 'IP 定位状态未知'
})
const locationText = value => located(value) ? `${value.label || `${value.latitude.toFixed(2)}, ${value.longitude.toFixed(2)}`} · ${{ asset_inventory: '资产登记', ipip: 'IPIP 城市近似', dbip: 'DB-IP 城市近似', maxmind: 'MaxMind 城市近似' }[value.provider]}` : LOCATION_REASONS[value?.status] || '地理位置未知'
let globe, observer, intersection, motion, animation = 0, lastTime = 0, elapsed = 0, visible = true, disposed = false
const active = () => !disposed && visible && !document.hidden && !motion?.matches && !paused.value
function draw(time) {
  animation = 0
  if (!active()) { lastTime = 0; return }
  if (!lastTime || time - lastTime >= 1000 / 30) {
    if (lastTime) elapsed += Math.min((time - lastTime) / 1000, .1)
    lastTime = time; globe?.render(elapsed)
  }
  animation = requestAnimationFrame(draw)
}
function syncAnimation() {
  cancelAnimationFrame(animation); animation = 0; lastTime = 0
  globe?.render(elapsed)
  if (active()) animation = requestAnimationFrame(draw)
}
function resize() {
  globe?.resize(surface.value.clientWidth, surface.value.clientHeight, window.devicePixelRatio || 1)
  globe?.render(elapsed)
}
function pickEvent(event) {
  const rect = canvas.value.getBoundingClientRect()
  const id = globe?.pick((event.clientX - rect.left) * canvas.value.clientWidth / rect.width, (event.clientY - rect.top) * canvas.value.clientHeight / rect.height)
  if (id != null) selectedId.value = id
}
watch(() => [props.events, props.ready, props.stale], () => {
  if (!props.events.some(event => event.id === selectedId.value)) selectedId.value = props.events[0]?.id ?? null
  globe?.setEvents(props.events, { ready: props.ready, stale: props.stale }); globe?.render(elapsed)
}, { immediate: true })
watch(selectedId, id => { globe?.select(id); globe?.render(elapsed) })
watch(paused, syncAnimation)
onMounted(() => {
  globe = createSecurityGlobe(canvas.value)
  globe?.setEvents(props.events, { ready: props.ready, stale: props.stale }); globe?.select(selectedId.value)
  motion = window.matchMedia('(prefers-reduced-motion: reduce)')
  observer = new ResizeObserver(resize); observer.observe(surface.value)
  intersection = new IntersectionObserver(entries => { visible = entries[0].isIntersecting; syncAnimation() }); intersection.observe(surface.value)
  motion.addEventListener('change', syncAnimation); document.addEventListener('visibilitychange', syncAnimation)
  resize(); syncAnimation()
})
onBeforeUnmount(() => {
  disposed = true; cancelAnimationFrame(animation); observer?.disconnect(); intersection?.disconnect()
  motion?.removeEventListener('change', syncAnimation); document.removeEventListener('visibilitychange', syncAnimation)
  globe?.dispose(); globe = null
})
</script>

<style scoped>
.security-globe { flex: 1; min-height: 0; display: flex; flex-direction: column; }
.situation-summary { display: flex; align-items: center; gap: 18px; height: 26px; flex: none; color: #82a99b; font-size: 10px; }
.situation-summary b { color: #c3eadb; font: 14px Consolas, monospace; margin-left: 4px; }.snapshot-state { margin-left: auto; color: #7cac98; }.snapshot-state.stale { color: #efbe64; }
.situation-body { display: grid; grid-template-columns: minmax(0, 1fr) 285px; flex: 1; min-height: 0; gap: 12px; }
.globe-visual { position: relative; overflow: hidden; min-height: 0; background: radial-gradient(ellipse at 50% 46%, #174f352b 0%, transparent 64%); }
canvas { display: block; width: 100%; height: 100%; cursor: pointer; }
.rotation-toggle { position: absolute; left: 4px; top: 8px; padding: 4px 8px; background: #102d26; border: 1px solid #34594d; color: #94cbbb; font: 10px inherit; border-radius: 3px; cursor: pointer; }
.geo-empty { position: absolute; left: 8px; right: 8px; bottom: 40px; display: flex; align-items: center; flex-direction: column; gap: 8px; padding: 14px 8px; background: #071e18e8; border-top: 1px solid #416d554d; pointer-events: none; }
.geo-empty strong { font-size: 13px; color: #bcddcf; font-weight: 500; }.geo-empty span { font-size: 10px; color: #8eae9f; }
.geo-legend { position: absolute; left: 8px; right: 8px; bottom: 8px; display: flex; justify-content: space-between; color: #7c9f90; font-size: 9px; }
.geo-legend span { display: flex; align-items: center; gap: 5px; }.geo-legend i { width: 5px; height: 5px; background: #62e0c0; border-radius: 50%; }
.event-evidence { min-height: 0; display: flex; flex-direction: column; border-left: 1px solid #3c665744; padding-left: 14px; overflow: hidden; }
.evidence-title { display: flex; justify-content: space-between; color: #c1e0d4; font-size: 11px; padding: 9px 0; }.evidence-title span { color: #729787; font-size: 9px; }
.event-relations { height: 155px; flex: none; overflow-y: auto; scrollbar-width: thin; scrollbar-color: #3d6f5e #10271f; }
.event-relation { display: block; width: 100%; padding: 8px; margin-bottom: 4px; border: 1px solid transparent; color: #c3dbd1; background: #173c302e; text-align: left; cursor: pointer; font: inherit; }
.event-relation.selected { background: #2e66513d; border-color: #538a6e85; }.event-relation:focus-visible { outline: 1px solid #68c8ad; }
.relation-line { display: flex; align-items: center; gap: 7px; font-size: 11px; }.relation-line b { min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; font-weight: 400; flex: 1; }.relation-line em { color: #5e9f85; font-style: normal; }.relation-line b:first-child { color: #b8cebe; }
.relation-caption { display: flex; justify-content: space-between; color: #779b8a; font-size: 9px; margin-top: 6px; }
.evidence-detail { display: grid; grid-template-columns: 57px minmax(0, 1fr); gap: 7px 8px; margin: 14px 0 0; font-size: 10px; overflow-y: auto; min-height: 0; scrollbar-width: thin; }
dt { color: #769988; }dd { margin: 0; color: #b8d4c7; overflow-wrap: anywhere; line-height: 1.5; }.event-text { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.no-relations { color: #779b8a; font-size: 11px; padding: 20px 0; }
.situation-footer { display: flex; justify-content: space-between; gap: 12px; color: #6e9682; font-size: 9px; padding: 10px 0 4px; flex: none; }
.situation-footer a { color: #81ae96; margin-left: 8px; }
</style>

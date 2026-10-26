<template>
  <div ref="surface" class="security-globe" :class="{ 'is-empty': !events.length }">
    <div class="globe-status"><span class="signal-dot"></span>安全事件态势<span class="live-tag">LIVE</span></div>
    <div class="globe-caption">{{ events.length ? '事件链路动态示意' : '持续监测 · 暂无安全事件' }}</div>
    <canvas ref="canvas" role="img" :aria-label="`旋转地球，展示 ${Math.min(events.length, 10)} 条安全事件动态示意连线，非真实地理定位`"></canvas>
    <div class="globe-side side-left"><span>ONLINE AGENTS</span><strong>{{ online }}<small> / {{ total }}</small></strong><em>在线接入</em></div>
    <div class="globe-side side-right"><span>SECURITY EVENTS</span><strong>{{ events.length }}</strong><em>最新安全事件</em></div>
    <div class="globe-footer"><span><i class="legend-critical"></i>严重 / 高危</span><span><i></i>其他事件</span><span class="schematic-note">链路为示意，非真实地理定位</span></div>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { createSecurityGlobe } from '../utils/securityGlobe'

const props = defineProps({ events: { type: Array, default: () => [] }, online: { type: Number, default: 0 }, total: { type: Number, default: 0 } })
const surface = ref(null), canvas = ref(null)
let globe, observer, intersection, motion, animation = 0, lastTime = 0, elapsed = 0, visible = true, disposed = false
const active = () => !disposed && visible && !document.hidden && !motion?.matches
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
  // The 1920px dashboard is CSS-scaled; use layout size, not transformed bounds.
  globe?.resize(surface.value.clientWidth, surface.value.clientHeight, window.devicePixelRatio || 1)
  globe?.render(elapsed)
}
watch(() => props.events, events => { globe?.setEvents(events); globe?.render(elapsed) })
onMounted(() => {
  globe = createSecurityGlobe(canvas.value)
  globe?.setEvents(props.events)
  motion = window.matchMedia('(prefers-reduced-motion: reduce)')
  observer = new ResizeObserver(resize); observer.observe(surface.value)
  intersection = new IntersectionObserver(entries => { visible = entries[0].isIntersecting; syncAnimation() })
  intersection.observe(surface.value)
  motion.addEventListener('change', syncAnimation)
  document.addEventListener('visibilitychange', syncAnimation)
  resize(); syncAnimation()
})
onBeforeUnmount(() => {
  disposed = true; cancelAnimationFrame(animation)
  observer?.disconnect(); intersection?.disconnect()
  motion?.removeEventListener('change', syncAnimation)
  document.removeEventListener('visibilitychange', syncAnimation)
  globe?.dispose(); globe = null
})
</script>

<style scoped>
.security-globe { flex: 1; min-height: 0; position: relative; overflow: hidden; background: radial-gradient(ellipse at 50% 46%, #174f352b 0%, transparent 64%); }
canvas { display: block; width: 100%; height: 100%; }
.globe-status { position: absolute; left: 8px; top: 10px; display: flex; align-items: center; gap: 8px; font-size: 11px; letter-spacing: 1px; color: #a3cabc; }
.signal-dot { width: 5px; height: 5px; border-radius: 50%; background: #77e1b6; box-shadow: 0 0 9px #77e1b680; }
.live-tag { font-size: 8px; letter-spacing: 1.3px; padding: 2px 5px; border: 1px solid #4b8b6659; color: #79bd9d; border-radius: 2px; }
.globe-caption { position: absolute; right: 8px; top: 13px; font-size: 10px; color: #70998a; letter-spacing: 1px; }
.globe-side { position: absolute; top: 42%; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
.side-left { left: 14px; }.side-right { right: 14px; text-align: right; }
.globe-side>span { color: #648d7d; font: 8px Consolas, monospace; letter-spacing: 1px; }
.globe-side strong { font: 32px Consolas, monospace; color: #b9f4dd; line-height: 1; }
.globe-side small { font-size: 16px; color: #749c8c; }.globe-side em { color: #8eb6a6; font-size: 11px; font-style: normal; }
.side-right strong { color: #edc17e; }
.globe-footer { position: absolute; left: 10px; right: 10px; bottom: 4px; display: flex; gap: 16px; align-items: center; color: #7c9f90; font-size: 10px; }
.globe-footer span { display: flex; align-items: center; gap: 5px; }
.globe-footer i { width: 5px; height: 5px; background: #62e0c0; border-radius: 50%; }.globe-footer .legend-critical { background: #efbe64; }
.globe-footer .schematic-note { margin-left: auto; color: #668b7b; font-size: 9px; }
.is-empty .side-right strong { color: #82b09b; }
</style>

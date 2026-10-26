<template>
  <section class="event-ticker" aria-label="实时安全事件流">
    <div class="ticker-toolbar">
      <span><i></i>{{ events.length }} 条最新事件 · 30s 更新</span>
      <button v-if="overflowing" type="button" :aria-pressed="paused" @click="paused = !paused">
        {{ paused ? '继续滚动' : '暂停滚动' }}
      </button>
    </div>
    <table class="event-table table-head" aria-hidden="true">
      <colgroup><col class="time-col" /><col class="severity-col" /><col class="type-col" /><col /><col class="host-col" /><col class="action-col" /></colgroup>
      <thead><tr><th>时间</th><th>级别</th><th>类型</th><th>内容</th><th>主机</th><th>响应动作</th></tr></thead>
    </table>
    <div ref="viewport" class="ticker-viewport" tabindex="0" aria-label="安全事件列表，悬停或聚焦暂停滚动"
      :class="{ 'user-paused': paused || pageHidden, overflowing }">
      <table v-if="events.length" :key="eventKey" class="event-table ticker-track"
        :class="{ scrolling: overflowing }" :style="trackStyle">
        <colgroup><col class="time-col" /><col class="severity-col" /><col class="type-col" /><col /><col class="host-col" /><col class="action-col" /></colgroup>
        <thead class="sr-only"><tr><th>时间</th><th>级别</th><th>类型</th><th>内容</th><th>主机</th><th>响应动作</th></tr></thead>
        <tbody ref="firstGroup">
          <tr v-for="ev in events" :key="ev.id" :class="{ fresh: ev.fresh }">
            <td>{{ ev.time }}</td><td><span class="severity" :class="ev.sev">{{ sevLabel(ev.sev) }}</span></td>
            <td :title="ev.type">{{ ev.type }}</td><td :title="ev.text">{{ ev.text }}</td>
            <td :title="ev.host">{{ ev.host }}</td><td class="action" :title="ev.action">{{ ev.action || '—' }}</td>
          </tr>
        </tbody>
        <tbody v-for="copy in duplicateCount" :key="copy" aria-hidden="true" class="ticker-copy">
          <tr v-for="ev in events" :key="ev.id">
            <td>{{ ev.time }}</td><td><span class="severity" :class="ev.sev">{{ sevLabel(ev.sev) }}</span></td>
            <td>{{ ev.type }}</td><td>{{ ev.text }}</td><td>{{ ev.host }}</td><td class="action">{{ ev.action || '—' }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty-events">暂无安全事件，正在持续监测</div>
    </div>
  </section>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { sevLabel } from '../utils/format'

const props = defineProps({ events: { type: Array, default: () => [] } })
const viewport = ref(null), firstGroup = ref(null)
const paused = ref(false), pageHidden = ref(document.hidden), overflowing = ref(false), groupHeight = ref(0), duplicateCount = ref(0)
const eventKey = computed(() => JSON.stringify(props.events.map(ev => ev.id)))
const trackStyle = computed(() => ({ '--scroll-distance': `-${groupHeight.value}px`, '--scroll-duration': `${Math.max(12, groupHeight.value / 22)}s` }))
let observer
const visibility = () => { pageHidden.value = document.hidden }
const measure = () => {
  groupHeight.value = firstGroup.value?.offsetHeight || 0
  overflowing.value = props.events.length > 1 && groupHeight.value > 0
  duplicateCount.value = overflowing.value ? Math.max(1, Math.ceil((viewport.value?.clientHeight || 0) / groupHeight.value)) : 0
}
watch(() => props.events, async () => { await nextTick(); measure() }, { deep: false })
onMounted(() => {
  observer = new ResizeObserver(measure)
  observer.observe(viewport.value)
  document.addEventListener('visibilitychange', visibility)
  measure()
})
onBeforeUnmount(() => { observer?.disconnect(); document.removeEventListener('visibilitychange', visibility) })
</script>

<style scoped>
.event-ticker { flex: 1; min-height: 0; display: flex; flex-direction: column; font-size: 12px; }
.ticker-toolbar { display: flex; align-items: center; justify-content: space-between; height: 22px; margin: -4px 0 5px; color: #789f95; font-size: 10px; }
.ticker-toolbar span { display: flex; align-items: center; gap: 6px; }
.ticker-toolbar i { width: 4px; height: 4px; background: #60d9bd; border-radius: 50%; box-shadow: 0 0 7px #60d9bd80; }
.ticker-toolbar button { background: none; color: #94cbbb; border: 1px solid #34594d; border-radius: 3px; padding: 2px 8px; cursor: pointer; font: inherit; }
.ticker-toolbar button:hover, .ticker-toolbar button:focus-visible { color: #dcfff2; border-color: #74d4b8; }
.event-table { width: 100%; table-layout: fixed; border-collapse: collapse; text-align: left; }
.time-col { width: 75px; }.severity-col { width: 59px; }.type-col { width: 108px; }.host-col { width: 108px; }.action-col { width: 100px; }
.table-head { flex: none; background: #102f28; }
th { padding: 7px 6px; color: #91b5aa; font-size: 10px; font-weight: 500; letter-spacing: 1px; }
td { height: 35px; padding: 7px 6px; border-bottom: 1px solid #6b9a8d24; color: #bdd5cd; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
td:first-child { font-family: Consolas, Menlo, monospace; font-size: 11px; color: #82a69a; }
td:nth-child(4) { color: #d9e8e3; }
td.action { color: #79c9ae; }
.ticker-viewport { flex: 1; min-height: 0; overflow: hidden; position: relative; }
.ticker-viewport:focus-visible { outline: 1px solid #68c8ad; outline-offset: -1px; }
.ticker-viewport:hover, .ticker-viewport:focus-within, .ticker-viewport.user-paused { overflow-y: auto; scrollbar-width: thin; scrollbar-color: #3d6f5e #10271f; }
.ticker-track.scrolling { animation: event-scroll var(--scroll-duration) linear infinite; will-change: transform; }
.ticker-viewport:hover .ticker-track, .ticker-viewport:focus-within .ticker-track, .user-paused .ticker-track { animation-play-state: paused; }
.severity { display: inline-block; padding: 2px 5px; font-size: 10px; border: 1px solid #a9c9c059; border-radius: 3px; color: #a9c9c0; }
.severity.critical { color: #ff958b; border-color: #ef6c628c; background: #ef6c621a; }
.severity.high { color: #f0c46f; border-color: #e4ae4f8c; background: #e4ae4f1a; }
.severity.medium { color: #7de2d0; border-color: #4dd5c073; background: #4dd5c014; }
.fresh { animation: event-arrive .9s ease-out; }
.empty-events { display: grid; height: 100%; place-items: center; color: #72988a; font-size: 12px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; clip-path: inset(50%); overflow: hidden; white-space: nowrap; }
@keyframes event-scroll { to { transform: translateY(var(--scroll-distance)); } }
@keyframes event-arrive { from { background: #4dd5c033; } to { background: transparent; } }
@media (prefers-reduced-motion: reduce) {
  .ticker-track.scrolling, .fresh { animation: none; will-change: auto; }
  .ticker-viewport { overflow-y: auto; }
  .ticker-copy { display: none; }
  .ticker-toolbar button { display: none; }
}
</style>

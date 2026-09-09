<template>
  <div class="dashboard-shell" v-loading="loading">
    <section class="ops-overview">
      <div class="overview-copy">
        <div class="eyebrow"><span class="live-dot"></span>SECURITY OPERATIONS</div>
        <h1>安全运营概览</h1>
        <p>受管主机、检测引擎与处置状态正在持续汇总。</p>
        <div class="overview-meta">
          <span><b>{{ hostCoverage }}%</b> 主机在线覆盖</span><i></i>
          <span><b>{{ d.stats.pending || 0 }}</b> 项待处置风险</span>
        </div>
      </div>
      <div class="overview-actions">
        <div class="sync-note"><span class="live-dot"></span>Agent 数据实时同步</div>
        <div class="action-row">
          <el-button @click="refresh" :loading="loading"><el-icon><Refresh /></el-icon>刷新</el-button>
          <el-button type="primary" @click="$router.push('/hosts')"><el-icon><Plus /></el-icon>接入主机</el-button>
        </div>
      </div>
    </section>

    <section class="metric-grid">
      <article class="metric-card metric-hosts"><div class="metric-head"><span class="metric-label">在线主机</span><span class="metric-icon"><el-icon><Monitor /></el-icon></span></div><div class="metric-value">{{ d.stats.hosts || 0 }}<small>/ {{ d.stats.hostsTotal || 0 }}</small></div><div class="metric-foot success"><span class="trend-mark">+</span> 本周新增 {{ d.stats.weekNew || 0 }} 台</div></article>
      <article class="metric-card metric-alerts"><div class="metric-head"><span class="metric-label">待处置风险</span><span class="metric-icon"><el-icon><Bell /></el-icon></span></div><div class="metric-value">{{ d.stats.pending || 0 }}</div><div class="metric-foot danger">严重 {{ d.stats.crit || 0 }} <i></i> 高危 {{ d.stats.high || 0 }}</div></article>
      <article class="metric-card metric-virus"><div class="metric-head"><span class="metric-label">恶意样本检出</span><span class="metric-icon"><el-icon><Search /></el-icon></span></div><div class="metric-value">{{ d.stats.virusWeek || 0 }}</div><div class="metric-foot">已隔离 {{ d.stats.quarantined || 0 }} <i></i> 待处置 {{ d.stats.virusTodo || 0 }}</div></article>
      <article class="metric-card metric-risk"><div class="metric-head"><span class="metric-label">重点风险主机</span><span class="metric-icon"><el-icon><Warning /></el-icon></span></div><div class="metric-value">{{ d.stats.riskHosts || 0 }}</div><div class="metric-foot truncate">TOP · {{ d.stats.topRisk || '暂无数据' }}</div></article>
    </section>

    <section class="workspace-grid">
      <article class="workspace-panel resource-panel">
        <header class="panel-heading"><div><span class="section-kicker">FLEET HEALTH</span><h2>主机资源态势</h2></div><button class="text-action" @click="$router.push('/hosts')">查看主机 <el-icon><ArrowRight /></el-icon></button></header>
        <div class="resource-summary"><div><span>CPU 集群均值</span><b>{{ latestPercent(d.res.cpu) }}</b></div><div><span>内存集群均值</span><b>{{ latestPercent(d.res.mem) }}</b></div><p>过去 24 小时</p></div>
        <div ref="resEl" class="chart resource-chart"></div>
      </article>
      <article class="workspace-panel threat-panel">
        <header class="panel-heading"><div><span class="section-kicker">THREAT POSTURE</span><h2>风险构成</h2></div></header>
        <div class="threat-body"><div ref="riskEl" class="chart risk-chart"></div><div class="risk-legend"><div v-for="item in severityRows" :key="item.name"><span :style="{ background: item.color }"></span><em>{{ item.name }}</em><b>{{ item.value }}</b></div><button class="text-action" @click="$router.push('/alerts')">进入告警中心 <el-icon><ArrowRight /></el-icon></button></div></div>
      </article>
    </section>

    <section class="lower-grid">
      <article class="workspace-panel trend-panel"><header class="panel-heading"><div><span class="section-kicker">7 DAY WINDOW</span><h2>告警处置趋势</h2></div><span class="panel-note">新增与已处置</span></header><div ref="alertEl" class="chart alert-chart"></div></article>
      <article class="workspace-panel event-panel">
        <header class="panel-heading"><div><span class="section-kicker">LATEST SIGNALS</span><h2>最新安全事件</h2></div><button class="text-action" @click="$router.push('/alerts')">全部事件 <el-icon><ArrowRight /></el-icon></button></header>
        <div v-if="d.events.length" class="event-list"><div v-for="e in d.events" :key="e.id" class="event-row"><div class="event-time">{{ e.time }}</div><span class="severity-rail" :class="e.sev"></span><div class="event-main"><div><el-tag size="small" :type="sevType(e.sev)" :effect="e.sev === 'critical' ? 'dark' : 'plain'">{{ sevLabel(e.sev) }}</el-tag><strong>{{ e.text }}</strong></div><span>{{ e.host || '未识别主机' }} · {{ e.action || 'alert_only' }}</span></div></div></div>
        <el-empty v-else description="暂无安全事件" :image-size="50" />
      </article>
    </section>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { fetchDashboard, fetchMetricsRange } from '../api'
import { sevType, sevLabel, AX } from '../utils/format'
import { useChart } from '../composables/useChart'

const d = reactive({ stats: {}, events: [], sevDist: [], trend: [], res: { hrs: [], cpu: [], mem: [] } })
const loading = ref(false)
const hostCoverage = computed(() => d.stats.hostsTotal ? Math.round((d.stats.hosts || 0) / d.stats.hostsTotal * 100) : 0)
const severityRows = computed(() => {
  const colors = ['#d94f45', '#d88b1d', '#2d7797', '#71818a']
  return d.sevDist.map((row, i) => ({ ...row, color: colors[i] }))
})
const latestPercent = values => values?.length ? `${values[values.length - 1]}%` : '—'

const resEl = ref(null)
const resChart = useChart(resEl, () => ({
  grid: { left: 38, right: 18, top: 20, bottom: 28 },
  tooltip: { trigger: 'axis', backgroundColor: '#182b30', borderWidth: 0, textStyle: { color: '#fff' } },
  legend: { data: ['CPU %', '内存 %'], textStyle: { color: '#617178' }, top: 0, right: 0, itemWidth: 12, itemHeight: 8 },
  xAxis: { type: 'category', data: d.res.hrs, ...AX }, yAxis: { type: 'value', max: 100, ...AX },
  series: [
    { name: 'CPU %', type: 'line', smooth: true, showSymbol: false, data: d.res.cpu, lineStyle: { color: '#28778b', width: 2 }, areaStyle: { color: 'rgba(40,119,139,.12)' } },
    { name: '内存 %', type: 'line', smooth: true, showSymbol: false, data: d.res.mem, lineStyle: { color: '#c58a29', width: 2 } },
  ]
}))
const riskEl = ref(null)
const riskChart = useChart(riskEl, () => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c}（{d}%）' },
  series: [{ type: 'pie', radius: ['57%', '76%'], center: ['50%', '50%'], minAngle: 5, label: { show: false }, labelLine: { show: false }, itemStyle: { borderColor: '#fff', borderWidth: 4, borderRadius: 4 }, data: severityRows.value.map(row => ({ value: row.value, name: row.name, itemStyle: { color: row.color } })) }],
  graphic: [{ type: 'text', left: 'center', top: '42%', style: { text: String(d.stats.pending || 0), fill: '#17272b', font: '600 28px Arial', textAlign: 'center' } }, { type: 'text', left: 'center', top: '56%', style: { text: '待处置', fill: '#708087', font: '12px Arial', textAlign: 'center' } }]
}))
const alertEl = ref(null)
const alertChart = useChart(alertEl, () => ({
  grid: { left: 38, right: 18, top: 24, bottom: 28 },
  tooltip: { trigger: 'axis', backgroundColor: '#182b30', borderWidth: 0, textStyle: { color: '#fff' } },
  legend: { data: ['告警数', '处置数'], textStyle: { color: '#617178' }, top: 0, right: 0, itemWidth: 12, itemHeight: 8 },
  xAxis: { type: 'category', data: d.trend.map(t => t.date), ...AX }, yAxis: { type: 'value', ...AX },
  series: [{ name: '告警数', type: 'bar', barWidth: 16, data: d.trend.map(t => t.count), itemStyle: { color: '#d88b1d', borderRadius: [3, 3, 0, 0] } }, { name: '处置数', type: 'line', smooth: true, showSymbol: false, data: d.trend.map(t => t.handled), lineStyle: { color: '#27805e', width: 2 }, itemStyle: { color: '#27805e' } }]
}))

function toSeries(result) { const hrs = [], vals = []; for (const [ts, v] of result?.[0]?.values || []) { hrs.push(new Date(ts * 1000).toTimeString().slice(0, 5)); vals.push(Math.round(Number(v))) }; return { hrs, vals } }
async function refresh() {
  loading.value = true
  try {
    Object.assign(d, await fetchDashboard()); riskChart.render(); alertChart.render()
    try { const [cpu, mem] = await Promise.all([fetchMetricsRange('avg(alinksec_cpu_usage)', '1h', 24), fetchMetricsRange('avg(100 * alinksec_mem_used_bytes / alinksec_mem_total_bytes)', '1h', 24)]); const c = toSeries(cpu); d.res = { hrs: c.hrs, cpu: c.vals, mem: toSeries(mem).vals }; resChart.render() } catch (e) { console.warn('指标查询失败', e) }
  } finally { loading.value = false }
}
onMounted(refresh)
</script>

<style scoped>
.dashboard-shell { max-width: 1560px; margin: 0 auto; padding-bottom: 8px; }.ops-overview { min-height: 178px; background: #153235; color: #edf6f4; padding: 28px 32px; display: flex; justify-content: space-between; gap: 32px; align-items: flex-start; border-radius: 8px; margin-bottom: 18px; position: relative; overflow: hidden; }.ops-overview::after { content: ''; position: absolute; right: 0; top: 0; width: 38%; height: 100%; border-left: 1px solid rgba(220,239,235,.16); background: repeating-linear-gradient(90deg, transparent 0, transparent 28px, rgba(220,239,235,.05) 29px); pointer-events: none; }.overview-copy,.overview-actions { position: relative; z-index: 1; }.eyebrow,.section-kicker { color: #78bbb3; font-size: 11px; font-weight: 700; letter-spacing: 1.4px; }.live-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: #61c4a0; margin-right: 7px; box-shadow: 0 0 0 3px rgba(97,196,160,.13); }.overview-copy h1 { font-size: 28px; line-height: 1.15; font-weight: 650; margin: 9px 0 7px; }.overview-copy p { color: #b6cdca; font-size: 13px; }.overview-meta { display: flex; align-items: center; gap: 12px; margin-top: 21px; color: #c7d8d5; font-size: 12px; }.overview-meta b { color: #fff; font-family: Consolas, monospace; font-size: 15px; }.overview-meta i { height: 14px; width: 1px; background: rgba(220,239,235,.3); }.overview-actions { min-width: 240px; display: flex; align-items: flex-end; flex-direction: column; gap: 33px; }.sync-note { color: #b8cdca; font-size: 12px; white-space: nowrap; }.action-row { display: flex; gap: 9px; }.action-row :deep(.el-button) { border-color: rgba(222,240,236,.36); background: rgba(255,255,255,.04); color: #eaf4f1; }.action-row :deep(.el-button--primary) { background: #dd9b31; border-color: #dd9b31; color: #17272b; font-weight: 600; }
.metric-grid { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 14px; margin-bottom: 14px; }.metric-card { background: #fff; min-height: 154px; padding: 17px 18px; border: 1px solid #dce6e4; border-top: 3px solid #7b9994; border-radius: 7px; box-shadow: 0 2px 7px rgba(34,57,58,.04); }.metric-alerts { border-top-color: #d95c50; }.metric-virus { border-top-color: #ce9130; }.metric-risk { border-top-color: #35768c; }.metric-head { display: flex; align-items: center; justify-content: space-between; }.metric-label { color: #617178; font-size: 12px; font-weight: 600; }.metric-icon { display: flex; align-items: center; justify-content: center; width: 31px; height: 31px; color: #477c77; background: #edf5f2; border-radius: 5px; font-size: 16px; }.metric-alerts .metric-icon { background: #fdf0ee; color: #c64d42; }.metric-virus .metric-icon { background: #fff6e7; color: #ba7d1b; }.metric-risk .metric-icon { background: #ebf4f7; color: #2d7189; }.metric-value { color: #16282c; font-family: Consolas,monospace; font-size: 32px; line-height: 1; font-weight: 700; margin-top: 18px; }.metric-value small { color: #839398; font-size: 13px; font-weight: 400; }.metric-foot { display: flex; align-items: center; gap: 7px; color: #839398; font-size: 11px; margin-top: 16px; white-space: nowrap; }.metric-foot i { width: 3px; height: 3px; border-radius: 50%; background: #b6c5c3; }.metric-foot.success { color: #218164; }.metric-foot.danger { color: #c64d42; }.trend-mark { font-size: 15px; font-weight: 700; }.truncate { overflow: hidden; text-overflow: ellipsis; }
.workspace-grid,.lower-grid { display: grid; grid-template-columns: minmax(0,1.55fr) minmax(340px,.95fr); gap: 14px; margin-bottom: 14px; }.lower-grid { grid-template-columns: minmax(0,1.28fr) minmax(360px,1fr); }.workspace-panel { background: #fff; border: 1px solid #dce6e4; border-radius: 7px; box-shadow: 0 2px 7px rgba(34,57,58,.04); min-width: 0; padding: 20px; }.panel-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }.panel-heading h2 { color: #1a2c30; font-size: 16px; margin-top: 5px; line-height: 1.15; font-weight: 650; }.section-kicker { color: #76918d; font-size: 10px; }.text-action { display: inline-flex; align-items: center; gap: 4px; border: 0; padding: 3px 0; background: transparent; color: #28778b; font: inherit; font-size: 12px; cursor: pointer; white-space: nowrap; }.text-action:hover { color: #195967; }.panel-note { color: #839398; font-size: 11px; padding-top: 8px; }.resource-summary { display: flex; gap: 24px; align-items: flex-end; padding: 16px 0 3px; }.resource-summary div { display: grid; gap: 3px; }.resource-summary span { color: #839398; font-size: 11px; }.resource-summary b { color: #1b3033; font-family: Consolas,monospace; font-size: 19px; }.resource-summary p { margin-left: auto; color: #94a29f; font-size: 11px; }.resource-chart { height: 205px; }.threat-body { height: 240px; display: flex; align-items: center; }.risk-chart { width: 52%; height: 218px; }.risk-legend { width: 48%; display: grid; gap: 10px; }.risk-legend > div { display: grid; grid-template-columns: 8px 1fr auto; gap: 8px; align-items: center; }.risk-legend span { width: 8px; height: 8px; border-radius: 50%; }.risk-legend em { color: #66777b; font-size: 12px; font-style: normal; }.risk-legend b { color: #23363a; font-family: Consolas,monospace; font-size: 13px; }.risk-legend .text-action { margin-top: 7px; }.alert-chart { height: 225px; }.event-panel { min-height: 287px; }.event-list { margin-top: 11px; max-height: 223px; overflow: auto; }.event-row { display: grid; grid-template-columns: 80px 3px minmax(0,1fr); gap: 10px; padding: 10px 0; border-bottom: 1px solid #e8efed; }.event-row:last-child { border-bottom: 0; }.event-time { color: #8a999c; font-family: Consolas,monospace; font-size: 11px; padding-top: 3px; }.severity-rail { background: #7d9192; border-radius: 2px; }.severity-rail.critical { background: #d95c50; }.severity-rail.high { background: #d88b1d; }.severity-rail.medium { background: #35768c; }.event-main { min-width: 0; }.event-main > div { display: flex; align-items: center; gap: 7px; min-width: 0; }.event-main strong { color: #34474a; font-size: 12px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.event-main > span { display: block; color: #8a999c; font-size: 11px; margin-top: 5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
@media (max-width:1180px) { .metric-grid { grid-template-columns: repeat(2,minmax(0,1fr)); }.workspace-grid,.lower-grid { grid-template-columns: 1fr; }.overview-actions { min-width: auto; }.event-panel { min-height: 0; } } @media (max-width:720px) { .ops-overview { padding: 23px 20px; min-height: 0; display: block; }.ops-overview::after { display:none; }.overview-actions { align-items:flex-start; margin-top:22px; gap:14px; }.metric-grid { grid-template-columns:1fr; }.workspace-panel { padding:16px; }.overview-copy h1 { font-size:24px; }.resource-summary { gap:14px; }.risk-chart,.risk-legend { width:50%; } }
</style>

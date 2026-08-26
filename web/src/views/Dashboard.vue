<template>
  <div>
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-ico" style="background:#2563eb"><el-icon><Monitor /></el-icon></div>
        <div><div class="num">{{ d.stats.hosts }}<span style="font-size:13px;color:#94a3b8"> / {{ d.stats.hostsTotal }}</span></div><div class="lbl">在线主机</div><div class="sub" style="color:#16a34a">▲ {{ d.stats.weekNew }} 本周新增接入</div></div></div>
      <div class="stat-card"><div class="stat-ico" style="background:#dc2626"><el-icon><Bell /></el-icon></div>
        <div><div class="num">{{ d.stats.pending }}</div><div class="lbl">待处置安全事件</div><div class="sub" style="color:#dc2626">严重 {{ d.stats.crit }} · 高危 {{ d.stats.high }}</div></div></div>
      <div class="stat-card"><div class="stat-ico" style="background:#7c3aed"><el-icon><Search /></el-icon></div>
        <div><div class="num">{{ d.stats.virusWeek }}</div><div class="lbl">病毒检出（近7日）</div><div class="sub">已隔离 {{ d.stats.quarantined }} · 待处置 {{ d.stats.virusTodo }}</div></div></div>
      <div class="stat-card"><div class="stat-ico" style="background:#f59e0b"><el-icon><Warning /></el-icon></div>
        <div><div class="num">{{ d.stats.riskHosts }}</div><div class="lbl">高风险主机</div><div class="sub">TOP：{{ d.stats.topRisk }}</div></div></div>
    </div>

    <div class="grid-2">
      <div class="panel"><h4>主机资源趋势（近 24h · 集群均值）<span class="more" @click="$router.push('/hosts')">查看主机 ›</span></h4>
        <div ref="resEl" class="chart"></div></div>
      <div class="panel"><h4>告警级别分布</h4><div ref="riskEl" class="chart"></div></div>
    </div>

    <div class="grid-2">
      <div class="panel"><h4>近 7 日告警趋势<span class="more" @click="$router.push('/alerts')">告警中心 ›</span></h4>
        <div ref="alertEl" class="chart" style="height:230px"></div></div>
      <div class="panel"><h4>最新安全事件</h4>
        <div v-for="e in d.events" :key="e.id" class="evt-item">
          <span class="t">{{ e.time }}</span>
          <div style="flex:1">
            <el-tag size="small" :type="sevType(e.sev)" :effect="e.sev === 'critical' ? 'dark' : 'light'">{{ sevLabel(e.sev) }}</el-tag>
            {{ e.text }}<br />
            <span style="color:#94a3b8;font-size:11px">{{ e.host }} · 响应动作：</span>
            <el-tag size="small" effect="plain" type="info">{{ e.action }}</el-tag>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { fetchDashboard, fetchMetricsRange } from '../api'
import { sevType, sevLabel, AX } from '../utils/format'
import { useChart } from '../composables/useChart'

const d = reactive({ stats: {}, events: [], sevDist: [], trend: [], res: { hrs: [], cpu: [], mem: [] } })

// 近 24h CPU/内存趋势：VM 区间查询（集群均值；无数据时展示空图）
const resEl = ref(null)
const resChart = useChart(resEl, () => ({
  grid: { left: 40, right: 16, top: 30, bottom: 26 },
  tooltip: { trigger: 'axis' },
  legend: { data: ['CPU %', '内存 %'], textStyle: { color: '#64748b' }, top: 0, itemWidth: 14 },
  xAxis: { type: 'category', data: d.res.hrs, ...AX }, yAxis: { type: 'value', max: 100, ...AX },
  series: [
    { name: 'CPU %', type: 'line', smooth: true, showSymbol: false, data: d.res.cpu, lineStyle: { color: '#2563eb' }, areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(37,99,235,.2)' }, { offset: 1, color: 'rgba(37,99,235,0)' }] } } },
    { name: '内存 %', type: 'line', smooth: true, showSymbol: false, data: d.res.mem, lineStyle: { color: '#06b6d4' } },
  ]
}))

// 告警级别分布：summary.alerts.bySeverity（实时）
const riskEl = ref(null)
const riskChart = useChart(riskEl, () => ({
  tooltip: { trigger: 'item', formatter: '{b}: {c}（{d}%）' },
  legend: { bottom: 0, textStyle: { color: '#64748b' }, itemWidth: 14 },
  series: [{
    type: 'pie', radius: ['42%', '68%'], center: ['50%', '44%'],
    label: { show: true, formatter: '{b}\n{c}', color: '#475569', fontSize: 11 },
    itemStyle: { borderColor: '#fff', borderWidth: 2 },
    data: d.sevDist.map((x, i) => ({ ...x, itemStyle: { color: ['#dc2626', '#f59e0b', '#2563eb', '#94a3b8'][i] } }))
  }]
}))

// 近 7 日告警趋势：alert-trend（count 新增 / handled 已处置）
const alertEl = ref(null)
const alertChart = useChart(alertEl, () => ({
  grid: { left: 40, right: 16, top: 30, bottom: 26 },
  tooltip: { trigger: 'axis' },
  legend: { data: ['告警数', '处置数'], textStyle: { color: '#64748b' }, top: 0, itemWidth: 14 },
  xAxis: { type: 'category', data: d.trend.map((t) => t.date), ...AX }, yAxis: { type: 'value', ...AX },
  series: [
    { name: '告警数', type: 'bar', barWidth: 16, data: d.trend.map((t) => t.count), itemStyle: { color: '#2563eb', borderRadius: [4, 4, 0, 0] } },
    { name: '处置数', type: 'line', smooth: true, data: d.trend.map((t) => t.handled), lineStyle: { color: '#16a34a' }, itemStyle: { color: '#16a34a' } },
  ]
}))

// VM 矩阵 → 图表序列：值取整，时间戳格式化 HH:mm
function toSeries(result) {
  const hrs = []
  const vals = []
  for (const [ts, v] of result?.[0]?.values || []) {
    hrs.push(new Date(ts * 1000).toTimeString().slice(0, 5))
    vals.push(Math.round(Number(v)))
  }
  return { hrs, vals }
}

onMounted(async () => {
  const res = await fetchDashboard()
  Object.assign(d, res)
  riskChart.render()
  alertChart.render()

  // 资源趋势（VM 查询失败不影响大盘其余部分）
  try {
    const [cpu, mem] = await Promise.all([
      fetchMetricsRange('avg(alinksec_cpu_usage)', '1h', 24),
      fetchMetricsRange('avg(100 * alinksec_mem_used_bytes / alinksec_mem_total_bytes)', '1h', 24),
    ])
    const c = toSeries(cpu)
    d.res = { hrs: c.hrs, cpu: c.vals, mem: toSeries(mem).vals }
    resChart.render()
  } catch (e) {
    console.warn('指标查询失败', e)
  }
})
</script>

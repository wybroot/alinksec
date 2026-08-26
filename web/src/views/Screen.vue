<template>
  <div id="stage" :style="stageStyle">
    <!-- 顶栏 -->
    <div class="header">
      <div class="sub">
        <div class="mark">AS</div>
        <div><b>ALinkSec</b><br /><span style="font-size:11px;color:#4d7cb8;letter-spacing:1px">HOST SECURITY OPERATIONS</span></div>
      </div>
      <div class="glow-title">主 机 安 全 态 势 感 知 大 屏</div>
      <div class="clock">
        <div class="time">{{ clock.time }}</div>
        <div class="date">{{ clock.date }} {{ clock.week }} · 数据实时同步中</div>
      </div>
      <div class="deco-btn">
        <a @click="$router.push('/')">‹ 返回控制台</a>
        <a @click="toggleFullscreen">全屏</a>
      </div>
    </div>

    <!-- 主体三列 -->
    <div class="body">
      <!-- 左列 -->
      <div class="col">
        <div class="panel" style="height:300px">
          <h3>安全健康评分<span class="tail">综合风险模型</span></h3>
          <div ref="gaugeEl" class="chart"></div>
        </div>
        <div class="panel" style="height:330px">
          <h3>防护引擎运行状态<span class="tail">{{ kpi.hosts }}/{{ kpi.total }} 在线 · {{ kpi.protectOn }} 台防护开启</span></h3>
          <div class="engines" style="flex:1;padding-top:4px">
            <div class="eng" v-for="e in engines" :key="e.name">
              <div class="row"><b>{{ e.name }}</b><span class="st" :class="{ off: !e.on }">{{ e.on ? '● 运行中' : '○ 已停用' }}</span></div>
              <div class="track"><div class="fill" :style="{ width: e.load + '%' }"></div></div>
            </div>
          </div>
        </div>
        <div class="panel" style="flex:1">
          <h3>告警级别分布<span class="tail">近 7 日</span></h3>
          <div ref="pieEl" class="chart"></div>
        </div>
      </div>

      <!-- 中列 -->
      <div class="col">
        <div class="kpis">
          <div class="kpi"><div class="v">{{ kpi.hosts }}</div><div class="l">在线主机</div><div class="delta">接入率 {{ kpi.coverage }}%</div><div class="bar"></div></div>
          <div class="kpi"><div class="v red">{{ kpi.pending }}</div><div class="l">待处置威胁</div><div class="delta">严重 {{ kpi.crit }} · 高危 {{ kpi.high }}</div><div class="bar"></div></div>
          <div class="kpi"><div class="v amber">{{ kpi.virus }}</div><div class="l">恶意样本检出</div><div class="delta">近 30 日 · 自动处置 {{ kpi.rtHit }} 起</div><div class="bar"></div></div>
          <div class="kpi"><div class="v green">{{ kpi.compliance == null ? '—' : kpi.compliance + '%' }}</div><div class="l">基线合规率</div><div class="delta">最近任务已核查 {{ kpi.hostsChecked }} 台</div><div class="bar"></div></div>
        </div>

        <div class="panel" style="flex:1">
          <h3>主机接入态势<span class="tail">Agent 实时接入 · 地域标注待 Agent 上报</span></h3>
          <div ref="mapEl" class="chart"></div>
        </div>

        <div class="panel" style="height:252px">
          <h3>实时安全事件流<span class="tail">30s 轮询 · 新事件高亮</span></h3>
          <div class="tick">
            <table>
              <thead><tr><th style="width:88px">时间</th><th style="width:74px">级别</th><th style="width:150px">类型</th><th>内容</th><th style="width:130px">主机</th><th style="width:120px">响应动作</th></tr></thead>
              <tbody>
                <tr v-for="ev in events" :key="ev.id" :class="{ 'enter-anim': ev.fresh }">
                  <td class="num">{{ ev.time }}</td>
                  <td><span class="sev" :class="ev.sev">{{ sevLabel(ev.sev) }}</span></td>
                  <td class="num">{{ ev.type }}</td>
                  <td>{{ ev.text }}</td>
                  <td class="num">{{ ev.host }}</td>
                  <td class="num" style="color:#00ffa3">{{ ev.action || '—' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- 右列 -->
      <div class="col">
        <div class="panel" style="height:300px">
          <h3>威胁拦截趋势<span class="tail">近 7 日</span></h3>
          <div ref="trendEl" class="chart"></div>
        </div>
        <div class="panel" style="height:330px">
          <h3>主机风险值 TOP5<span class="tail">点击处置 ›</span></h3>
          <div ref="riskEl" class="chart"></div>
        </div>
        <div class="panel" style="flex:1">
          <h3>基线合规画像<span class="tail">等保 2.0 六大领域</span></h3>
          <div ref="radarEl" class="chart"></div>
        </div>
      </div>
    </div>
    <div class="foot-note">ALINKSEC SECURITY OPERATIONS CENTER · 数据来源：AGENT 实采实时上报</div>
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import * as echarts from 'echarts'
import { sevLabel } from '../utils/format'
import { useChart } from '../composables/useChart'
import { fetchScreen } from '../api'

const C = { cyan: '#00e5ff', blue: '#2f7bff', green: '#00ffa3', red: '#ff4d6b', amber: '#ffb800', dim: '#7fa8d8' }
const AXT = { color: '#5f88b8', fontSize: 11 }
const DEFAULT_DIMS = ['身份鉴别', '访问控制', '安全审计', '入侵防范', '剩余信息', '恶意代码']

const clock = reactive({ time: '--:--:--', date: '', week: '' })
const stageStyle = reactive({ transform: 'translate(-50%,-50%) scale(1)' })

/* ---- 真实数据（fetchScreen 聚合，30s 轮询刷新） ---- */
const kpi = reactive({ hosts: 0, total: 0, coverage: 0, protectOn: 0, pending: 0, crit: 0, high: 0, virus: 0, rtHit: 0, compliance: null, hostsChecked: 0 })
const sevPie = ref([])
const trendRows = ref([])
const riskHosts = ref([])
const radarRows = ref([])
const events = ref([])
const engines = ref([])
let knownEventIds = new Set()

// 统一登记定时器，卸载时清理
const timers = []
const addTimer = (fn, ms) => timers.push(setInterval(fn, ms))

const toggleFullscreen = () => {
  if (document.fullscreenElement) document.exitFullscreen()
  else document.documentElement.requestFullscreen()
}

const fitStage = () => {
  const s = Math.min(innerWidth / 1920, innerHeight / 1080)
  stageStyle.transform = 'translate(-50%,-50%) scale(' + s + ')'
  Object.values(chartsAlive).forEach(c => c.resize())
}
const chartsAlive = {}

const tickClock = () => {
  const d = new Date(), p = n => (n < 10 ? '0' : '') + n
  clock.time = p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds())
  clock.date = d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate())
  clock.week = '周' + '日一二三四五六'[d.getDay()]
}

const applyScreen = (d) => {
  Object.assign(kpi, d.kpi)
  sevPie.value = d.sevPie
  trendRows.value = d.trend
  riskHosts.value = d.riskHosts
  radarRows.value = d.radar
  const cover = d.kpi.total ? Math.round((d.kpi.protectOn / d.kpi.total) * 100) : 0
  engines.value = d.engines.map(e => ({ name: e.name, on: d.kpi.protectOn > 0, load: cover }))
  // 事件流：新出现的 id 高亮
  const freshIds = new Set(d.events.filter(ev => !knownEventIds.has(ev.id)).map(ev => ev.id))
  events.value = d.events.map(ev => ({ ...ev, fresh: freshIds.has(ev.id) }))
  knownEventIds = new Set(d.events.map(ev => ev.id))
  if (freshIds.size) setTimeout(() => events.value.forEach(ev => ev.fresh = false), 900)
}

const load = async () => {
  try {
    applyScreen(await fetchScreen())
    gauge.render(); pie.render(); trend.render(); risk.render(); radar.render()
  } catch (e) { /* 后端暂不可达时保持上次数据 */ }
}

/* ---- 图表 ---- */
const gaugeEl = ref(null)
const gauge = useChart(gaugeEl, () => {
  const v = kpi.compliance ?? 0
  const [level, color] = v >= 85 ? ['低', C.green] : v >= 70 ? ['中低', C.green] : v >= 50 ? ['中', C.amber] : ['高', C.red]
  return {
    series: [{
      type: 'gauge', startAngle: 210, endAngle: -30, min: 0, max: 100, radius: '92%', center: ['50%', '58%'],
      progress: { show: true, width: 14, roundCap: true, itemStyle: { color: { type: 'linear', x: 0, y: 0, x2: 1, y2: 0, colorStops: [{ offset: 0, color: C.blue }, { offset: 1, color: C.cyan }] }, shadowColor: 'rgba(0,229,255,.5)', shadowBlur: 12 } },
      axisLine: { lineStyle: { width: 14, color: [[1, 'rgba(0,229,255,.12)']] } },
      pointer: { show: false }, axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
      anchor: { show: false },
      title: { offsetCenter: [0, '34%'], fontSize: 13, color: C.dim },
      detail: { valueAnimation: true, fontSize: 44, fontWeight: 700, offsetCenter: [0, '-2%'], color: '#e8f6ff', formatter: val => val, fontFamily: 'Consolas' },
      data: [{ value: v, name: '基线合规评分' }]
    }],
    graphic: [{ type: 'text', left: 'center', top: '72%', style: { text: `风险等级：${level}`, fill: color, fontSize: 13 } }]
  }
})

const pieEl = ref(null)
const pie = useChart(pieEl, () => {
  const data = sevPie.value.some(d => d.value > 0) ? sevPie.value : [{ value: 0, name: '暂无告警' }]
  const colors = { 严重: C.red, 高危: C.amber, 中危: C.cyan, 低危: '#3f6aa6' }
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c}（{d}%）', backgroundColor: '#071a38', borderColor: '#1d4f8a', textStyle: { color: '#cfe6ff' } },
    legend: { bottom: 0, textStyle: { color: C.dim, fontSize: 11 }, itemWidth: 12, itemHeight: 8, icon: 'roundRect' },
    series: [{
      type: 'pie', roseType: 'radius', radius: ['18%', '72%'], center: ['50%', '44%'],
      label: { color: C.dim, fontSize: 11, formatter: '{b}\n{c}' },
      itemStyle: { borderColor: '#04102b', borderWidth: 2 },
      data: data.map(d => ({ ...d, itemStyle: { color: colors[d.name] || C.cyan } }))
    }]
  }
})

const trendEl = ref(null)
const trend = useChart(trendEl, () => ({
  grid: { left: 40, right: 14, top: 34, bottom: 24 },
  tooltip: { trigger: 'axis', backgroundColor: '#071a38', borderColor: '#1d4f8a', textStyle: { color: '#cfe6ff' } },
  legend: { top: 0, right: 0, textStyle: { color: C.dim, fontSize: 11 }, itemWidth: 14, data: ['病毒检出', '防护拦截'] },
  xAxis: { type: 'category', data: trendRows.value.map(r => r.date), axisLine: { lineStyle: { color: '#1d4f8a' } }, axisLabel: AXT },
  yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(0,229,255,.08)' } }, axisLabel: AXT },
  series: [
    { name: '病毒检出', type: 'bar', barWidth: 12, data: trendRows.value.map(r => r.virus), itemStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: C.cyan }, { offset: 1, color: 'rgba(0,229,255,.15)' }] } } },
    { name: '防护拦截', type: 'line', smooth: true, data: trendRows.value.map(r => r.blocked), lineStyle: { color: C.red, width: 2 }, itemStyle: { color: C.red }, areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(255,77,107,.25)' }, { offset: 1, color: 'rgba(255,77,107,0)' }] } } },
  ]
}))

const riskEl = ref(null)
const risk = useChart(riskEl, () => {
  const rows = riskHosts.value.length ? riskHosts.value : [{ hostname: '暂无风险主机', risk: 0, alerts: 0 }]
  return {
    grid: { left: 10, right: 56, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis', axisPointer: { type: 'none' }, backgroundColor: '#071a38', borderColor: '#1d4f8a', textStyle: { color: '#cfe6ff' }, formatter: p => `${p[0].name}：待处置告警 ${rows[p[0].dataIndex].alerts} 条` },
    xAxis: { type: 'value', max: 100, show: false },
    yAxis: {
      type: 'category', inverse: true, data: rows.map(r => r.hostname),
      axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: '#cfe6ff', fontSize: 12, fontFamily: 'Consolas' }
    },
    series: [{
      type: 'bar', barWidth: 12, data: rows.map(r => ({
        value: r.risk,
        itemStyle: {
          borderRadius: [0, 6, 6, 0],
          color: r.risk > 80 ? C.red : r.risk > 60 ? C.amber : C.cyan,
          shadowColor: r.risk > 80 ? 'rgba(255,77,107,.6)' : r.risk > 60 ? 'rgba(255,184,0,.5)' : 'rgba(0,229,255,.5)', shadowBlur: 8
        }
      })),
      label: { show: true, position: 'right', color: '#dff3ff', fontFamily: 'Consolas', fontSize: 13, formatter: p => rows[p.dataIndex].alerts + ' 条' }
    }]
  }
})

const radarEl = ref(null)
const radar = useChart(radarEl, () => {
  const rows = radarRows.value.length
    ? radarRows.value.map(r => ({ name: r.category, rate: r.rate }))
    : DEFAULT_DIMS.map(name => ({ name, rate: 0 }))
  const values = rows.map(r => r.rate)
  return {
    tooltip: { backgroundColor: '#071a38', borderColor: '#1d4f8a', textStyle: { color: '#cfe6ff' } },
    legend: { bottom: 0, textStyle: { color: C.dim, fontSize: 11 }, itemWidth: 14, data: ['当前'] },
    radar: {
      center: ['50%', '46%'], radius: '64%',
      indicator: rows.map(r => ({ name: r.name, max: 100 })),
      axisName: { color: C.dim, fontSize: 11 },
      splitLine: { lineStyle: { color: 'rgba(0,229,255,.15)' } },
      splitArea: { areaStyle: { color: ['rgba(0,229,255,.03)', 'rgba(0,229,255,.06)'] } },
      axisLine: { lineStyle: { color: 'rgba(0,229,255,.2)' } }
    },
    series: [{
      type: 'radar', data: [
        { name: '当前', value: values, lineStyle: { color: C.cyan, width: 2 }, itemStyle: { color: C.cyan }, areaStyle: { color: 'rgba(0,229,255,.25)' }, symbolSize: 4 },
      ]
    }]
  }
})

// 地图（china.json 加载失败不影响其余面板；地域标注待 Agent 上报归属地后启用）
const mapEl = ref(null)
const initMap = async () => {
  try {
    const r = await fetch(import.meta.env.BASE_URL + 'china.json')
    echarts.registerMap('china', await r.json())
  } catch (e) { return }
  if (!mapEl.value) return
  const chart = echarts.init(mapEl.value)
  chartsAlive.map = chart
  const renderMap = () => chart.setOption({
    geo: {
      map: 'china', roam: false, zoom: 1.18, center: [104.5, 36],
      itemStyle: { areaColor: '#0b2350', borderColor: '#1d4f8a', borderWidth: 1, shadowColor: 'rgba(0,140,255,.35)', shadowBlur: 14 },
      emphasis: { disabled: true }, select: { disabled: true }, label: { show: false }
    },
    graphic: [
      { type: 'text', left: 'center', top: '36%', style: { text: `${kpi.hosts} / ${kpi.total}`, fill: '#e8f6ff', fontSize: 30, fontWeight: 700, fontFamily: 'Consolas', align: 'center' } },
      { type: 'text', left: 'center', top: '43%', style: { text: '在线 Agent / 接入总数', fill: C.dim, fontSize: 13, align: 'center' } },
      { type: 'text', left: 'center', top: '47%', style: { text: `防护开启 ${kpi.protectOn} 台 · 接入率 ${kpi.coverage}%`, fill: '#9fd8ff', fontSize: 14, align: 'center' } },
    ]
  })
  renderMap()
  addTimer(renderMap, 30000)
}

onMounted(() => {
  chartsAlive.gauge = gauge.chart.value
  chartsAlive.pie = pie.chart.value
  chartsAlive.trend = trend.chart.value
  chartsAlive.risk = risk.chart.value
  chartsAlive.radar = radar.chart.value

  fitStage()
  tickClock()
  addTimer(tickClock, 1000)
  initMap()

  // 真实数据首次加载 + 30s 轮询
  load()
  addTimer(load, 30000)

  window.addEventListener('resize', fitStage)
})

onBeforeUnmount(() => {
  timers.forEach(clearInterval)
  window.removeEventListener('resize', fitStage)
  Object.values(chartsAlive).forEach(c => c && c.dispose())
})
</script>

<style>
/* 大屏为独立全屏路由，样式不 scoped（需覆盖 body 背景） */
* { box-sizing: border-box; }
html, body { width: 100%; height: 100%; overflow: hidden; background: #020617; }
#stage {
  position: absolute; left: 50%; top: 50%; width: 1920px; height: 1080px; transform-origin: center center;
  background: radial-gradient(1200px 700px at 50% -10%, #0a2547 0%, #04102b 45%, #020617 100%);
  color: #cfe6ff; font-family: "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
}
#stage::before {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background-image: linear-gradient(rgba(0, 229, 255, .035) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 229, 255, .035) 1px, transparent 1px);
  background-size: 48px 48px;
}
.header { position: relative; height: 86px; display: flex; align-items: center; justify-content: center; }
.header .glow-title { font-size: 34px; font-weight: 800; letter-spacing: 6px; color: #e8f6ff; text-shadow: 0 0 18px rgba(0, 229, 255, .85), 0 0 46px rgba(0, 229, 255, .35); }
.header .sub { position: absolute; left: 28px; top: 50%; transform: translateY(-50%); display: flex; align-items: center; gap: 10px; }
.header .sub .mark { width: 38px; height: 38px; border-radius: 9px; background: linear-gradient(135deg, #00e5ff, #2f7bff); display: flex; align-items: center; justify-content: center; color: #04102b; font-weight: 800; font-size: 15px; box-shadow: 0 0 16px rgba(0, 229, 255, .5); }
.header .sub b { font-size: 16px; color: #9fd8ff; letter-spacing: 2px; }
.header .clock { position: absolute; right: 28px; top: 50%; transform: translateY(-50%); text-align: right; }
.header .clock .time { font-family: Consolas, Menlo, monospace; font-size: 26px; color: #00e5ff; text-shadow: 0 0 12px rgba(0, 229, 255, .6); letter-spacing: 2px; }
.header .clock .date { font-size: 12px; color: #5f88b8; margin-top: 2px; }
.header::after { content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 2px; background: linear-gradient(90deg, transparent, #00e5ff 18%, #2f7bff 50%, #00e5ff 82%, transparent); opacity: .7; }
.deco-btn { position: absolute; left: 28px; bottom: 14px; display: flex; gap: 8px; }
.deco-btn a { font-size: 12px; color: #7fd4ff; text-decoration: none; border: 1px solid rgba(0, 229, 255, .35); padding: 3px 12px; border-radius: 3px; background: rgba(0, 229, 255, .06); cursor: pointer; }
.deco-btn a:hover { background: rgba(0, 229, 255, .18); }
.body { display: grid; grid-template-columns: 440px 1fr 440px; gap: 16px; padding: 14px 20px 18px; height: 994px; }
.col { display: flex; flex-direction: column; gap: 16px; min-height: 0; }
.panel { position: relative; border: 1px solid rgba(0, 229, 255, .22); background: linear-gradient(180deg, rgba(8, 28, 58, .72), rgba(4, 15, 38, .82)); box-shadow: inset 0 0 32px rgba(0, 120, 255, .08); display: flex; flex-direction: column; padding: 12px 14px 10px; }
.panel::before, .panel::after { content: ""; position: absolute; width: 14px; height: 14px; pointer-events: none; }
.panel::before { left: -1px; top: -1px; border-left: 2px solid #00e5ff; border-top: 2px solid #00e5ff; }
.panel::after { right: -1px; bottom: -1px; border-right: 2px solid #00e5ff; border-bottom: 2px solid #00e5ff; }
.panel h3 { font-size: 15px; color: #dff3ff; font-weight: 700; letter-spacing: 2px; display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-shrink: 0; }
.panel h3::before { content: ""; width: 4px; height: 15px; background: linear-gradient(180deg, #00e5ff, #2f7bff); box-shadow: 0 0 8px rgba(0, 229, 255, .8); }
.panel h3 .tail { margin-left: auto; font-size: 11px; font-weight: 400; color: #4d7cb8; }
.chart { flex: 1; min-height: 0; }
.kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; height: 118px; flex-shrink: 0; }
.kpi { position: relative; border: 1px solid rgba(0, 229, 255, .18); background: linear-gradient(180deg, rgba(9, 32, 66, .85), rgba(4, 14, 36, .9)); display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px; }
.kpi .v { font-family: Consolas, Menlo, monospace; font-size: 40px; font-weight: 700; line-height: 1; color: #00e5ff; text-shadow: 0 0 14px rgba(0, 229, 255, .55); }
.kpi .v.red { color: #ff4d6b; text-shadow: 0 0 14px rgba(255, 77, 107, .55); }
.kpi .v.green { color: #00ffa3; text-shadow: 0 0 14px rgba(0, 255, 163, .45); }
.kpi .v.amber { color: #ffb800; text-shadow: 0 0 14px rgba(255, 184, 0, .45); }
.kpi .l { font-size: 13px; color: #7fa8d8; letter-spacing: 2px; }
.kpi .delta { font-size: 11px; color: #4d7cb8; }
.kpi .bar { position: absolute; left: 0; right: 0; bottom: 0; height: 2px; background: linear-gradient(90deg, transparent, #00e5ff, transparent); opacity: .6; }
.tick { flex: 1; min-height: 0; overflow: hidden; position: relative; }
.tick table { width: 100%; border-collapse: collapse; font-size: 13px; }
.tick th { position: sticky; top: 0; background: #071a38; color: #7fa8d8; font-weight: 600; font-size: 12px; padding: 6px 8px; text-align: left; letter-spacing: 1px; }
.tick td { padding: 7px 8px; border-bottom: 1px dashed rgba(0, 229, 255, .1); color: #cfe6ff; }
.tick .num { font-family: Consolas, Menlo, monospace; }
.sev { display: inline-block; padding: 1px 10px; border-radius: 2px; font-size: 12px; }
.sev.critical { color: #ff4d6b; border: 1px solid rgba(255, 77, 107, .6); background: rgba(255, 77, 107, .12); }
.sev.high { color: #ffb800; border: 1px solid rgba(255, 184, 0, .6); background: rgba(255, 184, 0, .1); }
.sev.medium { color: #00e5ff; border: 1px solid rgba(0, 229, 255, .5); background: rgba(0, 229, 255, .08); }
.sev.low { color: #7fa8d8; border: 1px solid rgba(127, 168, 216, .4); }
.enter-anim { animation: slideIn .5s ease; }
@keyframes slideIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: none; } }
.engines { display: flex; flex-direction: column; gap: 10px; overflow: hidden; }
.eng { display: flex; flex-direction: column; gap: 5px; }
.eng .row { display: flex; align-items: center; font-size: 13px; }
.eng .row b { color: #dff3ff; font-weight: 600; width: 88px; }
.eng .row .st { margin-left: auto; font-size: 11px; color: #00ffa3; }
.eng .row .st.off { color: #ff4d6b; }
.eng .track { height: 6px; background: rgba(0, 229, 255, .1); border-radius: 3px; overflow: hidden; }
.eng .fill { height: 100%; border-radius: 3px; background: linear-gradient(90deg, #2f7bff, #00e5ff); box-shadow: 0 0 8px rgba(0, 229, 255, .6); transition: width .8s; }
.foot-note { position: absolute; left: 0; right: 0; bottom: 4px; text-align: center; font-size: 11px; color: #2e5386; letter-spacing: 2px; }
</style>

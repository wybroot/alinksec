<template>
  <div class="screen-viewport">
  <div id="stage" :style="stageStyle">
    <!-- 顶栏 -->
    <div class="header">
      <div class="sub">
        <div class="mark">AS</div>
        <div><b>ALinkSec</b><br /><span style="font-size:11px;color:#4d7cb8;letter-spacing:1px">HOST SECURITY OPERATIONS</span></div>
      </div>
      <div class="glow-title">主机安全态势感知中心</div>
      <div class="clock">
        <div class="time">{{ clock.time }}</div>
        <div class="date">{{ clock.date }} {{ clock.week }} · {{ loadError ? '数据更新暂不可用' : lastUpdated ? '数据已同步 ' + lastUpdated : '正在连接数据' }}</div>
      </div>
      <div class="deco-btn">
        <button type="button" @click="$router.push('/')">返回控制台</button>
        <button type="button" @click="toggleFullscreen">全屏显示</button>
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
          <h3>全球安全态势<span class="tail">地球视图 · 动态事件链路</span></h3>
          <SecurityGlobe :events="events" :online="kpi.hosts" :total="kpi.total" />
        </div>

        <div class="panel" style="height:252px">
          <h3>实时安全事件流<span class="tail">循环滚动 · 悬停暂停</span></h3>
          <SecurityEventTicker :events="events" />
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
  </div>
</template>

<script setup>
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import * as echarts from 'echarts'
import { useChart } from '../composables/useChart'
import { fetchScreen } from '../api'
import SecurityGlobe from '../components/SecurityGlobe.vue'
import SecurityEventTicker from '../components/SecurityEventTicker.vue'

const C = { cyan: '#4dd5c0', blue: '#3b8a92', green: '#72c987', red: '#ef6c62', amber: '#e4ae4f', dim: '#89aaa2' }
const AXT = { color: '#78948d', fontSize: 11 }
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
const lastUpdated = ref(''), loadError = ref(false)
let knownEventIds = new Set()
let highlightTimer, loading = false, disposed = false

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
}

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
  clearTimeout(highlightTimer)
  if (freshIds.size) highlightTimer = setTimeout(() => events.value.forEach(ev => ev.fresh = false), 900)
}

const load = async () => {
  if (loading || disposed || document.hidden) return
  loading = true
  try {
    const data = await fetchScreen()
    if (disposed) return
    applyScreen(data)
    gauge.render(); pie.render(); trend.render(); risk.render(); radar.render()
    lastUpdated.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
    loadError.value = false
  } catch (e) { if (!disposed) loadError.value = true /* 后端暂不可达时保持上次数据 */ }
  finally { loading = false }
}
const resumeData = () => { if (!document.hidden) load() }

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
      title: { offsetCenter: [0, '20%'], fontSize: 13, color: C.dim },
      detail: { valueAnimation: true, fontSize: 44, fontWeight: 700, offsetCenter: [0, '-2%'], color: '#e8f6ff', formatter: val => val, fontFamily: 'Consolas' },
      data: [{ value: v, name: '基线合规评分' }]
    }],
    graphic: [{ type: 'text', left: 'center', top: '84%', style: { text: `风险等级：${level}`, fill: color, fontSize: 13 } }]
  }
})

const pieEl = ref(null)
const pie = useChart(pieEl, () => {
  const nonzero = sevPie.value.filter(d => d.value > 0)
  const data = nonzero.length ? nonzero : [{ value: 0, name: '暂无告警' }]
  const colors = { 严重: C.red, 高危: C.amber, 中危: C.cyan, 低危: '#3f6aa6', 信息: '#547b81', 未知: '#8e8195' }
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c}（{d}%）', backgroundColor: '#102c25', borderColor: '#38655a', textStyle: { color: '#d9e8e3' } },
    legend: { bottom: 0, textStyle: { color: C.dim, fontSize: 11 }, itemWidth: 12, itemHeight: 8, icon: 'roundRect' },
    series: [{
      type: 'pie', roseType: 'radius', radius: ['18%', '72%'], center: ['50%', '44%'],
      label: { color: C.dim, fontSize: 11, formatter: '{b}\n{c}' },
      itemStyle: { borderColor: '#0b241f', borderWidth: 2 },
      data: data.map(d => ({ ...d, itemStyle: { color: colors[d.name] || C.cyan } }))
    }]
  }
})

const trendEl = ref(null)
const trend = useChart(trendEl, () => ({
  grid: { left: 40, right: 14, top: 34, bottom: 24 },
  tooltip: { trigger: 'axis', backgroundColor: '#102c25', borderColor: '#38655a', textStyle: { color: '#d9e8e3' } },
  legend: { top: 0, right: 0, textStyle: { color: C.dim, fontSize: 11 }, itemWidth: 14, data: ['病毒检出', '防护拦截'] },
  xAxis: { type: 'category', data: trendRows.value.map(r => r.date), axisLine: { lineStyle: { color: '#38655a' } }, axisLabel: AXT },
  yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(118, 167, 154, .12)' } }, axisLabel: AXT },
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
    tooltip: { trigger: 'axis', axisPointer: { type: 'none' }, confine: true, extraCssText: 'max-width:260px;white-space:normal;overflow-wrap:anywhere;', backgroundColor: '#102c25', borderColor: '#38655a', textStyle: { color: '#d9e8e3' }, formatter: p => `${echarts.format.encodeHTML(p[0].name)}：待处置告警 ${rows[p[0].dataIndex].alerts} 条` },
    xAxis: { type: 'value', max: 100, show: false },
    yAxis: {
      type: 'category', inverse: true, data: rows.map(r => r.hostname),
      axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: '#c8ddd7', fontSize: 12, fontFamily: 'Consolas', width: 110, overflow: 'truncate' }
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
      label: { show: true, position: 'right', color: '#dcece7', fontFamily: 'Consolas', fontSize: 13, formatter: p => rows[p.dataIndex].alerts + ' 条' }
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
    tooltip: { backgroundColor: '#102c25', borderColor: '#38655a', textStyle: { color: '#d9e8e3' } },
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

onMounted(() => {
  fitStage()
  tickClock()
  addTimer(tickClock, 1000)

  // 真实数据首次加载 + 30s 轮询
  load()
  addTimer(load, 30000)

  window.addEventListener('resize', fitStage)
  document.addEventListener('visibilitychange', resumeData)
})

onBeforeUnmount(() => {
  disposed = true
  timers.forEach(clearInterval)
  clearTimeout(highlightTimer)
  window.removeEventListener('resize', fitStage)
  document.removeEventListener('visibilitychange', resumeData)
})
</script>

<style scoped>
/* 大屏主题只作用于当前路由，返回控制台后恢复原布局。 */
* { box-sizing: border-box; }
.screen-viewport { position: fixed; inset: 0; overflow: hidden; background: #06120f; }
#stage {
  position: absolute; left: 50%; top: 50%; width: 1920px; height: 1080px; transform-origin: center center;
  background: #081713; color: #d9e8e3; font-family: "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
}
#stage::before { content: ""; position: absolute; inset: 0; pointer-events: none; background-image: linear-gradient(rgba(133, 178, 164, .045) 1px, transparent 1px), linear-gradient(90deg, rgba(133, 178, 164, .045) 1px, transparent 1px); background-size: 52px 52px; }
.header { position: relative; height: 88px; display: flex; align-items: center; justify-content: center; border-bottom: 1px solid #28453e; }
.header .glow-title { font-size: 30px; font-weight: 700; letter-spacing: 4px; color: #eff7f4; }
.header .sub { position: absolute; left: 28px; top: 50%; transform: translateY(-50%); display: flex; align-items: center; gap: 11px; }
.header .sub .mark { width: 38px; height: 38px; border-radius: 5px; border: 1px solid #4dd5c0; background: #11342e; display: flex; align-items: center; justify-content: center; color: #7ae3d1; font-weight: 800; font-size: 14px; }
.header .sub b { font-size: 16px; color: #dceee8; letter-spacing: 1.5px; }
.header .sub span { color: #789f95 !important; }
.header .clock { position: absolute; right: 28px; top: 50%; transform: translateY(-50%); text-align: right; }
.header .clock .time { font-family: Consolas, Menlo, monospace; font-size: 25px; color: #8be2d0; letter-spacing: 1px; }
.header .clock .date { font-size: 12px; color: #789f95; margin-top: 3px; }
.header::after { content: ""; position: absolute; width: 240px; height: 3px; left: calc(50% - 120px); bottom: -2px; background: #4dd5c0; }
.deco-btn { position: absolute; left: 340px; top: 50%; transform: translateY(-50%); display: flex; gap: 8px; }
.deco-btn button { color: #a4ccc1; border: 1px solid #385e55; padding: 4px 11px; border-radius: 3px; background: #0c2520; font: inherit; font-size: 12px; cursor: pointer; }
.deco-btn button:hover { color: #e3f5ef; border-color: #65c9b7; background: #12352d; }
.body { display: grid; grid-template-columns: 440px 1fr 440px; gap: 16px; padding: 14px 20px 18px; height: 994px; }
.col { display: flex; flex-direction: column; gap: 16px; min-height: 0; }
.panel { position: relative; border: 1px solid #29473f; background: rgba(11, 34, 29, .94); box-shadow: inset 0 1px 0 rgba(140, 211, 194, .06), 0 12px 28px rgba(0, 0, 0, .15); display: flex; flex-direction: column; padding: 13px 14px 11px; overflow: hidden; }
.panel::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px; background: #48bca9; opacity: .85; }
.panel::after { content: ""; position: absolute; right: 10px; top: 0; width: 34px; height: 2px; background: #4dd5c0; }
.panel h3 { color: #e2efeb; font-size: 14px; font-weight: 700; letter-spacing: 1.4px; display: flex; align-items: center; gap: 8px; margin-bottom: 9px; flex-shrink: 0; }
.panel h3::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: #55c9b4; box-shadow: 0 0 0 4px rgba(85, 201, 180, .10); }
.panel h3 .tail { margin-left: auto; color: #7a9b92; font-size: 11px; font-weight: 400; letter-spacing: 0; }
.chart { flex: 1; min-height: 0; }
.kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; height: 118px; flex-shrink: 0; }
.kpi { position: relative; border: 1px solid #29473f; border-top: 3px solid #4bbca9; background: #0b241f; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 5px; overflow: hidden; }
.kpi:nth-child(2) { border-top-color: #ef6c62; }.kpi:nth-child(3) { border-top-color: #e4ae4f; }.kpi:nth-child(4) { border-top-color: #72c987; }
.kpi .v { font-family: Consolas, Menlo, monospace; font-size: 39px; font-weight: 700; line-height: 1; color: #68d7c4; }.kpi .v.red { color: #ef7b70; }.kpi .v.green { color: #83d594; }.kpi .v.amber { color: #e8b45b; }
.kpi .l { color: #a7c1ba; font-size: 13px; letter-spacing: 1px; }.kpi .delta { color: #78978e; font-size: 11px; }.kpi .bar { position: absolute; left: 0; right: 0; bottom: 0; height: 2px; background: #48bca9; opacity: .55; }
.engines { display: flex; flex-direction: column; gap: 11px; overflow: hidden; }.eng { display: flex; flex-direction: column; gap: 6px; }.eng .row { display: flex; align-items: center; font-size: 13px; }.eng .row b { color: #d9e8e3; font-weight: 600; width: 88px; }.eng .row .st { margin-left: auto; color: #7bd294; font-size: 11px; }.eng .row .st.off { color: #ef7b70; }.eng .track { height: 5px; background: #183b33; border-radius: 3px; overflow: hidden; }.eng .fill { height: 100%; border-radius: 3px; background: #4bbca9; transition: width .8s; }
.foot-note { position: absolute; left: 0; right: 0; bottom: 4px; color: #52746b; font-size: 11px; letter-spacing: 1.5px; text-align: center; }
</style>

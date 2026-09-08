<template>
  <div class="panel">
    <div class="toolbar">
      <el-input v-model="query" placeholder="主机名 / IP 搜索" style="width:220px" clearable>
        <template #prefix><el-icon><Search /></el-icon></template></el-input>
      <el-select v-model="statusFilter" placeholder="状态" clearable style="width:130px">
        <el-option label="在线" value="online" /><el-option label="离线" value="offline" />
        <el-option label="已隔离" value="isolated" /><el-option label="待激活" value="pending" /></el-select>
      <el-select placeholder="主机组" clearable style="width:150px">
        <el-option v-for="g in groups" :key="g" :label="g" :value="g" /></el-select>
      <div class="spacer"></div>
      <el-button type="primary" @click="newInstallToken">+ 安装 Agent</el-button>
      <el-button @click="router.push('/system')">Agent 升级</el-button>
    </div>
    <el-table :data="filtered" stripe>
      <el-table-column label="主机" min-width="170">
        <template #default="{ row }"><div><div class="host-name">{{ row.host }}</div><div class="host-ip mono">{{ row.ip }}</div></div></template>
      </el-table-column>
      <el-table-column prop="os" label="系统" width="160" />
      <el-table-column prop="group" label="分组" width="110" />
      <el-table-column prop="ver" label="Agent" width="80" />
      <el-table-column label="容器" width="76">
        <template #default="{ row }"><el-tag v-if="row.containerCount" size="small" type="info">{{ row.containerCount }}</el-tag><span v-else>—</span></template>
      </el-table-column>
      <el-table-column label="进程" width="76">
        <template #default="{ row }"><el-tag v-if="row.processCount" size="small" type="info">{{ row.processCount }}</el-tag><span v-else>—</span></template>
      </el-table-column>
      <el-table-column label="状态" width="90">
        <template #default="{ row }"><el-tag size="small" :type="hostTagType(row.status)">{{ hostStatusLabel(row.status) }}</el-tag></template>
      </el-table-column>
      <el-table-column label="防护" width="70">
        <template #default="{ row }"><el-switch v-model="row.protect" size="small" @change="msg((row.protect ? '已开启 ' : '已关闭 ') + row.host + ' 实时防护')" /></template>
      </el-table-column>
      <el-table-column prop="hb" label="最近心跳" width="90" />
      <el-table-column label="风险值" width="130">
        <template #default="{ row }"><el-progress :percentage="row.risk" :stroke-width="8" :color="row.risk > 80 ? '#dc2626' : row.risk > 60 ? '#f59e0b' : '#16a34a'" /></template>
      </el-table-column>
      <el-table-column label="操作" width="170" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openHost(row)">详情</el-button>
          <el-button v-if="row.status === 'online'" link type="danger" size="small" @click="isolate(row, true)">隔离</el-button>
          <el-button v-if="row.status === 'isolated'" link type="success" size="small" @click="isolate(row, false)">解除</el-button>
          <el-button link type="warning" size="small" @click="armUninstall(row)">卸载</el-button>
        </template>
      </el-table-column>
    </el-table>
    <div style="display:flex;justify-content:flex-end;margin-top:12px">
      <el-pagination background layout="total, prev, pager, next" :total="filtered.length" :page-size="10" /></div>
  </div>

  <!-- 主机详情抽屉 -->
  <el-drawer v-model="drawer" :title="curHost.host" size="480px">
    <template v-if="curHost.host">
      <el-descriptions :column="1" border size="small">
        <el-descriptions-item label="IP">{{ curHost.ip }}</el-descriptions-item>
        <el-descriptions-item label="操作系统">{{ curHost.os }} · x86_64</el-descriptions-item>
        <el-descriptions-item label="Agent 版本">{{ curHost.ver }}（策略 v20260820）</el-descriptions-item>
        <el-descriptions-item label="状态">{{ hostStatusLabel(curHost.status) }} · 心跳 {{ curHost.hb }}</el-descriptions-item>
      </el-descriptions>
      <div class="panel" style="margin-top:14px;box-shadow:none;border:1px solid #eef2f7">
        <h4>近 1h CPU / 内存</h4><div ref="miniEl" style="height:180px"></div>
      </div>
      <div class="panel" style="margin-top:14px;box-shadow:none;border:1px solid #eef2f7">
        <h4>本机待处置</h4>
        <p style="font-size:12px;line-height:2">
          漏洞 6（严重 1）· 基线不合规 9 项 · 病毒待处置 1<br />
          最近事件：{{ curHost.lastEvt || '无' }}</p>
      </div>
      <div style="display:flex;gap:10px;margin-top:14px">
        <el-button size="small" :loading="busyAction === 'collect'" @click="doCollect">立即采集</el-button>
        <el-button size="small" :loading="busyAction === 'scan'" @click="doQuickScan">病毒快扫</el-button>
        <el-button size="small" type="danger" v-if="curHost.status === 'online'" @click="isolate(curHost, true)">隔离主机</el-button>
      </div>
      <section class="container-assets">
        <h4>本机容器与工作负载 <span>{{ containers.length }}</span></h4>
        <el-table v-if="containers.length" :data="containers" size="small" max-height="220">
          <el-table-column prop="name" label="容器" min-width="110" show-overflow-tooltip />
          <el-table-column label="来源" width="86"><template #default="{ row }"><el-tag size="small" effect="plain">{{ row.orchestrator === 'kubernetes' ? 'K8s' : 'Docker' }}</el-tag></template></el-table-column>
          <el-table-column prop="image" label="镜像" min-width="145" show-overflow-tooltip />
          <el-table-column prop="status" label="状态" min-width="110" show-overflow-tooltip />
          <el-table-column label="风险" min-width="120" show-overflow-tooltip><template #default="{ row }"><el-tag v-if="row.risky" size="small" type="danger">{{ riskReasons(row) }}</el-tag><span v-else>—</span></template></el-table-column>
          <el-table-column label="端口" min-width="110" show-overflow-tooltip>
            <template #default="{ row }">{{ (row.ports || []).join(', ') || '—' }}</template>
          </el-table-column>
        </el-table>
        <el-empty v-else :image-size="48" description="未发现本机 Docker 容器或 K8s 工作负载" />
      </section>
      <section class="container-assets">
        <h4>本机进程 <span>{{ processes.length }}</span></h4>
        <el-table v-if="processes.length" :data="processes" size="small" max-height="220">
          <el-table-column prop="pid" label="PID" width="76" />
          <el-table-column prop="name" label="进程" min-width="110" show-overflow-tooltip />
          <el-table-column prop="username" label="用户" min-width="90" show-overflow-tooltip />
          <el-table-column prop="exe" label="路径" min-width="150" show-overflow-tooltip />
          <el-table-column prop="cmdline" label="命令行（已脱敏）" min-width="180" show-overflow-tooltip />
          <el-table-column label="RSS" width="86">
            <template #default="{ row }">
              {{ Math.round((Number(row.rss_bytes) || 0) / 1024 / 1024) }} MB
            </template>
          </el-table-column>
        </el-table>
        <el-empty v-else :image-size="48" description="未采集到本机进程" />
      </section>
    </template>
  </el-drawer>
</template>

<script setup>
import { computed, onMounted, reactive, ref, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as echarts from 'echarts'
import { fetchHosts, fetchGroups, fetchHostDetail, armUninstallToken, createEnrollToken, collectNow, isolateHost, createVirusTask } from '../api'
import { hostTagType, hostStatusLabel, AX } from '../utils/format'

const router = useRouter()

// 数据源：GET /api/hosts → t_agent（注册/心跳/策略版本均来自 Agent 实采）
const hosts = reactive([])
const groups = ref([])
const query = ref('')
const statusFilter = ref('')
const drawer = ref(false)
const curHost = reactive({})
const containers = ref([])
const processes = ref([])
const riskReasons = row => {
  const value = row.risk_reasons
  if (Array.isArray(value)) return value.join(', ')
  try { return JSON.parse(value || '[]').join(', ') || '风险' } catch { return '风险' }
}
const miniEl = ref(null)
let miniChart = null

const filtered = computed(() => hosts.filter(h => {
  const q = query.value.toLowerCase()
  const hitQ = !q || h.host.toLowerCase().includes(q) || h.ip.includes(q)
  const hitS = !statusFilter.value || h.status === statusFilter.value
  return hitQ && hitS
}))

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

// 卸载口令（docs/01 §6.1 防恶意卸载）：平台布防 → 15min 内目标主机执行一次性口令卸载
const armUninstall = async row => {
  try {
    await ElMessageBox.confirm(`将为 ${row.host} 布防一次性卸载口令（15 分钟内有效），确认？`, '卸载 Agent', { type: 'warning' })
  } catch { return }
  try {
    const r = await armUninstallToken(row.agentId)
    ElMessageBox.alert(
      `<p>口令已布防到目标主机，<b>15 分钟内</b>在主机执行：</p>
       <p style="font-family:monospace;background:#0f172a;color:#4ade80;padding:8px;border-radius:4px">${r.usage}</p>
       <p style="color:#94a3b8;font-size:12px">口令一次性消费，过期需重新申请</p>`,
      '卸载口令', { dangerouslyUseHTMLString: true, confirmButtonText: '我已知晓' })
  } catch (e) {
    ElMessage({ message: e?.message || '口令布防失败（主机需在线）', type: 'error' })
  }
}

const openHost = async row => {
  Object.assign(curHost, row)
  containers.value = []
  processes.value = []
  drawer.value = true
  try {
    const data = await fetchHostDetail(row.agentId)
    containers.value = data.containers || []
    processes.value = data.processes || []
  } catch (e) {
    ElMessage({ message: e?.message || '容器资产加载失败', type: 'error' })
  }
  nextTick(() => {
    if (!miniEl.value) return
    if (!miniChart) miniChart = echarts.init(miniEl.value)
    const d = new Array(60).fill(0).map((_, i) => ({
      cpu: Math.round(30 + 20 * Math.sin(i / 8) + Math.random() * 10),
      mem: Math.round(45 + 15 * Math.sin(i / 15) + Math.random() * 5)
    }))
    miniChart.setOption({
      grid: { left: 34, right: 10, top: 24, bottom: 22 },
      tooltip: { trigger: 'axis' },
      legend: { data: ['CPU %', '内存 %'], textStyle: { color: '#64748b' }, top: 0, itemWidth: 14 },
      xAxis: { type: 'category', data: d.map((_, i) => i + 'm'), ...AX },
      yAxis: { type: 'value', max: 100, ...AX },
      series: [
        { name: 'CPU %', type: 'line', smooth: true, showSymbol: false, data: d.map(x => x.cpu), lineStyle: { color: '#2563eb' }, areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(37,99,235,.18)' }, { offset: 1, color: 'rgba(37,99,235,0)' }] } } },
        { name: '内存 %', type: 'line', smooth: true, showSymbol: false, data: d.map(x => x.mem), lineStyle: { color: '#06b6d4' } },
      ]
    })
  })
}

// 隔离 / 解除隔离：CmdProtectAction.ISOLATE_HOST / RESTORE_ISOLATION（Agent ACK 后生效）
const isolate = (row, toIsolated) => {
  const tip = toIsolated
    ? '隔离后仅保留 Agent 与平台通信通道，业务访问将被阻断。确认隔离？'
    : '确认解除该主机隔离，恢复业务网络访问？'
  ElMessageBox.confirm(tip, toIsolated ? '主机隔离确认' : '解除隔离确认',
    { confirmButtonText: toIsolated ? '确认隔离' : '确认解除', cancelButtonText: '取消', type: 'warning' })
    .then(async () => {
      await isolateHost(row.agentId, toIsolated)
      row.status = toIsolated ? 'isolated' : 'online'
      if (curHost.agentId === row.agentId) curHost.status = row.status
      msg(toIsolated ? '隔离指令已下发（Agent ACK 后生效）' : '解除隔离指令已下发')
    })
    .catch(() => { })
}

// 立即采集（CmdCollectNow）
const busyAction = ref('')
const doCollect = async () => {
  busyAction.value = 'collect'
  try {
    await collectNow(curHost.agentId)
    msg('采集指令已下发，结果稍后在资产明细中更新')
  } catch (e) {
    ElMessage({ message: e?.message || '下发失败', type: 'error' })
  } finally {
    busyAction.value = ''
  }
}

// 病毒快扫（复用病毒查杀任务通道，QUICK 模式）
const doQuickScan = async () => {
  busyAction.value = 'scan'
  try {
    await createVirusTask([curHost.agentId], 1, [], `快扫-${curHost.host}`)
    msg('快速扫描任务已下发（结果见病毒查杀页）')
  } catch (e) {
    ElMessage({ message: e?.message || '下发失败', type: 'error' })
  } finally {
    busyAction.value = ''
  }
}

// 安装 Agent：生成一次性注册码并展示安装命令
const newInstallToken = async () => {
  try {
    const r = await createEnrollToken()
    ElMessageBox.alert(
      `<p>注册码已生成（可用 <b>${r.maxUses}</b> 次，<b>${r.validDays}</b> 天内有效）：</p>
       <p style="font-family:monospace;background:#0f172a;color:#4ade80;padding:8px;border-radius:4px;word-break:break-all">${r.usage}</p>
       <p style="color:#94a3b8;font-size:12px">将 &lt;服务端地址&gt; 替换为平台 gRPC 地址后在目标主机以管理员执行</p>`,
      '安装 Agent', { dangerouslyUseHTMLString: true, confirmButtonText: '我已知晓' })
  } catch (e) {
    ElMessage({ message: e?.message || '注册码生成失败', type: 'error' })
  }
}

onMounted(async () => {
  hosts.push(...await fetchHosts())
  groups.value = await fetchGroups()
})
</script>

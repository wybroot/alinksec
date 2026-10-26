<template>
  <div class="panel">
    <div class="toolbar">
      <el-input v-model="query" placeholder="主机名 / IP 搜索" style="width:220px" clearable>
        <template #prefix><el-icon><Search /></el-icon></template></el-input>
      <el-select v-model="statusFilter" placeholder="状态" clearable style="width:130px">
        <el-option label="在线" value="online" /><el-option label="离线" value="offline" />
        <el-option label="隔离中" value="isolating" /><el-option label="已隔离" value="isolated" />
        <el-option label="隔离状态待确认" value="isolation_unknown" /><el-option label="解除中" value="restoring" /><el-option label="隔离失败" value="isolate_failed" />
        <el-option label="解除失败" value="restore_failed" /><el-option label="待激活" value="pending" /></el-select>
      <el-select placeholder="主机组" clearable style="width:150px">
        <el-option v-for="g in groups" :key="g" :label="g" :value="g" /></el-select>
      <div class="spacer"></div>
      <el-button type="primary" @click="newInstallToken">+ 安装 Agent</el-button>
      <el-button @click="router.push('/system')">Agent 升级</el-button>
    </div>
    <el-table v-loading="loading" :data="hosts" stripe>
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
      <el-table-column label="端口" width="76">
        <template #default="{ row }"><el-tag v-if="row.portCount" size="small" type="warning">{{ row.portCount }}</el-tag><span v-else>—</span></template>
      </el-table-column>
      <el-table-column label="风险账户" width="96">
        <template #default="{ row }"><el-tag v-if="row.riskyAccountCount" size="small" type="danger">{{ row.riskyAccountCount }}</el-tag><span v-else>—</span></template>
      </el-table-column>
      <el-table-column label="连接 / 隔离" width="190">
        <template #default="{ row }">
          <div style="display:flex;align-items:center;gap:4px">
            <el-tag size="small" :type="hostTagType(row.connectionStatus)">{{ hostStatusLabel(row.connectionStatus) }}</el-tag>
            <el-tooltip v-if="row.isolationStatus !== 'normal' || row.isolationAutomatic" :disabled="!row.isolationError" :content="row.isolationError">
              <el-tag size="small" :type="hostTagType(row.isolationStatus)">{{ row.isolationAutomatic && row.isolationStatus === 'normal' ? '已自动解除' : hostStatusLabel(row.isolationStatus) }}</el-tag>
            </el-tooltip>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="策略配置" width="94">
        <template #default="{ row }"><el-tag size="small" effect="plain" :type="row.protect ? 'success' : 'info'">{{ row.protect ? '开启' : '关闭' }}</el-tag></template>
      </el-table-column>
      <el-table-column prop="hb" label="最近心跳" width="90" />
      <el-table-column label="风险值" width="130">
        <template #default="{ row }"><el-progress :percentage="row.risk" :stroke-width="8" :color="row.risk > 80 ? '#dc2626' : row.risk > 60 ? '#f59e0b' : '#16a34a'" /></template>
      </el-table-column>
      <el-table-column label="操作" width="170" fixed="right">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openHost(row)">详情</el-button>
          <el-button v-if="canIsolate(row)" link type="danger" size="small" :loading="busyIsolation === row.agentId" @click="isolate(row, true)">隔离</el-button>
          <el-button v-if="canRestore(row)" link type="success" size="small" :loading="busyIsolation === row.agentId" @click="isolate(row, false)">解除</el-button>
          <el-button link type="warning" size="small" @click="armUninstall(row)">卸载</el-button>
        </template>
      </el-table-column>
    </el-table>
    <div style="display:flex;justify-content:flex-end;margin-top:12px">
      <el-pagination v-model:current-page="page" background layout="total, prev, pager, next"
        :total="total" :page-size="pageSize" @current-change="loadHosts" /></div>
  </div>

  <el-drawer v-model="drawer" size="min(1120px, 96vw)" class="host-detail-drawer" destroy-on-close
    @opened="renderMiniChart(runtime)" @closed="disposeChart">
    <template #header>
      <div class="detail-heading"><span class="detail-kicker">主机详情</span><h2>{{ curHost.host }}</h2>
        <div class="detail-identity"><span class="mono">{{ curHost.ip }}</span><el-tag size="small" :type="hostTagType(curHost.connectionStatus)">{{ hostStatusLabel(curHost.connectionStatus) }}</el-tag>
          <el-tag size="small" :type="hostTagType(curHost.isolationStatus)">{{ hostStatusLabel(curHost.isolationStatus) }}</el-tag></div>
      </div>
    </template>
    <div v-if="curHost.agentId" class="host-detail" v-loading="detailLoading">
      <el-alert v-if="detailError" :title="detailError" type="error" :closable="false" show-icon />
      <div class="detail-actions">
        <span class="hint">{{ runtimeFresh ? '性能采样正常' : '性能采样暂缺或已过期' }} · {{ formatDate(latest.sampled_at) }}</span>
        <el-button :loading="detailLoading" @click="refreshDetail">刷新详情</el-button>
        <el-button :loading="busyAction === 'collect'" @click="doCollect">立即采集</el-button>
        <el-button :loading="busyAction === 'scan'" @click="doQuickScan">病毒快扫</el-button>
        <el-button type="danger" v-if="canIsolate(curHost)" :loading="busyIsolation === curHost.agentId" @click="isolate(curHost, true)">隔离主机</el-button>
        <el-button type="success" v-if="canRestore(curHost)" :loading="busyIsolation === curHost.agentId" @click="isolate(curHost, false)">解除隔离</el-button>
      </div>
      <div class="host-stat-grid">
        <div class="host-stat"><span>CPU 使用率</span><strong>{{ percentText(latest.cpu_percent) }}</strong><small>{{ hardware.logical_cpus ? hardware.logical_cpus + ' 个逻辑处理器' : '等待硬件信息' }}</small></div>
        <div class="host-stat"><span>内存使用率</span><strong>{{ percentText(latest.memory_percent) }}</strong><small>总容量 {{ bytesText(hardware.memory_total_bytes) }}</small></div>
        <div class="host-stat"><span>连续运行时间</span><strong class="uptime-value">{{ durationText(latest.uptime_sec) }}</strong><small>开机 {{ formatDate(hardware.boot_time_sec ? hardware.boot_time_sec * 1000 : null) }}</small></div>
        <div class="host-stat"><span>待处置安全告警</span><strong>{{ curHost.alertCount || 0 }}</strong><small>{{ curHost.lastEvt || '暂无安全事件' }}</small></div>
      </div>
      <el-tabs v-model="detailTab" class="host-detail-tabs" @tab-change="resizeChart">
        <el-tab-pane label="主机概览" name="overview">
          <div class="detail-overview-grid">
            <section class="detail-section"><h3>系统与硬件</h3>
              <dl class="host-info-grid">
                <div><dt>操作系统</dt><dd>{{ curHost.os }}</dd></div>
                <div><dt>内核版本</dt><dd class="mono">{{ hostInfo.kernel || '未上报' }}</dd></div>
                <div><dt>CPU 型号</dt><dd>{{ hardware.cpu_model || '未上报，请更新 Agent 并等待心跳' }}</dd></div>
                <div><dt>处理器架构</dt><dd>{{ hostInfo.arch || curHost.arch }}</dd></div>
                <div><dt>物理核心 / 逻辑处理器</dt><dd>{{ hardware.physical_cores || '—' }} / {{ hardware.logical_cpus || '—' }}</dd></div>
                <div><dt>物理内存</dt><dd>{{ bytesText(hardware.memory_total_bytes) }}</dd></div>
                <div><dt>开机时间</dt><dd>{{ formatDate(hardware.boot_time_sec ? hardware.boot_time_sec * 1000 : null) }}</dd></div>
                <div><dt>系统时区</dt><dd>{{ hardware.timezone || '未上报' }}</dd></div>
                <div><dt>虚拟化</dt><dd>{{ [hardware.virtualization_system, hardware.virtualization_role].filter(Boolean).join(' / ') || '未上报' }}</dd></div>
                <div><dt>硬件信息更新时间</dt><dd>{{ formatDate(latest.host_info_at) }}</dd></div>
              </dl>
            </section>
            <section class="detail-section"><h3>接入与防护</h3>
              <dl class="host-info-grid">
                <div class="full-width"><dt>Agent ID</dt><dd class="mono">{{ curHost.agentId }}</dd></div>
                <div><dt>Agent 版本</dt><dd>{{ hostInfo.agent_version || curHost.ver }}</dd></div>
                <div><dt>策略版本</dt><dd>{{ hostInfo.policy_version || '未上报' }}</dd></div>
                <div><dt>首次接入</dt><dd>{{ formatDate(hostInfo.created_at) }}</dd></div>
                <div><dt>最近心跳</dt><dd>{{ formatDate(hostInfo.last_heartbeat) }}</dd></div>
                <div class="full-width"><dt>IP 地址</dt><dd class="mono">{{ (hardware.ip_list || []).join(' · ') || curHost.ip }}</dd></div>
                <div class="full-width"><dt>MAC 地址</dt><dd class="mono">{{ (hardware.mac_list || []).join(' · ') || '未上报' }}</dd></div>
                <div class="full-width"><dt>隔离保护</dt><dd>{{ curHost.isolationContract === 1 ? '管理通道失联 10 秒后自动解除' : '当前 Agent 不支持安全隔离，请升级并使用原生服务' }}</dd></div>
                <div v-if="curHost.isolationError" class="full-width"><dt>隔离说明</dt><dd>{{ curHost.isolationError }}</dd></div>
              </dl>
            </section>
          </div>
          <section class="detail-section performance-section"><div class="section-title"><h3>近一小时 CPU / 内存</h3><span class="hint">每分钟保留最近一次心跳采样 · 每 15 秒刷新</span></div>
            <el-alert v-if="runtimeError" :title="runtimeError" type="warning" :closable="false" />
            <div ref="miniEl" class="host-performance-chart"></div>
            <p v-if="!hasMetricSamples" class="hint">暂无有效性能采样，等待 Agent 上报；缺失值不会显示为 0%。</p>
          </section>
          <section class="detail-section"><h3>磁盘与文件系统</h3>
            <el-table v-if="hostInfo.disks?.length" :data="hostInfo.disks" size="small">
              <el-table-column prop="mount" label="挂载点" min-width="160" show-overflow-tooltip />
              <el-table-column prop="fs_type" label="文件系统" width="110" />
              <el-table-column label="已用 / 总容量" min-width="180"><template #default="{ row }">{{ bytesText(row.used_bytes) }} / {{ bytesText(row.total_bytes) }}</template></el-table-column>
              <el-table-column label="使用率" min-width="160"><template #default="{ row }"><el-progress :percentage="Math.min(100, Math.round(row.used_bytes / row.total_bytes * 100))" :stroke-width="8" /></template></el-table-column>
              <el-table-column label="采集时间" min-width="170"><template #default="{ row }">{{ formatDate(row.updated_at) }}</template></el-table-column>
            </el-table>
            <el-empty v-else :image-size="48" description="暂无磁盘清单，请立即采集" />
          </section>
        </el-tab-pane>
        <el-tab-pane label="软件清单" name="software">
          <section class="container-assets">
        <h4>软件清单</h4>
        <el-alert :type="softwareInventory.software_collection_status === 'complete' ? 'info' : 'warning'"
          :title="inventoryStatusLabel" :closable="false" />
        <p style="font-size:12px;line-height:1.8">
          发行版：{{ softwareInventory.distro_id || '未知' }} · {{ softwareInventory.distro_version || '版本未知' }}<br />
          清单来源：{{ softwareInventory.software_inventory_source || '未知' }}<br />
          最近成功采集：{{ softwareInventory.software_succeeded_at || '暂无完整采集记录' }}
        </p>
        <el-table v-if="software.length" :data="software" size="small" max-height="220">
          <el-table-column prop="name" label="软件包" min-width="120" show-overflow-tooltip />
          <el-table-column prop="version" label="完整版本" min-width="140" show-overflow-tooltip />
          <el-table-column prop="source" label="来源" width="85" />
          <el-table-column label="包架构" width="100"><template #default="{ row }">{{ row.architecture || '未知' }}</template></el-table-column>
        </el-table>
        <p v-if="software.length === 500" style="font-size:12px">当前展示前 500 条软件记录。</p>
        <el-empty v-if="!software.length" :image-size="48"
          :description="softwareInventory.software_collection_status === 'complete' ? '完整采集结果为空' : '暂无可用软件清单'" />
      </section>
        </el-tab-pane>
        <el-tab-pane label="容器与工作负载" name="containers">
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
        </el-tab-pane>
        <el-tab-pane label="进程" name="processes">
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
        </el-tab-pane>
        <el-tab-pane label="监听端口" name="ports">
          <section class="container-assets">
        <h4>监听端口 <span>{{ ports.length }}</span></h4>
        <el-table v-if="ports.length" :data="ports" size="small" max-height="180">
          <el-table-column prop="protocol" label="协议" width="76" />
          <el-table-column prop="port" label="端口" width="76" />
          <el-table-column prop="bind_addr" label="绑定地址" min-width="120" show-overflow-tooltip />
          <el-table-column prop="process" label="所属进程" min-width="130" show-overflow-tooltip />
        </el-table>
        <el-empty v-else :image-size="48" description="未发现监听端口" />
      </section>
        </el-tab-pane>
        <el-tab-pane label="风险账户" name="accounts">
          <section class="container-assets">
        <h4>高风险账户 <span>{{ riskyAccounts.length }}</span></h4>
        <el-table v-if="riskyAccounts.length" :data="riskyAccounts" size="small" max-height="180">
          <el-table-column prop="name" label="账户" min-width="110" show-overflow-tooltip />
          <el-table-column prop="uid" label="UID" width="76" />
          <el-table-column prop="shell" label="Shell" min-width="120" show-overflow-tooltip />
          <el-table-column prop="risky_reason" label="风险原因" min-width="180" show-overflow-tooltip>
            <template #default="{ row }"><el-tag type="danger" size="small">{{ row.risky_reason || '风险账户' }}</el-tag></template>
          </el-table-column>
        </el-table>
        <el-empty v-else :image-size="48" description="未发现高风险账户" />
      </section>
        </el-tab-pane>
      </el-tabs>
    </div>
  </el-drawer>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount, reactive, ref, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as echarts from 'echarts'
import { fetchHosts, fetchHostState, fetchGroups, fetchHostDetail, fetchHostMetrics, armUninstallToken, createEnrollToken, collectNow, isolateHost, createVirusTask } from '../api'
import { hostTagType, hostStatusLabel, AX } from '../utils/format'
import { metricPoints, percentText, bytesText, durationText, formatDate } from '../utils/host-detail'

const router = useRouter()

// 数据源：GET /api/hosts → t_agent（注册/心跳/策略版本均来自 Agent 实采）
const hosts = reactive([])
const groups = ref([])
const query = ref('')
const statusFilter = ref('')
const page = ref(1)
const pageSize = 20
const total = ref(0)
const loading = ref(false)
const drawer = ref(false)
const curHost = reactive({})
const hostInfo = ref({})
const detailTab = ref('overview')
const detailLoading = ref(false)
const detailError = ref('')
const runtime = ref({})
const runtimeError = ref('')
const now = ref(Date.now())
const latest = computed(() => runtime.value.latest || {})
const hardware = computed(() => latest.value.host || {})
const runtimeFresh = computed(() => !runtimeError.value && curHost.connectionStatus === 'online' && latest.value.sampled_at && now.value - Number(latest.value.sampled_at) < 90000)
const hasMetricSamples = computed(() => {
  const points = metricPoints(runtime.value)
  return [...points.cpu, ...points.mem].some(value => value !== null)
})
const containers = ref([])
const processes = ref([])
const ports = ref([])
const riskyAccounts = ref([])
const software = ref([])
const softwareInventory = ref({})
const inventoryStatusLabel = computed(() => {
  const inventory = softwareInventory.value
  if (inventory.software_collection_status === 'complete') {
    return inventory.software_identity_error ? '软件清单已采集，发行版身份信息不完整' : '软件清单已完整采集'
  }
  if (inventory.software_collection_status === 'failed') return '最近软件采集失败；当前显示上次保留的清单，自动修复已阻断'
  if (inventory.software_collection_status === 'unsupported') return '当前系统的软件采集尚不支持；自动修复已阻断'
  return '软件清单完整性未知，请重新采集后进行自动修复'
})
const riskReasons = row => {
  const value = row.risk_reasons
  if (Array.isArray(value)) return value.join(', ')
  try { return JSON.parse(value || '[]').join(', ') || '风险' } catch { return '风险' }
}
const miniEl = ref(null)
let miniChart = null
let chartObserver
const disposeChart = () => {
  chartObserver?.disconnect()
  chartObserver = null
  miniChart?.dispose()
  miniChart = null
}
const resizeChart = () => nextTick(() => miniChart?.resize())

const renderMiniChart = (metrics) => {
  const points = metricPoints(metrics)
  nextTick(() => {
    if (!drawer.value || !miniEl.value) return
    if (!miniChart) {
      miniChart = echarts.init(miniEl.value)
      chartObserver = new ResizeObserver(() => miniChart?.resize())
      chartObserver.observe(miniEl.value)
    }
    miniChart.setOption({
      grid: { left: 34, right: 10, top: 24, bottom: 22 },
      tooltip: { trigger: 'axis' },
      legend: { data: ['CPU %', '内存 %'], textStyle: { color: '#64748b' }, top: 0, itemWidth: 14 },
      xAxis: { type: 'category', data: points.labels, ...AX },
      yAxis: { type: 'value', max: 100, ...AX },
      series: [
        { name: 'CPU %', type: 'line', connectNulls: false, symbolSize: 5, data: points.cpu, lineStyle: { color: '#2563eb' }, areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(37,99,235,.18)' }, { offset: 1, color: 'rgba(37,99,235,0)' }] } } },
        { name: '内存 %', type: 'line', connectNulls: false, symbolSize: 5, data: points.mem, lineStyle: { color: '#06b6d4' } },
      ]
    }, true)
  })
}

let loadVersion = 0
let hostRequestPending = false
const loadHosts = async (silent = false) => {
  silent = silent === true
  const version = ++loadVersion
  hostRequestPending = true
  if (!silent) loading.value = true
  try {
    const result = await fetchHosts({
      keyword: query.value,
      status: statusFilter.value,
      page: page.value,
      size: pageSize,
    })
    if (version !== loadVersion) return
    hosts.splice(0, hosts.length, ...result.list)
    const current = result.list.find(row => row.agentId === curHost.agentId)
    if (current) Object.assign(curHost, current)
    else if (drawer.value && curHost.agentId) {
      const agentId = curHost.agentId
      const state = await fetchHostState(agentId)
      if (version === loadVersion && curHost.agentId === agentId) Object.assign(curHost, state)
    }
    total.value = result.total
  } catch (e) {
    if (version === loadVersion && !silent) ElMessage({ message: e?.message || '主机列表加载失败', type: 'error' })
  } finally {
    if (version === loadVersion) { loading.value = false; hostRequestPending = false }
  }
}

let queryTimer
watch(query, () => {
  page.value = 1
  clearTimeout(queryTimer)
  queryTimer = setTimeout(loadHosts, 250)
})
watch(statusFilter, () => {
  page.value = 1
  loadHosts()
})

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })
const busyIsolation = ref('')
const canIsolate = row => row.connectionStatus === 'online' && row.isolationContract === 1 && ['normal', 'isolate_failed'].includes(row.isolationStatus)
const canRestore = row => row.connectionStatus === 'online' && ['isolating', 'isolated', 'isolate_failed', 'restore_failed', 'isolation_unknown'].includes(row.isolationStatus)

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

let detailVersion = 0
let runtimeVersion = 0
const openHost = row => {
  detailVersion++
  runtimeVersion++
  for (const key of Object.keys(curHost)) delete curHost[key]
  Object.assign(curHost, row)
  hostInfo.value = {}
  runtime.value = {}
  runtimeError.value = ''
  detailError.value = ''
  detailTab.value = 'overview'
  containers.value = []
  processes.value = []
  ports.value = []
  riskyAccounts.value = []
  software.value = []
  softwareInventory.value = {}
  drawer.value = true
  renderMiniChart({})
  refreshDetail()
}
const refreshRuntime = async () => {
  const version = ++runtimeVersion, agentId = curHost.agentId
  now.value = Date.now()
  try {
    const metrics = await fetchHostMetrics(agentId)
    if (version !== runtimeVersion || !drawer.value || curHost.agentId !== agentId) return
    runtime.value = metrics
    runtimeError.value = ''
    renderMiniChart(metrics)
  } catch (e) {
    if (version === runtimeVersion && drawer.value) runtimeError.value = e?.message || '性能数据加载失败'
  }
}
const refreshDetail = async () => {
  const version = ++detailVersion, agentId = curHost.agentId
  detailLoading.value = true
  const performance = refreshRuntime()
  try {
    const data = await fetchHostDetail(agentId)
    if (version !== detailVersion || !drawer.value || curHost.agentId !== agentId) return
    containers.value = data.containers || []
    processes.value = data.processes || []
    ports.value = data.ports || []
    riskyAccounts.value = (data.accounts || []).filter(account => account.risky)
    software.value = data.software || []
    softwareInventory.value = data.detail || {}
    hostInfo.value = data.detail || {}
    detailError.value = ''
  } catch (e) {
    if (version === detailVersion && drawer.value) detailError.value = e?.message || '主机资产加载失败'
  } finally {
    if (version === detailVersion) detailLoading.value = false
    await performance
  }
}
watch(drawer, value => { if (!value) { detailVersion++; runtimeVersion++; detailLoading.value = false } })

// 隔离 / 解除隔离：CmdProtectAction.ISOLATE_HOST / RESTORE_ISOLATION（本机状态与认证往返确认后生效）
const isolate = async (row, toIsolated) => {
  const tip = toIsolated
    ? '隔离后仅保留 Agent 与平台通信通道，业务访问将被阻断。管理通道失联 10 秒后会自动解除隔离。确认隔离？'
    : '确认解除该主机隔离，恢复业务网络访问？'
  try {
    await ElMessageBox.confirm(tip, toIsolated ? '主机隔离确认' : '解除隔离确认',
      { confirmButtonText: toIsolated ? '确认隔离' : '确认解除', cancelButtonText: '取消', type: 'warning' })
  } catch { return }
  busyIsolation.value = row.agentId
  try {
    const result = await isolateHost(row.agentId, toIsolated)
    row.isolationStatus = result.isolationStatus
    row.isolationError = ''
    row.isolationAutomatic = false
    row.status = result.isolationStatus
    if (curHost.agentId === row.agentId) Object.assign(curHost, row)
    msg(toIsolated ? '隔离指令已下发，等待 Agent 确认' : '解除指令已下发，等待 Agent 确认')
  } catch (e) {
    ElMessage({ message: e?.message || '隔离状态变更失败', type: 'error' })
  } finally {
    busyIsolation.value = ''
  }
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

let isolationRefreshTimer
let runtimeRefreshTimer
onMounted(async () => {
  runtimeRefreshTimer = setInterval(() => {
    now.value = Date.now()
    if (drawer.value && !detailLoading.value && document.visibilityState === 'visible') refreshRuntime()
  }, 15000)
  isolationRefreshTimer = setInterval(() => {
    if (!hostRequestPending && !busyIsolation.value && document.visibilityState === 'visible') loadHosts(true)
  }, 3000)
  await Promise.all([
    loadHosts(),
    fetchGroups().then(value => { groups.value = value }),
  ])
})
onBeforeUnmount(() => { clearInterval(runtimeRefreshTimer); clearInterval(isolationRefreshTimer); clearTimeout(queryTimer); loadVersion++; detailVersion++; runtimeVersion++; disposeChart() })
</script>

<style scoped>
.detail-heading { min-width: 0; }
.detail-kicker { color: #64748b; font-size: 12px; }
.detail-heading h2 { margin: 5px 0 10px; font-size: 23px; overflow-wrap: anywhere; }
.detail-identity, .detail-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.detail-actions { margin-bottom: 20px; }
.detail-actions .hint { margin-right: auto; }
.detail-actions .el-button { margin-left: 0; }
.host-stat-grid { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 12px; margin-bottom: 20px; }
.host-stat { border: 1px solid #e2e8f0; border-radius: 10px; background: #f8fafc; padding: 16px; min-width: 0; display: flex; flex-direction: column; gap: 8px; }
.host-stat > span { color: #64748b; font-size: 13px; }
.host-stat strong { font-size: 27px; color: #0f172a; font-weight: 650; }
.host-stat strong.uptime-value { font-size: 19px; line-height: 32px; }
.host-stat small { font-size: 12px; color: #64748b; overflow-wrap: anywhere; }
.detail-overview-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 16px; }
.detail-section { border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; margin-bottom: 16px; min-width: 0; }
.detail-section h3 { font-size: 15px; margin: 0 0 16px; color: #0f172a; }
.host-info-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); margin: 0; gap: 18px 16px; }
.host-info-grid > div { min-width: 0; }
.host-info-grid .full-width { grid-column: 1 / -1; }
.host-info-grid dt { color: #64748b; font-size: 12px; margin-bottom: 6px; }
.host-info-grid dd { margin: 0; color: #1e293b; font-size: 13px; line-height: 1.6; overflow-wrap: anywhere; }
.section-title { display: flex; align-items: baseline; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.hint { color: #64748b; font-size: 12px; line-height: 1.6; }
.host-performance-chart { height: 250px; width: 100%; }
.host-detail-tabs { min-width: 0; }
.container-assets h4 { margin: 16px 0; }
@media (max-width: 760px) {
  .host-stat-grid { grid-template-columns: repeat(2,minmax(0,1fr)); }
  .detail-overview-grid { grid-template-columns: 1fr; gap: 0; }
  .detail-section { padding: 14px; }
  .host-stat { padding: 12px; }
  .host-stat strong { font-size: 24px; }
}
@media (max-width: 420px) { .host-info-grid { grid-template-columns: 1fr; } }
</style>

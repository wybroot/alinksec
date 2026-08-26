<template>
  <div class="panel">
    <el-tabs v-model="tab">
      <!-- ============ Agent 升级 ============ -->
      <el-tab-pane label="Agent 升级" name="upgrade">
        <div class="row" style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
          <el-input v-model="upVersion" placeholder="版本号，如 1.2.0" style="width:160px" />
          <el-select v-model="upPlatform" style="width:170px">
            <el-option label="linux-amd64" value="linux-amd64" />
            <el-option label="linux-arm64" value="linux-arm64" />
            <el-option label="windows-amd64" value="windows-amd64" />
          </el-select>
          <input ref="pkgFile" type="file" style="display:none" @change="onPkgFile" />
          <el-button type="primary" size="small" :disabled="!upVersion || !upPlatform" @click="pkgFile.click()">上传升级包</el-button>
          <span class="hint">上传后 Agent 侧校验 SHA256 并原子替换，退出后由 systemd/SCM 拉起新版本，旧版本保留可回滚</span>
        </div>
        <el-table :data="packages" stripe size="small">
          <el-table-column prop="version" label="版本" width="110" />
          <el-table-column prop="platform" label="平台" width="140" />
          <el-table-column label="SHA256" min-width="220">
            <template #default="{ row }"><span class="mono">{{ String(row.sha256 || '').slice(0, 24) }}…</span></template>
          </el-table-column>
          <el-table-column prop="notes" label="说明" min-width="160" show-overflow-tooltip />
          <el-table-column label="操作" width="110">
            <template #default="{ row }">
              <el-button type="primary" link size="small" @click="openDispatch(row)">灰度下发</el-button>
            </template>
          </el-table-column>
        </el-table>
        <h4 style="margin:16px 0 8px">版本分布（心跳实时）</h4>
        <el-table :data="versions" stripe size="small">
          <el-table-column prop="version" label="Agent 版本" min-width="140" />
          <el-table-column prop="count" label="主机数" width="120" />
        </el-table>
      </el-tab-pane>

      <!-- ============ 操作审计 ============ -->
      <el-tab-pane label="操作审计" name="audit">
        <el-table :data="auditLogs" stripe size="small">
          <el-table-column prop="time" label="时间" width="150" />
          <el-table-column prop="username" label="操作人" width="110" />
          <el-table-column label="动作" width="80">
            <template #default="{ row }"><el-tag size="small" :type="methodType(row.method)" effect="plain">{{ row.method }}</el-tag></template>
          </el-table-column>
          <el-table-column prop="path" label="接口" min-width="220" class="mono" />
          <el-table-column prop="ip" label="来源 IP" width="130" />
          <el-table-column prop="status" label="响应码" width="80" />
          <el-table-column prop="cost" label="耗时" width="90" />
        </el-table>
        <el-pagination v-model:current-page="page" :page-size="20" :total="total" layout="prev, pager, next" style="margin-top:12px" @current-change="loadAudit" />
      </el-tab-pane>

      <!-- ============ 合规报表 ============ -->
      <el-tab-pane label="合规报表" name="report">
        <div style="display:flex;gap:8px;align-items:center">
          <el-date-picker v-model="range" type="daterange" range-separator="~" start-placeholder="开始" end-placeholder="结束" style="width:260px" />
          <el-button type="primary" size="small" @click="exportCsv">导出 CSV（Excel 可开）</el-button>
          <span class="hint">报表含主机资产概览 / 基线合规率 / 漏洞分布 / 告警处置四部分</span>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 灰度下发弹窗 -->
    <el-dialog v-model="dispatchDlg" title="灰度下发升级" width="420px">
      <p style="margin:0 0 8px;font-size:13px">目标：{{ dispatchPkg?.version }} / {{ dispatchPkg?.platform }}</p>
      <el-input v-model="dispatchAgents" type="textarea" :rows="4" placeholder="Agent ID 列表，逗号或换行分隔" />
      <template #footer>
        <el-button @click="dispatchDlg = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="doDispatch">下发</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchUpgradePackages, uploadUpgradePackage, dispatchUpgrade, fetchAgentVersions, fetchAuditLogs, downloadComplianceReport } from '../api'

const tab = ref('upgrade')
const busy = ref(false)

/* ---- 升级 ---- */
const packages = ref([])
const versions = ref([])
const upVersion = ref('')
const upPlatform = ref('linux-amd64')
const pkgFile = ref(null)
const dispatchDlg = ref(false)
const dispatchPkg = ref(null)
const dispatchAgents = ref('')

const msg = (t, type = 'success') => ElMessage({ message: t, type, duration: 2200 })

async function loadUpgrade() {
  const [pkgs, vers] = await Promise.all([fetchUpgradePackages(), fetchAgentVersions()])
  packages.value = pkgs || []
  versions.value = (vers || []).map((v) => ({ version: v.version, count: v.count }))
}

function onPkgFile(e) {
  const file = e.target.files?.[0]
  e.target.value = ''
  if (!file) return
  busy.value = true
  uploadUpgradePackage(file, upVersion.value, upPlatform.value, '')
    .then((r) => { msg(`升级包 ${r?.version} 上传成功`); loadUpgrade() })
    .catch((err) => msg(err?.message || '上传失败', 'error'))
    .finally(() => { busy.value = false })
}

function openDispatch(row) {
  dispatchPkg.value = row
  dispatchAgents.value = ''
  dispatchDlg.value = true
}

async function doDispatch() {
  const agentIds = dispatchAgents.value.split(/[\n,，\s]+/).filter(Boolean)
  if (!agentIds.length) return msg('请填写目标 Agent ID', 'warning')
  busy.value = true
  try {
    const r = await dispatchUpgrade(dispatchPkg.value.id, agentIds)
    msg(`已向 ${r?.dispatched ?? agentIds.length} 台主机下发升级指令`)
    dispatchDlg.value = false
  } catch (e) {
    msg(e?.message || '下发失败', 'error')
  } finally {
    busy.value = false
  }
}

/* ---- 审计 ---- */
const auditLogs = ref([])
const page = ref(1)
const total = ref(0)

async function loadAudit() {
  const data = await fetchAuditLogs(page.value, 20)
  total.value = Number(data?.total || 0)
  auditLogs.value = (data?.list || []).map((l) => ({
    time: fmtTime(l.created_at), username: l.username || '—', method: l.method,
    path: l.path, ip: l.source_ip || '—', status: l.status, cost: `${l.cost_ms}ms`,
  }))
}

const fmtTime = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  const p = (x) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const methodType = (m) => ({ POST: 'primary', PUT: 'warning', DELETE: 'danger' }[m] || 'info')

/* ---- 报表 ---- */
const range = ref(null)

async function exportCsv() {
  const from = range.value?.[0] ? new Date(range.value[0]).toISOString().slice(0, 10) : ''
  const to = range.value?.[1] ? new Date(range.value[1]).toISOString().slice(0, 10) : ''
  try {
    await downloadComplianceReport(from, to)
    msg('报表已导出')
  } catch (e) {
    msg(e?.message || '导出失败', 'error')
  }
}

onMounted(() => { loadUpgrade(); loadAudit() })
</script>

<style scoped>
.row { flex-wrap: wrap }
.hint { font-size: 12px; color: #94a3b8 }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px }
</style>

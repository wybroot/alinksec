<template>
  <div class="panel">
    <el-tabs v-model="tab">
      <el-tab-pane v-if="isAdmin" label="组件健康" name="health" lazy><ComponentHealthPanel v-if="tab === 'health'" /></el-tab-pane>
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
          <el-button v-if="isAdmin" type="primary" size="small" :disabled="!upVersion || !upPlatform" @click="pkgFile.click()">上传升级包</el-button>
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
              <el-button v-if="canUpgrade" type="primary" link size="small" @click="openDispatch(row)">灰度下发</el-button>
            </template>
          </el-table-column>
        </el-table>
        <h4>升级批次 <el-button size="small" @click="loadBatches">刷新</el-button></h4>
        <el-alert v-if="upgradeError" :title="upgradeError" type="error" :closable="false" />
        <el-table :data="upgradeBatches" size="small">
          <el-table-column prop="id" label="批次" min-width="230" /><el-table-column prop="version" label="目标版本" /><el-table-column prop="platform" label="平台" /><el-table-column prop="target_count" label="主机数" />
          <el-table-column label="结果"><template #default="{ row }"><el-button link @click="openBatch(row.id)">查看逐机结果</el-button></template></el-table-column>
        </el-table>
        <el-pagination v-model:current-page="batchPage" :total="batchTotal" :page-size="20" layout="total, prev, pager, next" @current-change="loadBatches" />
        <template v-if="batchId">
          <h4>批次 {{ batchId }} <el-button size="small" @click="loadBatch">刷新结果</el-button></h4>
          <p>发送成功不代表升级完成。只有最终回执中的版本、摘要及启动健康确认均匹配，才显示验证成功；未收到的安装／重启阶段保持待确认。</p>
          <el-table :data="batchRows" size="small">
            <el-table-column prop="agent_id" label="主机" min-width="150" /><el-table-column prop="command_id" label="指令编号" min-width="210" />
            <el-table-column label="执行状态" min-width="170"><template #default="{ row }">{{ commandStatus(row.status) }}{{ row.rolled_back ? '；已回退' : '' }}</template></el-table-column>
            <el-table-column label="版本／摘要确认" min-width="150"><template #default="{ row }">{{ row.confirmation === 'verified' ? '验证成功' : '未验证' }}<div>{{ row.expected_version }}</div><small class="mono">{{ row.expected_sha256 }}</small></template></el-table-column>
            <el-table-column prop="result_message" label="回执／失败原因" min-width="240" />
          </el-table>
          <el-pagination v-model:current-page="batchTargetPage" :total="batchTargetTotal" :page-size="20" layout="total, prev, pager, next" @current-change="loadBatch" />
        </template>
        <h4 style="margin:16px 0 8px">版本分布（心跳实时）</h4>
        <el-table :data="versions" stripe size="small">
          <el-table-column prop="version" label="Agent 版本" min-width="140" />
          <el-table-column prop="count" label="主机数" width="120" />
        </el-table>
      </el-tab-pane>

      <!-- ============ 操作审计 ============ -->
      <el-tab-pane v-if="isAdmin" label="操作审计" name="audit">
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
      <el-tab-pane label="合规报表" name="report" lazy><ReportPanel /></el-tab-pane>
      <el-tab-pane v-if="isAdmin" label="集中取证" name="evidence" lazy><EvidencePanel /></el-tab-pane>
      <el-tab-pane v-if="isAdmin" label="服务集群" name="cluster" lazy><ClusterPanel /></el-tab-pane>

      <!-- ============ WAF 防护 ============ -->
      <el-tab-pane v-if="isAdmin" label="WAF 防护" name="waf">
        <div style="max-width:680px;padding:12px 0">
          <el-descriptions title="WAF 引擎状态与规格" :column="2" border size="small">
            <el-descriptions-item label="引擎名称">{{ wafStatus.engine || 'ALinkSec WAF Engine' }}</el-descriptions-item>
            <el-descriptions-item label="规则集版本">{{ wafStatus.version || 'v4.1.0-crs-compat' }}</el-descriptions-item>
            <el-descriptions-item label="已加载规则">{{ wafStatus.ruleCount || 0 }} 条</el-descriptions-item>
            <el-descriptions-item label="当前异常阈值">{{ wafStatus.threshold || 5 }} 分</el-descriptions-item>
          </el-descriptions>
          <h4 style="margin:20px 0 12px">WAF 运行模式与异常规则集配置</h4>
          <el-form label-width="120px" :disabled="wafSaving">
            <el-form-item label="启用 WAF">
              <el-switch v-model="wafForm.enabled" />
            </el-form-item>
            <el-form-item label="防护模式">
              <el-radio-group v-model="wafForm.mode">
                <el-radio value="DetectionOnly">仅检测并记录 (DetectionOnly)</el-radio>
                <el-radio value="On">阻断攻击请求 (On / HTTP 403)</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="异常评分阈值">
              <el-input-number v-model="wafForm.threshold" :min="1" :max="100" controls-position="right" />
              <span class="hint" style="margin-left:10px">单请求累计异常分值超出阈值时判定攻击</span>
            </el-form-item>
            <el-form-item label="Paranoia Level">
              <el-select v-model="wafForm.paranoiaLevel" style="width:220px">
                <el-option :value="1" label="PL 1 - 基础防护规则" />
                <el-option :value="2" label="PL 2 - 进阶防护规则" />
                <el-option :value="3" label="PL 3 - 高安全敏感规则" />
                <el-option :value="4" label="PL 4 - 极严格防御规则" />
              </el-select>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="wafSaving" @click="saveWafConfig">保存 WAF 配置</el-button>
              <el-button @click="loadWafStatus">刷新状态</el-button>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <el-tab-pane v-if="isAdmin" label="告警通道" name="notify">
        <div class="row" style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
          <el-button type="primary" size="small" @click="openChannel()">新增 Webhook</el-button>
          <span class="hint">仅推送达到通道设定等级的告警。Webhook 返回 2xx 才会视为投递成功。</span>
        </div>
        <el-table :data="channels" stripe size="small">
          <el-table-column prop="name" label="名称" min-width="140" />
          <el-table-column prop="webhook_url" label="Webhook 地址" min-width="280" show-overflow-tooltip />
          <el-table-column label="最低等级" width="110">
            <template #default="{ row }">{{ severityName(row.min_severity) }}</template>
          </el-table-column>
          <el-table-column label="状态" width="90">
            <template #default="{ row }"><el-tag size="small" :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '停用' }}</el-tag></template>
          </el-table-column>
          <el-table-column label="操作" width="120">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="openChannel(row)">编辑</el-button>
              <el-button link type="danger" size="small" @click="deleteChannel(row)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ============ 账号管理 (G10) ============ -->
      <el-tab-pane v-if="isAdmin" label="账号管理" name="users">
        <div class="row" style="margin-bottom:12px;display:flex;gap:8px;align-items:center">
          <el-button type="primary" size="small" @click="openCreateUser">新增账号</el-button>
          <span class="hint">管理端本地账号生命周期治理。至少保留一个启用的系统管理员。</span>
        </div>
        <el-table :data="userList" stripe size="small" :loading="userLoading">
          <el-table-column prop="id" label="UID" width="70" />
          <el-table-column prop="username" label="用户名" width="130" />
          <el-table-column prop="real_name" label="姓名/昵称" min-width="120" />
          <el-table-column label="角色" width="120">
            <template #default="{ row }">
              <el-tag size="small" :type="row.role_name === 'admin' ? 'danger' : (row.role_name === 'operator' ? 'warning' : 'info')">
                {{ row.role_name === 'admin' ? '系统管理员' : (row.role_name === 'operator' ? '安全运维员' : '只读审计员') }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="100">
            <template #default="{ row }">
              <el-tag size="small" :type="Number(row.status) === 1 ? 'success' : 'danger'">
                {{ Number(row.status) === 1 ? '正常' : '已停用' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="last_login_at" label="最后登录时间" width="160" />
          <el-table-column prop="created_at" label="创建时间" width="160" />
          <el-table-column label="操作" width="180">
            <template #default="{ row }">
              <el-button link type="primary" size="small" @click="openEditUser(row)">编辑</el-button>
              <el-button link type="warning" size="small" @click="openResetPassword(row)">重置密码</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <!-- 灰度下发弹窗 -->
    <el-dialog v-model="dispatchDlg" title="灰度下发升级" width="min(700px, 94vw)">
      <p style="margin:0 0 8px;font-size:13px">目标：{{ dispatchPkg?.version }} / {{ dispatchPkg?.platform }}</p>
      <p>仅列出匹配升级包平台且具备原生升级看护能力的主机。离线主机将保持排队。</p>
      <el-alert v-if="upgradeError" :title="upgradeError" type="error" :closable="false" />
      <el-checkbox-group v-model="dispatchAgents"><div v-for="host in upgradeTargets" :key="host.agent_id"><el-checkbox :value="host.agent_id">{{ host.hostname }} · {{ host.agent_id }} · {{ host.agent_version }} · {{ Number(host.status) === 1 ? '在线' : '离线／待激活' }}</el-checkbox></div></el-checkbox-group>
      <el-pagination v-model:current-page="targetPage" :total="targetTotal" :page-size="20" layout="total, prev, pager, next" @current-change="loadTargets" />
      <p>已选择 {{ dispatchAgents.length }} 台（包含其他页选择）</p>
      <template #footer>
        <el-button @click="dispatchDlg = false">取消</el-button>
        <el-button type="primary" :loading="busy" @click="doDispatch">下发</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="channelDlg" :title="channelForm.id ? '编辑告警通道' : '新增告警通道'" width="500px">
      <el-form label-width="96px">
        <el-form-item label="名称" required><el-input v-model="channelForm.name" maxlength="64" /></el-form-item>
        <el-form-item label="Webhook" required><el-input v-model="channelForm.webhookUrl" placeholder="https://example.com/webhook" /></el-form-item>
        <el-form-item label="最低等级">
          <el-select v-model="channelForm.minSeverity" style="width:160px">
            <el-option label="低危及以上" :value="1" />
            <el-option label="中危及以上" :value="2" />
            <el-option label="高危及以上" :value="3" />
            <el-option label="严重" :value="4" />
          </el-select>
        </el-form-item>
        <el-form-item label="启用"><el-switch v-model="channelForm.enabled" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="channelDlg = false">取消</el-button>
        <el-button type="primary" :loading="channelBusy" @click="saveChannel">保存</el-button>
      </template>
    </el-dialog>

    <!-- 新增用户弹窗 -->
    <el-dialog v-model="userCreateDlg" title="新增管理端账号" width="460px">
      <el-form label-width="80px">
        <el-form-item label="用户名" required>
          <el-input v-model="userCreateForm.username" placeholder="3-32 位字母/数字/下划线" maxlength="32" />
        </el-form-item>
        <el-form-item label="初始密码" required>
          <el-input v-model="userCreateForm.password" type="password" show-password placeholder="不少于 8 位" />
        </el-form-item>
        <el-form-item label="真实姓名">
          <el-input v-model="userCreateForm.realName" placeholder="姓名或昵称" maxlength="64" />
        </el-form-item>
        <el-form-item label="分配角色" required>
          <el-select v-model="userCreateForm.roleName" style="width:100%">
            <el-option label="系统管理员 (admin)" value="admin" />
            <el-option label="安全运维员 (operator)" value="operator" />
            <el-option label="只读审计员 (viewer)" value="viewer" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="userCreateDlg = false">取消</el-button>
        <el-button type="primary" :loading="userBusy" @click="saveCreateUser">确认创建</el-button>
      </template>
    </el-dialog>

    <!-- 编辑用户弹窗 -->
    <el-dialog v-model="userEditDlg" title="编辑账号" width="460px">
      <el-form label-width="80px">
        <el-form-item label="用户名">
          <el-input :value="userEditForm.username" disabled />
        </el-form-item>
        <el-form-item label="真实姓名">
          <el-input v-model="userEditForm.realName" placeholder="姓名或昵称" maxlength="64" />
        </el-form-item>
        <el-form-item label="分配角色" required>
          <el-select v-model="userEditForm.roleName" style="width:100%">
            <el-option label="系统管理员 (admin)" value="admin" />
            <el-option label="安全运维员 (operator)" value="operator" />
            <el-option label="只读审计员 (viewer)" value="viewer" />
          </el-select>
        </el-form-item>
        <el-form-item label="启用状态">
          <el-switch v-model="userEditForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="userEditDlg = false">取消</el-button>
        <el-button type="primary" :loading="userBusy" @click="saveEditUser">保存修改</el-button>
      </template>
    </el-dialog>

    <!-- 重置密码弹窗 -->
    <el-dialog v-model="userResetPwdDlg" title="重置用户密码" width="460px">
      <el-form label-width="80px">
        <el-form-item label="用户名">
          <el-input :value="userResetPwdForm.username" disabled />
        </el-form-item>
        <el-form-item label="新密码" required>
          <el-input v-model="userResetPwdForm.password" type="password" show-password placeholder="不少于 8 位" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="userResetPwdDlg = false">取消</el-button>
        <el-button type="primary" :loading="userBusy" @click="saveResetPassword">重置密码</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import ReportPanel from '../components/ReportPanel.vue'
import EvidencePanel from '../components/EvidencePanel.vue'
import ClusterPanel from '../components/ClusterPanel.vue'
import ComponentHealthPanel from '../components/ComponentHealthPanel.vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { fetchUpgradeTargets, fetchUpgradeBatches, fetchUpgradeBatch, getUser, fetchUpgradePackages, uploadUpgradePackage, dispatchUpgrade, fetchAgentVersions, fetchAuditLogs, fetchNotifyChannels, createNotifyChannel, updateNotifyChannel, removeNotifyChannel, fetchWafStatus, updateWafConfig, fetchUsers, createUser, updateUser, resetUserPassword } from '../api'

const busy = ref(false)
const canUpgrade = ['admin', 'operator'].includes(getUser()?.role)
const isAdmin = getUser()?.role === 'admin'
const tab = ref('upgrade')

/* ---- 升级 ---- */
const packages = ref([])
const versions = ref([])
const upVersion = ref('')
const upPlatform = ref('linux-amd64')
const pkgFile = ref(null)
const dispatchDlg = ref(false)
const dispatchPkg = ref(null)
const dispatchAgents = ref([])
const upgradeTargets = ref([]), targetPage = ref(1), targetTotal = ref(0)
const upgradeBatches = ref([]), batchPage = ref(1), batchTotal = ref(0)
const batchId = ref(''), batchRows = ref([]), batchTargetPage = ref(1), batchTargetTotal = ref(0)
const upgradeError = ref('')
const commandStatus = status => ({ 0:'排队中', 1:'已发送，待回执', 2:'Agent 已接收', 3:'执行中，待最终回执', 4:'收到完成回执', 5:'执行失败', 6:'回执超时' }[status] || '状态未知')
async function loadTargets() {
  try { const r = await fetchUpgradeTargets(dispatchPkg.value.id, targetPage.value); upgradeTargets.value = r.list; targetTotal.value = r.total; upgradeError.value = '' }
  catch(e) { upgradeTargets.value = []; upgradeError.value = e.message || '目标加载失败' }
}
async function loadBatches() {
  try { const r = await fetchUpgradeBatches(batchPage.value); upgradeBatches.value = r.list; batchTotal.value = r.total; upgradeError.value = '' }
  catch(e) { upgradeError.value = e.message || '批次加载失败' }
}
async function loadBatch() {
  try { const r = await fetchUpgradeBatch(batchId.value, batchTargetPage.value); batchRows.value = r.list; batchTargetTotal.value = r.total; upgradeError.value = '' }
  catch(e) { batchRows.value = []; upgradeError.value = e.message || '逐机结果加载失败' }
}
function openBatch(id) { batchId.value = id; batchTargetPage.value = 1; loadBatch() }

const msg = (t, type = 'success') => ElMessage({ message: t, type, duration: 2200 })

async function loadUpgrade() {
  const [pkgs, vers] = await Promise.all([fetchUpgradePackages(), fetchAgentVersions()])
  await loadBatches()
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
  dispatchAgents.value = []; targetPage.value = 1; loadTargets()
  dispatchDlg.value = true
}

async function doDispatch() {
  const agentIds = dispatchAgents.value
  if (!agentIds.length) return msg('请选择目标主机', 'warning')
  busy.value = true
  try {
    const r = await dispatchUpgrade(dispatchPkg.value.id, agentIds)
    msg(`已向 ${r?.dispatched ?? agentIds.length} 台主机下发升级指令`)
    dispatchDlg.value = false
    await loadBatches(); openBatch(r.batchId)
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

/* ---- 告警通道 ---- */
const channels = ref([])
const channelDlg = ref(false)
const channelBusy = ref(false)
const channelForm = ref({ id: null, name: '', webhookUrl: '', minSeverity: 3, enabled: true })
const severityName = (value) => ({ 1: '低危及以上', 2: '中危及以上', 3: '高危及以上', 4: '严重' }[Number(value)] || '高危及以上')

/* ---- WAF ---- */
const wafStatus = ref({})
const wafForm = ref({ enabled: true, mode: 'DetectionOnly', threshold: 5, paranoiaLevel: 1 })
const wafSaving = ref(false)

async function loadWafStatus() {
  if (isAdmin) {
    try {
      const data = await fetchWafStatus()
      wafStatus.value = data || {}
      wafForm.value = {
        enabled: data?.enabled !== false,
        mode: data?.mode || 'DetectionOnly',
        threshold: data?.threshold || 5,
        paranoiaLevel: data?.paranoiaLevel || 1,
      }
    } catch {
      // ignore
    }
  }
}

async function saveWafConfig() {
  wafSaving.value = true
  try {
    await updateWafConfig(wafForm.value)
    msg('WAF 配置已保存')
    await loadWafStatus()
  } catch (e) {
    msg(e?.message || 'WAF 配置保存失败', 'error')
  } finally {
    wafSaving.value = false
  }
}

async function loadChannels() {
  if (isAdmin) channels.value = await fetchNotifyChannels()
}

function openChannel(row) {
  channelForm.value = row
    ? { id: row.id, name: row.name, webhookUrl: row.webhook_url, minSeverity: Number(row.min_severity), enabled: !!row.enabled }
    : { id: null, name: '', webhookUrl: '', minSeverity: 3, enabled: true }
  channelDlg.value = true
}

async function saveChannel() {
  if (!channelForm.value.name.trim() || !channelForm.value.webhookUrl.trim()) return msg('请填写通道名称和 Webhook 地址', 'warning')
  channelBusy.value = true
  try {
    const form = { ...channelForm.value }
    if (form.id) await updateNotifyChannel(form.id, form)
    else await createNotifyChannel(form)
    channelDlg.value = false
    await loadChannels()
    msg('告警通道已保存')
  } catch (e) {
    msg(e?.message || '保存失败', 'error')
  } finally {
    channelBusy.value = false
  }
}

async function deleteChannel(row) {
  try {
    await ElMessageBox.confirm(`删除告警通道“${row.name}”后将停止后续投递，是否继续？`, '删除告警通道', { type: 'warning' })
    await removeNotifyChannel(row.id)
    await loadChannels()
    msg('告警通道已删除')
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') msg(e?.message || '删除失败', 'error')
  }
}

/* ---- 账号管理 (G10) ---- */
const userList = ref([])
const userLoading = ref(false)
const userBusy = ref(false)
const userCreateDlg = ref(false)
const userCreateForm = ref({ username: '', password: '', realName: '', roleName: 'operator' })
const userEditDlg = ref(false)
const userEditForm = ref({ id: null, username: '', realName: '', roleName: 'operator', enabled: true })
const userResetPwdDlg = ref(false)
const userResetPwdForm = ref({ id: null, username: '', password: '' })

async function loadUsers() {
  if (!isAdmin) return
  userLoading.value = true
  try {
    userList.value = await fetchUsers()
  } catch (e) {
    msg(e?.message || '加载用户列表失败', 'error')
  } finally {
    userLoading.value = false
  }
}

function openCreateUser() {
  userCreateForm.value = { username: '', password: '', realName: '', roleName: 'operator' }
  userCreateDlg.value = true
}

async function saveCreateUser() {
  if (!userCreateForm.value.username.trim()) return msg('请输入用户名', 'warning')
  if (!userCreateForm.value.password || userCreateForm.value.password.length < 8) return msg('密码长度不能少于8位', 'warning')
  userBusy.value = true
  try {
    await createUser(userCreateForm.value)
    userCreateDlg.value = false
    await loadUsers()
    msg('账号创建成功')
  } catch (e) {
    msg(e?.message || '创建账号失败', 'error')
  } finally {
    userBusy.value = false
  }
}

function openEditUser(row) {
  userEditForm.value = {
    id: row.id,
    username: row.username,
    realName: row.real_name || '',
    roleName: row.role_name,
    enabled: Number(row.status) === 1
  }
  userEditDlg.value = true
}

async function saveEditUser() {
  userBusy.value = true
  try {
    await updateUser(userEditForm.value.id, userEditForm.value)
    userEditDlg.value = false
    await loadUsers()
    msg('账号修改成功')
  } catch (e) {
    msg(e?.message || '修改账号失败', 'error')
  } finally {
    userBusy.value = false
  }
}

function openResetPassword(row) {
  userResetPwdForm.value = { id: row.id, username: row.username, password: '' }
  userResetPwdDlg.value = true
}

async function saveResetPassword() {
  if (!userResetPwdForm.value.password || userResetPwdForm.value.password.length < 8) return msg('新密码不能少于8位', 'warning')
  userBusy.value = true
  try {
    await resetUserPassword(userResetPwdForm.value.id, { password: userResetPwdForm.value.password })
    userResetPwdDlg.value = false
    msg('密码已重置，该用户现有会话已被强制注销')
  } catch (e) {
    msg(e?.message || '重置密码失败', 'error')
  } finally {
    userBusy.value = false
  }
}

onMounted(() => { loadUpgrade(); if (isAdmin) { loadAudit(); loadChannels(); loadWafStatus(); loadUsers() } })
</script>

<style scoped>
.row { flex-wrap: wrap }
.hint { font-size: 12px; color: #94a3b8 }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px }
</style>

<template>
  <div>
    <div class="grid-4">
      <div class="prot-card" v-for="p in cards" :key="p.title">
        <div class="hd"><b>{{ p.title }}</b></div>
        <p>{{ p.desc }}</p>
      </div>
    </div>
    <div class="grid-2eq">
      <div class="panel"><h4>勒索诱饵防护配置</h4>
        <el-form label-width="90px" style="max-width:420px" v-loading="loading">
          <el-form-item label="响应级别">
            <el-radio-group v-model="decoyLevel" :disabled="!ruleLoaded">
              <el-radio value="alert_only">仅告警</el-radio><el-radio value="kill">结束进程（仅 Windows 可信归因）</el-radio><el-radio value="kill_and_isolate">隔离主机</el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="投放目录">
            <el-input v-model="decoyDirs" placeholder="/home/*, /srv, /opt" />
          </el-form-item>
          <el-form-item label="排除进程">
            <el-input v-model="decoyExcludes" placeholder="备份/杀毒进程路径，逗号分隔" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" size="small" :disabled="!ruleLoaded" @click="saveRule">保存配置</el-button>
          </el-form-item>
        </el-form>
        <p style="font-size:12px;color:#94a3b8">Linux 不支持可信写入者归因，勒索自动结束进程能力已禁用：选择 kill 时仅告警，选择 kill_and_isolate 时仅按策略隔离，不会终止进程。Windows 通过内核文件事件关联写入进程；无法核实、存在多个写入者或采集不可用时跳过进程终止，主机隔离仍独立执行。告警中心可查看归因证据。</p>
      </div>
      <div class="panel"><h4>最近检测与响应记录</h4>
        <el-empty v-if="!blocks.length" description="暂无检测记录" :image-size="60" />
        <div v-for="b in blocks" :key="b.id" class="evt-item">
          <span class="t">{{ b.time }}</span>
          <div style="flex:1">
            <el-tag size="small" :type="sevType(b.severity)">{{ sevLabel(b.severity) }}</el-tag> {{ b.title }} <el-tag v-if="b.legacySeverity" size="small" type="info">历史等级</el-tag><br />
            <span style="color:#94a3b8;font-size:11px">{{ b.hostname || b.agent_id }} · </span>
            <el-tag size="small" effect="plain" type="info">{{ actionLabel(b.action_taken) }}</el-tag>
          </div>
        </div>
      </div>
    </div>
    <div class="protection-settings" v-loading="loading">
      <section class="protection-setting"><h4>关键文件完整性防护</h4>
        <el-form v-if="fileRule" label-width="100px" :disabled="fileSaving">
          <el-form-item label="启用"><el-switch v-model="fileForm.enabled" /></el-form-item>
          <el-form-item label="响应方式"><el-radio-group v-model="fileForm.restore"><el-radio :value="false">仅告警</el-radio><el-radio :value="true">自动恢复</el-radio></el-radio-group></el-form-item>
          <el-form-item label="文件路径"><el-input v-model="fileForm.paths" type="textarea" :rows="5" placeholder="/etc/passwd" /></el-form-item>
          <el-form-item><el-button type="primary" :icon="Check" :loading="fileSaving" @click="saveFileRule">保存配置</el-button></el-form-item>
        </el-form>
        <el-empty v-else description="文件规则未加载" :image-size="48" />
      </section>
      <section class="protection-setting"><h4>SSH 登录防护</h4>
        <el-form v-if="loginRule" label-width="110px" :disabled="loginSaving">
          <el-form-item label="启用"><el-switch v-model="loginForm.enabled" /></el-form-item>
          <el-form-item label="响应方式"><el-radio-group v-model="loginForm.block"><el-radio :value="false">仅告警</el-radio><el-radio :value="true">限时封禁</el-radio></el-radio-group></el-form-item>
          <div class="protection-numbers">
            <el-form-item label="失败次数"><el-input-number v-model="loginForm.threshold" :min="2" :max="100" :step="1" :precision="0" controls-position="right" /></el-form-item>
            <el-form-item label="窗口（秒）"><el-input-number v-model="loginForm.window" :min="1" :max="3600" :precision="0" controls-position="right" /></el-form-item>
            <el-form-item label="告警间隔（秒）"><el-input-number v-model="loginForm.cooldown" :min="1" :max="86400" :precision="0" controls-position="right" /></el-form-item>
            <el-form-item label="封禁（秒）"><el-input-number :key="loginForm.block" v-model="loginForm.duration" :min="5" :max="3600" :precision="0" :disabled="!loginForm.block" controls-position="right" /></el-form-item>
          </div>
          <el-form-item label="SSH 端口"><el-input v-model="loginForm.ports" placeholder="22" /></el-form-item>
          <el-form-item label="信任来源"><el-input v-model="loginForm.trusted" type="textarea" :rows="2" placeholder="192.0.2.10, 198.51.100.0/24" /></el-form-item>
          <el-form-item label="排除账户"><el-input v-model="loginForm.users" placeholder="backup, deploy" /></el-form-item>
          <el-form-item label="异常时段告警"><el-switch v-model="loginForm.offHours" /></el-form-item>
          <div v-if="loginForm.offHours" class="protection-numbers">
            <el-form-item label="允许起始时"><el-input-number v-model="loginForm.start" :min="0" :max="23" :precision="0" controls-position="right" /></el-form-item>
            <el-form-item label="允许结束时"><el-input-number v-model="loginForm.end" :min="0" :max="24" :precision="0" controls-position="right" /></el-form-item>
          </div>
          <el-form-item v-if="loginForm.offHours" label="时区"><el-select v-model="loginForm.timezone" filterable allow-create default-first-option><el-option v-for="zone in ['Local', 'UTC', 'Asia/Shanghai']" :key="zone" :label="zone" :value="zone" /></el-select></el-form-item>
          <el-form-item><el-button type="primary" :icon="Check" :loading="loginSaving" @click="saveLoginRule">保存配置</el-button></el-form-item>
        </el-form>
        <el-empty v-else description="登录规则未加载" :image-size="48" />
      </section>
    </div>
    <WindowsLoginProtection :rule="windowsLoginRule" />
    <FileWatchStatus />
    <div class="panel" style="margin-top:16px"><h4>进程路径／命令行匹配规则</h4>
      <p>启动或策略更新时对已有进程仅告警，随后每 2 秒枚举新进程并按规则响应。当前规则不是完整 EDR：短生命周期进程可能漏检，仅按程序名的规则可被改名绕过；不提供通用提权、注入或凭据窃取检测。Linux 可由管理员另行启用 audit 执行日志补充短命进程线索，该来源只告警，不使用历史 PID 终止进程；默认未启用。</p>
      <el-table v-if="processRules.length" :data="processRules" size="small" v-loading="loading">
        <el-table-column prop="name" label="规则" min-width="150" />
        <el-table-column label="匹配条件" min-width="260" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.match?.exe_regex || row.match?.cmdline_regex || '—' }}</span></template>
        </el-table-column>
        <el-table-column label="处置" width="120"><template #default="{ row }"><el-tag size="small" :type="(row.actions || []).includes('kill') ? 'danger' : 'info'">{{ (row.actions || []).includes('kill') ? '结束进程树' : '仅告警' }}</el-tag></template></el-table-column>
        <el-table-column label="启用" width="90"><template #default="{ row }"><el-switch v-model="row.enabled" @change="toggleProcessRule(row)" /></template></el-table-column>
      </el-table>
      <el-empty v-else description="暂无进程匹配规则" :image-size="48" />
    </div>

    <div class="panel" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
        <h4 style="margin:0">自动化响应规则（告警联动处置）</h4>
        <div style="display:flex;gap:8px">
          <el-button v-if="canEditResponse" type="primary" size="small" @click="openResponseRuleDlg()">新建响应规则</el-button>
          <el-button size="small" @click="loadResponseRules">刷新</el-button>
        </div>
      </div>
      <p style="font-size:12px;color:#94a3b8">
        当产生匹配告警时自动触发处置动作（如隔离主机、阻断IP、查杀进程）。为防止越权与误处置，高危处置规则需经管理员审批 (Approved) 后方可生效执行。
      </p>
      <el-table v-if="responseRules.length" :data="responseRules" size="small" v-loading="loadingResponse">
        <el-table-column prop="name" label="规则名称" min-width="150" />
        <el-table-column label="触发事件" width="130">
          <template #default="{ row }"><el-tag size="small">{{ eventTypeName(row.alert_type) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="最低等级" width="110">
          <template #default="{ row }">{{ sevNumLabel(row.min_severity) }}</template>
        </el-table-column>
        <el-table-column label="处置动作" width="130">
          <template #default="{ row }">
            <el-tag size="small" :type="actionType(row.action)">{{ actionName(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="超时自动撤销" width="120">
          <template #default="{ row }">{{ row.timeout_sec ? `${row.timeout_sec} 秒` : '无' }}</template>
        </el-table-column>
        <el-table-column label="审批状态" width="120">
          <template #default="{ row }">
            <el-tag size="small" :type="row.approved_at ? 'success' : 'warning'">
              {{ row.approved_at ? '已审批' : '待管理员审批' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <el-switch v-model="row.enabled" :disabled="!canEditResponse" @change="toggleResponseRule(row)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="160">
          <template #default="{ row }">
            <el-button v-if="isAdmin && !row.approved_at" link type="success" size="small" @click="approveRule(row)">批准</el-button>
            <el-button v-if="canEditResponse" link type="primary" size="small" @click="openResponseRuleDlg(row)">编辑</el-button>
            <el-button v-if="isAdmin" link type="danger" size="small" @click="delResponseRule(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <el-empty v-else description="暂无自动化响应规则" :image-size="48" />
    </div>

    <!-- 响应规则编辑弹窗 -->
    <el-dialog v-model="responseRuleDlg" :title="responseForm.id ? '编辑自动化响应规则' : '新建自动化响应规则'" width="560px">
      <el-form label-width="120px">
        <el-form-item label="规则名称" required>
          <el-input v-model="responseForm.name" placeholder="例如：反弹Shell主机网络自动隔离" />
        </el-form-item>
        <el-form-item label="触发事件类型" required>
          <el-select v-model="responseForm.alertType" style="width:100%">
            <el-option value="all" label="全部告警类型 (all)" />
            <el-option value="reverse_shell" label="反弹 Shell (reverse_shell)" />
            <el-option value="virus" label="恶意文件 / 木马病毒 (virus)" />
            <el-option value="brute_force" label="登录暴力破解 (brute_force)" />
            <el-option value="web_attack" label="Web 攻击检测 (web_attack)" />
            <el-option value="priv_esc" label="特权提升 (priv_esc)" />
            <el-option value="file_tamper" label="关键文件篡改 (file_tamper)" />
          </el-select>
        </el-form-item>
        <el-form-item label="最低触发等级">
          <el-select v-model="responseForm.minSeverity" style="width:100%">
            <el-option :value="1" label="1 - 低危及以上 (Low+)" />
            <el-option :value="2" label="2 - 中危及以上 (Medium+)" />
            <el-option :value="3" label="3 - 高危及以上 (High+)" />
            <el-option :value="4" label="4 - 严重 (Critical)" />
            <el-option :value="5" label="5 - 致命 (Critical Level 5)" />
          </el-select>
        </el-form-item>
        <el-form-item label="响应处置动作" required>
          <el-select v-model="responseForm.action" style="width:100%">
            <el-option value="isolate_host" label="隔离主机网络 (isolate_host)" />
            <el-option value="restore_isolation" label="解除主机网络隔离 (restore_isolation)" />
            <el-option value="block_ip" label="Linux 防火墙封禁源 IP (block_ip)" />
            <el-option value="kill_process" label="查杀目标进程树 (kill_process)" />
          </el-select>
        </el-form-item>
        <el-form-item label="执行位置">
          <el-radio-group v-model="responseForm.location">
            <el-radio value="local">告警所在主机 Agent (local)</el-radio>
            <el-radio value="agent">指定目标主机 Agent (agent)</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="responseForm.location === 'agent'" label="目标主机 ID">
          <el-input v-model="responseForm.targetAgentId" placeholder="例如：agt-xxxx" />
        </el-form-item>
        <el-form-item label="匹配主机标签">
          <el-input v-model="responseForm.hostTag" placeholder="可选，留空则匹配全部主机" />
        </el-form-item>
        <el-form-item label="超时自动撤销">
          <el-input-number v-model="responseForm.timeoutSec" :min="0" :max="86400" controls-position="right" />
          <span style="margin-left:8px;font-size:12px;color:#94a3b8">秒（0 表示不撤销，仅封禁/隔离支持）</span>
        </el-form-item>
        <el-form-item label="启用规则">
          <el-switch v-model="responseForm.enabled" />
        </el-form-item>
        <el-form-item label="管理员授权">
          <el-checkbox v-model="responseForm.requireAdminAuth">需要管理员审批后方可生效执行</el-checkbox>
        </el-form-item>
        <el-form-item label="规则说明">
          <el-input v-model="responseForm.description" type="textarea" :rows="2" placeholder="规则用途描述" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="responseRuleDlg = false">取消</el-button>
        <el-button type="primary" :loading="responseBusy" @click="saveResponseRule">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import WindowsLoginProtection from '../components/WindowsLoginProtection.vue'
import FileWatchStatus from '../components/FileWatchStatus.vue'
import { ElMessage } from 'element-plus'
import { Check } from '@element-plus/icons-vue'
import { fetchProtect, fetchProtectRules, updateProtectRule, fetchResponseRules, createResponseRule, updateResponseRule, deleteResponseRule, approveResponseRule, getUser } from '../api'
import { sevType, sevLabel, actionLabel } from '../utils/format'
import { fileProtectionPayload, loginProtectionPayload } from '../utils/protection'

const cards = ref([])
const blocks = ref([])
const loading = ref(false)
const ruleLoaded = ref(false)
const decoyLevel = ref('kill_and_isolate')
const decoyDirs = ref('')
const decoyExcludes = ref('')
const processRules = ref([])
const fileRule = ref(null)
const loginRule = ref(null)
const windowsLoginRule = ref(null)
const fileSaving = ref(false)
const loginSaving = ref(false)
const fileForm = reactive({ enabled: false, restore: false, paths: '' })
const loginForm = reactive({ enabled: false, block: false, threshold: 5, window: 300, cooldown: 300, duration: 600, ports: '22', trusted: '', users: '', offHours: false, start: 8, end: 20, timezone: 'Local' })

// 响应级别 ↔ PR-0010 actions 映射（docs/05 §2.4）
const levelActions = {
  alert_only: ['alert'],
  kill: ['kill', 'alert'],
  kill_and_isolate: ['kill', 'isolate_host', 'alert'],
}
const actionsLevel = (actions) => {
  const a = actions || []
  if (a.includes('isolate_host')) return 'kill_and_isolate'
  if (a.includes('kill')) return 'kill'
  return 'alert_only'
}

const msg = (t, type = 'success') => ElMessage({ message: t, type, duration: 1800 })

// 加载 PR-0010 内置规则 → 表单
onMounted(async () => {
  loading.value = true
  try {
    const [res, rules] = await Promise.all([fetchProtect(), fetchProtectRules()])
    cards.value = res.cards
    blocks.value = res.blocks
    const decoy = (rules || []).find((r) => r.rule_id === 'PR-0010')
    processRules.value = (rules || []).filter((r) => r.type === 'process')
    fileRule.value = (rules || []).find((r) => r.type === 'file_integrity') || null
    loginRule.value = (rules || []).find((r) => r.type === 'login' && !r.match?.windows_contract) || null
    windowsLoginRule.value = (rules || []).find(r => r.type === 'login' && r.match?.windows_contract === 1) || null
    if (fileRule.value) Object.assign(fileForm, { enabled: fileRule.value.enabled, restore: (fileRule.value.actions || []).includes('restore'), paths: (fileRule.value.match?.paths || []).join('\n') })
    if (loginRule.value) {
      const r = loginRule.value, m = r.match || {}
      Object.assign(loginForm, { enabled: r.enabled, block: (r.actions || []).includes('block_ip'), threshold: m.failure_threshold ?? 5, window: m.window_sec ?? 300, cooldown: m.cooldown_sec ?? 300, duration: m.block_duration_sec ?? 600, ports: (m.ssh_ports || [22]).join(', '), trusted: (m.trusted_ips || []).join('\n'), users: (m.user_exclude || []).join(', '), offHours: m.off_hours_enabled ?? false, start: m.allowed_start_hour ?? 8, end: m.allowed_end_hour ?? 20, timezone: m.timezone || 'Local' })
    }
    if (decoy) {
      decoyLevel.value = actionsLevel(decoy.actions)
      decoyDirs.value = (decoy.match?.dirs || []).join(', ')
      decoyExcludes.value = (decoy.match?.exclude_exes || []).join(', ')
      ruleLoaded.value = true
    }
    loadResponseRules()
  } catch (e) {
    msg(e.message || '防护配置加载失败', 'error')
  } finally {
    loading.value = false
  }
})

// 保存：match（dirs/count_per_dir/exclude_exes）+ actions（响应级别）
const saveRule = async () => {
  const split = (s) => s.split(/[,，]/).map((x) => x.trim()).filter(Boolean)
  try {
    await updateProtectRule('PR-0010', {
      match: {
        dirs: split(decoyDirs.value),
        count_per_dir: 4,
        exclude_exes: split(decoyExcludes.value),
      },
      actions: levelActions[decoyLevel.value] || ['alert'],
    })
    msg('诱饵防护配置已保存')
  } catch (e) {
    msg(e.message || '保存失败', 'error')
  }
}

const toggleProcessRule = async (row) => {
  try {
    await updateProtectRule(row.rule_id, { enabled: row.enabled })
    msg(`${row.name}已${row.enabled ? '开启' : '关闭'}`)
  } catch (e) {
    row.enabled = !row.enabled
    msg(e.message || '保存失败', 'error')
  }
}

const saveFileRule = async () => {
  if (!fileRule.value || fileSaving.value) return
  fileSaving.value = true
  try {
    const payload = fileProtectionPayload(fileRule.value, fileForm)
    await updateProtectRule(fileRule.value.rule_id, payload)
    Object.assign(fileRule.value, payload)
    msg('文件完整性防护配置已保存')
  } catch (e) { msg(e.message || '保存失败', 'error') }
  finally { fileSaving.value = false }
}

const saveLoginRule = async () => {
  if (!loginRule.value || loginSaving.value) return
  loginSaving.value = true
  try {
    const payload = loginProtectionPayload(loginRule.value, loginForm)
    await updateProtectRule(loginRule.value.rule_id, payload)
    Object.assign(loginRule.value, payload)
    msg('SSH 登录防护配置已保存')
  } catch (e) { msg(e.message || '保存失败', 'error') }
  finally { loginSaving.value = false }
}

/* ---- 自动化响应规则管理 ---- */
const isAdmin = getUser()?.role === 'admin'
const canEditResponse = ['admin', 'operator'].includes(getUser()?.role)
const responseRules = ref([])
const loadingResponse = ref(false)
const responseRuleDlg = ref(false)
const responseBusy = ref(false)
const responseForm = ref({
  id: null,
  name: '',
  alertType: 'all',
  minSeverity: 3,
  action: 'isolate_host',
  location: 'local',
  targetAgentId: '',
  hostTag: '',
  timeoutSec: 0,
  enabled: true,
  requireAdminAuth: false,
  description: ''
})

const sevNumLabel = s => ({ 1: '低危及以上', 2: '中危及以上', 3: '高危及以上', 4: '高危+', 5: '严重' }[s] || `${s} 级及以上`)
const actionName = a => ({ isolate_host: '隔离主机网络', restore_isolation: '解除主机网络隔离', block_ip: 'Linux 防火墙封禁 IP', kill_process: '查杀进程树' }[a] || a)
const actionType = a => ({ isolate_host: 'danger', kill_process: 'danger', block_ip: 'warning', restore_isolation: 'success' }[a] || 'info')
const eventTypeName = t => ({
  all: '全部告警',
  reverse_shell: '反弹 Shell',
  virus: '恶意样本/病毒',
  brute_force: '登录暴力破解',
  web_attack: 'Web 攻击',
  priv_esc: '特权提升',
  file_tamper: '文件篡改'
}[t] || t || '全部告警')

async function loadResponseRules() {
  loadingResponse.value = true
  try {
    responseRules.value = (await fetchResponseRules()) || []
  } catch (e) {
    msg(e?.message || '自动响应规则加载失败', 'error')
  } finally {
    loadingResponse.value = false
  }
}

function openResponseRuleDlg(row) {
  if (row) {
    responseForm.value = {
      id: row.id,
      name: row.name,
      alertType: row.alert_type || 'all',
      minSeverity: row.min_severity || 3,
      action: row.action || 'isolate_host',
      location: row.location || 'local',
      targetAgentId: row.target_agent_id || '',
      hostTag: row.host_tag || '',
      timeoutSec: row.timeout_sec || 0,
      enabled: row.enabled !== false,
      requireAdminAuth: !!row.require_admin_auth,
      description: row.description || ''
    }
  } else {
    responseForm.value = {
      id: null,
      name: '',
      alertType: 'all',
      minSeverity: 3,
      action: 'isolate_host',
      location: 'local',
      targetAgentId: '',
      hostTag: '',
      timeoutSec: 0,
      enabled: true,
      requireAdminAuth: false,
      description: ''
    }
  }
  responseRuleDlg.value = true
}

async function saveResponseRule() {
  if (!responseForm.value.name?.trim()) return msg('请填写规则名称', 'warning')
  responseBusy.value = true
  try {
    const payload = { ...responseForm.value }
    if (payload.id) {
      await updateResponseRule(payload.id, payload)
      msg('响应规则已更新')
    } else {
      await createResponseRule(payload)
      msg('响应规则已创建')
    }
    responseRuleDlg.value = false
    await loadResponseRules()
  } catch (e) {
    msg(e?.message || '保存失败', 'error')
  } finally {
    responseBusy.value = false
  }
}

async function toggleResponseRule(row) {
  try {
    await updateResponseRule(row.id, { enabled: row.enabled })
    msg(`规则已${row.enabled ? '启用' : '停用'}`)
  } catch (e) {
    row.enabled = !row.enabled
    msg(e?.message || '状态切换失败', 'error')
  }
}

async function approveRule(row) {
  try {
    await approveResponseRule(row.id)
    msg('规则已批准生效')
    await loadResponseRules()
  } catch (e) {
    msg(e?.message || '审批失败', 'error')
  }
}

async function delResponseRule(row) {
  try {
    await deleteResponseRule(row.id)
    msg('规则已删除')
    await loadResponseRules()
  } catch (e) {
    msg(e?.message || '删除失败', 'error')
  }
}
</script>

<style scoped>
.protection-settings { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr); gap: 24px; margin-top: 20px; border-top: 1px solid #e4e7ed; }
.protection-setting { min-width: 0; }
.protection-setting h4 { font-size: 15px; margin: 20px 0 16px; }
.protection-numbers { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 12px; }
.protection-setting :deep(.el-input-number), .protection-setting :deep(.el-select) { width: 100%; min-width: 0; }
@media (max-width: 1100px) { .protection-settings { grid-template-columns: minmax(0, 1fr); gap: 0; } }
@media (max-width: 580px) { .protection-numbers { grid-template-columns: minmax(0, 1fr); } }
</style>

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
              <el-radio value="alert_only">仅告警</el-radio><el-radio value="kill">结束进程</el-radio><el-radio value="kill_and_isolate">隔离主机</el-radio>
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
        <p style="font-size:12px;color:#94a3b8">默认 kill_and_isolate：诱饵被篡改或检测到批量加密行为时，本地立即结束进程并隔离主机（仅放行管控通道），同步上报 critical 事件。</p>
      </div>
      <div class="panel"><h4>最近拦截记录</h4>
        <el-empty v-if="!blocks.length" description="暂无拦截记录" :image-size="60" />
        <div v-for="b in blocks" :key="b.id" class="evt-item">
          <span class="t">{{ b.time }}</span>
          <div style="flex:1">
            <el-tag size="small" :type="sevType(b.severity)">{{ sevLabel(b.severity) }}</el-tag> {{ b.title }}<br />
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
    <div class="panel" style="margin-top:16px"><h4>EDR 进程行为规则</h4>
      <el-table v-if="processRules.length" :data="processRules" size="small" v-loading="loading">
        <el-table-column prop="name" label="规则" min-width="150" />
        <el-table-column label="匹配条件" min-width="260" show-overflow-tooltip>
          <template #default="{ row }"><span class="mono">{{ row.match?.exe_regex || row.match?.cmdline_regex || '—' }}</span></template>
        </el-table-column>
        <el-table-column label="处置" width="120"><template #default="{ row }"><el-tag size="small" :type="(row.actions || []).includes('kill') ? 'danger' : 'info'">{{ (row.actions || []).includes('kill') ? '结束进程树' : '仅告警' }}</el-tag></template></el-table-column>
        <el-table-column label="启用" width="90"><template #default="{ row }"><el-switch v-model="row.enabled" @change="toggleProcessRule(row)" /></template></el-table-column>
      </el-table>
      <el-empty v-else description="暂无 EDR 进程规则" :image-size="48" />
    </div>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Check } from '@element-plus/icons-vue'
import { fetchProtect, fetchProtectRules, updateProtectRule } from '../api'
import { sevType, sevLabel } from '../utils/format'
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
const actionLabel = action => ({ alert_only: '仅告警', restored: '已恢复文件', restore_failed: '恢复失败', blocked_ip: '已封禁来源', block_failed: '封禁失败', killed: '已结束进程', isolated: '已隔离主机' }[action] || action || '仅告警')

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
    loginRule.value = (rules || []).find((r) => r.type === 'login') || null
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

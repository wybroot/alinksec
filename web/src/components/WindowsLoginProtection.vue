<template>
  <section class="windows-login panel" data-testid="windows-login">
    <h4>Windows 登录防护</h4>
    <p class="help">检测 Security 日志中的网络登录（类型 3）和远程交互登录（类型 10）。首次启用从当前日志开始，每 5 秒查询一次。</p>
    <el-form v-if="rule" label-width="112px" :disabled="saving || readOnly" class="settings">
      <el-form-item label="启用"><el-switch v-model="form.enabled" /></el-form-item>
      <el-form-item label="响应方式"><el-radio-group v-model="form.block"><el-radio :value="false">仅告警</el-radio><el-radio :value="true">限时封禁来源</el-radio></el-radio-group></el-form-item>
      <el-form-item label="登录类型"><el-checkbox-group v-model="form.types"><el-checkbox :value="3">网络登录（3）</el-checkbox><el-checkbox :value="10">远程交互（10）</el-checkbox></el-checkbox-group></el-form-item>
      <div class="numbers">
        <el-form-item v-for="field in numbers" :key="field.key" :label="field.label"><el-input-number v-model="form[field.key]" :min="field.min" :max="field.max" :precision="0" controls-position="right" /></el-form-item>
      </div>
      <el-form-item label="封禁 TCP 端口"><el-input v-model="form.ports" placeholder="3389，按需增加 445" /></el-form-item>
      <p class="help">类型 3 也包括 SMB 等网络认证。失败次数按来源 IP 汇总；封禁作用于指定端口，日志不提供服务端目标端口。成功登录只触发异常时段告警。</p>
      <el-form-item label="信任来源"><el-input v-model="form.trusted" type="textarea" :rows="2" placeholder="管理来源 IP 或网段，每行一个" /></el-form-item>
      <el-form-item label="排除账户"><el-input v-model="form.users" placeholder="DOMAIN\backup，完整匹配，不区分大小写" /></el-form-item>
      <el-form-item label="异常时段告警"><el-switch v-model="form.offHours" /></el-form-item>
      <div v-if="form.offHours" class="numbers">
        <el-form-item label="允许起始时"><el-input-number v-model="form.start" :min="0" :max="23" :precision="0" controls-position="right" /></el-form-item>
        <el-form-item label="允许结束时"><el-input-number v-model="form.end" :min="0" :max="24" :precision="0" controls-position="right" /></el-form-item>
      </div>
      <el-form-item v-if="form.offHours" label="时区"><el-select v-model="form.timezone" filterable allow-create default-first-option><el-option v-for="zone in ['Local','UTC','Asia/Shanghai']" :key="zone" :value="zone" :label="zone" /></el-select></el-form-item>
      <el-form-item><el-button type="primary" :loading="saving" @click="save">保存 Windows 登录配置</el-button></el-form-item>
    </el-form>
    <el-empty v-else description="Windows 登录规则未加载，请刷新页面重试" :image-size="48" />
    <p v-if="saveError" role="alert" class="error">{{ saveError }}</p>
    <p v-if="saved" role="status">配置已保存，实际生效情况请查看各主机状态。</p>
    <div class="status-heading"><h4>Windows 主机监测状态</h4><el-button :loading="loading" @click="refresh">刷新状态</el-button></div>
    <p class="help">需启用系统“审核登录”的成功与失败审核，并授予 Agent 读取 Security 日志的权限。以下为最近心跳报告的状态。</p>
    <el-alert v-if="error" :title="error" type="error" :closable="false"><el-button size="small" @click="refresh">重试</el-button></el-alert>
    <div v-else class="status-table" v-loading="loading">
      <el-table :data="items" empty-text="暂无 Windows 主机" size="small">
        <el-table-column label="主机" min-width="160"><template #default="{ row }">{{ row.hostname }}<div class="help">{{ row.ip }}</div></template></el-table-column>
        <el-table-column label="监测状态" min-width="145"><template #default="{ row }"><el-tag :type="row.state === 'polling' ? 'success' : ['disabled','offline'].includes(row.state) ? 'info' : 'warning'">{{ windowsLoginStateLabel(row.state) }}</el-tag></template></el-table-column>
        <el-table-column label="覆盖与问题" min-width="265"><template #default="{ row }"><div>{{ windowsLoginIssueLabel(row.coverage?.issue) }}</div><span class="help">成功审计：{{ row.coverage?.audit_success ? '启用' : '未确认' }} · 失败审计：{{ row.coverage?.audit_failure ? '启用' : '未确认' }}</span></template></el-table-column>
        <el-table-column label="当前封禁" min-width="90"><template #default="{ row }">{{ row.state === 'polling' || row.state === 'degraded' || row.state === 'behind' ? row.coverage?.active_blocks ?? '—' : '—' }}</template></el-table-column>
      </el-table>
    </div>
    <el-pagination v-if="total > 20" v-model:current-page="page" :page-size="20" :total="total" layout="prev, pager, next" @current-change="refresh" />
  </section>
</template>
<script setup>
import { onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { fetchWindowsLoginStatus, getUser, updateProtectRule } from '../api'
import { windowsLoginProtectionPayload, windowsLoginStateLabel, windowsLoginIssueLabel } from '../utils/protection'
const props = defineProps({ rule: { type: Object, default: null } })
const saving = ref(false), saveError = ref(''), saved = ref(false), loading = ref(false), error = ref('')
const items = ref([]), page = ref(1), total = ref(0)
const readOnly = getUser()?.role === 'viewer'
const form = reactive({ enabled: false, block: false, types: [3, 10], threshold: 5, window: 300, cooldown: 300, duration: 600, ports: '3389', trusted: '', users: '', offHours: false, start: 8, end: 20, timezone: 'Local' })
const numbers = [{ key: 'threshold', label: '失败次数', min: 2, max: 100 }, { key: 'window', label: '窗口（秒）', min: 1, max: 3600 }, { key: 'cooldown', label: '告警间隔（秒）', min: 1, max: 86400 }, { key: 'duration', label: '封禁（秒）', min: 5, max: 3600 }]
watch(() => props.rule, r => {
  if (!r) return
  const m = r.match || {}
  Object.assign(form, { enabled: r.enabled, block: (r.actions || []).includes('block_ip'), types: [...(m.windows_logon_types || [3, 10])], threshold: m.failure_threshold ?? 5, window: m.window_sec ?? 300, cooldown: m.cooldown_sec ?? 300, duration: m.block_duration_sec ?? 600, ports: (m.windows_ports || [3389]).join(', '), trusted: (m.trusted_ips || []).join('\n'), users: (m.user_exclude || []).join(', '), offHours: m.off_hours_enabled ?? false, start: m.allowed_start_hour ?? 8, end: m.allowed_end_hour ?? 20, timezone: m.timezone || 'Local' })
}, { immediate: true })
async function save() {
  if (!props.rule || saving.value || readOnly) return
  saving.value = true; saveError.value = ''; saved.value = false
  try { await updateProtectRule(props.rule.rule_id, windowsLoginProtectionPayload(props.rule, form)); saved.value = true; await refresh() }
  catch (e) { saveError.value = e.message || 'Windows 登录配置保存失败' }
  finally { saving.value = false }
}
async function refresh() {
  if (loading.value) return
  loading.value = true; error.value = ''
  try { const data = await fetchWindowsLoginStatus(page.value); items.value = data.items || []; total.value = data.total || 0 }
  catch (e) { error.value = e.message || 'Windows 主机状态加载失败'; items.value = [] }
  finally { loading.value = false }
}
let timer
onMounted(() => { refresh(); timer = setInterval(refresh, 15000) })
onUnmounted(() => clearInterval(timer))
</script>
<style scoped>
.windows-login { margin-top: 20px; min-width: 0; }
.settings { max-width: 760px; }
.help { font-size: 12px; color: #64748b; line-height: 1.65; overflow-wrap: anywhere; }
.numbers { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 16px; }
.numbers :deep(.el-input-number), .settings :deep(.el-select) { width: 100%; min-width: 0; }
.status-heading { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.status-table { overflow-x: auto; }
.error { color: #b91c1c; }
@media (max-width: 580px) { .numbers { grid-template-columns: minmax(0, 1fr); } }
</style>

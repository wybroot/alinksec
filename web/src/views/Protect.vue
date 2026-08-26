<template>
  <div>
    <div class="grid-4">
      <div class="prot-card" v-for="p in cards" :key="p.title">
        <div class="hd"><b>{{ p.title }}</b><el-switch v-model="p.on" @change="msg((p.on ? '已开启 ' : '已关闭 ') + p.title)" /></div>
        <p>{{ p.desc }}</p>
        <div class="stats">{{ p.stats }}</div>
        <el-tag size="small" effect="plain" type="success" style="margin-top:8px">断网仍生效</el-tag>
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
          <span class="t">{{ fmtTime(b.last_time) }}</span>
          <div style="flex:1">
            <el-tag size="small" :type="sevType(b.severity)">{{ sevLabel(b.severity) }}</el-tag> {{ b.title }}<br />
            <span style="color:#94a3b8;font-size:11px">{{ b.hostname || b.agent_id }} · </span>
            <el-tag size="small" effect="plain" type="info">{{ b.action_taken || 'alert_only' }}</el-tag>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchProtect, fetchProtectRules, updateProtectRule } from '../api'
import { sevType, sevLabel } from '../utils/format'

const cards = ref([])
const blocks = ref([])
const loading = ref(false)
const ruleLoaded = ref(false)
const decoyLevel = ref('kill_and_isolate')
const decoyDirs = ref('')
const decoyExcludes = ref('')

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
    if (decoy) {
      decoyLevel.value = actionsLevel(decoy.actions)
      decoyDirs.value = (decoy.match?.dirs || []).join(', ')
      decoyExcludes.value = (decoy.match?.exclude_exes || []).join(', ')
      ruleLoaded.value = true
    }
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
</script>

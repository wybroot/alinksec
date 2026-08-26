<template>
  <div class="panel">
    <el-tabs v-model="tab">
      <el-tab-pane label="全部" name="all" />
      <el-tab-pane label="严重" name="critical" />
      <el-tab-pane label="高危" name="high" />
      <el-tab-pane label="待处置" name="open" />
    </el-tabs>
    <el-table :data="filtered" stripe>
      <el-table-column label="级别" width="80">
        <template #default="{ row }"><el-tag size="small" :type="sevType(row.sev)" :effect="row.sev === 'critical' ? 'dark' : 'light'">{{ sevLabel(row.sev) }}</el-tag></template>
      </el-table-column>
      <el-table-column label="类型" width="130"><template #default="{ row }"><span class="mono">{{ row.type }}</span></template></el-table-column>
      <el-table-column prop="text" label="内容" min-width="260" />
      <el-table-column prop="host" label="主机" width="130" />
      <el-table-column prop="time" label="时间" width="150" />
      <el-table-column label="状态" width="90">
        <template #default="{ row }"><el-tag size="small" :type="row.done ? 'success' : 'danger'" effect="plain">{{ row.done ? '已处置' : '待处置' }}</el-tag></template>
      </el-table-column>
      <el-table-column label="操作" width="120" fixed="right">
        <template #default="{ row }">
          <el-button v-if="!row.done" link type="primary" size="small" :loading="row._busy" @click="handle(row, '处置')">处置</el-button>
          <el-button v-if="!row.done" link size="small" :loading="row._busy" @click="handle(row, '已忽略')">忽略</el-button>
          <span v-else style="font-size:12px;color:#94a3b8">{{ row.handler }}</span>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchAlerts, handleAlert } from '../api'
import { sevType, sevLabel } from '../utils/format'

// 数据源：GET /api/alerts → t_alert；处置/忽略 POST /api/alerts/{id}/handle（M3 闭环）
const alerts = ref([])
const tab = ref('all')

const filtered = computed(() => alerts.value.filter(a => {
  if (tab.value === 'critical') return a.sev === 'critical'
  if (tab.value === 'high') return a.sev === 'high'
  if (tab.value === 'open') return !a.done
  return true
}))

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

const handle = async (row, remark) => {
  row._busy = true
  try {
    await handleAlert(row.id, remark)
    row.done = true
    row.handler = remark === '已忽略' ? '已忽略' : '已处置'
    msg(remark === '已忽略' ? '已忽略' : '处置动作已下发')
  } catch (e) {
    ElMessage({ message: e?.message || '操作失败', type: 'error' })
  } finally {
    row._busy = false
  }
}

onMounted(async () => { alerts.value = await fetchAlerts() })
</script>

<template>
  <div class="panel">
    <p v-if="loadError" role="alert">{{ loadError }} <el-button size="small" @click="load">重试</el-button></p>
    <el-tabs v-model="tab" @tab-change="changeFilter">
      <el-tab-pane label="全部" name="all" />
      <el-tab-pane label="严重" name="critical" />
      <el-tab-pane label="高危" name="high" />
      <el-tab-pane label="待处置" name="open" />
    </el-tabs>
    <el-table :data="alerts" stripe>
      <el-table-column label="级别" width="80">
        <template #default="{ row }"><el-tag size="small" :type="sevType(row.sev)" :effect="row.sev === 'critical' ? 'dark' : 'light'">{{ sevLabel(row.sev) }}</el-tag></template>
      </el-table-column>
      <el-table-column label="类型" width="130"><template #default="{ row }"><span class="mono">{{ row.type }}</span></template></el-table-column>
      <el-table-column label="内容" min-width="260"><template #default="{ row }">
        {{ row.text }}
        <el-tag v-if="row.legacySeverity" size="small" type="info">历史等级，沿用旧含义</el-tag>
        <el-button v-if="['windows_kernel_file_etw', 'linux_writer_evidence'].includes(row.detail?.attribution?.source)" link type="primary" size="small" @click="evidence = row">查看归因证据</el-button>
      </template></el-table-column>
      <el-table-column prop="host" label="主机" width="130" />
      <el-table-column prop="time" label="时间" width="150" />
      <el-table-column label="状态" width="90">
        <template #default="{ row }"><el-tag size="small" :type="row.done ? 'success' : 'danger'" effect="plain">{{ row.done ? '已处理' : '待处理' }}</el-tag></template>
      </el-table-column>
      <el-table-column label="操作" width="120" fixed="right">
        <template #default="{ row }">
          <el-button v-if="!row.done && !readOnly" link type="primary" size="small" :loading="row._busy" @click="handle(row, '标记已处理')">标记已处理</el-button>
          <el-button v-if="!row.done && !readOnly" link size="small" :loading="row._busy" @click="handle(row, '已忽略')">忽略</el-button>
          <span v-else style="font-size:12px;color:#94a3b8">{{ row.handler }}</span>
        </template>
      </el-table-column>
    </el-table>
    <el-pagination v-model:current-page="page" :page-size="100" :total="total" layout="total, prev, pager, next" @current-change="load" />
    <el-dialog :model-value="!!evidence" title="勒索进程归因证据" width="min(680px, 94vw)" top="5vh" style="max-height:90vh;overflow-y:auto" @close="evidence = null">
      <RansomAttribution v-if="evidence" :detail="evidence.detail" :action="evidence.action" />
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { fetchAlertPage, getUser, handleAlert } from '../api'
import { sevType, sevLabel } from '../utils/format'
import RansomAttribution from '../components/RansomAttribution.vue'

// 数据源：GET /api/alerts → t_alert；处置/忽略 POST /api/alerts/{id}/handle（M3 闭环）
const alerts = ref([])
const tab = ref('all')
const evidence = ref(null)
const readOnly = getUser()?.role === 'viewer'
const loadError = ref('')
const page=ref(1), total=ref(0)
let generation=0
async function load() {
  const request=++generation
  try {
    const data=await fetchAlertPage({page:page.value,size:100,tab:tab.value})
    if(request!==generation)return
    alerts.value=data.list;total.value=data.total;loadError.value=''
    if(page.value>1 && !data.list.length){page.value=1;await load()}
  }catch(e){if(request!==generation)return;alerts.value=[];total.value=0;loadError.value=e?.message || '告警加载失败'}
}
function changeFilter(){page.value=1;load()}

const msg = t => ElMessage({ message: t, type: 'success', duration: 1800 })

const handle = async (row, remark) => {
  row._busy = true
  try {
    await handleAlert(row.id, remark)
    msg(remark === '已忽略' ? '已标记忽略' : '已标记处理；未下发主机动作')
    await load()
  } catch (e) {
    ElMessage({ message: e?.message || '操作失败', type: 'error' })
    await load()
  } finally {
    row._busy = false
  }
}

onMounted(load)
</script>

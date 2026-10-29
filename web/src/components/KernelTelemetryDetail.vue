<template>
  <div class="telemetry-detail">
    <el-descriptions :column="2" border size="small">
      <el-descriptions-item label="遥测源">
        <el-tag size="small" type="primary">{{ detail.telemetry_source === 'falco_ebpf' ? 'Falco eBPF Probe' : 'Elkeid Driver (Kprobe)' }}</el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="规则/事件标识">
        <span class="mono">{{ detail.falco_rule || ('Data Type ' + detail.data_type) }}</span>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.falco_priority" label="原始告警级别">
        <el-tag size="small" effect="plain">{{ detail.falco_priority }}</el-tag>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.nodename" label="上报节点">
        <span>{{ detail.nodename }}</span>
      </el-descriptions-item>
      <el-descriptions-item label="容器状态">
        <el-tag size="small" :type="detail.in_container ? 'warning' : 'info'">{{ detail.in_container ? '容器内部 (Containerized)' : '宿主机 (Host)' }}</el-tag>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.container_id" label="容器 ID">
        <span class="mono">{{ detail.container_id }}</span>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.container?.image" label="容器镜像" :span="2">
        <span class="mono">{{ detail.container.image }}</span>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.proc_pid || detail.pid" label="进程 PID">
        <span class="mono">{{ detail.proc_pid || detail.pid }}</span>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.ppid" label="父进程 PPID">
        <span class="mono">{{ detail.ppid }}</span>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.proc_name || detail.exe" label="执行程序" :span="2">
        <span class="mono">{{ detail.proc_name || detail.exe }}</span>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.proc_cmdline || detail.argv" label="完整命令行" :span="2">
        <pre class="cmd-box">{{ detail.proc_cmdline || detail.argv }}</pre>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.pid_tree" label="进程调用树 (pid_tree)" :span="2">
        <pre class="cmd-box">{{ detail.pid_tree }}</pre>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.tags && detail.tags.length" label="MITRE ATT&CK 标签" :span="2">
        <el-tag v-for="tag in detail.tags" :key="tag" size="small" style="margin-right:6px;margin-bottom:4px" effect="plain">{{ tag }}</el-tag>
      </el-descriptions-item>
      <el-descriptions-item v-if="detail.raw_output" label="原始日志输出" :span="2">
        <pre class="cmd-box">{{ detail.raw_output }}</pre>
      </el-descriptions-item>
    </el-descriptions>
  </div>
</template>

<script setup>
defineProps({
  detail: {
    type: Object,
    required: true
  }
})
</script>

<style scoped>
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13px; }
.cmd-box { margin: 0; padding: 6px 10px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 180px; overflow-y: auto; }
</style>

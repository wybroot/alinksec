<template>
  <div v-if="entries?.length" class="provenance">
    <div v-for="entry in entries" :key="entry.release_id">
      <p>签名来源：<router-link :to="{ path: '/baseline-upstreams', query: { source: entry.source_id } }">{{ entry.source_id }}</router-link> · 序号 {{ entry.sequence }}</p>
      <p class="hash">下载原件 SHA256：{{ entry.download_sha256 }}</p>
      <p>签名索引有效至：{{ new Date(Number(entry.expires_at)).toLocaleString() }}</p>
      <el-alert v-if="entry.remote_status !== 'active' || !entry.configured || entry.receipt_config !== entry.source_config || entry.expires_at <= Date.now()" title="上游内容已撤回、配置已变更或索引已过期。候选版本暂不能继续审核、测试或发布；已发布规则可人工撤回。" type="warning" :closable="false" />
    </div>
  </div>
</template>
<script setup>
defineProps({ entries: Array })
</script>
<style scoped>
.provenance{margin:16px 0;padding:12px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;overflow-wrap:anywhere}.provenance p{margin:6px 0;font-size:13px}.hash{font-family:monospace;font-size:12px}a{color:#2563eb}
</style>

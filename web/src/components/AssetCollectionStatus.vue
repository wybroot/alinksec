<template>
  <section class="container-assets asset-collection-status">
    <h4>资产采集状态</h4>
    <p>以下为最近报告，实时变更需重新采集。主机采集时间可能受时钟偏差影响；平台接纳时间用于核对报告到达时间。</p>
    <details v-for="[category, name] in assetCategories" :key="category" :data-category="category" class="collection-observation">
      <summary><span :class="{ incomplete: state(category).status !== 'complete' }">{{ name + '：' + collectionLabel(state(category)) }}</span></summary>
      <p v-if="state(category).error">{{ state(category).error }}</p>
      <p>最近尝试：{{ collectionTime(state(category).collected_at) }}<br />
        平台接纳：{{ collectionTime(state(category).received_at) }}<br />
        最近完整采集：{{ collectionTime(state(category).succeeded_collected_at) }}<br />
        完整报告接纳：{{ collectionTime(state(category).succeeded_received_at) }}</p>
      <p v-if="category === 'containers' && state(category).status === 'partial'">仅更新成功来源；其他来源保留旧记录，各来源时间可能不同。</p>
    </details>
  </section>
</template>

<script setup>
import { assetCategories, collectionLabel, collectionTime } from '../utils/asset-collection'
const props = defineProps({ collections: { type: Array, default: () => [] } })
const state = category => props.collections.find(item => item.category === category) || {}
</script>

<style scoped>
p { font-size: 12px; line-height: 1.8; color: #64748b; overflow-wrap: anywhere; }
.collection-observation { margin-top: 12px; }
summary { cursor: pointer; font-size: 13px; line-height: 1.8; }
.incomplete { color: #b45309; }
</style>

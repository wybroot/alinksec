<template>
  <article class="report-document" aria-label="安全运营报表">
    <h1>{{ report.title }}</h1>
    <p>{{ report.query.from }} 至 {{ report.query.to }}（含结束日，{{ report.timezone }}）</p>
    <p>{{ report.scope.group }} · {{ report.scope.os }} · 生成于 {{ report.generatedAt }}</p>
    <p v-if="report.snapshotId">快照 {{ report.snapshotId }} · 生成账号 ID {{ report.createdBy }}</p>
    <p v-if="digest" class="report-digest">快照 SHA256：{{ digest }}</p>
    <section><h2>主机资产 · 生成时快照</h2><div class="report-metrics">
      <div v-for="[key, label] in assets" :key="key"><span>{{ label }}</span><strong>{{ report.assets[key] }}</strong></div>
    </div></section>
    <section><h2>基线自动检查 · 区间内最后分配任务</h2><div class="report-metrics">
      <div v-for="[key, label] in baseline" :key="key"><span>{{ label }}</span><strong>{{ report.baseline[key] }}</strong></div>
      <div><span>自动检查通过率</span><strong>{{ rate }}</strong></div>
    </div><p>区间内分配 {{ report.baseline.assigned_hosts }} 台，未分配 {{ report.baseline.unassessed_hosts }} 台。通过率分母包括预期的异常、旧证据和待回报项。</p></section>
    <section><h2>每日新增趋势</h2><div class="report-legend">蓝色：告警条数 · 橙色：漏洞记录数 · 最高日 {{ peak }}</div>
      <svg class="report-chart" viewBox="0 0 800 150" role="img" aria-label="每日新增告警和漏洞记录趋势">
        <path d="M10 130H790" stroke="#cbd5e1" fill="none" />
        <polyline :points="points('alerts')" stroke="#2563eb" stroke-width="2" fill="none" />
        <polyline :points="points('vulnerabilities')" stroke="#d97706" stroke-width="2" fill="none" />
      </svg>
      <div class="report-scroll"><table><thead><tr><th>日期</th><th>新增告警条数</th><th>新增漏洞记录数</th></tr></thead><tbody><tr v-for="day in report.trend" :key="day.day"><td>{{ day.day }}</td><td>{{ day.alerts }}</td><td>{{ day.vulnerabilities }}</td></tr></tbody></table></div>
    </section>
    <section><h2>漏洞发现记录 · 按创建时间</h2><div class="report-scroll"><table><thead><tr><th>等级</th><th>记录状态</th><th>发现记录数</th><th>记录中仍匹配标记数</th></tr></thead><tbody><tr v-for="row in report.vulnerabilities" :key="`${row.severity}-${row.status}`"><td>{{ severity(row.severity) }}</td><td>{{ vulnStatus[row.status] || row.status }}</td><td>{{ row.records }}</td><td>{{ row.recorded_match }}</td></tr><tr v-if="!report.vulnerabilities.length"><td colspan="4">区间内没有发现记录；不能据此判断安全。</td></tr></tbody></table></div></section>
    <section><h2>告警处置 · 状态截至生成时</h2><div class="report-scroll"><table><thead><tr><th>等级</th><th>告警条数</th><th>合并次数</th><th>已处置</th><th>忽略</th><th>未处置</th></tr></thead><tbody><tr v-for="row in report.alerts" :key="`${row.severity_source}-${row.severity}`"><td>{{ row.severity_label || severity(row.severity) }}</td><td>{{ row.records }}</td><td>{{ row.occurrences }}</td><td>{{ row.handled }}</td><td>{{ row.ignored }}</td><td>{{ row.open }}</td></tr><tr v-if="!report.alerts.length"><td colspan="6">区间内没有告警记录。</td></tr></tbody></table></div></section>
    <section><h2>漏洞覆盖 · 生成时状态</h2><div class="report-scroll"><table><thead><tr><th>采集或评估状态</th><th>主机数</th></tr></thead><tbody><tr v-for="row in report.coverage" :key="row.status"><td>{{ coverageName[row.status] || row.status }}</td><td>{{ row.hosts }}</td></tr><tr v-if="!report.coverage.length"><td colspan="2">所选范围没有主机。</td></tr></tbody></table></div></section>
    <section><h2>来源待处理</h2><p>{{ report.sourceHoldsScope }}</p><div class="report-scroll"><table><thead><tr><th>CVE 声明状态</th><th>条数</th></tr></thead><tbody><tr v-for="row in report.sourceHolds" :key="row.status"><td>{{ holds[row.status] || row.status }}</td><td>{{ row.items }}</td></tr><tr v-if="!report.sourceHolds.length"><td colspan="2">当前没有上述状态的声明。</td></tr></tbody></table></div></section>
    <section><h2>主机与基线明细</h2><p>显示 {{ report.hosts.length }} / {{ report.detailTotal }} 台。<strong v-if="report.detailsTruncated">明细已截断；汇总覆盖全部所选主机。</strong></p><div class="report-scroll"><table class="report-hosts"><thead><tr><th>主机 / Agent</th><th>系统 / 状态</th><th>最后分配任务</th><th>预期</th><th>通过</th><th>不通过</th><th>异常</th><th>旧证据</th><th>待回报</th></tr></thead><tbody><tr v-for="host in report.hosts" :key="host.agent_id"><td>{{ host.hostname }}<small>{{ host.agent_id }}</small></td><td>{{ host.os_type === 1 ? 'Linux' : host.os_type === 2 ? 'Windows' : '未知' }} / {{ host.status === 1 ? '在线' : host.status === 2 ? '离线' : '其他' }}</td><td>{{ host.task_id ? `${host.task_name || '未命名'} #${host.task_id}` : '区间内未分配' }}</td><td v-for="key in ['expected', 'passed', 'failed', 'errors', 'legacy', 'pending']" :key="key">{{ host[key] }}</td></tr><tr v-if="!report.hosts.length"><td colspan="9">所选范围没有主机。</td></tr></tbody></table></div></section>
    <section><h2>统计口径与范围</h2><ol><li v-for="note in report.notes" :key="note">{{ note }}</li></ol></section>
  </article>
</template>
<script setup>
import { computed } from 'vue'
const props = defineProps({ report: { type: Object, required: true }, digest: { type: String, default: '' } })
const assets = [['total', '主机总数'], ['online', '在线'], ['offline', '离线'], ['other', '其他状态']]
const baseline = [['expected', '预期项'], ['passed', '通过'], ['failed', '不通过'], ['errors', '执行异常'], ['legacy', '旧证据'], ['pending', '待回报']]
const rate = computed(() => props.report.baseline.expected ? (100 * props.report.baseline.passed / props.report.baseline.expected).toFixed(1) + '%' : '无可计算分母')
const peak = computed(() => Math.max(1, ...props.report.trend.flatMap(d => [d.alerts, d.vulnerabilities])))
const points = key => props.report.trend.map((d, i, all) => `${all.length === 1 ? 400 : 10 + 780 * i / (all.length - 1)},${130 - 110 * d[key] / peak.value}`).join(' ')
const severity = value => ({ 1: '低危（1）', 2: '中危（2）', 3: '高危（3）', 4: '严重（4）', 5: '危急（5）' }[value] || `未知（${value}）`)
const vulnStatus = { 0: '新增', 1: '已确认', 2: '已忽略', 3: '已修复' }
const coverageName = { complete: '已完成评估（不等于安全）', partial: '部分评估', unknown: '未知', legacy: '旧证据', not_scanned: '未扫描', stale_inventory: '资产已变化', stale_rules: '规则已变化', selection_pending: '来源选择待重新评估', failed: '采集失败', unsupported: '不支持' }
const holds = { conflict: '同级冲突', review_required: '等待复核', quarantined: '来源隔离', suppressed: '暂停采用', withdrawn: '已撤销', retired: '已退役' }
</script>
<style scoped>
.report-document{padding:20px;background:white;border:1px solid #dbe3ec;border-radius:10px;color:#25364b;overflow-wrap:anywhere}.report-document h1{font-size:24px}.report-document h2{font-size:17px;margin-top:28px}.report-document p,.report-document li{font-size:13px;line-height:1.7}.report-digest{font-family:monospace;font-size:11px!important}.report-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px}.report-metrics div{padding:12px;background:#f1f5f9;border-radius:6px}.report-metrics span{display:block;font-size:12px}.report-metrics strong{display:block;font-size:23px;margin-top:6px}.report-scroll{overflow:auto;max-height:440px}.report-document table{border-collapse:collapse;width:100%;font-size:12px}.report-document th,.report-document td{border:1px solid #dbe3ec;padding:8px;text-align:left;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}.report-document th{background:#f1f5f9}.report-hosts{min-width:850px}.report-document small{display:block;color:#64748b;margin-top:5px}.report-chart{display:block;width:100%;height:150px}.report-legend{font-size:12px}.report-document ol{padding-left:20px}@media(max-width:600px){.report-document{padding:12px}.report-document h1{font-size:20px}.report-metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.report-hosts{min-width:760px}}@media print{.report-document{border:0;padding:0}.report-scroll{overflow:visible;max-height:none}.report-hosts{min-width:0}.report-document table{font-size:9px;table-layout:fixed}.report-document th,.report-document td{padding:4px}.report-document thead{display:table-header-group}.report-document tr{break-inside:avoid}.report-document h2{break-after:avoid}.report-metrics{grid-template-columns:repeat(4,1fr)}}
</style>

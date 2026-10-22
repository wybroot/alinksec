<template>
  <div>
    <div class="panel">
      <div class="toolbar">
        <h4>安全库管理</h4>
        <div class="spacer"></div>
        <el-button :loading="loading" @click="load">刷新</el-button>
        <el-button v-if="canImport" type="primary" :loading="uploading" @click="signatureInput.click()">导入病毒特征库</el-button>
        <el-button v-if="canImport" type="primary" plain :loading="uploading" @click="cveInput.click()">导入漏洞库</el-button>
      </div>
      <el-alert v-if="error" :title="error" type="error" :closable="false" show-icon />
      <el-descriptions v-if="!error" :column="compact ? 1 : 2" :label-width="compact ? 110 : undefined" border style="margin-top:12px">
        <el-descriptions-item label="病毒库版本">{{ state.signature?.db_version || '尚无可用特征库' }}</el-descriptions-item>
        <el-descriptions-item label="病毒检测依据">{{ state.signature?.hash_count || 0 }} 条哈希 / {{ state.signature?.rule_count || 0 }} 条内部规则</el-descriptions-item>
        <el-descriptions-item label="更新包">全量 {{ packageSize(state.signature?.size) }}<template v-if="Number(state.signature?.delta_size) > 0"> · 增量 {{ packageSize(state.signature.delta_size) }}，基于 {{ state.signature.delta_base_version }}</template><template v-else> · 当前版本使用全量更新</template></el-descriptions-item>
        <el-descriptions-item label="已管理漏洞信息">{{ state.managedCveCount || 0 }} 条</el-descriptions-item>
        <el-descriptions-item label="含资产比对规则">{{ state.matchableCveCount || 0 }} 条</el-descriptions-item>
        <el-descriptions-item label="存储方式">{{ state.storage === 's3' ? '对象存储' : '本地持久化存储' }}</el-descriptions-item>
        <el-descriptions-item label="病毒库发布时间">{{ date(state.signature?.imported_at) }}</el-descriptions-item>
      </el-descriptions>
      <p v-if="!error" class="hint">支持增量更新且基库一致的 Agent 优先下载差量；基库不符或差量失败时回退完整包，校验失败保留旧库。旧 Agent 使用全量包。此处仅指内置哈希及内部规则库，ClamAV 与原生 YARA 沿用各自的本机配置。</p>
      <el-alert v-if="!loading && !error && (!state.signature?.db_version || Number(state.signature?.hash_count || 0) + Number(state.signature?.rule_count || 0) === 0)" title="当前有效病毒特征为空，缺少病毒识别依据；零特征不代表主机安全。请导入基础特征库或启用有效来源。" type="warning" :closable="false" show-icon style="margin-top:12px" />
      <p class="hint">人工导入与远端同步可同时使用。远端不可用时，平台和 Agent 继续使用已有库；人工补充的规则优先保留。</p>
      <p class="hint">漏洞信息只有包含适用的软件和版本条件，才能参与资产比对。补丁包继续在漏洞修复流程中按需使用。</p>
      <el-alert v-if="state.unattributedCveCount" type="warning" :closable="false" :title="`${state.unattributedCveCount} 条历史漏洞缺少入库来源记录，请重新导入并扫描；旧依据保持未知`" style="margin-bottom:12px" />
      <el-button @click="showRules = true; loadRules()">查看漏洞规则依据</el-button>
      <input ref="signatureInput" type="file" accept=".zip" hidden @change="importFile($event, 'signature')" />
      <input ref="cveInput" type="file" accept=".json" hidden @change="importFile($event, 'cve')" />
    </div>
    <div v-if="showRules" class="panel" style="margin-top:16px">
      <h4>漏洞规则与依据</h4>
      <p class="hint">公告引用和引用摘要来自导入声明；原生公告同时保留原件和传输来源，均不代表厂商签名已验证。源码包和上游范围不能直接推断发行版二进制包的回移状态。</p>
      <el-input v-model="rulesKeyword" placeholder="CVE 或标题" @keyup.enter="rulesPage = 1; loadRules()" style="max-width:320px" />
      <el-button :loading="rulesLoading" @click="rulesPage = 1; loadRules()">查询</el-button>
      <el-alert v-if="rulesError" :title="rulesError" type="error" :closable="false" />
      <el-table :data="ruleRows" v-loading="rulesLoading" style="margin-top:12px">
        <el-table-column prop="cve_id" label="CVE" min-width="160" />
        <el-table-column prop="title" label="标题" min-width="180" />
        <el-table-column label="声明用途" min-width="130"><template #default="{ row }">{{ row.rule_status === 'withdrawn' ? '公告已撤销' : row.rule_status === 'retired' ? '来源已退役' : row.evaluation === 'declared' ? '含可评估声明' : '仅元数据或旧依据缺失' }}</template></el-table-column>
        <el-table-column label="实际导入来源" min-width="130"><template #default="{ row }">{{ row.rule_source_id || '历史来源未知' }}</template></el-table-column>
        <el-table-column label="操作" width="100"><template #default="{ row }"><el-button link type="primary" @click="openRule(row)">查看依据</el-button></template></el-table-column>
      </el-table>
      <el-pagination v-model:current-page="rulesPage" :page-size="20" :total="rulesTotal" layout="prev, pager, next" @current-change="loadRules" />
    </div>
    <el-dialog :model-value="!!ruleDetail" :title="ruleDetail?.cve_id" :width="compact ? 'calc(100% - 24px)' : '650px'" @close="closeRule">
      <el-alert v-if="ruleDetail?.rule_status && ruleDetail.rule_status !== 'active'" title="当前声明已撤销或来源已退役，不参与比对和自动修复。历史结果保留，不代表漏洞已修复。" type="warning" :closable="false" />
      <VulnerabilityEvidence v-if="ruleDetail" :snapshot="{ import: ruleDetail.provenance, rules: ruleDetail.affected }" :source-id="ruleDetail.rule_source_id" :digest="ruleDetail.rule_digest" :status="ruleDetail.rule_digest ? 'declared' : 'legacy'" />
      <h4>各来源公告</h4>
      <p class="hint">按整条 CVE 选择人工来源优先、其他来源按标识排序。优先公告撤销后不自动采用较低优先声明；整源退役后才重新选择其他来源。</p>
      <el-alert v-if="declarationsError" :title="declarationsError" type="error" :closable="false" />
      <div v-loading="declarationsLoading" v-for="item in declarations" :key="item.source_id" class="declaration">
        <div><strong>{{ item.source_id }}</strong> · {{ declarationState(item) }}</div>
        <p class="hint digest">原文摘要 {{ item.documentDigest }}</p>
        <el-button link @click="declarationDetail = item">查看原始声明</el-button>
        <el-button link @click="showGovernance(item.source_id)">治理记录</el-button>
        <el-button v-if="isAdmin && !item.retired && item.document?.status !== 'withdrawn'" link type="warning" :disabled="governanceBusy" @click="decide(item)">{{ item.locally_withdrawn ? '恢复本地声明' : '撤销本地声明' }}</el-button>
      </div>
    </el-dialog>
    <el-dialog :model-value="!!declarationDetail" title="原始公告声明" :width="compact ? 'calc(100% - 24px)' : '650px'" @close="declarationDetail = null">
      <template v-if="declarationDetail"><p>{{ declarationDetail.source_id }} · {{ declarationDetail.cve_id }}</p>
        <p>{{ declarationState(declarationDetail) }}</p><p>{{ declarationDetail.document?.withdrawal_reason }}</p>
        <p>{{ declarationDetail.document?.title }}</p>
        <p class="document-description">{{ declarationDetail.document?.description }}</p>
        <VulnerabilityEvidence :snapshot="{ import: declarationDetail.provenance, rules: declarationDetail.document?.affected }" :source-id="declarationDetail.source_id" :digest="declarationDetail.documentDigest" status="declared" />
        <details><summary>完整公告声明</summary><pre class="original-document">{{ JSON.stringify(declarationDetail.document, null, 2) }}</pre></details>
      </template>
    </el-dialog>
    <div class="panel" style="margin-top:16px">
      <h4>来源治理</h4>
      <p class="hint">暂停同步保留有效数据。退役来源会撤销其当前效力、保留原始数据和历史，并阻止该标识再次同步。已离线 Agent 在收到新库前仍可能使用旧特征。</p>
      <el-table :data="state.governanceSources || []" stripe>
        <el-table-column prop="id" label="来源" min-width="140" />
        <el-table-column label="状态" min-width="140"><template #default="{ row }">{{ row.retired ? '已退役' : row.id === 'manual' ? '人工来源' : row.configured ? '部署已配置' : '部署已移除，数据仍有效' }}</template></el-table-column>
        <el-table-column label="保留数据" min-width="180"><template #default="{ row }">{{ row.cves }} 公告 / {{ row.hashes }} 哈希 / {{ row.rules }} 特征规则</template></el-table-column>
        <el-table-column prop="retirement_note" label="退役原因" min-width="160" />
        <el-table-column label="操作" min-width="180"><template #default="{ row }"><el-button link @click="showGovernance(row.id)">治理记录</el-button><el-button v-if="isAdmin && row.id !== 'manual' && !row.retired" link type="danger" :disabled="state.running || governanceBusy" @click="retire(row)">退役来源</el-button></template></el-table-column>
      </el-table>
    </div>
    <el-dialog v-model="governance.visible" :title="`${governance.id} · 治理记录`" :width="compact ? 'calc(100% - 24px)' : '800px'">
      <el-alert v-if="governance.error" :title="governance.error" type="error" :closable="false" />
      <el-table :data="governance.rows" v-loading="governance.loading">
        <el-table-column prop="cve_id" label="公告" min-width="160" />
        <el-table-column label="操作" min-width="90"><template #default="{ row }">{{ governanceOperations[row.operation] || row.operation }}</template></el-table-column>
        <el-table-column label="时间" min-width="170"><template #default="{ row }">{{ date(row.recorded_at) }}</template></el-table-column>
        <el-table-column label="账号" width="90"><template #default="{ row }">{{ row.actor ?? '自动同步' }}</template></el-table-column>
        <el-table-column prop="note" label="原因" min-width="150" />
        <el-table-column label="依据" width="90"><template #default="{ row }"><el-button link @click="governanceEvent = row">查看</el-button></template></el-table-column>
      </el-table>
      <el-pagination v-model:current-page="governance.page" :total="governance.total" :page-size="20" layout="prev, pager, next" @current-change="loadGovernance" />
    </el-dialog>
    <el-dialog :model-value="!!governanceEvent" title="治理时原始依据" :width="compact ? 'calc(100% - 24px)' : '650px'" @close="governanceEvent = null">
      <template v-if="governanceEvent"><p>{{ governanceEvent.source_id }} · {{ governanceEvent.cve_id }} · {{ governanceOperations[governanceEvent.operation] }}</p><p>{{ governanceEvent.note }}</p>
        <p class="digest">{{ governanceEvent.document_sha256 }}</p>
        <p>{{ governanceEvent.snapshot?.document?.title }}</p>
        <p class="document-description">{{ governanceEvent.snapshot?.document?.description }}</p>
        <VulnerabilityEvidence v-if="governanceEvent.cve_id" :snapshot="{ import: governanceEvent.snapshot?.provenance, rules: governanceEvent.snapshot?.document?.affected }" :source-id="governanceEvent.source_id" :digest="governanceEvent.document_sha256" status="declared" />
        <details v-if="governanceEvent.cve_id"><summary>完整公告声明</summary><pre class="original-document">{{ JSON.stringify(governanceEvent.snapshot?.document, null, 2) }}</pre></details>
        <p v-else>退役时保留 {{ governanceEvent.snapshot?.provenance?.cves || 0 }} 公告 / {{ governanceEvent.snapshot?.provenance?.hashes || 0 }} 哈希 / {{ governanceEvent.snapshot?.provenance?.rules || 0 }} 特征规则</p>
      </template>
    </el-dialog>
    <div class="panel" style="margin-top:16px">
      <h4>远端同步状态</h4>
      <p class="hint">数据源按计划串行检查。连续失败会延后重试，已有库继续可用。管理员可调整计划，设置保存后立即生效。</p>
      <el-empty v-if="!state.sources?.length" description="尚未配置远端数据源，可继续人工导入" />
      <el-table v-else :data="state.sources" stripe>
        <el-table-column prop="id" label="数据源" min-width="130" />
        <el-table-column label="内容" min-width="150">
          <template #default="{ row }">{{ types[row.type] || row.type }}<div v-if="row.nativeAdvisories" class="hint">{{ row.nativeAdvisories.archive_documents }} 份当前公告 · {{ row.nativeAdvisories.pending_count || 0 }} 份待检查</div><div v-if="row.coverage === 'recent-60m'" class="hint">最近 60 分钟新增情报</div><div v-if="row.coverage === 'modified-window'" class="hint">按修改日期增量同步<div>已完成至 {{ date(row.cursor) }}</div><div v-if="row.nvd_window_seconds">下次窗口最多 {{ Math.round(row.nvd_window_seconds / 60) }} 分钟</div></div><div v-if="row.coverage === 'curated-snapshot'" class="hint">已审核哈希的完整快照</div></template>
        </el-table-column>
        <el-table-column label="状态" width="140">
          <template #default="{ row }">
            <el-tag :type="!row.enabled ? 'info' : row.status === 'failed' ? 'danger' : row.status === 'running' ? 'primary' : row.stale || row.catchingUp ? 'warning' : 'success'">
              {{ row.retired ? '已退役' : !row.enabled ? '未启用' : row.status === 'running' ? '同步中' : row.status === 'failed' ? '同步失败' : row.status === 'never' ? '尚未同步' : row.catchingUp ? '追赶历史中' : row.stale ? '更新超时' : '检查正常' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="检查间隔" width="110"><template #default="{ row }">{{ Math.round(row.intervalMs / 60000) }} 分钟</template></el-table-column>
        <el-table-column label="最近成功检查" min-width="170"><template #default="{ row }">{{ date(row.success_at) }}</template></el-table-column>
        <el-table-column label="下次检查" min-width="170"><template #default="{ row }">{{ row.enabled && row.status === 'running' ? '本次执行中' : nextCheck(row.nextCheckAt) }}<div v-if="row.failure_count > 1 && row.enabled" class="hint">连续失败 {{ row.failure_count }} 次，已延后重试</div></template></el-table-column>
        <el-table-column prop="entry_count" label="当前条目" width="110" />
        <el-table-column label="说明" min-width="180"><template #default="{ row }">{{ row.configurationIssue || row.error || '—' }}</template></el-table-column>
        <el-table-column label="操作" :width="isAdmin ? 340 : 180" :fixed="compact ? false : 'right'">
          <template #default="{ row }">
            <el-button v-if="isAdmin" link type="primary" :disabled="!row.enabled || !!row.configurationIssue || state.running || syncing" @click="synchronize(row.id)">立即同步</el-button>
            <el-button v-if="isAdmin && !row.retired" link type="primary" @click="editSchedule(row)">同步计划</el-button>
            <el-button v-if="row.nativeAdvisories" link type="primary" @click="showAdvisories(row.id)">厂商公告</el-button>
            <el-button link type="primary" @click="showHistory(row.id)">执行记录</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
    <el-dialog v-model="advisories.visible" :title="`${advisories.id} · 厂商公告原件`" :width="compact ? 'calc(100% - 24px)' : '1000px'">
      <p class="hint">近期范围内发现公告，并复查已导入文档；首次发现数量受部署范围限制。每轮分批抓取，待检查文档会继续处理。公告中的修复包、源码包状态和 KB 信息按原文保留。</p>
      <el-button :loading="advisories.loading" @click="loadAdvisories">刷新公告</el-button>
      <p>当前公告 {{ advisories.state.archive_documents || 0 }} · 本轮发现 {{ advisories.state.discovered_count || 0 }} · 待检查 {{ advisories.state.pending_count || 0 }}</p>
      <el-alert v-if="advisories.error" :title="advisories.error" type="error" :closable="false" />
      <el-table :data="advisories.rows" v-loading="advisories.loading" empty-text="尚无已归档公告">
        <el-table-column prop="document_id" label="公告" min-width="170" />
        <el-table-column prop="publisher" label="发布方" min-width="140" />
        <el-table-column label="版本" min-width="130"><template #default="{ row }">{{ row.current_version ? '当前文档' : '历史文档' }} · {{ row.vendor_version || '未提供版本号' }}</template></el-table-column>
        <el-table-column label="声明" min-width="140"><template #default="{ row }">{{ row.cve_count }} CVE / {{ row.rule_count }} 条明确包状态</template></el-table-column>
        <el-table-column label="操作" min-width="160"><template #default="{ row }"><el-button link @click="openAdvisory(row)">查看原件记录</el-button></template></el-table-column>
      </el-table>
      <el-pagination v-model:current-page="advisories.page" :total="advisories.total" :page-size="20" layout="prev, pager, next" @current-change="loadAdvisories" />
    </el-dialog>
    <el-dialog :model-value="!!advisoryDetail" title="厂商公告原件记录" :width="compact ? 'calc(100% - 24px)' : '680px'" @close="advisoryDetail = null">
      <template v-if="advisoryDetail">
        <el-alert :title="advisoryDetail.verification" type="info" :closable="false" />
        <p>{{ advisoryDetail.document_id }} · {{ advisoryDetail.publisher }} · {{ types[advisoryDetail.format] }}</p>
        <p>{{ advisoryDetail.title }}</p>
        <p>传输来源：{{ advisoryDetail.origin_kind === 'official_https' ? '官方 HTTPS 地址' : '部署配置的镜像地址' }}</p>
        <p class="digest">{{ advisoryDetail.origin }}</p>
        <p>归档 {{ date(advisoryDetail.imported_at) }} · {{ packageSize(advisoryDetail.size_bytes) }}</p>
        <p>SHA-256</p><p class="digest">{{ advisoryDetail.sha256 }}</p>
        <p>{{ advisoryDetail.cve_count }} 条 CVE 声明；{{ advisoryDetail.rule_count }} 条包状态规则。修复版本本身不表示所有更早版本受影响，KB 和构建号也不表示主机已安装补丁。</p>
        <p class="digest">当前由此原件贡献的 CVE（最多显示 200 条）：{{ advisoryDetail.contributions?.join('、') || '无当前贡献' }}</p>
        <el-alert v-if="advisoryDownloadError" :title="advisoryDownloadError" type="error" :closable="false" />
        <el-button v-if="advisoryDetail.raw_available" :loading="advisoryDownloading" @click="downloadAdvisory">下载原件并校验摘要</el-button>
        <p v-else>原件已按保留策略清理，原始摘要和导入记录仍保留。</p>
      </template>
    </el-dialog>
    <el-dialog v-model="schedule.visible" title="同步计划" :width="compact ? 'calc(100% - 24px)' : '540px'" :close-on-click-modal="!schedule.saving" :show-close="!schedule.saving">
      <el-form label-width="110px">
        <el-form-item label="数据源">{{ schedule.id }}</el-form-item>
        <el-form-item label="自动同步"><el-switch v-model="schedule.enabled" :disabled="schedule.saving || !!schedule.issue && !schedule.enabled" /></el-form-item>
        <el-form-item label="检查间隔">
          <el-input-number v-model="schedule.minutes" :min="schedule.minimum" :max="10080" :precision="0" :disabled="schedule.saving" />
          <span style="margin-left:8px">分钟</span>
        </el-form-item>
      </el-form>
      <el-alert v-if="schedule.issue" :title="schedule.issue" type="warning" :closable="false" show-icon />
      <el-alert v-if="schedule.type === 'malwarebazaar' && schedule.minutes > 60" title="该来源只覆盖最近 60 分钟，当前检查间隔可能遗漏情报。建议每 30 分钟检查。" type="warning" :closable="false" show-icon />
      <p class="hint">暂停后停止发起新任务，正在执行的任务会继续完成，已入库数据保留。控制台计划会保存在数据库中，重启后继续生效。</p>
      <template #footer>
        <el-button v-if="schedule.overridden" :disabled="schedule.saving" @click="saveSchedule(true)">恢复部署配置</el-button>
        <el-button :disabled="schedule.saving" @click="schedule.visible = false">取消</el-button>
        <el-button type="primary" :loading="schedule.saving" :disabled="!Number.isInteger(schedule.minutes) || schedule.enabled && !!schedule.issue" @click="saveSchedule(false)">保存</el-button>
      </template>
    </el-dialog>
    <el-dialog v-model="history.visible" :title="`${history.id} · 最近执行记录`" :width="compact ? 'calc(100% - 24px)' : '850px'">
      <el-button :loading="history.loading" @click="loadHistory">刷新记录</el-button>
      <el-alert v-if="history.error" :title="history.error" type="error" :closable="false" show-icon />
      <el-table v-loading="history.loading" :data="history.rows" stripe style="margin-top:12px" empty-text="暂无执行记录">
        <el-table-column label="触发方式" width="100"><template #default="{ row }">{{ row.trigger_type === 'scheduled' ? '定时' : '手动' }}</template></el-table-column>
        <el-table-column label="开始时间" min-width="170"><template #default="{ row }">{{ date(row.started_at) }}</template></el-table-column>
        <el-table-column label="结束时间" min-width="170"><template #default="{ row }">{{ date(row.finished_at) }}</template></el-table-column>
        <el-table-column label="结果" width="100"><template #default="{ row }">{{ runStatus[row.status] || row.status }}</template></el-table-column>
        <el-table-column prop="entry_count" label="有效条目" width="100" />
        <el-table-column prop="error" label="说明" min-width="220" />
      </el-table>
      <p class="hint">每个来源保留最近 50 次执行。成功检查表示本次同步完成，特征内容没有变化时不会重复发布。</p>
    </el-dialog>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { fetchLibraries, fetchLibraryCves, fetchLibraryDeclarations, decideLibraryCve, retireLibrarySource, fetchLibraryGovernance, synchronizeLibrary, updateLibrarySchedule, resetLibrarySchedule, fetchLibraryRuns, fetchVendorAdvisories, fetchVendorAdvisory, downloadVendorAdvisory, importCveLibrary, importVirusDb, getUser } from '../api'
import VulnerabilityEvidence from '../components/VulnerabilityEvidence.vue'

const state = ref({ sources: [], signature: {} })
const advisories = ref({ visible: false, id: '', rows: [], total: 0, page: 1, state: {}, loading: false, error: '' })
const advisoryDetail = ref(null), advisoryDownloadError = ref(''), advisoryDownloading = ref(false)
let advisoryRequest = 0
async function showAdvisories(id) {
  advisoryRequest++; advisoryDetail.value = null
  advisories.value = { visible: true, id, rows: [], total: 0, page: 1, state: {}, loading: false, error: '' }
  await loadAdvisories()
}
async function loadAdvisories() {
  const id = advisories.value.id, request = ++advisoryRequest
  advisories.value.loading = true; advisories.value.error = ''
  try { const data = await fetchVendorAdvisories(id, advisories.value.page); if (request === advisoryRequest) Object.assign(advisories.value, { rows: data.items, total: data.total, state: data.state }) }
  catch (e) { if (request === advisoryRequest) advisories.value.error = e.message }
  finally { if (request === advisoryRequest) advisories.value.loading = false }
}
async function openAdvisory(row) {
  const id = advisories.value.id, request = ++advisoryRequest
  advisoryDownloadError.value = ''
  try { const data = await fetchVendorAdvisory(id, row.id); if (request === advisoryRequest && advisories.value.visible) advisoryDetail.value = data }
  catch (e) { if (request === advisoryRequest) advisories.value.error = e.message }
}
async function downloadAdvisory() {
  const document = advisoryDetail.value, id = advisories.value.id
  advisoryDownloading.value = true; advisoryDownloadError.value = ''
  try { await downloadVendorAdvisory(id, document) }
  catch (e) { if (advisoryDetail.value?.id === document.id) advisoryDownloadError.value = e.message }
  finally { advisoryDownloading.value = false }
}

const showRules = ref(false), ruleRows = ref([]), rulesKeyword = ref(''), rulesPage = ref(1), rulesTotal = ref(0), rulesLoading = ref(false), rulesError = ref(''), ruleDetail = ref(null)
const declarations = ref([]), declarationsError = ref(''), declarationsLoading = ref(false), declarationDetail = ref(null)
const governanceBusy = ref(false), governanceEvent = ref(null)
const governance = ref({ visible: false, id: '', rows: [], page: 1, total: 0, error: '', loading: false })
const governanceOperations = { import: '导入声明', withdraw: '本地撤销', reinstate: '本地恢复', retire: '来源退役' }
const declarationState = item => item.retired ? '来源已退役' : item.locally_withdrawn ? '本地已撤销' : item.document?.status === 'withdrawn' ? '上游已撤销' : '有效声明'
let declarationRequest = 0
function closeRule() { declarationRequest++; ruleDetail.value = null }
async function openRule(row) {
  const request = ++declarationRequest
  ruleDetail.value = row; declarations.value = []; declarationsError.value = ''; declarationsLoading.value = true
  try { const data = await fetchLibraryDeclarations(row.cve_id); if (request === declarationRequest && ruleDetail.value?.cve_id === row.cve_id) declarations.value = data }
  catch (e) { if (request === declarationRequest && ruleDetail.value?.cve_id === row.cve_id) declarationsError.value = e.message }
  finally { if (request === declarationRequest && ruleDetail.value?.cve_id === row.cve_id) declarationsLoading.value = false }
}
async function decide(item) {
  const withdraw = !item.locally_withdrawn
  try {
    const { value } = await ElMessageBox.prompt(`${item.source_id} · ${item.cve_id}：填写${withdraw ? '撤销' : '恢复'}原因。撤销将阻止当前比对并使关联补丁复核失效。`, withdraw ? '撤销公告声明' : '恢复公告声明', { inputValidator: v => !!v?.trim() && v.trim().length <= 2000 || '请填写 1 至 2000 字原因', confirmButtonText: '确认', cancelButtonText: '取消' })
    governanceBusy.value = true
    await decideLibraryCve(item.source_id, item.cve_id, { withdraw, documentDigest: item.documentDigest, note: value })
    await loadRules(); await load()
    if (ruleDetail.value?.cve_id === item.cve_id) { const row = ruleRows.value.find(r => r.cve_id === item.cve_id); if (row) await openRule(row) }
    ElMessage.success(withdraw ? '声明已撤销，历史依据保留' : '本地声明已恢复，请重新扫描并复核补丁')
  } catch (e) { if (e !== 'cancel' && e !== 'close') ElMessage.error(e.message || '治理操作失败') }
  finally { governanceBusy.value = false }
}
async function retire(row) {
  try {
    const { value } = await ElMessageBox.prompt(`确认退役 ${row.id}：其当前数据将退出有效库，历史保留。该标识不能恢复同步；最后一个特征来源退役时将向 Agent 发布清空版本。请填写原因。`, '退役安全来源', { inputValidator: v => !!v?.trim() && v.trim().length <= 2000 || '请填写 1 至 2000 字原因', confirmButtonText: '确认退役', cancelButtonText: '取消' })
    governanceBusy.value = true; await retireLibrarySource(row.id, value); await load(); await loadRules()
    ElMessage.success('来源已退役，新库按现有更新流程送达 Agent')
  } catch (e) { if (e !== 'cancel' && e !== 'close') ElMessage.error(e.message || '来源退役失败') }
  finally { governanceBusy.value = false }
}
async function showGovernance(id) {
  governance.value = { visible: true, id, rows: [], page: 1, total: 0, error: '', loading: false }; await loadGovernance()
}
async function loadGovernance() {
  const { id, page } = governance.value; governance.value.loading = true
  try {
    const data = await fetchLibraryGovernance(id, page)
    if (governance.value.id === id && governance.value.page === page) { governance.value.rows = data.list || []; governance.value.total = Number(data.total || 0); governance.value.error = '' }
  } catch (e) { if (governance.value.id === id && governance.value.page === page) governance.value.error = e.message }
  finally { if (governance.value.id === id && governance.value.page === page) governance.value.loading = false }
}
async function loadRules() {
  rulesLoading.value = true
  try {
    const data = await fetchLibraryCves({ keyword: rulesKeyword.value, page: rulesPage.value })
    ruleRows.value = data.list || []; rulesTotal.value = Number(data.total || 0); rulesError.value = ''
  } catch (e) { rulesError.value = e.message }
  finally { rulesLoading.value = false }
}
const loading = ref(false), uploading = ref(false), syncing = ref(false), error = ref('')
const signatureInput = ref(), cveInput = ref()
const schedule = ref({ visible: false, saving: false })
const history = ref({ visible: false, id: '', rows: [], loading: false, error: '' })
const viewport = window.matchMedia('(max-width: 640px)')
const compact = ref(viewport.matches)
const updateViewport = () => { compact.value = viewport.matches }
const user = getUser()
const role = user?.role ?? user?.roleName
const isAdmin = role === 'admin'
const canImport = isAdmin || role === 'operator'
const types = { 'ubuntu-usn': 'Ubuntu USN', 'debian-tracker': 'Debian Security Tracker', 'redhat-csaf': 'Red Hat CSAF 2.0', 'msrc-cvrf': 'Microsoft CVRF 3.0', hashes: '恶意文件哈希', 'signature-zip': '病毒特征包', malwarebazaar: 'MalwareBazaar', misp: 'MISP 文件情报', 'cve-json': '漏洞比对规则', nvd: 'NVD 漏洞信息' }
const runStatus = { success: '成功', failed: '失败', running: '执行中', interrupted: '重启中断' }
const date = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
const packageSize = value => Number.isFinite(Number(value)) && Number(value) > 0 ? `${(Number(value) / 1024).toFixed(1)} KiB` : '—'
const nextCheck = value => !value ? '已暂停' : new Date(value).getTime() <= Date.now() ? '等待调度' : date(value)
let timer
function editSchedule(row) {
  schedule.value = { visible: true, saving: false, id: row.id, type: row.type, enabled: row.enabled, minutes: Math.ceil(row.intervalMs / 60000), minimum: row.minIntervalMs / 60000, overridden: row.scheduleOverridden, issue: row.configurationIssue }
}
async function saveSchedule(reset) {
  schedule.value.saving = true
  try {
    if (reset) await resetLibrarySchedule(schedule.value.id)
    else await updateLibrarySchedule(schedule.value.id, { enabled: schedule.value.enabled, intervalMs: schedule.value.minutes * 60000 })
    ElMessage.success(reset ? '已恢复部署配置中的同步计划' : '同步计划已保存')
    schedule.value.visible = false
    await load()
  } catch (e) { ElMessage.error(e.message) }
  finally { schedule.value.saving = false }
}
async function showHistory(id) {
  history.value = { visible: true, id, rows: [], loading: false, error: '' }
  await loadHistory()
}
async function loadHistory() {
  const id = history.value.id
  history.value.loading = true
  try {
    const rows = await fetchLibraryRuns(id)
    if (history.value.id === id) { history.value.rows = rows; history.value.error = '' }
  } catch (e) { if (history.value.id === id) history.value.error = e.message }
  finally { if (history.value.id === id) history.value.loading = false }
}
async function load() {
  if (loading.value) return
  loading.value = true
  try { state.value = await fetchLibraries(); error.value = '' }
  catch (e) { error.value = e.message }
  finally { loading.value = false }
}
async function synchronize(id) {
  syncing.value = true
  try {
    const result = await synchronizeLibrary(id)
    ElMessage({ message: result.accepted ? '同步任务已提交' : '已有同步任务正在执行', type: result.accepted ? 'success' : 'info' })
    await load()
  } catch (e) { ElMessage.error(e.message) }
  finally { syncing.value = false }
}
async function importFile(event, kind) {
  const file = event.target.files?.[0]
  if (!file) return
  uploading.value = true
  try {
    if (kind === 'signature') await importVirusDb(file)
    else await importCveLibrary(file)
    ElMessage.success('安全库已导入')
    await load()
  } catch (e) { ElMessage.error(e.message) }
  finally { uploading.value = false; event.target.value = '' }
}
onMounted(() => { load(); timer = setInterval(load, 5000); viewport.addEventListener('change', updateViewport) })
onUnmounted(() => { clearInterval(timer); viewport.removeEventListener('change', updateViewport) })
</script>

<style scoped>
.declaration { border-top: 1px solid #e2e8f0; padding: 12px 0; }
.digest { overflow-wrap: anywhere; }
.document-description { white-space: pre-wrap; overflow-wrap: anywhere; }
.original-document { max-height: 360px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; }
.hint { color: #64748b; font-size: 12px; line-height: 1.8; }
</style>

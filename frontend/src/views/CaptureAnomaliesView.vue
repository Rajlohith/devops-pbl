<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { analyticsApi } from '@/api/analytics'
import AnalyticsFilters from '@/components/analytics/AnalyticsFilters.vue'
import AnalyticsTable from '@/components/analytics/AnalyticsTable.vue'
import PacketRefs from '@/components/analytics/PacketRefs.vue'
import SeverityBadge from '@/components/analytics/SeverityBadge.vue'
import UnavailableNotice from '@/components/analytics/UnavailableNotice.vue'
import ChartCard from '@/components/charts/ChartCard.vue'
import AlertBanner from '@/components/common/AlertBanner.vue'
import AppCard from '@/components/common/AppCard.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import { usePagedList } from '@/composables/usePagedList'
import { useReportDownload } from '@/composables/useReportDownload'
import { useAnalyticsStore } from '@/stores/analytics'
import { SEVERITIES, evidenceValue, label, severityBar } from '@/utils/analytics'
import { num } from '@/utils/format'

const id = useRoute().params.id
const store = useAnalyticsStore()
const exporter = useReportDownload(id)
const summary = computed(() => store.document?.anomalies)
const thresholds = computed(() => store.document?.thresholds ?? {})

const DEFAULTS = { page: 1, severity: '', rule: '', ip: '', order: 'desc' }
const list = usePagedList((params) => analyticsApi.anomalies(id, params), DEFAULTS)
const selected = ref(null)
const selectedRow = computed(() => list.items.value.find((r) => r.finding_id === selected.value) ?? null)

const rules = computed(() => Object.keys(summary.value?.by_rule ?? {}).sort())
const fields = computed(() => [
  { key: 'severity', label: 'Severity', type: 'select', options: [{ value: '', label: 'Any' }, ...SEVERITIES.map((s) => ({ value: s, label: s }))] },
  { key: 'rule', label: 'Rule', type: 'select', options: [{ value: '', label: 'Any' }, ...rules.value.map((r) => ({ value: r, label: label(r) }))] },
  { key: 'ip', label: 'Affected IP', type: 'text' },
  { key: 'order', label: 'Severity order', type: 'select', options: [{ value: 'desc', label: 'Highest first' }, { value: 'asc', label: 'Lowest first' }] },
])
const columns = [
  { key: 'severity', label: 'Severity' },
  { key: 'name', label: 'Finding' },
  { key: 'reason', label: 'Why it triggered' },
  { key: 'ips', label: 'Affected addresses' },
]
const chart = computed(() => severityBar(summary.value?.by_severity))
const exportParams = computed(() => ({ ...list.applied.value, page: undefined }))

onMounted(() => store.load(id))
</script>

<template>
  <StateBlock v-if="store.loading && !store.document" kind="loading" message="Loading anomaly findings…" />
  <UnavailableNotice v-else-if="store.unavailable" :message="store.error?.message" />
  <StateBlock v-else-if="store.error" kind="error" :message="store.error.message" @retry="store.load(id, { force: true })" />

  <div v-else-if="summary" id="panel-anomalies" class="space-y-4">
    <AlertBanner kind="info" data-testid="anomaly-disclaimer">
      <strong>Findings are heuristics, not proof of malicious activity.</strong> Each comes from a
      threshold rule over measured metrics (no machine learning, no threat intelligence); busy servers,
      administrator scans and misconfigured clients trigger them too.
    </AlertBanner>

    <div class="grid grid-cols-2 gap-4 md:grid-cols-5">
      <StatCard label="Findings" :value="num(summary.total)" />
      <StatCard v-for="s in SEVERITIES" :key="s" :label="`${s} severity`" :value="num(summary.by_severity[s])" />
    </div>
    <ChartCard title="Findings by severity" :config="chart" aria-label="Bar chart of anomaly findings by severity" empty-text="No findings: no rule's threshold was reached." />

    <AnalyticsTable
      title="Findings" subtitle="Click a row for evidence and the reason it triggered"
      :columns="columns" :rows="list.items.value" row-key="finding_id" :loading="list.loading.value"
      :error="list.error.value" :page="list.applied.value.page" :per-page="list.perPage" :total="list.total.value"
      clickable :selected-key="selected" empty-text="No findings match the current filters."
      @update:page="list.setPage" @row-click="(r) => (selected = r.finding_id)" @retry="list.reload()"
    >
      <template #actions>
        <button type="button" class="btn btn-secondary" :disabled="Boolean(exporter.busy.value)"
          @click="exporter.download('anomalies', '/export/anomalies.csv', exportParams)">Export CSV</button>
      </template>
      <template #filters>
        <AnalyticsFilters :fields="fields" :model-value="list.applied.value" @apply="list.apply" @reset="list.reset" />
        <p v-if="exporter.error.value" class="px-3 pb-2 text-xs text-red-700" role="alert">{{ exporter.error.value }}</p>
      </template>
      <template #cell-severity="{ row }"><SeverityBadge :severity="row.severity" /></template>
      <template #cell-reason="{ row }"><span class="text-xs">{{ row.reason }}</span></template>
      <template #cell-ips="{ row }"><span class="font-mono text-xs">{{ row.affected_ips.join(', ') || '—' }}</span></template>
    </AnalyticsTable>

    <AppCard v-if="selectedRow" :title="selectedRow.name" :subtitle="`Rule: ${selectedRow.rule}`" data-testid="anomaly-detail">
      <div class="space-y-3 text-sm">
        <p><SeverityBadge :severity="selectedRow.severity" class="mr-2" />{{ selectedRow.description }}</p>
        <p><span class="label mb-0 inline">Reason</span> {{ selectedRow.reason }}</p>
        <dl class="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-3">
          <div v-for="(value, key) in selectedRow.evidence" :key="key"><dt class="label">{{ label(key) }}</dt><dd class="break-all">{{ evidenceValue(value) }}</dd></div>
        </dl>
        <p class="text-xs text-slate-600"><span class="font-medium">Thresholds used:</span>
          {{ Object.entries(selectedRow.thresholds).map(([k, v]) => `${k} = ${v}`).join(', ') }}</p>
        <p class="text-xs text-slate-600"><span class="font-medium">Affected addresses:</span> <span class="font-mono">{{ selectedRow.affected_ips.join(', ') || 'none' }}</span>
          · <span class="font-medium">flows:</span> {{ selectedRow.affected_flows.join(', ') || 'none' }}</p>
        <PacketRefs :capture-id="id" :packets="selectedRow.packet_refs" :flow-id="selectedRow.affected_flows[0] ?? null" />
        <p class="text-xs italic text-slate-500">{{ selectedRow.note }}</p>
      </div>
    </AppCard>

    <details class="text-xs text-slate-500">
      <summary class="cursor-pointer text-blue-700">Thresholds used for this capture</summary>
      <p class="mt-1 font-mono">{{ Object.entries(thresholds).map(([k, v]) => `${k}=${v}`).join(' · ') }}</p>
    </details>
  </div>
</template>

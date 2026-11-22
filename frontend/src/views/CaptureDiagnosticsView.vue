<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { analyticsApi } from '@/api/analytics'
import AnalyticsFilters from '@/components/analytics/AnalyticsFilters.vue'
import AnalyticsTable from '@/components/analytics/AnalyticsTable.vue'
import MetricNote from '@/components/analytics/MetricNote.vue'
import PacketRefs from '@/components/analytics/PacketRefs.vue'
import SeverityBadge from '@/components/analytics/SeverityBadge.vue'
import UnavailableNotice from '@/components/analytics/UnavailableNotice.vue'
import ChartCard from '@/components/charts/ChartCard.vue'
import AlertBanner from '@/components/common/AlertBanner.vue'
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { usePagedList } from '@/composables/usePagedList'
import { useReportDownload } from '@/composables/useReportDownload'
import { useAnalyticsStore } from '@/stores/analytics'
import { countBar, evidenceValue, label, pct, senderLabel } from '@/utils/analytics'
import { DASH, bytes, num } from '@/utils/format'

const id = useRoute().params.id
const store = useAnalyticsStore()
const exporter = useReportDownload(id)
const diag = computed(() => store.document?.diagnostics)
const win = computed(() => store.document?.windows)
const defs = computed(() => store.document?.definitions ?? {})
const types = computed(() => diag.value?.indicator_types ?? {})

const DEFAULTS = { page: 1, type: '', severity: '', connection_id: '', sort: 'severity', order: 'desc' }
const list = usePagedList((params) => analyticsApi.indicators(id, params), DEFAULTS)
const windows = useAsyncData(() => analyticsApi.windows(id))
const selected = ref(null)
const selectedRow = computed(() => list.items.value.find((r) => r.indicator_id === selected.value) ?? null)

const choose = (values) => [{ value: '', label: 'Any' }, ...values.map((v) => ({ value: v, label: label(v) }))]
const fields = [
  { key: 'type', label: 'Indicator', type: 'select', options: choose(['retransmission', 'duplicate_ack', 'sequence_gap', 'out_of_order', 'partial_overlap']) },
  { key: 'severity', label: 'Severity', type: 'select', options: choose(['high', 'medium', 'low', 'info']) },
  { key: 'connection_id', label: 'Connection #', type: 'text' },
  { key: 'sort', label: 'Sort by', type: 'select', options: ['severity', 'count', 'connection'].map((v) => ({ value: v, label: label(v) })) },
  { key: 'order', label: 'Order', type: 'select', options: [{ value: 'desc', label: 'Descending' }, { value: 'asc', label: 'Ascending' }] },
]
const columns = [
  { key: 'connection_id', label: 'Conn.' },
  { key: 'type', label: 'Indicator' },
  { key: 'sender', label: 'Sent by' },
  { key: 'packet_count', label: 'Packets', align: 'right' },
  { key: 'severity', label: 'Severity' },
  { key: 'confidence', label: 'Confidence' },
]
const windowColumns = [
  { key: 'connection_id', label: 'Conn.' },
  { key: 'scaling', label: 'Window scaling' },
  { key: 'a', label: 'Endpoint A advertised (min / max / last)' },
  { key: 'b', label: 'Endpoint B advertised (min / max / last)' },
  { key: 'zero', label: 'Zero-window events', align: 'right' },
]

const indicatorChart = computed(() => countBar(Object.fromEntries(Object.entries(types.value).map(([k, v]) => [k, v.events])), 'Events'))
const scalingChart = computed(() => countBar(win.value?.scaling_status, 'Connections'))

/** "min / max / last" for one side, using effective (scaled) bytes when known, else raw values. */
function sideText(side) {
  if (!side || side.samples === 0) return DASH
  const eff = side.effective
  const v = eff || side.raw
  const unit = eff ? ' B' : ' (raw, scale unknown)'
  return `${num(v.min)} / ${num(v.max)} / ${num(v.last)}${unit}`
}
const exportParams = computed(() => ({ ...list.applied.value, page: undefined }))

onMounted(() => {
  store.load(id)
  windows.load()
})
</script>

<template>
  <StateBlock v-if="store.loading && !store.document" kind="loading" message="Loading TCP diagnostics…" />
  <UnavailableNotice v-else-if="store.unavailable" :message="store.error?.message" />
  <StateBlock v-else-if="store.error" kind="error" :message="store.error.message" @retry="store.load(id, { force: true })" />

  <div v-else-if="diag" id="panel-diagnostics" class="space-y-4">
    <AlertBanner kind="info" data-testid="loss-disclaimer">
      <strong>These are indicators, not measured packet loss.</strong> A single capture cannot show whether
      packets were lost in the network, so NetScope reports no loss percentage.
    </AlertBanner>

    <div class="grid grid-cols-2 gap-4 md:grid-cols-4">
      <StatCard label="Packet loss" value="Not measurable" hint="from a single capture" />
      <StatCard label="Retransmissions" :value="num(diag.retransmission_packets)" :hint="`${pct(diag.retransmission_rate, 2)} of ${num(diag.tcp_packets)} TCP packets (indicator)`" />
      <StatCard label="Duplicate ACKs" :value="num(types.duplicate_ack?.events ?? 0)" :hint="`${num(types.duplicate_ack?.connections ?? 0)} connections`" />
      <StatCard label="Sequence gaps" :value="num(types.sequence_gap?.events ?? 0)" :hint="`${num(types.sequence_gap?.connections ?? 0)} connections`" />
      <StatCard label="Connections with indicators" :value="num(diag.connections_with_indicators)" :hint="`of ${num(diag.tcp_connections)} tracked`" />
      <StatCard label="Zero-window connections" :value="num(win.connections_with_zero_window)" />
      <StatCard label="Zero-window events" :value="num(win.zero_window_events)" />
      <StatCard label="Largest effective window" :value="win.max_effective_window_bytes === null ? 'Unknown' : bytes(win.max_effective_window_bytes)" :hint="win.max_effective_window_bytes === null ? 'window scale not captured' : `known for ${num(win.effective_window_available_for)} directions`" />
    </div>
    <MetricNote :text="defs.packet_loss_indicators" />

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <ChartCard title="Indicator events" :config="indicatorChart" aria-label="Bar chart of TCP loss-indicator events by type" empty-text="No indicators observed." />
      <ChartCard title="Window scaling status" subtitle="Connections by what the handshake showed" :config="scalingChart" aria-label="Bar chart of connections by window-scaling status" empty-text="No TCP connections." />
    </div>

    <AnalyticsTable
      title="Loss indicators" subtitle="Per connection and sending direction"
      :columns="columns" :rows="list.items.value" row-key="indicator_id" :loading="list.loading.value"
      :error="list.error.value" :page="list.applied.value.page" :per-page="list.perPage" :total="list.total.value"
      clickable :selected-key="selected" empty-text="No indicators match the current filters."
      @update:page="list.setPage" @row-click="(r) => (selected = r.indicator_id)" @retry="list.reload()"
    >
      <template #actions>
        <button type="button" class="btn btn-secondary" :disabled="Boolean(exporter.busy.value)"
          @click="exporter.download('tcp-indicators', '/export/tcp-indicators.csv', exportParams)">Export CSV</button>
      </template>
      <template #filters>
        <AnalyticsFilters :fields="fields" :model-value="list.applied.value" @apply="list.apply" @reset="list.reset" />
        <p v-if="exporter.error.value" class="px-3 pb-2 text-xs text-red-700" role="alert">{{ exporter.error.value }}</p>
      </template>
      <template #cell-type="{ row }">{{ label(row.type) }}</template>
      <template #cell-sender="{ row }">{{ senderLabel(row.sender) }}</template>
      <template #cell-severity="{ row }"><SeverityBadge :severity="row.severity" /></template>
    </AnalyticsTable>

    <AppCard v-if="selectedRow" :title="`${label(selectedRow.type)} · connection ${selectedRow.connection_id}`" subtitle="Supporting evidence" data-testid="indicator-detail">
      <p class="text-sm text-slate-600">{{ selectedRow.endpoint_a }} ↔ {{ selectedRow.endpoint_b }}</p>
      <dl class="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-4">
        <div v-for="(value, key) in selectedRow.detail" :key="key"><dt class="label">{{ label(key) }}</dt><dd>{{ evidenceValue(value) }}</dd></div>
      </dl>
      <ul class="mt-2 space-y-1 font-mono text-xs text-slate-700">
        <li v-for="(ev, i) in selectedRow.evidence" :key="i">{{ Object.entries(ev).map(([k, v]) => `${k}=${evidenceValue(v)}`).join('  ') }}</li>
      </ul>
      <p v-if="selectedRow.packet_count > selectedRow.evidence.length" class="mt-1 text-xs text-slate-500">
        Showing the first {{ selectedRow.evidence.length }} of {{ num(selectedRow.packet_count) }} packets.
      </p>
      <div class="mt-2"><PacketRefs :capture-id="id" :packets="selectedRow.evidence.map((e) => e.packet)" :flow-id="selectedRow.flow_id" /></div>
    </AppCard>

    <AppCard title="Advertised receive windows" subtitle="Connections that advertised a zero window" flush>
      <StateBlock v-if="windows.loading.value && !windows.data.value" kind="loading" />
      <StateBlock v-else-if="windows.error.value" kind="error" :message="windows.error.value.message" @retry="windows.load()" />
      <StateBlock v-else-if="!windows.data.value?.zero_window_connections.length" kind="empty" message="No zero-window advertisements were observed." />
      <DataTable v-else :columns="windowColumns" :rows="windows.data.value.zero_window_connections" row-key="connection_id" caption="Zero-window connections">
        <template #cell-scaling="{ row }">{{ label(row.window_scaling) }}</template>
        <template #cell-a="{ row }"><span class="font-mono text-xs">{{ sideText(row.window.a) }}</span></template>
        <template #cell-b="{ row }"><span class="font-mono text-xs">{{ sideText(row.window.b) }}</span></template>
        <template #cell-zero="{ row }">
          {{ num(row.zero_window_events) }}
          <span class="block font-mono text-xs text-slate-500">pkts {{ [...row.window.a.zero_window_evidence, ...row.window.b.zero_window_evidence].join(', ') }}</span>
        </template>
      </DataTable>
      <p class="px-4 py-2 text-xs text-slate-500">When the handshake was not captured the scale factor is unknown: raw advertised values are shown and no effective size is computed.</p>
    </AppCard>
    <MetricNote :text="defs.tcp_window" />
  </div>
</template>

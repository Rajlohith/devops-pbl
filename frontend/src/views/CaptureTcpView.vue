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
import AppCard from '@/components/common/AppCard.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { usePagedList } from '@/composables/usePagedList'
import { useReportDownload } from '@/composables/useReportDownload'
import { useAnalyticsStore } from '@/stores/analytics'
import {
  TCP_STATES, TERMINATIONS, histogramBar, label, msOrDash, pct, secondsOrDash, senderLabel,
  stateDoughnut, stateTone,
} from '@/utils/analytics'
import { DASH, endpoint, num } from '@/utils/format'

const id = useRoute().params.id
const store = useAnalyticsStore()
const exporter = useReportDownload(id)
const tcp = computed(() => store.document?.tcp)
const resets = computed(() => store.document?.resets)
const defs = computed(() => store.document?.definitions ?? {})

const DEFAULTS = {
  page: 1, state: '', termination: '', ip: '', port: '', has_reset: false, truncated: false,
  sort: 'start', order: 'asc',
}
const list = usePagedList((params) => analyticsApi.connections(id, params), DEFAULTS)
const detail = useAsyncData((connectionId) => analyticsApi.connection(id, connectionId))
const selected = ref(null)

const options = (values) => [{ value: '', label: 'Any' }, ...values.map((v) => ({ value: v, label: label(v) }))]
const fields = [
  { key: 'state', label: 'State', type: 'select', options: options(TCP_STATES) },
  { key: 'termination', label: 'Termination', type: 'select', options: options(TERMINATIONS) },
  { key: 'ip', label: 'IP address', type: 'text' },
  { key: 'port', label: 'Port', type: 'text' },
  { key: 'has_reset', label: 'Has reset', type: 'checkbox' },
  { key: 'truncated', label: 'Capture-truncated', type: 'checkbox' },
  {
    key: 'sort', label: 'Sort by', type: 'select',
    options: ['start', 'duration', 'handshake', 'packets', 'bytes', 'resets'].map((v) => ({ value: v, label: label(v) })),
  },
  { key: 'order', label: 'Order', type: 'select', options: [{ value: 'asc', label: 'Ascending' }, { value: 'desc', label: 'Descending' }] },
]
const columns = [
  { key: 'connection_id', label: '#' },
  { key: 'endpoints', label: 'Endpoint A → B' },
  { key: 'state', label: 'State' },
  { key: 'handshake_ms', label: 'Handshake', align: 'right' },
  { key: 'duration_seconds', label: 'Observed lifetime', align: 'right' },
  { key: 'termination', label: 'Ended by' },
  { key: 'rst_packets', label: 'RST', align: 'right' },
  { key: 'packets', label: 'Packets', align: 'right' },
]

function select(row) {
  selected.value = row.connection_id
  detail.load(row.connection_id)
}

const stateChart = computed(() => (tcp.value?.total_connections ? stateDoughnut(tcp.value.states) : null))
const handshakeChart = computed(() => histogramBar(tcp.value?.charts.handshake_histogram, 'Connections'))
const lifetimeChart = computed(() => histogramBar(tcp.value?.charts.lifetime_histogram, 'Connections'))
const exportParams = computed(() => ({ ...list.applied.value, page: undefined }))

onMounted(() => store.load(id))
</script>

<template>
  <StateBlock v-if="store.loading && !store.document" kind="loading" message="Loading TCP analytics…" />
  <UnavailableNotice v-else-if="store.unavailable" :message="store.error?.message" />
  <StateBlock v-else-if="store.error" kind="error" :message="store.error.message" @retry="store.load(id, { force: true })" />

  <div v-else-if="tcp" id="panel-tcp" class="space-y-4">
    <div class="grid grid-cols-2 gap-4 md:grid-cols-4">
      <StatCard label="Connection success rate" :value="pct(tcp.success_rate)"
        :hint="tcp.observable_attempts ? `${num(tcp.states.established)} of ${num(tcp.observable_attempts)} observable attempts` : 'no observable attempts'" />
      <StatCard label="Established" :value="num(tcp.states.established)" hint="completed three-way handshake" />
      <StatCard label="Incomplete" :value="num(tcp.states.incomplete)" hint="not confirmed failures" />
      <StatCard label="Refused (confirmed)" :value="num(tcp.states.refused)" hint="SYN answered by RST" />
      <StatCard label="Unclassified" :value="num(tcp.states.unclassified)" hint="start of connection not captured" />
      <StatCard label="Median handshake" :value="msOrDash(tcp.handshake_ms?.median)" :hint="tcp.handshake_ms ? `p95 ${msOrDash(tcp.handshake_ms.p95)}` : 'no completed handshakes'" />
      <StatCard label="Median observed lifetime" :value="secondsOrDash(tcp.lifetime_seconds?.median)" hint="first to last captured packet" />
      <StatCard label="Capture-truncated" :value="num(tcp.capture_truncated_connections)" hint="start or end not captured" />
    </div>
    <MetricNote :text="`${defs.tcp_success_rate} ${defs.tcp_incomplete} ${defs.tcp_refused}`" />

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <ChartCard title="Connection outcomes" :config="stateChart" aria-label="Doughnut chart of TCP connections by state" empty-text="No TCP connections." />
      <ChartCard title="Handshake time" subtitle="First SYN to completing ACK" :config="handshakeChart" aria-label="Histogram of TCP handshake times" empty-text="No completed handshakes." />
      <ChartCard title="Observed lifetime" subtitle="Seconds between first and last captured packet" :config="lifetimeChart" aria-label="Histogram of observed connection lifetimes" empty-text="No connections." />
    </div>
    <MetricNote :text="`${defs.tcp_handshake_ms} ${defs.tcp_observed_duration}`" summary="Handshake and lifetime definitions" />

    <AppCard title="TCP resets" subtitle="Reset packets are counted separately from reset connections">
      <div class="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="RST packets" :value="num(resets.rst_packets)" :hint="`of ${num(resets.tcp_packets)} TCP packets`" />
        <StatCard label="Reset packet rate" :value="pct(resets.packet_rate, 2)" hint="RST packets / TCP packets" />
        <StatCard label="Connections with a reset" :value="num(resets.connections_with_reset)" :hint="`of ${num(resets.tcp_connections)} tracked`" />
        <StatCard label="Reset connection rate" :value="pct(resets.connection_rate, 2)" hint="reset connections / tracked connections" />
      </div>
      <p class="mt-3 text-xs text-slate-600" data-testid="reset-breakdown">
        Reset before establishment: {{ num(resets.reset_before_established) }} · after establishment:
        {{ num(resets.reset_after_established) }} · handshake not captured: {{ num(resets.reset_unclassified) }}
      </p>
      <ul v-if="resets.top_senders.length" class="mt-2 text-xs text-slate-600">
        <li v-for="s in resets.top_senders.slice(0, 5)" :key="s.ip" class="font-mono">{{ s.ip }} sent {{ num(s.rst_packets) }} RST</li>
      </ul>
      <div class="mt-2"><MetricNote :text="`${defs.tcp_reset_packet_rate} ${defs.tcp_reset_connection_rate}`" /></div>
    </AppCard>

    <AnalyticsTable
      title="Connections" subtitle="Click a row for handshake timing, window and diagnostics"
      :columns="columns" :rows="list.items.value" row-key="connection_id" :loading="list.loading.value"
      :error="list.error.value" :page="list.applied.value.page" :per-page="list.perPage" :total="list.total.value"
      clickable :selected-key="selected" @update:page="list.setPage" @row-click="select" @retry="list.reload()"
    >
      <template #actions>
        <button type="button" class="btn btn-secondary" :disabled="Boolean(exporter.busy.value)"
          @click="exporter.download('tcp-connections', '/export/tcp-connections.csv', exportParams)">
          {{ exporter.busy.value === 'tcp-connections' ? 'Preparing…' : 'Export CSV' }}
        </button>
      </template>
      <template #filters>
        <AnalyticsFilters :fields="fields" :model-value="list.applied.value" @apply="list.apply" @reset="list.reset" />
        <p v-if="exporter.error.value" class="px-3 pb-2 text-xs text-red-700" role="alert">{{ exporter.error.value }}</p>
      </template>
      <template #cell-endpoints="{ row }">
        <span class="font-mono text-xs">{{ endpoint(row.endpoint_a.ip, row.endpoint_a.port) }} → {{ endpoint(row.endpoint_b.ip, row.endpoint_b.port) }}</span>
      </template>
      <template #cell-state="{ row }">
        <span class="badge" :class="stateTone(row.state)">{{ row.state }}</span>
        <span v-if="row.incomplete_reason" class="ml-1 text-xs text-slate-500">{{ label(row.incomplete_reason) }}</span>
      </template>
      <template #cell-handshake_ms="{ row }">{{ msOrDash(row.handshake_ms) }}</template>
      <template #cell-duration_seconds="{ row }">
        {{ secondsOrDash(row.duration_seconds) }}
        <span v-if="row.capture_truncated" class="badge bg-slate-100 text-slate-600" title="The capture does not show the start or end of this connection">truncated</span>
      </template>
      <template #cell-termination="{ row }">{{ label(row.termination) }}</template>
    </AnalyticsTable>

    <AppCard v-if="selected !== null" :title="`Connection ${selected}`" subtitle="Detail">
      <StateBlock v-if="detail.loading.value" kind="loading" />
      <StateBlock v-else-if="detail.error.value" kind="error" :message="detail.error.value.message" @retry="detail.load(selected)" />
      <div v-else-if="detail.data.value" class="space-y-3 text-sm" data-testid="connection-detail">
        <dl class="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
          <div><dt class="label">SYN → SYN-ACK</dt><dd>{{ msOrDash(detail.data.value.connection.syn_to_synack_ms) }}</dd></div>
          <div><dt class="label">SYN-ACK → ACK</dt><dd>{{ msOrDash(detail.data.value.connection.synack_to_ack_ms) }}</dd></div>
          <div><dt class="label">Handshake total</dt><dd>{{ msOrDash(detail.data.value.connection.handshake_ms) }}</dd></div>
          <div><dt class="label">SYN retransmissions</dt><dd>{{ num(detail.data.value.connection.syn_retransmissions) }}</dd></div>
          <div><dt class="label">Ended</dt><dd>{{ label(detail.data.value.connection.termination) }} ({{ detail.data.value.connection.terminated_by ? senderLabel(detail.data.value.connection.terminated_by) : DASH }})</dd></div>
          <div><dt class="label">Window scaling</dt><dd>{{ label(detail.data.value.connection.window_scaling) }}</dd></div>
          <div><dt class="label">Zero-window events</dt><dd>{{ num(detail.data.value.connection.zero_window_events) }}</dd></div>
          <div><dt class="label">Truncation</dt><dd>{{ detail.data.value.connection.truncation_reasons.map(label).join(', ') || 'none' }}</dd></div>
        </dl>
        <PacketRefs :capture-id="id" :flow-id="detail.data.value.connection.flow_id"
          :packets="[detail.data.value.connection.syn_packet, ...detail.data.value.connection.rst_evidence.map((e) => e.packet)].filter((p) => p !== null)" />
        <ul v-if="detail.data.value.indicators.length" class="space-y-1">
          <li v-for="ind in detail.data.value.indicators" :key="ind.indicator_id" class="flex items-center gap-2 text-xs">
            <SeverityBadge :severity="ind.severity" />
            {{ label(ind.type) }} from {{ senderLabel(ind.sender) }} · {{ num(ind.packet_count) }} packets · confidence {{ ind.confidence }}
          </li>
        </ul>
        <p v-else class="text-xs text-slate-500">No loss indicators for this connection.</p>
      </div>
    </AppCard>
  </div>
</template>

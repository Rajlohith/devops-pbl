<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { analyticsApi } from '@/api/analytics'
import AnalyticsFilters from '@/components/analytics/AnalyticsFilters.vue'
import AnalyticsTable from '@/components/analytics/AnalyticsTable.vue'
import MetricNote from '@/components/analytics/MetricNote.vue'
import PacketRefs from '@/components/analytics/PacketRefs.vue'
import UnavailableNotice from '@/components/analytics/UnavailableNotice.vue'
import ChartCard from '@/components/charts/ChartCard.vue'
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import { usePagedList } from '@/composables/usePagedList'
import { useReportDownload } from '@/composables/useReportDownload'
import { useAnalyticsStore } from '@/stores/analytics'
import { countBar, histogramBar, label, msOrDash, pct } from '@/utils/analytics'
import { DASH, endpoint, num } from '@/utils/format'

const id = useRoute().params.id
const store = useAnalyticsStore()
const exporter = useReportDownload(id)
const dns = computed(() => store.document?.dns)
const defs = computed(() => store.document?.definitions ?? {})

const DEFAULTS = {
  page: 1, status: '', rcode: '', transport: '', q: '', client_ip: '', server_ip: '',
  min_latency_ms: '', sort: 'time', order: 'asc',
}
const list = usePagedList((params) => analyticsApi.dnsTransactions(id, params), DEFAULTS)
const selected = ref(null)
const selectedRow = computed(() => list.items.value.find((r) => r.transaction_id === selected.value) ?? null)

const choose = (values) => [{ value: '', label: 'Any' }, ...values.map((v) => ({ value: v, label: label(v) }))]
const fields = [
  { key: 'status', label: 'Status', type: 'select', options: choose(['answered', 'unanswered', 'unanswered_inferred_timeout', 'unanswered_indeterminate', 'unmatched_response']) },
  { key: 'rcode', label: 'Response code', type: 'select', options: [{ value: '', label: 'Any' }, ...['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP'].map((v) => ({ value: v, label: v }))] },
  { key: 'transport', label: 'Transport', type: 'select', options: [{ value: '', label: 'Any' }, { value: 'udp', label: 'UDP' }, { value: 'tcp', label: 'TCP' }] },
  { key: 'q', label: 'Name contains', type: 'text' },
  { key: 'client_ip', label: 'Client IP', type: 'text' },
  { key: 'server_ip', label: 'Server IP', type: 'text' },
  { key: 'min_latency_ms', label: 'Min latency (ms)', type: 'text' },
  { key: 'sort', label: 'Sort by', type: 'select', options: ['time', 'latency', 'name', 'retries'].map((v) => ({ value: v, label: label(v) })) },
  { key: 'order', label: 'Order', type: 'select', options: [{ value: 'asc', label: 'Ascending' }, { value: 'desc', label: 'Descending' }] },
]
const columns = [
  { key: 'transaction_id', label: '#' },
  { key: 'name', label: 'Query' },
  { key: 'client', label: 'Client → server' },
  { key: 'latency_ms', label: 'Response time', align: 'right' },
  { key: 'rcode_name', label: 'Response' },
  { key: 'status', label: 'Status' },
]
const serverColumns = [
  { key: 'server_ip', label: 'Server' },
  { key: 'queries', label: 'Queries', align: 'right' },
  { key: 'answered', label: 'Answered', align: 'right' },
  { key: 'errors', label: 'Error responses', align: 'right' },
  { key: 'mean_latency_ms', label: 'Mean response time', align: 'right' },
]

const latencyChart = computed(() => histogramBar(dns.value?.charts.latency_histogram, 'Transactions'))
const rcodeChart = computed(() => countBar(dns.value?.rcodes, 'Responses'))
const statusTone = (s) => (s === 'answered' ? 'bg-green-100 text-green-800' : s === 'unmatched_response' ? 'bg-slate-100 text-slate-700' : 'bg-amber-100 text-amber-800')
const exportParams = computed(() => ({ ...list.applied.value, page: undefined }))

onMounted(() => store.load(id))
</script>

<template>
  <StateBlock v-if="store.loading && !store.document" kind="loading" message="Loading DNS analytics…" />
  <UnavailableNotice v-else-if="store.unavailable" :message="store.error?.message" />
  <StateBlock v-else-if="store.error" kind="error" :message="store.error.message" @retry="store.load(id, { force: true })" />

  <AppCard v-else-if="dns && !dns.available" flush>
    <StateBlock kind="empty" message="No DNS traffic was identified in this capture." />
  </AppCard>

  <div v-else-if="dns" id="panel-dns" class="space-y-4">
    <div class="grid grid-cols-2 gap-4 md:grid-cols-4">
      <StatCard label="DNS queries" :value="num(dns.queries)" :hint="`${num(dns.answered)} answered`" />
      <StatCard label="Median response time" :value="msOrDash(dns.latency_ms?.median)" :hint="dns.latency_ms ? `p95 ${msOrDash(dns.latency_ms.p95)} · n=${num(dns.latency_ms.count)}` : 'no matched transactions'" />
      <StatCard label="Error response rate" :value="pct(dns.error_response_rate)" :hint="`${num(dns.error_responses)} of ${num(dns.responses_observed)} responses (incl. NXDOMAIN)`" />
      <StatCard label="Server failure rate" :value="pct(dns.server_failure_rate)" hint="SERVFAIL, REFUSED, FORMERR… (excl. NXDOMAIN)" />
      <StatCard label="NXDOMAIN rate" :value="pct(dns.nxdomain_rate)" />
      <StatCard label="Inferred timeouts" :value="num(dns.unanswered.inferred_timeout)" hint="unanswered; capture continued past the timeout" />
      <StatCard label="Indeterminate" :value="num(dns.unanswered.indeterminate)" hint="unanswered; capture ended too soon to tell" />
      <StatCard label="Unmatched responses" :value="num(dns.unmatched_responses)" hint="no query observed" />
    </div>
    <MetricNote :text="`${defs.dns_latency} ${defs.dns_failure_rate} ${defs.dns_inferred_timeout}`" />
    <p class="text-xs text-slate-500">
      Retransmitted queries: {{ num(dns.transactions_with_retransmitted_query) }} ·
      duplicate responses ignored: {{ num(dns.duplicate_responses) }} · truncated responses: {{ num(dns.truncated_responses) }}
    </p>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <ChartCard title="Response time" subtitle="Matched transactions" :config="latencyChart" aria-label="Histogram of DNS response times" empty-text="No matched transactions." />
      <ChartCard title="Response codes" :config="rcodeChart" aria-label="Bar chart of DNS response codes" empty-text="No responses observed." />
    </div>

    <AppCard v-if="dns.servers.length" title="Servers" flush>
      <DataTable :columns="serverColumns" :rows="dns.servers" row-key="server_ip" caption="DNS servers">
        <template #cell-mean_latency_ms="{ row }">{{ msOrDash(row.mean_latency_ms) }}</template>
      </DataTable>
    </AppCard>

    <AnalyticsTable
      title="Transactions" subtitle="One row per query and its response"
      :columns="columns" :rows="list.items.value" row-key="transaction_id" :loading="list.loading.value"
      :error="list.error.value" :page="list.applied.value.page" :per-page="list.perPage" :total="list.total.value"
      clickable :selected-key="selected" @update:page="list.setPage" @row-click="(r) => (selected = r.transaction_id)" @retry="list.reload()"
    >
      <template #actions>
        <button type="button" class="btn btn-secondary" :disabled="Boolean(exporter.busy.value)"
          @click="exporter.download('dns-transactions', '/export/dns-transactions.csv', exportParams)">
          {{ exporter.busy.value === 'dns-transactions' ? 'Preparing…' : 'Export CSV' }}
        </button>
      </template>
      <template #filters>
        <AnalyticsFilters :fields="fields" :model-value="list.applied.value" @apply="list.apply" @reset="list.reset" />
        <p v-if="exporter.error.value" class="px-3 pb-2 text-xs text-red-700" role="alert">{{ exporter.error.value }}</p>
      </template>
      <template #cell-name="{ row }">
        <span class="font-mono text-xs break-all">{{ row.qname || DASH }}</span>
        <span v-if="row.qtype" class="ml-1 text-xs text-slate-500">{{ row.qtype }}</span>
        <span v-if="row.question_count > 1" class="ml-1 text-xs text-slate-500">(+{{ row.question_count - 1 }} more)</span>
      </template>
      <template #cell-client="{ row }">
        <span class="font-mono text-xs">{{ endpoint(row.client.ip, row.client.port) }} → {{ endpoint(row.server.ip, row.server.port) }} ({{ row.transport.toUpperCase() }})</span>
      </template>
      <template #cell-latency_ms="{ row }">
        {{ msOrDash(row.latency_ms) }}
        <span v-if="row.query_count > 1" class="text-xs text-slate-500" title="Query was retransmitted">×{{ row.query_count }}</span>
      </template>
      <template #cell-rcode_name="{ row }">{{ row.rcode_name || DASH }}</template>
      <template #cell-status="{ row }">
        <span class="badge" :class="statusTone(row.status)">{{ label(row.status) }}</span>
      </template>
    </AnalyticsTable>

    <AppCard v-if="selectedRow" :title="`Transaction ${selectedRow.transaction_id}`" subtitle="Evidence" data-testid="dns-detail">
      <dl class="grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-4">
        <div><dt class="label">Response time (first query)</dt><dd>{{ msOrDash(selectedRow.latency_ms) }}</dd></div>
        <div><dt class="label">From last (re)transmission</dt><dd>{{ msOrDash(selectedRow.latency_from_last_query_ms) }}</dd></div>
        <div><dt class="label">Query transmissions</dt><dd>{{ num(selectedRow.query_count) }}</dd></div>
        <div><dt class="label">Transaction ID</dt><dd class="font-mono">{{ selectedRow.dns_id }}</dd></div>
      </dl>
      <p v-if="selectedRow.note" class="mt-2 text-xs text-slate-600">{{ selectedRow.note }}</p>
      <ul class="mt-2 text-xs text-slate-600">
        <li v-for="(q, i) in selectedRow.questions" :key="i" class="font-mono">{{ q.name }} {{ q.type }}</li>
      </ul>
      <div class="mt-2">
        <PacketRefs :capture-id="id" :packets="[selectedRow.query_packet, selectedRow.response_packet].filter((p) => p !== null)"
          :filter="{ ip: selectedRow.client.ip, port: String(selectedRow.client.port ?? '') }" />
      </div>
    </AppCard>
  </div>
</template>

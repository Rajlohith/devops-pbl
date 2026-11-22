<script setup>
import { computed, onMounted, reactive, watch } from 'vue'
import { useRoute } from 'vue-router'

import { analyticsApi } from '@/api/analytics'
import MetricNote from '@/components/analytics/MetricNote.vue'
import UnavailableNotice from '@/components/analytics/UnavailableNotice.vue'
import ChartCard from '@/components/charts/ChartCard.vue'
import AlertBanner from '@/components/common/AlertBanner.vue'
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { useReportDownload } from '@/composables/useReportDownload'
import { useRouteQuery } from '@/composables/useRouteQuery'
import { useAnalyticsStore } from '@/stores/analytics'
import { directionDoughnut, label, pctValue, talkersBar } from '@/utils/analytics'
import { bytes, num } from '@/utils/format'

const id = useRoute().params.id
const store = useAnalyticsStore()
const exporter = useReportDownload(id)
const traffic = computed(() => store.document?.traffic)
const defs = computed(() => store.document?.definitions ?? {})

const DEFAULTS = { by: 'bytes', role: 'bidirectional', limit: 10, ip_version: '', local: '' }
const query = useRouteQuery(DEFAULTS, { onUnchanged: () => refresh() })
const talkers = useAsyncData((p) => analyticsApi.talkers(id, p))
const direction = useAsyncData((p) => analyticsApi.direction(id, p))
const draft = reactive({ ...DEFAULTS })

const talkerParams = () => {
  const { by, role, limit, ip_version: ipVersion } = query.applied.value
  return { by, role, limit, ip_version: ipVersion }
}
function refresh() {
  talkers.load(talkerParams())
  direction.load({ local: query.applied.value.local })
}
watch(query.applied, (value) => { Object.assign(draft, value); refresh() }, { immediate: true })

const submit = () => query.apply({ ...draft })
const columns = [
  { key: 'rank', label: '#' },
  { key: 'ip', label: 'Address' },
  { key: 'bytes', label: 'Bytes', align: 'right' },
  { key: 'packets', label: 'Packets', align: 'right' },
  { key: 'share', label: '% of IP bytes', align: 'right' },
  { key: 'sent', label: 'Sent / received', align: 'right' },
]
const talkerChart = computed(() => talkersBar(talkers.data.value?.items))
const directionChart = computed(() => (direction.data.value?.configured ? directionDoughnut(direction.data.value.directions) : null))
const directionRows = computed(() =>
  Object.entries(direction.data.value?.directions ?? {}).map(([name, d]) => ({ name, ...d })),
)
const directionColumns = [
  { key: 'name', label: 'Direction' },
  { key: 'packets', label: 'Packets', align: 'right' },
  { key: 'bytes', label: 'Bytes', align: 'right' },
  { key: 'percent_of_bytes', label: '% of IP bytes', align: 'right' },
  { key: 'explanation', label: 'Meaning' },
]

onMounted(() => store.load(id))
</script>

<template>
  <StateBlock v-if="store.loading && !store.document" kind="loading" message="Loading traffic intelligence…" />
  <UnavailableNotice v-else-if="store.unavailable" :message="store.error?.message" />
  <StateBlock v-else-if="store.error" kind="error" :message="store.error.message" @retry="store.load(id, { force: true })" />

  <div v-else-if="traffic" id="panel-traffic" class="space-y-4">
    <div class="grid grid-cols-2 gap-4 md:grid-cols-4">
      <StatCard label="IP packets" :value="num(traffic.total_ip_packets)" hint="denominator for packet shares" />
      <StatCard label="IP bytes" :value="bytes(traffic.total_ip_bytes)" hint="denominator for byte shares" />
      <StatCard label="Addresses" :value="num(traffic.unique_addresses)" />
      <StatCard label="IPv4 / IPv6 bytes" :value="`${bytes(traffic.ip_versions.ipv4.bytes)} / ${bytes(traffic.ip_versions.ipv6.bytes)}`" />
    </div>

    <AppCard title="Top talkers" subtitle="Addresses ranked by traffic" flush>
      <form class="flex flex-wrap items-end gap-3 border-b border-slate-100 p-3" @submit.prevent="submit">
        <label class="flex flex-col gap-1"><span class="label mb-0">Rank by</span>
          <select v-model="draft.by" class="field" data-filter="by"><option value="bytes">Bytes</option><option value="packets">Packets</option></select></label>
        <label class="flex flex-col gap-1"><span class="label mb-0">Traffic</span>
          <select v-model="draft.role" class="field" data-filter="role">
            <option value="bidirectional">Sent + received</option><option value="source">Sent (source)</option><option value="destination">Received (destination)</option>
          </select></label>
        <label class="flex flex-col gap-1"><span class="label mb-0">Show top</span>
          <select v-model.number="draft.limit" class="field" data-filter="limit"><option v-for="n in [5, 10, 25, 50, 100]" :key="n" :value="n">{{ n }}</option></select></label>
        <label class="flex flex-col gap-1"><span class="label mb-0">IP version</span>
          <select v-model="draft.ip_version" class="field" data-filter="ip_version"><option value="">Both</option><option value="4">IPv4</option><option value="6">IPv6</option></select></label>
        <button type="submit" class="btn btn-primary">Apply</button>
        <button type="button" class="btn btn-secondary" :disabled="Boolean(exporter.busy.value)"
          @click="exporter.download('top-talkers', '/export/top-talkers.csv', talkerParams())">Export CSV</button>
      </form>
      <StateBlock v-if="talkers.loading.value && !talkers.data.value" kind="loading" />
      <StateBlock v-else-if="talkers.error.value" kind="error" :message="talkers.error.value.message" @retry="refresh" />
      <StateBlock v-else-if="!talkers.data.value?.items.length" kind="empty" message="No IP traffic matches." />
      <DataTable v-else :columns="columns" :rows="talkers.data.value.items" row-key="ip" caption="Top talkers">
        <template #cell-bytes="{ row }">{{ bytes(row.bytes) }}</template>
        <template #cell-packets="{ row }">{{ num(row.packets) }}</template>
        <template #cell-share="{ row }">{{ pctValue(row.percent_of_bytes) }}</template>
        <template #cell-sent="{ row }">{{ bytes(row.sent_bytes) }} / {{ bytes(row.received_bytes) }}</template>
      </DataTable>
    </AppCard>
    <ChartCard title="Top talkers by bytes" :config="talkerChart" aria-label="Bar chart of the top talkers by bytes" empty-text="No IP traffic." heightClass="h-72" />
    <MetricNote :text="defs.top_talkers" />

    <AppCard title="Inbound vs outbound" subtitle="Relative to the local networks you specify">
      <form class="flex flex-wrap items-end gap-3" @submit.prevent="submit">
        <label class="flex min-w-[18rem] flex-1 flex-col gap-1">
          <span class="label mb-0">Local networks (addresses or CIDR, comma-separated)</span>
          <input v-model.trim="draft.local" class="field" placeholder="192.168.1.0/24, 10.0.0.5, 2001:db8::/32" data-filter="local" />
        </label>
        <button type="submit" class="btn btn-primary">Classify</button>
        <button type="button" class="btn btn-secondary" :disabled="Boolean(exporter.busy.value)"
          @click="exporter.download('traffic-direction', '/export/traffic-direction.csv', { local: query.applied.value.local })">Export CSV</button>
      </form>
      <p v-if="exporter.error.value" class="mt-2 text-xs text-red-700" role="alert">{{ exporter.error.value }}</p>
      <StateBlock v-if="direction.loading.value && !direction.data.value" kind="loading" />
      <StateBlock v-else-if="direction.error.value" kind="error" :message="direction.error.value.message" @retry="refresh" />
      <template v-else-if="direction.data.value">
        <AlertBanner v-if="!direction.data.value.configured" kind="info" class="mt-3">
          No local networks configured, so all traffic is <strong>unknown</strong>. Private address ranges are
          not assumed to be local; enter the network(s) this capture was taken on to classify direction.
        </AlertBanner>
        <div class="mt-3 grid grid-cols-1 gap-4 lg:grid-cols-2">
          <DataTable :columns="directionColumns" :rows="directionRows" row-key="name" caption="Traffic direction">
            <template #cell-name="{ row }"><span class="font-medium">{{ label(row.name) }}</span></template>
            <template #cell-packets="{ row }">{{ num(row.packets) }}</template>
            <template #cell-bytes="{ row }">{{ bytes(row.bytes) }}</template>
            <template #cell-percent_of_bytes="{ row }">{{ pctValue(row.percent_of_bytes) }}</template>
            <template #cell-explanation="{ row }"><span class="text-xs text-slate-500">{{ row.explanation }}</span></template>
          </DataTable>
          <ChartCard v-if="directionChart" title="Bytes by direction" :config="directionChart" aria-label="Doughnut chart of bytes by traffic direction" />
        </div>
        <p class="mt-2 text-xs text-slate-500">{{ direction.data.value.rule }}</p>
      </template>
      <div class="mt-2"><MetricNote :text="defs.direction" /></div>
    </AppCard>
  </div>
</template>

<script setup>
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'

import { analysisApi } from '@/api/analysis'
import ChartCard from '@/components/charts/ChartCard.vue'
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { useCaptureDetailStore } from '@/stores/captureDetail'
import { protocolDoughnut, throughputLine } from '@/utils/charts'
import { bytes, duration, flowLabel, num } from '@/utils/format'

const route = useRoute()
const detail = useCaptureDetailStore()
const id = route.params.id

const { data, error, loading, load } = useAsyncData(async () => {
  const [summary, perf, flows] = await Promise.all([
    detail.getSummary(),
    detail.getPerformance(),
    analysisApi.flows(id, { per_page: 5 }),
  ])
  return { summary, perf, flows }
})

const totals = computed(() => data.value?.summary.totals)
const protocolChart = computed(() => {
  const rows = data.value?.summary.protocols.transport ?? []
  return rows.length ? protocolDoughnut(rows) : null
})
const throughputChart = computed(() => {
  const points = data.value?.perf.performance.timeseries.points ?? []
  return points.length ? throughputLine(points) : null
})

const columns = [
  { key: 'flow', label: 'Flow' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'packets', label: 'Packets', align: 'right' },
  { key: 'bytes', label: 'Bytes', align: 'right' },
]

onMounted(load)
</script>

<template>
  <StateBlock v-if="loading && !data" kind="loading" message="Loading overview…" />
  <StateBlock v-else-if="error" kind="error" :message="error.message" @retry="load" />
  <div v-else-if="data" id="panel-overview" class="space-y-4">
    <div class="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
      <StatCard label="Packets" :value="num(totals.total_packets)" />
      <StatCard label="Data" :value="bytes(totals.total_bytes)" />
      <StatCard label="Duration" :value="duration(totals.duration_seconds)" />
      <StatCard label="Unique IPs" :value="num(totals.unique_ips)" />
      <StatCard label="Flows" :value="num(totals.flow_count)" />
      <StatCard
        label="Malformed"
        :value="num(totals.malformed_packets)"
        :hint="totals.malformed_packets ? 'kept, flagged in the explorer' : ''"
      />
    </div>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <ChartCard
        title="Protocol distribution"
        subtitle="Packets by transport protocol"
        :config="protocolChart"
        aria-label="Doughnut chart of packets by transport protocol"
        empty-text="No packets."
      />
      <ChartCard
        title="Traffic over time"
        subtitle="Throughput per second"
        :config="throughputChart"
        aria-label="Line chart of throughput over time"
        empty-text="No traffic in this capture."
      />
    </div>

    <AppCard title="Top flows by bytes" flush>
      <template #actions>
        <RouterLink class="btn-link" :to="{ name: 'capture-flows', params: { id } }">View all flows</RouterLink>
      </template>
      <DataTable
        v-if="data.flows.items.length"
        :columns="columns"
        :rows="data.flows.items"
        row-key="flow_id"
        caption="Top flows by bytes"
      >
        <template #cell-flow="{ row }">{{ flowLabel(row) }}</template>
        <template #cell-protocol="{ row }">{{ row.application_protocol || row.protocol }}</template>
        <template #cell-packets="{ row }">{{ num(row.packets.total) }}</template>
        <template #cell-bytes="{ row }">{{ bytes(row.bytes.total) }}</template>
      </DataTable>
      <StateBlock v-else kind="empty" message="No IP flows in this capture." />
    </AppCard>
  </div>
</template>

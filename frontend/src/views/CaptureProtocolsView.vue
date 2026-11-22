<script setup>
import { onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { analysisApi } from '@/api/analysis'
import ChartCard from '@/components/charts/ChartCard.vue'
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { protocolBytesBar, protocolDoughnut } from '@/utils/charts'
import { bytes, num, percent } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const id = route.params.id

const { data, error, loading, load } = useAsyncData(() => analysisApi.protocols(id))

const layers = [
  { key: 'transport', title: 'Transport layer', none: 'No packets.' },
  {
    key: 'application',
    title: 'Application protocols (DNS, HTTP)',
    none: 'No DNS or HTTP traffic was identified in this capture.',
  },
]
const columns = [
  { key: 'protocol', label: 'Protocol' },
  { key: 'packets', label: 'Packets', align: 'right' },
  { key: 'packet_percent', label: '% packets', align: 'right' },
  { key: 'bytes', label: 'Bytes', align: 'right' },
  { key: 'byte_percent', label: '% bytes', align: 'right' },
  { key: 'actions', label: 'Explore' },
]

const viewPackets = (protocol) =>
  router.push({ name: 'capture-packets', params: { id }, query: { protocol } })

onMounted(load)
</script>

<template>
  <StateBlock v-if="loading && !data" kind="loading" message="Loading protocols…" />
  <StateBlock v-else-if="error" kind="error" :message="error.message" @retry="load" />
  <div v-else-if="data" id="panel-protocols" class="space-y-8">
    <section v-for="layer in layers" :key="layer.key" :data-layer="layer.key">
      <h2 class="mb-3 text-lg font-semibold text-slate-900">{{ layer.title }}</h2>
      <AppCard v-if="!data[layer.key].length" flush>
        <StateBlock kind="empty" :message="layer.none" />
      </AppCard>
      <template v-else>
        <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <ChartCard
            title="Packets"
            :config="protocolDoughnut(data[layer.key])"
            :aria-label="`Doughnut chart of packets by ${layer.key} protocol`"
          />
          <ChartCard
            title="Bytes"
            :config="protocolBytesBar(data[layer.key])"
            :aria-label="`Bar chart of bytes by ${layer.key} protocol`"
          />
        </div>
        <AppCard class="mt-4" flush>
          <DataTable
            :columns="columns"
            :rows="data[layer.key]"
            row-key="protocol"
            :caption="`${layer.title} protocol breakdown`"
          >
            <template #cell-packets="{ row }">{{ num(row.packets) }}</template>
            <template #cell-packet_percent="{ row }">{{ percent(row.packet_percent) }}</template>
            <template #cell-bytes="{ row }">{{ bytes(row.bytes) }}</template>
            <template #cell-byte_percent="{ row }">{{ percent(row.byte_percent) }}</template>
            <template #cell-actions="{ row }">
              <button type="button" class="btn-link" @click="viewPackets(row.protocol)">
                View packets<span class="sr-only"> for {{ row.protocol }}</span>
              </button>
            </template>
          </DataTable>
        </AppCard>
      </template>
    </section>
  </div>
</template>

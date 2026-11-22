<script setup>
import DataTable from '@/components/common/DataTable.vue'
import { bytes, duration, endpoint, ms, num } from '@/utils/format'

defineProps({ flows: { type: Array, required: true } })
defineEmits(['view-packets'])

const columns = [
  { key: 'flow_id', label: '#' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'a', label: 'Endpoint A (initiator)' },
  { key: 'b', label: 'Endpoint B' },
  { key: 'packets', label: 'Packets', align: 'right' },
  { key: 'bytes', label: 'Bytes', align: 'right' },
  { key: 'duration', label: 'Duration', align: 'right' },
  { key: 'retransmissions', label: 'Retrans.', align: 'right' },
  { key: 'rtt', label: 'RTT', align: 'right' },
  { key: 'jitter', label: 'Jitter', align: 'right' },
  { key: 'actions', label: 'Packets' },
]
</script>

<template>
  <DataTable :columns="columns" :rows="flows" row-key="flow_id" caption="Network flows">
    <template #cell-protocol="{ row }">
      {{ row.application_protocol ? `${row.protocol} / ${row.application_protocol}` : row.protocol }}
    </template>
    <template #cell-a="{ row }">{{ endpoint(row.endpoint_a.ip, row.endpoint_a.port) }}</template>
    <template #cell-b="{ row }">{{ endpoint(row.endpoint_b.ip, row.endpoint_b.port) }}</template>
    <template #cell-packets="{ row }">
      {{ num(row.packets.total) }} ({{ num(row.packets.a_to_b) }}→ / ←{{ num(row.packets.b_to_a) }})
    </template>
    <template #cell-bytes="{ row }">{{ bytes(row.bytes.total) }}</template>
    <template #cell-duration="{ row }">{{ duration(row.duration_seconds) }}</template>
    <template #cell-retransmissions="{ row }">{{ num(row.retransmissions) }}</template>
    <template #cell-rtt="{ row }">{{ ms(row.handshake_rtt_ms) }}</template>
    <template #cell-jitter="{ row }">{{ ms(row.jitter_ms) }}</template>
    <template #cell-actions="{ row }">
      <button type="button" class="btn-link" :data-flow="row.flow_id" @click="$emit('view-packets', row)">
        View<span class="sr-only"> packets of flow {{ row.flow_id }}</span>
      </button>
    </template>
  </DataTable>
</template>

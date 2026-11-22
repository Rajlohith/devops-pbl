<script setup>
import DataTable from '@/components/common/DataTable.vue'
import { clock, endpoint, packetInfo } from '@/utils/format'

defineProps({
  packets: { type: Array, required: true },
  selected: { type: Number, default: null },
})
defineEmits(['select'])

const columns = [
  { key: 'packet_number', label: '#', align: 'right' },
  { key: 'timestamp', label: 'Time (UTC)' },
  { key: 'source', label: 'Source' },
  { key: 'destination', label: 'Destination' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'original_length', label: 'Length', align: 'right' },
  { key: 'info', label: 'Info' },
]
</script>

<template>
  <DataTable
    :columns="columns"
    :rows="packets"
    row-key="packet_number"
    caption="Packets. Select a row to see its details."
    clickable
    monospace
    :selected-key="selected"
    @row-click="(packet) => $emit('select', packet.packet_number)"
  >
    <template #cell-timestamp="{ row }">{{ clock(row.timestamp) }}</template>
    <template #cell-source="{ row }">{{ endpoint(row.source_ip, row.source_port) }}</template>
    <template #cell-destination="{ row }">{{ endpoint(row.destination_ip, row.destination_port) }}</template>
    <template #cell-info="{ row }">
      {{ packetInfo(row) }}
      <span v-if="row.is_retransmission" class="badge bg-amber-100 text-amber-800">retransmission</span>
      <span v-if="row.malformed_reason" class="badge bg-red-100 text-red-800" :title="row.malformed_reason">
        malformed
      </span>
    </template>
  </DataTable>
</template>

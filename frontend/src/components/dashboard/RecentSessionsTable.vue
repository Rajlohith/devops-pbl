<script setup>
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { bytes, dateTime, num } from '@/utils/format'

defineProps({ sessions: { type: Array, required: true } })

const columns = [
  { key: 'filename', label: 'Capture' },
  { key: 'status', label: 'Status' },
  { key: 'packets', label: 'Packets', align: 'right' },
  { key: 'bytes', label: 'Data', align: 'right' },
  { key: 'flows', label: 'Flows', align: 'right' },
  { key: 'uploaded_at', label: 'Uploaded' },
]
</script>

<template>
  <AppCard title="Recent analysis sessions" flush>
    <DataTable :columns="columns" :rows="sessions" row-key="id" caption="Recent analysis sessions">
      <template #cell-filename="{ row }">
        <RouterLink class="link" :to="{ name: 'capture-overview', params: { id: row.id } }">
          {{ row.filename }}
        </RouterLink>
      </template>
      <template #cell-status="{ row }"><StatusBadge :status="row.status" /></template>
      <template #cell-packets="{ row }">{{ num(row.packets) }}</template>
      <template #cell-bytes="{ row }">{{ bytes(row.bytes) }}</template>
      <template #cell-flows="{ row }">{{ num(row.flows) }}</template>
      <template #cell-uploaded_at="{ row }">{{ dateTime(row.uploaded_at) }}</template>
    </DataTable>
  </AppCard>
</template>

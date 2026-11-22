<script setup>
import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { bytes, dateTime, num } from '@/utils/format'

defineProps({ captures: { type: Array, required: true } })
defineEmits(['analyze', 'delete'])

const columns = [
  { key: 'original_filename', label: 'File' },
  { key: 'file_format', label: 'Format' },
  { key: 'file_size_bytes', label: 'Size', align: 'right' },
  { key: 'uploaded_at', label: 'Uploaded' },
  { key: 'status', label: 'Status' },
  { key: 'actions', label: 'Actions', align: 'right' },
]
</script>

<template>
  <DataTable :columns="columns" :rows="captures" row-key="id" caption="Uploaded captures">
    <template #cell-original_filename="{ row }">
      <RouterLink class="link" :to="{ name: 'capture-overview', params: { id: row.id } }">
        {{ row.original_filename }}
      </RouterLink>
    </template>
    <template #cell-file_size_bytes="{ row }">{{ bytes(row.file_size_bytes) }}</template>
    <template #cell-uploaded_at="{ row }">{{ dateTime(row.uploaded_at) }}</template>
    <template #cell-status="{ row }">
      <StatusBadge :status="row.status" />
      <p v-if="row.status === 'processing' && row.packet_count" class="mt-1 text-xs text-slate-500">
        {{ num(row.packet_count) }} packets so far
      </p>
      <p v-else-if="row.status === 'completed'" class="mt-1 text-xs text-slate-500">
        {{ num(row.packet_count) }} packets
      </p>
      <p v-else-if="row.status === 'failed' && row.error_message" class="mt-1 max-w-xs text-xs text-red-700">
        {{ row.error_message }}
      </p>
    </template>
    <template #cell-actions="{ row }">
      <div class="flex justify-end gap-2">
        <button
          v-if="row.status === 'uploaded' || row.status === 'failed'"
          type="button"
          class="btn btn-secondary"
          data-action="analyze"
          @click="$emit('analyze', row)"
        >
          {{ row.status === 'failed' ? 'Retry' : 'Analyse' }}
          <span class="sr-only"> {{ row.original_filename }}</span>
        </button>
        <button
          type="button"
          class="btn btn-secondary text-red-700"
          data-action="delete"
          @click="$emit('delete', row)"
        >
          Delete<span class="sr-only"> {{ row.original_filename }}</span>
        </button>
      </div>
    </template>
  </DataTable>
</template>

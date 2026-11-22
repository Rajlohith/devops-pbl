<script setup>
import { computed } from 'vue'

import AppCard from '@/components/common/AppCard.vue'

const props = defineProps({ packet: { type: Object, required: true } })
defineEmits(['close'])

// Every present field, except the structured metadata which gets its own block below.
const fields = computed(() =>
  Object.entries(props.packet)
    .filter(([key, value]) => value !== null && value !== false && key !== 'application_metadata')
    .map(([key, value]) => ({ key, label: key.replace(/_/g, ' '), value: String(value) })),
)
</script>

<template>
  <AppCard id="packet-detail-card" :title="`Packet ${packet.packet_number}`">
    <template #actions>
      <button type="button" class="btn-link text-slate-500" @click="$emit('close')">Close</button>
    </template>
    <dl class="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2 lg:grid-cols-3">
      <div v-for="field in fields" :key="field.key" class="flex justify-between gap-3 border-b border-slate-100 py-1">
        <dt class="text-slate-500">{{ field.label }}</dt>
        <dd class="break-all text-right font-mono text-xs">{{ field.value }}</dd>
      </div>
    </dl>
    <pre
      v-if="packet.application_metadata"
      class="mt-3 overflow-x-auto rounded bg-slate-50 p-3 text-xs"
      data-role="metadata"
      >{{ JSON.stringify(packet.application_metadata, null, 2) }}</pre
    >
  </AppCard>
</template>

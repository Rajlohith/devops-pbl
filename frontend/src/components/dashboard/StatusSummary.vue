<script setup>
import AppCard from '@/components/common/AppCard.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { num } from '@/utils/format'

defineProps({
  counts: { type: Object, required: true },
  inProgress: { type: Number, default: 0 },
})

const STATUSES = ['completed', 'processing', 'pending', 'uploaded', 'failed']
</script>

<template>
  <AppCard title="Processing status">
    <ul class="flex flex-wrap gap-x-6 gap-y-3">
      <li
        v-for="status in STATUSES"
        :key="status"
        class="flex items-center gap-2"
        :data-status-count="status"
      >
        <StatusBadge :status="status" />
        <span class="text-lg font-semibold text-slate-900">{{ num(counts[status]) }}</span>
      </li>
    </ul>
    <p v-if="inProgress > 0" class="mt-3 text-xs text-slate-500" role="status">
      {{ num(inProgress) }} analysis {{ inProgress === 1 ? 'job' : 'jobs' }} in progress — this page
      refreshes automatically.
    </p>
  </AppCard>
</template>

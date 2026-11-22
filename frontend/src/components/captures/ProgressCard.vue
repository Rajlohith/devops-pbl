<script setup>
import { computed } from 'vue'

import AppCard from '@/components/common/AppCard.vue'
import { num } from '@/utils/format'

const props = defineProps({ capture: { type: Object, required: true } })

const processingText = computed(() =>
  props.capture.packet_count
    ? `Analysing — ${num(props.capture.packet_count)} packets processed so far`
    : 'Analysing…',
)
</script>

<template>
  <AppCard id="progress-card">
    <p v-if="capture.status === 'uploaded'" class="text-sm text-slate-600">
      This capture has not been analysed yet. Start the analysis to see packets, flows and
      performance results.
    </p>

    <div v-else-if="capture.status === 'failed'">
      <p class="font-medium text-red-800">Analysis failed</p>
      <p id="fail-reason" class="mt-1 text-sm text-red-700">
        {{ capture.error_message || 'No details were recorded.' }}
      </p>
      <p class="mt-2 text-xs text-slate-500">No partial results were kept. You can retry the analysis.</p>
    </div>

    <div v-else>
      <p id="progress-text" class="text-sm font-medium text-slate-700" role="status">
        {{ capture.status === 'pending' ? 'Queued — waiting for a worker…' : processingText }}
      </p>
      <div
        class="mt-3 h-2 overflow-hidden rounded bg-slate-200"
        role="progressbar"
        aria-label="Analysis in progress"
      >
        <div class="h-full w-1/3 animate-pulse rounded bg-blue-600"></div>
      </div>
      <p class="mt-2 text-xs text-slate-500">This page updates automatically when the analysis finishes.</p>
    </div>
  </AppCard>
</template>

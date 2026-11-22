<script setup>
import AppCard from '@/components/common/AppCard.vue'

import BaseChart from './BaseChart.vue'

/**
 * A card holding one chart. `config` is a `{ type, data, options }` object from utils/charts;
 * when it is null the card shows `emptyText` instead of an empty plot.
 */
defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  config: { type: Object, default: null },
  ariaLabel: { type: String, required: true },
  emptyText: { type: String, default: 'No data' },
  heightClass: { type: String, default: 'h-64' },
})
</script>

<template>
  <AppCard :title="title" :subtitle="subtitle">
    <BaseChart
      v-if="config"
      :type="config.type"
      :data="config.data"
      :options="config.options"
      :aria-label="ariaLabel"
      :height-class="heightClass"
    />
    <p
      v-else
      class="flex items-center justify-center text-sm text-slate-500"
      :class="heightClass"
      data-state="empty"
    >
      {{ emptyText }}
    </p>
  </AppCard>
</template>

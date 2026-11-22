<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** info | low | medium | high */
  severity: { type: String, required: true },
})

const tones = {
  info: 'bg-slate-100 text-slate-700',
  low: 'bg-blue-100 text-blue-800',
  medium: 'bg-amber-100 text-amber-800',
  high: 'bg-red-100 text-red-800',
}
const tone = computed(() => tones[props.severity] ?? tones.info)
</script>

<template>
  <span class="badge" :class="tone" :data-severity="severity">{{ severity }}</span>
</template>

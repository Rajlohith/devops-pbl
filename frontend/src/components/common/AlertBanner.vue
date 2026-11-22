<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** 'error' | 'success' | 'info' | 'warning' */
  kind: { type: String, default: 'info' },
})

const tones = {
  error: 'border-red-300 bg-red-50 text-red-800',
  success: 'border-green-300 bg-green-50 text-green-800',
  warning: 'border-amber-300 bg-amber-50 text-amber-900',
  info: 'border-blue-200 bg-blue-50 text-blue-900',
}
const tone = computed(() => tones[props.kind] ?? tones.info)
</script>

<template>
  <div
    class="rounded-md border px-4 py-3 text-sm"
    :class="tone"
    :role="kind === 'error' ? 'alert' : 'status'"
    :data-alert="kind"
  >
    <slot />
  </div>
</template>

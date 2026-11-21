<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** 'online' | 'offline' | 'checking' */
  state: { type: String, default: 'checking' },
})

const presets = {
  online: { label: 'API online', dot: 'bg-emerald-500', text: 'text-emerald-700' },
  offline: { label: 'API unreachable', dot: 'bg-red-500', text: 'text-red-700' },
  checking: { label: 'Checking API', dot: 'bg-amber-400', text: 'text-slate-500' },
}

const preset = computed(() => presets[props.state] ?? presets.checking)
</script>

<template>
  <span
    class="inline-flex items-center gap-2 rounded-full bg-white px-2.5 py-1 text-xs font-medium ring-1 ring-slate-200"
    :class="preset.text"
    role="status"
  >
    <span class="h-2 w-2 rounded-full" :class="preset.dot" aria-hidden="true"></span>
    {{ preset.label }}
  </span>
</template>

<script setup>
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: '—' },
  hint: { type: String, default: '' },
})
</script>

<template>
  <div class="rounded-lg bg-white p-4 shadow-sm ring-1 ring-slate-200">
    <p class="text-xs font-medium uppercase tracking-wide text-slate-500">{{ label }}</p>
    <p class="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900" :data-stat="label">
      {{ value }}
    </p>
    <p v-if="hint" class="mt-1 text-xs text-slate-500">{{ hint }}</p>
  </div>
</template>

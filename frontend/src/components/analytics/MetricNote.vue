<script setup>
/** A collapsible "what does this measure?" note, so every figure carries its definition. */
defineProps({
  text: { type: String, required: true },
  summary: { type: String, default: 'How is this measured?' },
})
</script>

<template>
  <details class="text-xs text-slate-500" data-metric-note>
    <summary class="cursor-pointer select-none text-blue-700 hover:underline">{{ summary }}</summary>
    <p class="mt-1 max-w-3xl leading-relaxed">{{ text }}</p>
  </details>
</template>

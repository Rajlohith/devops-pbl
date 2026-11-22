<script setup>
/** Route-based tabs: each tab is a real link, so tabs are bookmarkable and Back works. */
defineProps({
  /** [{ label, to }] */
  tabs: { type: Array, required: true },
  label: { type: String, default: 'Sections' },
})
</script>

<template>
  <nav class="flex gap-1 overflow-x-auto border-b border-slate-200" :aria-label="label">
    <RouterLink
      v-for="tab in tabs"
      :key="tab.label"
      :to="tab.to"
      class="tab whitespace-nowrap"
      exact-active-class="tab-active"
    >
      {{ tab.label }}
    </RouterLink>
  </nav>
</template>

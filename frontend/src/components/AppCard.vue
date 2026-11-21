<script setup>
defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
})
</script>

<template>
  <section class="rounded-lg bg-white shadow-sm ring-1 ring-slate-200">
    <header class="flex items-start justify-between gap-4 border-b border-slate-100 px-4 py-3">
      <div class="min-w-0">
        <h2 class="text-sm font-semibold text-slate-900">{{ title }}</h2>
        <p v-if="subtitle" class="mt-0.5 text-xs text-slate-500">{{ subtitle }}</p>
      </div>
      <slot name="actions" />
    </header>
    <div class="p-4">
      <slot />
    </div>
  </section>
</template>

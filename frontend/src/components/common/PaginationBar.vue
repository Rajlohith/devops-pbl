<script setup>
import { computed } from 'vue'

import { num } from '@/utils/format'

const props = defineProps({
  page: { type: Number, required: true },
  perPage: { type: Number, required: true },
  total: { type: Number, required: true },
})
const emit = defineEmits(['update:page'])

const pages = computed(() => Math.max(1, Math.ceil(props.total / props.perPage)))
const first = computed(() => (props.total === 0 ? 0 : (props.page - 1) * props.perPage + 1))
const last = computed(() => Math.min(props.total, props.page * props.perPage))
</script>

<template>
  <nav
    class="flex flex-wrap items-center justify-between gap-2 border-t border-slate-100 px-3 py-2 text-sm text-slate-600"
    aria-label="Pagination"
  >
    <span data-role="range">{{ num(first) }}–{{ num(last) }} of {{ num(total) }}</span>
    <span class="flex items-center gap-2">
      <button
        type="button"
        class="btn btn-secondary"
        :disabled="page <= 1"
        @click="emit('update:page', page - 1)"
      >
        Previous
      </button>
      <span aria-live="polite">Page {{ page }} / {{ pages }}</span>
      <button
        type="button"
        class="btn btn-secondary"
        :disabled="page >= pages"
        @click="emit('update:page', page + 1)"
      >
        Next
      </button>
    </span>
  </nav>
</template>

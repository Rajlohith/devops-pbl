<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** uploaded | pending | processing | completed | failed */
  status: { type: String, required: true },
})

const classes = {
  uploaded: 'bg-slate-200 text-slate-800',
  pending: 'bg-amber-100 text-amber-800',
  processing: 'bg-blue-100 text-blue-800',
  completed: 'bg-green-100 text-green-800',
  failed: 'bg-red-100 text-red-800',
}
const tone = computed(() => classes[props.status] ?? classes.uploaded)
</script>

<template>
  <span class="badge" :class="tone">{{ status }}</span>
</template>

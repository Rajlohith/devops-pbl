<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'

import { REPORTS } from '@/api/reports'
import { useReportDownload } from '@/composables/useReportDownload'

const props = defineProps({ captureId: { type: String, required: true } })

const open = ref(false)
const root = ref(null)
const { busy, error, download } = useReportDownload(() => props.captureId)

async function choose(report) {
  await download(report.key, report.path)
  open.value = false
}

const onDocumentClick = (event) => {
  if (open.value && root.value && !root.value.contains(event.target)) open.value = false
}
const onKeydown = (event) => {
  if (event.key === 'Escape') open.value = false
}

onMounted(() => {
  document.addEventListener('click', onDocumentClick)
  document.addEventListener('keydown', onKeydown)
})
onBeforeUnmount(() => {
  document.removeEventListener('click', onDocumentClick)
  document.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <div ref="root" class="relative" id="reports-menu">
    <button
      type="button"
      class="btn btn-secondary"
      aria-haspopup="true"
      :aria-expanded="open"
      aria-controls="reports-list"
      @click="open = !open"
    >
      Reports <span aria-hidden="true">▾</span>
    </button>
    <ul
      v-if="open"
      id="reports-list"
      class="absolute right-0 z-20 mt-1 w-60 rounded-md bg-white p-1 text-sm shadow-lg ring-1 ring-slate-200"
    >
      <li v-for="report in REPORTS" :key="report.key">
        <button
          type="button"
          class="block w-full rounded px-3 py-1.5 text-left hover:bg-slate-100 disabled:opacity-50"
          :disabled="Boolean(busy)"
          :data-report="report.path"
          @click="choose(report)"
        >
          {{ busy === report.key ? 'Preparing…' : report.label }}
        </button>
      </li>
    </ul>
    <p v-if="error" class="absolute right-0 mt-1 w-72 rounded bg-red-50 p-2 text-xs text-red-800 ring-1 ring-red-200" role="alert">
      {{ error }}
    </p>
  </div>
</template>

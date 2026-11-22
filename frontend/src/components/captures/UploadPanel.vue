<script setup>
import { computed, ref } from 'vue'

import AppCard from '@/components/common/AppCard.vue'
import { ALLOWED_EXTENSIONS, useCaptureUpload } from '@/composables/useCaptureUpload'

const emit = defineEmits(['uploaded'])

const { analyze, uploading, progress, error, uploaded, fileLabel, canUpload, pick, upload } =
  useCaptureUpload()

const input = ref(null)
const dragging = ref(false)

const percent = computed(() => Math.round(progress.value * 100))
const progressText = computed(() =>
  percent.value < 100 ? `Uploading… ${percent.value}%` : 'Upload complete — validating…',
)

function onChange(event) {
  pick(event.target.files[0] ?? null)
}

function onDrop(event) {
  dragging.value = false
  const dropped = event.dataTransfer?.files?.[0]
  if (dropped) pick(dropped)
}

async function submit() {
  const capture = await upload()
  if (capture) {
    if (input.value) input.value.value = ''
    emit('uploaded', capture)
  }
}
</script>

<template>
  <AppCard title="Upload a capture">
    <form @submit.prevent="submit">
      <input
        id="file-input"
        ref="input"
        type="file"
        class="sr-only"
        :accept="ALLOWED_EXTENSIONS.join(',')"
        @change="onChange"
      />
      <label
        for="file-input"
        id="drop-zone"
        class="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed bg-white p-8 text-center transition hover:border-blue-400 focus-within:border-blue-500"
        :class="dragging ? 'border-blue-500 bg-blue-50' : 'border-slate-300'"
        @dragenter.prevent="dragging = true"
        @dragover.prevent="dragging = true"
        @dragleave.prevent="dragging = false"
        @drop.prevent="onDrop"
      >
        <span class="font-medium text-slate-700">Drop a capture here or click to choose</span>
        <span class="mt-1 text-xs text-slate-500">PCAP or PCAPNG — validated on upload</span>
      </label>

      <div class="mt-3 flex flex-wrap items-center gap-4">
        <span id="chosen-file" class="text-sm text-slate-600">{{ fileLabel }}</span>
        <label class="flex items-center gap-2 text-sm" for="analyze-now">
          <input id="analyze-now" v-model="analyze" type="checkbox" :disabled="uploading" />
          Start analysis immediately
        </label>
        <button id="upload-button" type="submit" class="btn btn-primary" :disabled="!canUpload">
          {{ uploading ? 'Uploading…' : 'Upload' }}
        </button>
      </div>

      <div v-if="uploading" id="upload-progress" class="mt-3">
        <div
          class="h-2 overflow-hidden rounded bg-slate-200"
          role="progressbar"
          aria-label="Upload progress"
          aria-valuemin="0"
          aria-valuemax="100"
          :aria-valuenow="percent"
        >
          <div class="h-full bg-blue-600 transition-all" :style="{ width: `${percent}%` }"></div>
        </div>
        <p id="upload-progress-text" class="mt-1 text-xs text-slate-500">{{ progressText }}</p>
      </div>

      <p id="upload-message" class="mt-3 text-sm" role="status" aria-live="polite">
        <span v-if="error" class="text-red-700">{{ error }}</span>
        <span v-else-if="uploaded && uploaded.status === 'failed'" class="text-red-700">
          Uploaded, but analysis could not start: {{ uploaded.error_message || 'unknown error' }}
          <RouterLink class="underline" :to="{ name: 'capture-overview', params: { id: uploaded.id } }">
            Open it
          </RouterLink>
        </span>
        <span v-else-if="uploaded" class="text-green-700">
          Uploaded {{ uploaded.original_filename }}.
          <RouterLink class="underline" :to="{ name: 'capture-overview', params: { id: uploaded.id } }">
            Open it
          </RouterLink>
        </span>
      </p>
    </form>
  </AppCard>
</template>

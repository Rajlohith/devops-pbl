<script setup>
import { computed, onBeforeUnmount, watch } from 'vue'
import { useRouter } from 'vue-router'

import ProgressCard from '@/components/captures/ProgressCard.vue'
import ReportsMenu from '@/components/captures/ReportsMenu.vue'
import AlertBanner from '@/components/common/AlertBanner.vue'
import AppCard from '@/components/common/AppCard.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import TabNav from '@/components/common/TabNav.vue'
import { useCaptureDetailStore } from '@/stores/captureDetail'
import { bytes, dateTime } from '@/utils/format'

const props = defineProps({ id: { type: String, required: true } })

const detail = useCaptureDetailStore()
const router = useRouter()

const capture = computed(() => detail.capture)
const notFound = computed(() => detail.error?.status === 404)

// Reload when navigating between captures (the component is reused for a new :id).
watch(() => props.id, (id) => detail.load(id), { immediate: true })

watch(
  () => capture.value?.original_filename,
  (name) => {
    if (name) document.title = `${name} · NetScope`
  },
)
onBeforeUnmount(() => detail.stopPolling())

const tabs = computed(() => {
  const params = { id: props.id }
  return [
    { label: 'Overview', to: { name: 'capture-overview', params } },
    { label: 'Protocols', to: { name: 'capture-protocols', params } },
    { label: 'Flows', to: { name: 'capture-flows', params } },
    { label: 'Packets', to: { name: 'capture-packets', params } },
    { label: 'Performance', to: { name: 'capture-performance', params } },
  ]
})

// Phase 4 sections live in a second nav so the original five tabs stay exactly as they were.
const intelligenceTabs = computed(() => {
  const params = { id: props.id }
  return [
    { label: 'TCP Connections', to: { name: 'capture-tcp', params } },
    { label: 'DNS Analytics', to: { name: 'capture-dns', params } },
    { label: 'Traffic Intelligence', to: { name: 'capture-traffic', params } },
  ]
})

async function remove() {
  const name = capture.value.original_filename
  if (!window.confirm(`Delete ${name} and all of its analysis permanently?`)) return
  if (await detail.remove()) router.replace({ name: 'captures' })
}
</script>

<template>
  <div>
    <RouterLink class="text-sm text-blue-700 hover:underline" :to="{ name: 'captures' }">
      <span aria-hidden="true">←</span> All captures
    </RouterLink>

    <AppCard v-if="detail.loading && !capture" class="mt-3" flush>
      <StateBlock kind="loading" message="Loading capture…" />
    </AppCard>

    <AppCard v-else-if="notFound" class="mt-3" flush>
      <StateBlock kind="empty">
        <h2 class="text-lg font-semibold text-slate-900">Capture not found</h2>
        <p class="mt-1">It may have been deleted, or it does not belong to your account.</p>
        <RouterLink class="btn btn-primary mt-4" :to="{ name: 'captures' }">Back to captures</RouterLink>
      </StateBlock>
    </AppCard>

    <AppCard v-else-if="detail.error && !capture" class="mt-3" flush>
      <StateBlock kind="error" :message="detail.error.message" @retry="detail.reload()" />
    </AppCard>

    <template v-else-if="capture">
      <div class="mt-3 flex flex-wrap items-start justify-between gap-3">
        <div class="min-w-0">
          <h2 id="cap-title" class="break-all text-2xl font-semibold text-slate-900">
            {{ capture.original_filename }}
            <StatusBadge :status="capture.status" class="align-middle" />
          </h2>
          <p class="mt-1 text-xs text-slate-500">
            {{ capture.file_format.toUpperCase() }} · {{ bytes(capture.file_size_bytes) }} · uploaded
            {{ dateTime(capture.uploaded_at) }} · ID {{ capture.id }}
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <template v-if="detail.isCompleted">
            <ReportsMenu :capture-id="capture.id" />
            <RouterLink class="btn btn-secondary" :to="{ name: 'compare', query: { a: capture.id } }">
              Compare…
            </RouterLink>
          </template>
          <button
            v-if="capture.status === 'uploaded' || capture.status === 'failed'"
            id="analyze-btn"
            type="button"
            class="btn btn-primary"
            @click="detail.startAnalysis()"
          >
            {{ capture.status === 'failed' ? 'Retry analysis' : 'Start analysis' }}
          </button>
          <button id="delete-btn" type="button" class="btn btn-danger" @click="remove">Delete</button>
        </div>
      </div>

      <AlertBanner v-if="detail.actionError" kind="error" class="mt-4">{{ detail.actionError }}</AlertBanner>
      <AlertBanner v-if="detail.error" kind="warning" class="mt-4">
        Could not refresh this capture: {{ detail.error.message }}
      </AlertBanner>

      <template v-if="detail.isCompleted">
        <TabNav class="mt-6" :tabs="tabs" label="Capture sections" />
        <TabNav class="mt-1" :tabs="intelligenceTabs" label="Network intelligence sections" />
        <div class="mt-4"><RouterView :key="capture.id" /></div>
      </template>
      <ProgressCard v-else class="mt-4" :capture="capture" />
    </template>
  </div>
</template>

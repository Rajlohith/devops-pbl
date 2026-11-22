<script setup>
import { onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'

import CaptureHistoryTable from '@/components/captures/CaptureHistoryTable.vue'
import UploadPanel from '@/components/captures/UploadPanel.vue'
import AlertBanner from '@/components/common/AlertBanner.vue'
import AppCard from '@/components/common/AppCard.vue'
import PaginationBar from '@/components/common/PaginationBar.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import { usePolling } from '@/composables/usePolling'
import { useRouteQuery } from '@/composables/useRouteQuery'
import { useCapturesStore } from '@/stores/captures'

const STATUSES = ['completed', 'processing', 'pending', 'uploaded', 'failed']

const store = useCapturesStore()
const router = useRouter()
const { applied, apply, setPage } = useRouteQuery({ page: 1, status: '' })
const poller = usePolling(() => store.refresh(), { interval: 2000 })

async function load() {
  await store.fetch({ page: applied.value.page, status: applied.value.status })
  // The store steps back if the requested page no longer exists; keep the URL honest.
  if (store.loaded && store.page !== applied.value.page) {
    router.replace({ query: { ...(applied.value.status && { status: applied.value.status }), ...(store.page > 1 && { page: store.page }) } })
  }
}

// Poll only while something is queued or being analysed.
watch(
  () => store.hasActiveJobs,
  (active) => (active ? poller.start() : poller.stop()),
  { immediate: true },
)
watch(applied, load)
onMounted(load)

const onStatusChange = (event) => apply({ status: event.target.value, page: 1 })

function onDelete(capture) {
  if (window.confirm(`Delete ${capture.original_filename} and its analysis permanently?`)) {
    store.remove(capture.id)
  }
}
</script>

<template>
  <div class="space-y-6">
    <UploadPanel @uploaded="store.refresh()" />

    <AlertBanner v-if="store.actionError" kind="error">{{ store.actionError }}</AlertBanner>

    <AppCard title="Capture history" flush>
      <template #actions>
        <div>
          <label class="sr-only" for="status-filter">Filter by status</label>
          <select
            id="status-filter"
            class="field w-40"
            :value="applied.status"
            @change="onStatusChange"
          >
            <option value="">All statuses</option>
            <option v-for="status in STATUSES" :key="status" :value="status">{{ status }}</option>
          </select>
        </div>
      </template>

      <StateBlock v-if="store.loading && !store.loaded" kind="loading" message="Loading captures…" />
      <StateBlock
        v-else-if="store.error && !store.items.length"
        kind="error"
        :message="store.error.message"
        @retry="load"
      />
      <StateBlock
        v-else-if="!store.items.length"
        kind="empty"
        :message="
          applied.status
            ? `No captures with status “${applied.status}”.`
            : 'No captures yet. Upload a .pcap or .pcapng file above.'
        "
      />
      <template v-else>
        <CaptureHistoryTable
          :captures="store.items"
          @analyze="(capture) => store.analyze(capture.id)"
          @delete="onDelete"
        />
        <PaginationBar
          :page="store.page"
          :per-page="store.perPage"
          :total="store.total"
          @update:page="setPage"
        />
      </template>
    </AppCard>
  </div>
</template>

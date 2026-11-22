<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

import { analysisApi } from '@/api/analysis'
import AppCard from '@/components/common/AppCard.vue'
import PaginationBar from '@/components/common/PaginationBar.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import PacketDetail from '@/components/packets/PacketDetail.vue'
import PacketFilters from '@/components/packets/PacketFilters.vue'
import PacketTable from '@/components/packets/PacketTable.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { useReportDownload } from '@/composables/useReportDownload'
import { useRouteQuery } from '@/composables/useRouteQuery'
import { useCaptureDetailStore } from '@/stores/captureDetail'

const route = useRoute()
const detail = useCaptureDetailStore()
const id = route.params.id

const DEFAULTS = {
  page: 1, per_page: 50, sort: 'number', order: 'asc', q: '', protocol: '', ip: '', port: '',
  tcp_flags: '', min_length: '', max_length: '', flow_id: '', retransmission: false, malformed: false,
}
const FILTER_KEYS = [
  'q', 'protocol', 'ip', 'port', 'tcp_flags', 'min_length', 'max_length', 'flow_id',
  'retransmission', 'malformed',
]
const { applied, apply, setPage, reset } = useRouteQuery(DEFAULTS, { onUnchanged: () => fetchPackets() })

const packets = useAsyncData((params) => analysisApi.packets(id, params))
const packetDetail = useAsyncData((number) => analysisApi.packet(id, number))
const protocolNames = ref([])
const selected = ref(null)
const exporter = useReportDownload(id)

const filterParams = computed(() => Object.fromEntries(FILTER_KEYS.map((k) => [k, applied.value[k]])))
const hasFilters = computed(() => FILTER_KEYS.some((k) => applied.value[k] !== DEFAULTS[k]))

function fetchPackets() {
  selected.value = null
  packetDetail.reset()
  return packets.load({ ...applied.value })
}

async function loadProtocolNames() {
  try {
    const { protocols } = await detail.getSummary()
    protocolNames.value = [
      ...new Set([...protocols.transport, ...protocols.application].map((r) => r.protocol)),
    ].sort()
  } catch {
    /* the dropdown simply lists fewer protocols; the explorer itself still works */
  }
}

function select(number) {
  selected.value = number
  packetDetail.load(number)
}

function closeDetail() {
  selected.value = null
  packetDetail.reset()
}

watch(applied, fetchPackets)
onMounted(() => {
  loadProtocolNames()
  fetchPackets()
})

const emptyMessage = computed(() =>
  hasFilters.value ? 'No packets match these filters.' : 'This capture contains no packets.',
)
</script>

<template>
  <div id="panel-packets" class="space-y-4">
    <AppCard>
      <PacketFilters :model-value="applied" :protocols="protocolNames" @apply="apply" @reset="reset">
        <button
          id="pf-export"
          type="button"
          class="btn btn-secondary"
          :disabled="Boolean(exporter.busy.value)"
          @click="exporter.download('packets', '/export/packets.csv', filterParams)"
        >
          {{ exporter.busy.value ? 'Preparing…' : 'Export matches (CSV)' }}
        </button>
      </PacketFilters>
      <p v-if="exporter.error.value" class="mt-2 text-sm text-red-700" role="alert">
        {{ exporter.error.value }}
      </p>
    </AppCard>

    <AppCard flush>
      <div id="packet-results">
        <StateBlock v-if="packets.loading.value && !packets.data.value" kind="loading" message="Loading packets…" />
        <StateBlock
          v-else-if="packets.error.value"
          kind="error"
          :message="packets.error.value.message"
          @retry="fetchPackets"
        />
        <StateBlock v-else-if="packets.data.value && !packets.data.value.items.length" kind="empty" :message="emptyMessage" />
        <template v-else-if="packets.data.value">
          <PacketTable :packets="packets.data.value.items" :selected="selected" @select="select" />
          <PaginationBar
            :page="packets.data.value.page"
            :per-page="packets.data.value.per_page"
            :total="packets.data.value.total"
            @update:page="setPage"
          />
        </template>
      </div>
    </AppCard>

    <div id="packet-detail">
      <StateBlock v-if="packetDetail.loading.value" kind="loading" :message="`Loading packet ${selected}…`" />
      <StateBlock
        v-else-if="packetDetail.error.value"
        kind="error"
        :message="packetDetail.error.value.message"
        @retry="select(selected)"
      />
      <PacketDetail
        v-else-if="packetDetail.data.value && selected !== null"
        :packet="packetDetail.data.value"
        @close="closeDetail"
      />
    </div>
  </div>
</template>

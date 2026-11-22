<script setup>
import { computed, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { analysisApi } from '@/api/analysis'
import ChartCard from '@/components/charts/ChartCard.vue'
import AppCard from '@/components/common/AppCard.vue'
import PaginationBar from '@/components/common/PaginationBar.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import FlowFilters from '@/components/flows/FlowFilters.vue'
import FlowTable from '@/components/flows/FlowTable.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { useRouteQuery } from '@/composables/useRouteQuery'
import { topFlowsBar } from '@/utils/charts'
import { flowLabel } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const id = route.params.id

const DEFAULTS = {
  page: 1, per_page: 20, protocol: '', application: '', ip: '', port: '', sort: 'bytes', order: 'desc',
}
const { applied, apply, setPage } = useRouteQuery(DEFAULTS, { onUnchanged: () => fetchFlows() })

const flows = useAsyncData((params) => analysisApi.flows(id, params))
const top = useAsyncData(() => analysisApi.flows(id, { per_page: 10, sort: 'bytes', order: 'desc' }))

const topChart = computed(() =>
  top.data.value?.items.length ? topFlowsBar(top.data.value.items, flowLabel) : null,
)

const fetchFlows = () => flows.load({ ...applied.value })
watch(applied, fetchFlows)
onMounted(() => {
  top.load()
  fetchFlows()
})

const viewPackets = (flow) =>
  router.push({ name: 'capture-packets', params: { id }, query: { flow_id: String(flow.flow_id) } })
</script>

<template>
  <div id="panel-flows" class="space-y-4">
    <StateBlock v-if="top.error.value" kind="error" :message="top.error.value.message" @retry="top.load" />
    <ChartCard
      v-else
      title="Top 10 flows by bytes"
      :config="topChart"
      aria-label="Horizontal bar chart of the ten busiest flows by bytes"
      empty-text="No IP flows in this capture."
      height-class="h-72"
    />

    <AppCard>
      <FlowFilters :model-value="applied" @apply="apply" />
    </AppCard>

    <AppCard flush>
      <div id="flow-results">
        <StateBlock v-if="flows.loading.value && !flows.data.value" kind="loading" message="Loading flows…" />
        <StateBlock
          v-else-if="flows.error.value"
          kind="error"
          :message="flows.error.value.message"
          @retry="fetchFlows"
        />
        <StateBlock
          v-else-if="flows.data.value && !flows.data.value.items.length"
          kind="empty"
          message="No flows match these filters."
        />
        <template v-else-if="flows.data.value">
          <FlowTable :flows="flows.data.value.items" @view-packets="viewPackets" />
          <PaginationBar
            :page="flows.data.value.page"
            :per-page="flows.data.value.per_page"
            :total="flows.data.value.total"
            @update:page="setPage"
          />
        </template>
      </div>
    </AppCard>
  </div>
</template>

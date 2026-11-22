<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import ChartCard from '@/components/charts/ChartCard.vue'
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import { useComparison } from '@/composables/useComparison'
import { compareBytesBar } from '@/utils/charts'
import { byUnit, dateTime, DASH, num, signed, signedPercent } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const cmp = useComparison()

const a = ref(String(route.query.a ?? ''))
const b = ref(String(route.query.b ?? ''))

const columns = computed(() => [
  { key: 'label', label: 'Metric' },
  { key: 'a', label: `A — ${cmp.result.value.a.filename}`, align: 'right' },
  { key: 'b', label: `B — ${cmp.result.value.b.filename}`, align: 'right' },
  { key: 'delta', label: 'Change (B − A)', align: 'right' },
  { key: 'delta_percent', label: '%', align: 'right' },
])
const chart = computed(() => {
  const rows = cmp.result.value?.protocols ?? []
  return rows.length ? compareBytesBar(rows) : null
})
const overlaps = computed(() => {
  const ips = cmp.result.value.ips
  return [
    { title: 'In both captures', items: ips.sample.shared, count: ips.shared },
    { title: 'Only in A', items: ips.sample.only_a, count: ips.only_a },
    { title: 'Only in B', items: ips.sample.only_b, count: ips.only_b },
  ]
})

async function run() {
  // Keep the chosen pair in the URL so the comparison can be bookmarked or shared.
  if (a.value && b.value && a.value !== b.value) {
    router.replace({ query: { a: a.value, b: b.value } })
  }
  await cmp.compare(a.value, b.value)
}

onMounted(async () => {
  await cmp.loadOptions()
  if (cmp.optionsState.value === 'ready' && a.value && b.value) run()
})

const label = (c) => `${c.original_filename} — ${dateTime(c.uploaded_at)}`
</script>

<template>
  <div class="space-y-6">
    <div>
      <h2 class="text-lg font-semibold text-slate-900">Compare captures</h2>
      <p class="mt-1 text-slate-500">See how two analysed captures differ.</p>
    </div>

    <AppCard v-if="cmp.optionsState.value === 'loading'" flush>
      <StateBlock kind="loading" message="Loading captures…" />
    </AppCard>
    <AppCard v-else-if="cmp.optionsState.value === 'error'" flush>
      <StateBlock kind="error" :message="cmp.optionsError.value.message" @retry="cmp.loadOptions" />
    </AppCard>
    <AppCard v-else-if="cmp.options.value.length < 2" flush>
      <StateBlock
        kind="empty"
        message="You need at least two analysed captures to compare. Upload and analyse another capture first."
      />
    </AppCard>

    <template v-else>
      <AppCard>
        <form class="grid items-end gap-3 md:grid-cols-3" @submit.prevent="run">
          <div>
            <label class="label" for="cmp-a">Capture A (baseline)</label>
            <select id="cmp-a" v-model="a" class="field">
              <option value="">Choose a capture…</option>
              <option v-for="c in cmp.options.value" :key="c.id" :value="c.id">{{ label(c) }}</option>
            </select>
          </div>
          <div>
            <label class="label" for="cmp-b">Capture B</label>
            <select id="cmp-b" v-model="b" class="field">
              <option value="">Choose a capture…</option>
              <option v-for="c in cmp.options.value" :key="c.id" :value="c.id">{{ label(c) }}</option>
            </select>
          </div>
          <div>
            <button id="compare-btn" type="submit" class="btn btn-primary" :disabled="cmp.comparing.value">
              {{ cmp.comparing.value ? 'Comparing…' : 'Compare' }}
            </button>
          </div>
        </form>
      </AppCard>

      <div id="compare-result" aria-live="polite">
        <StateBlock v-if="cmp.comparing.value" kind="loading" message="Comparing…" />
        <StateBlock v-else-if="cmp.error.value" kind="error" :message="cmp.error.value" :retryable="false" />
        <div v-else-if="cmp.result.value" class="space-y-4">
          <AppCard flush>
            <DataTable :columns="columns" :rows="cmp.result.value.metrics" row-key="key" caption="Metric comparison">
              <template #cell-a="{ row }"><span :data-cell="`${row.key}-a`">{{ byUnit(row.a, row.unit) }}</span></template>
              <template #cell-b="{ row }"><span :data-cell="`${row.key}-b`">{{ byUnit(row.b, row.unit) }}</span></template>
              <template #cell-delta="{ row }">
                <span :data-cell="`${row.key}-delta`">{{ signed(row.delta, row.unit) }}</span>
              </template>
              <template #cell-delta_percent="{ row }">{{ signedPercent(row.delta_percent) }}</template>
            </DataTable>
          </AppCard>
          <p class="text-xs text-slate-500">
            A dash ({{ DASH }}) means the value is not available for that capture (for example, no TCP
            handshake was captured).
          </p>

          <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <ChartCard
              title="Bytes by transport protocol"
              :config="chart"
              aria-label="Grouped bar chart of bytes per transport protocol for captures A and B"
              empty-text="No protocol data."
            />
            <AppCard title="IP address overlap">
              <div class="space-y-2">
                <details
                  v-for="group in overlaps"
                  :key="group.title"
                  class="rounded border border-slate-200 p-2 text-sm"
                  :data-ips="group.title"
                >
                  <summary class="cursor-pointer font-medium">{{ group.title }}: {{ num(group.count) }}</summary>
                  <ul v-if="group.items.length" class="mt-2 font-mono text-xs">
                    <li v-for="ip in group.items" :key="ip">{{ ip }}</li>
                  </ul>
                  <p v-else class="mt-2 text-xs text-slate-500">None</p>
                  <p v-if="group.count > group.items.length" class="mt-1 text-xs text-slate-500">
                    Showing the first {{ group.items.length }}.
                  </p>
                </details>
              </div>
            </AppCard>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

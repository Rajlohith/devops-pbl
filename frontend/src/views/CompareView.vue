<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import ChartCard from '@/components/charts/ChartCard.vue'
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import { useComparison } from '@/composables/useComparison'
import { compareBytesBar, compareBytesBarMulti } from '@/utils/charts'
import { byUnit, dateTime, num, signed, signedPercent } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const cmp = useComparison()

const LETTERS = ['C', 'D', 'E'] // up to three extra captures after A and B
const a = ref(String(route.query.a ?? ''))
const b = ref(String(route.query.b ?? ''))
const extras = ref(LETTERS.map((_, i) => route.query[LETTERS[i].toLowerCase()]).filter(Boolean).map(String))
const canAdd = computed(() => extras.value.length < LETTERS.length)

const others = computed(() => cmp.result.value?.others ?? [])
const columns = computed(() => {
  const result = cmp.result.value
  const cols = [
    { key: 'label', label: 'Metric', sticky: true },
    { key: 'a', label: `A — ${result.a.filename}`, align: 'right' },
    { key: 'b', label: `B — ${result.b.filename}`, align: 'right' },
    { key: 'delta', label: 'Change (B − A)', align: 'right' },
    { key: 'delta_percent', label: '%', align: 'right' },
  ]
  others.value.forEach((other, i) => {
    const letter = LETTERS[i]
    cols.push(
      { key: `x${i}`, label: `${letter} — ${other.b.filename}`, align: 'right' },
      { key: `x${i}_delta`, label: `Change (${letter} − A)`, align: 'right' },
      { key: `x${i}_pct`, label: '%', align: 'right' },
    )
  })
  return cols
})
// Slot names for the C/D/E columns (kept as plain strings so the template needs no expressions).
const extraCols = computed(() =>
  others.value.map((_, i) => ({
    i,
    letter: LETTERS[i].toLowerCase(),
    value: `cell-x${i}`,
    delta: `cell-x${i}_delta`,
    pct: `cell-x${i}_pct`,
  })),
)
// One row per metric; `extra[i]` is the same metric measured against capture C, D or E.
const rows = computed(() =>
  cmp.result.value.metrics.map((metric, index) => ({
    ...metric,
    extra: others.value.map((other) => other.metrics[index]),
  })),
)
const chart = computed(() => {
  const result = cmp.result.value
  if (!result?.protocols.length && !others.value.length) return null
  if (others.value.length) return compareBytesBarMulti(result)
  return result.protocols.length ? compareBytesBar(result.protocols) : null
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
  // Keep the chosen captures in the URL so the comparison can be bookmarked or shared.
  if (a.value && b.value && a.value !== b.value) {
    const query = { a: a.value, b: b.value }
    extras.value.forEach((id, i) => {
      if (id) query[LETTERS[i].toLowerCase()] = id
    })
    router.replace({ query })
  }
  await cmp.compare(a.value, b.value, extras.value)
}

function switchAB() {
  ;[a.value, b.value] = [b.value, a.value]
  if (cmp.result.value && a.value && b.value) run() // keep a shown table in step with the selection
}

const addCapture = () => {
  if (canAdd.value) extras.value.push('')
}
const removeCapture = (index) => extras.value.splice(index, 1)

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
      <p class="mt-1 text-slate-500">Compare two analysed captures, or add up to three more (C, D, E) against the baseline A.</p>
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
        <form class="space-y-4" @submit.prevent="run">
          <div class="grid items-end gap-3 sm:grid-cols-2 lg:grid-cols-3">
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
            <div v-for="(_, i) in extras" :key="i">
              <label class="label" :for="`cmp-${LETTERS[i].toLowerCase()}`">Capture {{ LETTERS[i] }}</label>
              <div class="flex gap-2">
                <select :id="`cmp-${LETTERS[i].toLowerCase()}`" v-model="extras[i]" class="field">
                  <option value="">Choose a capture…</option>
                  <option v-for="c in cmp.options.value" :key="c.id" :value="c.id">{{ label(c) }}</option>
                </select>
                <button
                  type="button"
                  class="btn btn-secondary"
                  :aria-label="`Remove capture ${LETTERS[i]}`"
                  :data-remove="LETTERS[i]"
                  @click="removeCapture(i)"
                >
                  ×
                </button>
              </div>
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-3">
            <button id="compare-btn" type="submit" class="btn btn-primary" :disabled="cmp.comparing.value">
              {{ cmp.comparing.value ? 'Comparing…' : 'Compare' }}
            </button>
            <button
              id="switch-btn"
              type="button"
              class="btn btn-secondary"
              title="Swap captures A and B"
              @click="switchAB"
            >
              ⇄ Switch
            </button>
            <button
              v-if="canAdd"
              id="add-capture-btn"
              type="button"
              class="btn btn-secondary"
              :aria-label="`Add capture ${LETTERS[extras.length]}`"
              @click="addCapture"
            >
              + Add capture {{ LETTERS[extras.length] }}
            </button>
          </div>
        </form>
      </AppCard>

      <div id="compare-result" aria-live="polite">
        <StateBlock v-if="cmp.comparing.value" kind="loading" message="Comparing…" />
        <StateBlock v-else-if="cmp.error.value" kind="error" :message="cmp.error.value" :retryable="false" />
        <div v-else-if="cmp.result.value" class="space-y-4">
          <AppCard flush>
            <DataTable
              :columns="columns"
              :rows="rows"
              row-key="key"
              caption="Metric comparison"
              scroll
            >
              <template #cell-a="{ row }"><span :data-cell="`${row.key}-a`">{{ byUnit(row.a, row.unit) }}</span></template>
              <template #cell-b="{ row }"><span :data-cell="`${row.key}-b`">{{ byUnit(row.b, row.unit) }}</span></template>
              <template #cell-delta="{ row }">
                <span :data-cell="`${row.key}-delta`">{{ signed(row.delta, row.unit) }}</span>
              </template>
              <template #cell-delta_percent="{ row }">{{ signedPercent(row.delta_percent) }}</template>
              <template v-for="col in extraCols" :key="col.value" #[col.value]="{ row }">
                <span :data-cell="`${row.key}-${col.letter}`">{{ byUnit(row.extra[col.i].b, row.unit) }}</span>
              </template>
              <template v-for="col in extraCols" :key="col.delta" #[col.delta]="{ row }">
                <span :data-cell="`${row.key}-${col.letter}-delta`">{{ signed(row.extra[col.i].delta, row.unit) }}</span>
              </template>
              <template v-for="col in extraCols" :key="col.pct" #[col.pct]="{ row }">
                {{ signedPercent(row.extra[col.i].delta_percent) }}
              </template>
            </DataTable>
          </AppCard>

          <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <ChartCard
              title="Bytes by transport protocol"
              :config="chart"
              aria-label="Grouped bar chart of bytes per transport protocol for the compared captures"
              empty-text="No protocol data."
            />
            <AppCard title="IP address overlap" :subtitle="others.length ? 'Capture A against capture B' : ''">
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

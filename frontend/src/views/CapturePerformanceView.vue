<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { analysisApi } from '@/api/analysis'
import ChartCard from '@/components/charts/ChartCard.vue'
import AppCard from '@/components/common/AppCard.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { useCaptureDetailStore } from '@/stores/captureDetail'
import { packetRateLine, throughputLine } from '@/utils/charts'
import { bps, DASH, duration, ms, num, percent } from '@/utils/format'

const route = useRoute()
const detail = useCaptureDetailStore()
const id = route.params.id

const { data, error, loading, load } = useAsyncData(() => detail.getPerformance())

const points = computed(() => data.value?.performance.timeseries.points ?? [])
const bpsChart = computed(() => (points.value.length ? throughputLine(points.value) : null))
const ppsChart = computed(() => (points.value.length ? packetRateLine(points.value) : null))

const sizeRange = computed(() => {
  const p = data.value.performance
  return p.min_packet_size_bytes === null ? DASH : `${p.min_packet_size_bytes} / ${p.max_packet_size_bytes} B`
})
const avgSize = computed(() => {
  const size = data.value.performance.avg_packet_size_bytes
  return size === null ? DASH : `${size.toFixed(1)} B`
})
const retransHint = computed(() => {
  const tcp = data.value.tcp
  return tcp.retransmission_rate === null
    ? 'no TCP traffic'
    : `${percent(100 * tcp.retransmission_rate, 2)} of ${num(tcp.packets)} TCP packets`
})

// Bandwidth utilisation needs a link speed, which a capture does not contain, so ask for it.
const linkMbps = ref('')
const utilization = ref(null)
const utilizationError = ref('')
const calculating = ref(false)

async function calculate() {
  calculating.value = true
  utilizationError.value = ''
  try {
    const result = await analysisApi.performance(id, { link_mbps: linkMbps.value })
    utilization.value = result.utilization
  } catch (e) {
    utilization.value = null
    utilizationError.value = e.message
  } finally {
    calculating.value = false
  }
}

const distributions = computed(() => [
  {
    title: 'TCP handshake RTT',
    dist: data.value.latency.handshake_rtt_ms,
    hint: 'First SYN to its SYN-ACK as seen at the capture point; only flows whose handshake was captured.',
  },
  {
    title: 'Flow jitter',
    dist: data.value.latency.flow_jitter_ms,
    hint: 'Mean change in packet inter-arrival gap within each flow (needs 3+ packets). Arrival-time jitter, not RFC 3550.',
  },
])

onMounted(load)
</script>

<template>
  <StateBlock v-if="loading && !data" kind="loading" message="Loading performance…" />
  <StateBlock v-else-if="error" kind="error" :message="error.message" @retry="load" />
  <div v-else-if="data" id="panel-performance" class="space-y-4">
    <div class="grid grid-cols-2 gap-4 md:grid-cols-4">
      <StatCard label="Avg throughput" :value="bps(data.performance.avg_throughput_bps)" />
      <StatCard label="Peak throughput (1 s)" :value="bps(data.performance.peak_throughput_bps)" />
      <StatCard label="Avg packets/s" :value="num(data.performance.avg_packets_per_second, 2)" />
      <StatCard label="Peak packets/s (1 s)" :value="num(data.performance.peak_packets_per_second)" />
      <StatCard label="Avg packet size" :value="avgSize" />
      <StatCard label="Min / max size" :value="sizeRange" />
      <StatCard label="TCP retransmissions" :value="num(data.tcp.retransmissions)" :hint="retransHint" />
      <StatCard label="Duration" :value="duration(data.performance.duration_seconds)" />
    </div>

    <AppCard title="Bandwidth utilisation">
      <form class="flex flex-wrap items-center gap-2" novalidate @submit.prevent="calculate">
        <label class="sr-only" for="link-mbps">Link speed in Mbit/s</label>
        <input
          id="link-mbps"
          v-model="linkMbps"
          class="field w-32"
          type="number"
          min="0"
          step="any"
          placeholder="e.g. 100"
        />
        <span>Mbit/s</span>
        <button id="util-btn" type="submit" class="btn btn-secondary" :disabled="calculating">Calculate</button>
      </form>
      <p id="utilization-result" class="mt-2 text-sm text-slate-600" role="status">
        <span v-if="utilizationError" class="text-red-700">{{ utilizationError }}</span>
        <template v-else-if="utilization">
          At {{ num(utilization.link_capacity_mbps, 2) }} Mbit/s: average
          {{ percent(utilization.avg_percent, 3) }}, peak {{ percent(utilization.peak_percent, 3) }} of
          capacity.
        </template>
        <template v-else>
          Enter the link speed to estimate utilisation. A capture does not record it, so it is not guessed.
        </template>
      </p>
    </AppCard>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <ChartCard
        title="Throughput over time"
        :config="bpsChart"
        aria-label="Line chart of throughput over time"
        empty-text="No traffic in this capture."
      />
      <ChartCard
        title="Packets per second over time"
        :config="ppsChart"
        aria-label="Line chart of packets per second over time"
        empty-text="No traffic in this capture."
      />
    </div>

    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <AppCard v-for="d in distributions" :key="d.title" :title="d.title" :data-card="d.title">
        <dl v-if="d.dist" class="grid grid-cols-2 gap-x-4 text-sm">
          <template
            v-for="[label, value] in [
              ['Samples', num(d.dist.count)], ['Mean', ms(d.dist.mean)], ['Median', ms(d.dist.median)],
              ['95th percentile', ms(d.dist.p95)], ['Min', ms(d.dist.min)], ['Max', ms(d.dist.max)],
            ]"
            :key="label"
          >
            <dt class="text-slate-500">{{ label }}</dt>
            <dd class="text-right font-medium">{{ value }}</dd>
          </template>
        </dl>
        <p v-else class="text-sm text-slate-500">Not available for this capture.</p>
        <p class="mt-2 text-xs text-slate-500">{{ d.hint }}</p>
      </AppCard>
    </div>
    <p class="text-xs text-slate-500">
      Retransmissions count exact duplicate TCP segments, so the figure is a lower bound.
    </p>
  </div>
</template>

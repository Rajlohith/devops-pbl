<script setup>
import {
  BarController,
  BarElement,
  CategoryScale,
  Chart,
  Filler,
  Legend,
  LineController,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
} from 'chart.js'
import { computed, onBeforeUnmount, onMounted, ref, toRaw, watch } from 'vue'

// Register only what the app uses so unused Chart.js code stays out of the bundle.
Chart.register(
  BarController,
  BarElement,
  CategoryScale,
  Filler,
  Legend,
  LineController,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
)
Chart.defaults.font.family = 'ui-sans-serif, system-ui, sans-serif'
Chart.defaults.font.size = 12
Chart.defaults.color = '#64748b'
Chart.defaults.borderColor = '#e2e8f0'

const props = defineProps({
  /** Any Chart.js type registered above: 'line' or 'bar'. */
  type: { type: String, default: 'line' },
  data: { type: Object, required: true },
  options: { type: Object, default: () => ({}) },
  ariaLabel: { type: String, required: true },
  emptyText: { type: String, default: 'No data yet' },
})

const canvas = ref(null)
let chart = null

const isEmpty = computed(() => !props.data.datasets?.some((dataset) => dataset.data?.length))

// Chart.js mutates the objects it is given, so hand it plain copies, never Vue proxies.
const plainData = () => JSON.parse(JSON.stringify(props.data))
const plainOptions = () => ({
  responsive: true,
  maintainAspectRatio: false,
  ...toRaw(props.options),
})

onMounted(() => {
  chart = new Chart(canvas.value, {
    type: props.type,
    data: plainData(),
    options: plainOptions(),
  })
})

watch(
  () => props.data,
  () => {
    if (!chart) return
    chart.data = plainData()
    chart.update()
  },
  { deep: true },
)

onBeforeUnmount(() => {
  chart?.destroy()
  chart = null
})
</script>

<template>
  <div class="relative h-64">
    <canvas ref="canvas" role="img" :aria-label="ariaLabel"></canvas>
    <p
      v-if="isEmpty"
      class="absolute inset-0 flex items-center justify-center text-sm text-slate-400"
    >
      {{ emptyText }}
    </p>
  </div>
</template>

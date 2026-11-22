<script setup>
import {
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  Chart,
  DoughnutController,
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
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  DoughnutController,
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
  /** 'line' | 'bar' | 'doughnut' */
  type: { type: String, default: 'line' },
  data: { type: Object, required: true },
  options: { type: Object, default: () => ({}) },
  /** Required: the canvas is an image to assistive technology, so say what it shows. */
  ariaLabel: { type: String, required: true },
  emptyText: { type: String, default: 'No data yet' },
  /** Tailwind height class for the plot area. */
  heightClass: { type: String, default: 'h-64' },
})

const canvas = ref(null)
let chart = null

const isEmpty = computed(() => !props.data.datasets?.some((dataset) => dataset.data?.length))

// Chart.js mutates what it is given, and misbehaves with Vue's reactive proxies, so hand it
// plain deep copies (functions such as tooltip callbacks are kept as they are).
function plain(value) {
  const raw = toRaw(value)
  if (Array.isArray(raw)) return raw.map(plain)
  if (raw && typeof raw === 'object') {
    return Object.fromEntries(Object.entries(raw).map(([key, item]) => [key, plain(item)]))
  }
  return raw
}

const plainOptions = () => ({ responsive: true, maintainAspectRatio: false, ...plain(props.options) })

onMounted(() => {
  chart = new Chart(canvas.value, {
    type: props.type,
    data: plain(props.data),
    options: plainOptions(),
  })
})

watch(
  () => [props.data, props.options],
  () => {
    if (!chart) return
    chart.data = plain(props.data)
    chart.options = plainOptions()
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
  <div class="relative" :class="heightClass">
    <canvas ref="canvas" role="img" :aria-label="ariaLabel" data-chart="true"></canvas>
    <p v-if="isEmpty" class="absolute inset-0 flex items-center justify-center text-sm text-slate-400">
      {{ emptyText }}
    </p>
  </div>
</template>

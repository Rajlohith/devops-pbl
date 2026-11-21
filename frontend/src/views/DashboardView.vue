<script setup>
import AppCard from '@/components/AppCard.vue'
import BaseChart from '@/components/BaseChart.vue'
import StatCard from '@/components/StatCard.vue'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()

// Placeholders only: no dashboard data is loaded in this foundation step.
const stats = [
  { label: 'Captures', hint: 'Uploaded and analysed' },
  { label: 'Packets analysed', hint: 'Across all captures' },
  { label: 'Total traffic', hint: 'Bytes on the wire' },
  { label: 'Active jobs', hint: 'Queued or processing' },
]

const trafficData = {
  labels: [],
  datasets: [
    {
      label: 'Packets',
      data: [],
      borderColor: '#2563eb',
      backgroundColor: 'rgba(37, 99, 235, 0.1)',
      fill: true,
      tension: 0.3,
      pointRadius: 0,
      borderWidth: 2,
    },
  ],
}
const trafficOptions = {
  plugins: { legend: { display: false } },
  scales: { y: { beginAtZero: true } },
}

const protocolData = {
  labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP'],
  datasets: [{ label: 'Packets', data: [], backgroundColor: '#2563eb', borderRadius: 3 }],
}
const protocolOptions = {
  indexAxis: 'y',
  plugins: { legend: { display: false } },
  scales: { x: { beginAtZero: true } },
}

const columns = ['Capture', 'Status', 'Packets', 'Size', 'Uploaded']
</script>

<template>
  <div class="space-y-6">
    <div>
      <h2 class="text-lg font-semibold text-slate-900">Network overview</h2>
      <p class="mt-1 text-slate-500">Traffic captured and analysed across your sessions.</p>
    </div>

    <div class="rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-blue-900">
      <p class="font-medium">Frontend foundation preview</p>
      <p class="mt-0.5 text-blue-800">
        This dashboard is a placeholder and is not connected to data yet. The existing NetScope
        pages remain the working interface while they are migrated.
        <span v-if="auth.status === 'anonymous'">You are not signed in.</span>
      </p>
    </div>

    <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatCard v-for="stat in stats" :key="stat.label" v-bind="stat" />
    </div>

    <div class="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <AppCard
        class="xl:col-span-2"
        title="Traffic over time"
        subtitle="Packets per interval across recent captures"
      >
        <BaseChart
          type="line"
          :data="trafficData"
          :options="trafficOptions"
          aria-label="Line chart of packets over time; no data yet"
        />
      </AppCard>

      <AppCard title="Protocol distribution" subtitle="Packets by protocol">
        <BaseChart
          type="bar"
          :data="protocolData"
          :options="protocolOptions"
          aria-label="Bar chart of packets by protocol; no data yet"
        />
      </AppCard>
    </div>

    <AppCard title="Recent captures">
      <div class="-m-4 overflow-x-auto">
        <table class="min-w-full text-left">
          <thead class="border-b border-slate-100 bg-slate-50">
            <tr>
              <th
                v-for="column in columns"
                :key="column"
                scope="col"
                class="whitespace-nowrap px-4 py-2 text-xs font-semibold uppercase tracking-wide text-slate-500"
              >
                {{ column }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td :colspan="columns.length" class="px-4 py-10 text-center text-slate-400">
                No captures to display yet.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </AppCard>
  </div>
</template>

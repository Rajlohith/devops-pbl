<script setup>
import { computed, onBeforeUnmount, onMounted, watch } from 'vue'

import ChartCard from '@/components/charts/ChartCard.vue'
import AlertBanner from '@/components/common/AlertBanner.vue'
import AppCard from '@/components/common/AppCard.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatCard from '@/components/common/StatCard.vue'
import RecentSessionsTable from '@/components/dashboard/RecentSessionsTable.vue'
import StatusSummary from '@/components/dashboard/StatusSummary.vue'
import { usePolling } from '@/composables/usePolling'
import { useDashboardStore } from '@/stores/dashboard'
import { capturesBytesBar, protocolDoughnut } from '@/utils/charts'
import { pct, SEVERITIES } from '@/utils/analytics'
import { bytes, num } from '@/utils/format'

const store = useDashboardStore()
const poller = usePolling(() => store.fetch({ silent: true }), { interval: 2500 })

const data = computed(() => store.data)
const trafficChart = computed(() =>
  data.value?.recent_traffic.length ? capturesBytesBar(data.value.recent_traffic) : null,
)
const protocolChart = computed(() =>
  data.value?.protocols.transport.length ? protocolDoughnut(data.value.protocols.transport) : null,
)

// Keep the numbers live only while something is being analysed.
watch(
  () => store.inProgress,
  (count) => (count > 0 ? poller.start() : poller.stop()),
  { immediate: true },
)

onMounted(() => store.fetch())
onBeforeUnmount(poller.stop)
</script>

<template>
  <div class="space-y-6">
    <div>
      <h2 class="text-lg font-semibold text-slate-900">Network overview</h2>
      <p class="mt-1 text-slate-500">Traffic captured and analysed across your sessions.</p>
    </div>

    <AppCard v-if="store.loading && !data" flush>
      <StateBlock kind="loading" message="Loading dashboard…" />
    </AppCard>

    <AppCard v-else-if="store.error && !data" flush>
      <StateBlock kind="error" :message="store.error.message" @retry="store.fetch()" />
    </AppCard>

    <AppCard v-else-if="store.isEmpty" flush>
      <StateBlock kind="empty">
        <h3 class="text-lg font-semibold text-slate-900">No captures yet</h3>
        <p class="mt-1 text-slate-500">Upload a PCAP or PCAPNG file to see traffic statistics here.</p>
        <RouterLink class="btn btn-primary mt-4" :to="{ name: 'captures' }">Upload a capture</RouterLink>
      </StateBlock>
    </AppCard>

    <template v-else-if="data">
      <AlertBanner v-if="data.totals.captures && !data.recent_traffic.length" kind="info">
        None of your captures has been analysed yet, so there are no traffic figures to show.
      </AlertBanner>

      <div class="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <StatCard label="Total captures" :value="num(data.totals.captures)" />
        <StatCard label="Packets analysed" :value="num(data.totals.packets)" />
        <StatCard label="Data processed" :value="bytes(data.totals.bytes)" />
        <StatCard label="Unique IPs" :value="num(data.totals.unique_ips)" />
        <StatCard label="Flows" :value="num(data.totals.flows)" />
      </div>

      <StatusSummary :counts="data.status_counts" :in-progress="data.in_progress" />

      <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ChartCard
          title="Data per analysed capture"
          subtitle="Most recent completed analyses"
          :config="trafficChart"
          aria-label="Bar chart of bytes captured per recent analysis"
          empty-text="No completed analyses yet."
        />
        <ChartCard
          title="Protocol distribution"
          subtitle="Packets by transport protocol"
          :config="protocolChart"
          aria-label="Doughnut chart of packets by transport protocol"
          empty-text="No protocol data yet."
        />
      </div>

      <AppCard
        v-if="data.network_intelligence?.captures_included"
        title="Network intelligence"
        :subtitle="`Pooled across your ${data.network_intelligence.captures_included} most recent analysed captures`"
        data-testid="network-intelligence"
      >
        <div class="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard
            label="TCP connection success"
            :value="pct(data.network_intelligence.tcp.success_rate)"
            :hint="`${num(data.network_intelligence.tcp.established)} of ${num(data.network_intelligence.tcp.observable_attempts)} observable attempts`"
          />
          <StatCard
            label="DNS error responses"
            :value="pct(data.network_intelligence.dns.error_rate)"
            :hint="`${num(data.network_intelligence.dns.queries)} queries`"
          />
          <StatCard
            label="TCP reset rate"
            :value="pct(data.network_intelligence.resets.packet_rate, 2)"
            hint="RST packets / TCP packets"
          />
          <StatCard
            label="Anomaly findings"
            :value="num(data.network_intelligence.anomalies.total)"
            :hint="SEVERITIES.map((s) => `${data.network_intelligence.anomalies.by_severity[s]} ${s}`).join(' · ')"
          />
        </div>
        <p class="mt-3 text-xs text-slate-500">
          Rates are pooled from counts, not averaged; an em dash means nothing could be measured.
          Retransmissions are indicators, not measured packet loss.
        </p>
      </AppCard>

      <RecentSessionsTable :sessions="data.recent_sessions" />
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  captureId: { type: String, required: true },
  packets: { type: Array, default: () => [] },
  /** First related flow, if any; the packet explorer can filter by it. */
  flowId: { type: Number, default: null },
  /** Alternative explorer filter, e.g. { ip, port } for a DNS client. */
  filter: { type: Object, default: null },
})

const query = computed(() => (props.flowId ? { flow_id: String(props.flowId) } : props.filter))
</script>

<template>
  <p class="text-xs text-slate-600" data-packet-refs>
    <span class="font-medium">Packets:</span>
    <span v-if="packets.length" class="font-mono"> {{ packets.join(', ') }}</span>
    <span v-else> none recorded</span>
    <RouterLink
      v-if="query"
      class="ml-2 text-blue-700 hover:underline"
      :to="{ name: 'capture-packets', params: { id: captureId }, query }"
    >
      Open in packet explorer
    </RouterLink>
  </p>
</template>

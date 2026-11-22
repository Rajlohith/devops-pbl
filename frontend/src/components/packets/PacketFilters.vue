<script setup>
import { computed, reactive, watch } from 'vue'

const props = defineProps({
  modelValue: { type: Object, required: true },
  /** Protocol names seen in this capture, for the dropdown. */
  protocols: { type: Array, default: () => [] },
  /** Slot for the export button, which sits with the form actions. */
})
const emit = defineEmits(['apply', 'reset'])

const draft = reactive({ ...props.modelValue })
watch(() => props.modelValue, (next) => Object.assign(draft, next), { deep: true })

// Keep a protocol from the URL selectable even if the summary does not list it.
const protocolOptions = computed(() =>
  props.modelValue.protocol && !props.protocols.includes(props.modelValue.protocol)
    ? [...props.protocols, props.modelValue.protocol]
    : props.protocols,
)

const submit = () => emit('apply', { ...draft, page: 1 })
</script>

<template>
  <form id="packet-filters" class="grid grid-cols-2 items-end gap-3 md:grid-cols-6" @submit.prevent="submit">
    <div>
      <label class="label" for="pf-q">Search</label>
      <input id="pf-q" v-model.trim="draft.q" class="field" type="search" placeholder="IP, port, MAC, packet #" />
    </div>
    <div>
      <label class="label" for="pf-protocol">Protocol</label>
      <select id="pf-protocol" v-model="draft.protocol" class="field">
        <option value="">All protocols</option>
        <option v-for="name in protocolOptions" :key="name" :value="name">{{ name }}</option>
      </select>
    </div>
    <div>
      <label class="label" for="pf-ip">IP address</label>
      <input id="pf-ip" v-model.trim="draft.ip" class="field" placeholder="10.0.0.1 or 2001:db8::1" />
    </div>
    <div>
      <label class="label" for="pf-port">Port</label>
      <input id="pf-port" v-model.trim="draft.port" class="field" type="number" min="0" max="65535" />
    </div>
    <div>
      <label class="label" for="pf-tcp_flags">TCP flags</label>
      <input id="pf-tcp_flags" v-model.trim="draft.tcp_flags" class="field" maxlength="8" placeholder="S, SA, FA…" />
    </div>
    <div>
      <label class="label" for="pf-flow_id">Flow #</label>
      <input id="pf-flow_id" v-model.trim="draft.flow_id" class="field" type="number" min="1" />
    </div>
    <div>
      <label class="label" for="pf-min_length">Min length (B)</label>
      <input id="pf-min_length" v-model.trim="draft.min_length" class="field" type="number" min="0" />
    </div>
    <div>
      <label class="label" for="pf-max_length">Max length (B)</label>
      <input id="pf-max_length" v-model.trim="draft.max_length" class="field" type="number" min="0" />
    </div>
    <div>
      <label class="label" for="pf-sort">Sort</label>
      <select id="pf-sort" v-model="draft.sort" class="field">
        <option value="number">Packet #</option>
        <option value="time">Time</option>
        <option value="length">Length</option>
      </select>
    </div>
    <div>
      <label class="label" for="pf-order">Order</label>
      <select id="pf-order" v-model="draft.order" class="field">
        <option value="asc">Ascending</option>
        <option value="desc">Descending</option>
      </select>
    </div>
    <div>
      <label class="label" for="pf-per_page">Per page</label>
      <select id="pf-per_page" v-model.number="draft.per_page" class="field">
        <option v-for="n in [25, 50, 100, 200]" :key="n" :value="n">{{ n }}</option>
      </select>
    </div>
    <fieldset class="flex flex-col gap-1">
      <legend class="sr-only">Only show</legend>
      <label class="flex items-center gap-2 text-sm">
        <input id="pf-retransmission" v-model="draft.retransmission" type="checkbox" />
        Retransmissions only
      </label>
      <label class="flex items-center gap-2 text-sm">
        <input id="pf-malformed" v-model="draft.malformed" type="checkbox" />
        Malformed only
      </label>
    </fieldset>
    <div class="col-span-2 flex flex-wrap gap-2 md:col-span-6">
      <button type="submit" class="btn btn-primary">Apply filters</button>
      <button id="pf-reset" type="button" class="btn btn-secondary" @click="$emit('reset')">Reset</button>
      <slot />
    </div>
  </form>
</template>

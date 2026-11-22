<script setup>
import { reactive, watch } from 'vue'

const props = defineProps({ modelValue: { type: Object, required: true } })
const emit = defineEmits(['apply'])

const draft = reactive({ ...props.modelValue })
// Keep the form in step when the URL changes (Back button, cross-links).
watch(() => props.modelValue, (next) => Object.assign(draft, next), { deep: true })

const submit = () => emit('apply', { ...draft, page: 1 })
</script>

<template>
  <form id="flow-filters" class="grid grid-cols-2 items-end gap-3 md:grid-cols-6" @submit.prevent="submit">
    <div>
      <label class="label" for="ff-protocol">Protocol</label>
      <input id="ff-protocol" v-model.trim="draft.protocol" class="field" placeholder="TCP, UDP…" />
    </div>
    <div>
      <label class="label" for="ff-application">Application</label>
      <input id="ff-application" v-model.trim="draft.application" class="field" placeholder="DNS, HTTP" />
    </div>
    <div>
      <label class="label" for="ff-ip">IP address</label>
      <input id="ff-ip" v-model.trim="draft.ip" class="field" placeholder="10.0.0.1" />
    </div>
    <div>
      <label class="label" for="ff-port">Port</label>
      <input id="ff-port" v-model.trim="draft.port" class="field" type="number" min="0" max="65535" />
    </div>
    <div>
      <label class="label" for="ff-sort">Sort by</label>
      <select id="ff-sort" v-model="draft.sort" class="field">
        <option value="bytes">Bytes</option>
        <option value="packets">Packets</option>
        <option value="duration">Duration</option>
        <option value="start">Start time</option>
      </select>
    </div>
    <div class="flex gap-2">
      <div class="min-w-0 flex-1">
        <label class="label" for="ff-order">Order</label>
        <select id="ff-order" v-model="draft.order" class="field">
          <option value="desc">Descending</option>
          <option value="asc">Ascending</option>
        </select>
      </div>
      <button type="submit" class="btn btn-primary">Apply</button>
    </div>
  </form>
</template>

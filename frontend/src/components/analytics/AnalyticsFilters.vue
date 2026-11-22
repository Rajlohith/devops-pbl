<script setup>
import { reactive, watch } from 'vue'

/**
 * A compact filter bar. `fields` is `[{ key, label, type: 'select'|'text'|'checkbox', options? }]`
 * and `modelValue` the applied values. Emits `apply` with the edited values and `reset`.
 */
const props = defineProps({
  fields: { type: Array, required: true },
  modelValue: { type: Object, required: true },
})
const emit = defineEmits(['apply', 'reset'])

const draft = reactive({})
watch(
  () => props.modelValue,
  (value) => Object.assign(draft, value),
  { immediate: true, deep: true },
)

const submit = () => emit('apply', { ...draft, page: 1 })
</script>

<template>
  <form class="flex flex-wrap items-end gap-3 border-b border-slate-100 p-3 text-sm" @submit.prevent="submit">
    <label v-for="field in fields" :key="field.key" class="flex flex-col gap-1 text-xs text-slate-600">
      <span class="label mb-0">{{ field.label }}</span>
      <select v-if="field.type === 'select'" v-model="draft[field.key]" class="field" :data-filter="field.key">
        <option v-for="option in field.options" :key="option.value" :value="option.value">
          {{ option.label }}
        </option>
      </select>
      <input
        v-else-if="field.type === 'checkbox'"
        v-model="draft[field.key]"
        type="checkbox"
        class="h-4 w-4"
        :data-filter="field.key"
      />
      <input v-else v-model.trim="draft[field.key]" type="text" class="field" :data-filter="field.key" />
    </label>
    <button type="submit" class="btn btn-primary" data-action="apply">Apply</button>
    <button type="button" class="btn btn-secondary" data-action="reset" @click="emit('reset')">Reset</button>
  </form>
</template>

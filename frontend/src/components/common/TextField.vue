<script setup>
import { computed } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  id: { type: String, required: true },
  label: { type: String, required: true },
  type: { type: String, default: 'text' },
  autocomplete: { type: String, default: '' },
  error: { type: String, default: '' },
  hint: { type: String, default: '' },
  required: { type: Boolean, default: true },
})
defineEmits(['update:modelValue'])

const describedBy = computed(() => {
  const ids = []
  if (props.error) ids.push(`${props.id}-error`)
  if (props.hint) ids.push(`${props.id}-hint`)
  return ids.join(' ') || undefined
})
</script>

<template>
  <div>
    <label :for="id" class="block text-sm font-medium text-slate-700">{{ label }}</label>
    <input
      :id="id"
      :name="id"
      :type="type"
      :value="modelValue"
      :autocomplete="autocomplete || undefined"
      :required="required"
      :aria-invalid="error ? 'true' : undefined"
      :aria-describedby="describedBy"
      class="field mt-1"
      @input="$emit('update:modelValue', $event.target.value)"
    />
    <p v-if="hint && !error" :id="`${id}-hint`" class="mt-1 text-xs text-slate-500">{{ hint }}</p>
    <p v-if="error" :id="`${id}-error`" class="mt-1 text-sm text-red-700">{{ error }}</p>
  </div>
</template>

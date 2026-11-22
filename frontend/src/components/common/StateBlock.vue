<script setup>
defineProps({
  /** 'loading' | 'empty' | 'error' */
  kind: { type: String, required: true },
  message: { type: String, default: '' },
  /** Show a "Try again" button for errors; emits `retry`. */
  retryable: { type: Boolean, default: true },
})
defineEmits(['retry'])
</script>

<template>
  <div
    v-if="kind === 'loading'"
    class="flex items-center gap-3 p-6 text-sm text-slate-500"
    role="status"
    data-state="loading"
  >
    <span
      class="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-slate-600"
      aria-hidden="true"
    ></span>
    {{ message || 'Loading…' }}
  </div>
  <div v-else-if="kind === 'empty'" class="p-8 text-center text-sm text-slate-500" data-state="empty">
    <slot>{{ message }}</slot>
  </div>
  <div v-else class="p-6 text-sm" role="alert" data-state="error">
    <p class="text-red-700">{{ message || 'Something went wrong.' }}</p>
    <button v-if="retryable" type="button" class="btn btn-secondary mt-3" @click="$emit('retry')">
      Try again
    </button>
  </div>
</template>

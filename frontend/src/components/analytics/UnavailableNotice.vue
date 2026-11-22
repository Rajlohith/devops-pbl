<script setup>
import AlertBanner from '@/components/common/AlertBanner.vue'

defineProps({ message: { type: String, default: '' } })
</script>

<template>
  <AlertBanner kind="info" data-state="unavailable">
    <p class="font-medium">Advanced analytics are not available for this capture.</p>
    <p class="mt-1">
      {{ message || 'It was analysed before these metrics existed. Upload it again to generate them.' }}
    </p>
  </AlertBanner>
</template>

<script setup>
import AppCard from '@/components/common/AppCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import PaginationBar from '@/components/common/PaginationBar.vue'
import StateBlock from '@/components/common/StateBlock.vue'

/**
 * Card with loading / error / empty states, a table and pagination. Cell slots
 * (`#cell-<key>="{ row }"`) are passed through to the DataTable.
 */
defineProps({
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  columns: { type: Array, required: true },
  rows: { type: Array, required: true },
  rowKey: { type: [String, Function], required: true },
  loading: { type: Boolean, default: false },
  error: { type: Object, default: null },
  page: { type: Number, required: true },
  perPage: { type: Number, required: true },
  total: { type: Number, required: true },
  emptyText: { type: String, default: 'Nothing matches the current filters.' },
  clickable: { type: Boolean, default: false },
  selectedKey: { type: [String, Number], default: null },
})
const emit = defineEmits(['update:page', 'row-click', 'retry'])
</script>

<template>
  <AppCard :title="title" :subtitle="subtitle" flush>
    <template #actions><slot name="actions" /></template>
    <slot name="filters" />
    <StateBlock v-if="loading && !rows.length" kind="loading" />
    <StateBlock v-else-if="error" kind="error" :message="error.message" @retry="emit('retry')" />
    <StateBlock v-else-if="!rows.length" kind="empty" :message="emptyText" />
    <template v-else>
      <DataTable
        :columns="columns"
        :rows="rows"
        :row-key="rowKey"
        :caption="title"
        :clickable="clickable"
        :selected-key="selectedKey"
        @row-click="emit('row-click', $event)"
      >
        <template v-for="(_, name) in $slots" :key="name" #[name]="slotProps">
          <slot :name="name" v-bind="slotProps || {}" />
        </template>
      </DataTable>
      <PaginationBar
        :page="page"
        :per-page="perPage"
        :total="total"
        @update:page="emit('update:page', $event)"
      />
    </template>
  </AppCard>
</template>

<script setup>
/**
 * A simple, accessible table. Columns are `{ key, label, align?: 'right' }`.
 * Customise a cell with a `#cell-<key>="{ row }"` slot; otherwise `row[key]` is shown.
 * With `clickable`, rows are focusable and activate on click or Enter/Space.
 * Wide tables: `scroll` keeps every column at its natural width (the wrapper scrolls
 * horizontally) and a column with `sticky: true` stays visible while scrolling.
 */
defineProps({
  columns: { type: Array, required: true },
  rows: { type: Array, required: true },
  rowKey: { type: [String, Function], required: true },
  caption: { type: String, default: '' },
  clickable: { type: Boolean, default: false },
  selectedKey: { type: [String, Number], default: null },
  monospace: { type: Boolean, default: false },
  scroll: { type: Boolean, default: false },
})
defineEmits(['row-click'])

const keyOf = (row, rowKey) => (typeof rowKey === 'function' ? rowKey(row) : row[rowKey])
</script>

<template>
  <div class="overflow-x-auto">
    <table
      class="w-full text-left text-sm"
      :class="[monospace ? 'font-mono text-xs' : '', scroll ? 'min-w-max whitespace-nowrap' : '']"
    >
      <caption v-if="caption" class="sr-only">{{ caption }}</caption>
      <thead class="bg-slate-50">
        <tr>
          <th
            v-for="column in columns"
            :key="column.key"
            scope="col"
            class="th"
            :class="[column.align === 'right' ? 'text-right' : '', column.sticky ? 'sticky left-0 z-10 bg-slate-50' : '']"
          >
            {{ column.label }}
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in rows"
          :key="keyOf(row, rowKey)"
          class="border-t border-slate-100"
          :class="[
            clickable ? 'cursor-pointer hover:bg-slate-50 focus-visible:bg-slate-50' : '',
            selectedKey !== null && selectedKey === keyOf(row, rowKey) ? 'bg-blue-50' : '',
          ]"
          :tabindex="clickable ? 0 : undefined"
          :aria-selected="clickable && selectedKey !== null ? selectedKey === keyOf(row, rowKey) : undefined"
          @click="clickable && $emit('row-click', row)"
          @keydown.enter="clickable && $emit('row-click', row)"
          @keydown.space.prevent="clickable && $emit('row-click', row)"
        >
          <td
            v-for="column in columns"
            :key="column.key"
            class="td"
            :class="[column.align === 'right' ? 'text-right' : '', column.sticky ? 'sticky left-0 z-10 bg-white' : '']"
          >
            <slot :name="`cell-${column.key}`" :row="row">{{ row[column.key] }}</slot>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

import { flushPromises, mount } from '@vue/test-utils'
import { Chart } from 'chart.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'

import BaseChart from '@/components/charts/BaseChart.vue'
import ChartCard from '@/components/charts/ChartCard.vue'
import DataTable from '@/components/common/DataTable.vue'
import PaginationBar from '@/components/common/PaginationBar.vue'
import StateBlock from '@/components/common/StateBlock.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import { useAsyncData } from '@/composables/useAsyncData'
import { usePolling } from '@/composables/usePolling'

afterEach(() => vi.useRealTimers())

describe('BaseChart', () => {
  const data = { labels: ['a', 'b'], datasets: [{ data: [1, 2] }] }

  it('creates a Chart.js chart of the requested type with the given data and options', () => {
    const tooltip = vi.fn()
    mount(BaseChart, {
      props: { type: 'bar', data, options: { plugins: { tooltip: { callbacks: { label: tooltip } } } }, ariaLabel: 'Bytes per host' },
    })
    expect(Chart.instances).toHaveLength(1)
    const chart = Chart.instances[0]
    expect(chart.config.type).toBe('bar')
    expect(chart.config.data).toEqual(data)
    expect(chart.config.options.responsive).toBe(true)
    expect(chart.config.options.maintainAspectRatio).toBe(false)
    expect(chart.config.options.plugins.tooltip.callbacks.label).toBe(tooltip) // functions survive
  })

  it('is exposed to assistive technology', () => {
    const wrapper = mount(BaseChart, { props: { data, ariaLabel: 'Throughput over time' } })
    const canvas = wrapper.get('canvas')
    expect(canvas.attributes('role')).toBe('img')
    expect(canvas.attributes('aria-label')).toBe('Throughput over time')
  })

  it('updates in place when the data changes, and does not create a second chart', async () => {
    const wrapper = mount(BaseChart, { props: { data, ariaLabel: 'x' } })
    await wrapper.setProps({ data: { labels: ['a', 'b', 'c'], datasets: [{ data: [1, 2, 3] }] } })
    expect(Chart.instances).toHaveLength(1)
    expect(Chart.instances[0].update).toHaveBeenCalled()
    expect(Chart.instances[0].data.datasets[0].data).toEqual([1, 2, 3])
  })

  it('destroys the chart on unmount', () => {
    const wrapper = mount(BaseChart, { props: { data, ariaLabel: 'x' } })
    wrapper.unmount()
    expect(Chart.instances[0].destroyed).toBe(true)
  })

  it('shows an empty message when there is nothing to plot', () => {
    const wrapper = mount(BaseChart, {
      props: { data: { labels: [], datasets: [{ data: [] }] }, ariaLabel: 'x', emptyText: 'No traffic yet' },
    })
    expect(wrapper.text()).toBe('No traffic yet')
  })

  it('ChartCard shows its empty text instead of a chart when it has no config', () => {
    const wrapper = mount(ChartCard, { props: { title: 'T', config: null, ariaLabel: 'x', emptyText: 'Nothing to show' } })
    expect(wrapper.text()).toContain('Nothing to show')
    expect(Chart.instances).toHaveLength(0)
  })
})

describe('DataTable', () => {
  const columns = [{ key: 'name', label: 'Name' }, { key: 'size', label: 'Size', align: 'right' }]
  const rows = [{ id: 1, name: 'a', size: 10 }, { id: 2, name: 'b', size: 20 }]

  it('renders accessible headers, a caption and cell slots', () => {
    const wrapper = mount(DataTable, {
      props: { columns, rows, rowKey: 'id', caption: 'Things' },
      slots: { 'cell-size': '<template #cell-size="{ row }">{{ row.size }} B</template>' },
    })
    expect(wrapper.get('caption').text()).toBe('Things')
    expect(wrapper.findAll('th').every((th) => th.attributes('scope') === 'col')).toBe(true)
    expect(wrapper.findAll('tbody tr')).toHaveLength(2)
    expect(wrapper.findAll('td')[1].text()).toBe('10 B')
  })

  it('makes clickable rows keyboard operable', async () => {
    const wrapper = mount(DataTable, { props: { columns, rows, rowKey: 'id', clickable: true, selectedKey: 2 } })
    const [first, second] = wrapper.findAll('tbody tr')
    expect(first.attributes('tabindex')).toBe('0')
    expect(second.attributes('aria-selected')).toBe('true')
    await first.trigger('click')
    await first.trigger('keydown.enter')
    await first.trigger('keydown.space')
    expect(wrapper.emitted('row-click')).toHaveLength(3)
    expect(wrapper.emitted('row-click')[0][0]).toEqual(rows[0])
  })

  it('leaves rows inert when not clickable', async () => {
    const wrapper = mount(DataTable, { props: { columns, rows, rowKey: 'id' } })
    await wrapper.get('tbody tr').trigger('click')
    expect(wrapper.emitted('row-click')).toBeUndefined()
    expect(wrapper.get('tbody tr').attributes('tabindex')).toBeUndefined()
  })
})

describe('PaginationBar', () => {
  it('reports the visible range and the page count', () => {
    const wrapper = mount(PaginationBar, { props: { page: 2, perPage: 15, total: 40 } })
    expect(wrapper.get('[data-role="range"]').text()).toBe('16–30 of 40')
    expect(wrapper.text()).toContain('Page 2 / 3')
  })

  it('disables Previous on the first page and Next on the last', () => {
    const first = mount(PaginationBar, { props: { page: 1, perPage: 10, total: 25 } }).findAll('button')
    expect([first[0].attributes('disabled'), first[1].attributes('disabled')]).toEqual(['', undefined])
    const last = mount(PaginationBar, { props: { page: 3, perPage: 10, total: 25 } }).findAll('button')
    expect([last[0].attributes('disabled'), last[1].attributes('disabled')]).toEqual([undefined, ''])
  })

  it('emits the new page', async () => {
    const wrapper = mount(PaginationBar, { props: { page: 2, perPage: 10, total: 50 } })
    const [previous, next] = wrapper.findAll('button')
    await next.trigger('click')
    await previous.trigger('click')
    expect(wrapper.emitted('update:page')).toEqual([[3], [1]])
  })

  it('handles an empty result', () => {
    const wrapper = mount(PaginationBar, { props: { page: 1, perPage: 10, total: 0 } })
    expect(wrapper.get('[data-role="range"]').text()).toBe('0–0 of 0')
    expect(wrapper.findAll('button').every((b) => b.attributes('disabled') !== undefined)).toBe(true)
  })
})

describe('small components', () => {
  it('StateBlock: loading, empty, and error with retry', async () => {
    expect(mount(StateBlock, { props: { kind: 'loading', message: 'Loading things…' } }).text()).toContain('Loading things…')
    expect(mount(StateBlock, { props: { kind: 'empty', message: 'Nothing here' } }).text()).toBe('Nothing here')
    const error = mount(StateBlock, { props: { kind: 'error', message: 'Broke' } })
    expect(error.attributes('role')).toBe('alert')
    await error.get('button').trigger('click')
    expect(error.emitted('retry')).toHaveLength(1)
    expect(mount(StateBlock, { props: { kind: 'error', retryable: false } }).find('button').exists()).toBe(false)
  })

  it('StatusBadge tolerates an unknown status', () => {
    expect(mount(StatusBadge, { props: { status: 'completed' } }).classes()).toContain('bg-green-100')
    expect(mount(StatusBadge, { props: { status: 'mystery' } }).text()).toBe('mystery')
  })
})

describe('composables', () => {
  it('usePolling waits for each run to finish, and stops', async () => {
    vi.useFakeTimers()
    let running = 0
    let maxConcurrent = 0
    const task = vi.fn(async () => {
      running += 1
      maxConcurrent = Math.max(maxConcurrent, running)
      await new Promise((r) => setTimeout(r, 3000))
      running -= 1
    })
    const poller = usePolling(task, { interval: 1000 })
    poller.start()
    poller.start() // idempotent
    await vi.advanceTimersByTimeAsync(10_000)
    expect(maxConcurrent).toBe(1)
    expect(task.mock.calls.length).toBeGreaterThanOrEqual(2)
    poller.stop()
    const calls = task.mock.calls.length
    await vi.advanceTimersByTimeAsync(10_000)
    expect(task.mock.calls.length).toBe(calls)
  })

  it('usePolling survives a failing task', async () => {
    vi.useFakeTimers()
    const task = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValue(undefined)
    const poller = usePolling(task, { interval: 100 })
    poller.start()
    await vi.advanceTimersByTimeAsync(350)
    expect(task.mock.calls.length).toBeGreaterThanOrEqual(3)
    poller.stop()
  })

  it('useAsyncData tracks loading/error/data and ignores stale responses', async () => {
    const resolvers = []
    const fetcher = vi.fn(() => new Promise((resolve) => resolvers.push(resolve)))
    const state = useAsyncData(fetcher)
    const first = state.load('slow')
    const second = state.load('fast')
    expect(state.loading.value).toBe(true)
    resolvers[1]('fast result')
    await second
    resolvers[0]('slow result') // arrives late and must not overwrite the newer answer
    await first
    await flushPromises()
    expect(state.data.value).toBe('fast result')
    expect(state.loading.value).toBe(false)
  })

  it('useAsyncData keeps data on a silent refresh failure but reports a normal failure', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce('ok').mockRejectedValue(new Error('down'))
    const state = useAsyncData(fetcher)
    await state.load()
    await state.refresh()
    expect(state.data.value).toBe('ok')
    expect(state.error.value).toBeNull()
    await state.load()
    expect(state.error.value.message).toBe('down')
    await nextTick()
  })
})

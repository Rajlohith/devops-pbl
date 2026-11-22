import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from '@/api/errors'
import CapturesView from '@/views/CapturesView.vue'

import { capture, page } from '../fixtures'
import { ID, mountAt, settle, text } from '../helpers'

vi.mock('@/api/captures', () => ({
  capturesApi: { list: vi.fn(), get: vi.fn(), status: vi.fn(), analyze: vi.fn(), remove: vi.fn(), upload: vi.fn() },
}))
const { capturesApi } = await import('@/api/captures')

const pcap = (name = 'trace.pcap', size = 2048) => {
  const file = new File(['x'.repeat(8)], name, { type: 'application/octet-stream' })
  Object.defineProperty(file, 'size', { value: size })
  return file
}

async function choose(wrapper, file) {
  const input = wrapper.get('#file-input')
  Object.defineProperty(input.element, 'files', { value: [file], configurable: true })
  await input.trigger('change')
}

beforeEach(() => {
  vi.clearAllMocks()
  capturesApi.list.mockResolvedValue(page([]))
})
afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('upload', () => {
  it('starts disabled and accepts a valid file', async () => {
    const { wrapper } = await mountAt(CapturesView, '/captures')
    expect(wrapper.get('#upload-button').attributes('disabled')).toBeDefined()
    expect(wrapper.get('#chosen-file').text()).toBe('No file selected')
    await choose(wrapper, pcap('trace.pcapng', 2_500_000))
    expect(wrapper.get('#chosen-file').text()).toBe('trace.pcapng (2.50 MB)')
    expect(wrapper.get('#upload-button').attributes('disabled')).toBeUndefined()
  })

  it('rejects unsupported file types before uploading', async () => {
    const { wrapper } = await mountAt(CapturesView, '/captures')
    await choose(wrapper, pcap('notes.txt'))
    expect(wrapper.get('#upload-message').text()).toContain('Unsupported file type')
    expect(wrapper.get('#upload-button').attributes('disabled')).toBeDefined()
    await wrapper.get('form').trigger('submit')
    expect(capturesApi.upload).not.toHaveBeenCalled()
  })

  it('uploads with a live progress bar, then offers a link to the capture and refreshes the list', async () => {
    let report
    let finish
    capturesApi.upload.mockImplementation((file, options) => {
      report = options.onProgress
      return new Promise((resolve) => (finish = resolve))
    })
    const { wrapper } = await mountAt(CapturesView, '/captures')
    const file = pcap('trace.pcap')
    await choose(wrapper, file)
    await wrapper.get('form').trigger('submit')

    expect(capturesApi.upload).toHaveBeenCalledWith(file, expect.objectContaining({ analyze: true }))
    expect(wrapper.get('#upload-button').attributes('disabled')).toBeDefined()

    report(0.42)
    await settle()
    const bar = wrapper.get('[role="progressbar"]')
    expect(bar.attributes('aria-valuenow')).toBe('42')
    expect(wrapper.get('#upload-progress-text').text()).toBe('Uploading… 42%')

    report(1)
    await settle()
    expect(wrapper.get('#upload-progress-text').text()).toContain('validating')

    capturesApi.list.mockResolvedValue(page([capture({ id: ID, original_filename: 'trace.pcap' })]))
    finish(capture({ id: ID, original_filename: 'trace.pcap', status: 'pending' }))
    await settle()
    const message = wrapper.get('#upload-message')
    expect(message.text()).toContain('Uploaded trace.pcap.')
    expect(message.get('a').attributes('href')).toBe(`/captures/${ID}`)
    expect(wrapper.find('[role="progressbar"]').exists()).toBe(false)
    expect(wrapper.get('#chosen-file').text()).toBe('No file selected')
    expect(wrapper.findAll('tbody tr')).toHaveLength(1) // history refreshed
  })

  it('can upload without starting the analysis', async () => {
    capturesApi.upload.mockResolvedValue(capture({ status: 'uploaded' }))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    await choose(wrapper, pcap())
    await wrapper.get('#analyze-now').setValue(false)
    await wrapper.get('form').trigger('submit')
    expect(capturesApi.upload).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ analyze: false }))
  })

  it('shows the server rejection and allows another attempt', async () => {
    capturesApi.upload.mockRejectedValue(new ApiError({ message: 'Not a valid PCAP or PCAPNG capture.', status: 400 }))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    await choose(wrapper, pcap('fake.pcap'))
    await wrapper.get('form').trigger('submit')
    await settle()
    expect(wrapper.get('#upload-message').text()).toContain('Not a valid PCAP')
    await choose(wrapper, pcap('real.pcap'))
    expect(wrapper.get('#upload-message').text()).toBe('')
    expect(wrapper.get('#upload-button').attributes('disabled')).toBeUndefined()
  })

  it('reports an unreachable server', async () => {
    capturesApi.upload.mockRejectedValue(new ApiError({ message: 'x', kind: 'network' }))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    await choose(wrapper, pcap())
    await wrapper.get('form').trigger('submit')
    await settle()
    expect(wrapper.get('#upload-message').text()).toBe('Upload failed: could not reach the server.')
  })

  it('warns when the upload was stored but the analysis could not be queued', async () => {
    capturesApi.upload.mockResolvedValue(capture({ status: 'failed', error_message: 'Job service unavailable.' }))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    await choose(wrapper, pcap())
    await wrapper.get('form').trigger('submit')
    await settle()
    expect(wrapper.get('#upload-message').text()).toContain('analysis could not start: Job service unavailable.')
  })

  it('accepts a dropped file', async () => {
    const { wrapper } = await mountAt(CapturesView, '/captures')
    const file = pcap('dropped.cap')
    await wrapper.get('#drop-zone').trigger('drop', { dataTransfer: { files: [file] } })
    expect(wrapper.get('#chosen-file').text()).toContain('dropped.cap')
  })
})

describe('capture history', () => {
  it('shows an empty state, and a filter-specific one', async () => {
    const { wrapper } = await mountAt(CapturesView, '/captures')
    expect(wrapper.get('[data-state="empty"]').text()).toContain('No captures yet')
    const filtered = await mountAt(CapturesView, '/captures?status=failed')
    expect(filtered.wrapper.get('[data-state="empty"]').text()).toContain('No captures with status “failed”')
  })

  it('lists captures with status-specific details and actions', async () => {
    capturesApi.list.mockResolvedValue(page([
      capture({ id: 'a', original_filename: 'done.pcap', status: 'completed', packet_count: 15 }),
      capture({ id: 'b', original_filename: 'busy.pcap', status: 'processing', packet_count: 4000 }),
      capture({ id: 'c', original_filename: 'bad.pcap', status: 'failed', error_message: 'File ended unexpectedly (truncated).' }),
      capture({ id: 'd', original_filename: 'new.pcap', status: 'uploaded' }),
    ]))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(4)
    expect(rows[0].text()).toContain('15 packets')
    expect(rows[0].find('[data-action="analyze"]').exists()).toBe(false)
    expect(rows[1].text()).toContain('4,000 packets so far')
    expect(rows[2].text()).toContain('File ended unexpectedly')
    expect(rows[2].get('[data-action="analyze"]').text()).toContain('Retry')
    expect(rows[3].get('[data-action="analyze"]').text()).toContain('Analyse')
    expect(rows[0].get('a').attributes('href')).toBe('/captures/a')
    // every action has an accessible name that says which capture it affects
    expect(rows[2].get('[data-action="delete"]').text()).toContain('bad.pcap')
  })

  it('shows an error with a retry', async () => {
    capturesApi.list.mockRejectedValueOnce(new ApiError({ message: 'Unable to reach the NetScope server.', kind: 'network' }))
    capturesApi.list.mockResolvedValueOnce(page([capture()]))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    expect(wrapper.get('[role="alert"]').text()).toContain('Unable to reach')
    await wrapper.get('[data-state="error"] button').trigger('click')
    await settle()
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
  })

  it('filters by status through the URL', async () => {
    const { wrapper, router } = await mountAt(CapturesView, '/captures')
    capturesApi.list.mockClear()
    await wrapper.get('#status-filter').setValue('failed')
    await settle()
    expect(router.currentRoute.value.query).toEqual({ status: 'failed' })
    expect(capturesApi.list).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed', page: 1 }))
  })

  it('restores filters and the page from the URL', async () => {
    await mountAt(CapturesView, '/captures?status=completed&page=2')
    expect(capturesApi.list).toHaveBeenCalledWith(expect.objectContaining({ status: 'completed', page: 2, per_page: 15 }))
  })

  it('paginates', async () => {
    const items = Array.from({ length: 15 }, (_, i) => capture({ id: `id-${i}`, original_filename: `f${i}.pcap` }))
    capturesApi.list.mockResolvedValue(page(items, { total: 40 }))
    const { wrapper, router } = await mountAt(CapturesView, '/captures')
    expect(wrapper.get('[data-role="range"]').text()).toBe('1–15 of 40')
    expect(text(wrapper)).toContain('Page 1 / 3')
    const [previous, next] = wrapper.findAll('nav[aria-label="Pagination"] button')
    expect(previous.attributes('disabled')).toBeDefined()
    capturesApi.list.mockResolvedValue(page(items, { total: 40, page: 2 }))
    await next.trigger('click')
    await settle()
    expect(router.currentRoute.value.query.page).toBe('2')
    expect(capturesApi.list).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 }))
    expect(wrapper.get('[data-role="range"]').text()).toBe('16–30 of 40')
  })

  it('steps back to the last page if the current one empties', async () => {
    capturesApi.list.mockImplementation(async ({ page: p }) =>
      p === 3 ? page([], { total: 20, page: 3 }) : page([capture({ id: `p${p}` })], { total: 20, page: p }),
    )
    const { wrapper, router } = await mountAt(CapturesView, '/captures?page=3')
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)
    await vi.waitFor(() => expect(router.currentRoute.value.query.page).toBe('2'))
  })

  it('retries an analysis and refreshes the list', async () => {
    capturesApi.list.mockResolvedValue(page([capture({ id: 'c', status: 'failed', error_message: 'boom' })]))
    capturesApi.analyze.mockResolvedValue(capture({ id: 'c', status: 'pending' }))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    capturesApi.list.mockResolvedValue(page([capture({ id: 'c', status: 'pending' })]))
    await wrapper.get('[data-action="analyze"]').trigger('click')
    await settle()
    expect(capturesApi.analyze).toHaveBeenCalledWith('c')
    expect(wrapper.get('tbody tr').text()).toContain('pending')
  })

  it('shows why an analysis could not be started', async () => {
    capturesApi.list.mockResolvedValue(page([capture({ id: 'c', status: 'uploaded' })]))
    capturesApi.analyze.mockRejectedValue(new ApiError({ message: 'Job service unavailable.', status: 503 }))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    await wrapper.get('[data-action="analyze"]').trigger('click')
    await settle()
    expect(wrapper.get('[data-alert="error"]').text()).toContain('Job service unavailable.')
  })

  it('deletes only after confirmation', async () => {
    capturesApi.list.mockResolvedValue(page([capture({ id: 'c', original_filename: 'old.pcap' })]))
    capturesApi.remove.mockResolvedValue(undefined)
    const confirm = vi.spyOn(window, 'confirm')
    const { wrapper } = await mountAt(CapturesView, '/captures')

    confirm.mockReturnValueOnce(false)
    await wrapper.get('[data-action="delete"]').trigger('click')
    expect(capturesApi.remove).not.toHaveBeenCalled()

    confirm.mockReturnValueOnce(true)
    capturesApi.list.mockResolvedValue(page([]))
    await wrapper.get('[data-action="delete"]').trigger('click')
    await settle()
    expect(confirm).toHaveBeenLastCalledWith(expect.stringContaining('old.pcap'))
    expect(capturesApi.remove).toHaveBeenCalledWith('c')
    expect(wrapper.find('[data-state="empty"]').exists()).toBe(true)
  })

  it('shows a failed delete', async () => {
    capturesApi.list.mockResolvedValue(page([capture({ id: 'c' })]))
    capturesApi.remove.mockRejectedValue(new ApiError({ message: 'Capture not found.', status: 404 }))
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const { wrapper } = await mountAt(CapturesView, '/captures')
    await wrapper.get('[data-action="delete"]').trigger('click')
    await settle()
    expect(wrapper.get('[data-alert="error"]').text()).toContain('Delete failed: Capture not found.')
  })

  it('updates statuses automatically while jobs run, then stops polling', async () => {
    vi.useFakeTimers()
    capturesApi.list
      .mockResolvedValueOnce(page([capture({ status: 'processing', packet_count: 100 })]))
      .mockResolvedValueOnce(page([capture({ status: 'processing', packet_count: 900 })]))
      .mockResolvedValue(page([capture({ status: 'completed', packet_count: 1500 })]))
    const { wrapper } = await mountAt(CapturesView, '/captures')
    expect(wrapper.get('tbody tr').text()).toContain('100 packets so far')
    await vi.advanceTimersByTimeAsync(2100)
    expect(wrapper.get('tbody tr').text()).toContain('900 packets so far')
    await vi.advanceTimersByTimeAsync(2100)
    expect(wrapper.get('tbody tr').text()).toContain('1,500 packets')
    const calls = capturesApi.list.mock.calls.length
    await vi.advanceTimersByTimeAsync(10_000)
    expect(capturesApi.list.mock.calls.length).toBe(calls)
  })
})

import { describe, expect, it } from 'vitest'

import { cleanParams } from '@/api/params'
import { filenameFromDisposition } from '@/api/reports'
import { compareBytesBar, protocolDoughnut, throughputLine } from '@/utils/charts'
import { safeNext } from '@/utils/safeNext'

describe('safeNext (post-login redirects)', () => {
  it('accepts same-site paths, with query and hash', () => {
    expect(safeNext('/captures')).toBe('/captures')
    expect(safeNext('/captures/abc/packets?protocol=TCP#x')).toBe('/captures/abc/packets?protocol=TCP#x')
  })

  it.each([
    'https://evil.example/', '//evil.example', '/\\evil.example', '/javascript:alert(1)',
    'javascript:alert(1)', 'captures', '', null, undefined, 42,
  ])('rejects %j', (target) => {
    expect(safeNext(target)).toBeNull()
  })
})

describe('cleanParams', () => {
  it('drops unset values and sends true as a string', () => {
    expect(cleanParams({ a: '', b: null, c: undefined, d: false, e: 0, f: 'x', g: true })).toEqual({
      e: 0, f: 'x', g: 'true',
    })
  })
})

describe('filenameFromDisposition', () => {
  it('reads the quoted filename the API sends', () => {
    expect(filenameFromDisposition('attachment; filename="netscope-4318f5fd-report.pdf"', 'x')).toBe('netscope-4318f5fd-report.pdf')
  })
  it('falls back when there is no header', () => {
    expect(filenameFromDisposition(undefined, 'fallback.csv')).toBe('fallback.csv')
  })
})

describe('chart configuration builders', () => {
  it('builds a protocol doughnut with one colour per protocol', () => {
    const cfg = protocolDoughnut([{ protocol: 'TCP', packets: 9 }, { protocol: 'UDP', packets: 2 }])
    expect(cfg.type).toBe('doughnut')
    expect(cfg.data.labels).toEqual(['TCP', 'UDP'])
    expect(cfg.data.datasets[0].data).toEqual([9, 2])
    expect(new Set(cfg.data.datasets[0].backgroundColor).size).toBe(2)
  })

  it('builds a time series from the API points', () => {
    const cfg = throughputLine([
      { time: '2023-11-14T22:13:20+00:00', bits_per_second: 5600 },
      { time: '2023-11-14T22:13:21+00:00', bits_per_second: 1600 },
    ])
    expect(cfg.type).toBe('line')
    expect(cfg.data.labels).toEqual(['22:13:20', '22:13:21'])
    expect(cfg.data.datasets[0].data).toEqual([5600, 1600])
    // tooltips and axis ticks use the same unit formatting as the rest of the UI
    expect(cfg.options.plugins.tooltip.callbacks.label({ parsed: { y: 1712 } })).toBe('1.71 Kbit/s')
  })

  it('treats a protocol missing from one capture as zero bytes', () => {
    const cfg = compareBytesBar([{ protocol: 'ARP', a: { bytes: 42 }, b: null }])
    expect(cfg.data.datasets.map((d) => d.data[0])).toEqual([42, 0])
  })
})

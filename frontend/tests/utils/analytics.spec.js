import { describe, expect, it } from 'vitest'

import {
  countBar, directionDoughnut, evidenceValue, histogramBar, label, msOrDash, pct, pctValue,
  severityBar, stateDoughnut, talkersBar,
} from '@/utils/analytics'

describe('analytics formatting', () => {
  it('formats ratios and shows a dash for unavailable values', () => {
    expect(pct(0.5)).toBe('50.0%')
    expect(pct(0.1234, 2)).toBe('12.34%')
    expect(pct(null)).toBe('\u2014')
    expect(pct(0)).toBe('0.0%') // a real zero is not "unavailable"
    expect(pctValue(12.5)).toBe('12.5%')
    expect(msOrDash(null)).toBe('\u2014')
    expect(msOrDash(5)).toBe('5.00 ms')
    expect(msOrDash(120)).toBe('120.0 ms')
    expect(label('no_synack')).toBe('no synack')
  })

  it('renders evidence values readably', () => {
    expect(evidenceValue([1, 2])).toBe('1, 2')
    expect(evidenceValue(0.123456)).toBe('0.1235')
    expect(evidenceValue({ a: 1 })).toBe('{"a":1}')
    expect(evidenceValue(null)).toBe('\u2014')
  })
})

describe('analytics charts', () => {
  it('hides empty histograms and series', () => {
    expect(histogramBar([{ label: 'a', count: 0 }], 'x')).toBeNull()
    expect(histogramBar(undefined, 'x')).toBeNull()
    expect(countBar({}, 'x')).toBeNull()
    expect(severityBar({ info: 0, low: 0, medium: 0, high: 0 })).toBeNull()
    expect(talkersBar([])).toBeNull()
    expect(directionDoughnut({ inbound: { bytes: 0 } })).toBeNull()
  })

  it('draws only non-empty TCP states, in fixed colours', () => {
    const chart = stateDoughnut({ established: 3, incomplete: 0, refused: 1, unclassified: 0 })
    expect(chart.data.labels).toEqual(['established', 'refused'])
    expect(chart.data.datasets[0].data).toEqual([3, 1])
  })

  it('orders severities high to info', () => {
    const chart = severityBar({ info: 1, low: 2, medium: 3, high: 4 })
    expect(chart.data.labels).toEqual(['high', 'medium', 'low', 'info'])
    expect(chart.data.datasets[0].data).toEqual([4, 3, 2, 1])
  })
})

/** Formatting and chart builders for the Phase 4 analytics views. */
import { PALETTE, colorAt } from './charts'
import { DASH, bytes, num } from './format'

/** A 0..1 ratio as a percentage; an em dash when the metric is unavailable (null). */
export const pct = (ratio, digits = 1) =>
  ratio === null || ratio === undefined ? DASH : `${(100 * ratio).toFixed(digits)}%`

/** A value that is already a percentage (0..100). */
export const pctValue = (value, digits = 1) =>
  value === null || value === undefined ? DASH : `${Number(value).toFixed(digits)}%`

export const msOrDash = (value) =>
  value === null || value === undefined ? DASH : `${Number(value).toFixed(value < 10 ? 2 : 1)} ms`

export const secondsOrDash = (value) =>
  value === null || value === undefined ? DASH : `${Number(value).toFixed(value < 10 ? 3 : 1)} s`

export const label = (text) => (text ? String(text).replace(/_/g, ' ') : DASH)

export const STATE_COLORS = {
  established: '#16a34a',
  incomplete: '#f59e0b',
  refused: '#dc2626',
  unclassified: '#94a3b8',
}
export const SEVERITY_COLORS = { info: '#94a3b8', low: '#2563eb', medium: '#f59e0b', high: '#dc2626' }
export const SEVERITIES = ['high', 'medium', 'low', 'info']

const hideLegend = { legend: { display: false } }

export function stateDoughnut(states) {
  const keys = Object.keys(STATE_COLORS).filter((k) => states[k] > 0)
  return {
    type: 'doughnut',
    data: {
      labels: keys.map(label),
      datasets: [{ data: keys.map((k) => states[k]), backgroundColor: keys.map((k) => STATE_COLORS[k]) }],
    },
    options: { plugins: { legend: { position: 'right' } } },
  }
}

/** Bars for a histogram: `rows` are `{label, count}`. Returns null when nothing was measured. */
export function histogramBar(rows, seriesLabel) {
  if (!rows || !rows.some((r) => r.count > 0)) return null
  return {
    type: 'bar',
    data: {
      labels: rows.map((r) => r.label),
      datasets: [{ label: seriesLabel, data: rows.map((r) => r.count), backgroundColor: PALETTE[0] }],
    },
    options: { plugins: hideLegend, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
  }
}

export function countBar(counts, seriesLabel, colors = null) {
  const keys = Object.keys(counts || {})
  if (!keys.length) return null
  return {
    type: 'bar',
    data: {
      labels: keys.map(label),
      datasets: [
        {
          label: seriesLabel,
          data: keys.map((k) => counts[k]),
          backgroundColor: keys.map((k, i) => (colors && colors[k]) || colorAt(i)),
        },
      ],
    },
    options: { plugins: hideLegend, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } },
  }
}

export function severityBar(bySeverity) {
  const ordered = Object.fromEntries(SEVERITIES.map((s) => [s, bySeverity?.[s] ?? 0]))
  if (!Object.values(ordered).some(Boolean)) return null
  return countBar(ordered, 'Findings', SEVERITY_COLORS)
}

/** Horizontal bytes bars for ranked addresses. */
export function talkersBar(items) {
  if (!items?.length) return null
  return {
    type: 'bar',
    data: {
      labels: items.map((r) => r.ip),
      datasets: [{ label: 'Bytes', data: items.map((r) => r.bytes), backgroundColor: PALETTE[0] }],
    },
    options: {
      indexAxis: 'y',
      plugins: {
        ...hideLegend,
        tooltip: { callbacks: { label: (c) => `${bytes(c.parsed.x)} \u00b7 ${num(items[c.dataIndex].packets)} packets` } },
      },
      scales: { x: { beginAtZero: true, ticks: { callback: (v) => bytes(v) } } },
    },
  }
}

export const DIRECTION_COLORS = {
  inbound: '#2563eb',
  outbound: '#16a34a',
  internal: '#7c3aed',
  unknown: '#94a3b8',
}

export function directionDoughnut(directions) {
  const keys = Object.keys(DIRECTION_COLORS).filter((k) => directions[k]?.bytes > 0)
  if (!keys.length) return null
  return {
    type: 'doughnut',
    data: {
      labels: keys,
      datasets: [{ data: keys.map((k) => directions[k].bytes), backgroundColor: keys.map((k) => DIRECTION_COLORS[k]) }],
    },
    options: {
      plugins: {
        legend: { position: 'right' },
        tooltip: { callbacks: { label: (c) => `${c.label}: ${bytes(c.parsed)}` } },
      },
    },
  }
}

/** Short text for an indicator's "who sent it": endpoint A or B of the connection. */
export const senderLabel = (side) => (side === 'a' ? 'endpoint A' : side === 'b' ? 'endpoint B' : DASH)

export const TCP_STATES = ['established', 'incomplete', 'refused', 'unclassified']
export const TERMINATIONS = ['fin', 'reset', 'half_closed', 'none']

/** Render an evidence value (number, string, list or object) as one readable string. */
export function evidenceValue(value) {
  if (value === null || value === undefined) return DASH
  if (Array.isArray(value)) return value.map(evidenceValue).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  if (typeof value === 'number' && !Number.isInteger(value)) return value.toFixed(4)
  return String(value)
}

export const stateTone = (state) =>
  ({
    established: 'bg-green-100 text-green-800',
    incomplete: 'bg-amber-100 text-amber-800',
    refused: 'bg-red-100 text-red-800',
    unclassified: 'bg-slate-100 text-slate-700',
  })[state] ?? 'bg-slate-100 text-slate-700'

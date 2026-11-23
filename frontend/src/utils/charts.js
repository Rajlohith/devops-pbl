/** Shared Chart.js palette and configuration builders, so every chart looks the same. */
import { bps, bytes, clock, num } from './format'

export const PALETTE = [
  '#2563eb', '#16a34a', '#f59e0b', '#dc2626', '#7c3aed',
  '#0891b2', '#db2777', '#65a30d', '#64748b',
]

export const colorAt = (index) => PALETTE[index % PALETTE.length]

const bytesAxis = { beginAtZero: true, ticks: { callback: (v) => bytes(v) } }

/** Doughnut of packet counts per protocol. `rows` come from the protocol summaries. */
export function protocolDoughnut(rows) {
  return {
    type: 'doughnut',
    data: {
      labels: rows.map((r) => r.protocol),
      datasets: [{ data: rows.map((r) => r.packets), backgroundColor: rows.map((_, i) => colorAt(i)) }],
    },
    options: { plugins: { legend: { position: 'right' } } },
  }
}

/** Bars of bytes per protocol, coloured to match the doughnut. */
export function protocolBytesBar(rows) {
  return {
    type: 'bar',
    data: {
      labels: rows.map((r) => r.protocol),
      datasets: [{ label: 'Bytes', data: rows.map((r) => r.bytes), backgroundColor: rows.map((_, i) => colorAt(i)) }],
    },
    options: {
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => bytes(c.parsed.y) } } },
      scales: { y: bytesAxis },
    },
  }
}

/** Bytes per analysed capture (dashboard). */
export function capturesBytesBar(rows) {
  return {
    type: 'bar',
    data: {
      labels: rows.map((r) => r.filename),
      datasets: [{ label: 'Bytes', data: rows.map((r) => r.bytes), backgroundColor: PALETTE[0] }],
    },
    options: {
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: { label: (c) => `${bytes(c.parsed.y)} \u00b7 ${num(rows[c.dataIndex].packets)} packets` },
        },
      },
      scales: { y: bytesAxis },
    },
  }
}

/** Horizontal bars for the busiest flows. `labelOf` renders a flow's axis label. */
export function topFlowsBar(flows, labelOf) {
  return {
    type: 'bar',
    data: {
      labels: flows.map(labelOf),
      datasets: [{ label: 'Bytes', data: flows.map((f) => f.bytes.total), backgroundColor: PALETTE[0] }],
    },
    options: {
      indexAxis: 'y',
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => bytes(c.parsed.x) } } },
      scales: { x: bytesAxis },
    },
  }
}

/** A filled line over the capture's one-second time series. */
export function timeSeriesLine(points, field, label, formatter) {
  return {
    type: 'line',
    data: {
      labels: points.map((p) => clock(p.time).slice(0, 8)),
      datasets: [
        {
          label,
          data: points.map((p) => p[field]),
          borderColor: PALETTE[0],
          backgroundColor: 'rgba(37, 99, 235, 0.12)',
          fill: true,
          tension: 0.2,
          pointRadius: points.length < 40 ? 3 : 0,
        },
      ],
    },
    options: {
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => formatter(c.parsed.y) } } },
      scales: { y: { beginAtZero: true, ticks: { callback: (v) => formatter(v) } }, x: { ticks: { maxTicksLimit: 10 } } },
    },
  }
}

export const throughputLine = (points) => timeSeriesLine(points, 'bits_per_second', 'Throughput', bps)
export const packetRateLine = (points) =>
  timeSeriesLine(points, 'packets_per_second', 'Packets/s', (v) => num(v, 2))

/** Side-by-side bytes per transport protocol for two compared captures. */
export function compareBytesBar(protocols) {
  return {
    type: 'bar',
    data: {
      labels: protocols.map((p) => p.protocol),
      datasets: [
        { label: 'A', data: protocols.map((p) => (p.a ? p.a.bytes : 0)), backgroundColor: PALETTE[0] },
        { label: 'B', data: protocols.map((p) => (p.b ? p.b.bytes : 0)), backgroundColor: PALETTE[2] },
      ],
    },
    options: {
      plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${bytes(c.parsed.y)}` } } },
      scales: { y: bytesAxis },
    },
  }
}

/**
 * Grouped bytes-per-transport-protocol bars for A, B and any extra captures.
 * `result` is a comparison with `protocols` (A vs B) and `others` (A vs C, A vs D, ...).
 */
export function compareBytesBarMulti(result) {
  const series = [
    { letter: 'A', bytes: new Map() },
    { letter: 'B', bytes: new Map() },
    ...(result.others ?? []).map((_, i) => ({ letter: 'CDE'[i], bytes: new Map() })),
  ]
  const labels = []
  const add = (rows, a, b) => {
    for (const row of rows) {
      if (!labels.includes(row.protocol)) labels.push(row.protocol)
      if (a && row.a) a.bytes.set(row.protocol, row.a.bytes)
      if (row.b) b.bytes.set(row.protocol, row.b.bytes)
    }
  }
  add(result.protocols, series[0], series[1])
  ;(result.others ?? []).forEach((other, i) => add(other.protocols, null, series[2 + i]))
  const colors = [PALETTE[0], PALETTE[2], ...PALETTE.slice(3)]
  return {
    type: 'bar',
    data: {
      labels,
      datasets: series.map((s, i) => ({
        label: s.letter,
        data: labels.map((l) => s.bytes.get(l) ?? 0),
        backgroundColor: colors[i % colors.length],
      })),
    },
    options: {
      plugins: { tooltip: { callbacks: { label: (c) => `${c.dataset.label}: ${bytes(c.parsed.y)}` } } },
      scales: { y: bytesAxis },
    },
  }
}

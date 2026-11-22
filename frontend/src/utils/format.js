/**
 * Display formatting for network figures. Ported from the legacy `ns.js`, so numbers read
 * exactly as they did in the Jinja interface (decimal units, an em dash for "not available").
 */
export const DASH = '\u2014'

const isMissing = (value) => value === null || value === undefined

export function num(value, digits = 0) {
  if (isMissing(value)) return DASH
  return Number(value).toLocaleString('en-US', {
    maximumFractionDigits: digits,
    minimumFractionDigits: digits,
  })
}

function scaled(value, units) {
  let v = Math.abs(Number(value))
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i += 1
  }
  return { v, i, sign: value < 0 ? '-' : '' }
}

export function bytes(value) {
  if (isMissing(value)) return DASH
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const { v, i, sign } = scaled(value, units)
  return `${sign}${i === 0 ? Math.round(v) : v.toFixed(2)} ${units[i]}`
}

export function bps(value) {
  if (isMissing(value)) return DASH
  const units = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s']
  const { v, i, sign } = scaled(value, units)
  return `${sign}${i === 0 ? Math.round(v) : v.toFixed(2)} ${units[i]}`
}

export function duration(seconds) {
  if (isMissing(seconds)) return DASH
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`
  if (seconds < 60) return `${seconds.toFixed(2)} s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ${Math.round(seconds - minutes * 60)}s`
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`
}

export const percent = (value, digits = 1) =>
  isMissing(value) ? DASH : `${Number(value).toFixed(digits)}%`

export const ms = (value) => (isMissing(value) ? DASH : `${Number(value).toFixed(2)} ms`)

/** ISO timestamp -> "2023-11-14 22:13:20 UTC" (the API always sends UTC). */
export const dateTime = (iso) => (iso ? `${iso.replace('T', ' ').slice(0, 19)} UTC` : DASH)

/** ISO timestamp -> its time of day, "22:13:20.123". */
export function clock(iso) {
  const match = /T(\d\d:\d\d:\d\d(?:\.\d+)?)/.exec(iso || '')
  return match ? match[1] : DASH
}

/** Format a comparison/metric value according to the unit the API reports. */
export function byUnit(value, unit) {
  switch (unit) {
    case 'bytes':
      return bytes(value)
    case 'bps':
      return bps(value)
    case 'seconds':
      return duration(value)
    case 'ms':
      return ms(value)
    case 'ratio':
      return isMissing(value) ? DASH : percent(value * 100, 2)
    case 'pps':
      return isMissing(value) ? DASH : `${num(value, 2)} /s`
    default:
      return num(value, Number.isInteger(value) ? 0 : 2)
  }
}

/** A signed difference such as "+1.20 KB" or "-12". */
export function signed(delta, unit) {
  if (isMissing(delta)) return DASH
  return `${delta > 0 ? '+' : ''}${byUnit(delta, unit)}`
}

export function signedPercent(value) {
  if (isMissing(value)) return DASH
  return `${value > 0 ? '+' : ''}${value.toFixed(1)}%`
}

/** "10.0.0.1:443", "[2001:db8::1]:443", or just the address when there is no port. */
export function endpoint(ip, port) {
  if (isMissing(ip)) return DASH
  if (isMissing(port)) return ip
  return `${ip.includes(':') ? `[${ip}]` : ip}:${port}`
}

export const flowLabel = (flow) =>
  `${endpoint(flow.endpoint_a.ip, flow.endpoint_a.port)} \u2194 ${endpoint(flow.endpoint_b.ip, flow.endpoint_b.port)}`

/** The one-line summary the packet table shows in its Info column. */
export function packetInfo(p) {
  const meta = p.application_metadata
  if (p.application_protocol === 'DNS' && meta) {
    return `${meta.is_response ? 'Response' : 'Query'} ${meta.query || ''}`.trim()
  }
  if (p.application_protocol === 'HTTP' && meta) return meta.start_line
  if (p.tcp_flags !== null && p.tcp_flags !== undefined) {
    return `[${p.tcp_flags}] seq=${p.tcp_sequence_number} ack=${p.tcp_acknowledgement_number}`
  }
  if (meta && meta.icmp_type !== undefined) return `ICMP type ${meta.icmp_type} code ${meta.icmp_code}`
  return p.protocol === 'ARP' ? 'ARP' : ''
}

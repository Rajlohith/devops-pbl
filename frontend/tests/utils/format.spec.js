import { describe, expect, it } from 'vitest'

import {
  byUnit, bytes, bps, clock, dateTime, DASH, duration, endpoint, flowLabel, ms, num, packetInfo,
  percent, signed, signedPercent,
} from '@/utils/format'

describe('number formatting', () => {
  it('uses an em dash for missing values everywhere', () => {
    for (const fn of [num, bytes, bps, duration, percent, ms, dateTime, signed, signedPercent]) {
      expect(fn(null)).toBe(DASH)
    }
    expect(num(undefined)).toBe(DASH)
  })

  it('formats counts and sizes in decimal units', () => {
    expect(num(1234567)).toBe('1,234,567')
    expect(num(3.14159, 2)).toBe('3.14')
    expect(bytes(512)).toBe('512 B')
    expect(bytes(1070)).toBe('1.07 KB')
    expect(bytes(2_500_000)).toBe('2.50 MB')
    expect(bytes(-1500)).toBe('-1.50 KB')
    expect(bps(1712)).toBe('1.71 Kbit/s')
    expect(bps(42)).toBe('42 bit/s')
  })

  it('formats durations across magnitudes', () => {
    expect(duration(0.05)).toBe('50 ms')
    expect(duration(5)).toBe('5.00 s')
    expect(duration(125)).toBe('2m 5s')
    expect(duration(3720)).toBe('1h 2m')
  })

  it('formats timestamps from the API as UTC', () => {
    expect(dateTime('2023-11-14T22:13:20.123456+00:00')).toBe('2023-11-14 22:13:20 UTC')
    expect(clock('2023-11-14T22:13:20.123456+00:00')).toBe('22:13:20.123456')
    expect(clock(null)).toBe(DASH)
  })

  it('formats comparison values by unit and sign', () => {
    expect(byUnit(0.0123, 'ratio')).toBe('1.23%')
    expect(byUnit(8, 'pps')).toBe('8.00 /s')
    expect(byUnit(2.5, 'count')).toBe('2.50')
    expect(signed(12, 'count')).toBe('+12')
    expect(signed(-908, 'bytes')).toBe('-908 B')
    expect(signedPercent(5)).toBe('+5.0%')
    expect(percent(12.345, 2)).toBe('12.35%')
    expect(ms(50)).toBe('50.00 ms')
  })
})

describe('network labels', () => {
  it('brackets IPv6 addresses that have a port', () => {
    expect(endpoint('10.0.0.1', 80)).toBe('10.0.0.1:80')
    expect(endpoint('2001:db8::1', 443)).toBe('[2001:db8::1]:443')
    expect(endpoint('10.0.0.1', null)).toBe('10.0.0.1')
    expect(endpoint(null, null)).toBe(DASH)
  })

  it('labels a flow with both endpoints', () => {
    const f = { endpoint_a: { ip: '10.0.0.1', port: 1 }, endpoint_b: { ip: '10.0.0.2', port: 2 } }
    expect(flowLabel(f)).toBe('10.0.0.1:1 ↔ 10.0.0.2:2')
  })

  it('summarises a packet in the Info column', () => {
    expect(packetInfo({ application_protocol: 'DNS', application_metadata: { is_response: false, query: 'a.test' } })).toBe('Query a.test')
    expect(packetInfo({ application_protocol: 'DNS', application_metadata: { is_response: true, query: 'a.test' } })).toBe('Response a.test')
    expect(packetInfo({ application_protocol: 'HTTP', application_metadata: { start_line: 'GET / HTTP/1.1' } })).toBe('GET / HTTP/1.1')
    expect(packetInfo({ tcp_flags: 'SA', tcp_sequence_number: 5, tcp_acknowledgement_number: 6 })).toBe('[SA] seq=5 ack=6')
    expect(packetInfo({ tcp_flags: null, application_metadata: { icmp_type: 8, icmp_code: 0 } })).toBe('ICMP type 8 code 0')
    expect(packetInfo({ tcp_flags: null, protocol: 'ARP' })).toBe('ARP')
  })
})

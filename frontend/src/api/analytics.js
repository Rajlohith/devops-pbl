import { apiClient } from './client'
import { cleanParams } from './params'

const base = (id) => `/captures/${id}`
const get = (url, params) => apiClient.get(url, { params: cleanParams(params) }).then((r) => r.data)

/** Phase 4 network-intelligence results for a completed capture (all owner-scoped by the API). */
export const analyticsApi = {
  document: (id) => get(`${base(id)}/analytics`).then((d) => d.analytics),

  tcpSummary: (id) => get(`${base(id)}/tcp/summary`),
  connections: (id, params) => get(`${base(id)}/tcp/connections`, params),
  connection: (id, connectionId) => get(`${base(id)}/tcp/connections/${connectionId}`),
  resets: (id) => get(`${base(id)}/tcp/resets`),
  indicators: (id, params) => get(`${base(id)}/tcp/indicators`, params),
  windows: (id) => get(`${base(id)}/tcp/windows`),

  dnsSummary: (id) => get(`${base(id)}/dns/summary`),
  dnsTransactions: (id, params) => get(`${base(id)}/dns/transactions`, params),
  dnsTransaction: (id, transactionId) =>
    get(`${base(id)}/dns/transactions/${transactionId}`).then((d) => d.transaction),

  talkers: (id, params) => get(`${base(id)}/traffic/talkers`, params),
  direction: (id, params) => get(`${base(id)}/traffic/direction`, params),

  anomalies: (id, params) => get(`${base(id)}/anomalies`, params),
}

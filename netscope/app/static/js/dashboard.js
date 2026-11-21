(function () {
  'use strict';
  const { api, el, num, bytes, dateTime, statusBadge, showState, table, statCard, chart, chartBox, PALETTE } = NS;
  const root = document.getElementById('dashboard-root');
  let timer = null;

  function render(data) {
    const t = data.totals;
    if (t.captures === 0) {
      NS.clear(root).append(el('div', { class: 'card text-center', 'data-state': 'empty' },
        el('h2', { class: 'text-lg font-semibold' }, 'No captures yet'),
        el('p', { class: 'mt-1 text-sm text-slate-500' }, 'Upload a PCAP or PCAPNG file to see traffic statistics here.'),
        el('a', { class: 'btn btn-primary mt-4', href: '/captures' }, 'Upload a capture')));
      return;
    }

    const sc = data.status_counts;
    const status = el('div', { class: 'card', id: 'status-card' },
      el('h3', { class: 'mb-3 text-sm font-semibold text-slate-700' }, 'Processing status'),
      el('div', { class: 'flex flex-wrap gap-3' },
        ['completed', 'processing', 'pending', 'uploaded', 'failed'].map((s) =>
          el('div', { class: 'flex items-center gap-2', 'data-status-count': s }, statusBadge(s), el('span', { class: 'text-lg font-semibold' }, num(sc[s]))))),
      data.in_progress > 0
        ? el('p', { class: 'mt-3 text-xs text-slate-500' }, num(data.in_progress) + ' analysis job' + (data.in_progress === 1 ? '' : 's') + ' in progress \u2014 this page refreshes automatically.')
        : null);

    const recent = el('div', { class: 'card p-0' },
      el('h3', { class: 'px-4 pb-3 pt-4 text-sm font-semibold text-slate-700' }, 'Recent analysis sessions'),
      table([
        { label: 'Capture', render: (r) => el('a', { class: 'text-blue-700 hover:underline', href: '/captures/' + r.id }, r.filename) },
        { label: 'Status', render: (r) => statusBadge(r.status) },
        { label: 'Packets', class: 'text-right', render: (r) => num(r.packets) },
        { label: 'Data', class: 'text-right', render: (r) => (r.bytes === null ? NS.dash : bytes(r.bytes)) },
        { label: 'Flows', class: 'text-right', render: (r) => num(r.flows) },
        { label: 'Uploaded', render: (r) => dateTime(r.uploaded_at) },
      ], data.recent_sessions));

    const trafficBox = chartBox('Data per analysed capture (most recent)');
    const protocolBox = chartBox('Protocol distribution (packets, transport layer)');

    NS.clear(root).append(
      el('div', { class: 'grid grid-cols-2 gap-4 md:grid-cols-5' },
        statCard('Total captures', num(t.captures)),
        statCard('Packets analysed', num(t.packets)),
        statCard('Data processed', bytes(t.bytes)),
        statCard('Unique IPs', num(t.unique_ips)),
        statCard('Flows', num(t.flows))),
      el('div', { class: 'mt-4' }, status),
      el('div', { class: 'mt-4 grid gap-4 lg:grid-cols-2' }, trafficBox, protocolBox),
      el('div', { class: 'mt-4' }, recent));

    const traffic = data.recent_traffic;
    const trafficWrap = trafficBox.querySelector('div.relative');
    if (traffic.length === 0) {
      showState(trafficWrap, 'empty', 'No completed analyses yet.');
    } else {
      chart(trafficWrap, {
        type: 'bar',
        data: {
          labels: traffic.map((r) => r.filename),
          datasets: [{ label: 'Bytes', data: traffic.map((r) => r.bytes), backgroundColor: PALETTE[0] }],
        },
        options: {
          plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => bytes(c.parsed.y) + ' \u00b7 ' + num(traffic[c.dataIndex].packets) + ' packets' } } },
          scales: { y: { beginAtZero: true, ticks: { callback: (v) => bytes(v) } } },
        },
      });
    }

    const protocols = data.protocols.transport;
    const protocolWrap = protocolBox.querySelector('div.relative');
    if (protocols.length === 0) {
      showState(protocolWrap, 'empty', 'No protocol data yet.');
    } else {
      chart(protocolWrap, {
        type: 'doughnut',
        data: {
          labels: protocols.map((p) => p.protocol),
          datasets: [{ data: protocols.map((p) => p.packets), backgroundColor: protocols.map((_, i) => PALETTE[i % PALETTE.length]) }],
        },
        options: { plugins: { legend: { position: 'right' } } },
      });
    }
  }

  async function load(initial) {
    clearTimeout(timer);
    if (initial) showState(root, 'loading', 'Loading dashboard\u2026');
    try {
      const data = await api('/dashboard');
      render(data);
      if (data.in_progress > 0) timer = setTimeout(() => load(false), 2500);
    } catch (e) {
      if (initial) showState(root, 'error', e.message, () => load(true));
      else timer = setTimeout(() => load(false), 5000); // keep trying quietly
    }
  }
  load(true);
})();

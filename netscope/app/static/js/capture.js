(function () {
  'use strict';
  const { api, el, clear, num, bytes, bps, duration, percent, ms, dateTime, clock, statusBadge, showState,
    table, pager, statCard, chart, chartBox, PALETTE } = NS;

  const root = document.getElementById('capture-root');
  const id = root.dataset.captureId;
  const base = '/captures/' + id;
  const TABS = [['overview', 'Overview'], ['protocols', 'Protocols'], ['flows', 'Flows'], ['packets', 'Packets'], ['performance', 'Performance']];

  let capture = null;
  let memo = {};
  let loaded = {};
  let pollTimer = null;
  let activeTab = null;

  const header = el('div', { id: 'cap-header' });
  const notice = el('div', { id: 'cap-notice', class: 'mt-4' });
  const tabBar = el('div', { class: 'mt-6 hidden border-b border-slate-200', role: 'tablist', id: 'tab-bar' });
  const panels = {};
  const panelWrap = el('div', { class: 'mt-4' });
  for (const [key] of TABS) {
    panels[key] = el('div', { id: 'panel-' + key, role: 'tabpanel', class: 'hidden' });
    panelWrap.append(panels[key]);
  }
  root.append(header, notice, tabBar, panelWrap);

  // memoised fetches shared by several tabs
  const getSummary = () => (memo.summary ||= api(base + '/summary'));
  const getPerformance = () => (memo.performance ||= api(base + '/performance'));

  // ------------------------------------------------------------------ header & state
  function renderHeader() {
    const c = capture;
    const reports = el('details', { class: 'relative', id: 'reports-menu' },
      el('summary', { class: 'btn btn-secondary cursor-pointer list-none' }, 'Reports \u25be'),
      el('div', { class: 'absolute right-0 z-10 mt-1 w-56 rounded-md bg-white p-1 text-sm shadow-lg ring-1 ring-slate-200' },
        [['PDF report', '/report.pdf'], ['CSV \u2014 packets', '/export/packets.csv'], ['CSV \u2014 flows', '/export/flows.csv'],
          ['CSV \u2014 protocols', '/export/protocols.csv'], ['CSV \u2014 performance', '/export/performance.csv'],
          ['CSV \u2014 traffic over time', '/export/timeseries.csv']].map(([label, path]) =>
          el('a', { class: 'block rounded px-3 py-1.5 hover:bg-slate-100', href: '/api/v1' + base + path, 'data-report': path }, label))));
    clear(header).append(
      el('div', { class: 'flex flex-wrap items-start justify-between gap-3' },
        el('div', {},
          el('h1', { class: 'break-all text-2xl font-semibold', id: 'cap-title' }, c.original_filename, ' ', statusBadge(c.status)),
          el('p', { class: 'mt-1 text-xs text-slate-500' },
            c.file_format.toUpperCase() + ' \u00b7 ' + bytes(c.file_size_bytes) + ' \u00b7 uploaded ' + dateTime(c.uploaded_at) + ' \u00b7 ID ' + c.id)),
        el('div', { class: 'flex flex-wrap items-center gap-2' },
          c.status === 'completed' ? [reports, el('a', { class: 'btn btn-secondary', href: '/compare?a=' + c.id }, 'Compare\u2026')] : null,
          c.status === 'uploaded' || c.status === 'failed'
            ? el('button', { class: 'btn btn-primary', type: 'button', id: 'analyze-btn', onclick: startAnalysis }, c.status === 'failed' ? 'Retry analysis' : 'Start analysis') : null,
          el('button', { class: 'btn btn-danger', type: 'button', id: 'delete-btn', onclick: remove }, 'Delete'))));
  }

  async function startAnalysis() {
    try {
      await api(base + '/analyze', { method: 'POST' });
      memo = {}; loaded = {};
      await load();
    } catch (e) {
      clear(notice).append(el('div', { class: 'rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800', role: 'alert' }, e.message));
      await load();
    }
  }

  async function remove() {
    if (!confirm('Delete ' + capture.original_filename + ' and all of its analysis permanently?')) return;
    try {
      await api(base, { method: 'DELETE' });
      window.location.href = '/captures';
    } catch (e) {
      clear(notice).append(el('div', { class: 'rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800', role: 'alert' }, 'Delete failed: ' + e.message));
    }
  }

  function setTabsVisible(visible) {
    tabBar.classList.toggle('hidden', !visible);
    for (const key of Object.keys(panels)) panels[key].classList.toggle('hidden', !visible || key !== activeTab);
  }

  async function load() {
    clearTimeout(pollTimer);
    try {
      capture = (await api(base)).capture;
    } catch (e) {
      showState(notice, 'error', e.message, load);
      return;
    }
    renderHeader();
    clear(notice);
    if (capture.status === 'completed') {
      buildTabs();
      setTabsVisible(true);
    } else {
      setTabsVisible(false);
      renderProgress();
      if (capture.status === 'pending' || capture.status === 'processing') pollTimer = setTimeout(poll, 1000);
    }
  }

  function renderProgress() {
    const c = capture;
    let body;
    if (c.status === 'uploaded') {
      body = el('p', { class: 'text-sm text-slate-600' }, 'This capture has not been analysed yet. Start the analysis to see packets, flows and performance results.');
    } else if (c.status === 'failed') {
      body = el('div', {}, el('p', { class: 'font-medium text-red-800' }, 'Analysis failed'),
        el('p', { class: 'mt-1 text-sm text-red-700', id: 'fail-reason' }, c.error_message || 'No details were recorded.'),
        el('p', { class: 'mt-2 text-xs text-slate-500' }, 'No partial results were kept. You can retry the analysis.'));
    } else {
      const queued = c.status === 'pending';
      body = el('div', {},
        el('p', { class: 'text-sm font-medium text-slate-700', id: 'progress-text' },
          queued ? 'Queued \u2014 waiting for a worker\u2026' : 'Analysing' + (c.packet_count ? ' \u2014 ' + num(c.packet_count) + ' packets processed so far' : '\u2026')),
        el('div', { class: 'mt-3 h-2 overflow-hidden rounded bg-slate-200', role: 'progressbar', 'aria-label': 'Analysis in progress' },
          el('div', { class: 'h-full w-1/3 animate-pulse rounded bg-blue-600' })),
        el('p', { class: 'mt-2 text-xs text-slate-500' }, 'This page updates automatically when the analysis finishes.'));
    }
    clear(notice).append(el('div', { class: 'card ' + (c.status === 'failed' ? 'ring-red-200' : ''), id: 'progress-card' }, body));
  }

  async function poll() {
    try {
      const s = await api(base + '/status');
      if (s.status !== capture.status) { await load(); return; }
      capture.packet_count = s.packet_count;
      renderProgress();
    } catch (e) { /* transient; keep polling */ }
    pollTimer = setTimeout(poll, 1500);
  }

  // ------------------------------------------------------------------ tabs
  function buildTabs() {
    if (tabBar.childElementCount) return;
    for (const [key, label] of TABS) {
      tabBar.append(el('button', { class: 'tab', type: 'button', role: 'tab', 'data-tab': key, id: 'tab-' + key, onclick: () => showTab(key) }, label));
    }
    const wanted = window.location.hash.slice(1);
    showTab(TABS.some(([k]) => k === wanted) ? wanted : 'overview');
  }

  function showTab(name) {
    activeTab = name;
    if (window.location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
    for (const [key] of TABS) {
      panels[key].classList.toggle('hidden', key !== name);
      const btn = document.getElementById('tab-' + key);
      btn.classList.toggle('tab-active', key === name);
      btn.setAttribute('aria-selected', key === name ? 'true' : 'false');
    }
    if (!loaded[name]) { loaded[name] = true; loaders[name](); }
  }

  const loaders = {
    overview: loadOverview, protocols: loadProtocols, flows: loadFlows, packets: loadPackets, performance: loadPerformance,
  };

  function guard(panel, fn, key) {
    showState(panel, 'loading');
    return fn().catch((e) => { loaded[key] = false; showState(panel, 'error', e.message, () => showTab(key)); });
  }

  const endpoint = (ip, port) => (ip === null ? NS.dash : (port === null || port === undefined ? ip : (ip.includes(':') ? '[' + ip + ']' : ip) + ':' + port));
  const flowLabel = (f) => endpoint(f.endpoint_a.ip, f.endpoint_a.port) + ' \u2194 ' + endpoint(f.endpoint_b.ip, f.endpoint_b.port);

  function tsChart(wrapper, points, field, label, formatter) {
    if (points.length === 0) { showState(wrapper, 'empty', 'No traffic in this capture.'); return; }
    chart(wrapper, {
      type: 'line',
      data: { labels: points.map((p) => clock(p.time).slice(0, 8)),
        datasets: [{ label, data: points.map((p) => p[field]), borderColor: PALETTE[0], backgroundColor: 'rgba(37,99,235,0.12)', fill: true, tension: 0.2, pointRadius: points.length < 40 ? 3 : 0 }] },
      options: { plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => formatter(c.parsed.y) } } },
        scales: { y: { beginAtZero: true, ticks: { callback: (v) => formatter(v) } }, x: { ticks: { maxTicksLimit: 10 } } } },
    });
  }

  function distributionCard(title, dist, hint, fmt) {
    return el('div', { class: 'card', 'data-card': title },
      el('h3', { class: 'text-sm font-semibold text-slate-700' }, title),
      dist
        ? el('dl', { class: 'mt-2 grid grid-cols-2 gap-x-4 text-sm' },
            [['Samples', num(dist.count)], ['Mean', fmt(dist.mean)], ['Median', fmt(dist.median)], ['95th percentile', fmt(dist.p95)], ['Min', fmt(dist.min)], ['Max', fmt(dist.max)]]
              .map(([k, v]) => [el('dt', { class: 'text-slate-500' }, k), el('dd', { class: 'text-right font-medium' }, v)]))
        : el('p', { class: 'mt-2 text-sm text-slate-500' }, 'Not available for this capture.'),
      el('p', { class: 'mt-2 text-xs text-slate-500' }, hint));
  }

  // ------------------------------------------------------------------ overview
  function loadOverview() {
    const panel = panels.overview;
    return guard(panel, async () => {
      const [summary, perf, flows] = await Promise.all([getSummary(), getPerformance(), api(base + '/flows', { query: { per_page: 5 } })]);
      const t = summary.totals;
      const protoBox = chartBox('Protocol distribution (packets)');
      const trafficBox = chartBox('Traffic over time');
      clear(panel).append(
        el('div', { class: 'grid grid-cols-2 gap-4 md:grid-cols-6' },
          statCard('Packets', num(t.total_packets)), statCard('Data', bytes(t.total_bytes)),
          statCard('Duration', duration(t.duration_seconds)), statCard('Unique IPs', num(t.unique_ips)),
          statCard('Flows', num(t.flow_count)),
          statCard('Malformed', num(t.malformed_packets), t.malformed_packets ? 'kept, flagged in the explorer' : null)),
        el('div', { class: 'mt-4 grid gap-4 lg:grid-cols-2' }, protoBox, trafficBox),
        el('div', { class: 'card mt-4 p-0' },
          el('div', { class: 'flex items-center justify-between px-4 pb-3 pt-4' },
            el('h3', { class: 'text-sm font-semibold text-slate-700' }, 'Top flows by bytes'),
            el('button', { class: 'text-sm text-blue-700 hover:underline', type: 'button', onclick: () => showTab('flows') }, 'View all flows')),
          flows.items.length ? table([
            { label: 'Flow', render: (f) => flowLabel(f) }, { label: 'Protocol', render: (f) => f.application_protocol || f.protocol },
            { label: 'Packets', class: 'text-right', render: (f) => num(f.packets.total) }, { label: 'Bytes', class: 'text-right', render: (f) => bytes(f.bytes.total) },
          ], flows.items) : el('p', { class: 'p-6 text-sm text-slate-500' }, 'No IP flows in this capture.')));
      const rows = summary.protocols.transport;
      const pw = protoBox.querySelector('div.relative');
      if (!rows.length) showState(pw, 'empty', 'No packets.');
      else chart(pw, { type: 'doughnut', data: { labels: rows.map((r) => r.protocol), datasets: [{ data: rows.map((r) => r.packets), backgroundColor: rows.map((_, i) => PALETTE[i % PALETTE.length]) }] }, options: { plugins: { legend: { position: 'right' } } } });
      tsChart(trafficBox.querySelector('div.relative'), perf.performance.timeseries.points, 'bits_per_second', 'Throughput', bps);
    }, 'overview');
  }

  // ------------------------------------------------------------------ protocols
  function loadProtocols() {
    const panel = panels.protocols;
    return guard(panel, async () => {
      const { protocols } = await api(base + '/protocols');
      clear(panel);
      for (const [layer, title, none] of [['transport', 'Transport layer', 'No packets.'], ['application', 'Application protocols (DNS, HTTP)', 'No DNS or HTTP traffic was identified in this capture.']]) {
        const rows = protocols[layer];
        const section = el('section', { class: 'mb-8', 'data-layer': layer }, el('h2', { class: 'mb-3 text-lg font-semibold' }, title));
        if (!rows.length) { section.append(el('div', { class: 'card text-sm text-slate-500', 'data-state': 'empty' }, none)); panel.append(section); continue; }
        const pk = chartBox('Packets'); const by = chartBox('Bytes');
        section.append(el('div', { class: 'grid gap-4 lg:grid-cols-2' }, pk, by),
          el('div', { class: 'card mt-4 p-0' }, table([
            { label: 'Protocol', render: (r) => r.protocol }, { label: 'Packets', class: 'text-right', render: (r) => num(r.packets) },
            { label: '% packets', class: 'text-right', render: (r) => percent(r.packet_percent) }, { label: 'Bytes', class: 'text-right', render: (r) => bytes(r.bytes) },
            { label: '% bytes', class: 'text-right', render: (r) => percent(r.byte_percent) },
            { label: '', class: 'text-right', render: (r) => el('button', { class: 'text-sm text-blue-700 hover:underline', type: 'button', onclick: () => { pf.protocol = r.protocol; pf.flow_id = ''; pf.page = 1; pf.dirty = true; showTab('packets'); } }, 'View packets') },
          ], rows)));
        panel.append(section);
        const colors = rows.map((_, i) => PALETTE[i % PALETTE.length]);
        chart(pk.querySelector('div.relative'), { type: 'doughnut', data: { labels: rows.map((r) => r.protocol), datasets: [{ data: rows.map((r) => r.packets), backgroundColor: colors }] }, options: { plugins: { legend: { position: 'right' } } } });
        chart(by.querySelector('div.relative'), { type: 'bar', data: { labels: rows.map((r) => r.protocol), datasets: [{ label: 'Bytes', data: rows.map((r) => r.bytes), backgroundColor: colors }] },
          options: { plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => bytes(c.parsed.y) } } }, scales: { y: { beginAtZero: true, ticks: { callback: (v) => bytes(v) } } } } });
      }
    }, 'protocols');
  }

  // ------------------------------------------------------------------ flows
  const ff = { page: 1, per_page: 20, protocol: '', application: '', ip: '', port: '', sort: 'bytes', order: 'desc' };

  function loadFlows() {
    const panel = panels.flows;
    const topBox = chartBox('Top 10 flows by bytes', 'h-72');
    const results = el('div', { id: 'flow-results' });
    const field = (name, label, attrs) => el('div', {}, el('label', { class: 'label', for: 'ff-' + name }, label), el('input', Object.assign({ class: 'field', id: 'ff-' + name, name }, attrs)));
    const select = (name, label, options) => el('div', {}, el('label', { class: 'label', for: 'ff-' + name }, label),
      el('select', { class: 'field', id: 'ff-' + name, name }, options.map(([v, t]) => el('option', { value: v, selected: ff[name] === v }, t))));
    const form = el('form', { class: 'card grid grid-cols-2 items-end gap-3 md:grid-cols-6', id: 'flow-filters' },
      field('protocol', 'Protocol', { placeholder: 'TCP, UDP\u2026', value: ff.protocol }), field('application', 'Application', { placeholder: 'DNS, HTTP', value: ff.application }),
      field('ip', 'IP address', { placeholder: '10.0.0.1', value: ff.ip }), field('port', 'Port', { type: 'number', min: 0, max: 65535, value: ff.port }),
      select('sort', 'Sort by', [['bytes', 'Bytes'], ['packets', 'Packets'], ['duration', 'Duration'], ['start', 'Start time']]),
      el('div', { class: 'flex gap-2' }, select('order', 'Order', [['desc', 'Descending'], ['asc', 'Ascending']]), el('button', { class: 'btn btn-primary', type: 'submit' }, 'Apply')));
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      for (const k of ['protocol', 'application', 'ip', 'port', 'sort', 'order']) ff[k] = form.elements[k].value.trim();
      ff.page = 1; fetchFlows();
    });
    clear(panel).append(topBox, el('div', { class: 'mt-4' }, form), el('div', { class: 'card mt-4 p-0' }, results));

    api(base + '/flows', { query: { per_page: 10, sort: 'bytes', order: 'desc' } }).then((top) => {
      const w = topBox.querySelector('div.relative');
      if (!top.items.length) { showState(w, 'empty', 'No IP flows in this capture.'); return; }
      chart(w, { type: 'bar', data: { labels: top.items.map(flowLabel), datasets: [{ label: 'Bytes', data: top.items.map((f) => f.bytes.total), backgroundColor: PALETTE[0] }] },
        options: { indexAxis: 'y', plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => bytes(c.parsed.x) } } }, scales: { x: { beginAtZero: true, ticks: { callback: (v) => bytes(v) } } } } });
    }).catch((e) => showState(topBox.querySelector('div.relative'), 'error', e.message));
    fetchFlows();

    async function fetchFlows() {
      showState(results, 'loading', 'Loading flows\u2026');
      try {
        const data = await api(base + '/flows', { query: ff });
        if (!data.items.length) { showState(results, 'empty', 'No flows match these filters.'); return; }
        clear(results).append(table([
          { label: '#', render: (f) => f.flow_id },
          { label: 'Protocol', render: (f) => f.application_protocol ? f.protocol + ' / ' + f.application_protocol : f.protocol },
          { label: 'Endpoint A (initiator)', render: (f) => endpoint(f.endpoint_a.ip, f.endpoint_a.port) },
          { label: 'Endpoint B', render: (f) => endpoint(f.endpoint_b.ip, f.endpoint_b.port) },
          { label: 'Packets', class: 'text-right', render: (f) => num(f.packets.total) + ' (' + num(f.packets.a_to_b) + '\u2192 / \u2190' + num(f.packets.b_to_a) + ')' },
          { label: 'Bytes', class: 'text-right', render: (f) => bytes(f.bytes.total) },
          { label: 'Duration', class: 'text-right', render: (f) => duration(f.duration_seconds) },
          { label: 'Retrans.', class: 'text-right', render: (f) => num(f.retransmissions) },
          { label: 'RTT', class: 'text-right', render: (f) => ms(f.handshake_rtt_ms) },
          { label: 'Jitter', class: 'text-right', render: (f) => ms(f.jitter_ms) },
          { label: '', render: (f) => el('button', { class: 'text-sm text-blue-700 hover:underline', type: 'button', 'data-flow': f.flow_id, onclick: () => { pf.flow_id = String(f.flow_id); pf.protocol = ''; pf.page = 1; pf.dirty = true; showTab('packets'); } }, 'Packets') },
        ], data.items), pager(data, (p) => { ff.page = p; fetchFlows(); }));
      } catch (e) { showState(results, 'error', e.message, fetchFlows); }
    }
  }

  // ------------------------------------------------------------------ packet explorer
  const pf = { page: 1, per_page: 50, sort: 'number', order: 'asc', q: '', protocol: '', ip: '', port: '', tcp_flags: '', min_length: '', max_length: '', flow_id: '', retransmission: false, malformed: false, dirty: false };
  let packetUi = null;

  function packetQuery(includePaging) {
    const q = { q: pf.q, protocol: pf.protocol, ip: pf.ip, port: pf.port, tcp_flags: pf.tcp_flags, min_length: pf.min_length, max_length: pf.max_length,
      flow_id: pf.flow_id, retransmission: pf.retransmission, malformed: pf.malformed };
    if (includePaging) Object.assign(q, { page: pf.page, per_page: pf.per_page, sort: pf.sort, order: pf.order });
    return q;
  }

  function packetInfo(p) {
    const m = p.application_metadata;
    if (p.application_protocol === 'DNS' && m) return (m.is_response ? 'Response' : 'Query') + ' ' + (m.query || '');
    if (p.application_protocol === 'HTTP' && m) return m.start_line;
    if (p.tcp_flags !== null) return '[' + p.tcp_flags + '] seq=' + p.tcp_sequence_number + ' ack=' + p.tcp_acknowledgement_number;
    if (m && m.icmp_type !== undefined) return 'ICMP type ' + m.icmp_type + ' code ' + m.icmp_code;
    return p.protocol === 'ARP' ? 'ARP' : '';
  }

  function loadPackets() {
    const panel = panels.packets;
    return guard(panel, async () => {
      const { protocols } = await getSummary();
      const names = [...new Set([...protocols.transport, ...protocols.application].map((r) => r.protocol))].sort();
      const field = (name, label, attrs) => el('div', {}, el('label', { class: 'label', for: 'pf-' + name }, label), el('input', Object.assign({ class: 'field', id: 'pf-' + name, name }, attrs)));
      const check = (name, label) => el('label', { class: 'flex items-center gap-2 text-sm' }, el('input', { type: 'checkbox', name, id: 'pf-' + name }), label);
      const protocolSelect = el('select', { class: 'field', id: 'pf-protocol', name: 'protocol' }, el('option', { value: '' }, 'All protocols'), names.map((n) => el('option', { value: n }, n)));
      const form = el('form', { class: 'card grid grid-cols-2 items-end gap-3 md:grid-cols-6', id: 'packet-filters' },
        field('q', 'Search', { placeholder: 'IP, port, MAC, packet #', type: 'search' }),
        el('div', {}, el('label', { class: 'label', for: 'pf-protocol' }, 'Protocol'), protocolSelect),
        field('ip', 'IP address', { placeholder: '10.0.0.1 or 2001:db8::1' }), field('port', 'Port', { type: 'number', min: 0, max: 65535 }),
        field('tcp_flags', 'TCP flags', { placeholder: 'S, SA, FA\u2026', maxlength: 8 }), field('flow_id', 'Flow #', { type: 'number', min: 1 }),
        field('min_length', 'Min length (B)', { type: 'number', min: 0 }), field('max_length', 'Max length (B)', { type: 'number', min: 0 }),
        el('div', {}, el('label', { class: 'label', for: 'pf-sort' }, 'Sort'),
          el('select', { class: 'field', id: 'pf-sort', name: 'sort' }, [['number', 'Packet #'], ['time', 'Time'], ['length', 'Length']].map(([v, t]) => el('option', { value: v }, t)))),
        el('div', {}, el('label', { class: 'label', for: 'pf-order' }, 'Order'),
          el('select', { class: 'field', id: 'pf-order', name: 'order' }, [['asc', 'Ascending'], ['desc', 'Descending']].map(([v, t]) => el('option', { value: v }, t)))),
        el('div', {}, el('label', { class: 'label', for: 'pf-per_page' }, 'Per page'),
          el('select', { class: 'field', id: 'pf-per_page', name: 'per_page' }, [25, 50, 100, 200].map((n) => el('option', { value: n }, n)))),
        el('div', { class: 'flex flex-col gap-1' }, check('retransmission', 'Retransmissions only'), check('malformed', 'Malformed only')),
        el('div', { class: 'col-span-2 flex gap-2 md:col-span-6' },
          el('button', { class: 'btn btn-primary', type: 'submit' }, 'Apply filters'),
          el('button', { class: 'btn btn-secondary', type: 'button', id: 'pf-reset' }, 'Reset'),
          el('a', { class: 'btn btn-secondary', id: 'pf-export', href: '#' }, 'Export matches (CSV)')));
      const results = el('div', { id: 'packet-results' });
      const detail = el('div', { id: 'packet-detail', class: 'mt-4' });
      clear(panel).append(form, el('div', { class: 'card mt-4 p-0' }, results), detail);
      packetUi = { form, results, detail };

      const readForm = () => {
        for (const k of ['q', 'protocol', 'ip', 'port', 'tcp_flags', 'flow_id', 'min_length', 'max_length', 'sort', 'order']) pf[k] = form.elements[k].value.trim();
        pf.per_page = Number(form.elements.per_page.value);
        pf.retransmission = form.elements.retransmission.checked;
        pf.malformed = form.elements.malformed.checked;
      };
      form.addEventListener('submit', (e) => { e.preventDefault(); readForm(); pf.page = 1; fetchPackets(); });
      document.getElementById('pf-reset').addEventListener('click', () => {
        Object.assign(pf, { page: 1, per_page: 50, sort: 'number', order: 'asc', q: '', protocol: '', ip: '', port: '', tcp_flags: '', min_length: '', max_length: '', flow_id: '', retransmission: false, malformed: false });
        writeForm(); fetchPackets();
      });
      writeForm();
      pf.dirty = false;
      fetchPackets();
    }, 'packets');
  }

  function writeForm() {
    const f = packetUi.form.elements;
    for (const k of ['q', 'protocol', 'ip', 'port', 'tcp_flags', 'flow_id', 'min_length', 'max_length', 'sort', 'order', 'per_page']) f[k].value = pf[k];
    f.retransmission.checked = pf.retransmission;
    f.malformed.checked = pf.malformed;
  }

  async function fetchPackets() {
    const { results, detail } = packetUi;
    clear(detail);
    document.getElementById('pf-export').href = '/api/v1' + base + '/export/packets.csv' + NS.queryString(packetQuery(false));
    showState(results, 'loading', 'Loading packets\u2026');
    try {
      const data = await api(base + '/packets', { query: packetQuery(true) });
      if (!data.items.length) { showState(results, 'empty', data.total === 0 && !pf.dirty && !hasFilters() ? 'This capture contains no packets.' : 'No packets match these filters.'); return; }
      clear(results).append(table([
        { label: '#', class: 'text-right', render: (p) => p.packet_number },
        { label: 'Time (UTC)', render: (p) => clock(p.timestamp) },
        { label: 'Source', render: (p) => endpoint(p.source_ip, p.source_port) },
        { label: 'Destination', render: (p) => endpoint(p.destination_ip, p.destination_port) },
        { label: 'Protocol', render: (p) => p.protocol },
        { label: 'Length', class: 'text-right', render: (p) => p.original_length },
        { label: 'Info', render: (p) => el('span', {}, packetInfo(p), ' ',
            p.is_retransmission ? el('span', { class: 'badge bg-amber-100 text-amber-800' }, 'retransmission') : null,
            p.malformed_reason ? el('span', { class: 'badge bg-red-100 text-red-800', title: p.malformed_reason }, 'malformed') : null) },
      ], data.items, { onRowClick: (p) => showPacket(p.packet_number), rowClass: () => 'font-mono text-xs' }), pager(data, (pg) => { pf.page = pg; fetchPackets(); }));
    } catch (e) { showState(results, 'error', e.message, fetchPackets); }
  }

  const hasFilters = () => Object.keys(packetQuery(false)).some((k) => pf[k] !== '' && pf[k] !== false);

  async function showPacket(n) {
    const { detail } = packetUi;
    showState(detail, 'loading', 'Loading packet ' + n + '\u2026');
    try {
      const { packet: p } = await api(base + '/packets/' + n);
      const rows = Object.entries(p).filter(([k, v]) => v !== null && v !== false && k !== 'application_metadata');
      clear(detail).append(el('div', { class: 'card', id: 'packet-detail-card' },
        el('div', { class: 'mb-2 flex items-center justify-between' }, el('h3', { class: 'text-sm font-semibold' }, 'Packet ' + p.packet_number),
          el('button', { class: 'text-sm text-slate-500 hover:underline', type: 'button', onclick: () => clear(detail) }, 'Close')),
        el('dl', { class: 'grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2 lg:grid-cols-3' },
          rows.map(([k, v]) => el('div', { class: 'flex justify-between gap-3 border-b border-slate-100 py-1' }, el('dt', { class: 'text-slate-500' }, k.replace(/_/g, ' ')), el('dd', { class: 'break-all text-right font-mono text-xs' }, String(v))))),
        p.application_metadata ? el('pre', { class: 'mt-3 overflow-x-auto rounded bg-slate-50 p-3 text-xs', 'data-role': 'metadata' }, JSON.stringify(p.application_metadata, null, 2)) : null));
      detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (e) { showState(detail, 'error', e.message, () => showPacket(n)); }
  }

  // ------------------------------------------------------------------ performance
  function loadPerformance() {
    const panel = panels.performance;
    return guard(panel, async () => {
      const { performance: p, tcp, latency } = await getPerformance();
      const util = el('div', { id: 'utilization-result', class: 'mt-2 text-sm text-slate-600' }, 'Enter the link speed to estimate utilisation. A capture does not record it, so it is not guessed.');
      const speed = el('input', { class: 'field w-32', type: 'number', min: 0, step: 'any', id: 'link-mbps', placeholder: 'e.g. 100', 'aria-label': 'Link speed in Mbit/s' });
      const calc = el('button', { class: 'btn btn-secondary', type: 'button', id: 'util-btn' }, 'Calculate');
      calc.addEventListener('click', async () => {
        try {
          const r = await api(base + '/performance', { query: { link_mbps: speed.value } });
          clear(util).append('At ' + num(r.utilization.link_capacity_mbps, 2) + ' Mbit/s: average ' + percent(r.utilization.avg_percent, 3) + ', peak ' + percent(r.utilization.peak_percent, 3) + ' of capacity.');
        } catch (e) { clear(util).append(el('span', { class: 'text-red-700' }, e.message)); }
      });
      const bpsBox = chartBox('Throughput over time'); const ppsBox = chartBox('Packets per second over time');
      clear(panel).append(
        el('div', { class: 'grid grid-cols-2 gap-4 md:grid-cols-4' },
          statCard('Avg throughput', bps(p.avg_throughput_bps)), statCard('Peak throughput (1 s)', bps(p.peak_throughput_bps)),
          statCard('Avg packets/s', NS.num(p.avg_packets_per_second, 2)), statCard('Peak packets/s (1 s)', num(p.peak_packets_per_second)),
          statCard('Avg packet size', p.avg_packet_size_bytes === null ? NS.dash : p.avg_packet_size_bytes.toFixed(1) + ' B'),
          statCard('Min / max size', p.min_packet_size_bytes === null ? NS.dash : p.min_packet_size_bytes + ' / ' + p.max_packet_size_bytes + ' B'),
          statCard('TCP retransmissions', num(tcp.retransmissions), tcp.retransmission_rate === null ? 'no TCP traffic' : percent(100 * tcp.retransmission_rate, 2) + ' of ' + num(tcp.packets) + ' TCP packets'),
          statCard('Duration', duration(p.duration_seconds))),
        el('div', { class: 'card mt-4' }, el('h3', { class: 'text-sm font-semibold text-slate-700' }, 'Bandwidth utilisation'),
          el('div', { class: 'mt-2 flex items-center gap-2' }, speed, 'Mbit/s', calc), util),
        el('div', { class: 'mt-4 grid gap-4 lg:grid-cols-2' }, bpsBox, ppsBox),
        el('div', { class: 'mt-4 grid gap-4 lg:grid-cols-2' },
          distributionCard('TCP handshake RTT', latency.handshake_rtt_ms, 'First SYN to its SYN-ACK as seen at the capture point; only flows whose handshake was captured.', ms),
          distributionCard('Flow jitter', latency.flow_jitter_ms, 'Mean change in packet inter-arrival gap within each flow (needs 3+ packets). Arrival-time jitter, not RFC 3550.', ms)),
        el('p', { class: 'mt-4 text-xs text-slate-500' }, 'Retransmissions count exact duplicate TCP segments, so the figure is a lower bound.'));
      tsChart(bpsBox.querySelector('div.relative'), p.timeseries.points, 'bits_per_second', 'Throughput', bps);
      tsChart(ppsBox.querySelector('div.relative'), p.timeseries.points, 'packets_per_second', 'Packets/s', (v) => num(v, 2));
    }, 'performance');
  }

  window.addEventListener('hashchange', () => {
    const wanted = window.location.hash.slice(1);
    if (capture && capture.status === 'completed' && TABS.some(([k]) => k === wanted) && wanted !== activeTab) showTab(wanted);
  });

  // showTab('packets') after a cross-link must re-run the query with the new filters
  const originalShowTab = showTab;
  showTab = function (name) {
    originalShowTab(name);
    if (name === 'packets' && pf.dirty && packetUi) { pf.dirty = false; writeForm(); fetchPackets(); }
  };

  load();
})();

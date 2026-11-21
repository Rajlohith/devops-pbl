(function () {
  'use strict';
  const { api, el, clear, num, byUnit, dateTime, showState, table, chart, chartBox, PALETTE, bytes } = NS;
  const root = document.getElementById('compare-root');
  const params = new URLSearchParams(window.location.search);

  function signed(delta, unit) {
    if (delta === null || delta === undefined) return NS.dash;
    return (delta > 0 ? '+' : '') + byUnit(delta, unit);
  }

  function renderResult(target, r) {
    const a = r.a, b = r.b;
    const protoBox = chartBox('Bytes by transport protocol');
    const ipList = (title, items, count) => el('details', { class: 'rounded border border-slate-200 p-2 text-sm', 'data-ips': title },
      el('summary', { class: 'cursor-pointer font-medium' }, title + ': ' + num(count)),
      items.length ? el('ul', { class: 'mt-2 font-mono text-xs' }, items.map((ip) => el('li', {}, ip))) : el('p', { class: 'mt-2 text-xs text-slate-500' }, 'None'),
      count > items.length ? el('p', { class: 'mt-1 text-xs text-slate-500' }, 'Showing the first ' + items.length + '.') : null);

    clear(target).append(
      el('div', { class: 'card p-0' }, table([
        { label: 'Metric', render: (m) => m.label },
        { label: 'A \u2014 ' + a.filename, class: 'text-right', render: (m) => el('span', { 'data-cell': m.key + '-a' }, byUnit(m.a, m.unit)) },
        { label: 'B \u2014 ' + b.filename, class: 'text-right', render: (m) => el('span', { 'data-cell': m.key + '-b' }, byUnit(m.b, m.unit)) },
        { label: 'Change (B \u2212 A)', class: 'text-right', render: (m) => el('span', { 'data-cell': m.key + '-delta' }, signed(m.delta, m.unit)) },
        { label: '%', class: 'text-right', render: (m) => (m.delta_percent === null ? NS.dash : (m.delta_percent > 0 ? '+' : '') + m.delta_percent.toFixed(1) + '%') },
      ], r.metrics)),
      el('p', { class: 'mt-2 text-xs text-slate-500' }, 'A dash means the value is not available for that capture (for example, no TCP handshake was captured).'),
      el('div', { class: 'mt-4 grid gap-4 lg:grid-cols-2' }, protoBox,
        el('div', { class: 'card' }, el('h3', { class: 'mb-2 text-sm font-semibold text-slate-700' }, 'IP address overlap'),
          el('div', { class: 'space-y-2' },
            ipList('In both captures', r.ips.sample.shared, r.ips.shared),
            ipList('Only in A', r.ips.sample.only_a, r.ips.only_a),
            ipList('Only in B', r.ips.sample.only_b, r.ips.only_b)))));

    const protocols = r.protocols;
    chart(protoBox.querySelector('div.relative'), {
      type: 'bar',
      data: { labels: protocols.map((p) => p.protocol), datasets: [
        { label: 'A', data: protocols.map((p) => (p.a ? p.a.bytes : 0)), backgroundColor: PALETTE[0] },
        { label: 'B', data: protocols.map((p) => (p.b ? p.b.bytes : 0)), backgroundColor: PALETTE[2] }] },
      options: { plugins: { tooltip: { callbacks: { label: (c) => c.dataset.label + ': ' + bytes(c.parsed.y) } } }, scales: { y: { beginAtZero: true, ticks: { callback: (v) => bytes(v) } } } },
    });
  }

  async function init() {
    showState(root, 'loading', 'Loading captures\u2026');
    let items;
    try {
      items = (await api('/captures', { query: { status: 'completed', per_page: 100 } })).items;
    } catch (e) { showState(root, 'error', e.message, init); return; }
    if (items.length < 2) {
      showState(root, 'empty', 'You need at least two analysed captures to compare. Upload and analyse another capture first.');
      return;
    }
    const option = (c) => el('option', { value: c.id }, c.original_filename + ' \u2014 ' + dateTime(c.uploaded_at));
    const select = (id, label, chosen) => el('div', {}, el('label', { class: 'label', for: id }, label),
      el('select', { class: 'field', id }, el('option', { value: '' }, 'Choose a capture\u2026'),
        items.map((c) => { const o = option(c); if (c.id === chosen) o.selected = true; return o; })));
    const a = select('cmp-a', 'Capture A (baseline)', params.get('a'));
    const b = select('cmp-b', 'Capture B', params.get('b'));
    const result = el('div', { class: 'mt-6', id: 'compare-result' });
    const run = el('button', { class: 'btn btn-primary', type: 'button', id: 'compare-btn' }, 'Compare');

    async function compare() {
      const av = a.querySelector('select').value, bv = b.querySelector('select').value;
      if (!av || !bv) { showState(result, 'empty', 'Choose two captures.'); return; }
      if (av === bv) { showState(result, 'error', 'Choose two different captures to compare.'); return; }
      history.replaceState(null, '', '?a=' + av + '&b=' + bv);
      showState(result, 'loading', 'Comparing\u2026');
      try { renderResult(result, await api('/compare', { query: { a: av, b: bv } })); }
      catch (e) { showState(result, 'error', e.message, compare); }
    }
    run.addEventListener('click', compare);
    clear(root).append(el('div', { class: 'card grid items-end gap-3 md:grid-cols-3' }, a, b, el('div', {}, run)), result);
    if (params.get('a') && params.get('b')) compare();
  }
  init();
})();

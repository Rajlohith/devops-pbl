/* NetScope shared client library. All data is rendered through textContent / text
 * nodes (never innerHTML), so capture contents cannot inject markup into pages. */
(function () {
  'use strict';

  const csrfToken = () => document.querySelector('meta[name="csrf-token"]').content;

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.status = status;
    }
  }

  function queryString(query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(query || {})) {
      if (v !== undefined && v !== null && v !== '' && v !== false) q.set(k, v === true ? 'true' : v);
    }
    const s = q.toString();
    return s ? '?' + s : '';
  }

  async function api(path, { method = 'GET', json, query } = {}) {
    const headers = { Accept: 'application/json', 'X-CSRFToken': csrfToken() };
    const init = { method, headers, credentials: 'same-origin' };
    if (json !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(json);
    }
    let res;
    try {
      res = await fetch('/api/v1' + path + queryString(query), init);
    } catch (e) {
      throw new ApiError('Could not reach the server. Check your connection and try again.', 0);
    }
    if (res.status === 401) {
      window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
      throw new ApiError('Your session has expired.', 401);
    }
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON error body */ }
    if (!res.ok) {
      throw new ApiError((data && data.error && data.error.message) || 'Request failed (' + res.status + ').', res.status);
    }
    return data;
  }

  /* el('div', {class: 'x', onclick: fn}, 'text', childNode, [more]) */
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  const clear = (node) => { node.replaceChildren(); return node; };

  // ------------------------------------------------------------------ formatting
  const dash = '\u2014';
  const num = (n, digits = 0) =>
    n === null || n === undefined ? dash : Number(n).toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits });

  function bytes(n) {
    if (n === null || n === undefined) return dash;
    let v = Math.abs(Number(n));
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    const text = i === 0 ? String(Math.round(v)) : v.toFixed(2);
    return (n < 0 ? '-' : '') + text + ' ' + units[i];
  }

  function bps(n) {
    if (n === null || n === undefined) return dash;
    let v = Math.abs(Number(n));
    const units = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s'];
    let i = 0;
    while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    return (n < 0 ? '-' : '') + (i === 0 ? Math.round(v) : v.toFixed(2)) + ' ' + units[i];
  }

  function duration(s) {
    if (s === null || s === undefined) return dash;
    if (s < 1) return (s * 1000).toFixed(0) + ' ms';
    if (s < 60) return s.toFixed(2) + ' s';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + Math.round(s - m * 60) + 's';
    return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
  }

  const percent = (p, digits = 1) => (p === null || p === undefined ? dash : Number(p).toFixed(digits) + '%');
  const ms = (v) => (v === null || v === undefined ? dash : Number(v).toFixed(2) + ' ms');
  const dateTime = (iso) => (iso ? iso.replace('T', ' ').slice(0, 19) + ' UTC' : dash);
  const clock = (iso) => {
    const m = /T(\d\d:\d\d:\d\d(?:\.\d+)?)/.exec(iso || '');
    return m ? m[1] : dash;
  };

  function byUnit(value, unit) {
    switch (unit) {
      case 'bytes': return bytes(value);
      case 'bps': return bps(value);
      case 'seconds': return duration(value);
      case 'ms': return ms(value);
      case 'ratio': return value === null || value === undefined ? dash : percent(value * 100, 2);
      case 'pps': return value === null || value === undefined ? dash : num(value, 2) + ' /s';
      default: return num(value, Number.isInteger(value) ? 0 : 2);
    }
  }

  // ------------------------------------------------------------------ components
  const STATUS_CLASSES = {
    uploaded: 'bg-slate-200 text-slate-800',
    pending: 'bg-amber-100 text-amber-800',
    processing: 'bg-blue-100 text-blue-800',
    completed: 'bg-green-100 text-green-800',
    failed: 'bg-red-100 text-red-800',
  };
  const statusBadge = (status) => el('span', { class: 'badge ' + (STATUS_CLASSES[status] || STATUS_CLASSES.uploaded), text: status });

  /* Replace a container's content with a loading / empty / error state. */
  function showState(container, kind, message, onRetry) {
    clear(container);
    if (kind === 'loading') {
      container.append(el('div', { class: 'flex items-center gap-3 p-6 text-sm text-slate-500', role: 'status' },
        el('span', { class: 'h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-slate-600' }),
        message || 'Loading\u2026'));
    } else if (kind === 'empty') {
      container.append(el('div', { class: 'p-8 text-center text-sm text-slate-500', 'data-state': 'empty' }, message));
    } else {
      container.append(el('div', { class: 'p-6 text-sm', role: 'alert', 'data-state': 'error' },
        el('p', { class: 'mb-3 text-red-700' }, message || 'Something went wrong.'),
        onRetry ? el('button', { class: 'btn btn-secondary', type: 'button', onclick: onRetry }, 'Try again') : null));
    }
    return container;
  }

  /* columns: [{label, render(row) -> Node|string, class}] */
  function table(columns, rows, { onRowClick, rowClass } = {}) {
    const head = el('tr', {}, columns.map((c) => el('th', { class: 'th ' + (c.class || ''), scope: 'col' }, c.label)));
    const body = rows.map((row) => {
      const tr = el('tr', { class: 'border-t border-slate-100 ' + (onRowClick ? 'cursor-pointer hover:bg-slate-50 ' : '') + (rowClass ? rowClass(row) : '') },
        columns.map((c) => el('td', { class: 'td ' + (c.class || '') }, c.render(row))));
      if (onRowClick) tr.addEventListener('click', () => onRowClick(row));
      return tr;
    });
    return el('div', { class: 'overflow-x-auto' },
      el('table', { class: 'w-full text-left text-sm' }, el('thead', { class: 'bg-slate-50' }, head), el('tbody', {}, body)));
  }

  function pager({ page, per_page, total }, onPage) {
    const pages = Math.max(1, Math.ceil(total / per_page));
    const first = total === 0 ? 0 : (page - 1) * per_page + 1;
    const last = Math.min(total, page * per_page);
    return el('div', { class: 'flex items-center justify-between border-t border-slate-100 px-3 py-2 text-sm text-slate-600' },
      el('span', { 'data-role': 'range' }, num(first) + '\u2013' + num(last) + ' of ' + num(total)),
      el('span', { class: 'flex items-center gap-2' },
        el('button', { class: 'btn btn-secondary', type: 'button', disabled: page <= 1, onclick: () => onPage(page - 1) }, 'Previous'),
        el('span', {}, 'Page ' + page + ' / ' + pages),
        el('button', { class: 'btn btn-secondary', type: 'button', disabled: page >= pages, onclick: () => onPage(page + 1) }, 'Next')));
  }

  const statCard = (label, value, hint) =>
    el('div', { class: 'card' },
      el('div', { class: 'text-xs font-medium uppercase tracking-wide text-slate-500' }, label),
      el('div', { class: 'mt-1 text-2xl font-semibold text-slate-900', 'data-stat': label }, value),
      hint ? el('div', { class: 'mt-1 text-xs text-slate-500' }, hint) : null);

  // ------------------------------------------------------------------ charts
  const PALETTE = ['#2563eb', '#16a34a', '#f59e0b', '#dc2626', '#7c3aed', '#0891b2', '#db2777', '#65a30d', '#64748b'];

  /* Draw a Chart.js chart into a wrapper element, replacing any previous chart. */
  function chart(wrapper, config) {
    clear(wrapper);
    if (typeof window.Chart === 'undefined') {
      wrapper.append(el('p', { class: 'p-4 text-sm text-slate-500' }, 'Charts are unavailable (Chart.js failed to load).'));
      return null;
    }
    const canvas = el('canvas', { 'data-chart': 'true' });
    wrapper.append(canvas);
    config.options = Object.assign({ responsive: true, maintainAspectRatio: false }, config.options || {});
    return new window.Chart(canvas, config);
  }

  const chartBox = (title, height = 'h-64') =>
    el('div', { class: 'card' }, el('h3', { class: 'mb-2 text-sm font-semibold text-slate-700' }, title), el('div', { class: height + ' relative' }));

  window.NS = { api, ApiError, el, clear, num, bytes, bps, duration, percent, ms, dateTime, clock, byUnit,
    statusBadge, showState, table, pager, statCard, chart, chartBox, PALETTE, dash, queryString, csrfToken };
})();

(function () {
  'use strict';
  const { api, el, num, bytes, dateTime, statusBadge, showState, table, pager } = NS;
  const uploadRoot = document.getElementById('upload-root');
  const historyRoot = document.getElementById('history-root');
  const ALLOWED = ['.pcap', '.pcapng', '.cap'];
  const view = { page: 1, status: '' };
  let timer = null;

  // ------------------------------------------------------------------ upload
  function buildUpload() {
    const input = el('input', { type: 'file', id: 'file-input', accept: ALLOWED.join(','), class: 'sr-only' });
    const analyze = el('input', { type: 'checkbox', id: 'analyze-now', checked: true });
    const message = el('p', { class: 'mt-3 text-sm', role: 'status', 'aria-live': 'polite', id: 'upload-message' });
    const bar = el('div', { class: 'h-full w-0 bg-blue-600 transition-all', id: 'upload-bar' });
    const progress = el('div', { class: 'mt-3 hidden', id: 'upload-progress' },
      el('div', { class: 'h-2 overflow-hidden rounded bg-slate-200' }, bar),
      el('div', { class: 'mt-1 text-xs text-slate-500', id: 'upload-progress-text' }));
    const chosen = el('span', { class: 'text-sm text-slate-600', id: 'chosen-file' }, 'No file selected');
    const button = el('button', { class: 'btn btn-primary', type: 'button', id: 'upload-button', disabled: true }, 'Upload');
    const drop = el('label', {
      for: 'file-input', id: 'drop-zone',
      class: 'flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-slate-300 bg-white p-8 text-center hover:border-blue-400',
    }, el('span', { class: 'font-medium text-slate-700' }, 'Drop a capture here or click to choose'),
       el('span', { class: 'mt-1 text-xs text-slate-500' }, 'PCAP or PCAPNG \u2014 validated on upload'));

    function pick(file) {
      message.textContent = '';
      message.className = 'mt-3 text-sm';
      if (!file) { chosen.textContent = 'No file selected'; button.disabled = true; return; }
      const ok = ALLOWED.some((ext) => file.name.toLowerCase().endsWith(ext));
      chosen.textContent = file.name + ' (' + bytes(file.size) + ')';
      button.disabled = !ok;
      if (!ok) {
        message.textContent = 'Unsupported file type. Choose a .pcap, .pcapng or .cap file.';
        message.className = 'mt-3 text-sm text-red-700';
      }
    }
    input.addEventListener('change', () => pick(input.files[0]));
    ['dragover', 'dragenter'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('border-blue-500'); }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('border-blue-500'); }));
    drop.addEventListener('drop', (e) => {
      if (e.dataTransfer.files.length) { input.files = e.dataTransfer.files; pick(input.files[0]); }
    });

    button.addEventListener('click', () => {
      const file = input.files[0];
      if (!file) return;
      const form = new FormData();
      form.append('file', file);
      form.append('analyze', analyze.checked ? 'true' : 'false');
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/v1/captures');
      xhr.setRequestHeader('X-CSRFToken', NS.csrfToken());
      xhr.setRequestHeader('Accept', 'application/json');
      progress.classList.remove('hidden');
      button.disabled = true;
      message.textContent = '';
      xhr.upload.onprogress = (e) => {
        if (!e.lengthComputable) return;
        const pct = Math.round((100 * e.loaded) / e.total);
        bar.style.width = pct + '%';
        document.getElementById('upload-progress-text').textContent =
          pct < 100 ? 'Uploading\u2026 ' + pct + '%' : 'Upload complete \u2014 validating\u2026';
      };
      const fail = (text) => {
        progress.classList.add('hidden');
        bar.style.width = '0%';
        button.disabled = false;
        message.textContent = text;
        message.className = 'mt-3 text-sm text-red-700';
      };
      xhr.onerror = () => fail('Upload failed: could not reach the server.');
      xhr.onload = () => {
        if (xhr.status === 401) { window.location.href = '/login?next=/captures'; return; }
        let data = null;
        try { data = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
        if (xhr.status === 201) {
          const capture = data.capture;
          progress.classList.add('hidden');
          bar.style.width = '0%';
          input.value = '';
          pick(null);
          message.className = 'mt-3 text-sm ' + (capture.status === 'failed' ? 'text-red-700' : 'text-green-700');
          message.replaceChildren(
            capture.status === 'failed'
              ? 'Uploaded, but analysis could not start: ' + (capture.error_message || 'unknown error') + ' '
              : 'Uploaded ' + capture.original_filename + '. ',
            el('a', { class: 'underline', href: '/captures/' + capture.id }, 'Open it'));
          loadHistory();
        } else {
          fail((data && data.error && data.error.message) || 'Upload failed (' + xhr.status + ').');
        }
      };
      xhr.send(form);
    });

    uploadRoot.append(el('div', { class: 'card' },
      el('h2', { class: 'mb-3 text-sm font-semibold text-slate-700' }, 'Upload a capture'),
      input, drop,
      el('div', { class: 'mt-3 flex flex-wrap items-center gap-4' }, chosen,
        el('label', { class: 'flex items-center gap-2 text-sm', for: 'analyze-now' }, analyze, 'Start analysis immediately'),
        button),
      progress, message));
  }

  // ------------------------------------------------------------------ history
  async function loadHistory(showLoading) {
    clearTimeout(timer);
    if (showLoading) showState(historyRoot, 'loading', 'Loading captures\u2026');
    let data;
    try {
      data = await api('/captures', { query: { page: view.page, per_page: 15, status: view.status } });
    } catch (e) {
      showState(historyRoot, 'error', e.message, () => loadHistory(true));
      return;
    }
    renderHistory(data);
    if (data.items.some((c) => c.status === 'pending' || c.status === 'processing')) {
      timer = setTimeout(() => loadHistory(false), 2000);
    }
  }

  async function act(label, fn) {
    try { await fn(); } catch (e) { alert(label + ' failed: ' + e.message); }
    loadHistory();
  }

  function renderHistory(data) {
    const filter = el('select', { class: 'field w-40', id: 'status-filter', 'aria-label': 'Filter by status' },
      ['', 'completed', 'processing', 'pending', 'uploaded', 'failed'].map((s) =>
        el('option', { value: s, selected: s === view.status }, s === '' ? 'All statuses' : s)));
    filter.addEventListener('change', () => { view.status = filter.value; view.page = 1; loadHistory(true); });

    const header = el('div', { class: 'flex items-center justify-between px-4 pb-3 pt-4' },
      el('h2', { class: 'text-sm font-semibold text-slate-700' }, 'Capture history'), filter);

    const card = el('div', { class: 'card p-0' }, header);
    if (data.items.length === 0 && data.total > 0) {
      view.page = 1; loadHistory(true); return;  // the last page emptied (e.g. after a delete)
    }
    if (data.items.length === 0) {
      card.append(el('div', { class: 'p-8 text-center text-sm text-slate-500', 'data-state': 'empty' },
        view.status ? 'No captures with status \u201c' + view.status + '\u201d.' : 'No captures yet. Upload a .pcap or .pcapng file above.'));
    } else {
      card.append(table([
        { label: 'File', render: (c) => el('a', { class: 'font-medium text-blue-700 hover:underline', href: '/captures/' + c.id }, c.original_filename) },
        { label: 'Format', render: (c) => c.file_format },
        { label: 'Size', class: 'text-right', render: (c) => bytes(c.file_size_bytes) },
        { label: 'Uploaded', render: (c) => dateTime(c.uploaded_at) },
        { label: 'Status', render: (c) => el('div', {}, statusBadge(c.status),
            c.status === 'processing' && c.packet_count ? el('div', { class: 'mt-1 text-xs text-slate-500' }, num(c.packet_count) + ' packets so far') : null,
            c.status === 'completed' ? el('div', { class: 'mt-1 text-xs text-slate-500' }, num(c.packet_count) + ' packets') : null,
            c.status === 'failed' && c.error_message ? el('div', { class: 'mt-1 max-w-xs text-xs text-red-700' }, c.error_message) : null) },
        { label: '', class: 'text-right', render: (c) => el('div', { class: 'flex justify-end gap-2' },
            c.status === 'uploaded' || c.status === 'failed'
              ? el('button', { class: 'btn btn-secondary', type: 'button', 'data-action': 'analyze',
                  onclick: () => act('Analysis', () => api('/captures/' + c.id + '/analyze', { method: 'POST' })) },
                  c.status === 'failed' ? 'Retry' : 'Analyse') : null,
            el('button', { class: 'btn btn-secondary text-red-700', type: 'button', 'data-action': 'delete',
              onclick: () => { if (confirm('Delete ' + c.original_filename + ' and its analysis permanently?')) act('Delete', () => api('/captures/' + c.id, { method: 'DELETE' })); } },
              'Delete')) },
      ], data.items));
      card.append(pager(data, (p) => { view.page = p; loadHistory(true); }));
    }
    NS.clear(historyRoot).append(card);
  }

  buildUpload();
  loadHistory(true);
})();

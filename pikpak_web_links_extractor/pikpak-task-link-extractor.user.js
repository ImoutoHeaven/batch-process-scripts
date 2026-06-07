// ==UserScript==
// @name         PikPak Task Link Extractor
// @namespace    local.pikpak.task.link.extractor
// @version      0.1.0
// @description  Extract magnet/ed2k/http(s) links from PikPak task API responses
// @match        https://mypikpak.com/*
// @match        https://www.mypikpak.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

  if (window.__pikpakTaskLinkExtractorInstalled) return;
  window.__pikpakTaskLinkExtractorInstalled = true;

  const ENDPOINT_HOST = 'api-drive.mypikpak.com';
  const ENDPOINT_PATH = '/drive/v1/tasks';
  const KNOWN_PHASES = [
    'PHASE_TYPE_UNKNOW',
    'PHASE_TYPE_PENDING',
    'PHASE_TYPE_RUNNING',
    'PHASE_TYPE_PAUSED',
    'PHASE_TYPE_ERROR',
  ];

  const state = {
    itemsByLink: new Map(),
    phaseOrder: [...KNOWN_PHASES],
    filterMode: 'single',
    selectedPhases: new Set(),
    ui: null,
    visible: false,
  };

  function normalizeUrl(value) {
    if (typeof value !== 'string') return '';
    return value.trim();
  }

  function isSupportedLink(value) {
    return /^(magnet:|ed2k:\/\/|https?:\/\/)/i.test(value);
  }

  function isTasksEndpoint(url) {
    try {
      const parsed = new URL(url, location.href);
      return parsed.hostname === ENDPOINT_HOST && parsed.pathname === ENDPOINT_PATH;
    } catch {
      return false;
    }
  }

  function toUpperMethod(method) {
    return String(method || 'GET').toUpperCase();
  }

  function getFetchInfo(input, init) {
    let url = '';
    let method = 'GET';

    if (typeof input === 'string' || input instanceof URL) {
      url = String(input);
    } else if (input && typeof input === 'object') {
      if (typeof input.url === 'string') url = input.url;
      if (typeof input.method === 'string') method = input.method;
    }

    if (init && typeof init === 'object' && typeof init.method === 'string') {
      method = init.method;
    }

    return { url, method: toUpperMethod(method) };
  }

  function ensurePhaseKnown(phase) {
    if (!phase || state.phaseOrder.includes(phase)) return;
    state.phaseOrder.push(phase);
    if (state.ui) renderPhaseButtons();
  }

  function createEmptyItem(link, task, phase, source) {
    return {
      link,
      phaseSet: new Set(),
      latestPhase: phase || '',
      nameSet: new Set(),
      taskIdSet: new Set(),
      createdTime: '',
      updatedTime: '',
      sourceSet: new Set(),
      count: 0,
    };
  }

  function recordLink(link, task, phase, source) {
    const normalizedLink = normalizeUrl(link);
    if (!normalizedLink || !isSupportedLink(normalizedLink)) return;

    const key = normalizedLink;
    const existing = state.itemsByLink.get(key) || createEmptyItem(key, task, phase, source);

    existing.count += 1;
    if (phase) {
      existing.latestPhase = phase;
      existing.phaseSet.add(phase);
      ensurePhaseKnown(phase);
    }
    if (task && typeof task === 'object') {
      if (task.id) existing.taskIdSet.add(String(task.id));
      if (task.name) existing.nameSet.add(String(task.name));
      if (task.created_time) existing.createdTime = existing.createdTime || String(task.created_time);
      if (task.updated_time) existing.updatedTime = String(task.updated_time);
    }
    if (source) existing.sourceSet.add(source);

    state.itemsByLink.set(key, existing);
  }

  function extractLinkFromTask(task) {
    if (!task || typeof task !== 'object') return [];
    const links = [];

    const candidatePaths = [
      task?.params?.url,
      task?.reference_resource?.params?.url,
      task?.callback,
    ];

    for (const candidate of candidatePaths) {
      const value = normalizeUrl(candidate);
      if (value && isSupportedLink(value)) links.push(value);
    }

    return links;
  }

  function extractFromPayload(payload, source) {
    const tasks = payload && Array.isArray(payload.tasks) ? payload.tasks : [];
    for (const task of tasks) {
      const phase = typeof task?.phase === 'string' ? task.phase : '';
      const links = extractLinkFromTask(task);
      for (const link of links) {
        recordLink(link, task, phase, source);
      }
    }
    updateUi();
  }

  function handleParsedResponse(payload, meta) {
    if (!payload || typeof payload !== 'object') return;
    if (!Array.isArray(payload.tasks)) return;
    if (!isTasksEndpoint(meta.url)) return;
    if (meta.method !== 'GET') return;
    if (meta.status !== 200) return;
    extractFromPayload(payload, meta.source);
  }

  function parseAndHandleBody(body, meta) {
    try {
      if (typeof body === 'string') {
        const text = body.trim();
        if (!text) return;
        handleParsedResponse(JSON.parse(text), meta);
        return;
      }

      if (body && typeof body === 'object') {
        handleParsedResponse(body, meta);
      }
    } catch {
      // Ignore non-JSON / malformed payloads silently.
    }
  }

  function handleFetchResponse(response, info) {
    if (!response || typeof response !== 'object') return;
    const meta = {
      method: info.method,
      url: info.url,
      status: response.status,
      source: 'fetch',
    };

    if (meta.method === 'OPTIONS' || meta.status === 204) return;
    if (meta.method !== 'GET' || meta.status !== 200) return;
    if (!isTasksEndpoint(meta.url)) return;

    response
      .clone()
      .text()
      .then((text) => parseAndHandleBody(text, meta))
      .catch(() => {});
  }

  function patchFetch() {
    if (typeof window.fetch !== 'function') return;
    const originalFetch = window.fetch;
    window.fetch = function patchedFetch(...args) {
      const info = getFetchInfo(args[0], args[1]);
      return originalFetch.apply(this, args).then((response) => {
        handleFetchResponse(response, info);
        return response;
      });
    };
  }

  function patchXhr() {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function patchedOpen(method, url, ...rest) {
      this.__pikpakMethod = toUpperMethod(method);
      this.__pikpakUrl = String(url || '');
      return originalOpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function patchedSend(...args) {
      const xhr = this;

      function onLoadEnd() {
        xhr.removeEventListener('loadend', onLoadEnd);
        const meta = {
          method: xhr.__pikpakMethod || 'GET',
          url: xhr.__pikpakUrl || '',
          status: xhr.status,
          source: 'xhr',
        };

        if (meta.method === 'OPTIONS' || meta.status === 204) return;
        if (meta.method !== 'GET' || meta.status !== 200) return;
        if (!isTasksEndpoint(meta.url)) return;

        try {
          if (xhr.responseType === 'json') {
            parseAndHandleBody(xhr.response, meta);
          } else {
            parseAndHandleBody(xhr.responseText, meta);
          }
        } catch {
          // Ignore read errors.
        }
      }

      xhr.addEventListener('loadend', onLoadEnd);
      return originalSend.apply(xhr, args);
    };
  }

  function getFilteredItems() {
    const items = [...state.itemsByLink.values()];
    const selected = state.selectedPhases;
    if (!selected.size) return items;
    return items.filter((item) => {
      const phases = item.phaseSet.size ? item.phaseSet : new Set([item.latestPhase].filter(Boolean));
      if (!phases.size) return false;
      if (state.filterMode === 'single') {
        const only = [...selected][0];
        return phases.has(only);
      }
      for (const phase of selected) {
        if (phases.has(phase)) return true;
      }
      return false;
    });
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function copyText(text) {
    if (!text) return Promise.resolve();
    if (typeof navigator.clipboard?.writeText === 'function') {
      return navigator.clipboard.writeText(text);
    }
    if (typeof GM_setClipboard === 'function') {
      GM_setClipboard(text, 'text');
      return Promise.resolve();
    }
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'readonly');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
    return Promise.resolve();
  }

  function buildUi() {
    if (state.ui) return state.ui;

    const host = document.createElement('div');
    host.id = 'pikpak-task-link-extractor-host';
    host.style.all = 'initial';
    host.style.position = 'fixed';
    host.style.zIndex = '2147483647';
    host.style.right = '16px';
    host.style.bottom = '16px';

    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        .wrap { font-family: Arial, Helvetica, sans-serif; color: #eaeef7; }
        .fab {
          appearance: none; border: 0; border-radius: 999px; cursor: pointer;
          padding: 10px 14px; font-size: 13px; font-weight: 700; letter-spacing: .02em;
          color: #fff; background: linear-gradient(135deg, #2e7dff, #1759f0);
          box-shadow: 0 8px 24px rgba(23, 89, 240, .35);
        }
        .fab:hover { filter: brightness(1.04); }
        .panel {
          display: none; width: min(700px, calc(100vw - 32px)); max-height: min(70vh, 720px);
          margin-bottom: 10px; overflow: hidden; border-radius: 14px;
          background: rgba(15, 19, 28, .96); border: 1px solid rgba(255,255,255,.12);
          box-shadow: 0 16px 48px rgba(0,0,0,.45); backdrop-filter: blur(12px);
        }
        .panel.show { display: block; }
        .header, .toolbar, .filters, .stats {
          display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
        }
        .header {
          justify-content: space-between; padding: 12px 12px 10px; border-bottom: 1px solid rgba(255,255,255,.08);
        }
        .title { font-size: 14px; font-weight: 800; }
        .subtle { font-size: 12px; color: rgba(234,238,247,.72); }
        .body { padding: 12px; display: grid; gap: 10px; }
        .section { display: grid; gap: 8px; }
        .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
        .btn {
          appearance: none; border: 1px solid rgba(255,255,255,.12); border-radius: 10px;
          background: rgba(255,255,255,.06); color: #eaeef7; cursor: pointer;
          padding: 7px 10px; font-size: 12px; line-height: 1; white-space: nowrap;
        }
        .btn:hover { background: rgba(255,255,255,.1); }
        .btn.primary { background: #2563eb; border-color: #2563eb; }
        .btn.active { background: rgba(59,130,246,.22); border-color: rgba(59,130,246,.55); color: #dbeafe; }
        .btn.danger { background: rgba(239,68,68,.18); border-color: rgba(239,68,68,.35); }
        .count { padding: 3px 8px; border-radius: 999px; background: rgba(255,255,255,.09); font-size: 12px; }
        .list {
          border-radius: 12px; border: 1px solid rgba(255,255,255,.09);
          background: rgba(255,255,255,.03); max-height: min(48vh, 460px); overflow: auto;
        }
        .item {
          padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,.06);
          display: grid; gap: 6px;
        }
        .item:last-child { border-bottom: 0; }
        .link {
          font-size: 12px; line-height: 1.4; color: #f8fbff; word-break: break-all; white-space: normal;
        }
        .meta { font-size: 11px; color: rgba(234,238,247,.66); display: flex; gap: 6px; flex-wrap: wrap; }
        .badge {
          padding: 2px 6px; border-radius: 999px; background: rgba(255,255,255,.08);
          border: 1px solid rgba(255,255,255,.08);
        }
        .empty {
          padding: 18px 12px; text-align: center; color: rgba(234,238,247,.65); font-size: 13px;
        }
        .mode {
          margin-left: auto; display: inline-flex; gap: 6px; align-items: center;
        }
      </style>
      <div class="wrap">
        <div class="panel" part="panel">
          <div class="header">
            <div>
              <div class="title">PikPak Task Link Extractor</div>
              <div class="subtle" data-role="summary">等待捕获 drive/v1/tasks 响应</div>
            </div>
            <div class="toolbar">
              <button class="btn primary" data-action="copy-all">复制全部</button>
              <button class="btn danger" data-action="clear">清空</button>
              <button class="btn" data-action="close">关闭</button>
            </div>
          </div>
          <div class="body">
            <div class="section">
              <div class="row stats">
                <span class="count" data-role="total-count">0</span>
                <span class="count" data-role="visible-count">0</span>
                <span class="count" data-role="mode-label">单选</span>
                <span class="mode">
                  <button class="btn" data-action="toggle-mode">切换到多选</button>
                  <button class="btn" data-action="show-all">全部</button>
                </span>
              </div>
            </div>
            <div class="section">
              <div class="subtle">phase 筛选</div>
              <div class="row filters" data-role="phase-filters"></div>
            </div>
            <div class="list" data-role="list"></div>
          </div>
        </div>
        <button class="fab" data-action="toggle">提取链接</button>
      </div>
    `;

    document.documentElement.appendChild(host);

    const ui = {
      host,
      shadow,
      panel: shadow.querySelector('.panel'),
      list: shadow.querySelector('[data-role="list"]'),
      summary: shadow.querySelector('[data-role="summary"]'),
      totalCount: shadow.querySelector('[data-role="total-count"]'),
      visibleCount: shadow.querySelector('[data-role="visible-count"]'),
      modeLabel: shadow.querySelector('[data-role="mode-label"]'),
      phaseFilters: shadow.querySelector('[data-role="phase-filters"]'),
      toggleButton: shadow.querySelector('[data-action="toggle"]'),
      toggleModeButton: shadow.querySelector('[data-action="toggle-mode"]'),
      showAllButton: shadow.querySelector('[data-action="show-all"]'),
      copyAllButton: shadow.querySelector('[data-action="copy-all"]'),
      clearButton: shadow.querySelector('[data-action="clear"]'),
      closeButton: shadow.querySelector('[data-action="close"]'),
    };

    ui.toggleButton.addEventListener('click', togglePanel);
    ui.closeButton.addEventListener('click', () => setPanelVisible(false));
    ui.toggleModeButton.addEventListener('click', toggleMode);
    ui.showAllButton.addEventListener('click', clearPhaseSelection);
    ui.copyAllButton.addEventListener('click', async () => {
      const items = getFilteredItems();
      await copyText(items.map((item) => item.link).join('\n'));
      ui.copyAllButton.textContent = '已复制';
      setTimeout(() => {
        ui.copyAllButton.textContent = '复制全部';
      }, 1200);
    });
    ui.clearButton.addEventListener('click', () => {
      state.itemsByLink.clear();
      renderAll();
    });

    state.ui = ui;
    renderPhaseButtons();
    renderAll();
    return ui;
  }

  function setPanelVisible(visible) {
    const ui = buildUi();
    state.visible = Boolean(visible);
    ui.panel.classList.toggle('show', state.visible);
    if (state.visible) renderAll();
  }

  function togglePanel() {
    setPanelVisible(!state.visible);
  }

  function toggleMode() {
    state.filterMode = state.filterMode === 'single' ? 'multi' : 'single';
    if (state.filterMode === 'single' && state.selectedPhases.size > 1) {
      const first = [...state.selectedPhases][0] || 'PHASE_TYPE_RUNNING';
      state.selectedPhases = new Set([first]);
    }
    if (!state.selectedPhases.size) {
      state.selectedPhases = new Set(['PHASE_TYPE_RUNNING']);
    }
    renderPhaseButtons();
    renderAll();
  }

  function clearPhaseSelection() {
    state.selectedPhases.clear();
    renderPhaseButtons();
    renderAll();
  }

  function selectPhase(phase) {
    if (!phase) return;
    if (state.filterMode === 'single') {
      state.selectedPhases = new Set([phase]);
    } else {
      if (state.selectedPhases.has(phase)) {
        state.selectedPhases.delete(phase);
      } else {
        state.selectedPhases.add(phase);
      }
    }
    renderPhaseButtons();
    renderAll();
  }

  function renderPhaseButtons() {
    if (!state.ui) return;
    const container = state.ui.phaseFilters;
    const selected = state.selectedPhases;

    const phases = [...new Set([...KNOWN_PHASES, ...state.phaseOrder])];
    container.innerHTML = phases
      .map((phase) => {
        const active = selected.has(phase) ? 'active' : '';
        return `<button class="btn ${active}" data-phase="${escapeHtml(phase)}">${escapeHtml(phase)}</button>`;
      })
      .join('');

    container.querySelectorAll('[data-phase]').forEach((button) => {
      button.addEventListener('click', () => selectPhase(button.getAttribute('data-phase')));
    });

    state.ui.modeLabel.textContent = state.filterMode === 'single' ? '单选' : '多选';
    state.ui.toggleModeButton.textContent = state.filterMode === 'single' ? '切换到多选' : '切换到单选';
  }

  function renderAll() {
    if (!state.ui) buildUi();
    const ui = state.ui;
    const items = getFilteredItems();
    const total = state.itemsByLink.size;
    const selectedInfo = state.selectedPhases.size ? [...state.selectedPhases].join(', ') : '全部';

    ui.totalCount.textContent = `总计 ${total}`;
    ui.visibleCount.textContent = `显示 ${items.length}`;
    ui.summary.textContent = state.itemsByLink.size
      ? `已捕获 ${total} 条链接，当前筛选：${selectedInfo}`
      : '等待捕获 drive/v1/tasks 响应';

    if (!items.length) {
      ui.list.innerHTML = `<div class="empty">暂无匹配链接</div>`;
      return;
    }

    ui.list.innerHTML = items
      .map((item) => {
        const phases = [...item.phaseSet].filter(Boolean);
        const names = [...item.nameSet].slice(0, 2);
        const sources = [...item.sourceSet];
        return `
          <div class="item">
            <div class="link" title="${escapeHtml(item.link)}">${escapeHtml(item.link)}</div>
            <div class="meta">
              ${item.latestPhase ? `<span class="badge">${escapeHtml(item.latestPhase)}</span>` : ''}
              ${phases.length > 1 ? `<span class="badge">phases:${escapeHtml(phases.join('|'))}</span>` : ''}
              ${names.length ? `<span class="badge">${escapeHtml(names.join(' / '))}</span>` : ''}
              ${sources.length ? `<span class="badge">${escapeHtml(sources.join('|'))}</span>` : ''}
            </div>
          </div>
        `;
      })
      .join('');
  }

  function updateUi() {
    if (state.ui && state.visible) renderAll();
  }

  function init() {
    buildUi();
    patchFetch();
    patchXhr();
  }

  if (document.documentElement) {
    init();
  } else {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  }
})();

/* 漏扫控制台 · 前端逻辑（无框架、无构建步骤） */
(() => {
  const $ = (sel) => document.querySelector(sel);
  const state = {
    tab: 'findings',
    sev: '',
    status: '',
    q: '',
    offset: 0,
    limit: 100,
    total: 0,
    selected: new Set(),
    lastSummaryKey: '',
    autoRefresh: true,
    filesOnly: false,
    logDetail: false,
  };

  // ------------------------------------------------------------ 主题（默认白色，选择记在 localStorage）
  const THEME_KEY = 'vc-theme';
  function applyTheme(t) {
    const theme = t === 'dark' ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(THEME_KEY, theme); } catch (e) { /* 隐私模式下忽略 */ }
    const btn = $('#btnTheme');
    if (btn) btn.textContent = theme === 'dark' ? '☀︎ 白色' : '☾ 暗色';
  }

  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const fmtNum = (n) => (n == null ? '0' : String(n));

  function toast(msg, ms = 3200) {
    const el = $('#toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.remove('show'), ms);
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts || {}));
    const ct = res.headers.get('content-type') || '';
    if (!ct.includes('json')) {
      const text = await res.text();
      throw new Error(res.status + ' ' + text.slice(0, 160));
    }
    const data = await res.json();
    if (!res.ok || data.ok === false) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  }

  // ------------------------------------------------------------ 摘要 / 侧栏

  function summaryKey(s) {
    return [s.findings, s.hits, s.assets, s.files, JSON.stringify(s.severity), s.last_scan].join('|');
  }

  function renderSummary(s) {
    state.lastSummaryKey = summaryKey(s);
    const sevCards = ['critical', 'high', 'medium', 'low', 'info']
      .map((k) => `<div class="stat ${k}"><div class="lab">${k}</div><div class="val">${fmtNum(s.severity[k])}</div></div>`)
      .join('');
    $('#stats').innerHTML =
      `<div class="stat total"><div class="lab">条目 / 命中</div><div class="val">${fmtNum(s.findings)}<span class="muted" style="font-size:12px"> / ${fmtNum(s.hits)}</span></div></div>`
      + sevCards
      + `<div class="stat"><div class="lab">资产</div><div class="val">${fmtNum(s.assets)}</div></div>`;

    const all = ['critical', 'high', 'medium', 'low', 'info']
      .map((k) => `<button class="chip ${state.sev === k ? 'on' : ''}" data-sev="${k}">${k}<span class="n">${s.severity[k]}</span></button>`)
      .join('');
    $('#sevChips').innerHTML = `<button class="chip ${state.sev === '' ? 'on' : ''}" data-sev="">全部<span class="n">${s.findings}</span></button>` + all;

    $('#topAssets').innerHTML = (s.top_assets || []).length
      ? s.top_assets.map((a) => `<li class="clickable" data-asset="${esc(a.asset)}"><span class="k mono">${esc(a.asset || '(空)')}</span><span class="v">${a.n}</span></li>`).join('')
      : '<li class="muted">暂无</li>';

    $('#topTypes').innerHTML = (s.by_type || []).length
      ? s.by_type.map((t) => `<li class="clickable" data-q="${esc(t.title)}"><span class="k">${esc(t.title)}</span><span class="v">${t.n}</span></li>`).join('')
      : '<li class="muted">暂无</li>';

    $('#lastScan').textContent = s.last_scan ? ('最近整理 ' + s.last_scan) : '尚未整理';
    $('#tabN-findings').textContent = s.findings;
    $('#tabN-assets').textContent = s.assets;
    $('#tabN-files').textContent = s.files;
  }

  // ------------------------------------------------------------ 漏洞表

  function rowHtml(r) {
    const sel = state.selected.has(r.id) ? 'sel' : '';
    const ev = r.evidence ? `<div class="ev">${esc(r.evidence).slice(0, 220)}</div>` : '';
    const par = r.param ? `<div class="par">参数：${esc(r.param)}</div>` : '';
    // 没有资产/端点时（比如从审计报告 Markdown 提炼的条目），把来源文件名挂出来，别让人对着空列猜
    const fileBase = (r.files || '').split('/').pop();
    const srcHint = (!r.asset && fileBase) ? `<div class="src-hint" title="${esc(r.files)}">↳ ${esc(fileBase)}</div>` : '';
    const statusOpts = ['待验证', '已确认', '误报', '已修复', '已忽略']
      .map((s) => `<option ${s === r.status ? 'selected' : ''}>${s}</option>`).join('');
    return `<tr class="${sel}" data-id="${r.id}">
      <td><input type="checkbox" class="rowCheck" data-id="${r.id}" ${sel ? 'checked' : ''}></td>
      <td><span class="sev ${esc(r.sev)}">${esc(r.sev)}</span></td>
      <td><div class="title-cell">${esc(r.title)}</div>${ev}</td>
      <td class="mono">${r.asset ? esc(r.asset) : ''}${r.port ? `<div class="par">:${esc(r.port)}</div>` : ''}${srcHint || (r.asset ? '' : '<span class="muted">—</span>')}</td>
      <td><div class="ep">${esc(r.endpoint || '—')}</div>${par}</td>
      <td class="mono nowrap" style="text-align:right">${r.count}</td>
      <td class="mono">${esc(r.sources)}</td>
      <td><select class="status-select" data-id="${r.id}" data-s="${esc(r.status)}">${statusOpts}</select></td>
      <td class="mono muted nowrap">${esc((r.first_seen || '').slice(0, 16))}</td>
    </tr>`;
  }

  async function loadFindings() {
    const qs = new URLSearchParams({ limit: state.limit, offset: state.offset });
    if (state.sev) qs.set('sev', state.sev);
    if (state.status) qs.set('status', state.status);
    if (state.q) qs.set('q', state.q);
    const data = await api('/api/findings?' + qs.toString());
    state.total = data.total;
    const rows = data.rows || [];
    $('#findingsBody').innerHTML = rows.length
      ? rows.map(rowHtml).join('')
      : `<tr><td colspan="9" class="muted center">没有匹配记录${state.q || state.sev || state.status ? '（试试清空筛选）' : ''}</td></tr>`;
    const from = state.total === 0 ? 0 : state.offset + 1;
    $('#pageInfo').textContent = `${from}–${Math.min(state.offset + rows.length, state.total)} / 共 ${state.total}`;
    $('#prevPage').disabled = state.offset <= 0;
    $('#nextPage').disabled = state.offset + state.limit >= state.total;
    renderSelInfo();
  }

  function renderSelInfo() {
    const n = state.selected.size;
    $('#selInfo').textContent = n ? `已选 ${n} 条` : '未选中';
    const all = document.querySelectorAll('.rowCheck');
    const checkAll = $('#checkAll');
    if (checkAll) checkAll.checked = n > 0 && Array.from(all).every((c) => c.checked);
  }

  // ------------------------------------------------------------ 资产 / 文件 / 日志

  async function loadAssets() {
    const qs = new URLSearchParams({ limit: 300 });
    if (state.q) qs.set('q', state.q);
    const data = await api('/api/assets?' + qs.toString());
    const rows = data.rows || [];
    $('#assetsBody').innerHTML = rows.length ? rows.map((a) => {
      const ports = (a.ports || []).map((p) => `${esc(p.port)}/${esc(p.proto || 'tcp')}${p.service ? ' · ' + esc(p.service) : ''}`).join('<br>');
      return `<tr>
        <td class="mono">${esc(a.host)}</td>
        <td class="mono muted">${esc(a.ip || '—')}</td>
        <td class="ep">${ports || '<span class="muted">—</span>'}</td>
        <td>${esc(a.title || '—')}</td>
        <td class="mono">${esc(a.sources)}</td>
        <td class="mono muted nowrap">${esc((a.last_seen || '').slice(0, 16))}</td>
      </tr>`;
    }).join('') : '<tr><td colspan="6" class="muted center">还没有资产记录（收件箱里没有端口扫描类产物？）</td></tr>';
  }

  async function loadFiles() {
    const data = await api('/api/files' + (state.filesOnly ? '?only=1' : ''));
    const rows = data.rows || [];
    $('#inboxList').innerHTML = (data.inboxes || []).map((p) => `<li title="${esc(p)}"><span class="k">${esc(p.replace(/^.*\//, ''))}</span><span class="v">dir</span></li>`).join('');
    $('#filesCount').textContent = `${rows.length} 个文件${state.filesOnly ? '（有产出）' : ''}`;
    $('#filesOnly').classList.toggle('on', !!state.filesOnly);
    $('#filesBody').innerHTML = rows.length ? rows.map((f) => `<tr>
      <td class="ep">${esc(f.path.replace(/^.*\/(pentest|pentest-assets|pentest-inbox)\//, '$1/'))}</td>
      <td class="mono">${esc(f.fmt)}</td>
      <td class="mono" style="text-align:right">${f.findings || 0}</td>
      <td class="mono" style="text-align:right">${f.assets || 0}</td>
      <td class="muted">${esc(f.note || '')}</td>
      <td class="mono muted nowrap">${esc((f.scanned_at || '').slice(0, 16))}</td>
    </tr>`).join('') : '<tr><td colspan="6" class="muted center">还没有摄入记录</td></tr>';
  }

  async function loadLog() {
    const data = await api('/api/log?limit=300' + (state.logDetail ? '&detail=1' : ''));
    const rows = data.rows || [];
    $('#logCount').textContent = `${rows.length} 行${state.logDetail ? '（含明细）' : ''}`;
    $('#logDetail').classList.toggle('on', !!state.logDetail);
    $('#logBody').innerHTML = rows.map((r) => {
      const cls = r.level === 'error' ? 'e' : r.level === 'warn' ? 'w' : r.level === 'detail' ? 'd' : 'i';
      return `<span class="t">${esc(r.ts)}</span> <span class="${cls}">${esc(r.level)}</span>  ${esc(r.msg)}`;
    }).join('\n') || '暂无日志';
    const pre = $('#logBody');
    pre.scrollTop = pre.scrollHeight;
  }

  // ------------------------------------------------------------ 刷新编排

  async function refreshAll(reason) {
    const s = await api('/api/summary');
    renderSummary(s);
    if (state.tab === 'findings') await loadFindings();
    if (state.tab === 'assets') await loadAssets();
    if (state.tab === 'files') await loadFiles();
    if (state.tab === 'log') await loadLog();
    if (reason) toast(reason);
  }

  async function rescan(force) {
    const btn = force ? $('#btnForce') : $('#btnRescan');
    const old = btn.textContent;
    btn.disabled = true;
    btn.textContent = force ? '重解析中…' : '整理中…';
    try {
      const data = await api('/api/rescan', { method: 'POST', body: JSON.stringify({ force: !!force }) });
      const st = data.stats || {};
      if (st.busy) { toast('已有一轮整理在进行中，稍等'); return; }
      const msg = `整理完成：解析 ${st.parsed} 个文件，新增 ${st.findings_added} 条 / 合并 ${st.findings_merged} 条，`
        + `资产 ${st.assets}，跳过 ${st.skipped}，未变 ${st.unchanged}，失败 ${st.errors}，耗时 ${st.elapsed}s`;
      state.offset = 0;
      state.selected.clear();
      await refreshAll(msg);
      if (st.errors) await loadLog();
    } catch (err) {
      toast('整理失败：' + err.message, 6000);
    } finally {
      btn.disabled = false;
      btn.textContent = old;
    }
  }

  // ------------------------------------------------------------ 事件

  function bind() {
    document.addEventListener('click', async (e) => {
      const chip = e.target.closest('.chip');
      if (chip) {
        state.sev = chip.dataset.sev || '';
        state.offset = 0;
        document.querySelectorAll('.chip').forEach((c) => c.classList.toggle('on', c === chip));
        await loadFindings();
        return;
      }
      const assetLi = e.target.closest('#topAssets li[data-asset]');
      if (assetLi) { state.q = assetLi.dataset.asset; $('#search').value = state.q; state.offset = 0; await loadFindings(); return; }
      const typeLi = e.target.closest('#topTypes li[data-q]');
      if (typeLi) { state.q = typeLi.dataset.q; $('#search').value = state.q; state.offset = 0; await loadFindings(); return; }

      const tab = e.target.closest('.tab');
      if (tab) {
        state.tab = tab.dataset.tab;
        document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
        ['findings', 'assets', 'files', 'log'].forEach((k) => {
          $('#view-' + k).classList.toggle('hidden', k !== state.tab);
        });
        await refreshAll('');
        return;
      }
    });

    document.addEventListener('change', async (e) => {
      const sel = e.target.closest('.status-select');
      if (sel) {
        try {
          await api('/api/status', { method: 'POST', body: JSON.stringify({ ids: [Number(sel.dataset.id)], status: sel.value }) });
          sel.dataset.s = sel.value;
          toast('已标记为「' + sel.value + '」');
          await refreshAll('');
        } catch (err) { toast('改状态失败：' + err.message, 5000); }
        return;
      }
      const check = e.target.closest('.rowCheck');
      if (check) {
        const id = Number(check.dataset.id);
        if (check.checked) state.selected.add(id); else state.selected.delete(id);
        check.closest('tr').classList.toggle('sel', check.checked);
        renderSelInfo();
        return;
      }
      if (e.target.id === 'checkAll') {
        const on = e.target.checked;
        document.querySelectorAll('.rowCheck').forEach((c) => {
          c.checked = on;
          const id = Number(c.dataset.id);
          if (on) state.selected.add(id); else state.selected.delete(id);
          c.closest('tr').classList.toggle('sel', on);
        });
        renderSelInfo();
        return;
      }
      if (e.target.id === 'statusFilter') { state.status = e.target.value; state.offset = 0; await loadFindings(); return; }
      if (e.target.id === 'bulkStatus') {
        const status = e.target.value;
        if (!status) return;
        if (!state.selected.size) { toast('先勾选几行再批量改状态'); e.target.value = ''; return; }
        try {
          const r = await api('/api/status', { method: 'POST', body: JSON.stringify({ ids: Array.from(state.selected), status }) });
          toast(`已把 ${r.updated} 条改成「${status}」`);
          state.selected.clear();
          e.target.value = '';
          await refreshAll('');
        } catch (err) { toast('批量改状态失败：' + err.message, 5000); }
        return;
      }
      if (e.target.id === 'autoRefresh') { state.autoRefresh = e.target.checked; return; }
    });

    let timer = null;
    $('#search').addEventListener('input', (e) => {
      clearTimeout(timer);
      const v = e.target.value.trim();
      timer = setTimeout(async () => {
        state.q = v;
        state.offset = 0;
        if (state.tab === 'findings') await loadFindings();
        else if (state.tab === 'assets') await loadAssets();
      }, 260);
    });

    $('#btnRescan').addEventListener('click', () => rescan(false));
    $('#btnForce').addEventListener('click', () => rescan(true));
    $('#filesOnly').addEventListener('click', async () => {
      state.filesOnly = !state.filesOnly;
      await loadFiles();
    });
    $('#logDetail').addEventListener('click', async () => {
      state.logDetail = !state.logDetail;
      await loadLog();
    });
    const exportFiltered = (e) => {
      e.preventDefault();
      const fmt = e.currentTarget.id === 'expMD' ? 'md' : 'csv';
      const qs = new URLSearchParams();
      if (state.sev) qs.set('sev', state.sev);
      if (state.status) qs.set('status', state.status);
      if (state.q) qs.set('q', state.q);
      const url = '/api/export?fmt=' + fmt + (qs.toString() ? '&' + qs : '');
      window.location.href = url;
      toast('已导出' + (qs.toString() ? '（当前筛选）' : '（全部）') + ' ' + fmt.toUpperCase());
    };
    $('#expCSV').addEventListener('click', exportFiltered);
    $('#expMD').addEventListener('click', exportFiltered);
    $('#btnTheme').addEventListener('click', () => {
      applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    });
    $('#prevPage').addEventListener('click', async () => {
      state.offset = Math.max(0, state.offset - state.limit);
      await loadFindings();
    });
    $('#nextPage').addEventListener('click', async () => {
      state.offset += state.limit;
      await loadFindings();
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'SELECT') {
        e.preventDefault();
        $('#search').focus();
      }
    });

    // 轮询：数据变了才重绘（不打断正在滚动的浏览）
    setInterval(async () => {
      if (!state.autoRefresh) return;
      try {
        const s = await api('/api/summary');
        if (summaryKey(s) === state.lastSummaryKey) return;
        renderSummary(s);
        if (state.tab === 'findings') await loadFindings();
        if (state.tab === 'assets') await loadAssets();
        if (state.tab === 'files') await loadFiles();
        toast('检测到新数据，已自动刷新');
      } catch (_) { /* 静默：下一轮再试 */ }
    }, 4000);
  }

  async function boot() {
    try { applyTheme(localStorage.getItem(THEME_KEY) || 'light'); } catch (e) { applyTheme('light'); }
    bind();
    try {
      await rescan(false); // 打开即自动整理
    } catch (err) {
      toast('初始整理失败：' + err.message, 6000);
      await refreshAll('');
    }
  }

  boot();
})();

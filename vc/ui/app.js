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

  // 扫描页的状态（和列表页互不影响）
  const SCAN_MODE_KEY = 'vc-scan-mode';
  const scan = {
    meta: null,
    mode: 'all',
    sel: 0,
    logNext: 0,
    active: 0,
    wasActive: 0,
    timer: null,
    liveKey: '',
    jobsKey: '',
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


  const SEV_ICON = {
    high: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.6l8.8 15.6H3.2L12 3.6z"/><path d="M12 10v4.3M12 17.1h.01"/></svg>',
    medium: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.6l8.8 15.6H3.2L12 3.6z"/><path d="M12 10v4.3M12 17.1h.01"/></svg>',
    lowinfo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"><circle cx="12" cy="12" r="8"/><path d="M12 16.2v-4.6M12 8.5h.01"/></svg>',
    todo: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8.2"/><path d="M12 7.5V12l3 1.8"/></svg>',
    done: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="8.2"/><path d="M8.4 12.2l2.4 2.4 4.8-4.9"/></svg>',
  };

  const sevSum = (sev, keys) => keys.reduce((a, k) => a + (Number(sev[k]) || 0), 0);

  function statusN(s, want) {
    const row = (s.by_status || []).find((x) => x.status === want);
    return row ? (Number(row.n) || 0) : 0;
  }

  // 每个视图自己的标题（面包屑 + 页面标题跟着导航走，不然切到资产页还写着「漏洞管理」）
  const VIEW_META = {
    findings: ['漏洞管理', '/VULN', '查看和管理所有扫描发现的漏洞'],
    assets: ['资产管理', '/ASSET', '主机、端口与服务指纹，按风险排序'],
    scan: ['扫描任务', '/SCAN', '起本机引擎跑任务，产物自动落进收件箱'],
    files: ['收件箱', '/INBOX', '扫描产物文件与解析状态'],
    log: ['摄入日志', '/LOG', '每轮整理的逐文件明细'],
  };

  function syncViewMeta() {
    const root = $('#pageRoot');
    if (root) root.dataset.view = state.tab || 'findings';
    const m = VIEW_META[state.tab] || VIEW_META.findings;
    const t = $('#pageTitle'), c = $('#pageCode'), d = $('#pageDesc'), cr = $('#crumbNow');
    if (t) t.textContent = '漏扫控制台';
    if (c) c.textContent = m[1];
    if (d) d.textContent = m[0] + ' · ' + m[2];
    if (cr) cr.textContent = m[0];
    document.title = '漏扫控制台 · Vuln Console';
  }

  // 状态分段与筛选下拉必须同源，否则会出现「上面写着待审查、下拉却是全部」的自相矛盾
  function syncStatusTabs() {
    const box = $('#statusTabs');
    if (box) {
      box.querySelectorAll('.tab2').forEach((b) => b.classList.toggle('on', (b.dataset.st || '') === (state.status || '')));
    }
    const sf = $('#statusFilter');
    if (sf && sf.value !== (state.status || '')) sf.value = state.status || '';
  }

  function renderSummary(s) {
    state.lastSummaryKey = summaryKey(s);
    const sv = s.severity || {};
    const setN = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = fmtNum(v); };

    const lowInfo = sevSum(sv, ['low', 'info']);
    const todo = statusN(s, '待验证');
    const done = statusN(s, '已确认');

    // 六联统计条：第一格「严重」用红点 + 特大数字 + 标签横排，其余五格统一「图标+标题 / 数字 / ● 说明」
    const cards = [
      { k: 'critical', label: '严重', n: sv.critical, hint: '需要立即处理' },
      { k: 'high', label: '高危', n: sv.high, hint: '优先排查修复' },
      { k: 'medium', label: '中危', n: sv.medium, hint: '纳入修复计划' },
      { k: 'lowinfo', label: '低危/信息', n: lowInfo, hint: '持续跟踪确认' },
      { k: 'todo', label: '待审查', n: todo, hint: '等待人工确认' },
      { k: 'done', label: '已审查', n: done, hint: '已完成确认' },
    ];

    $('#stats').innerHTML = cards.map((c, i) => {
      if (i === 0) {
        return `<div class="six ${c.k} first">
          <div class="row"><span class="blob"></span><span class="val">${fmtNum(c.n)}</span><span class="nm">${c.label}</span></div>
          <div class="ft">${c.hint}</div>
        </div>`;
      }
      const ico = SEV_ICON[c.k];
      return `<div class="six ${c.k}">
        <div class="hd">${ico ? `<span class="ico">${ico}</span>` : ''}${c.label}</div>
        <div class="val">${fmtNum(c.n)}</div>
        <div class="ft">${c.hint}</div>
      </div>`;
    }).join('');

    // 严重度 chips（收在筛选面板里，中文标签 + 计数）
    const chips = ['critical', 'high', 'medium', 'low', 'info']
      .map((k) => `<button class="chip ${state.sev === k ? 'on' : ''}" data-sev="${k}">${SEV_CN[k]}<span class="n">${fmtNum(sv[k])}</span></button>`)
      .join('');
    $('#sevChips').innerHTML =
      `<button class="chip ${state.sev === '' ? 'on' : ''}" data-sev="">全部<span class="n">${fmtNum(s.findings)}</span></button>` + chips;

    $('#topAssets').innerHTML = (s.top_assets || []).length
      ? s.top_assets.map((a) => `<li class="clickable" data-asset="${esc(a.asset)}"><span class="k mono">${esc(a.asset || '(空)')}</span><span class="v">${a.n}</span></li>`).join('')
      : '<li class="muted">暂无</li>';

    $('#topTypes').innerHTML = (s.by_type || []).length
      ? s.by_type.map((t) => `<li class="clickable" data-q="${esc(t.title)}"><span class="k">${esc(t.title)}</span><span class="v">${t.n}</span></li>`).join('')
      : '<li class="muted">暂无</li>';

    // 分段计数 + 顶栏元信息
    setN('nAll', s.findings);
    setN('nTodo', todo);
    setN('nDone', done);

    const meta = $('#topMeta');
    if (meta) {
      meta.textContent = `${fmtNum(s.findings)} 条漏洞 · ${fmtNum(s.hits)} 次命中 · ${fmtNum(s.assets)} 个资产 · ${fmtNum(s.files)} 个文件`;
    }

    const ls = $('#lastScan');
    if (ls) { const txt = s.last_scan ? ('最近整理 ' + s.last_scan) : '尚未整理'; ls.textContent = txt; ls.title = txt; }

    setN('tabN-findings', s.findings);
    setN('tabN-assets', s.assets);
    setN('tabN-files', s.files);
  }

  // ------------------------------------------------------------ 漏洞表

  function rowHtml(r) {
    const sel = state.selected.has(r.id) ? 'sel' : '';
    const evText = r.evidence ? String(r.evidence).slice(0, 260) : '';
    const evTitle = evText ? `<div class="ev" title="${esc(evText)}">${esc(evText)}</div>` : '';
    const par = r.param ? `<div class="par">参数：${esc(r.param)}</div>` : '';
    // 没有资产/端点时（比如从审计报告 Markdown 提炼的条目），把来源文件名挂出来，别让人对着空列猜
    const fileBase = (r.files || '').split('/').pop();
    const srcHint = (!r.asset && fileBase) ? `<div class="src-hint" title="${esc(r.files)}">↳ ${esc(fileBase)}</div>` : '';
    const statusOpts = ['待验证', '已确认', '误报', '已修复', '已忽略']
      .map((x) => `<option ${x === r.status ? 'selected' : ''}>${x}</option>`).join('');

    const sevCn = SEV_CN[r.sev] || r.sev || '—';

    // URL 列：有资产就拼成 http(s)://host:port/端点（跟天穹那个 URL 列一个意思），没资产就退回端点原文
    let url = '';
    if (r.asset) {
      const ep = String(r.endpoint || '');
      url = /^https?:\/\//i.test(ep)
        ? ep
        : 'https://' + r.asset + (r.port ? ':' + r.port : '') + (ep ? '/' + ep.replace(/^\/+/, '') : '');
    } else {
      url = String(r.endpoint || '');
    }

    return `<tr class="${sel}" data-id="${r.id}">
      <td class="w-check"><input type="checkbox" class="rowCheck" data-id="${r.id}" ${sel ? 'checked' : ''}></td>
      <td><select class="status-select" data-id="${r.id}" data-s="${esc(r.status)}">${statusOpts}</select></td>
      <td><span class="sev ${esc(r.sev)}">${esc(sevCn)}</span></td>
      <td class="mono src-cell">${esc(r.sources)}</td>
      <td><div class="title-cell" title="${esc(r.title)}">${esc(r.title)}</div>${evTitle}</td>
      <td class="asset-cell">${r.asset ? esc(r.asset) : (srcHint ? '' : '<span class="muted">—</span>')}${r.port ? `<div class="par">:${esc(r.port)}</div>` : ''}${srcHint}</td>
      <td class="w-url">${url ? `<div class="ep" title="${esc(url)}">${esc(url)}</div>` : '<span class="muted">—</span>'}${par}</td>
      <td class="mono nowrap" style="text-align:right">${r.count}</td>
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
    // 整列都是「—」的表格纯粹是噪声：这一页数据没有资产/端点时，直接把 URL 列收起来
    const anyUrl = rows.some((r) => r.asset || r.endpoint || r.param);
    const tbl = document.querySelector('#view-findings table');
    if (tbl) tbl.classList.toggle('hide-url', !anyUrl);
    $('#findingsBody').innerHTML = rows.length
      ? rows.map(rowHtml).join('')
      : `<tr><td colspan="${anyUrl ? 9 : 8}" class="muted center">没有匹配记录${state.q || state.sev || state.status ? '（试试清空筛选）' : ''}</td></tr>`;
    const from = state.total === 0 ? 0 : state.offset + 1;
    $('#pageInfo').textContent = `${from}–${Math.min(state.offset + rows.length, state.total)} / 共 ${state.total}`;
    $('#prevPage').disabled = state.offset <= 0;
    $('#nextPage').disabled = state.offset + state.limit >= state.total;
    renderSelInfo();
  }

  function renderSelInfo() {
    const n = state.selected.size;
    const total = Number(state.total) || 0;
    // 天穹式底部计数：「已选择 N 项 / 共 M 条」
    const fc = $('#footCount');
    if (fc) fc.textContent = `已选择 ${n} 项 / 共 ${total} 条`;
    const si = $('#selInfo');
    if (si) si.textContent = n ? `已选择 ${n} 项` : '未选中';
    const all = document.querySelectorAll('.rowCheck');
    const checkAll = $('#checkAll');
    if (checkAll) checkAll.checked = n > 0 && all.length > 0 && Array.from(all).every((c) => c.checked);
  }

  // ------------------------------------------------------------ 资产 / 文件 / 日志

  // 资产视图：卡片网格（表格读不出"这台机器长什么样"，卡片能）

  const ASSET_SORT_KEY = 'vc-asset-sort';
  const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const SEV_VAR = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', info: 'var(--info)' };
  const assetView = {
    sort: (() => { try { return localStorage.getItem(ASSET_SORT_KEY) || 'risk'; } catch (e) { return 'risk'; } })(),
    onlyRisk: false,
  };

  // 服务 → 圆点颜色（按"这东西一般多危险"分档，纯提示不是判定）
  function dotFor(svc) {
    const s = String(svc || '').toLowerCase();
    if (/^(mysql|mssql|oracle|postgres|redis|mongo|memcache|elastic|db)/.test(s)) return 'var(--low)';
    if (/^(smb|netbios|ldap|rsync|nfs)/.test(s)) return 'var(--crit)';
    if (/^(ssh|rdp|telnet|vnc|winrm)/.test(s)) return 'var(--med)';
    if (/(http|nginx|apache|tomcat|iis|web)/.test(s)) return 'var(--accent)';
    if (/^(ftp|mail|smtp|imap|pop)/.test(s)) return 'var(--info)';
    return 'var(--faint)';
  }

  function ago(ts) {
    if (!ts) return '—';
    const t = Date.parse(String(ts).replace(' ', 'T'));
    if (!t) return String(ts).slice(0, 16);
    const mins = Math.floor((Date.now() - t) / 60000);
    if (mins < 1) return '刚刚';
    if (mins < 60) return mins + ' 分钟前';
    if (mins < 1440) return Math.floor(mins / 60) + ' 小时前';
    if (mins < 43200) return Math.floor(mins / 1440) + ' 天前';
    return String(ts).slice(0, 10);
  }

  const SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
  // 长服务名（TLS 证书 CN 抓下来的随机串）必须截断，否则撑破 pill 和卡片
  function svcShort(s, n = 16) {
    s = String(s || '');
    return s.length > n ? s.slice(0, n) + '…' : s;
  }

  function assetCard(a) {
    const ports = a.ports || [];
    const mix = a.sev_mix || {};
    const top = a.top_sev || '';
    const badge = top
      ? `<span class="sev ${esc(top)}" title="${esc(SEV_CN[top] || top)}${a.n_find ? ' · ' + a.n_find + ' 条漏洞' : ''}">${esc(SEV_CN[top] || top)}${a.n_find > 1 ? ' ×' + a.n_find : ''}</span>`
      : '';
    const svcLine = String(a.services || '').split(',').filter(Boolean).slice(0, 3)
      .map((s) => s.split('/').filter((x) => x && x !== 'conn_keepalive' && x !== 'tcp').pop() || s).join(' · ');
    const maxChips = 5;
    const chips = ports.slice(0, maxChips).map((p) => {
      const svc = String(p.service || p.proto || '').split('/').filter((x) => x && x !== 'conn_keepalive').pop() || '';
      const tip = [a.host + ':' + p.port, p.proto, p.service, p.title].filter(Boolean).join(' · ');
      return `<span class="pchip" style="--dot:${dotFor(svc)}" title="${esc(tip)}"><i></i>${esc(p.port)}${svc && svc !== 'tcp' ? ' · ' + esc(svcShort(svc)) : ''}</span>`;
    }).join('');
    const more = ports.length > maxChips ? `<span class="pchip more">+${ports.length - maxChips}</span>` : '';
    const bar = ['critical', 'high', 'medium', 'low', 'info'].filter((k) => mix[k])
      .map((k) => `<span style="flex:${mix[k]};background:${SEV_VAR[k]}" title="${esc(SEV_CN[k] || k)} ${mix[k]} 条"></span>`).join('');
    // pill 已经把每个端口的服务显示出来了，sub 再列一遍服务名纯属重复；
    // 只有在没有端口信息时，才拿 services 兜底
    const sub = [];
    if (a.ip && a.ip !== a.host) sub.push(esc(a.ip));
    if (!ports.length && svcLine) sub.push(esc(svcLine));
    // 标题：扫描器的 title 常是「A|B|A」这种拼接，去重压成一行；没有 title 就用最高等级那条漏洞名
    const rawTitle = String(a.title || '').split('|').map((s) => s.trim()).filter(Boolean);
    const uniqTitle = [...new Set(rawTitle)].slice(0, 2).join(' · ');
    const shownTitle = uniqTitle || String(a.hint || '').trim();
    const title = shownTitle
      ? `<div class="acard-title${uniqTitle ? '' : ' hint'}" title="${esc(shownTitle)}">${uniqTitle ? '' : '<span class="hint-tag">最高</span>'}${esc(shownTitle)}</div>`
      : '';
    return `<div class="acard" role="button" tabindex="0" data-asset="${esc(a.host)}"
        style="--sev:${top ? SEV_VAR[top] : 'var(--line-strong)'}"
        aria-label="${esc(a.host)}：${a.n_find || 0} 条漏洞，${ports.length} 个端口">
      <div class="acard-top">
        <div class="acard-host" title="${esc(a.host)}">${esc(a.host)}</div>
        ${badge}
      </div>
      ${sub.length ? `<div class="acard-sub" title="${sub.join(' · ')}">${sub.join('<span class="sep" aria-hidden="true">·</span>')}</div>` : ''}
      ${title}
      ${ports.length ? `<div class="pchips">${chips}${more}</div>` : '<div class="acard-nop">没有端口信息</div>'}
      ${bar ? `<div class="mixbar">${bar}</div>` : ''}
      <div class="acard-foot">
        <span class="n">${a.n_find ? a.n_find + ' 条漏洞' : '暂无漏洞'}</span>
        <span class="sep" aria-hidden="true">·</span><span class="mono">${esc(a.sources || '—')}</span>
        <span class="grow"></span>
        <span class="mono" title="${esc(a.last_seen || '')}">${esc(ago(a.last_seen))}</span>
        <span class="go" aria-hidden="true">›</span>
      </div>
    </div>`;
  }

  function sortAssets(rows) {
    const by = assetView.sort;
    return rows.slice().sort((x, y) => {
      if (by === 'ports') return (y.ports || []).length - (x.ports || []).length || String(x.host).localeCompare(String(y.host));
      if (by === 'recent') return String(y.last_seen || '').localeCompare(String(x.last_seen || ''));
      const r = (SEV_RANK[y.top_sev] || 0) - (SEV_RANK[x.top_sev] || 0);
      return r || (y.n_find || 0) - (x.n_find || 0)
        || (y.ports || []).length - (x.ports || []).length || String(x.host).localeCompare(String(y.host));
    });
  }

  async function loadAssets() {
    const qs = new URLSearchParams({ limit: 300 });
    if (state.q) qs.set('q', state.q);
    const data = await api('/api/assets?' + qs.toString());
    let rows = data.rows || [];
    if (assetView.onlyRisk) rows = rows.filter((a) => (a.n_find || 0) > 0);
    rows = sortAssets(rows);
    $('#assetCount').textContent = `${rows.length} / ${data.total || rows.length} 个资产`
      + (assetView.onlyRisk ? '（有漏洞）' : '');
    $('#assetOnlyRisk').classList.toggle('on', assetView.onlyRisk);
    $('#assetSort').querySelectorAll('.segbtn')
      .forEach((b) => b.classList.toggle('on', b.dataset.sort === assetView.sort));
    $('#assetsGrid').innerHTML = rows.length
      ? rows.map(assetCard).join('')
      : `<div class="muted center asset-empty">还没有资产记录${state.q ? '（当前搜索词下）' : '——收件箱里没有端口扫描类产物？'}</div>`;
  }

  async function loadFiles() {
    const data = await api('/api/files' + (state.filesOnly ? '?only=1' : ''));
    const rows = data.rows || [];
    $('#inboxList').innerHTML = (data.inboxes || []).map((p) => `<li title="${esc(p)}"><span class="k">${esc(p.replace(/^.*\//, ''))}</span><span class="v">dir</span></li>`).join('');
    $('#filesCount').textContent = `${rows.length} 个文件${state.filesOnly ? '（有产出）' : ''}`;
    $('#filesOnly').classList.toggle('on', !!state.filesOnly);
    $('#filesBody').innerHTML = rows.length ? rows.map((f) => `<tr>
      <td class="ep" title="${esc(f.path)}">${esc(f.path.replace(/^.*\/(pentest|pentest-assets|pentest-inbox)\//, '$1/'))}</td>
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

  // ------------------------------------------------------------ 扫描控制

  const SCAN_LABEL = {
    queued: '排队中', running: '运行中', stopping: '停止中', ok: '已完成',
    partial: '部分完成', failed: '失败', stopped: '已停止', interrupted: '已中断',
  };
  const scanStatus = (s) => SCAN_LABEL[s] || s || '未知';

  function fmtDur(sec) {
    const s = Math.max(0, Math.round(Number(sec) || 0));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm' + String(s % 60).padStart(2, '0') + 's';
    return Math.floor(s / 3600) + 'h' + String(Math.floor((s % 3600) / 60)).padStart(2, '0') + 'm';
  }

  function fmtClock(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    const p = (n) => String(n).padStart(2, '0');
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  }

  function targetList() {
    const box = $('#scanTargets');
    return box ? box.value.split('\n').map((s) => s.trim()).filter(Boolean) : [];
  }

  function countTargets() {
    const n = targetList().length;
    const el = $('#tgtCount');
    if (el) el.textContent = n + ' 个';
  }

  function renderModes() {
    const box = $('#scanModes');
    if (!box) return;
    const modes = (scan.meta && scan.meta.modes) || [];
    if (!modes.length) {
      box.innerHTML = '<span class="muted mono" style="grid-column:1/-1">拿不到模式表</span>';
      return;
    }
    if (!modes.some((m) => m.id === scan.mode)) scan.mode = modes[0].id;
    box.innerHTML = modes.map((m) => `
      <button type="button" class="modebtn ${m.id === scan.mode ? 'on' : ''}" data-mode="${esc(m.id)}"
              title="${esc(m.hint || '')}">
        <span>${esc(m.label)}</span><span class="mh">${esc(m.hint || m.kind)}</span>
      </button>`).join('');
  }

  async function loadScanMeta() {
    const bar = $('#scanEngine');
    try {
      const m = await api('/api/scan/meta');
      scan.meta = m;
      const eng = m.engine || {};
      bar.classList.toggle('bad', !eng.ok);
      bar.innerHTML = eng.ok
        ? `<span class="pip"></span><span>引擎就绪 <code>${esc(eng.path)}</code></span>`
        : `<span class="pip"></span><span>没找到扫描引擎</span><div class="hintline">${esc(eng.hint || '')}</div>`;
      const d = m.defaults || {};
      const lim = m.limits || {};
      if (d.parallel) $('#scanParallel').value = d.parallel;
      if (d.timeout) $('#scanTimeout').value = d.timeout;
      if (lim.max_parallel) $('#scanParallel').max = lim.max_parallel;
      renderModes();
      countTargets();
    } catch (err) {
      bar.classList.add('bad');
      bar.innerHTML = `<span class="pip"></span><span>扫描接口不可用：${esc(err.message)}</span>`;
    }
  }

  function jobRow(j) {
    const c = j.counts || {};
    const meta = `${c.ok || 0}/${c.total || 0} 目标 · ${j.findings || 0} 命中 · ${fmtDur(j.elapsed)}`;
    return `<div class="job ${j.id === scan.sel ? 'on' : ''}" data-job="${j.id}" role="button" tabindex="0"
                 title="${esc((j.targets || []).slice(0, 6).join('  '))}">
      <span class="jid">#${j.id}</span>
      <span class="jmode">${esc(j.mode_label || j.mode)}</span>
      <span class="jstat ${esc(j.status)}">${esc(scanStatus(j.status))}</span>
      <span class="jmeta">${esc(meta)}</span>
      <span class="jt">${esc(fmtClock(j.created))}</span>
    </div>`;
  }

  function jobsKeyOf(rows) {
    return rows.map((j) => `${j.id}:${j.status}:${(j.counts || {}).ok}:${j.findings}`).join('|');
  }

  async function loadScanJobs() {
    const data = await api('/api/scan/jobs?limit=12');
    const rows = data.rows || [];
    scan.active = Number(data.active || 0);
    const badge = $('#tabN-scan');
    if (badge) badge.textContent = scan.active ? String(scan.active) : '';

    const box = $('#scanJobs');
    const key = jobsKeyOf(rows);
    if (key !== scan.jobsKey) {
      scan.jobsKey = key;
      box.innerHTML = rows.length
        ? rows.map(jobRow).join('')
        : '<div class="jobs-empty">还没有扫描任务</div>';
    }
    // 跑完那一刻把漏洞列表也刷一遍，别让新结果躺在收件箱里等
    const justFinished = scan.active === 0 && scan.wasActive > 0;
    scan.wasActive = scan.active;
    if (justFinished) await refreshAll('扫描结束，结果已入账');
    return rows;
  }

  function donePct(j) {
    const c = j.counts || {};
    const total = Number(c.total) || 0;
    if (!total) return j.status === 'ok' ? 100 : 0;
    const done = (c.ok || 0) + (c.failed || 0) + (c.stopped || 0) + (c.timeout || 0) + (c.interrupted || 0);
    return Math.round((done / total) * 100);
  }

  function stepsHtml(run) {
    const steps = run.steps || [];
    const expect = Math.max(Number(run.expect) || 0, steps.length);
    let out = '';
    for (let i = 0; i < Math.min(expect, 14); i += 1) {
      const s = steps[i];
      const cls = s ? (s.status === 'done' || s.status === 'skipped' ? 'done'
        : (s.status === 'failed' ? 'failed' : 'run')) : '';
      out += `<span class="step ${cls}" title="${esc(s ? (s.name + ' · ' + scanStatus(s.status)) : '待执行')}"></span>`;
    }
    return `<span class="steps">${out}</span>`;
  }

  function trowHtml(run) {
    const st = run.status || 'queued';
    const pct = Number(run.pct) || 0;
    const tail = run.error
      ? `失败：${run.error}`
      : (st === 'running' ? (run.step ? '正在跑 ' + run.step : '启动中…') : `${pct}% · 退出码 ${run.exit_code == null ? '—' : run.exit_code}`);
    return `<div class="trow ${esc(st)}">
      <div class="tname">${esc(run.target)}
        <span class="sub2">${esc(tail)}</span>
      </div>
      ${stepsHtml(run)}
      <span class="tpct">${pct}%</span>
    </div>`;
  }

  function appendScanLog(lines) {
    const el = $('#scanLog');
    if (!el || !lines || !lines.length) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
    const frag = document.createDocumentFragment();
    lines.forEach((ln) => {
      const d = document.createElement('div');
      d.className = /失败|错误|error|panic|timeout|超时/i.test(ln) ? 'err' : '';
      d.textContent = ln;
      frag.appendChild(d);
    });
    el.appendChild(frag);
    while (el.childElementCount > 600) el.removeChild(el.firstChild);
    if (atBottom) el.scrollTop = el.scrollHeight;
    const n = $('#scanLogN');
    if (n) n.textContent = el.childElementCount + ' 行';
  }

  function liveSkeleton(j) {
    const st = j.status || '';
    const running = st === 'queued' || st === 'running' || st === 'stopping';
    return `<div class="live-head">
        <span class="live-title">#${j.id} ${esc(j.mode_label || j.mode || '')}</span>
        <span class="jstat ${esc(st)}" id="liveStat">${esc(scanStatus(st))}</span>
        <span class="live-meta" id="liveTime">起 ${esc(fmtClock(j.created))} · 用时 ${esc(fmtDur(j.elapsed))}</span>
        <span class="grow"></span>
        <span class="live-meta" id="liveCounts"></span>
        <button class="btn ghost small ${running ? 'danger' : ''}" id="btnScanStop" data-job="${j.id}"
                ${running ? '' : 'disabled'}>${st === 'stopping' ? '停止中…' : '停止'}</button>
      </div>
      <div style="display:flex;align-items:center;gap:10px;padding:9px 13px 5px">
        <div class="pbar"><i id="liveBar" class="${running ? 'run' : ''}" style="width:0%"></i></div>
        <span class="live-meta" id="livePct" style="min-width:40px;text-align:right">0%</span>
      </div>
      <div class="tlist" id="scanTlist"></div>
      <div class="scanlogwrap">
        <div class="scanloghead"><span>进度日志</span><span id="scanLogN" class="mono"></span></div>
        <pre class="scanlog" id="scanLog"></pre>
      </div>`;
  }

  function renderLive(j, append) {
    const box = $('#scanLive');
    if (!box) return;
    const st = j.status || '';
    const running = st === 'queued' || st === 'running' || st === 'stopping';

    if (scan.liveKey !== String(j.id)) {
      scan.liveKey = String(j.id);
      box.innerHTML = liveSkeleton(j);
      append = false;
    }

    const stat = $('#liveStat');
    if (stat) {
      stat.className = 'jstat ' + st;
      stat.textContent = scanStatus(st);
    }
    const time = $('#liveTime');
    if (time) {
      time.textContent = `起 ${fmtClock(j.created)}` + (j.finished ? ` · 止 ${fmtClock(j.finished)}` : '')
        + ` · 用时 ${fmtDur(j.elapsed)}`;
    }
    const c = j.counts || {};
    const counts = $('#liveCounts');
    if (counts) counts.textContent = `${c.ok || 0}/${c.total || 0} 目标 · ${j.findings || 0} 命中`;

    const stop = $('#btnScanStop');
    if (stop) {
      stop.disabled = !running;
      stop.textContent = st === 'stopping' ? '停止中…' : '停止';
      stop.classList.toggle('danger', running);
    }

    const pct = donePct(j);
    const bar = $('#liveBar');
    if (bar) {
      bar.style.width = pct + '%';
      bar.classList.toggle('run', running);
    }
    const pt = $('#livePct');
    if (pt) pt.textContent = pct + '%';

    const list = $('#scanTlist');
    if (list) {
      const rows = j.runs || [];
      const keep = list.scrollTop;
      list.innerHTML = rows.length
        ? rows.map(trowHtml).join('')
        : '<div class="muted center" style="padding:22px">目标还没开始跑</div>';
      list.scrollTop = keep;
    }

    if (!append) $('#scanLog').innerHTML = '';
    appendScanLog((j.log && j.log.lines) || []);
  }

  async function openJob(id, opts) {
    opts = opts || {};
    if (opts.reset) { scan.logNext = 0; scan.liveKey = ''; }
    scan.sel = id;
    const qs = new URLSearchParams({ id: String(id) });
    if (scan.logNext) qs.set('log_from', String(scan.logNext));
    const j = await api('/api/scan/job?' + qs.toString());
    renderLive(j, !!scan.logNext);
    scan.logNext = (j.log && j.log.next) || 0;
    document.querySelectorAll('#scanJobs .job').forEach((el) => {
      el.classList.toggle('on', Number(el.dataset.job) === id);
    });
    return j;
  }

  async function startScan() {
    const targets = targetList();
    if (!targets.length) { toast('先填目标：一行一个'); $('#scanTargets').focus(); return; }
    const btn = $('#btnScanStart');
    const old = btn.textContent;
    btn.disabled = true;
    btn.textContent = '启动中…';
    try {
      const r = await api('/api/scan/start', {
        method: 'POST',
        body: JSON.stringify({
          mode: scan.mode,
          targets,
          parallel: Number($('#scanParallel').value) || undefined,
          timeout: Number($('#scanTimeout').value) || undefined,
        }),
      });
      scan.sel = r.job_id;
      scan.liveKey = '';
      scan.logNext = 0;
      toast(`任务 #${r.job_id} 已启动：${r.count} 个目标`);
      await loadScanJobs();
      await openJob(r.job_id, { reset: true });
      ensureScanPoll();
    } catch (err) {
      toast('启动失败：' + err.message, 6000);
    } finally {
      btn.disabled = false;
      btn.textContent = old;
    }
  }

  function ensureScanPoll() {
    if (scan.timer) return;
    scan.timer = setInterval(async () => {
      if (state.tab !== 'scan' && scan.active === 0) {
        clearInterval(scan.timer);
        scan.timer = null;
        return;
      }
      try {
        await loadScanJobs();
        if (scan.sel) await openJob(scan.sel);
      } catch (_) { /* 静默：下一轮再试 */ }
    }, 1500);
  }

  async function loadScan() {
    if (!scan.meta) await loadScanMeta();
    try {
      await loadScanJobs();
    } catch (err) {
      toast('扫描任务列表读取失败：' + err.message, 5000);
    }
    if (scan.sel) {
      try { await openJob(scan.sel, { reset: true }); } catch (_) { scan.sel = 0; }
    }
    ensureScanPoll();
  }

  // ------------------------------------------------------------ 刷新编排

  async function refreshAll(reason) {
    const s = await api('/api/summary');
    renderSummary(s);
    if (state.tab === 'findings') await loadFindings();
    if (state.tab === 'assets') await loadAssets();
    if (state.tab === 'files') await loadFiles();
    if (state.tab === 'log') await loadLog();
    if (state.tab === 'scan') await loadScan();
    if (reason) toast(reason);
  }

  async function rescan(force, quiet) {
    const btn = force ? $('#btnForce') : $('#btnRescan');
    const lbl = btn.querySelector('.lbl') || btn;
    const old = lbl.textContent;
    btn.disabled = true;
    lbl.textContent = force ? '重解析中…' : '整理中…';
    try {
      const data = await api('/api/rescan', { method: 'POST', body: JSON.stringify({ force: !!force }) });
      const st = data.stats || {};
      if (st.busy) { if (!quiet) toast('已有一轮整理在进行中，稍等'); return; }
      const msg = `整理完成：解析 ${st.parsed} 个文件，新增 ${st.findings_added} 条 / 合并 ${st.findings_merged} 条，`
        + `资产 ${st.assets}，跳过 ${st.skipped}，未变 ${st.unchanged}，失败 ${st.errors}，耗时 ${st.elapsed}s`;
      state.offset = 0;
      state.selected.clear();
      // 打开页面时的自动整理不弹提示；只有真扫出新东西才说一声
      await refreshAll(quiet && !st.findings_added ? '' : msg);
      if (st.errors) await loadLog();
    } catch (err) {
      toast('整理失败：' + err.message, 6000);
    } finally {
      btn.disabled = false;
      lbl.textContent = old;
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

      // 资产卡 / 排序 / 只看有漏洞
      const card = e.target.closest('.acard[data-asset]');
      if (card) {
        const tab = document.querySelector('.tab[data-tab="findings"]');
        if (tab && state.tab !== 'findings') tab.click();
        state.q = card.dataset.asset;
        state.sev = '';
        state.status = '';
        $('#search').value = state.q;
        document.querySelectorAll('.chip').forEach((c) => c.classList.toggle('on', !c.dataset.sev));
        state.offset = 0;
        state.selected.clear();
        await loadFindings();
        toast('已筛出「' + state.q + '」的条目');
        return;
      }
      const segBtn = e.target.closest('#assetSort .segbtn');
      if (segBtn) {
        assetView.sort = segBtn.dataset.sort || 'risk';
        try { localStorage.setItem(ASSET_SORT_KEY, assetView.sort); } catch (err) { /* 忽略 */ }
        await loadAssets();
        return;
      }
      if (e.target.closest('#assetOnlyRisk')) {
        assetView.onlyRisk = !assetView.onlyRisk;
        await loadAssets();
        return;
      }

      // 扫描页：模式选择 / 任务切换 / 停止 / 清空
      const mb = e.target.closest('.modebtn[data-mode]');
      if (mb) {
        scan.mode = mb.dataset.mode;
        try { localStorage.setItem(SCAN_MODE_KEY, scan.mode); } catch (err) { /* 隐私模式忽略 */ }
        document.querySelectorAll('#scanModes .modebtn').forEach((b) => b.classList.toggle('on', b === mb));
        return;
      }
      if (e.target.id === 'btnScanClear') { $('#scanTargets').value = ''; countTargets(); $('#scanTargets').focus(); return; }
      const stopBtn = e.target.closest('#btnScanStop');
      if (stopBtn) {
        const id = Number(stopBtn.dataset.job);
        stopBtn.disabled = true;
        try {
          const r = await api('/api/scan/stop', { method: 'POST', body: JSON.stringify({ id }) });
          toast(`任务 #${id} 停止请求已发（结束 ${r.killed || 0} 个进程）`);
          await openJob(id);
        } catch (err) {
          toast('停止失败：' + err.message, 5000);
        }
        return;
      }
      const jobEl = e.target.closest('.job[data-job]');
      if (jobEl) {
        await openJob(Number(jobEl.dataset.job), { reset: true });
        ensureScanPoll();
        return;
      }

      const tab = e.target.closest('.tab');
      if (tab) {
        state.tab = tab.dataset.tab;
        document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
        ['findings', 'assets', 'scan', 'files', 'log'].forEach((k) => {
          $('#view-' + k).classList.toggle('hidden', k !== state.tab);
        });
        syncViewMeta();
        await refreshAll('');
        return;
      }
    });

    document.addEventListener('keydown', (e) => {
      const card = e.target.closest && e.target.closest('.acard[data-asset]');
      if (card && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); card.click(); }
      const jobEl = e.target.closest && e.target.closest('.job[data-job]');
      if (jobEl && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); jobEl.click(); }
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
      if (e.target.id === 'statusFilter') {
        state.status = e.target.value;
        state.offset = 0;
        syncStatusTabs();
        await loadFindings();
        return;
      }
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

    // 扫描表单：回车即开扫，目标数随手数
    const scanForm = $('#scanForm');
    if (scanForm) {
      scanForm.addEventListener('submit', (e) => { e.preventDefault(); startScan(); });
      $('#scanTargets').addEventListener('input', countTargets);
      $('#scanTargets').addEventListener('keydown', (e) => {
        // Ctrl/⌘+Enter 直接开扫（普通回车留给换行）
        if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); startScan(); }
      });
    }

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
    // 状态分段（全部漏洞 / 待审查 / 已审查）——与筛选面板里的状态下拉同源
    const statusTabs = $('#statusTabs');
    if (statusTabs) {
      statusTabs.addEventListener('click', async (e) => {
        const btn = e.target.closest('.tab2');
        if (!btn) return;
        state.status = btn.dataset.st || '';
        state.offset = 0;
        syncStatusTabs();
        if (state.tab !== 'findings') {
          const t = document.querySelector('.tab[data-tab="findings"]');
          if (t) t.click();
        } else {
          syncViewMeta();
          await loadFindings();
        }
      });
    }

    // 筛选面板开关（默认收起，主区干净；严重度/状态/TOP 排行都在里面）
    const btnFilter = $('#btnFilter');
    const filterPanel = $('#filterPanel');
    if (btnFilter && filterPanel) {
      btnFilter.addEventListener('click', () => {
        const closed = filterPanel.classList.toggle('hidden');
        btnFilter.classList.toggle('on', !closed);
      });
    }

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
    try {
      const saved = localStorage.getItem(SCAN_MODE_KEY);
      if (saved) scan.mode = saved;
    } catch (e) { /* 隐私模式忽略 */ }
    bind();
    loadScanMeta();   // 引擎探测放后台，不挡首屏
    try {
      await rescan(false, true); // 打开即自动整理（静默）
    } catch (err) {
      toast('初始整理失败：' + err.message, 6000);
      await refreshAll('');
    }
  }

  boot();
})();

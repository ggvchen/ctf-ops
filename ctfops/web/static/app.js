/* ctf-ops 控制台前端：零依赖、零构建，断网可用 */
(() => {
  'use strict';

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
  const fmtNum = (n) => (n == null ? '—' : Number(n).toLocaleString('zh-CN'));

  const S = {
    view: 'overview',
    overview: null,
    targets: [],
    plugins: [],
    flags: [],
    jobs: new Map(),
    activeJob: null,
    pollTimer: null,
    selection: {},       // 每个视图的靶机选择
    logJob: null,        // 抽屉当前渲染的日志所属任务
    ws: null,            // WebSocket 连接
    wsLive: false,       // 是否已走实时推送
    wsTries: 0,
    wsClosed: false,
    selFindings: new Set(),   // 发现汇总里勾选的 id（跨页保留）
    lastTrash: '',            // 上次删除的快照文件名（用于撤销）
    lastTrashCount: 0,
  };
  const FD = { offset: 0, limit: 50, total: 0, rows: [] };   // 发现汇总的分页状态
  const TERM = { hist: {}, max: 6 };
  let RD_TIMER = null;

  const TITLES = {
    overview: ['总览', '比赛现场作战态势'],
    targets: ['靶机', '地址、凭据与标签'],
    ssh: ['运维', '批量执行命令、传文件、现场快照'],
    term: ['终端', '多机命令网格，会话状态保留'],
    backup: ['备份', '业务系统打包、校验与回滚'],
    waf: ['防护', 'WAF 旁路监听、攻击取证与加固'],
    scan: ['扫描', '端口、Web 指纹、漏洞模板'],
    exploit: ['利用', '插件式 PoC 批量打击'],
    flag: ['FLAG', '收集、去重与自动提交'],
    logs: ['日志', '主机入侵溯源与 Web 访问研判'],
    traffic: ['流量', 'pcap 全链还原'],
    shots: ['取证', 'CTF 解题步骤截图与时间线'],
    ai: ['AI', '本地模型辅助研判'],
    report: ['报告', '作战报告与产物'],
  };

  /* ---------------------------------------------------------------- API */
  async function api(path, opt = {}) {
    const init = { headers: {}, ...opt };
    if (init.body && typeof init.body !== 'string') {
      init.body = JSON.stringify(init.body);
      init.headers['Content-Type'] = 'application/json';
    }
    const r = await fetch(path, init);
    let data = null;
    const ct = r.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await r.json();
    } else {
      data = { error: await r.text() };
    }
    if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
    return data;
  }

  /* --------------------------------------------------------------- toast */
  function toast(msg, level = '') {
    const el = document.createElement('div');
    el.className = 'toast ' + level;
    el.textContent = msg;
    $('#toasts').appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transition = 'opacity .25s';
      setTimeout(() => el.remove(), 260);
    }, level === 'err' ? 5200 : 3000);
  }

  function fail(e) {
    console.error(e);
    toast(e.message || String(e), 'err');
  }

  /* --------------------------------------------------------------- modal */
  function modal(title, bodyHtml) {
    $('#modalTitle').textContent = title;
    $('#modalBody').innerHTML = bodyHtml;
    $('#modal').classList.remove('hidden');
  }
  function closeModal() { $('#modal').classList.add('hidden'); }
  function ask(title, text, okLabel = '确认') {
    return new Promise((resolve) => {
      modal(title, `<p style="margin:0 0 16px;font-size:12.5px;color:#4b5563">${esc(text)}</p>
        <div style="display:flex;justify-content:flex-end;gap:8px">
          <button class="btn ghost" id="askNo">取消</button>
          <button class="btn danger" id="askYes">${esc(okLabel)}</button>
        </div>`);
      $('#askNo').onclick = () => { closeModal(); resolve(false); };
      $('#askYes').onclick = () => { closeModal(); resolve(true); };
    });
  }

  /* ---------------------------------------------------------------- nav */
  function go(view) {
    if (!TITLES[view]) return;
    S.view = view;
    $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
    $$('.view').forEach((v) => v.classList.toggle('active', v.dataset.view === view));
    $('#pageTitle').textContent = TITLES[view][0];
    $('#pageSub').textContent = TITLES[view][1];
    if (location.hash !== '#' + view) history.replaceState(null, '', '#' + view);
    refreshView();
    window.scrollTo({ top: 0 });
  }

  function refreshView() {
    const v = S.view;
    if (v === 'overview') return Promise.all([loadOverview(), loadAuto()]);
    if (v === 'targets') return Promise.all([loadTargets(), loadIface()]);
    if (v === 'backup') return Promise.all([loadBackups(), loadBackupConfig(), loadSources()]);
    if (v === 'term') { renderTerminal(); return Promise.resolve(); }
    if (v === 'waf') return Promise.all([loadWafStatus(), loadVulns(), loadHardenLast(),
                                         Promise.resolve(initBanPanel())]);
    if (v === 'scan') { loadShellRules(); return loadFindings(); }
    if (v === 'flag') return spLoad().then(() => Promise.all(
      [loadFlags(), loadRoundState(), loadRounds(), loadFlagServer()]));
    if (v === 'exploit') return loadPlugins();
    if (v === 'shots') return loadShots();
    if (v === 'report') return loadArtifacts();
    if (v === 'ai') return Promise.all([loadAiHealth(), loadAiConfig()]);
    return Promise.resolve();
  }

  /* ------------------------------------------------- 拖拽文件到路径输入框 */
  // 浏览器（非 Electron）拿不到本地绝对路径，所以"拖进来"= 把文件传到
  // evidence/uploads/<时间戳>/<原名>，再把相对路径填进输入框 —— 分析接口本来就
  // 支持 workdir 相对路径。跑在 Electron 外壳里时 file.path 有值，直接用它，不复制。
  const DROP_MAX_FILES = 500;
  const DROP_MAX_TOTAL = 1 << 30;

  function readEntry(entry, prefix) {
    return new Promise((resolve) => {
      if (!entry) return resolve([]);
      if (entry.isFile) {
        entry.file((f) => resolve([{ file: f, rel: prefix + f.name }]), () => resolve([]));
        return;
      }
      if (!entry.isDirectory) return resolve([]);
      const reader = entry.createReader();
      const acc = [];
      const step = () => {
        reader.readEntries(async (batch) => {
          if (batch.length) {
            acc.push(...batch);
            step();
            return;
          }
          const out = [];
          for (const ch of acc) {
            out.push(...await readEntry(ch, prefix + entry.name + '/'));
          }
          resolve(out);
        }, () => resolve([]));
      };
      step();
    });
  }

  async function collectDropped(dt) {
    const out = [];
    const items = dt.items ? [...dt.items] : [];
    const entries = items.map((i) => i.kind === 'file' && i.webkitGetAsEntry
      ? i.webkitGetAsEntry() : null).filter(Boolean);
    if (entries.length) {
      for (const en of entries) out.push(...await readEntry(en, ''));
      if (out.length) return out;
    }
    // 老浏览器 / 从别的网页拖：只有 File 列表
    [...(dt.files || [])].forEach((f) => out.push({ file: f, rel: f.name }));
    return out;
  }

  function stamp() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}`
      + `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  }

  async function importDropped(files, opts) {
    const paths = [];
    let skipped = 0;
    let resumed = 0;
    let total = 0;
    const dir = stamp();
    for (const item of files.slice(0, DROP_MAX_FILES)) {
      const f = item.file;
      total += f.size;
      if (total > DROP_MAX_TOTAL) { skipped += 1; continue; }
      // Electron：直接拿真实路径，省一次复制
      if (typeof f.path === 'string' && f.path) {
        paths.push(f.path);
        continue;
      }
      // 同名的同尺寸文件已经在 uploads 里了就复用，别重复复制
      try {
        const hit = await fetch('/api/upload/exists?name=' + encodeURIComponent(f.name)
          + '&size=' + f.size).then((r) => r.json()).catch(() => ({}));
        if (hit && hit.path) {
          if (!paths.includes(hit.path)) paths.push(hit.path);
          resumed += 1;
          continue;
        }
      } catch (e) { /* 复用失败就走正常上传 */ }
      const target = `evidence/uploads/${dir}/${item.rel}`;
      try {
        const r = await fetch('/api/upload?path=' + encodeURIComponent(target),
          { method: 'PUT', body: f });
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
        paths.push(d.path);
      } catch (e) {
        skipped += 1;
        console.warn('导入失败', item.rel, e);
      }
    }
    if (files.length > DROP_MAX_FILES) skipped += files.length - DROP_MAX_FILES;
    if (!paths.length) {
      toast(total > DROP_MAX_TOTAL ? '文件太大（合计超过 1GB）' : '导入失败：没有可用文件', 'err');
      return [];
    }
    if (skipped) toast(`${skipped} 个文件被跳过（超限或写入失败）`, 'warn');
    if (resumed) toast(`${resumed} 个文件已存在，直接复用原路径`, '');
    return paths;
  }

  function fillDropInput(input, paths, multiple) {
    if (!input || !paths.length) return;
    if (multiple) {
      const all = (input.value || '').split(',').map((s) => s.trim()).filter(Boolean);
      paths.forEach((p) => { if (!all.includes(p)) all.push(p); });
      input.value = all.join(', ');
    } else {
      input.value = paths[0];
    }
    input.classList.add('dropped');
    setTimeout(() => input.classList.remove('dropped'), 1200);
  }

  function enablePathDrop(input, opts = {}) {
    if (!input) return;
    const multiple = !!opts.multiple;
    input.addEventListener('dragenter', (e) => {
      e.preventDefault(); e.stopPropagation();
      input.classList.add('drop-hover');
    });
    input.addEventListener('dragover', (e) => {
      e.preventDefault(); e.stopPropagation();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
      input.classList.add('drop-hover');
    });
    input.addEventListener('dragleave', () => input.classList.remove('drop-hover'));
    input.addEventListener('drop', async (e) => {
      e.preventDefault(); e.stopPropagation();
      input.classList.remove('drop-hover');
      const dt = e.dataTransfer;
      if (!dt) return;
      toast('正在导入拖入的文件…', '');
      try {
        const files = await collectDropped(dt);
        if (!files.length) return toast('没读到文件（拖的是网页内容？）', 'warn');
        if (!multiple && files.length > 1) {
          toast(`这个输入框只收一个文件，取第 1 个：${files[0].rel}`, 'warn');
        }
        const paths = await importDropped(multiple ? files : files.slice(0, 1), opts);
        if (!paths.length) return;
        fillDropInput(input, paths, multiple);
        toast(`已导入 ${paths.length} 个文件，路径已填好`, 'ok');
      } catch (err) {
        fail(err);
      }
    });
  }

  /* --------------------------------------------------------- 面板折叠 */
  // 配置类面板默认展开，折起来的状态记在 localStorage，刷新/换页都保持
  function initFolds() {
    $$('[data-fold]').forEach((btn) => {
      const panel = btn.closest('.panel');
      if (!panel) return;
      const key = 'ctfops.fold.' + (panel.dataset.collapse || 'panel');
      const apply = (collapsed) => {
        panel.classList.toggle('collapsed', collapsed);
        btn.textContent = collapsed ? '⌄' : '⌃';
        btn.title = collapsed ? '展开' : '折叠';
      };
      apply(localStorage.getItem(key) === '1');
      btn.onclick = () => {
        const next = !panel.classList.contains('collapsed');
        apply(next);
        try { localStorage.setItem(key, next ? '1' : '0'); } catch (e) { /* 隐私模式 */ }
      };
    });
  }

  /* ------------------------------------------------------- 靶机选择器 */
  const ROLE_DEFAULT = {
    ssh: 'defense', term: 'defense', backup: 'defense',
    logs: 'defense', waf: 'defense', scan: 'attack', exploit: 'attack',
    ban: 'defense', harden: 'defense',
  };

  function renderChips(el, key, onChange) {
    if (!el) return;
    if (S.selection[key] === undefined) {
      const role = ROLE_DEFAULT[key];
      S.selection[key] = role
        ? S.targets.filter((t) => (t.role || 'defense') === role).map((t) => t.name)
        : [];
    }
    const sel = S.selection[key] || [];
    if (!S.targets.length) {
      el.innerHTML = '<span class="muted sm">没有靶机，请先在「靶机」页添加</span>';
      return;
    }
    el.innerHTML = `
      <span class="chip ${sel.length ? '' : 'on'}" data-chip="__all">全部
        <span class="cnt">${S.targets.length}</span></span>
      ${S.targets.map((t) => `
        <span class="chip ${sel.includes(t.name) ? 'on' : ''}" data-chip="${esc(t.name)}"
              title="${esc(t.host)} · ${t.role === 'attack' ? '攻击目标' : '防守靶机'}${t.tags.length ? ' · ' + esc(t.tags.join(',')) : ''}">
          <i class="role ${t.role === 'attack' ? 'atk' : 'def'}">${t.role === 'attack' ? '攻' : '防'}</i>
          ${esc(t.name)}<span class="cnt">${esc(t.host)}</span>
        </span>`).join('')}`;
    el.onclick = (ev) => {
      const chip = ev.target.closest('.chip');
      if (!chip) return;
      const v = chip.dataset.chip;
      const cur = S.selection[key] || [];
      if (v === '__all') S.selection[key] = [];
      else if (cur.includes(v)) S.selection[key] = cur.filter((x) => x !== v);
      else S.selection[key] = [...cur, v];
      renderChips(el, key, onChange);
      if (onChange) onChange();
    };
  }

  function chipsSelected(key) { return S.selection[key] || []; }

  function pickTargets(key) {
    const sel = S.selection[key] || [];
    return sel.length ? sel : null;   // null = 全部
  }

  /* ---------------------------------------------------------- 任务抽屉 */
  function trackJob(job, title, onDone) {
    S.jobs.set(job.id, {
      id: job.id, title: title || job.title || job.kind, kind: job.kind,
      status: job.status || 'queued', logs: [], count: 0, elapsed: 0,
      result: null, error: '', onDone: onDone || null,
    });
    S.activeJob = job.id;
    renderDock(true);
    if (!S.wsLive) ensurePolling();
  }

  function ensurePolling() {
    if (S.pollTimer) return;
    S.pollTimer = setInterval(pollJobs, 900);
  }

  async function pollJobs() {
    const running = [...S.jobs.values()].filter((j) => j.status === 'queued' || j.status === 'running');
    if (!running.length) {
      clearInterval(S.pollTimer);
      S.pollTimer = null;
      renderDock();
      return;
    }
    for (const j of running) {
      try {
        const { job } = await api(`/api/jobs/${j.id}?offset=${j.count}`);
        const before = j.status;
        j.status = job.status;
        j.elapsed = job.elapsed;
        j.error = job.error || '';
        j.result = job.result;
        if (job.logs && job.logs.length) {
          job.logs.forEach((l) => j.logs.push(l));
          j.count = job.log_count;
          if (S.activeJob === j.id) appendDockLog(job.logs);
        }
        if ((job.status === 'done' || job.status === 'failed') && before !== job.status) {
          finalizeJob(j);
        }
      } catch (e) {
        j.status = 'failed';
        j.error = e.message;
        onJobFinished(j);
      }
    }
    renderDock();
  }

  function finalizeJob(j) {
    if (!j || j._finalized) return;
    j._finalized = true;
    onJobFinished(j);
  }

  async function syncJob(id) {
    const j = S.jobs.get(id);
    if (!j || j._finalized) return;
    try {
      const d = await api(`/api/jobs/${id}`);
      const jd = d.job;
      j.status = jd.status;
      j.elapsed = jd.elapsed;
      j.error = jd.error || '';
      if (jd.logs && jd.logs.length > (j.logs || []).length) {
        j.logs = jd.logs;
        j.count = j.logs.length;
      }
      j.result = jd.result;
      renderDock(true);
      if (j.status === 'done' || j.status === 'failed') finalizeJob(j);
    } catch (e) { /* 对账失败交给 WS / 轮询 */ }
  }

  function onJobFinished(j) {
    if (j.status === 'done') toast(`完成：${j.title}（${j.elapsed}s）`, 'ok');
    else toast(`失败：${j.title} — ${j.error}`, 'err');
    if (j.onDone) { try { j.onDone(j); } catch (e) { console.error(e); } }
    loadOverview(true);
  }

  function appendDockLog(lines) {
    const box = $('#dockLog');
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    lines.forEach((l) => box.appendChild(lineEl(l)));
    if (atBottom) box.scrollTop = box.scrollHeight;
  }

  function lineEl(l) {
    const span = document.createElement('span');
    span.className = 'l-' + (l.level || 'info');
    span.textContent = `[${new Date((l.ts || Date.now() / 1000) * 1000)
      .toLocaleTimeString('zh-CN', { hour12: false })}] ${l.msg}\n`;
    return span;
  }

  function renderDock(forceLog) {
    const dock = $('#dock');
    const jobs = [...S.jobs.values()].slice(-6);
    if (!jobs.length) { dock.classList.add('hidden'); S.logJob = null; return; }
    dock.classList.remove('hidden');
    $('#dockTabs').innerHTML = jobs.map((j) => `
      <button class="dock-tab ${j.id === S.activeJob ? 'on' : ''}" data-job="${j.id}">
        ${esc(j.title.slice(0, 16))}
        <span class="st">${j.status === 'running' ? '●' : j.status === 'done' ? '✓' : j.status === 'failed' ? '✕' : '…'}</span>
      </button>`).join('');

    const cur = S.jobs.get(S.activeJob);
    if (!cur) return;
    if (forceLog || S.logJob !== cur.id) {
      const box = $('#dockLog');
      const frag = document.createDocumentFragment();
      cur.logs.forEach((l) => frag.appendChild(lineEl(l)));
      box.innerHTML = '';
      box.appendChild(frag);
      box.scrollTop = box.scrollHeight;
      S.logJob = cur.id;
    }
    const st = { queued: '排队中', running: '执行中', done: '已完成', failed: '失败' }[cur.status] || cur.status;
    $('#dockStatus').textContent = `${st} · ${cur.elapsed || 0}s · ${cur.logs.length} 条日志`
      + (cur.error ? ` · ${cur.error.slice(0, 60)}` : '');
  }

  /* --------------------------------------------------------- 通用工具 */
  function sevPill(sev) {
    const s = (sev || 'info').toLowerCase();
    return `<span class="pill ${esc(s)}">${esc(s)}</span>`;
  }

  function findingsTable(rows, opts = {}) {
    if (!rows || !rows.length) {
      return `<div class="empty">${opts.empty || '暂无发现'}</div>`;
    }
    const sel = opts.selectable;
    return `<div class="table-wrap"><table class="grid"><thead><tr>
      ${sel ? '<th class="cb"><input type="checkbox" id="fdAll"></th>' : ''}
      <th style="width:74px">级别</th><th style="width:110px">靶机</th>
      <th>标题</th><th>位置</th>${opts.time ? '<th style="width:110px">时间</th>' : ''}
    </tr></thead><tbody>${rows.map((f, i) => `
      <tr data-finding="${i}" class="clickable">
        ${sel ? `<td class="cb"><input type="checkbox" class="fd-cb" data-fid="${esc(f.id)}"
                 ${S.selFindings.has(Number(f.id)) ? 'checked' : ''}></td>` : ''}
        <td>${sevPill(f.severity)}</td>
        <td>${esc(f.target || '-')}</td>
        <td>${esc(f.title || '')}</td>
        <td class="mono">${esc((f.data && f.data.location) || f.location || '')}</td>
        ${opts.time ? `<td class="num muted">${esc((f.ts || '').slice(5, 16).replace('T', ' '))}</td>` : ''}
      </tr>`).join('')}</tbody></table></div>`;
  }

  function bindFindingRows(container, rows, opts = {}) {
    container.querySelectorAll('tr[data-finding]').forEach((tr) => {
      tr.onclick = () => {
        const f = rows[Number(tr.dataset.finding)];
        const d = f.data || f;
        modal(f.title || '发现详情', `<div class="kv">
          <div>级别<b>${esc(f.severity || 'info')}</b></div>
          <div>靶机<b>${esc(f.target || '-')}</b></div>
          <div>位置<b class="mono">${esc(d.location || '-')}</b></div>
        </div>
        <p style="margin:12px 0 6px;font-size:12px;color:#6b7280">${esc(d.detail || '')}</p>
        <pre>${esc(d.evidence || '(无证据文本)')}</pre>`);
      };
    });
    if (!opts.selectable) return;
    const fire = () => { if (opts.onSelectChange) opts.onSelectChange(); };
    const boxes = [...container.querySelectorAll('input.fd-cb')];
    const all = container.querySelector('#fdAll');
    const syncAll = () => {
      if (!all) return;
      all.checked = boxes.length > 0 && boxes.every((b) => b.checked);
      all.indeterminate = !all.checked && boxes.some((b) => b.checked);
    };
    boxes.forEach((cb) => {
      cb.onclick = (e) => e.stopPropagation();     // 点勾选框不要弹详情
      cb.onchange = () => {
        const id = Number(cb.dataset.fid);
        if (cb.checked) S.selFindings.add(id); else S.selFindings.delete(id);
        syncAll();
        fire();
      };
    });
    if (all) {
      all.onclick = (e) => e.stopPropagation();
      all.onchange = () => {
        boxes.forEach((b) => {
          b.checked = all.checked;
          const id = Number(b.dataset.fid);
          if (all.checked) S.selFindings.add(id); else S.selFindings.delete(id);
        });
        syncAll();
        fire();
      };
    }
    syncAll();
  }

  function statKv(obj) {
    const rows = Object.entries(obj || {});
    if (!rows.length) return '';
    return `<div class="kv">${rows.map(([k, v]) => {
      let val = v;
      if (typeof v === 'object' && v !== null) val = JSON.stringify(v);
      if (typeof val === 'string' && val.length > 110) val = val.slice(0, 110) + '…';
      return `<div>${esc(k)}<b>${esc(val)}</b></div>`;
    }).join('')}</div>`;
  }

  // 日志统计按"文件:指标"聚合过，多文件时拍平成三列表比挤成一排 kv 好读
  function logStatsTable(stats) {
    const rows = Object.entries(stats || {});
    if (!rows.length) return '';
    const multi = rows.some(([k]) => k.includes(':'));
    if (!multi) return statKv(stats);
    const body = rows.map(([k, v]) => {
      const i = k.indexOf(':');
      const file = i > 0 ? k.slice(0, i) : '—';
      const name = i > 0 ? k.slice(i + 1) : k;
      const val = (typeof v === 'object' && v !== null) ? JSON.stringify(v) : String(v);
      return `<tr>
        <td class="mono sm">${esc(file)}</td>
        <td>${esc(name)}</td>
        <td class="mono sm" title="${esc(val)}">${esc(val.length > 160 ? val.slice(0, 160) + '…' : val)}</td>
      </tr>`;
    }).join('');
    return `<div class="table-wrap"><table class="grid"><thead><tr>
      <th style="width:170px">文件</th><th style="width:120px">指标</th><th>值</th>
    </tr></thead><tbody>${body}</tbody></table></div>`;
  }

  /* ------------------------------------------------------------- 总览 */
  async function loadOverview(silent) {
    try {
      const [ov, fd] = await Promise.all([api('/api/overview'), api('/api/findings?severity=')]);
      S.overview = ov;
      S.targets = ov.targets;
      const sm = ov.summary || {};
      const sev = ov.severity || {};
      const totalSev = Object.values(sev).reduce((a, b) => a + b, 0) || 1;

      $('#sideName').textContent = ov.name;
      $('#sideMeta').innerHTML = `${ov.mode.toUpperCase()} · ${ov.targets.length} 台靶机<br>${esc(ov.config.split('/').pop())}`;

      // 后端 .py 改过但没重启时，接口会报"未知接口"，这里直接把原因说出来
      const srv = ov.server || {};
      const bar = $('#staleBar');
      if (bar) {
        bar.classList.toggle('hidden', !srv.stale);
        if (srv.stale) {
          bar.innerHTML = `<b>服务端是旧代码</b>：进程启动于 ${esc(srv.started_at)}
            ，而代码改于 ${esc(srv.code_mtime)}。请重启控制台（Ctrl-C 后重跑 <code>ops dash</code>），
            否则新接口会报「未知接口」。`;
        }
      }

      const cards = [
        ['靶机', sm.targets, '', `${ov.active_jobs ? ov.active_jobs + ' 个任务执行中' : '全部就绪'}`],
        ['发现', sm.findings, '', (sev.critical ? `${sev.critical} 个 critical` : '暂无严重项')],
        ['FLAG', sm.flags, sm.flags ? 'ok' : '', sm.flags ? `${sm.flags_submitted} 已提交` : '尚未收集'],
        ['待提交', Math.max(0, (sm.flags || 0) - (sm.flags_submitted || 0)),
          (sm.flags > sm.flags_submitted) ? 'alert' : '', ov.submit.mode === 'manual' ? '人工 outbox' : 'API 直提'],
        ['备份', sm.backups, sm.backups ? 'ok' : '', sm.backups ? '可用于回滚' : '改动前先跑一次'],
        ['插件', ov.plugins, '', ov.ai.enabled ? (ov.ai.alive ? 'AI 在线' : 'AI 离线') : 'AI 关闭'],
      ];
      $('#ovCards').innerHTML = cards.map(([l, n, cls, d]) => `
        <div class="card ${cls}"><div class="n">${fmtNum(n)}</div>
        <div class="l">${l}</div><div class="d">${esc(d)}</div></div>`).join('');

      const order = ['critical', 'high', 'medium', 'low', 'info'];
      const colors = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };
      $('#ovSeverity').innerHTML = `
        <div class="sevbar">${order.map((k) => sev[k]
          ? `<span class="${colors[k]}" style="width:${(sev[k] / totalSev * 100).toFixed(1)}%"></span>` : '').join('')}</div>
        <div class="legend">${order.map((k) => `
          <span><i class="${colors[k]}" style="background:${{ critical: '#d7232c', high: '#ea580c', medium: '#d97706', low: '#64748b', info: '#cbd5e1' }[k]}"></i>
          ${k} ${sev[k] || 0}</span>`).join('')}</div>
        <p class="muted sm" style="margin:12px 0 0">
          提交模式 <b>${esc(ov.submit.mode)}</b>${ov.submit.url ? ' · ' + esc(ov.submit.url) : '（写 outbox 人工粘贴）'}<br>
          本地模型 <b>${esc(ov.ai.model)}</b> · ${esc(ov.ai.base_url)}
        </p>`;

      $('#ovTargets').innerHTML = S.targets.length ? `
        <div class="chips">${S.targets.map((t) => `
          <span class="chip" style="cursor:default">
            <i class="role ${t.role === 'attack' ? 'atk' : 'def'}">${t.role === 'attack' ? '攻' : '防'}</i>
            ${esc(t.name)}<span class="cnt">${esc(t.user)}@${esc(t.host)}</span></span>`).join('')}</div>`
        : '<div class="empty">还没有靶机，去「靶机」页添加</div>';

      const rows = fd.findings.slice(0, 12);
      $('#ovFindings').innerHTML = findingsTable(rows, { time: true });
      bindFindingRows($('#ovFindings'), rows);
      $('#ovFindingsCount').textContent = `共 ${fd.total} 条`;

      // 顶栏便签：点一下跳到对应页面（高危顺带把级别过滤设好）
      const pending = Math.max(0, (sm.flags || 0) - (sm.flags_submitted || 0));
      const high = (sev.critical || 0) + (sev.high || 0);
      const chips = [
        { label: '靶机', n: ov.targets.length, nav: 'targets', title: '去靶机页' },
        { label: '高危', n: high, cls: high ? 'hot' : '', nav: 'scan',
          sev: 'critical,high', title: '去扫描页，只看 critical/high' },
        { label: 'FLAG', n: sm.flags || 0, nav: 'flag', title: '去 FLAG 页' },
        { label: '待提交', n: pending, cls: pending ? 'hot' : 'good', nav: 'flag',
          scroll: '#flagTable', title: '去 FLAG 列表' },
        ov.active_jobs
          ? { raw: `任务 <b>${ov.active_jobs}</b> 执行中`, nav: 'jobs', cls: 'hot',
              title: '展开任务日志' }
          : { raw: '空闲', nav: 'jobs', title: '当前没有运行中的任务' },
      ];
      $('#statusChips').innerHTML = chips.map((c) => `
        <button type="button" class="stat-chip nav ${c.cls || ''}"
                data-nav="${c.nav}" data-sev="${c.sev || ''}"
                data-scroll="${c.scroll || ''}" title="${esc(c.title || '')}">
          ${c.raw || `${esc(c.label)} <b>${c.n}</b>`}
        </button>`).join('');
      bindStatChips();
    } catch (e) {
      if (!silent) fail(e);
      else console.warn(e);
    }
  }

  /* 顶栏便签的跳转逻辑：故意做成 <button>，键盘 Tab + 回车也能用 */
  function bindStatChips() {
    $$('#statusChips [data-nav]').forEach((el) => {
      el.onclick = () => {
        const nav = el.dataset.nav;
        if (nav === 'jobs') {
          const n = (S.overview && S.overview.active_jobs) || 0;
          if (!n) return toast('当前没有运行中的任务', '');
          renderDock(true);
          $('#dock').classList.remove('hidden');
          return;
        }
        const sev = el.dataset.sev;
        if (sev && $('#sevFilter')) $('#sevFilter').value = sev;
        go(nav);
        const sel = el.dataset.scroll;
        if (sel) {
          setTimeout(() => {
            const t = $(sel);
            if (t) t.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }, 260);
        }
      };
    });
  }

  /* ------------------------------------------------------------- 靶机 */
  async function loadTargets() {
    try {
      const [{ targets }, fs] = await Promise.all([api('/api/targets'), api('/api/flagserver')]);
      S.targets = targets;
      S.fsConf = fs.conf || {};
      S.fsTokens = S.fsConf.tokens || {};
      $('#tgCount').textContent = `${targets.length} 台`;
      if (!targets.length) {
        $('#targetTable').innerHTML = '<div class="empty">还没有靶机</div>';
        return;
      }
      $('#targetTable').innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
        <th class="cb"><input type="checkbox" id="tgAll"></th>
        <th>角色</th><th>名称</th><th>地址</th><th>SSH</th><th>认证</th><th>Web</th><th>标签</th>
        <th>本机 token</th><th>备注</th>
        <th style="width:130px">操作</th>
      </tr></thead><tbody>${targets.map((t) => {
        const tk = S.fsTokens[t.name] || S.fsTokens[t.host] || '';
        return `
        <tr>
          <td class="cb"><input type="checkbox" class="tg-cb" data-name="${esc(t.name)}"></td>
          <td><span class="pill ${t.role === 'attack' ? 'attack' : 'defense'}">${t.role === 'attack' ? '攻击' : '防守'}</span></td>
          <td><b>${esc(t.name)}</b></td>
          <td class="mono">${esc(t.host)}</td>
          <td class="mono">${esc(t.user)}:${t.ssh_port}</td>
          <td>${t.auth === 'key' ? '<span class="pill info">密钥</span>' : t.auth === 'password' ? '<span class="pill warn">口令</span>' : '<span class="pill err">未配置</span>'}</td>
          <td class="mono">${t.web.map(esc).join('<br>') || '—'}</td>
          <td>${t.tags.map((x) => `<span class="pill info">${esc(x)}</span>`).join(' ') || '—'}</td>
          <td><input class="tk-input ${tk ? 'set' : ''}" data-token="${esc(t.name)}" type="password"
                     placeholder="${tk ? '已设置' : '默认'}" title="flagserver 逐机 token，留空用全局 token"></td>
          <td class="muted">${esc(t.note || '—')}</td>
          <td><div class="row-actions">
            <button class="btn ghost xs" data-target-edit="${esc(t.name)}">编辑</button>
            <button class="btn ghost xs" data-target-del="${esc(t.name)}">删除</button>
          </div></td>
        </tr>`; }).join('')}</tbody></table></div>`;

      $$('#targetTable [data-target-edit]').forEach((b) => {
        b.onclick = () => openTargetEditor(b.dataset.targetEdit);
      });
      $$('#targetTable [data-target-del]').forEach((b) => {
        b.onclick = () => deleteTarget(b.dataset.targetDel);
      });
      $$('#targetTable input[data-token]').forEach((inp) => {
        const save = async () => {
          try {
            await api('/api/flagserver/token', {
              method: 'POST',
              body: { target: inp.dataset.token, token: inp.value.trim() },
            });
            inp.classList.toggle('set', !!inp.value.trim());
            inp.placeholder = inp.value.trim() ? '已设置' : '默认';
            toast(inp.value.trim() ? '本机 token 已保存' : '已清除本机 token', 'ok');
          } catch (e) { fail(e); }
        };
        inp.onchange = save;
        inp.onkeydown = (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); save(); } };
      });
      const all = $('#tgAll');
      if (all) {
        all.checked = false;
        all.onchange = () => {
          $$('#targetTable .tg-cb').forEach((cb) => { cb.checked = all.checked; });
          updateBatchBar();
        };
      }
      $$('#targetTable .tg-cb').forEach((cb) => { cb.onchange = updateBatchBar; });
      updateBatchBar();
    } catch (e) { fail(e); }
  }


  /* ------------------------------------------------- 接口配置（靶机页统一） */
  // 两个请求格式在这里一次填完：交 flag 的接口、问 flag 服务器的格式。
  // 提交接口落到库里的「页面配置」这条 profile（Submitter 优先用它），
  // flagserver 落到 settings，逐机 token 落在 conf.tokens。
  function subBodyText(c) {
    if (c.json_body) return JSON.stringify(c.json_body, null, 2);
    if (c.form_body) return Object.entries(c.form_body).map(([k, v]) => `${k}=${v}`).join('\n');
    return c.raw_body || '';
  }

  async function loadIface() {
    try {
      const [sub, fs] = await Promise.all([api('/api/submit/global'), api('/api/flagserver')]);
      const c = sub.config || {};
      S.subGlobal = sub;
      $('#ifSubUrl').value = c.url || '';
      $('#ifSubMethod').value = (c.method || 'POST').toUpperCase();
      $('#ifSubBodyType').value = c.json_body ? 'json' : c.form_body ? 'form'
        : (c.raw_body ? 'raw' : 'json');
      $('#ifSubBody').value = subBodyText(c);
      const hk = Object.keys(c.headers || {});
      $('#ifSubHeaders').value = hk.length ? JSON.stringify(c.headers, null, 2) : '';
      $('#ifSubSuccess').value = c.success_key || '';
      $('#ifSubToken').value = '';
      $('#ifSubToken').placeholder = c.token_set ? '已设置，留空不改' : '可留空';
      $('#ifSubHint').textContent = c.url
        ? `当前生效：${sub.source || '库内配置'} · ${c.method || 'POST'} ${c.url}`
        : '还没配置提交接口；平台没有 API 时保持为空即可（会写 outbox 提醒人工粘贴）';

      const f = fs.conf || {};
      S.fsConf = f;
      S.fsTokens = f.tokens || {};
      $('#ifFsMode').value = f.mode || 'http';
      $('#ifFsScope').value = f.scope || 'defense';
      $('#ifFsUrl').value = f.url || '';
      $('#ifFsCmd').value = f.cmd || '';
      $('#ifFsMethod').value = (f.method || 'GET').toUpperCase();
      $('#ifFsField').value = f.field || '';
      $('#ifFsHeaders').value = Object.keys(f.headers || {}).length
        ? JSON.stringify(f.headers, null, 2) : '';
      $('#ifFsBody').value = f.body || '';
      $('#ifFsTokenCmd').value = f.token_cmd || '';
      $('#ifFsSubmit').checked = f.submit_after !== false;
      $('#ifFsTool').value = f.tool || 'auto';
      fsModeToggle();
      const nTok = Object.values(S.fsTokens).filter(Boolean).length;
      $('#ifFsHint').textContent = [
        f.enabled === false ? '当前已停用' : '',
        `token：${nTok ? nTok + ' 台单独设置' : (f.token ? '全局一个' : '从靶机文件读')}`,
        f.submit_after !== false ? '拉到自动提交' : '只入库不提交',
      ].filter(Boolean).join(' · ');
    } catch (e) { fail(e); }
  }

  function fsModeToggle() {
    const cmd = ($('#ifFsMode') || {}).value === 'cmd';
    $('#ifFsUrlWrap').classList.toggle('hidden', cmd);
    $('#ifFsMethodWrap').classList.toggle('hidden', cmd);
    $('#ifFsBodyWrap').classList.toggle('hidden', cmd);
    $('#ifFsCmdWrap').classList.toggle('hidden', !cmd);
  }

  async function saveIface() {
    const btn = $('#btnIfaceSave');
    busy(btn, true);
    try {
      const url = $('#ifSubUrl').value.trim();
      if (url) {
        const type = $('#ifSubBodyType').value;
        const raw = $('#ifSubBody').value.trim();
        const conf = {
          url,
          method: $('#ifSubMethod').value.toUpperCase(),
          success_key: $('#ifSubSuccess').value.trim() || 'success',
          success_value: true, message_key: 'message', strict: true,
        };
        if (raw) {
          if (type === 'json') {
            try { conf.json_body = JSON.parse(raw); }
            catch { throw new Error('请求体不是合法 JSON（flag 位置写 "{flag}"）'); }
          } else if (type === 'form') {
            conf.form_body = {};
            raw.split('\n').forEach((line) => {
              const i = line.indexOf('=');
              if (i > 0) conf.form_body[line.slice(0, i).trim()] = line.slice(i + 1).trim();
            });
          } else {
            conf.raw_body = raw;
          }
        }
        const h = $('#ifSubHeaders').value.trim();
        if (h) {
          try { conf.headers = JSON.parse(h); }
          catch { throw new Error('请求头不是合法 JSON'); }
        }
        const tk = $('#ifSubToken').value.trim();
        if (tk) conf.token = tk;
        await api('/api/submit/profile', {
          method: 'POST',
          body: { name: '页面配置', config: conf, activate: true, note: '靶机页统一填写' },
        });
      }

      const mode = $('#ifFsMode').value;
      const fh = $('#ifFsHeaders').value.trim();
      let headers = {};
      if (fh) {
        try { headers = JSON.parse(fh); }
        catch { throw new Error('flag 服务器请求头不是合法 JSON'); }
      }
      const fsConf = {
        mode,
        url: $('#ifFsUrl').value.trim(),
        cmd: $('#ifFsCmd').value.trim(),
        method: $('#ifFsMethod').value.toUpperCase(),
        field: $('#ifFsField').value.trim(),
        headers,
        body: $('#ifFsBody').value,
        token_cmd: $('#ifFsTokenCmd').value.trim(),
        scope: $('#ifFsScope').value,
        tool: $('#ifFsTool').value,
        submit_after: $('#ifFsSubmit').checked,
        enabled: true,
      };
      if (!fsConf.url && !fsConf.cmd) {
        // 只配了提交接口也允许保存
        fsConf.mode = 'http';
        fsConf.url = '';
      }
      if (fsConf.url || fsConf.cmd) {
        await api('/api/flagserver', { method: 'PUT', body: { conf: fsConf } });
      }
      toast('接口配置已保存', 'ok');
      await loadIface();
      await loadTargets();
    } catch (e) { fail(e); }
    finally { busy(btn, false); }
  }

  /* --------------------------------------------------------- 批量操作 */

  function selectedTargetNames() {
    return $$('#targetTable .tg-cb:checked').map((cb) => cb.dataset.name);
  }

  function updateBatchBar() {
    const n = selectedTargetNames().length;
    const bar = $('#batchBar');
    if (!bar) return;
    bar.classList.toggle('hidden', n === 0);
    $('#batchCount').textContent = `已选 ${n} 台`;
  }

  function promptModal(title, text, placeholder, value = '') {
    return new Promise((resolve) => {
      modal(title, `
        <p style="margin:0 0 10px;font-size:12.5px;color:#4b5563">${esc(text)}</p>
        <input id="pmInput" value="${esc(value)}" placeholder="${esc(placeholder)}"
               style="width:100%;padding:8px 10px;border:1px solid var(--line-strong);border-radius:8px;font-family:var(--mono);font-size:12.5px">
        <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
          <button class="btn ghost" id="pmNo">取消</button>
          <button class="btn" id="pmYes">确定</button>
        </div>`);
      $('#pmYes').onclick = () => { const v = $('#pmInput').value; closeModal(); resolve(v); };
      $('#pmNo').onclick = () => { closeModal(); resolve(null); };
      setTimeout(() => { const i = $('#pmInput'); if (i) { i.focus(); i.select(); } }, 60);
    });
  }

  async function batchTargets(op, value, confirmText) {
    const names = selectedTargetNames();
    if (!names.length) return toast('先勾选靶机', 'warn');
    if (confirmText) {
      const ok = await ask('确认批量操作', confirmText, '执行');
      if (!ok) return;
    }
    try {
      const d = await api('/api/targets/batch', { method: 'POST', body: { op, names, value } });
      const extra = Object.entries(d.kept || {}).filter(([, v]) => v > 0)
        .map(([k, v]) => `${k} ${v}`).join(' / ');
      toast(`${d.label} ${d.affected} 台` + (extra ? `（保留历史：${extra}）` : '')
        + (d.missing.length ? `，${d.missing.length} 台未找到` : ''), 'ok');
      S.targets = d.targets;
      S.selection = {};
      await loadTargets();
      renderAllChips();
      loadOverview(true);
    } catch (e) { fail(e); }
  }

  /* ------------------------------------------------ 编辑 / 删除靶机 */
  function openTargetEditor(name) {
    const t = (S.targets || []).find((x) => x.name === name);
    if (!t) return toast('靶机不存在，刷新一下', 'warn');
    const sel = (v) => (t.role === v ? 'selected' : '');
    modal(`编辑靶机 · ${t.name}`, `
      <form id="editTargetForm" class="form-grid cols3">
        <label>角色
          <select name="role">
            <option value="defense" ${sel('defense')}>防守（我方靶机）</option>
            <option value="attack" ${sel('attack')}>攻击目标</option>
          </select>
        </label>
        <label>名称<input name="name" value="${esc(t.name)}"></label>
        <label>地址<input name="host" value="${esc(t.host)}" required></label>
        <label>SSH 端口<input name="ssh_port" value="${t.ssh_port || 22}"></label>
        <label>用户<input name="user" value="${esc(t.user || 'root')}"></label>
        <label>密码<input name="password" type="password" placeholder="留空表示不修改"></label>
        <label>密钥文件<input name="key_file" value="${esc(t.key_file || '')}" placeholder="~/.ssh/id_rsa（可留空）"></label>
        <label>备份源<input name="webroot" value="${esc(t.webroot || '')}" placeholder="留空 = 自动探测"></label>
        <label>标签<input name="tags" value="${esc((t.tags || []).join(','))}"></label>
        <label class="span3">Web 地址<input name="web" value="${esc((t.web || []).join(', '))}" placeholder="http://ip, http://ip:8080（逗号分隔）"></label>
        <label class="span3">备注<input name="note" value="${esc(t.note || '')}"></label>
        <label class="inline" style="align-self:center">
          <input type="checkbox" name="clear_credentials"> 清除已有口令 / 密钥
        </label>
        <div class="form-actions span2"><button class="btn" type="submit">保存</button></div>
      </form>
      <p class="muted sm" style="margin:12px 0 0">
        保存会直接改写 targets.yaml。改名会同步把历史备份 / 发现 / FLAG 记录里的靶机名一起改掉。
      </p>`);

    $('#editTargetForm').onsubmit = async (ev) => {
      ev.preventDefault();
      const form = ev.target;
      const body = Object.fromEntries(new FormData(form).entries());
      body.clear_credentials = !!form.querySelector('[name=clear_credentials]').checked;
      const btn = form.querySelector('button[type=submit]');
      busy(btn, true);
      try {
        const d = await api(`/api/targets/${encodeURIComponent(name)}`, { method: 'PUT', body });
        closeModal();
        toast(d.renamed
          ? `已保存，并改名为 ${d.renamed.to}（同步 ${Object.values(d.renamed.records).reduce((a, b) => a + b, 0)} 条历史记录）`
          : '已保存', 'ok');
        S.targets = d.targets;
        S.selection = {};
        await loadTargets();
        renderAllChips();
        loadOverview(true);
      } catch (e) { fail(e); } finally { busy(btn, false); }
    };
  }

  async function deleteTarget(name) {
    const ok = await ask('删除靶机',
      `从配置里移除「${name}」？历史备份 / 发现 / FLAG 记录会保留，但不再参与任何扫描、备份、防护动作。`,
      '删除');
    if (!ok) return;
    try {
      const d = await api(`/api/targets/${encodeURIComponent(name)}`, { method: 'DELETE' });
      const kept = Object.entries(d.kept || {}).filter(([, v]) => v > 0)
        .map(([k, v]) => `${k} ${v}`).join(' / ');
      toast(`已删除 ${name}` + (kept ? `（保留历史：${kept}）` : ''), 'ok');
      S.targets = d.targets;
      S.selection = {};
      await loadTargets();
      renderAllChips();
      loadOverview(true);
    } catch (e) { fail(e); }
  }

  /* ------------------------------------------------------------- 备份 */
  async function loadBackups() {
    try {
      const { backups } = await api('/api/backups');
      if (!backups.length) {
        $('#backupTable').innerHTML = '<div class="empty">暂无备份。改动靶机前先跑一次。</div>';
        return;
      }
      const rows = backups.map((b, i) => `
        <tr>
          <td class="num muted">${esc(b.ts.slice(5, 19).replace('T', ' '))}</td>
          <td><b>${esc(b.target)}</b></td>
          <td class="num">${esc(b.size_h)}</td>
          <td class="mono">${esc(b.file)}${b.exists ? '' : ' <span class="pill err">文件丢失</span>'}</td>
          <td class="mono muted">${esc((b.sha256 || '').slice(0, 12))}…</td>
          <td><div class="actions">
            <button class="btn ghost xs" data-restore="${esc(b.local_path)}" data-target="${esc(b.target)}">还原</button>
          </div></td>
        </tr>`);
      $('#backupTable').innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
        <th>时间</th><th>靶机</th><th>大小</th><th>文件</th><th>sha256</th><th>操作</th>
      </tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
      $$('#backupTable [data-restore]').forEach((btn) => {
        btn.onclick = async () => {
          const ok = await ask('确认回滚',
            `将用 ${btn.dataset.restore.split('/').pop()} 覆盖 ${btn.dataset.target} 的 web 目录，此操作不可撤销。`, '执行回滚');
          if (!ok) return;
          try {
            const { job } = await api('/api/backup/restore', {
              method: 'POST',
              body: { archive: btn.dataset.restore, targets: [btn.dataset.target], confirm: true },
            });
            trackJob(job, `回滚 ${btn.dataset.target}`);
          } catch (e) { fail(e); }
        };
      });
    } catch (e) { fail(e); }
  }

  /* ------------------------------------------------------------- 扫描 */
  async function loadFindings() {
    const sev = $('#sevFilter') ? $('#sevFilter').value : '';
    if ($('#fdLimit')) FD.limit = Number($('#fdLimit').value) || 50;
    // 撤销按钮要跨刷新可用：没删过就取最近一份快照
    if (!S.lastTrash) {
      try {
        const t = await api('/api/findings/trash');
        const f0 = (t.files || []).find((x) => x.kind === 'delete');
        if (f0) { S.lastTrash = f0.file; S.lastTrashCount = f0.count; }
      } catch (e) { /* 没有快照就算了 */ }
    }
    try {
      const d = await api(`/api/findings?severity=${encodeURIComponent(sev)}`
        + `&offset=${FD.offset}&limit=${FD.limit}`);
      FD.total = d.total || 0;
      FD.rows = d.findings || [];
      // 删到最后一页空掉时回退一页，别停在空白页
      if (!FD.rows.length && FD.offset > 0) {
        FD.offset = Math.max(0, Math.floor((FD.total - 1) / FD.limit)) * FD.limit;
        return loadFindings();
      }
      renderFindings();
    } catch (e) { fail(e); }
  }

  function renderFindings() {
    const box = $('#findingsTable');
    if (!box) return;
    box.innerHTML = findingsTable(FD.rows, { selectable: true,
      empty: '暂无发现，先跑一次扫描' });
    bindFindingRows(box, FD.rows, { selectable: true, onSelectChange: renderFdBar });
    renderFdBar();
  }

  function renderFdBar() {
    const bar = $('#fdBar');
    if (!bar) return;
    const pages = Math.max(1, Math.ceil(FD.total / FD.limit));
    const page = Math.floor(FD.offset / FD.limit) + 1;
    const n = S.selFindings.size;
    bar.innerHTML = `
      <span class="muted sm">共 <b>${FD.total}</b> 条 · 第 ${page} / ${pages} 页${
        n ? ` · 已选 <b>${n}</b> 条` : ''}</span>
      <div class="row tight">
        <button class="btn ghost sm" data-page="prev" ${page <= 1 ? 'disabled' : ''}>上一页</button>
        <button class="btn ghost sm" data-page="next" ${page >= pages ? 'disabled' : ''}>下一页</button>
        <button class="btn ghost sm danger" id="fdDelSel" ${n ? '' : 'disabled'}>
          删除选中${n ? `（${n}）` : ''}</button>
        <button class="btn ghost sm" id="fdDelAll" ${FD.total ? '' : 'disabled'}
                title="按当前级别筛选，删除全部匹配的发现">清空筛选结果</button>
        <button class="btn ghost sm" id="fdUndo" ${S.lastTrash ? '' : 'disabled'}
                title="从 evidence/trash 快照回填">撤销删除${S.lastTrash ? `（${S.lastTrashCount}）` : ''}</button>
      </div>`;
    $$('#fdBar [data-page]').forEach((b) => {
      b.onclick = () => {
        const dir = b.dataset.page;
        FD.offset = Math.max(0, FD.offset + (dir === 'next' ? FD.limit : -FD.limit));
        loadFindings();
      };
    });
    const delSel = $('#fdDelSel');
    if (delSel) delSel.onclick = deleteSelectedFindings;
    const delAll = $('#fdDelAll');
    if (delAll) delAll.onclick = deleteAllFindings;
    const undo = $('#fdUndo');
    if (undo) undo.onclick = undoFindingsDelete;
  }

  async function deleteSelectedFindings() {
    const ids = [...S.selFindings];
    if (!ids.length) return;
    if (!await ask('删除发现', `删除选中的 ${ids.length} 条发现记录？只删库里的记录，不影响靶机。`, '删除')) return;
    try {
      const d = await api('/api/findings/delete', { method: 'POST', body: { ids } });
      ids.forEach((i) => S.selFindings.delete(i));
      S.lastTrash = d.trash || '';
      S.lastTrashCount = d.removed || 0;
      toast(`已删除 ${d.removed} 条（可从「撤销删除」还原）`, 'ok');
      loadFindings();
      loadOverview(true);
    } catch (e) { fail(e); }
  }

  async function undoFindingsDelete() {
    if (!S.lastTrash) return toast('没有可撤销的删除记录', 'warn');
    if (!await ask('撤销删除', `从快照 ${S.lastTrash} 回填 ${S.lastTrashCount} 条发现？`, '回填')) return;
    try {
      const d = await api('/api/findings/restore', {
        method: 'POST', body: { file: S.lastTrash } });
      toast(`已回填 ${d.restored} 条`, 'ok');
      S.lastTrash = '';
      S.lastTrashCount = 0;
      FD.offset = 0;
      loadFindings();
      loadOverview(true);
    } catch (e) { fail(e); }
  }

  async function deleteAllFindings() {
    const sev = $('#sevFilter') ? $('#sevFilter').value : '';
    const label = sev ? `级别 ${sev}` : '全部级别';
    if (!await ask('清空发现', `按当前筛选（${label}，共 ${FD.total} 条）全部删除？此操作不可撤销。`, '清空')) return;
    try {
      const d = await api('/api/findings/delete', {
        method: 'POST', body: { all: true, severity: sev } });
      S.selFindings.clear();
      S.lastTrash = d.trash || '';
      S.lastTrashCount = d.removed || 0;
      toast(`已清空 ${d.removed} 条（可从「撤销删除」还原）`, 'ok');
      FD.offset = 0;
      loadFindings();
      loadOverview(true);
    } catch (e) { fail(e); }
  }

  function initBanPanel() {
    if (!$('#banTargets')) return;
    const def = S.targets.filter((t) => t.role !== 'attack');
    // 注意空数组是 truthy，必须判长度，否则会一直停在"全部"
    if ((!S.selection.ban || !S.selection.ban.length) && def.length) {
      S.selection.ban = [def[0].name];
    }
    renderChips($('#banTargets'), 'ban', banCaps);
    if (def.length) banCaps();
  }

  /* --------------------------------------------------- 封禁（权限自适应） */
  function banTargetName() {
    return chipsSelected('ban')[0]
      || ((S.targets.find((x) => x.role !== 'attack') || {}).name || '');
  }

  async function banCaps() {
    const t = banTargetName();
    if (!t) return toast('先选一台防守靶机', 'warn');
    try {
      const d = await api('/api/waf/ban/caps?target=' + encodeURIComponent(t));
      const c = d.caps || {};
      $('#banCaps').innerHTML = `uid=${c.uid} · sudo=${c.sudo ? '有' : '无'} · `
        + `iptables=${c.iptables ? '有' : '无'} · PHP=${c.php_agent ? '有' : '无'} · `
        + `web=${esc(c.web_server || '-')} · htaccess=${c.allow_override ? '可写' : '不可'} · `
        + `<b>推荐 ${esc(c.best || '无（只能拦 payload）')}</b>`;
      if (!c.best) toast('这台机器没有可用的封禁手段，只能靠 WAF 规则', 'warn');
    } catch (e) {
      // 靶机可达性不确定，这里不弹红条吓人，只在行内说明
      $('#banCaps').textContent = '探测失败：' + (e.message || e);
    }
  }

  async function banList() {
    const t = banTargetName();
    if (!t) return toast('先选一台防守靶机', 'warn');
    try {
      const d = await api('/api/waf/bans?target=' + encodeURIComponent(t));
      const rows = d.bans || [];
      const box = $('#banResult');
      box.classList.remove('hidden');
      box.innerHTML = rows.length ? `<table class="grid"><thead><tr>
        <th>已封禁 IP</th><th style="width:140px">来源</th></tr></thead><tbody>
        ${rows.map((ip) => `<tr><td class="mono">${esc(ip)}</td>
          <td class="muted sm">${(d.iptables || []).includes(ip) ? 'iptables' : 'PHP 黑名单'}</td>
        </tr>`).join('')}</tbody></table>`
        : '<div class="empty">当前没有封禁记录</div>';
    } catch (e) { fail(e); }
  }

  async function banRun(unban) {
    const t = banTargetName();
    if (!t) return toast('先选一台防守靶机', 'warn');
    const ips = $('#banIps').value.trim();
    if (!unban && !ips) return toast('填要封的 IP', 'warn');
    runJob(unban ? '/api/waf/unban' : '/api/waf/ban', {
      target: t, ips: ips.split(/[\s,;]+/).filter(Boolean),
      backend: $('#banBackend').value,
    }, {
      title: unban ? `解封 · ${t}` : `封禁 · ${t}`,
      btn: unban ? $('#btnUnban') : $('#btnBan'),
      onDone: (j) => {
        const r = j.result || {};
        const box = $('#banResult');
        box.classList.remove('hidden');
        if (unban) {
          box.innerHTML = `<div class="empty">已解封 ${(r.removed || []).length} 个`
            + `${(r.detail || []).length ? '（' + esc((r.detail || []).join('；')) + '）' : ''}</div>`;
          return;
        }
        const rows = (r.banned || []).map((ip) => [ip, '成功', ''])
          .concat((r.failed || []).map((ip) => [ip, '失败', '']));
        box.innerHTML = `<table class="grid"><thead><tr><th>IP</th><th style="width:80px">结果</th>
          <th style="width:110px">方式</th></tr></thead><tbody>
          ${rows.map(([ip, st, _]) => `<tr><td class="mono">${esc(ip)}</td>
            <td>${st === '成功' ? '<span class="pill ok">成功</span>' : '<span class="pill err">失败</span>'}</td>
            <td class="mono sm">${esc(r.backend || '—')}</td></tr>`).join('')}
          </tbody></table>
          ${r.error ? `<p class="muted sm">${esc(r.error)}</p>` : ''}
          ${(r.detail || []).length ? `<pre class="answer">${esc((r.detail || []).join('\n'))}</pre>` : ''}`;
      },
    });
  }

  /* ------------------------------------------------------ 漏洞修补计划 */
  const HARDEN = { actions: [], caps: {}, picked: new Set() };

  function renderHarden(job) {
    const r = (job && job.result) || {};
    HARDEN.actions = r.actions || HARDEN.actions || [];
    HARDEN.caps = r.caps || HARDEN.caps || {};
    HARDEN.picked = new Set(HARDEN.actions.filter((a) => a.auto).map((a) => a.id));
    drawHarden();
    if (r.report) $('#hardenHint').textContent = `方案已存 ${r.report}`;
  }

  function drawHarden() {
    const box = $('#hardenTable');
    const acts = HARDEN.actions || [];
    if (!acts.length) { box.innerHTML = '<div class="empty">没有生成方案</div>'; renderHardenBar(); return; }
    box.innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
      <th class="cb"><input type="checkbox" id="hdAll"></th>
      <th style="width:70px">级别</th><th style="width:70px">靶机</th>
      <th>修补动作</th><th style="width:70px">层面</th>
      <th style="width:70px">方式</th><th>说明 / 片段</th>
    </tr></thead><tbody>${acts.map((a) => `
      <tr>
        <td class="cb"><input type="checkbox" class="hd-cb" data-id="${esc(a.id)}"
          ${HARDEN.picked.has(a.id) ? 'checked' : ''} ${a.auto ? '' : 'disabled'}></td>
        <td>${sevPill(a.severity)}</td>
        <td class="mono sm">${esc(a.target)}</td>
        <td><b>${esc(a.title)}</b></td>
        <td class="muted sm">${esc(a.level)}</td>
        <td>${a.auto ? '<span class="pill ok">自动</span>'
          : `<span class="pill warn">人工</span>${a.needs_root ? '<div class="muted sm">需 root</div>' : ''}`}</td>
        <td class="muted sm">${esc(a.reason || '')}
          ${(a.files || []).length ? `<div class="mono sm">写 ${esc(a.files[0].path)}</div>` : ''}
          ${(a.cmds || []).length ? `<details><summary class="muted sm">看命令/片段</summary>
            <pre class="answer">${esc((a.cmds || []).join('\n'))}</pre></details>` : ''}
        </td>
      </tr>`).join('')}</tbody></table></div>`;
    $$('#hardenTable .hd-cb').forEach((cb) => {
      cb.onchange = () => {
        if (cb.checked) HARDEN.picked.add(cb.dataset.id);
        else HARDEN.picked.delete(cb.dataset.id);
        renderHardenBar();
      };
    });
    const all = $('#hdAll');
    if (all) {
      const boxes = $$('#hardenTable .hd-cb').filter((b) => !b.disabled);
      all.checked = boxes.length > 0 && boxes.every((b) => b.checked);
      all.onchange = () => {
        boxes.forEach((b) => {
          b.checked = all.checked;
          if (all.checked) HARDEN.picked.add(b.dataset.id);
          else HARDEN.picked.delete(b.dataset.id);
        });
        renderHardenBar();
      };
    }
    renderHardenBar();
  }

  function renderHardenBar() {
    const bar = $('#hardenBar');
    if (!bar) return;
    const n = HARDEN.picked.size;
    const auto = (HARDEN.actions || []).filter((a) => a.auto).length;
    const manual = (HARDEN.actions || []).length - auto;
    bar.innerHTML = `<span class="muted sm">共 <b>${HARDEN.actions.length}</b> 个动作 ·
      可自动 <b>${auto}</b> · 需人工 <b>${manual}</b>${n ? ` · 已选 <b>${n}</b>` : ''}</span>
      <div class="row tight">
        <button class="btn ghost sm" id="btnHardenDry">演练一下</button>
      </div>`;
    const dry = $('#btnHardenDry');
    if (dry) dry.onclick = () => hardenApply(true);
  }

  function hardenApply(dryRun) {
    const ids = [...HARDEN.picked];
    if (!ids.length) return toast('先勾选要应用的动作', 'warn');
    runJob('/api/harden/apply', { ids, dry_run: !!dryRun }, {
      title: dryRun ? '修补演练' : '应用修补', btn: $('#btnHardenApply'),
      onDone: (j) => {
        const rows = (j.result && j.result.results) || [];
        const bad = rows.filter((r) => !r.ok);
        toast(`完成 ${rows.length - bad.length}/${rows.length}`
          + (bad.length ? `，${bad.length} 个未落地（见任务日志）` : ''), bad.length ? 'warn' : 'ok');
      },
    });
  }

  async function loadHardenLast() {
    try {
      const d = await api('/api/harden/last');
      if (!d.actions) return;
      HARDEN.actions = d.actions;
      HARDEN.caps = d.caps || {};
      HARDEN.picked = new Set(d.actions.filter((a) => a.auto).map((a) => a.id));
      drawHarden();
      if (d.md) $('#hardenHint').textContent = `上次方案 ${d.md}`;
    } catch (e) { /* 没有历史 */ }
  }

  /* ------------------------------------------------------------- 利用 */
  async function loadPlugins() {
    try {
      const { plugins } = await api('/api/exploit/plugins');
      S.plugins = plugins;
      const sel = $('#exPlugin');
      const cur = sel.value;
      sel.innerHTML = plugins.map((p) => `<option value="${esc(p.name)}">${esc(p.name)} · ${esc(p.severity)}</option>`).join('')
        + '<option value="all">all · 全部插件</option>';
      if (cur) sel.value = cur;
      updatePluginDesc();
      fillAutoPlugins(plugins.map((p) => p.name));
    } catch (e) { fail(e); }
  }

  function updatePluginDesc() {
    const p = S.plugins.find((x) => x.name === $('#exPlugin').value);
    $('#exDesc').textContent = p ? `${p.description}（${p.kind}）` : '将依次执行所有插件';
  }

  function renderExploitResult(job) {
    const rows = (job.result && job.result.results) || [];
    if (!rows.length) { $('#exploitTable').innerHTML = '<div class="empty">没有结果</div>'; return; }
    $('#exploitTable').innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
      <th style="width:110px">靶机</th><th style="width:150px">插件</th><th style="width:80px">结果</th>
      <th>证据 / 错误</th><th style="width:70px">耗时</th></tr></thead><tbody>
      ${rows.map((r) => `<tr>
        <td><b>${esc(r.target)}</b></td>
        <td class="mono">${esc(r.plugin)}</td>
        <td>${r.ok ? '<span class="pill ok">命中</span>' : '<span class="pill err">失败</span>'}</td>
        <td class="mono">${esc((r.error || r.evidence || '').slice(0, 300))}
          ${r.flags && r.flags.length ? `<br><span class="pill ok">FLAG ${esc(r.flags.join(' '))}</span>` : ''}</td>
        <td class="num">${r.elapsed}s</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  /* ------------------------------------------------------------- FLAG */
  async function loadFlags() {
    try {
      const data = await api('/api/flags');
      S.flags = data.flags;
      const done = data.flags.filter((f) => f.submitted).length;
      $('#flagStats').innerHTML = `
        <div>总数<b>${data.total}</b></div>
        <div>已提交<b>${done}</b></div>
        <div>待提交<b>${data.pending}</b></div>
        <div>提交模式<b>${esc((S.overview && S.overview.submit.mode) || '—')}</b></div>`;
      const prof = S.submitActive || '';
      $('#flagMode').textContent = prof
        ? `接口提交（${prof}）`
        : ((S.overview && S.overview.submit.mode === 'manual')
            ? 'manual：写入 outbox 后人工粘贴' : 'API 直提');
      if (!data.flags.length) {
        $('#flagTable').innerHTML = '<div class="empty">还没有 FLAG</div>';
        return;
      }
      $('#flagTable').innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
        <th style="width:40px">#</th><th style="width:120px">时间</th><th style="width:110px">来源靶机</th>
        <th>FLAG</th><th style="width:200px">状态</th><th style="width:60px"></th>
      </tr></thead><tbody>${data.flags.map((f, i) => `
        <tr>
          <td class="num muted">${i + 1}</td>
          <td class="num muted">${esc(f.ts.slice(5, 16).replace('T', ' '))}</td>
          <td>${esc(f.target || '-')}</td>
          <td class="mono">${esc(f.value)}</td>
          <td>${f.submitted ? '<span class="pill ok">已提交</span>' : '<span class="pill warn">待提交</span>'}
            <span class="muted sm">${esc((f.submit_result || '').slice(0, 40))}</span></td>
          <td><button class="btn ghost xs" data-copy="${esc(f.value)}">复制</button></td>
        </tr>`).join('')}</tbody></table></div>`;
      $$('#flagTable [data-copy]').forEach((b) => {
        b.onclick = async () => {
          try { await navigator.clipboard.writeText(b.dataset.copy); toast('已复制', 'ok'); }
          catch { toast('复制失败，请手动选择', 'warn'); }
        };
      });
    } catch (e) { fail(e); }
  }



  /* --------------------------------------- 提交接口（浏览器 cURL 导入） */
  let SP_PARSED = null;

  function renderSpPreview(d) {
    const body = d.json_body || d.form_body || d.raw_body;
    const bodyTxt = body == null ? '（无 body）'
      : (typeof body === 'object' ? JSON.stringify(body, null, 1) : String(body));
    const chips = (d.flag_at || []).map((x) => `<span class="pill ok">${esc(x)}</span>`).join(' ');
    $('#spPreview').innerHTML = `
      <div class="kv" style="margin-top:12px">
        <div>方法<b>${esc(d.method)}</b></div>
        <div>URL<b class="path">${esc(d.url)}</b></div>
        <div>body 类型<b>${esc(d.body_kind)}</b></div>
        <div>flag 位置<b>${chips || '<span class="pill warn">未识别</span>'}</b></div>
      </div>
      <pre class="answer" style="max-height:180px;margin-top:10px">${esc(bodyTxt)}</pre>
      <div class="muted sm">保留的请求头：${(Object.keys(d.headers || {})).map(esc).join(', ') || '无'}</div>`;
    $('#spSaveRow').classList.remove('hidden');
    if (!$('#spName').value) {
      try { $('#spName').value = new URL(d.url).host; } catch (e) { /* ignore */ }
    }
    if (!d.has_placeholder) {
      $('#spHint').textContent = '未识别到 flag：请在左侧填字段名后重新解析';
    } else {
      $('#spHint').textContent = '';
    }
  }

  async function spParse() {
    const curl = $('#spCurl').value.trim();
    if (!curl) return toast('先粘贴 cURL', 'warn');
    const btn = $('#btnSpParse');
    busy(btn, true);
    try {
      const d = await api('/api/submit/parse', { method: 'POST', body: {
        curl, flag_key: $('#spKey').value.trim() || null,
      } });
      SP_PARSED = d;
      renderSpPreview(d);
      toast(d.has_placeholder ? '解析成功' : '解析成功，但没找到 flag 字段', 
            d.has_placeholder ? 'ok' : 'warn');
    } catch (e) { fail(e); } finally { busy(btn, false); }
  }

  /* ------------------------------------------------- flagserver（快捷拉取） */
  async function loadFlagServer() {
    try {
      const d = await api('/api/flagserver');
      const f = d.conf || {};
      S.fsConf = f;
      const configured = !!(f.url || f.cmd);
      const pill = $('#fsPill');
      pill.className = 'pill ' + (configured ? 'ok' : 'info');
      pill.textContent = configured ? (f.mode === 'cmd' ? '本地命令' : 'HTTP') : '未配置';
      const last = d.last || {};
      const tok = Object.values(f.tokens || {}).filter(Boolean).length;
      $('#fsMeta').innerHTML = `
        <div>方式<b>${esc(f.mode || 'http')}</b></div>
        <div>地址<b class="path">${esc(f.url || f.cmd || '—')}</b></div>
        <div>范围<b>${esc(f.scope || 'defense')}</b></div>
        <div>逐机 token<b>${tok || '—'}</b></div>
        <div>上次新增<b>${last.new != null ? last.new : '—'}</b></div>
        <div>上次提交<b>${last.submitted ? (last.submitted.ok + ' 成功 / ' + last.submitted.fail + ' 失败') : '—'}</b></div>`;
      const rows = last.rows || [];
      const box = $('#fsResult');
      if (!rows.length) { box.classList.add('hidden'); box.innerHTML = ''; return; }
      box.classList.remove('hidden');
      box.innerHTML = `<table class="grid"><thead><tr>
        <th style="width:130px">靶机</th><th style="width:70px">结果</th>
        <th style="width:70px">工具</th><th>FLAG / 错误</th><th style="width:80px">耗时</th>
      </tr></thead><tbody>${rows.map((r) => `
        <tr>
          <td><b>${esc(r.target)}</b><div class="muted sm mono">${esc(r.host || '')}</div></td>
          <td>${r.ok ? '<span class="pill ok">通</span>' : '<span class="pill err">失败</span>'}</td>
          <td class="muted sm mono">${esc(r.tool || '—')}</td>
          <td class="mono sm">${(r.flags || []).map(esc).join('<br>')
            || esc((r.error || '').slice(0, 120) || '—')}</td>
          <td class="num muted">${r.elapsed != null ? r.elapsed + 's' : '—'}</td>
        </tr>`).join('')}</tbody></table>`;
    } catch (e) { /* 静默 */ }
  }

  function fetchFlagServer() {
    const f = S.fsConf || {};
    if (!f.url && !f.cmd) {
      toast('还没配 flag 服务器，先去「靶机」页填写', 'warn');
      return go('targets');
    }
    runJob('/api/flagserver/fetch', { submit: f.submit_after !== false }, {
      title: '经靶机拉取 FLAG', btn: $('#btnFsFetch'),
      onDone: () => { loadFlagServer(); loadFlags(); loadOverview(true); },
    });
  }

  async function debugFlagServer() {
    const f = S.fsConf || {};
    if (!f.url && !f.cmd) return toast('还没配 flag 服务器，先去「靶机」页填写', 'warn');
    const names = S.targets.filter((t) => t.role !== 'attack').map((t) => t.name);
    const pick = names.length > 1 ? await promptModal('单机调试',
      `在哪台靶机上跑这次请求？留空用第一台（${names[0] || '无'}）`,
      names[0] || '', names[0] || '') : (names[0] || '');
    if (pick === null) return;
    runJob('/api/flagserver/test', { target: pick || undefined }, {
      title: 'flagserver 调试', btn: $('#btnFsDebug'),
      onDone: () => loadFlagServer(),
    });
  }

  async function spLoad() {

    try {
      const d = await api('/api/submit/profiles');
      S.submitActive = d.active || '';
      const pill = $('#spPill');
      if (d.active) { pill.className = 'pill ok'; pill.textContent = d.active; }
      else { pill.className = 'pill info'; pill.textContent = '未配置'; }
      if (!d.profiles.length) {
        $('#spList').innerHTML = '<div class="empty">还没有导入过提交接口。' +
          '从浏览器复制一次提交请求，粘到上面就能用。</div>';
        return;
      }
      $('#spList').innerHTML = `<table class="grid" style="margin-top:12px"><thead><tr>
        <th style="width:60px">状态</th><th style="width:180px">接口名</th>
        <th style="width:70px">方法</th><th>URL</th><th style="width:110px">flag 位置</th>
        <th style="width:150px">操作</th>
      </tr></thead><tbody>${d.profiles.map((p) => `
        <tr>
          <td>${p.active ? '<span class="pill ok">使用中</span>' : '<span class="muted">—</span>'}</td>
          <td><b>${esc(p.name)}</b><div class="muted sm mono">${esc(p.host || '')}</div></td>
          <td class="mono">${esc(p.method || '')}</td>
          <td class="mono sm">${esc(p.url || '')}</td>
          <td class="muted sm">${esc((p.flag_at || []).join(', ') || '—')}</td>
          <td><div class="row-actions">
            <button class="btn ghost xs" data-sp-use="${esc(p.name)}">${p.active ? '重载' : '启用'}</button>
            <button class="btn ghost xs" data-sp-del="${esc(p.name)}">删除</button>
          </div></td>
        </tr>`).join('')}</tbody></table>`;
      $$('#spList [data-sp-use]').forEach((b) => {
        b.onclick = async () => {
          try {
            await api('/api/submit/activate', { method: 'POST', body: { name: b.dataset.spUse } });
            toast(`已启用 ${b.dataset.spUse}`, 'ok');
            await spLoad();
            loadFlags(); loadOverview(true);
          } catch (e) { fail(e); }
        };
      });
      $$('#spList [data-sp-del]').forEach((b) => {
        b.onclick = async () => {
          if (!await ask('删除接口', `删除 ${b.dataset.spDel}？不影响已提交的 flag。`, '删除')) return;
          try {
            await api('/api/submit/profile/' + encodeURIComponent(b.dataset.spDel),
              { method: 'DELETE' });
            toast('已删除', 'ok'); spLoad();
          } catch (e) { fail(e); }
        };
      });
    } catch (e) { /* 页面刚开，静默 */ }
  }

  async function spSave() {
    const name = $('#spName').value.trim();
    const curl = $('#spCurl').value.trim();
    if (!name) return toast('给接口起个名字（一般用平台域名）', 'warn');
    if (!curl) return toast('先粘贴 cURL', 'warn');
    const btn = $('#btnSpSave');
    busy(btn, true);
    try {
      const d = await api('/api/submit/profile', { method: 'POST', body: {
        name, curl, flag_key: $('#spKey').value.trim() || null, activate: true,
      } });
      toast(`已保存并启用：${d.name}`, 'ok');
      await spLoad();
      loadFlags(); loadOverview(true);
      const tf = $('#spTestFlag').value.trim();
      if (tf) {
        const r = await api('/api/submit/test', { method: 'POST', body: { name, flag: tf } });
        toast(`测试提交${r.ok ? '成功' : '失败'}：${r.message.slice(0, 50)}`,
              r.ok ? 'ok' : 'err');
      }
    } catch (e) { fail(e); } finally { busy(btn, false); }
  }

  /* ------------------------------------------------------- AWD 轮次监控 */
  function fmtDur(sec) {
    sec = Math.max(0, Math.round(sec || 0));
    if (sec < 60) return `${sec} 秒`;
    const m = Math.floor(sec / 60), s2 = sec % 60;
    return s2 ? `${m} 分 ${s2} 秒` : `${m} 分钟`;
  }

  async function loadRoundState() {
    try {
      const st = await api('/api/round/state');
      S.round = st;
      const pill = $('#rdPill');
      pill.className = 'pill ' + (st.running ? 'ok' : 'info');
      pill.textContent = st.running ? '监控中' : '未启动';
      $('#rdNext').textContent = st.running
        ? `第 ${st.round_no} 轮 · 下次检测 ${fmtDur(st.next_in)}`
        : '未启动';
      $('#btnRdStart').disabled = st.running;
      $('#btnRdStop').disabled = !st.running;
      if (st.running && st.interval) $('#rdInterval').value = String(st.interval);
      $('#rdAuto').checked = !!st.auto_submit;

      const knownTotal = Object.values(st.known || {}).reduce((a, v) => a + v.length, 0);
      $('#rdStats').innerHTML = `
        <div>轮次<b>${st.round_no}</b></div>
        <div>检测次数<b>${st.ticks}</b></div>
        <div>间隔<b>${fmtDur(st.interval)}</b></div>
        <div>已识别 FLAG<b>${knownTotal}</b></div>
        <div>监控靶机<b>${st.running ? (st.targets || []).length : '—'}</b></div>
        <div>提交成功<b>${(st.stats || {}).submitted_ok || 0}</b></div>`;
    } catch (e) { /* 页面刚开，静默 */ }
  }

  async function loadRounds() {
    try {
      const d = await api('/api/round/history?limit=120');
      const rows = d.rounds || [];
      $('#rdSummary').textContent =
        `${d.stats.changed_rounds} 轮有刷新 · 提交成功 ${d.stats.submitted_ok}`;
      if (!rows.length) {
        $('#roundTable').innerHTML = '<div class="empty">还没有轮次记录</div>';
        return;
      }
      $('#roundTable').innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
        <th style="width:56px">轮次</th><th style="width:108px">时间</th>
        <th style="width:170px">靶机</th><th>FLAG</th>
        <th style="width:90px">刷新</th><th>结果</th>
      </tr></thead><tbody>${rows.map((r) => `
        <tr>
          <td class="num">${r.round_no || '-'}</td>
          <td class="num muted">${esc((r.ts || '').slice(5, 16).replace('T', ' '))}</td>
          <td>${esc(r.target || '-')}</td>
          <td class="mono">${esc(r.flag || '—')}</td>
          <td>${r.changed ? '<span class="pill high">新</span>' : '<span class="pill low">未变</span>'}</td>
          <td>${r.ok ? '<span class="pill ok">提交成功</span>'
            : r.submitted ? '<span class="pill err">提交失败</span>'
            : `<span class="muted sm">${esc((r.note || '').slice(0, 40))}</span>`}</td>
        </tr>`).join('')}</tbody></table></div>`;
    } catch (e) { fail(e); }
  }

  /* ------------------------------------------------------------- 日志 */
  function renderLogResult(job) {
    const r = job.result || {};
    const findings = r.findings || [];
    const h3 = (t) => `<h3 style="font-size:12px;margin:16px 0 6px">${t}</h3>`;
    $('#logResult').innerHTML = `
      ${logStatsTable(r.stats)}
      ${findings.length ? h3(`发现 ${findings.length} 项`) + findingsTable(findings)
        : '<div class="empty">未发现明显异常</div>'}
      ${r.timeline && r.timeline.length ? h3('时间线')
        + `<pre class="answer">${esc(r.timeline.slice(0, 60).join('\n'))}</pre>` : ''}
      ${r.detail && r.detail.length ? h3(`明细（${r.detail.length} 条，点开看全部）`)
        + `<pre class="answer">${esc(r.detail.slice(0, 120).join('\n'))}</pre>` : ''}
      ${r.samples && r.samples.length ? h3('原始样本（认不出格式时看这里）')
        + `<pre class="answer">${esc(r.samples.slice(0, 20).join('\n'))}</pre>` : ''}
      ${r.text ? `<details class="report" open><summary>完整报告${
        r.report ? `（已存 ${esc(r.report)}）` : ''}</summary>
        <pre class="answer">${esc(r.text)}</pre></details>` : ''}`;
    bindFindingRows($('#logResult'), findings);
  }

  /* ------------------------------------------------------------- 流量 */
  function renderTrafficResult(job) {
    const r = job.result || {};
    const findings = r.findings || [];
    $('#trafficResult').innerHTML = `
      ${statKv(r.stats)}
      ${findings.length ? `<h3 style="font-size:12px;margin:16px 0 8px">发现 ${findings.length} 项</h3>
        ${findingsTable(findings)}` : '<div class="empty">未发现可疑行为</div>'}
      ${r.timeline && r.timeline.length ? `<h3 style="font-size:12px;margin:16px 0 6px">可疑时序</h3>
        <pre class="answer">${esc(r.timeline.slice(0, 40).join('\n'))}</pre>` : ''}
      ${r.text ? `<h3 style="font-size:12px;margin:16px 0 6px">完整报告</h3>
        <pre class="answer">${esc(r.text)}</pre>` : ''}`;
    bindFindingRows($('#trafficResult'), findings);
  }

  /* ------------------------------------------------------------- 取证 */
  async function loadShots() {
    try {
      const { shots } = await api('/api/shots');
      $('#shotCount').textContent = `${shots.length} 条记录`;
      if (!shots.length) { $('#shotGrid').innerHTML = '<div class="empty">暂无截图</div>'; return; }
      $('#shotGrid').innerHTML = `<div class="gallery">${shots.map((s) => `
        <div class="thumb" ${s.exists ? `data-img="/artifact?path=${encodeURIComponent(s.rel)}"` : ''}>
          ${s.exists
            ? `<img src="/artifact?path=${encodeURIComponent(s.rel)}" alt="${esc(s.step)}" loading="lazy">`
            : '<div class="noimg"><b>无图片</b><span>仅记录文字步骤</span></div>'}
          <div class="cap"><b>${esc(s.step)}</b>
            <span>${esc(s.ts.slice(5, 16).replace('T', ' '))}${s.note ? ' · ' + esc(s.note.slice(0, 26)) : ''}</span>
          </div>
        </div>`).join('')}</div>`;
      $$('#shotGrid .thumb[data-img]').forEach((el) => {
        el.onclick = () => modal('证据截图',
          `<img src="${el.dataset.img}" alt="evidence"><p class="muted sm">${esc(el.querySelector('.cap b').textContent)}</p>`);
      });
      const tl = await api('/api/file?path=' + encodeURIComponent('report/timeline.md')).catch(() => null);
      if (tl) $('#timelinePreview').innerHTML = `<pre class="answer">${esc(tl.text)}</pre>`;
    } catch (e) { fail(e); }
  }

  /* ------------------------------------------------------------- 产物 */
  async function loadArtifacts() {
    try {
      const { artifacts } = await api('/api/artifacts');
      const box = $('#artifactTable');
      if (!artifacts.length) { box.innerHTML = '<div class="empty">还没有产物</div>'; return; }
      box.innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
        <th>文件</th><th style="width:130px">目录</th><th style="width:90px">大小</th>
        <th style="width:110px">时间</th><th style="width:130px">操作</th></tr></thead><tbody>
        ${artifacts.map((a) => `<tr>
          <td class="mono">${esc(a.path)}</td>
          <td class="muted">${esc(a.dir)}</td>
          <td class="num">${esc(a.size_h)}</td>
          <td class="num muted">${esc(a.mtime)}</td>
          <td><div class="actions">
            ${['.md', '.txt', '.log', '.json', '.html'].includes(a.ext)
              ? `<button class="btn ghost xs" data-view-file="${esc(a.path)}">预览</button>` : ''}
            <a class="btn ghost xs" href="/artifact?path=${encodeURIComponent(a.path)}&download=1">下载</a>
          </div></td>
        </tr>`).join('')}</tbody></table></div>`;
      $$('#artifactTable [data-view-file]').forEach((b) => {
        b.onclick = async () => {
          try {
            const f = await api('/api/file?path=' + encodeURIComponent(b.dataset.viewFile));
            modal(f.path.split('/').pop(), `<pre>${esc(f.text)}</pre>`);
          } catch (e) { fail(e); }
        };
      });
    } catch (e) { fail(e); }
  }

  /* ------------------------------------------------------------- AI */
  // 模型列表：select 里放 /v1/models 拿到的清单，值同步到隐藏的 #aiModel。
  // 用 select 而不是 datalist —— datalist 得先打字才弹，实际用起来"点了没反应"。
  function fillModelOptions(current) {
    const sel = $('#aiModelSel');
    if (!sel) return;
    const models = S.aiModels || [];
    const cur = (current !== undefined ? current : $('#aiModel').value) || '';
    const opts = [];
    if (!models.length) {
      opts.push(`<option value="">${cur ? '（当前：' + esc(cur) + '）' : '（点「拉取模型列表」）'}</option>`);
    } else {
      if (cur && !models.includes(cur)) {
        opts.push(`<option value="${esc(cur)}">${esc(cur)}（不在清单里）</option>`);
      }
      models.forEach((m) => opts.push(
        `<option value="${esc(m)}">${esc(m)}${m === cur ? '（当前）' : ''}</option>`));
    }
    sel.innerHTML = opts.join('');
    if (cur) sel.value = cur;
  }

  function handFillModel() {
    const box = $('#aiModel');
    const show = box.classList.contains('hidden');
    box.classList.toggle('hidden', !show);
    if (show) {
      if (!$('#aiModel').value && $('#aiModelSel').value) {
        $('#aiModel').value = $('#aiModelSel').value;
      }
      box.focus();
      box.select();
    }
  }

  async function loadAiConfig() {
    try {
      const d = await api('/api/ai/config');
      const c = d.ai || {};
      S.aiConf = c;
      $('#aiBaseUrl').value = c.base_url || '';
      $('#aiModel').value = c.model || '';
      fillModelOptions(c.model || '');
      $('#aiApiKey').value = '';
      $('#aiApiKey').placeholder = c.api_key_set ? '已设置，留空不改' : (c.api_key || 'not-needed');
      $('#aiTimeout').value = c.timeout ?? '';
      $('#aiTemp').value = c.temperature ?? '';
      $('#aiMaxTokens').value = c.max_tokens ?? '';
      $('#aiEnabled').checked = c.enabled !== false;
      const box = $('#aiPresets');
      if (box && !box.dataset.built) {
        box.dataset.built = '1';
        box.innerHTML = (d.presets || []).map((p) =>
          `<button class="chip-btn" data-ai-preset="${esc(p.base_url)}">${esc(p.name)}</button>`).join('');
        $$('#aiPresets [data-ai-preset]').forEach((b) => {
          b.onclick = () => { $('#aiBaseUrl').value = b.dataset.aiPreset; pullAiModels(); };
        });
      }
    } catch (e) { fail(e); }
  }

  async function pullAiModels() {
    const btn = $('#btnAiModels');
    busy(btn, true);
    try {
      const base = $('#aiBaseUrl').value.trim();
      const d = await api('/api/ai/models?base_url=' + encodeURIComponent(base));
      if (!d.ok) {
        toast(`拉取失败：${d.error}`, 'warn');
        fillModelOptions();
        return;
      }
      S.aiModels = d.models || [];
      const cur = $('#aiModel').value.trim();
      if (S.aiModels.length && !S.aiModels.includes(cur)) {
        $('#aiModel').value = S.aiModels[0];
      }
      fillModelOptions($('#aiModel').value);
      toast(`端点可用（${d.elapsed}ms），${S.aiModels.length} 个模型`, 'ok');
      if (!S.aiModels.length) {
        toast('节点没返回模型清单，点「手填」直接写模型名', 'warn');
      }
    } catch (e) { fail(e); }
    finally { busy(btn, false); }
  }

  async function saveAiConfig() {
    const btn = $('#btnAiSave');
    busy(btn, true);
    try {
      const body = {
        enabled: $('#aiEnabled').checked,
        base_url: $('#aiBaseUrl').value.trim(),
        model: $('#aiModel').value.trim(),
        timeout: Number($('#aiTimeout').value || 0) || undefined,
        temperature: $('#aiTemp').value === '' ? undefined : Number($('#aiTemp').value),
        max_tokens: Number($('#aiMaxTokens').value || 0) || undefined,
      };
      const key = $('#aiApiKey').value.trim();
      if (key) body.api_key = key;
      const d = await api('/api/ai/config', { method: 'PUT', body });
      toast(`已保存：${(d.changed || []).join(', ') || '无变化'}`, 'ok');
      await afterAiSaved(d);
    } catch (e) { fail(e); }
    finally { busy(btn, false); }
  }

  async function afterAiSaved(d) {
    S.aiConf = d.ai || S.aiConf;
    await loadAiConfig();
    await loadAiHealth();
  }

  function testAi() {
    const body = {
      base_url: $('#aiBaseUrl').value.trim(),
      model: $('#aiModel').value.trim(),
      api_key: $('#aiApiKey').value.trim() || undefined,
    };
    $('#aiTestOut').classList.remove('hidden');
    $('#aiTestOut').textContent = '测试中…';
    runJob('/api/ai/test', body, {
      title: '模型连通测试', btn: $('#btnAiTest'),
      onDone: (j) => {
        const r = j.result || {};
        const lines = [];
        lines.push(r.ok ? `✓ 补全成功 ${r.ms}ms` : `✗ 失败：${r.error}`);
        if (r.models) lines.push(`模型清单：${r.models.length ? r.models.join(', ') : '（空）'}`);
        if (r.usage) lines.push(`tokens：prompt ${r.usage.prompt_tokens ?? '?'} / completion ${r.usage.completion_tokens ?? '?'}`);
        if (r.text) lines.push(`回复：${r.text}`);
        $('#aiTestOut').textContent = lines.join('\n');
      },
    });
  }

  async function loadAiHealth() {
    try {
      const d = await api('/api/ai/health');
      const pill = $('#aiPill');
      pill.className = 'pill ' + (d.alive ? 'ok' : 'err');
      pill.textContent = d.alive ? '在线' : '离线';
      const n = (d.models || []).length;
      $('#aiMeta').innerHTML = `
        <div>模型<b>${esc(d.model)}</b></div>
        <div>端点<b class="path">${esc(d.base_url)}</b></div>
        <div>响应<b>${d.ms != null ? d.ms + ' ms' : '—'}</b></div>
        <div>模型数<b>${d.alive ? n : '—'}</b></div>
        <div>模型名<b>${d.model_present == null ? '—' : (d.model_present ? '在清单里' : '不在清单里')}</b></div>
        <div>启用<b>${d.enabled ? '是' : '否'}</b></div>`;
      if (d.alive && n) {
        S.aiModels = d.models;
        fillModelOptions();
      }
      if (d.error) $('#aiTestOut').title = d.error;
    } catch (e) { fail(e); }
  }

  /* ---------------------------------------------------------- 动作绑定 */
  function busy(btn, on) {
    if (!btn) return;
    btn.disabled = on;
    btn.dataset.label = btn.dataset.label || btn.textContent;
    btn.textContent = on ? '执行中…' : btn.dataset.label;
  }

  async function runJob(url, body, opts = {}) {
    const btn = opts.btn;
    busy(btn, true);
    try {
      const { job } = await api(url, { method: 'POST', body });
      trackJob(job, opts.title || job.title, opts.onDone);
      // 快任务（查杀/小目录扫描）可能在 POST 返回前就已跑完，
      // 那条 "job done" 的 WS 事件会因为 "任务还没登记" 被丢掉 —— 这里补一次对账
      setTimeout(() => syncJob(job.id), 400);
      toast(`已提交：${opts.title || job.title}`, '');
      if (opts.onTrack) opts.onTrack(job);
      return job;
    } catch (e) {
      fail(e);
      return null;
    } finally {
      busy(btn, false);
    }
  }

  /* ------------------------------------------------------ WebShell 查杀 */
  async function loadShellRules() {
    try {
      const d = await api('/api/scan/shell/rules');
      S.shellRules = d;
      $('#shRules').textContent = `${d.count} 条规则`;
    } catch (e) { /* 静默：规则库读不到不影响扫描 */ }
  }

  async function showShellRules() {
    try {
      const d = S.shellRules || await api('/api/scan/shell/rules');
      const rows = d.rules.map((r) => `
        <tr>
          <td class="mono">${esc(r.id)}</td>
          <td>${esc(r.name)}</td>
          <td>${sevPill(r.severity)}</td>
          <td class="num">+${r.score}</td>
          <td class="muted">${esc(r.category)}</td>
          <td class="muted sm">${esc(r.mode === 'all' ? '全部匹配' : '任一匹配')}</td>
        </tr>`).join('');
      modal(`规则库 · ${d.count} 条`,
        `<p class="muted sm" style="margin:0 0 10px">${esc(d.path)}</p>
         <div class="table-wrap" style="max-height:420px;overflow:auto">
         <table class="grid"><thead><tr>
           <th style="width:170px">规则</th><th>名称</th><th style="width:80px">级别</th>
           <th style="width:60px">分值</th><th style="width:90px">分类</th><th style="width:80px">模式</th>
         </tr></thead><tbody>${rows}</tbody></table></div>
         <p class="muted sm" style="margin:12px 0 0">
           想加规则直接改上面这个 YAML 文件，保存即生效（每次扫描重新读，不用重启）。
         </p>`);
    } catch (e) { fail(e); }
  }

  function renderShellResult(j) {
    const rows = (j.result && j.result.rows) || [];
    const box = $('#shellResult');
    if (!rows.length) {
      box.innerHTML = '<div class="empty">没有结果</div>';
      return;
    }
    const bad = rows.reduce((a, r) => a + (r.malicious || 0), 0);
    const sus = rows.reduce((a, r) => a + (r.suspicious || 0), 0);
    const files = rows.reduce((a, r) => a + (r.files || 0), 0);
    $('#shSummary').textContent = `${files} 个文件 · 恶意 ${bad} · 可疑 ${sus}`;

    const blocks = rows.map((r) => {
      const err = r.error ? `<div class="empty">${esc(r.error)}</div>` : '';
      const hit = (r.results || []).slice(0, 200);
      if (!hit.length && !err) {
        return `<div class="muted sm" style="padding:6px 2px">
          ${esc(r.target)}：扫了 ${r.files} 个文件，未发现后门特征</div>`;
      }
      return `<div class="muted sm" style="padding:8px 2px 4px">
          <b>${esc(r.target)}</b> · ${r.files} 个文件 · 恶意 ${r.malicious} · 可疑 ${r.suspicious}
          ${r.suspicious_names && r.suspicious_names.length
            ? ' · 可疑文件名 ' + r.suspicious_names.map(esc).join(', ') : ''}
        </div>${err}
        <div class="table-wrap"><table class="grid"><thead><tr>
          <th style="width:64px">判定</th><th style="width:52px">得分</th>
          <th style="width:190px">文件</th><th style="width:300px">命中特征</th><th>片段</th>
        </tr></thead><tbody>${hit.map((f) => `
          <tr>
            <td>${f.verdict === 'malicious'
              ? '<span class="pill high">恶意</span>' : '<span class="pill medium">可疑</span>'}</td>
            <td class="num">${f.score}</td>
            <td class="mono">${esc(f.path)}</td>
            <td>${(f.hits || []).map((h) => `<div class="sm">
                <span class="pill ${h.severity === 'critical' ? 'high' : h.severity === 'medium' ? 'medium' : 'low'}">+${h.score}</span>
                ${esc(h.name)}${h.line ? ` <span class="muted">L${h.line}</span>` : ''}
                ${h.count > 1 ? ` <span class="muted">×${h.count}</span>` : ''}
              </div>`).join('')}</td>
            <td class="mono sm">${esc(((f.hits || [])[0] || {}).snippet || '')}</td>
          </tr>`).join('')}</tbody></table></div>`;
    }).join('<div style="height:10px"></div>');
    box.innerHTML = blocks;
  }


  /* ------------------------------------------------------- 自动作战 */
  function autoSteps(title, steps) {
    if (!steps || !steps.length) return '';
    return `<div class="muted sm" style="margin:10px 0 4px"><b>${esc(title)}</b></div>
      <table class="grid"><thead><tr>
        <th style="width:150px">靶机</th><th style="width:150px">动作</th>
        <th style="width:44px">结果</th><th>说明</th>
      </tr></thead><tbody>${steps.map((r) => `
        <tr>
          <td>${esc(r.target)}</td>
          <td>${esc(r.action)}</td>
          <td>${r.ok ? '<span class="pill ok">✓</span>' : '<span class="pill err">✗</span>'}</td>
          <td class="sm">${esc((r.detail || '').slice(0, 160))}</td>
        </tr>`).join('')}</tbody></table>`;
  }

  function renderAuto(report) {
    const box = $('#autoResult');
    if (!box) return;
    if (!report) {
      box.innerHTML = '<div class="empty">还没有跑过自动作战</div>';
      $('#autoHint').textContent = '防守靶机自动守 · 攻击目标自动打';
      return;
    }
    const d = report.defense, a = report.attack, sub = report.submit;
    $('#autoHint').textContent = report.summary_text || '';
    let html = '';
    if (d) html += autoSteps('防守', d.steps);
    if (a) html += autoSteps('攻击', a.steps);
    const flags = report.flags || [];
    if (flags.length) {
      html += `<div class="muted sm" style="margin:12px 0 4px"><b>拿到 ${flags.length} 个 FLAG</b></div>
        <div class="row" style="gap:6px;flex-wrap:wrap">${flags.map((f) =>
          `<span class="pill ok mono">${esc(f)}</span>`).join('')}</div>`;
    }
    const rows = (sub && sub.submitted) || [];
    if (rows.length) {
      html += `<div class="muted sm" style="margin:12px 0 4px"><b>提交结果</b></div>
        <table class="grid"><thead><tr><th>FLAG</th><th style="width:60px">结果</th><th>平台返回</th></tr></thead>
        <tbody>${rows.map((r) => `<tr>
          <td class="mono">${esc(r.flag)}</td>
          <td>${r.ok ? '<span class="pill ok">成功</span>' : '<span class="pill err">失败</span>'}</td>
          <td class="sm">${esc((r.message || '').slice(0, 120))}</td></tr>`).join('')}</tbody></table>`;
    }
    const errs = report.errors || [];
    if (errs.length) {
      html += `<div class="muted sm" style="margin:10px 0 4px"><b>${errs.length} 处异常</b></div>
        <div class="sm" style="color:#b91c1c">${errs.slice(0, 6).map((e) => esc(String(e).slice(0, 120))).join('<br>')}</div>`;
    }
    box.innerHTML = html || '<div class="empty">没有产生任何动作（检查靶机角色）</div>';
  }

  async function loadAuto() {
    try {
      const d = await api('/api/auto/last');
      renderAuto(d.report);
    } catch (e) { /* 静默 */ }
  }


  /* --------------------------------------------------- 定时作战 + AI 排序 */
  function fillAutoPlugins(names) {
    const sel = $('#autoPlugins');
    if (!sel || sel.dataset.built) return;
    sel.dataset.built = '1';
    sel.innerHTML = '<option value="">全部插件</option>' +
      (names || []).map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
    // 选项是后到的：建好之后要把当前生效的插件重新选上，否则显示"全部"误导
    if (S.autoLoop && S.autoLoop.plugins && S.autoLoop.plugins.length) {
      sel.value = S.autoLoop.plugins[0];
    }
  }

  function renderAutoLoop(st) {
    const pill = $('#autoLoopPill');
    if (!pill) return;
    if (st.plugins && st.plugins.length && $('#autoPlugins')) {
      $('#autoPlugins').value = st.plugins[0];
    }
    if (st.running) {
      pill.className = 'pill ok';
      pill.textContent = `定时中 · 第 ${st.rounds} 轮`;
      $('#btnAutoLoopStart').disabled = true;
      $('#btnAutoLoopStop').disabled = false;
      const last = (st.logs || []).slice(-1)[0];
      $('#autoLoopNext').textContent = `${fmtDur(st.next_in)}后下一轮`
        + (st.plugins && st.plugins.length ? ` · 插件 ${st.plugins.join(', ')}` : ' · 全部插件')
        + (last ? ` · ${last.ts} ${last.msg}` : '');
      const sel = $('#autoInterval');
      if (st.interval && [...sel.options].some((o) => o.value === String(st.interval))) {
        sel.value = String(st.interval);
      }
    } else {
      pill.className = 'pill info';
      pill.textContent = st.rounds ? `已停 · 跑过 ${st.rounds} 轮` : '定时未开';
      $('#btnAutoLoopStart').disabled = false;
      $('#btnAutoLoopStop').disabled = true;
      $('#autoLoopNext').textContent = st.last_summary || '';
    }
  }

  async function loadTriageCache() {
    try {
      const d = await api('/api/ai/triage/last');
      if (d.result) {
        renderTriage($('#aiTriageBox'), { ...(d.result.triage || {}),
          count: d.result.count, model: d.result.model, ts: d.result.ts });
      }
    } catch (e) { /* 静默 */ }
  }

  async function loadAutoLoop() {
    try {
      const st = await api('/api/auto/schedule');
      S.autoLoop = st;
      renderAutoLoop(st);
    } catch (e) { /* 静默 */ }
  }

  function renderTriage(box, data) {
    if (!data) { box.innerHTML = ''; box.classList.add('hidden'); return; }
    const paths = data.paths || [];
    const skip = data.skip || [];
    if (!paths.length) {
      box.innerHTML = '<div class="empty">模型没有给出可执行路径</div>';
      box.classList.remove('hidden');
      return;
    }
    box.innerHTML = `<div class="muted sm" style="margin:6px 0 4px">
        <b>AI 攻击路径排序</b>（${esc(data.model || '本地模型')}，
        ${data.count != null ? `基于 ${data.count} 条发现` : ''}
        ${data.ts ? ` · ${esc(data.ts)}` : ''}）</div>
      <table class="grid"><thead><tr>
        <th style="width:36px">#</th><th style="width:130px">靶机</th>
        <th style="width:56px">类型</th><th style="width:220px">动作</th>
        <th>命令</th><th style="width:56px">把握</th>
      </tr></thead><tbody>${paths.map((p) => `
        <tr>
          <td class="num">${p.rank}</td>
          <td>${esc(p.target)}</td>
          <td>${p.kind ? `<span class="pill ${p.kind.startsWith('处置') ? 'medium' : 'info'}">${esc(p.kind)}</span>` : ''}</td>
          <td class="sm">${esc(p.action)}</td>
          <td class="mono sm">${esc(p.command)}</td>
          <td>${esc(p.score)}</td>
        </tr>`).join('')}</tbody></table>
      ${skip.length ? `<div class="muted sm" style="margin-top:6px">可放弃：${skip.map(esc).join('、')}</div>` : ''}`;
    box.classList.remove('hidden');
    $$('#aiTriageBox .mono').forEach((el) => {
      el.title = el.textContent;
      el.style.cursor = 'copy';
      el.onclick = () => navigator.clipboard?.writeText(el.textContent)
        .then(() => toast('命令已复制', 'ok')).catch(() => {});
    });
  }

  function bindActions() {
    $$('.nav-item').forEach((b) => { b.onclick = () => go(b.dataset.view); });
    $$('[data-refresh]').forEach((b) => { b.onclick = () => refreshView(); });
    initFolds();
    // 日志/流量：路径框直接拖文件或文件夹进来
    enablePathDrop($('#lgPaths'), { multiple: true });
    enablePathDrop($('#tpPath'), { multiple: false });
    // 拖到页面其它地方不要被浏览器当成"打开文件"跳走
    ['dragover', 'drop'].forEach((ev) => document.addEventListener(ev, (e) => {
      if (e.target && e.target.closest && e.target.closest('input[data-drop]')) return;
      if (e.target && e.target.tagName === 'INPUT') return;
      e.preventDefault();
    }));
    $('#modalClose').onclick = closeModal;
    $('#modal').onclick = (e) => { if (e.target.id === 'modal') closeModal(); };
    $('#dockClose').onclick = () => { S.jobs.clear(); S.activeJob = null; $('#dock').classList.add('hidden'); };
    $('#dockToggle').onclick = () => $('#dock').classList.toggle('min');
    $('#dockTabs').onclick = (e) => {
      const t = e.target.closest('[data-job]');
      if (!t) return;
      S.activeJob = t.dataset.job;
      renderDock(true);
    };

    // 总览快速动作
    $$('[data-quick]').forEach((b) => {
      b.onclick = () => {
        const q = b.dataset.quick;
        if (q === 'backup') {
          runJob('/api/backup/run', { targets: null, tag: 'baseline', db: true },
            { title: '备份全部靶机', btn: b, onDone: (j) => loadBackups() });
        } else if (q === 'ports') {
          go('scan');
          setTimeout(() => $('[data-scan="ports"]').click(), 120);
        } else if (q === 'web') {
          go('scan');
          setTimeout(() => $('[data-scan="web"]').click(), 120);
        } else if (q === 'flag') {
          go('flag');
          setTimeout(() => $('#btnHunt').click(), 120);
        } else if (q === 'snapshot') {
          runJob('/api/ssh/snapshot', { targets: null },
            { title: '现场快照', btn: b, onDone: () => loadArtifacts() });
        } else if (q === 'report') {
          go('report');
        }
      };
    });

    // 靶机
    $('#targetForm').onsubmit = async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      const body = Object.fromEntries(f.entries());
      try {
        const d = await api('/api/targets', { method: 'POST', body });
        S.targets = d.targets;
        toast('已添加靶机', 'ok');
        e.target.reset();
        loadTargets();
        loadOverview(true);
        renderAllChips();
      } catch (err) { fail(err); }
    };

    // SSH
    $('#btnSshRun').onclick = () => {
      const cmd = $('#sshCmd').value.trim();
      if (!cmd) return toast('请先输入命令', 'warn');
      runJob('/api/ssh/exec', {
        targets: pickTargets('ssh'), cmd, sudo: $('#sshSudo').checked,
        timeout: Number($('#sshTimeout').value) || 60,
      }, {
        title: 'SSH 执行', btn: $('#btnSshRun'),
        onDone: (j) => {
          const rows = (j.result && j.result.results) || [];
          $('#sshResult').innerHTML = rows.length ? rows.map((r) => `
            <div class="out-item">
              <div class="out-head">
                <b>${esc(r.target)}</b>
                <span class="pill ${r.ok ? 'ok' : 'err'}">${r.error ? '连接失败' : 'rc=' + r.rc}</span>
                <span class="muted sm">${r.elapsed}s</span>
                <span class="muted sm mono">${esc(r.host || '')}</span>
              </div>
              <pre class="out-body">${esc(r.error || (r.out + (r.err ? '\n' + r.err : '')) || '(无输出)')}</pre>
            </div>`).join('') : '<div class="empty">没有输出</div>';
        },
      });
    };
    $('#btnSshClear').onclick = () => { $('#sshResult').innerHTML = '<div class="empty">尚无输出</div>'; };

    // 备份
    $('#btnBackup').onclick = () => runJob('/api/backup/run', {
      targets: pickTargets('backup'), tag: $('#bkTag').value.trim() || 'snapshot',
      db: $('#bkDb').checked,
    }, { title: '业务备份', btn: $('#btnBackup'), onDone: () => loadBackups() });


    // 扫描
    $$('[data-scan]').forEach((b) => {
      b.onclick = () => {
        const kind = b.dataset.scan;
        const url = { ports: '/api/scan/ports', web: '/api/scan/web', vulns: '/api/scan/vulns' }[kind];
        const body = { targets: pickTargets('scan') };
        if (kind === 'ports') body.ports = $('#scPorts').value.trim();
        if (kind === 'vulns') body.severity = $('#scSev').value.trim();
        const titles = { ports: '端口扫描', web: 'Web 指纹', vulns: '漏洞模板扫描' };
        runJob(url, body, {
          title: titles[kind], btn: b,
          onDone: () => { loadFindings(); loadOverview(true); },
        });
      };
    });
    $('#sevFilter').onchange = () => { FD.offset = 0; loadFindings(); };
    if ($('#fdLimit')) {
      $('#fdLimit').onchange = () => { FD.offset = 0; loadFindings(); };
    }

    // WebShell 查杀
    $('#btnShRules').onclick = showShellRules;
    $('#btnShScan').onclick = () => {
      const path = $('#shPath').value.trim();
      runJob('/api/scan/shell', {
        path, targets: path ? null : pickTargets('scan'),
      }, {
        title: 'WebShell 查杀', btn: $('#btnShScan'),
        onDone: (j) => { renderShellResult(j); loadFindings(); loadOverview(true); },
      });
    };
    loadShellRules();

    // 利用
    $('#exPlugin').onchange = updatePluginDesc;
    $('#btnExploit').onclick = () => runJob('/api/exploit/run', {
      plugin: $('#exPlugin').value, targets: pickTargets('exploit'),
      check_only: $('#exCheck').checked,
    }, {
      title: '批量利用', btn: $('#btnExploit'),
      onDone: (j) => { renderExploitResult(j); loadFlags(); loadOverview(true); },
    });

    // FLAG
    $('#btnHunt').onclick = () => runJob('/api/flag/hunt', {
      targets: pickTargets('flag'), submit: $('#flSubmit').checked,
    }, { title: 'FLAG 检索', btn: $('#btnHunt'), onDone: () => { loadFlags(); loadOverview(true); } });
    // 自动作战
    const autoRun = (phases, title) => runJob('/api/auto/run', {
      phases,
      backup: $('#autoBackup').checked,
      shell: $('#autoShell').checked,
      replay: $('#autoReplay').checked,
    }, {
      title, btn: $('#btnAutoAll'),
      onDone: () => { loadAuto(); loadFindings(); loadFlags(); loadBackups();
                      loadOverview(true); },
    });
    $('#btnAutoAll').onclick = () => autoRun(['defense', 'attack', 'submit'], '自动作战 · 全流程');
    $('#btnAutoDef').onclick = () => autoRun(['defense'], '自动作战 · 防守');
    $('#btnAutoAtk').onclick = () => autoRun(['attack', 'submit'], '自动作战 · 攻击');
    $('#btnAutoRefresh').onclick = loadAuto;
    loadAuto();

    // 定时自动作战
    $('#btnAutoLoopStart').onclick = async () => {
      try {
        const one = $('#autoPlugins') ? $('#autoPlugins').value : '';
        const st = await api('/api/auto/schedule/start', { method: 'POST', body: {
          interval: Number($('#autoInterval').value) || 900,
          phases: ['defense', 'attack', 'submit'],
          plugins: one ? [one] : [],
        } });
        toast(`定时作战已启动：每 ${fmtDur(st.interval)} 一轮`, 'ok');
        renderAutoLoop(st);
      } catch (e) { fail(e); }
    };
    $('#btnAutoLoopStop').onclick = async () => {
      try {
        const st = await api('/api/auto/schedule/stop', { method: 'POST', body: {} });
        toast('已停止定时作战', 'ok');
        renderAutoLoop(st);
        loadAuto();
      } catch (e) { fail(e); }
    };
    loadAutoLoop();
    loadTriageCache();
    setInterval(() => {
      if (S.autoLoop && S.autoLoop.running) {
        S.autoLoop.next_in = Math.max(0, (S.autoLoop.next_in || 0) - 5);
        $('#autoLoopNext').textContent = `${fmtDur(S.autoLoop.next_in)}后下一轮`;
        if (S.autoLoop.next_in <= 0) { loadAutoLoop(); loadAuto(); }
      }
    }, 5000);

    // AI 排序
    $('#btnAiTriage').onclick = () => {
      const box = $('#aiTriageBox');
      box.classList.add('hidden');
      runJob('/api/ai/triage', { limit: 200 }, {
        title: 'AI 攻击路径排序', btn: $('#btnAiTriage'),
        onDone: (j) => {
          const r = j.result || {};
          const d = r.triage ? { ...r.triage, count: r.count, model: r.model } : null;
          renderTriage(box, d);
          toast(d && d.paths && d.paths.length ? `给出 ${d.paths.length} 条路径` : '没有可用路径',
                d && d.paths && d.paths.length ? 'ok' : 'warn');
        },
      });
    };

    // 提交接口
    $('#btnSpParse').onclick = spParse;
    $('#btnSpSave').onclick = spSave;
    $('#btnSpReload').onclick = spLoad;
    $('#spCurl').addEventListener('paste', () => setTimeout(() => {
      if (($('#spCurl').value || '').trim().startsWith('curl')) spParse();
    }, 60));
    spLoad();

    // 轮次监控
    $('#btnRdStart').onclick = async () => {
      try {
        const st = await api('/api/round/start', { method: 'POST', body: {
          interval: Number($('#rdInterval').value) || 300,
          auto_submit: $('#rdAuto').checked,
          deep: $('#rdDeep').checked,
        } });
        toast(`轮次监控已启动：每 ${fmtDur(st.interval)} 检查一次`, 'ok');
        loadRoundState();
      } catch (e) { fail(e); }
    };
    $('#btnRdStop').onclick = async () => {
      try {
        await api('/api/round/stop', { method: 'POST', body: {} });
        toast('已停止轮次监控', 'ok');
        loadRoundState();
      } catch (e) { fail(e); }
    };
    $('#btnRdTick').onclick = async () => {
      const btn = $('#btnRdTick');
      busy(btn, true);
      try {
        const d = await api('/api/round/tick', { method: 'POST', body: {} });
        const changed = (d.events || []).filter((e) => e.changed);
        const total = changed.reduce((a, e) => a + e.new_flags.length, 0);
        toast(total ? `发现 ${total} 个新 FLAG` : '检查完成，没有新 FLAG',
              total ? 'ok' : 'warn');
        changed.forEach((e) => (e.new_flags || []).forEach((f) => toast(`${e.target}: ${f}`, 'ok')));
        loadRoundState(); loadRounds(); loadFlags(); loadOverview(true);
      } catch (e) { fail(e); } finally { busy(btn, false); }
    };
    $('#btnRdReset').onclick = async () => {
      if (!await ask('清空已知 FLAG', '清空后旧的 flag 会被当成"新"再提交一次，仅在新场次开始时使用。', '清空')) return;
      try {
        await api('/api/round/reset', { method: 'POST', body: {} });
        toast('已清空', 'ok');
        loadRoundState(); loadRounds();
      } catch (e) { fail(e); }
    };

    $('#btnSubmitFlags').onclick = () => runJob('/api/flag/submit', { all: false },
      { title: '提交 FLAG', btn: $('#btnSubmitFlags'), onDone: () => loadFlags() });

    // 日志
    $('#btnPull').onclick = () => runJob('/api/logs/pull', {
      targets: pickTargets('logs'), analyze: true,
    }, { title: '日志取证', btn: $('#btnPull'), onDone: (j) => {
      const t = (j.result && j.result.targets) || [];
      const findings = [];
      const stats = {};
      t.forEach((x) => { stats[x.target] = `${x.files} 个文件 / ${x.findings} 项发现`; });
      $('#logResult').innerHTML = `${statKv(stats)}
        ${t.map((x) => `<h3 style="font-size:12px;margin:14px 0 6px">${esc(x.target)} · ${x.files} 文件 · ${x.findings} 项发现</h3>
          <pre class="answer">${esc(x.text || '')}</pre>`).join('')}`;
      loadFindings();
    } });
    $('#btnLogAnalyze').onclick = () => {
      const raw = $('#lgPaths').value.trim();
      const paths = raw ? raw.split(',').map((s) => s.trim()).filter(Boolean) : [];
      runJob('/api/logs/analyze', { paths, ai: $('#lgAi').checked },
        { title: '日志分析', btn: $('#btnLogAnalyze'), onDone: renderLogResult });
    };

    // 流量
    $('#btnPcap').onclick = () => {
      const p = $('#tpPath').value.trim();
      if (!p) return toast('请填写 pcap 路径', 'warn');
      runJob('/api/traffic/analyze', { path: p, ai: $('#tpAi').checked },
        { title: '流量分析', btn: $('#btnPcap'), onDone: renderTrafficResult });
    };

    // 取证
    $('#shotForm').onsubmit = async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        const d = await api('/api/shot/capture', {
          method: 'POST', body: Object.fromEntries(f.entries()),
        });
        toast(d.msg, d.ok ? 'ok' : 'warn');
        loadShots();
      } catch (err) { fail(err); }
    };
    $('#markForm').onsubmit = async (e) => {
      e.preventDefault();
      const f = new FormData(e.target);
      try {
        await api('/api/shot/mark', { method: 'POST', body: Object.fromEntries(f.entries()) });
        toast('已登记', 'ok');
        e.target.reset();
        loadShots();
      } catch (err) { fail(err); }
    };
    $('#btnTimeline').onclick = async () => {
      try {
        const d = await api('/api/shot/timeline', { method: 'POST', body: { title: '作战时间线' } });
        $('#timelinePreview').innerHTML = `<pre class="answer">${esc(d.content)}</pre>`;
        toast('timeline.md 已生成', 'ok');
        loadShots();
      } catch (e) { fail(e); }
    };

    // AI
    $('#btnAiModels').onclick = pullAiModels;
    $('#btnAiTest').onclick = testAi;
    $('#btnAiSave').onclick = saveAiConfig;
    if ($('#btnAiModelHand')) $('#btnAiModelHand').onclick = handFillModel;
    if ($('#aiModelSel')) {
      $('#aiModelSel').onchange = () => {
        $('#aiModel').value = $('#aiModelSel').value;
        $('#aiModel').classList.add('hidden');   // 选了清单里的就收起手填框
      };
    }
    // 靶机页：接口配置
    $('#btnIfaceSave').onclick = saveIface;
    $('#btnIfaceReload').onclick = loadIface;
    $('#ifFsMode').onchange = fsModeToggle;
    // flag 页：flagserver 快捷操作
    $('#btnFsFetch').onclick = fetchFlagServer;
    $('#btnFsDebug').onclick = debugFlagServer;
    $('#btnFsCfg').onclick = () => go('targets');
    $('#btnAsk').onclick = () => {
      const prompt = $('#aiPrompt').value.trim();
      if (!prompt) return toast('请输入问题', 'warn');
      const files = $('#aiFiles').value.split(',').map((s) => s.trim()).filter(Boolean);
      $('#aiAnswer').textContent = '思考中…';
      runJob('/api/ai/ask', { prompt, files }, {
        title: 'AI 研判', btn: $('#btnAsk'),
        onDone: (j) => {
          const r = j.result || {};
          $('#aiAnswer').textContent = r.ok ? r.text : `模型不可用：${r.error}`;
        },
      });
    };
    $('#btnAudit').onclick = () => {
      const path = $('#aiAuditPath').value.trim();
      if (!path) return toast('请填写源码路径', 'warn');
      $('#aiAnswer').textContent = '审计中…';
      runJob('/api/ai/audit', { path }, {
        title: '源码审计', btn: $('#btnAudit'),
        onDone: (j) => {
          const r = j.result || {};
          $('#aiAnswer').textContent = r.ok ? r.text : `模型不可用：${r.error}`;
        },
      });
    };

    // 批量添加靶机
    $('#btnBulkAdd').onclick = async () => {
      const text = $('#bulkText').value.trim();
      if (!text) return toast('请粘贴 IP / 域名列表', 'warn');
      try {
        const d = await api('/api/targets/bulk', { method: 'POST', body: {
          text, role: $('#bulkRole').value, user: $('#bulkUser').value.trim() || 'root',
          password: $('#bulkPwd').value, ssh_port: Number($('#bulkPort').value) || 22,
        } });
        $('#bulkHint').textContent = `新增 ${d.added_count} 个` +
          (d.skipped.length ? `，跳过 ${d.skipped.length}` : '') +
          (d.errors.length ? `，无效 ${d.errors.length}` : '');
        toast(`已添加 ${d.added_count} 个目标`, 'ok');
        $('#bulkText').value = '';
        S.targets = d.targets;
        S.selection = {};
        loadTargets();
        renderAllChips();
        loadOverview(true);
      } catch (e) { fail(e); }
    };

    // 防护
    // 封禁面板
    if ($('#banTargets')) renderChips($('#banTargets'), 'ban', banCaps);
    if ($('#btnBanCaps')) $('#btnBanCaps').onclick = banCaps;
    if ($('#btnBanList')) $('#btnBanList').onclick = banList;
    if ($('#btnBan')) $('#btnBan').onclick = () => banRun(false);
    if ($('#btnUnban')) $('#btnUnban').onclick = () => banRun(true);
    // 修补面板
    if ($('#btnHardenPlan')) {
      $('#btnHardenPlan').onclick = () => runJob('/api/harden/plan',
        { targets: pickTargets('harden') },
        { title: '漏洞修补方案', btn: $('#btnHardenPlan'), onDone: renderHarden });
    }
    if ($('#btnHardenSafe')) {
      $('#btnHardenSafe').onclick = () => {
        if (!HARDEN.actions.length) return toast('先生成方案', 'warn');
        HARDEN.picked = new Set(HARDEN.actions.filter((a) => a.auto).map((a) => a.id));
        drawHarden();
        hardenApply(false);
      };
    }
    if ($('#btnHardenApply')) $('#btnHardenApply').onclick = () => hardenApply(false);
    $('#btnWafDeploy').onclick = () => {
      const logs = $('#wfLogs').value.split(',').map((x) => x.trim()).filter(Boolean);
      runJob('/api/waf/deploy', {
        targets: pickTargets('waf'), mode: $('#wfMode').value,
        logs, autoban: $('#wfAutoban').checked, engine: $('#wfEngine').value,
      }, { title: '部署 WAF', btn: $('#btnWafDeploy'), onDone: loadWafStatus });
    };
    $('#btnWafStatus').onclick = loadWafStatus;
    $('#btnWafStop').onclick = async () => {
      if (!await ask('停止 WAF', '停止后不再记录攻击，已封禁的 IP 保留（可在靶机上 iptables -F 清空）。', '停止')) return;
      runJob('/api/waf/stop', { targets: pickTargets('waf') },
        { title: '停止 WAF', btn: $('#btnWafStop'), onDone: loadWafStatus });
    };
    $('#btnWafAudit').onclick = auditWaf;
    $('#btnWafToVuln').onclick = wafToVuln;
    $('#btnWafHarden').onclick = hardenWaf;
    $('#btnVulnRefresh').onclick = loadVulns;
    $('#btnVulnReplay').onclick = () => replayVulns(null);

    // AI 写插件
    $('#btnPlGen').onclick = generatePlugin;
    $('#btnPlInstall').onclick = installPlugin;
    $('#btnPlDrafts').onclick = showDrafts;

    // 终端
    $('#btnBroadcast').onclick = () => {
      const input = $('#tmBroadcast');
      const cmd = input.value.trim();
      if (!cmd) return toast('请输入命令', 'warn');
      input.value = '';
      broadcast(cmd);
    };
    $('#tmBroadcast').onkeydown = (e) => {
      if (e.key === 'Enter') $('#btnBroadcast').click();
    };
    $('#btnTermReset').onclick = async () => {
      try {
        const d = await api('/api/term/reset', { method: 'POST', body: {} });
        toast(`已断开 ${d.closed} 个会话`, 'ok');
        $$('#termGrid .term-out').forEach((el) => { el.innerHTML = ''; });
        $$('#termGrid .dot').forEach((el) => { el.className = 'dot'; });
      } catch (e) { fail(e); }
    };
    $$('[data-quick-cmd]').forEach((b) => {
      b.onclick = () => broadcast(b.dataset.quickCmd);
    });

    // 批量操作
    $('#btnBatchRole').onclick = () =>
      batchTargets('role', $('#batchRole').value,
        `把已选 ${selectedTargetNames().length} 台靶机的角色统一改为「${
          $('#batchRole').value === 'attack' ? '攻击目标' : '防守靶机'}」？`);
    $('#btnBatchWebroot').onclick = async () => {
      const n = selectedTargetNames().length;
      const v = await promptModal('批量改备份源',
        `为已选 ${n} 台靶机设置同一个备份源目录（留空 = 恢复自动探测）。`, '/www/wwwroot/site');
      if (v === null) return;
      batchTargets('webroot', v.trim(), null);
    };
    $('#btnBatchDelete').onclick = () =>
      batchTargets('delete', null,
        `从配置里移除已选 ${selectedTargetNames().length} 台靶机？历史备份/发现/FLAG 记录会保留。`);

    // 备份源
    $('#btnSrcDetect').onclick = () => detectSources(null);

    // 备份目录
    $('#btnBkPath').onclick = () => {
      const p = $('#bkPath').value.trim();
      if (!p) return toast('请填写目录', 'warn');
      saveBackupPath(p);
    };
    $('#btnBkPathReset').onclick = () => {
      const p = (S.backupCfg && S.backupCfg.default) || 'backups';
      saveBackupPath(p);
    };

    // 报告
    $('#btnReport').onclick = async () => {
      busy($('#btnReport'), true);
      try {
        const d = await api('/api/report', {
          method: 'POST', body: { title: $('#reportTitle').value.trim() },
        });
        $('#reportPreview').textContent = d.markdown;
        toast('报告已生成', 'ok');
        loadArtifacts();
        loadOverview(true);
      } catch (e) { fail(e); } finally { busy($('#btnReport'), false); }
    };

    window.addEventListener('hashchange', () => {
      const v = location.hash.replace('#', '');
      if (TITLES[v] && v !== S.view) go(v);
    });
  }

  function renderAllChips() {
    renderChips($('#sshTargets'), 'ssh');
    renderChips($('#bkTargets'), 'backup');
    renderChips($('#scTargets'), 'scan');
    renderChips($('#exTargets'), 'exploit');
    renderChips($('#flTargets'), 'flag');
    renderChips($('#lgTargets'), 'logs');
    renderChips($('#tmTargets'), 'term', renderTerminal);
    renderChips($('#wfTargets'), 'waf');
  }


  /* ------------------------------------------------------- WebSocket 推送 */
  function setWs(state, text) {
    const el = $('#wsChip');
    if (!el) return;
    el.className = 'ws-chip ' + state;
    el.innerHTML = `<i></i>${text}`;
    S.wsLive = state === 'live';
  }

  function connectWS() {
    if (S.wsClosed) return;
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    let ws;
    try {
      ws = new WebSocket(`${proto}://${location.host}/ws`);
    } catch (e) {
      return scheduleReconnect();
    }
    S.ws = ws;
    ws.onopen = () => {
      S.wsTries = 0;
      setWs('live', '实时');
      if (S.pollTimer) { clearInterval(S.pollTimer); S.pollTimer = null; }
      if (S.pingTimer) clearInterval(S.pingTimer);
      S.pingTimer = setInterval(() => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'ping' }));
      }, 25000);
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      handleWs(msg);
    };
    ws.onclose = () => { scheduleReconnect(); };
    ws.onerror = () => { try { ws.close(); } catch (e) { /* ignore */ } };
  }

  function scheduleReconnect() {
    if (S.wsClosed) return;
    S.wsTries += 1;
    if (S.wsTries <= 6) {
      setWs('fallback', '重连中');
      setTimeout(connectWS, Math.min(800 * S.wsTries, 4000));
    } else {
      setWs('fallback', '轮询');
      ensurePolling();
      setTimeout(connectWS, 20000);
    }
  }

  function handleWs(msg) {
    if (msg.type === 'hello') {
      // 只接管仍在跑的任务，已完成的不要自动弹抽屉打扰
      (msg.jobs || []).filter((j) => j.status === 'queued' || j.status === 'running')
        .forEach((j) => {
          if (!S.jobs.has(j.id)) {
            S.jobs.set(j.id, { id: j.id, title: j.title, kind: j.kind, status: j.status,
              logs: (j.logs || []).slice(), count: (j.logs || []).length,
              elapsed: j.elapsed || 0, result: null,
              error: j.error || '', onDone: null, _finalized: false });
          }
        });
      if (!S.activeJob && S.jobs.size) S.activeJob = [...S.jobs.keys()].pop();
      renderDock(true);
      return;
    }
    if (msg.type === 'log') {
      let j = S.jobs.get(msg.job);
      if (!j) {
        j = { id: msg.job, title: msg.title || '任务', kind: msg.kind || '',
          status: 'running', logs: [], count: 0, elapsed: 0, result: null,
          error: '', onDone: null, _finalized: false };
        S.jobs.set(msg.job, j);
      }
      j.logs.push(msg.entry);
      j.count = j.logs.length;
      if (!S.activeJob) S.activeJob = j.id;
      if (S.activeJob === j.id) appendDockLog([msg.entry]);
      renderDock();
      return;
    }
    if (msg.type === 'job') {
      const j = S.jobs.get(msg.job.id);
      if (!j) return;
      const prev = j.status;
      j.status = msg.job.status;
      j.elapsed = msg.job.elapsed;
      j.error = msg.job.error || '';
      renderDock();
      if ((j.status === 'done' || j.status === 'failed') && prev !== j.status) {
        // 结果可能几百 KB，走一次 HTTP 拉取，别塞进 WS 帧
        api(`/api/jobs/${j.id}`)
          .then((d) => { j.result = d.job.result; })
          .catch(() => {})
          .finally(() => finalizeJob(j));
      }
    }
  }

  /* ------------------------------------------------------------ 多机终端 */
  function termNames() {
    const sel = (S.selection.term || []).slice(0, TERM.max);
    if (sel.length) return sel;
    return S.targets.slice(0, Math.min(4, S.targets.length)).map((t) => t.name);
  }

  function cellOf(name) {
    return $$('#termGrid .term-cell').find((el) => el.dataset.target === name);
  }

  function termCell(name, t) {
    const cell = document.createElement('div');
    cell.className = 'term-cell';
    cell.dataset.target = name;
    cell.innerHTML = `
      <div class="term-head">
        <span class="dot"></span><b>${esc(name)}</b>
        <span class="host">${esc(t.user || '')}@${esc(t.host || '')}</span>
        <span class="spacer"></span>
        <button data-act="clear">清空</button>
        <button data-act="reset">重连</button>
      </div>
      <pre class="term-out"></pre>
      <div class="term-in"><span class="prompt">$</span>
        <input placeholder="输入命令，回车执行" autocomplete="off" spellcheck="false"></div>`;

    const input = cell.querySelector('input');
    const out = cell.querySelector('.term-out');
    cell.querySelector('[data-act=clear]').onclick = () => { out.innerHTML = ''; };
    cell.querySelector('[data-act=reset]').onclick = () => {
      out.innerHTML += '<span class="e">— 重新连接 —</span>\n';
      api('/api/term/reset', { method: 'POST', body: { targets: [name] } })
        .then(() => runInCell(name, 'id')).catch(fail);
    };
    input.onkeydown = (ev) => {
      const hist = TERM.hist[name] || (TERM.hist[name] = []);
      if (ev.key === 'Enter') {
        const cmd = input.value.trim();
        if (!cmd) return;
        input.value = '';
        hist.push(cmd);
        if (hist.length > 60) hist.shift();
        TERM.hist[name] = hist;
        TERM.histIdx = undefined;
        runInCell(name, cmd);
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        if (!hist.length) return;
        TERM.histIdx = TERM.histIdx == null ? hist.length - 1 : Math.max(0, TERM.histIdx - 1);
        input.value = hist[TERM.histIdx] || '';
      } else if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        if (!hist.length) return;
        TERM.histIdx = TERM.histIdx == null ? hist.length - 1 : Math.min(hist.length - 1, TERM.histIdx + 1);
        input.value = hist[TERM.histIdx] || '';
      }
    };
    return cell;
  }

  function renderTerminal() {
    const grid = $('#termGrid');
    if (!grid) return;
    const names = termNames();
    $('#termHint').textContent = names.length
      ? `${names.length} 台同时在线 · 最多 ${TERM.max} 台` : `最多 ${TERM.max} 台`;
    if (!names.length) {
      grid.innerHTML = '<div class="empty">没有靶机，先去「靶机」页添加</div>';
      return;
    }
    const keep = new Map($$('#termGrid .term-cell').map((el) => [el.dataset.target, el]));
    grid.innerHTML = '';
    names.forEach((name) => {
      const t = S.targets.find((x) => x.name === name) || { name, host: '', user: '' };
      grid.appendChild(keep.get(name) || termCell(name, t));
    });
  }

  function setDot(cell, cls) {
    const dot = cell.querySelector('.dot');
    if (dot) dot.className = 'dot ' + (cls || '');
  }

  function appendTerm(cell, text, cls) {
    const out = cell.querySelector('.term-out');
    const nearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 60;
    const span = document.createElement('span');
    if (cls) span.className = cls;
    span.textContent = text;
    out.appendChild(span);
    if (nearBottom) out.scrollTop = out.scrollHeight;
  }

  async function runInCell(name, cmd) {
    const cell = cellOf(name);
    if (!cell) return;
    const input = cell.querySelector('input');
    appendTerm(cell, `$ ${cmd}\n`, 'c');
    input.disabled = true;
    setDot(cell, 'busy');
    try {
      const d = await api('/api/term/exec', {
        method: 'POST', body: { targets: [name], cmd, timeout: 30 },
      });
      const r = (d.results || [])[0];
      renderTermResult(cell, r);
    } catch (e) {
      appendTerm(cell, `${e.message}\n`, 'e');
      setDot(cell, 'err');
    } finally {
      input.disabled = false;
      input.focus();
    }
  }

  function renderTermResult(cell, r) {
    if (!r) return;
    if (r.error) {
      appendTerm(cell, `[错误] ${r.error}\n`, 'e');
      setDot(cell, 'err');
      return;
    }
    if (r.output) appendTerm(cell, r.output.endsWith('\n') ? r.output : r.output + '\n');
    if (r.rc !== 0) appendTerm(cell, `[rc=${r.rc}]\n`, 'e');
    setDot(cell, 'on');
  }

  async function broadcast(cmd) {
    const names = termNames();
    if (!names.length) return toast('没有选择靶机', 'warn');
    if (!cmd.trim()) return;
    const cells = names.filter((n) => cellOf(n));
    cells.forEach((n) => appendTerm(cellOf(n), `$ ${cmd}\n`, 'c'));
    try {
      const d = await api('/api/term/exec', {
        method: 'POST', body: { targets: names, cmd, timeout: 30 },
      });
      (d.results || []).forEach((r) => renderTermResult(cellOf(r.target), r));
    } catch (e) {
      cells.forEach((n) => appendTerm(cellOf(n), `${e.message}\n`, 'e'));
    }
  }


  /* ------------------------------------------------------- 备份源（打什么） */
  async function loadSources() {
    const box = $('#srcTable');
    if (!box) return;
    try {
      const { sources } = await api('/api/backup/sources');
      S.sources = sources;
      renderSources();
    } catch (e) {
      box.innerHTML = `<div class="empty">读取失败：${esc(e.message)}</div>`;
    }
  }

  function renderSources() {
    const box = $('#srcTable');
    const rows = S.sources || [];
    if (!rows.length) {
      box.innerHTML = '<div class="empty">没有防守靶机，先去「靶机」页添加</div>';
      return;
    }
    $('#srcHint').textContent = `${rows.filter((r) => r.mode === 'manual').length} 台手动指定`;
    box.innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
      <th style="width:170px">靶机</th><th>源目录（远端绝对路径）</th>
      <th style="width:90px">模式</th><th style="width:190px">操作</th>
    </tr></thead><tbody>${rows.map((r) => `
      <tr data-src-row="${esc(r.target)}">
        <td><b>${esc(r.target)}</b><div class="muted sm mono">${esc(r.user)}@${esc(r.host)}</div></td>
        <td>
          <input class="src-input" data-src-input="${esc(r.target)}"
                 value="${esc(r.configured)}"
                 placeholder="${esc(r.detected || '留空 = 自动探测（nginx/apache 配置或常见目录）')}">
          ${r.detected && r.detected !== r.configured
            ? `<div class="muted sm mono">探测到：${esc(r.detected)}</div>` : ''}
        </td>
        <td>${r.mode === 'manual'
          ? '<span class="pill info">手动</span>' : '<span class="pill low">自动</span>'}</td>
        <td><div class="row-actions">
          <button class="btn ghost xs" data-src-save="${esc(r.target)}">保存</button>
          <button class="btn ghost xs" data-src-auto="${esc(r.target)}">恢复自动</button>
          <button class="btn ghost xs" data-src-detect="${esc(r.target)}">探测</button>
        </div></td>
      </tr>`).join('')}</tbody></table></div>`;

    $$('#srcTable [data-src-save]').forEach((b) => {
      b.onclick = () => {
        const input = $$('#srcTable [data-src-input]').find((i) => i.dataset.srcInput === b.dataset.srcSave);
        saveSource(b.dataset.srcSave, input ? input.value.trim() : '');
      };
    });
    $$('#srcTable [data-src-auto]').forEach((b) => {
      b.onclick = async () => {
        if (!await ask('恢复自动探测', `清除 ${b.dataset.srcAuto} 的手动源目录，改回按 nginx/apache 配置自动探测？`, '恢复自动')) return;
        saveSource(b.dataset.srcAuto, '');
      };
    });
    $$('#srcTable [data-src-detect]').forEach((b) => {
      b.onclick = () => detectSources([b.dataset.srcDetect]);
    });
  }

  async function saveSource(target, path) {
    try {
      const d = await api('/api/backup/source', { method: 'POST', body: { target, path } });
      const bits = [`${target} 备份源：${d.path || '自动探测'}`];
      if (d.warning) bits.push(d.warning);
      else if (d.verified === true) bits.push('已验证目录存在' + (d.detail ? `（${d.detail}）` : ''));
      toast(bits.join(' · '), d.warning ? 'warn' : 'ok');
      await loadSources();
      loadTargets();
    } catch (e) { fail(e); }
  }

  async function detectSources(targets) {
    const btn = $('#btnSrcDetect');
    if (btn) busy(btn, true);
    try {
      const d = await api('/api/backup/sources/detect', {
        method: 'POST', body: { targets: targets || null },
      });
      const okRows = (d.results || []).filter((r) => r.detected);
      toast(`探测完成：${okRows.length}/${(d.results || []).length} 台有结果`,
        okRows.length ? 'ok' : 'warn');
      await loadSources();
      // 把探测结果填进空输入框，方便一键保存
      $$('#srcTable [data-src-input]').forEach((i) => {
        const hit = (d.results || []).find((r) => r.target === i.dataset.srcInput);
        if (hit && hit.detected && !i.value) i.value = hit.detected;
      });
    } catch (e) { fail(e); } finally { if (btn) busy(btn, false); }
  }

  /* ------------------------------------------------------- 备份目录设置 */
  async function loadBackupConfig() {
    try {
      const d = await api('/api/backup/config');
      $('#bkPath').value = d.path;
      $('#bkPathInfo').innerHTML = `
        <div>当前目录<b class="path">${esc(d.path)}</b></div>
        <div>可写<b>${d.writable ? '是' : '否'}</b></div>
        <div>剩余空间<b>${esc(d.free_h || '—')}</b></div>
        <div>默认路径<b class="path">${esc(d.default)}</b></div>`;
      S.backupCfg = d;
    } catch (e) { fail(e); }
  }

  async function saveBackupPath(path) {
    try {
      const d = await api('/api/backup/config', { method: 'POST', body: { path } });
      toast(`备份目录已切换到 ${d.path}`, 'ok');
      await loadBackupConfig();
    } catch (e) { fail(e); }
  }


  /* ------------------------------------------------ 防护：WAF / 漏洞库 */
  function wafTable(rows) {
    return `<div class="table-wrap"><table class="grid"><thead><tr>
      <th>靶机</th><th style="width:110px">状态</th><th style="width:130px">引擎</th><th style="width:90px">模式</th>
      <th style="width:80px">请求</th><th style="width:80px">命中</th>
      <th style="width:80px">封禁</th><th style="width:90px">运行</th><th>日志</th>
    </tr></thead><tbody>${rows.map((r) => `
      <tr>
        <td><b>${esc(r.target)}</b><div class="muted sm mono">${esc(r.host || '')}</div></td>
        <td>${r.running ? '<span class="pill ok">运行中</span>'
          : `<span class="pill err">未部署</span>${r.error ? `<div class="muted sm">${esc(r.error.slice(0, 60))}</div>` : ''}`}</td>
        <td>${!r.running ? '<span class="muted">—</span>'
          : r.engine === 'php' ? '<span class="pill info">PHP</span>'
          : r.engine === 'go' ? '<span class="pill ok">Go</span>'
          : r.engine === 'python' ? '<span class="pill low">python</span>' : '—'}
          ${r.webroot ? `<div class="muted sm mono">${esc(r.webroot)}</div>` : ''}</td>
        <td>${r.mode === 'enforce' ? '<span class="pill high">拦截</span>' : r.mode === 'monitor' ? '<span class="pill info">只监听</span>' : '—'}</td>
        <td class="num">${r.requests || 0}</td>
        <td class="num">${r.matched || 0}</td>
        <td class="num">${r.banned || 0}</td>
        <td class="num muted">${!r.uptime ? '—'
          : r.uptime < 90 ? Math.round(r.uptime) + ' 秒'
          : Math.round(r.uptime / 60) + ' 分钟'}</td>
        <td class="mono muted">${(r.logs || []).map(esc).join('<br>') || '—'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  async function loadWafStatus() {
    const box = $('#wafStatus');
    if (!box) return;
    if (!box.dataset.loaded) box.innerHTML = '<div class="empty">检测中…</div>';
    try {
      const sel = S.selection.waf || [];
      const d = await api('/api/waf/status' + (sel.length ? '?targets=' + encodeURIComponent(sel.join(',')) : ''));
      if (!d.targets || !d.targets.length) {
        box.innerHTML = '<div class="empty">没有防守靶机，先去「靶机」页添加</div>';
        return;
      }
      box.innerHTML = wafTable(d.targets);
      box.dataset.loaded = '1';
    } catch (e) { box.innerHTML = `<div class="empty">读取失败：${esc(e.message)}</div>`; }
  }

  function renderWafAudit() {
    const rows = S.wafAudit || [];
    const box = $('#wafAudit');
    if (!rows.length) {
      box.innerHTML = '<div class="empty">没有命中记录。确认业务有流量、日志路径正确。</div>';
      $('#wafAuditHint').textContent = '';
      return;
    }
    $('#wafAuditHint').textContent = `${rows.length} 类命中`;
    box.innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
      <th class="cb"><input type="checkbox" id="wafAll"></th>
      <th style="width:70px">级别</th><th>规则</th><th style="width:100px">靶机</th>
      <th style="width:70px">次数</th><th style="width:130px">最近来源</th><th>样例请求</th>
    </tr></thead><tbody>${rows.map((h, i) => `
      <tr data-waf="${i}">
        <td class="cb"><input type="checkbox" class="waf-cb" data-idx="${i}"></td>
        <td>${sevPill(h.severity)}</td>
        <td>${esc(h.name || h.rule_id)}<div class="muted sm mono">${esc(h.rule_id || '')}</div></td>
        <td>${esc(h.target)}</td>
        <td class="num">${h.count}</td>
        <td class="mono">${esc(h.last_ip || '')}</td>
        <td class="mono">${esc(((h.sample && h.sample.method) || '') + ' ' + ((h.sample && h.sample.path) || ''))}</td>
      </tr>`).join('')}</tbody></table></div>`;
    $('#wafAll').onchange = (e) => {
      $$('#wafAudit .waf-cb').forEach((cb) => { cb.checked = e.target.checked; });
    };
  }

  function pickedAudit() {
    const sel = new Set($$('#wafAudit .waf-cb:checked').map((cb) => Number(cb.dataset.idx)));
    return (S.wafAudit || []).filter((_, i) => sel.has(i));
  }

  async function auditWaf() {
    const btn = $('#btnWafAudit');
    busy(btn, true);
    try {
      const d = await api('/api/waf/audit', {
        method: 'POST', body: { targets: pickTargets('waf'), limit: 400 },
      });
      S.wafAudit = d.hits || [];
      renderWafAudit();
      toast(`拉取完成，${S.wafAudit.length} 类命中`, S.wafAudit.length ? 'ok' : 'warn');
      loadOverview(true);
    } catch (e) { fail(e); } finally { busy(btn, false); }
  }

  async function wafToVuln() {
    const rows = pickedAudit();
    if (!rows.length) return toast('先勾选要入库的命中', 'warn');
    const items = rows.map((h) => {
      const s = h.sample || {};
      return {
        name: h.name || h.rule_id, severity: h.severity, rule_id: h.rule_id,
        target: h.target, method: s.method || 'GET', path: s.path || '/',
        ua: s.ua || '', matched: s.matched || '',
      };
    });
    try {
      const d = await api('/api/vulns/add', { method: 'POST', body: { items, source: 'waf' } });
      toast(`入库 ${d.added} 条（重复 ${d.duplicated}）`, d.added ? 'ok' : 'warn');
      loadVulns();
    } catch (e) { fail(e); }
  }

  function hardenWaf() {
    const rows = pickedAudit();
    const ids = rows.length ? rows.map((h) => h.rule_id).filter(Boolean) : null;
    runJob('/api/waf/enforce', {
      targets: pickTargets('waf'), rule_ids: ids, autoban: true,
    }, {
      title: ids ? `加固 · ${ids.join(',')}` : '加固 · 全部规则',
      btn: $('#btnWafHarden'),
      onDone: () => { loadWafStatus(); toast('已切换为拦截模式', 'ok'); },
    });
  }

  async function loadVulns() {
    const box = $('#vulnTable');
    if (!box) return;
    try {
      const { vulns } = await api('/api/vulns');
      S.vulns = vulns;
      $('#vulnHint').textContent = `${vulns.length} 条`;
      if (!vulns.length) {
        box.innerHTML = '<div class="empty">漏洞库是空的：WAF 命中后勾选「加入漏洞库」，或手工调用接口添加</div>';
        return;
      }
      box.innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
        <th class="cb"><input type="checkbox" id="vulnAll"></th>
        <th style="width:50px">#</th><th style="width:70px">级别</th><th>漏洞</th>
        <th>请求</th><th style="width:90px">来源</th><th style="width:90px">重放</th>
        <th style="width:210px">操作</th>
      </tr></thead><tbody>${vulns.map((v) => `
        <tr>
          <td class="cb"><input type="checkbox" class="vuln-cb" data-id="${v.id}"></td>
          <td class="num muted">${v.id}</td>
          <td>${sevPill(v.severity)}</td>
          <td>${esc(v.name)}<div class="muted sm mono">${esc(v.rule_id || '')}</div></td>
          <td class="mono">${esc(v.method + ' ' + v.path)}</td>
          <td class="muted sm">${esc(v.source || '-')}</td>
          <td>${v.replay_ok === 1 ? '<span class="pill ok">有响应</span>'
            : v.replay_ok === 0 ? '<span class="pill err">失败</span>'
            : '<span class="pill info">未重放</span>'}</td>
          <td><div class="actions">
            <button class="btn ghost xs" data-vuln-replay="${v.id}">重放</button>
            <button class="btn ghost xs" data-vuln-ai="${v.id}">AI 插件</button>
            <button class="btn ghost xs" data-vuln-del="${v.id}">删除</button>
          </div></td>
        </tr>`).join('')}</tbody></table></div>`;
      $('#vulnAll').onchange = (e) => {
        $$('#vulnTable .vuln-cb').forEach((cb) => { cb.checked = e.target.checked; });
      };
      $$('#vulnTable [data-vuln-replay]').forEach((b) => {
        b.onclick = () => replayVulns([Number(b.dataset.vulnReplay)]);
      });
      $$('#vulnTable [data-vuln-del]').forEach((b) => {
        b.onclick = async () => {
          if (!await ask('删除漏洞', '从漏洞库移除该条记录？', '删除')) return;
          try {
            await api('/api/vulns/' + b.dataset.vulnDel, { method: 'DELETE' });
            loadVulns();
          } catch (e) { fail(e); }
        };
      });
      $$('#vulnTable [data-vuln-ai]').forEach((b) => {
        b.onclick = () => {
          const v = (S.vulns || []).find((x) => String(x.id) === b.dataset.vulnAi);
          if (!v) return;
          go('exploit');
          setTimeout(() => {
            $('#plInfo').value = `${v.name}（${v.severity}）\n请求：${v.method} ${v.path}\n` +
              (v.rule_id ? `规则：${v.rule_id}\n` : '') +
              '请写一个能验证并利用该漏洞的插件，命中后返回 evidence。';
            $('#plInfo').focus();
          }, 150);
        };
      });
    } catch (e) { fail(e); }
  }

  function replayVulns(ids) {
    if (!ids || !ids.length) {
      ids = $$('#vulnTable .vuln-cb:checked').map((cb) => Number(cb.dataset.id));
    }
    if (!ids.length) {
      const all = (S.vulns || []).length;
      if (!all) return toast('漏洞库为空', 'warn');
      if (!confirm('没有勾选，是否重放全部漏洞？')) return;
      ids = 'all';
    }
    runJob('/api/vulns/replay', { ids, workers: 6 }, {
      title: '批量重放', btn: $('#btnVulnReplay'),
      onDone: (j) => {
        const rows = (j.result && j.result.results) || [];
        const box = $('#replayResult');
        if (!rows.length) { box.innerHTML = '<div class="empty">没有结果</div>'; return; }
        box.innerHTML = `<div class="table-wrap"><table class="grid"><thead><tr>
          <th style="width:110px">目标</th><th style="width:70px">方法</th><th>URL</th>
          <th style="width:70px">状态</th><th style="width:80px">长度</th><th>结果</th>
        </tr></thead><tbody>${rows.map((r) => `
          <tr>
            <td><b>${esc(r.target)}</b></td>
            <td class="mono">${esc(r.method || '')}</td>
            <td class="mono">${esc(r.url || r.error || '')}</td>
            <td class="num">${r.status || '—'}</td>
            <td class="num">${r.length || 0}</td>
            <td>${r.ok ? '<span class="pill ok">有响应</span>' : '<span class="pill err">失败</span>'}
              ${(r.flags || []).map((f) => `<span class="pill ok">${esc(f)}</span>`).join(' ')}</td>
          </tr>`).join('')}</tbody></table></div>`;
        loadVulns();
        loadFlags();
      },
    });
  }

  /* ------------------------------------------------------- AI 写插件 */
  function generatePlugin() {
    const info = $('#plInfo').value.trim();
    if (!info) return toast('请填写漏洞信息', 'warn');
    $('#plCode').textContent = '模型生成中…（本地 7B 约 20–60 秒）';
    $('#btnPlInstall').disabled = true;
    runJob('/api/ai/plugin/generate', { info }, {
      title: 'AI 写插件', btn: $('#btnPlGen'),
      onDone: (j) => {
        const r = j.result || {};
        S.pluginDraft = r.slug || '';
        $('#plCode').textContent = r.code || `生成失败：${r.error || '模型无输出'}`;
        $('#plHint').textContent = r.ok
          ? `${r.name} · ${r.severity} · 已存草稿（未启用）`
          : (r.error || '');
        $('#btnPlInstall').disabled = !r.ok;
      },
    });
  }

  async function installPlugin() {
    if (!S.pluginDraft) return toast('没有可安装的草稿', 'warn');
    try {
      const d = await api('/api/ai/plugin/install', {
        method: 'POST', body: { slug: S.pluginDraft, overwrite: false },
      });
      toast(`已启用插件 ${d.name}`, 'ok');
      $('#btnPlInstall').disabled = true;
      loadPlugins();
    } catch (e) { fail(e); }
  }

  async function showDrafts() {
    try {
      const { drafts } = await api('/api/ai/plugin/drafts');
      if (!drafts.length) return toast('草稿箱是空的', 'warn');
      modal('插件草稿箱', `<div class="table-wrap"><table class="grid"><thead><tr>
        <th>草稿</th><th style="width:110px">时间</th><th style="width:90px">操作</th>
      </tr></thead><tbody>${drafts.map((d) => `
        <tr><td class="mono">${esc(d.name)}</td><td class="muted">${esc(d.mtime)}</td>
        <td><button class="btn ghost xs" data-draft="${esc(d.slug)}">启用</button></td></tr>`).join('')}
      </tbody></table></div>
      <pre class="answer" style="max-height:260px">${esc(drafts[0].code)}</pre>`);
      $$('#modal [data-draft]').forEach((b) => {
        b.onclick = async () => {
          try {
            const d = await api('/api/ai/plugin/install',
              { method: 'POST', body: { slug: b.dataset.draft } });
            toast(`已启用 ${d.name}`, 'ok');
            closeModal();
            loadPlugins();
          } catch (e) { fail(e); }
        };
      });
    } catch (e) { fail(e); }
  }

  /* --------------------------------------------------------------- boot */
  async function boot() {
    bindActions();
    setWs('fallback', '连接中');
    connectWS();
    RD_TIMER = setInterval(() => {
      if (S.view === 'flag' && S.round && S.round.running) {
        S.round.next_in = Math.max(0, (S.round.next_in || 0) - 2);
        $('#rdNext').textContent =
          `第 ${S.round.round_no} 轮 · 下次检测 ${fmtDur(S.round.next_in)}`;
        if (S.round.next_in <= 0) { loadRoundState(); loadRounds(); }
      }
    }, 2000);
    await loadOverview(true);
    renderAllChips();
    loadPlugins().catch(() => {});
    const v = location.hash.replace('#', '');
    go(TITLES[v] ? v : 'overview');
    setInterval(() => loadOverview(true), 15000);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();

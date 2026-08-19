// NetWatch CookieGuard dashboard client.
// No external libraries: WebSocket + a bit of DOM/SVG.
(() => {
  'use strict';

  const MAX_ROWS = 400; // DOM rows kept per table/list, for render performance
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const SEV_LABEL = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };
  const SEV_ICON = { critical: '⛔', high: '🔺', medium: '⚠️', low: '🟢', info: 'ℹ️' };

  const state = {
    alerts: [],
    conns: [],
    files: [],
    dns: [],
    procs: new Map(), // pid -> proc
    seenSeq: { net: new Set(), dns: new Set(), file: new Set(), alert: new Set() },
    paused: false,
  };

  // ---------- utilities ----------

  function esc(s) {
    if (s === undefined || s === null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function fmtTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    const now = new Date();
    const sameDay = d.toDateString() === now.toDateString();
    const t = d.toLocaleTimeString('zh-CN', { hour12: false });
    return sameDay ? t : d.toLocaleDateString('zh-CN') + ' ' + t;
  }

  function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  // Collapsible "证据" block: full path, command line, parent PID, hash —
  // the forensic detail needed to actually tell a real threat from
  // developer tooling, kept out of the way until you ask for it.
  function renderEvidence(proc) {
    if (!proc) return '';
    const rows = [];
    if (proc.imagePath) rows.push(['完整路径', esc(proc.imagePath)]);
    if (proc.commandLine) rows.push(['命令行', esc(proc.commandLine)]);
    if (proc.ppid) rows.push(['父进程 PID', String(proc.ppid)]);
    if (proc.sha256) rows.push(['SHA-256', esc(proc.sha256) + ' <a href="https://www.virustotal.com/gui/search/' + esc(proc.sha256) + '" target="_blank" rel="noopener">用 VirusTotal 查这个哈希 ↗</a>']);
    if (proc.startTime) rows.push(['进程启动时间', fmtTime(proc.startTime)]);
    if (!rows.length) return '';
    return `<details class="evidence"><summary>🔎 证据详情</summary><table class="evidence-table">${
      rows.map(([k, v]) => `<tr><td class="evidence-key">${k}</td><td class="mono wrap">${v}</td></tr>`).join('')
    }</table></details>`;
  }

  // ---------- Wails runtime bridge ----------
  // This used to be a WebSocket + fetch() talking to a localhost HTTP
  // server; the dashboard now runs inside a native WebView2 window with no
  // network port at all. Wails injects window.runtime (event bus) and
  // window.go.main.App.* (the bound Go methods from cmd/netwatch/app.go)
  // before this script runs.

  let eventBuffer = [];
  let snapshotLoaded = false;

  function setConn(connected) {
    const dot = document.getElementById('connDot');
    const label = document.getElementById('connLabel');
    if (connected) {
      dot.classList.remove('off');
      label.textContent = '已连接·实时监控中';
    } else {
      dot.classList.add('off');
      label.textContent = '正在连接后台服务…';
    }
  }

  function connect() {
    if (!window.runtime) {
      // Should already be injected by the time this script runs; retry
      // defensively in case of an unusual load-order edge case.
      setTimeout(connect, 50);
      return;
    }
    ['alert', 'net', 'file', 'dns', 'proc'].forEach(t => {
      window.runtime.EventsOn(t, (data) => {
        const env = { type: t, data };
        if (!snapshotLoaded) { eventBuffer.push(env); return; }
        applyEnvelope(env);
      });
    });
    setConn(true);
  }

  async function loadSnapshot() {
    try {
      const snap = await window.go.main.App.GetSnapshot();
      state.alerts = snap.alerts || [];
      state.conns = snap.nets || [];
      state.files = snap.files || [];
      state.dns = snap.dns || [];
      (snap.procs || []).forEach(p => state.procs.set(p.pid, p));
      markSeen();
    } catch (e) {
      console.error('snapshot load failed', e);
    }
    snapshotLoaded = true;
    eventBuffer.forEach(applyEnvelope);
    eventBuffer = [];
    renderAll();
  }

  function markSeen() {
    state.alerts.forEach(a => state.seenSeq.alert.add(a.seq));
    state.conns.forEach(c => state.seenSeq.net.add(c.seq));
    state.files.forEach(f => state.seenSeq.file.add(f.seq));
    state.dns.forEach(d => state.seenSeq.dns.add(d.seq));
  }

  function applyEnvelope(env) {
    switch (env.type) {
      case 'alert':
        if (state.seenSeq.alert.has(env.data.seq)) return;
        state.seenSeq.alert.add(env.data.seq);
        state.alerts.unshift(env.data);
        state.alerts.length > 2000 && state.alerts.pop();
        scheduleRender('alerts');
        maybeNotify(env.data);
        break;
      case 'net':
        if (state.seenSeq.net.has(env.data.seq)) return;
        state.seenSeq.net.add(env.data.seq);
        state.conns.unshift(env.data);
        state.conns.length > 3000 && state.conns.pop();
        scheduleRender('conns');
        break;
      case 'file':
        if (state.seenSeq.file.has(env.data.seq)) return;
        state.seenSeq.file.add(env.data.seq);
        state.files.unshift(env.data);
        state.files.length > 3000 && state.files.pop();
        scheduleRender('files');
        break;
      case 'dns':
        if (state.seenSeq.dns.has(env.data.seq)) return;
        state.seenSeq.dns.add(env.data.seq);
        state.dns.unshift(env.data);
        state.dns.length > 3000 && state.dns.pop();
        scheduleRender('dns');
        break;
      case 'proc':
        state.procs.set(env.data.pid, env.data);
        scheduleRender('procs');
        break;
    }
  }

  function maybeNotify(alert) {
    if (!(alert.severity === 'critical' || alert.severity === 'high')) return;
    setTitleBadge(countUnacked());
    if (window.Notification && Notification.permission === 'granted') {
      try { new Notification('NetWatch CookieGuard: ' + alert.title, { body: alert.detail }); } catch {}
    }
  }

  function countUnacked() {
    return state.alerts.filter(a => !a.ack && (a.severity === 'critical' || a.severity === 'high')).length;
  }

  // Reflects the unacknowledged-alert count onto the actual OS window
  // title/taskbar entry (not just the in-page <title>), so it's visible
  // even when the window is minimized or behind other apps.
  function setTitleBadge(count) {
    const title = count > 0 ? `🔴 (${count}) NetWatch CookieGuard` : 'NetWatch CookieGuard';
    document.title = title;
    if (window.runtime && window.runtime.WindowSetTitle) {
      try { window.runtime.WindowSetTitle(title); } catch {}
    }
  }

  // ---------- render scheduling ----------

  const pending = new Set();
  function scheduleRender(section) {
    pending.add(section);
    if (state.paused) return;
    requestAnimationFrame(flushRender);
  }
  function flushRender() {
    pending.forEach(renderSection);
    pending.clear();
  }
  function renderAll() {
    ['alerts', 'conns', 'files', 'dns', 'procs'].forEach(renderSection);
  }

  function renderSection(section) {
    if (section === 'alerts') return renderAlerts();
    if (section === 'conns') return renderConns();
    if (section === 'files') return renderFiles();
    if (section === 'dns') return renderDns();
    if (section === 'procs') return renderProcs();
  }

  // ---------- alerts ----------

  function renderAlerts() {
    const q = document.getElementById('alertSearch').value.trim().toLowerCase();
    const sevFilter = document.getElementById('alertSevFilter').value;
    const hideAck = document.getElementById('hideAck').checked;

    let list = state.alerts;
    if (sevFilter) list = list.filter(a => a.severity === sevFilter);
    if (hideAck) list = list.filter(a => !a.ack);
    if (q) list = list.filter(a =>
      (a.procName || '').toLowerCase().includes(q) ||
      (a.title || '').toLowerCase().includes(q) ||
      (a.detail || '').toLowerCase().includes(q));

    list = list.slice(0, MAX_ROWS);

    const critical = state.alerts.filter(a => a.severity === 'critical').length;
    const high = state.alerts.filter(a => a.severity === 'high').length;
    document.getElementById('statCritical').textContent = critical;
    document.getElementById('statHigh').textContent = high;
    document.getElementById('tabCountAlerts').textContent = state.alerts.length;
    drawSparkline('sparkCritical', bucketCounts(state.alerts.filter(a => a.severity === 'critical')), 'var(--status-critical)');
    drawSparkline('sparkHigh', bucketCounts(state.alerts.filter(a => a.severity === 'high')), 'var(--status-serious)');

    const container = document.getElementById('alertList');
    const empty = document.getElementById('alertEmpty');
    if (list.length === 0) {
      container.innerHTML = '';
      empty.style.display = '';
      return;
    }
    empty.style.display = 'none';

    container.innerHTML = list.map(a => {
      const sev = a.severity || 'info';
      // a.process is the evidence snapshot taken at alert time (authoritative);
      // fall back to the live process table in case an older alert predates it.
      const proc = a.process || state.procs.get(a.pid);
      const identityUnknown = !proc || !proc.name;
      const procChip = identityUnknown
        ? `<span class="chip unsigned">❓ 身份不明 · PID ${a.pid || '-'}</span>`
        : `<span class="chip">${esc(proc.name)}${proc.nameInherited ? ' (继承自父进程)' : ''} · PID ${a.pid || '-'}</span>`;
      const signedChip = proc && proc.sigChecked
        ? (proc.signed ? `<span class="chip">✓ 已签名${proc.signerName ? ': ' + esc(truncate(proc.signerName, 20)) : ''}</span>` : `<span class="chip unsigned">⚠ 未签名</span>`)
        : '';
      const knownChip = proc && proc.known ? `<span class="chip known">常见浏览器</span>` : '';
      const suspChip = proc && proc.suspiciousLoc ? `<span class="chip unsigned">📁 可疑路径</span>` : '';
      const aiChip = a.aiService ? `<span class="chip known">🤖 ${esc(a.aiService)}</span>` : '';
      const evidence = renderEvidence(proc);
      return `
        <div class="alert-card sev-${sev} ${a.ack ? 'ack' : ''}" data-seq="${a.seq}">
          <div class="alert-body">
            <div class="alert-top-row">
              <span class="badge sev-${sev}"><span class="icon">${SEV_ICON[sev] || 'ℹ️'}</span>${SEV_LABEL[sev] || sev}</span>
              ${procChip}
              ${signedChip}${suspChip}${knownChip}${aiChip}
              <span class="spacer"></span>
              <span class="alert-time">${fmtTime(a.time)}</span>
            </div>
            <div class="alert-title">${esc(a.title)}</div>
            <div class="alert-detail">${esc(a.detail)}</div>
            ${evidence}
          </div>
          ${a.ack ? '' : `<button class="ack-btn" data-ack="${a.seq}">✓ 确认</button>`}
        </div>`;
    }).join('');
  }

  function bucketCounts(list) {
    const buckets = new Array(24).fill(0); // last 24 buckets of 5 min = 2h
    const now = Date.now();
    list.forEach(a => {
      const t = new Date(a.time).getTime();
      const idx = 23 - Math.floor((now - t) / (5 * 60 * 1000));
      if (idx >= 0 && idx < 24) buckets[idx]++;
    });
    return buckets;
  }

  function drawSparkline(id, buckets, color) {
    const svg = document.getElementById(id);
    if (!svg) return;
    const max = Math.max(1, ...buckets);
    const w = 100, h = 22, n = buckets.length;
    const step = w / (n - 1);
    const pts = buckets.map((v, i) => {
      const x = i * step;
      const y = h - 2 - (v / max) * (h - 4);
      return [x, y];
    });
    const path = pts.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
    const last = pts[pts.length - 1];
    svg.innerHTML = `<path d="${path}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="2.5" fill="${color}"/>`;
  }

  // ---------- connections ----------

  function renderConns() {
    document.getElementById('statConns').textContent = state.conns.length;
    document.getElementById('tabCountConns').textContent = state.conns.length;
    const q = document.getElementById('connSearch').value.trim().toLowerCase();
    const aiOnly = document.getElementById('aiOnlyFilter').checked;
    let list = state.conns;
    if (aiOnly) list = list.filter(c => !!c.aiService);
    if (q) list = list.filter(c =>
      (c.procName || '').toLowerCase().includes(q) ||
      (c.remoteAddr || '').includes(q) ||
      (c.domain || '').toLowerCase().includes(q));
    list = list.slice(0, MAX_ROWS);

    document.getElementById('connBody').innerHTML = list.map(c => {
      const dirFlag = c.direction === 'connect' ? 'dot-neutral' : c.direction === 'disconnect' ? 'dot-warn' : 'dot-ok';
      return `<tr${c.aiService ? ' style="background:color-mix(in srgb, var(--series-blue) 6%, transparent)"' : ''}>
        <td>${fmtTime(c.time)}</td>
        <td>${esc(c.procName || '?')}</td>
        <td class="num">${c.pid}</td>
        <td><span class="dot-flag ${dirFlag}"></span>${esc(c.direction)}</td>
        <td>${esc(c.proto)}</td>
        <td class="mono">${esc(c.remoteAddr)}</td>
        <td class="num">${c.remotePort || ''}</td>
        <td>${c.domain ? esc(c.domain) : '<span style="color:var(--text-muted)">—</span>'}</td>
        <td>${c.aiService ? `<span class="chip known">🤖 ${esc(c.aiService)}</span>` : ''}</td>
      </tr>`;
    }).join('');
  }

  // ---------- sensitive files ----------

  const KIND_LABEL = { open: '打开/读取', create: '创建', write: '写入', delete: '删除' };

  function renderFiles() {
    document.getElementById('statFiles').textContent = state.files.length;
    document.getElementById('tabCountFiles').textContent = state.files.length;
    const q = document.getElementById('fileSearch').value.trim().toLowerCase();
    let list = state.files;
    if (q) list = list.filter(f =>
      (f.procName || '').toLowerCase().includes(q) ||
      (f.app || '').toLowerCase().includes(q) ||
      (f.path || '').toLowerCase().includes(q));
    list = list.slice(0, MAX_ROWS);

    document.getElementById('fileBody').innerHTML = list.map(f => {
      const ownFlag = f.ownFile ? '<span class="dot-flag dot-ok"></span>本体访问' : '<span class="dot-flag dot-critical"></span>⚠ 非本体访问';
      return `<tr>
        <td>${fmtTime(f.time)}</td>
        <td>${esc(f.procName || '?')}</td>
        <td class="num">${f.pid}</td>
        <td>${esc(f.app)}</td>
        <td>${KIND_LABEL[f.kind] || esc(f.kind)}</td>
        <td>${ownFlag}</td>
        <td class="mono wrap">${esc(f.path)}</td>
      </tr>`;
    }).join('');
  }

  // ---------- dns ----------

  function renderDns() {
    document.getElementById('tabCountDns').textContent = state.dns.length;
    const q = document.getElementById('dnsSearch').value.trim().toLowerCase();
    let list = state.dns;
    if (q) list = list.filter(d =>
      (d.procName || '').toLowerCase().includes(q) ||
      (d.query || '').toLowerCase().includes(q));
    list = list.slice(0, MAX_ROWS);

    document.getElementById('dnsBody').innerHTML = list.map(d => `<tr${d.aiService ? ' style="background:color-mix(in srgb, var(--series-blue) 6%, transparent)"' : ''}>
        <td>${fmtTime(d.time)}</td>
        <td>${esc(d.procName || '?')}</td>
        <td class="num">${d.pid}</td>
        <td class="mono">${esc(d.query)}${d.aiService ? ` <span class="chip known">🤖 ${esc(d.aiService)}</span>` : ''}</td>
        <td class="mono wrap">${esc((d.results || []).join(', '))}</td>
      </tr>`).join('');
  }

  // ---------- processes ----------

  function renderProcs() {
    const all = Array.from(state.procs.values()).sort((a, b) => (b.startTime || '').localeCompare(a.startTime || ''));
    document.getElementById('statProcs').textContent = all.length;
    document.getElementById('tabCountProcs').textContent = all.length;
    const q = document.getElementById('procSearch').value.trim().toLowerCase();
    let list = all;
    if (q) list = list.filter(p =>
      (p.name || '').toLowerCase().includes(q) ||
      (p.imagePath || '').toLowerCase().includes(q));
    list = list.slice(0, MAX_ROWS);

    document.getElementById('procBody').innerHTML = list.map(p => {
      let sig;
      if (!p.imagePath) {
        // No path was ever resolved for this PID, so a signature check was
        // never possible — this is a dead end, not "still working on it".
        sig = '<span style="color:var(--text-muted)">无法验证(身份不明)</span>';
      } else if (p.sigChecked) {
        sig = p.signed ? `<span class="chip">✓ ${esc(truncate(p.signerName || '已签名', 22))}</span>` : `<span class="chip unsigned">⚠ 未签名</span>`;
      } else {
        sig = '<span style="color:var(--text-muted)">检查中…</span>';
      }
      const status = p.exited ? '<span class="chip">已退出</span>' : '<span class="chip known">运行中</span>';
      const susp = p.suspiciousLoc ? ' <span class="chip unsigned">📁 可疑路径</span>' : '';
      const name = p.name ? esc(p.name) + (p.nameInherited ? ' <span style="color:var(--text-muted);font-size:11px">(继承自父进程)</span>' : '') : '<span class="chip unsigned">❓ 身份不明</span>';
      return `<tr>
        <td>${name}</td>
        <td class="num">${p.pid}</td>
        <td class="num">${p.ppid || ''}</td>
        <td>${sig}</td>
        <td class="mono wrap">${esc(p.imagePath)}</td>
        <td>${status}${susp}</td>
      </tr>`;
    }).join('');
  }

  // ---------- tabs / filters / ack ----------

  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
    });
  });

  ['alertSearch', 'alertSevFilter', 'hideAck'].forEach(id =>
    document.getElementById(id).addEventListener('input', () => renderSection('alerts')));
  document.getElementById('connSearch').addEventListener('input', () => renderSection('conns'));
  document.getElementById('aiOnlyFilter').addEventListener('input', () => renderSection('conns'));
  document.getElementById('fileSearch').addEventListener('input', () => renderSection('files'));
  document.getElementById('dnsSearch').addEventListener('input', () => renderSection('dns'));
  document.getElementById('procSearch').addEventListener('input', () => renderSection('procs'));

  document.getElementById('alertList').addEventListener('click', (ev) => {
    const btn = ev.target.closest('[data-ack]');
    if (!btn) return;
    const seq = Number(btn.dataset.ack);
    window.go.main.App.AckAlert(seq)
      .then(() => {
        const a = state.alerts.find(x => x.seq === seq);
        if (a) a.ack = true;
        renderAlerts();
        setTitleBadge(countUnacked());
      });
  });

  document.getElementById('pauseBtn').addEventListener('click', (ev) => {
    state.paused = !state.paused;
    ev.target.textContent = state.paused ? '▶ 恢复刷新' : '⏸ 暂停刷新';
    if (!state.paused) renderAll();
  });

  if (window.Notification && Notification.permission === 'default') {
    // best-effort; ignored if the user dismisses it
    Notification.requestPermission().catch(() => {});
  }

  connect();
  loadSnapshot();
})();

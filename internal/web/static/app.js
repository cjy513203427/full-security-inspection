// NetWatch CookieGuard dashboard client.
// No external libraries: WebSocket + a bit of DOM/SVG.
(() => {
  'use strict';

  const MAX_ROWS = 400; // DOM rows kept per table/list, for render performance
  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const SEV_ICON_NAME = { critical: 'alert-octagon', high: 'alert-triangle', medium: 'alert-circle', low: 'check-circle', info: 'info' };

  // Severity/file-access-kind display labels come from i18n.js's catalog
  // (shared with the severity filter <select>'s own options) rather than a
  // static table here, so they follow the dashboard's active language.
  function sevLabel(sev) {
    return i18n.t('sev.' + (sev || 'info'));
  }
  function kindLabel(kind) {
    const key = 'kind.' + kind;
    const label = i18n.t(key);
    return label === key ? esc(kind) : label; // unrecognized kind: fall back to the raw (escaped) value rather than a literal "kind.foo"
  }

  // Inline SVG icons, resolved against the <symbol> sprite embedded in
  // index.html — self-hosted, no icon font/CDN, matches the app's
  // "loads no external resources" guarantee.
  function icon(name, cls) {
    return `<svg class="icon${cls ? ' ' + cls : ''}"><use href="#icon-${name}"/></svg>`;
  }

  const state = {
    alerts: [],
    conns: [],
    files: [],
    dns: [],
    certChecks: [],
    procs: new Map(), // pid -> proc
    seenSeq: { net: new Set(), dns: new Set(), file: new Set(), alert: new Set(), certcheck: new Set() },
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
    const loc = i18n.locale();
    const t = d.toLocaleTimeString(loc, { hour12: false });
    return sameDay ? t : d.toLocaleDateString(loc) + ' ' + t;
  }

  function truncate(s, n) {
    if (!s) return '';
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  // Collapsible evidence block: full path, command line, parent PID, hash —
  // the forensic detail needed to actually tell a real threat from
  // developer tooling, kept out of the way until you ask for it.
  function renderEvidence(proc) {
    if (!proc) return '';
    const rows = [];
    if (proc.imagePath) rows.push([i18n.t('ev.image_path'), esc(proc.imagePath)]);
    if (proc.commandLine) rows.push([i18n.t('ev.command_line'), esc(proc.commandLine)]);
    if (proc.ppid) rows.push([i18n.t('ev.ppid'), String(proc.ppid)]);
    if (proc.sha256) rows.push([i18n.t('ev.sha256'), esc(proc.sha256) + ' <a href="https://www.virustotal.com/gui/search/' + esc(proc.sha256) + '" target="_blank" rel="noopener">' + i18n.t('ev.vt_link') + '</a>']);
    if (proc.startTime) rows.push([i18n.t('ev.start_time'), fmtTime(proc.startTime)]);
    if (!rows.length) return '';
    return `<details class="evidence"><summary>${icon('search')} ${i18n.t('ev.summary')}</summary><table class="evidence-table">${
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

  // Tracked so a language switch (applyLanguage, below) can redraw whatever
  // the connection-state text currently says in the new language — setConn
  // itself only runs on an actual connect/disconnect, which won't
  // necessarily coincide with the user changing languages.
  let isConnected = false;

  function setConn(connected) {
    isConnected = connected;
    const dot = document.getElementById('connDot');
    const label = document.getElementById('connLabel');
    if (connected) {
      dot.classList.remove('off');
      label.textContent = i18n.t('conn.connected');
    } else {
      dot.classList.add('off');
      label.textContent = i18n.t('conn.connecting');
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
      state.certChecks = snap.certChecks || [];
      (snap.procs || []).forEach(upsertProc);
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
    state.certChecks.forEach(c => state.seenSeq.certcheck.add(c.seq));
  }

  // This tool is meant to run for weeks at a time, so "cap the array, but
  // never shrink the dedup Set that tracks it" would be a slow, real
  // memory leak — every popped array entry's seq has to come out of
  // seenSeq too, or the Set just grows forever even though the array
  // stays a fixed size.
  const ARRAY_CAPS = { alert: 2000, net: 3000, file: 3000, dns: 3000, certcheck: 1000 };

  function pushDeduped(type, arr, item) {
    const seen = state.seenSeq[type];
    if (seen.has(item.seq)) return false;
    seen.add(item.seq);
    arr.unshift(item);
    if (arr.length > ARRAY_CAPS[type]) {
      const dropped = arr.pop();
      seen.delete(dropped.seq);
    }
    return true;
  }

  // Same idea for the process table: state.procs is a Map that would
  // otherwise keep every PID ever observed for the life of the window.
  // The backend already retires long-exited processes from its own store
  // (see internal/store's procExitRetention), but that only stops it from
  // sending more updates for them — it doesn't reach into what the
  // frontend already cached, so the frontend bounds itself independently.
  const PROC_CAP = 5000;

  function upsertProc(p) {
    if (!state.procs.has(p.pid) && state.procs.size >= PROC_CAP) {
      // Map iteration order is insertion order; the first key is simply
      // the PID we've held onto the longest.
      state.procs.delete(state.procs.keys().next().value);
    }
    state.procs.set(p.pid, p);
  }

  function applyEnvelope(env) {
    switch (env.type) {
      case 'alert':
        if (!pushDeduped('alert', state.alerts, env.data)) return;
        scheduleRender('alerts');
        maybeNotify(env.data);
        break;
      case 'net':
        if (!pushDeduped('net', state.conns, env.data)) return;
        scheduleRender('conns');
        break;
      case 'file':
        if (!pushDeduped('file', state.files, env.data)) return;
        scheduleRender('files');
        break;
      case 'dns':
        if (!pushDeduped('dns', state.dns, env.data)) return;
        scheduleRender('dns');
        break;
      case 'proc':
        upsertProc(env.data);
        scheduleRender('procs');
        break;
      case 'certcheck':
        if (!pushDeduped('certcheck', state.certChecks, env.data)) return;
        scheduleRender('certchecks');
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
    // The native OS window/taskbar title can't render inline SVG, so this
    // uses a plain Unicode glyph (not an emoji) as a text-only marker.
    const title = count > 0 ? `● (${count}) NetWatch CookieGuard` : 'NetWatch CookieGuard';
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
    ['alerts', 'conns', 'files', 'dns', 'procs', 'certchecks'].forEach(renderSection);
  }

  function renderSection(section) {
    if (section === 'alerts') return renderAlerts();
    if (section === 'conns') return renderConns();
    if (section === 'files') return renderFiles();
    if (section === 'dns') return renderDns();
    if (section === 'procs') return renderProcs();
    if (section === 'certchecks') return renderCertChecks();
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
      // Some alert rules (e.g. certcheck's "tls_interception") aren't about
      // any one process at all — a.pid is 0/absent by design there, not a
      // failed identity lookup, so showing an "identity unknown" chip would
      // misleadingly imply an unidentified suspicious process was involved.
      const identityUnknown = !proc || !proc.name;
      const procChip = !a.pid ? '' : identityUnknown
        ? `<span class="chip unsigned">${icon('help-circle')} ${i18n.t('chip.identity_unknown_pid', a.pid)}</span>`
        : `<span class="chip">${i18n.t('chip.name_pid', esc(proc.name) + (proc.nameInherited ? i18n.t('chip.inherited_suffix') : ''), a.pid)}</span>`;
      const signedChip = proc && proc.sigChecked
        ? (proc.signed ? `<span class="chip">${icon('check')} ${proc.signerName ? i18n.t('chip.signed_by', esc(truncate(proc.signerName, 20))) : i18n.t('chip.signed')}</span>` : `<span class="chip unsigned">${icon('alert-triangle')} ${i18n.t('chip.unsigned')}</span>`)
        : '';
      const knownChip = proc && proc.known ? `<span class="chip known">${i18n.t('chip.known_browser')}</span>` : '';
      const suspChip = proc && proc.suspiciousLoc ? `<span class="chip unsigned">${icon('folder')} ${i18n.t('chip.suspicious_path')}</span>` : '';
      const aiChip = a.aiService ? `<span class="chip known">${icon('bot')} ${esc(a.aiService)}</span>` : '';
      const evidence = renderEvidence(proc);
      return `
        <div class="alert-card sev-${sev} ${a.ack ? 'ack' : ''}" data-seq="${a.seq}">
          <div class="alert-body">
            <div class="alert-top-row">
              <span class="badge sev-${sev}">${icon(SEV_ICON_NAME[sev] || 'info')}${sevLabel(sev)}</span>
              ${procChip}
              ${signedChip}${suspChip}${knownChip}${aiChip}
              <span class="spacer"></span>
              <span class="alert-time">${fmtTime(a.time)}</span>
            </div>
            <div class="alert-title">${esc(a.title)}</div>
            <div class="alert-detail">${esc(a.detail)}</div>
            ${evidence}
          </div>
          ${a.ack ? '' : `<button class="ack-btn" data-ack="${a.seq}">${icon('check')} ${i18n.t('btn.ack')}</button>`}
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
        <td>${c.aiService ? `<span class="chip known">${icon('bot')} ${esc(c.aiService)}</span>` : ''}</td>
      </tr>`;
    }).join('');
  }

  // ---------- sensitive files ----------

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
      const ownFlag = f.ownFile ? `<span class="dot-flag dot-ok"></span>${i18n.t('own.own_access')}` : `<span class="dot-flag dot-critical"></span>${icon('alert-triangle')} ${i18n.t('own.non_own_access')}`;
      return `<tr>
        <td>${fmtTime(f.time)}</td>
        <td>${esc(f.procName || '?')}</td>
        <td class="num">${f.pid}</td>
        <td>${esc(f.app)}</td>
        <td>${kindLabel(f.kind)}</td>
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
        <td class="mono">${esc(d.query)}${d.aiService ? ` <span class="chip known">${icon('bot')} ${esc(d.aiService)}</span>` : ''}</td>
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
        sig = `<span style="color:var(--text-muted)">${i18n.t('proc.cant_verify')}</span>`;
      } else if (p.sigChecked) {
        sig = p.signed ? `<span class="chip">${icon('check')} ${esc(truncate(p.signerName || i18n.t('chip.signed'), 22))}</span>` : `<span class="chip unsigned">${icon('alert-triangle')} ${i18n.t('chip.unsigned')}</span>`;
      } else {
        sig = `<span style="color:var(--text-muted)">${i18n.t('proc.checking')}</span>`;
      }
      const status = p.exited ? `<span class="chip">${i18n.t('proc.exited')}</span>` : `<span class="chip known">${i18n.t('proc.running')}</span>`;
      const susp = p.suspiciousLoc ? ` <span class="chip unsigned">${icon('folder')} ${i18n.t('chip.suspicious_path')}</span>` : '';
      const name = p.name ? esc(p.name) + (p.nameInherited ? ` <span style="color:var(--text-muted);font-size:11px">${i18n.t('chip.inherited_suffix')}</span>` : '') : `<span class="chip unsigned">${icon('help-circle')} ${i18n.t('chip.identity_unknown')}</span>`;
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

  // ---------- cert checks ----------

  function renderCertChecks() {
    document.getElementById('tabCountCertChecks').textContent = state.certChecks.length;
    const q = document.getElementById('certCheckSearch').value.trim().toLowerCase();
    let list = state.certChecks;
    if (q) list = list.filter(c => (c.domain || '').toLowerCase().includes(q));
    list = list.slice(0, MAX_ROWS);

    const body = document.getElementById('certCheckBody');
    const empty = document.getElementById('certCheckEmpty');
    const wrap = body.closest('.table-wrap');
    if (list.length === 0) {
      body.innerHTML = '';
      wrap.style.display = 'none';
      empty.style.display = '';
      return;
    }
    wrap.style.display = '';
    empty.style.display = 'none';

    body.innerHTML = list.map(c => {
      let status;
      if (!c.ok) {
        status = `<span class="dot-flag dot-neutral"></span>${i18n.t('cc.probe_failed')}${c.error ? `: ${esc(truncate(c.error, 40))}` : ''}`;
      } else if (c.suspectedVendor) {
        status = `<span class="dot-flag dot-critical"></span>${icon('shield-alert')} ${i18n.t('cc.suspected_intercept', esc(c.suspectedVendor))}`;
      } else if (!c.trustedPublicRoot) {
        status = `<span class="dot-flag dot-warn"></span>${icon('alert-triangle')} ${i18n.t('cc.not_public_ca')}`;
      } else if (c.suspectedConsumerAV) {
        status = `<span class="dot-flag dot-ok"></span>${i18n.t('cc.ok_local_av', esc(c.suspectedConsumerAV))}`;
      } else if (c.changed) {
        status = `<span class="dot-flag dot-warn"></span>${icon('alert-triangle')} ${i18n.t('cc.issuance_changed')}`;
      } else {
        status = `<span class="dot-flag dot-ok"></span>${icon('check')} ${i18n.t('cc.ok')}`;
      }
      const trusted = c.ok ? (c.trustedPublicRoot ? `<span class="chip known">${icon('check')} ${i18n.t('cc.trusted')}</span>` : `<span class="chip unsigned">${icon('alert-triangle')} ${i18n.t('cc.untrusted')}</span>`) : '';
      return `<tr>
        <td>${fmtTime(c.time)}</td>
        <td class="mono">${esc(c.domain)}</td>
        <td>${esc(c.issuerCN || c.issuerO || '—')}</td>
        <td class="mono wrap">${esc(c.rootSubject || '—')}</td>
        <td>${trusted}</td>
        <td>${status}</td>
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
  document.getElementById('certCheckSearch').addEventListener('input', () => renderSection('certchecks'));

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

  // Rewrites the pause button's label for the current state.paused/language
  // combination. Needed both on an actual click and — since the button's
  // whole innerHTML gets replaced here rather than living inside a
  // translatePage()-managed <span data-i18n> — on every language switch
  // too, or a switch while paused would leave stale text behind.
  function updatePauseBtn() {
    const btn = document.getElementById('pauseBtn');
    btn.innerHTML = state.paused ? `${icon('play')} ${i18n.t('btn.resume')}` : `${icon('pause')} ${i18n.t('btn.pause')}`;
  }

  document.getElementById('pauseBtn').addEventListener('click', () => {
    state.paused = !state.paused;
    updatePauseBtn();
    if (!state.paused) renderAll();
  });

  // ---------- settings (bottom-left gear FAB -> modal dialog) ----------

  const settingsBtn = document.getElementById('settingsBtn');
  const settingsOverlay = document.getElementById('settingsOverlay');
  const settingsClose = document.getElementById('settingsClose');

  function openSettings() {
    settingsOverlay.classList.add('open');
  }
  function closeSettings() {
    settingsOverlay.classList.remove('open');
  }
  settingsBtn.addEventListener('click', openSettings);
  settingsClose.addEventListener('click', closeSettings);
  // Clicking the dimmed backdrop closes it; clicking inside the modal card
  // itself must not (that's every settings-row select/label in there) — the
  // check is just "did the click land on the overlay element itself, not
  // something inside it", since .modal is the overlay's only child covering
  // part of it.
  settingsOverlay.addEventListener('click', (ev) => {
    if (ev.target === settingsOverlay) closeSettings();
  });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && settingsOverlay.classList.contains('open')) closeSettings();
  });

  // ---------- theme (light / dark / system) ----------
  //
  // "system" is the implicit default: no data-theme attribute at all, so
  // style.css's prefers-color-scheme media query alone decides. "light"/
  // "dark" set data-theme explicitly, which style.css's
  // :root[data-theme="..."] rules (and the :not([data-theme="light"]) guard
  // on the dark media query) give priority over the OS preference. See
  // index.html's inline head script for the no-flash-on-load counterpart
  // to this — it has to duplicate the localStorage key/values here since it
  // runs standalone, before this file loads.
  const THEME_STORAGE_KEY = 'netwatch_theme';

  function applyTheme(theme) {
    if (theme === 'light' || theme === 'dark') {
      document.documentElement.setAttribute('data-theme', theme);
    } else {
      theme = 'system';
      document.documentElement.removeAttribute('data-theme');
    }
    document.getElementById('themeSelect').value = theme;
  }

  document.getElementById('themeSelect').addEventListener('change', (ev) => {
    const theme = ev.target.value;
    localStorage.setItem(THEME_STORAGE_KEY, theme);
    applyTheme(theme);
  });

  applyTheme(localStorage.getItem(THEME_STORAGE_KEY) || 'system');

  // ---------- settings: autostart / log directory / clean logs ----------
  //
  // Unlike language/theme, these three have no client-side fallback at
  // all — they only mean anything via the Go backend (Task Scheduler,
  // this instance's actual data directory) — so each one's initial state
  // is fetched from window.go.main.App once at startup rather than having
  // a meaningful default to render before that resolves.

  async function initAutostartToggle() {
    const box = document.getElementById('autostartToggle');
    try {
      box.checked = await window.go.main.App.GetAutostartEnabled();
    } catch (e) {
      console.error('GetAutostartEnabled failed', e);
    }
  }

  document.getElementById('autostartToggle').addEventListener('change', async (ev) => {
    const box = ev.target;
    const wanted = box.checked;
    box.disabled = true;
    try {
      box.checked = await window.go.main.App.SetAutostart(wanted);
    } catch (e) {
      box.checked = !wanted; // the call rejected outright: revert the optimistic UI flip
      alert(i18n.t('settings.autostart_failed', String(e)));
    } finally {
      box.disabled = false;
    }
  });

  async function initDataDirDisplay() {
    try {
      document.getElementById('dataDirPath').textContent = await window.go.main.App.GetDataDir();
    } catch (e) {
      console.error('GetDataDir failed', e);
    }
  }

  document.getElementById('openDataDirBtn').addEventListener('click', () => {
    window.go.main.App.OpenDataDir().catch((e) => console.error('OpenDataDir failed', e));
  });

  document.getElementById('cleanLogsBtn').addEventListener('click', async () => {
    const btn = document.getElementById('cleanLogsBtn');
    const resultEl = document.getElementById('cleanLogsResult');
    btn.disabled = true;
    resultEl.textContent = '';
    try {
      // CleanLogs never rejects (see its Go doc comment: a partial clean —
      // some file(s) still locked by something other than this process
      // itself, since CleanLogs already pauses/resumes monitoring around
      // its own delete — is an expected outcome to display, not a failed
      // call), so this branch only fires on a genuine IPC-level failure.
      const res = await window.go.main.App.CleanLogs();
      const mb = (res.freedBytes / (1024 * 1024)).toFixed(1);
      let msg = i18n.t('settings.clean_logs_done', mb);
      if (res.error) msg += ' ' + i18n.t('settings.clean_logs_partial');
      resultEl.textContent = msg;
    } catch (e) {
      resultEl.textContent = i18n.t('settings.clean_logs_failed', String(e));
    } finally {
      btn.disabled = false;
      // CleanLogs may have paused/resumed monitoring around its own
      // delete (see its Go doc comment) — re-fetch so the "监控状态" hint
      // above never shows stale text if a resume happened to fail.
      refreshMonitorStatus();
    }
  });

  // Quitting is the one action in this modal that isn't reversible from
  // the dashboard — it stops monitoring and exits the whole background
  // process, not just this window (unlike the [X] title-bar close, which
  // HideWindowOnClose just hides). A plain window.confirm() is enough of
  // a speed bump for that; no need for a custom dialog to ask one yes/no
  // question.
  document.getElementById('quitBtn').addEventListener('click', () => {
    if (confirm(i18n.t('settings.quit_confirm'))) {
      window.go.main.App.Quit();
    }
  });

  // ---------- monitoring status (stop / start, without exiting) ----------
  //
  // Distinct from Quit above: this pauses/resumes the ETW collector and
  // cert-check prober only — the window, tray, and process all stay up.
  // Its button/hint text depends on runtime state, not just language, so
  // (like connLabel/pauseBtn) it's redrawn directly by JS rather than
  // through translatePage()'s static data-i18n attributes; applyLanguage
  // (below) re-calls updateMonitorUI with the last-known state so a
  // language switch while this text is showing doesn't leave it stale.
  let monitoringRunning = true; // matches the backend's state at a fresh launch

  function updateMonitorUI(running) {
    monitoringRunning = running;
    document.getElementById('monitorToggleBtn').textContent =
      running ? i18n.t('settings.stop_monitoring') : i18n.t('settings.start_monitoring');
    document.getElementById('monitorStatusHint').textContent =
      running ? i18n.t('settings.monitoring_running') : i18n.t('settings.monitoring_stopped');
  }

  async function refreshMonitorStatus() {
    try {
      updateMonitorUI(await window.go.main.App.GetMonitoring());
    } catch (e) {
      console.error('GetMonitoring failed', e);
    }
  }

  document.getElementById('monitorToggleBtn').addEventListener('click', async () => {
    const btn = document.getElementById('monitorToggleBtn');
    btn.disabled = true;
    try {
      if (monitoringRunning) {
        await window.go.main.App.StopMonitoring();
      } else {
        await window.go.main.App.StartMonitoring();
      }
    } catch (e) {
      alert(i18n.t('settings.monitoring_toggle_failed', String(e)));
    } finally {
      btn.disabled = false;
      refreshMonitorStatus();
    }
  });

  // ---------- language switching ----------
  //
  // The dashboard's own DOM chrome (this file + i18n.js) translates itself
  // instantly and entirely client-side. In the background, the choice is
  // also persisted to localStorage (so this window reopens in the same
  // language) and pushed to the Go backend via SetLanguage, which persists
  // it for the next launch and relabels the tray immediately — see
  // cmd/netwatch/app.go's SetLanguage doc comment. Alerts/cert-check
  // findings already on screen keep whatever language they arrived in
  // (they're plain text from the backend, not re-translatable client-side);
  // only new ones generated after the switch follow the new language.
  const LANG_STORAGE_KEY = 'netwatch_lang';

  function applyLanguage(lang) {
    i18n.setLang(lang);
    document.getElementById('langSelect').value = i18n.getLang();
    i18n.translatePage();
    // Neither of these lives inside a translatePage()-managed <span
    // data-i18n>: both fully replace their own innerHTML/textContent
    // dynamically, so a language switch has to explicitly redraw them in
    // whatever state they're currently in (see each function's own note).
    setConn(isConnected);
    updatePauseBtn();
    updateMonitorUI(monitoringRunning);
    renderAll();
  }

  document.getElementById('langSelect').addEventListener('change', (ev) => {
    const lang = ev.target.value;
    localStorage.setItem(LANG_STORAGE_KEY, lang);
    applyLanguage(lang);
    if (window.go && window.go.main && window.go.main.App && window.go.main.App.SetLanguage) {
      window.go.main.App.SetLanguage(lang).catch(() => {});
    }
  });

  // Resolves the language to open in: a previously saved choice for this
  // window, else whatever the backend itself is currently using (a saved
  // preference from a prior run, or the detected Windows UI language — see
  // internal/i18n.Init on the Go side), else Chinese.
  async function initLanguage() {
    let lang = localStorage.getItem(LANG_STORAGE_KEY);
    if (!lang) {
      try {
        lang = await window.go.main.App.GetLanguage();
      } catch (e) {
        lang = null;
      }
    }
    if (!lang || !i18n.SUPPORTED.includes(lang)) lang = 'zh';
    applyLanguage(lang);
  }

  if (window.Notification && Notification.permission === 'default') {
    // best-effort; ignored if the user dismisses it
    Notification.requestPermission().catch(() => {});
  }

  connect();
  initLanguage().finally(loadSnapshot);
  initAutostartToggle();
  initDataDirDisplay();
  refreshMonitorStatus();
})();

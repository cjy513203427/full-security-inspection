// NetWatch CookieGuard dashboard i18n.
//
// Deliberately its own file, loaded before app.js and with zero dependency
// on it: this only covers the dashboard's own static/dynamic DOM chrome
// (labels, table headers, chip text, buttons...). Alert and cert-check
// Title/Detail text is NOT translated here — those arrive from the Go
// backend already rendered in whichever language was active server-side at
// the moment they were generated (see internal/i18n on the Go side, whose
// package doc explains why retroactive re-translation of already-arrived
// text isn't attempted). Switching the language here only relabels this
// dashboard's own chrome and, from that point on, asks the backend (via
// window.go.main.App.SetLanguage) to generate anything new — new alerts,
// the tray menu — in the same language too.
window.i18n = (() => {
  'use strict';

  const DICT = {
    zh: {
      'header.subtitle': '本机进程级网络 / 敏感文件监控',

      'settings.title': '设置',
      'settings.close': '关闭',
      'settings.language': '语言',
      'settings.theme': '外观',
      'theme.system': '跟随系统',
      'theme.light': '浅色',
      'theme.dark': '深色',
      'settings.autostart': '开机自启动',
      'settings.log_dir': '日志目录',
      'settings.open_dir_btn': '打开',
      'settings.clean_logs': '清理日志',
      'settings.clean_logs_btn': '清理',
      'settings.clean_logs_done': '已释放 {0} MB 磁盘空间。',
      'settings.clean_logs_partial': '部分文件仍被其他程序占用,未能完全清理,可稍后重试。',
      'settings.clean_logs_failed': '清理失败: {0}',
      'settings.autostart_failed': '设置开机自启动失败: {0}',
      'settings.monitoring': '监控状态',
      'settings.stop_monitoring': '停止监控',
      'settings.start_monitoring': '开始监控',
      'settings.monitoring_running': '正在监控中。',
      'settings.monitoring_stopped': '已停止,程序仍在运行 —— 未采集任何新事件。',
      'settings.monitoring_toggle_failed': '操作失败: {0}',
      'settings.quit': '退出程序',
      'settings.quit_btn': '退出程序',
      'settings.quit_hint': '这会关闭整个程序,包括系统托盘图标。如果只是想暂停采集,用上面的「停止监控」即可,不用退出程序。',
      'settings.quit_confirm': '确定要退出程序吗?这会关闭整个程序,包括系统托盘图标。如果只是想暂停采集,用「停止监控」就够了。',

      'conn.connecting': '正在连接后台服务…',
      'conn.connected': '已连接·实时监控中',

      'btn.pause': '暂停刷新',
      'btn.pause_title': '暂停后新事件仍会记录,只是不刷新界面',
      'btn.resume': '恢复刷新',
      'btn.ack': '确认',

      'stat.critical': '严重告警',
      'stat.high': '高危告警',
      'stat.conns': '网络连接',
      'stat.files': '敏感文件访问',
      'stat.procs': '已观察进程数',

      'tab.alerts': '告警',
      'tab.conns': '网络连接',
      'tab.files': '敏感文件访问',
      'tab.dns': 'DNS 解析',
      'tab.procs': '进程',
      'tab.certchecks': '证书检测',

      'sev.all': '全部级别',
      'sev.critical': '严重',
      'sev.high': '高',
      'sev.medium': '中',
      'sev.low': '低',
      'sev.info': '信息',

      'filter.alert_search_ph': '按进程名 / 内容搜索…',
      'filter.hide_ack': '隐藏已确认',
      'filter.conn_search_ph': '按进程名 / IP / 域名搜索…',
      'filter.ai_only': '只看 Claude/ChatGPT/Gemini 相关流量',
      'filter.file_search_ph': '按进程名 / 应用 / 路径搜索…',
      'filter.dns_search_ph': '按进程名 / 域名搜索…',
      'filter.proc_search_ph': '按进程名 / 路径搜索…',
      'filter.certcheck_search_ph': '按域名搜索…',

      'col.time': '时间',
      'col.process': '进程',
      'col.pid': 'PID',
      'col.ppid': 'PPID',
      'col.direction': '方向',
      'col.proto': '协议',
      'col.remote_addr': '目标地址',
      'col.port': '端口',
      'col.domain': '关联域名',
      'col.ai_service': 'AI 服务',
      'col.target_app': '目标应用',
      'col.action': '操作',
      'col.own_access': '是否本体访问',
      'col.path': '路径',
      'col.query': '查询域名',
      'col.results': '解析结果',
      'col.signature': '签名',
      'col.status': '状态',
      'col.issuer': '证书颁发者',
      'col.root_cert': '根证书',
      'col.public_ca_trusted': '公共 CA 可信',

      'empty.alerts': '暂无告警 · 目前没有检测到可疑行为,监控仍在后台持续进行。',
      'empty.certchecks': '暂无证书检测记录,首次探测通常在启动后几秒内完成。',

      'footer.note': '数据全部只保存在本机 data 目录下的 .jsonl 日志文件中,不会上传到任何服务器,本页面也不加载任何外部资源。深度模式基于 Windows ETW 内核事件采集,已自动排除本工具自身产生的网络与文件活动。证书检测会周期性主动连接几个域名以校验 HTTPS 证书链(用于发现 TLS 拦截),是本工具唯一主动发起的网络连接,可用 -disable-cert-check 参数关闭。检测逻辑是启发式规则,请把告警当作「值得去查」的线索,而不是 100% 确定的结论。',

      'kind.open': '打开/读取',
      'kind.create': '创建',
      'kind.write': '写入',
      'kind.delete': '删除',

      'ev.summary': '证据详情',
      'ev.image_path': '完整路径',
      'ev.command_line': '命令行',
      'ev.ppid': '父进程 PID',
      'ev.sha256': 'SHA-256',
      'ev.start_time': '进程启动时间',
      'ev.vt_link': '用 VirusTotal 查这个哈希 ↗',

      'chip.identity_unknown': '身份不明',
      'chip.identity_unknown_pid': '身份不明 · PID {0}',
      'chip.name_pid': '{0} · PID {1}',
      'chip.inherited_suffix': ' (继承自父进程)',
      'chip.signed': '已签名',
      'chip.signed_by': '已签名: {0}',
      'chip.unsigned': '未签名',
      'chip.known_browser': '常见浏览器',
      'chip.suspicious_path': '可疑路径',

      'proc.cant_verify': '无法验证(身份不明)',
      'proc.checking': '检查中…',
      'proc.exited': '已退出',
      'proc.running': '运行中',

      'own.own_access': '本体访问',
      'own.non_own_access': '非本体访问',

      'cc.probe_failed': '探测失败',
      'cc.suspected_intercept': '疑似「{0}」拦截',
      'cc.not_public_ca': '非公共 CA',
      'cc.ok_local_av': '正常(本地安全软件: {0})',
      'cc.issuance_changed': '颁发信息已变化',
      'cc.ok': '正常',
      'cc.trusted': '可信',
      'cc.untrusted': '不可信',
    },

    en: {
      'header.subtitle': 'Per-process network / sensitive-file monitor',

      'settings.title': 'Settings',
      'settings.close': 'Close',
      'settings.language': 'Language',
      'settings.theme': 'Theme',
      'theme.system': 'System',
      'theme.light': 'Light',
      'theme.dark': 'Dark',
      'settings.autostart': 'Launch at startup',
      'settings.log_dir': 'Log directory',
      'settings.open_dir_btn': 'Open',
      'settings.clean_logs': 'Clean logs',
      'settings.clean_logs_btn': 'Clean',
      'settings.clean_logs_done': 'Freed {0} MB of disk space.',
      'settings.clean_logs_partial': 'Some files are still held open by another program and couldn\'t be cleaned — try again later.',
      'settings.clean_logs_failed': 'Clean failed: {0}',
      'settings.autostart_failed': 'Failed to change autostart: {0}',
      'settings.monitoring': 'Monitoring status',
      'settings.stop_monitoring': 'Stop Monitoring',
      'settings.start_monitoring': 'Start Monitoring',
      'settings.monitoring_running': 'Monitoring is active.',
      'settings.monitoring_stopped': 'Stopped — the program is still running, but no new events are being collected.',
      'settings.monitoring_toggle_failed': 'Action failed: {0}',
      'settings.quit': 'Exit program',
      'settings.quit_btn': 'Exit Program',
      'settings.quit_hint': 'This closes the whole program, including the system tray icon. If you just want to pause collection, use "Stop Monitoring" above instead — no need to exit.',
      'settings.quit_confirm': 'Exit the program? This closes the whole program, including the system tray icon. If you just want to pause collection, "Stop Monitoring" is enough.',

      'conn.connecting': 'Connecting to background service…',
      'conn.connected': 'Connected · live monitoring',

      'btn.pause': 'Pause refresh',
      'btn.pause_title': 'New events are still recorded while paused, the view just stops refreshing',
      'btn.resume': 'Resume refresh',
      'btn.ack': 'Ack',

      'stat.critical': 'Critical alerts',
      'stat.high': 'High alerts',
      'stat.conns': 'Network connections',
      'stat.files': 'Sensitive file access',
      'stat.procs': 'Processes observed',

      'tab.alerts': 'Alerts',
      'tab.conns': 'Connections',
      'tab.files': 'Sensitive Files',
      'tab.dns': 'DNS Lookups',
      'tab.procs': 'Processes',
      'tab.certchecks': 'Cert Checks',

      'sev.all': 'All severities',
      'sev.critical': 'Critical',
      'sev.high': 'High',
      'sev.medium': 'Medium',
      'sev.low': 'Low',
      'sev.info': 'Info',

      'filter.alert_search_ph': 'Search by process name / content…',
      'filter.hide_ack': 'Hide acknowledged',
      'filter.conn_search_ph': 'Search by process name / IP / domain…',
      'filter.ai_only': 'Claude/ChatGPT/Gemini traffic only',
      'filter.file_search_ph': 'Search by process name / app / path…',
      'filter.dns_search_ph': 'Search by process name / domain…',
      'filter.proc_search_ph': 'Search by process name / path…',
      'filter.certcheck_search_ph': 'Search by domain…',

      'col.time': 'Time',
      'col.process': 'Process',
      'col.pid': 'PID',
      'col.ppid': 'PPID',
      'col.direction': 'Direction',
      'col.proto': 'Proto',
      'col.remote_addr': 'Remote Address',
      'col.port': 'Port',
      'col.domain': 'Domain',
      'col.ai_service': 'AI Service',
      'col.target_app': 'Target App',
      'col.action': 'Action',
      'col.own_access': 'Own Access?',
      'col.path': 'Path',
      'col.query': 'Query',
      'col.results': 'Resolved To',
      'col.signature': 'Signature',
      'col.status': 'Status',
      'col.issuer': 'Issuer',
      'col.root_cert': 'Root Certificate',
      'col.public_ca_trusted': 'Public CA Trusted',

      'empty.alerts': 'No alerts · nothing suspicious detected so far, monitoring continues in the background.',
      'empty.certchecks': 'No certificate checks yet — the first probe usually completes within a few seconds of startup.',

      'footer.note': 'All data stays in local .jsonl log files under this machine’s data directory — nothing is uploaded to any server, and this page loads no external resources either. Deep-mode collection is based on Windows ETW kernel events, with this tool’s own network/file activity automatically excluded. Certificate checking periodically connects to a few domains to verify their HTTPS certificate chain (to detect TLS interception) — the only outbound connection this tool ever initiates itself; disable it with -disable-cert-check. Detection is heuristic — treat alerts as leads worth investigating, not as 100% certain conclusions.',

      'kind.open': 'Open/Read',
      'kind.create': 'Create',
      'kind.write': 'Write',
      'kind.delete': 'Delete',

      'ev.summary': 'Evidence details',
      'ev.image_path': 'Full path',
      'ev.command_line': 'Command line',
      'ev.ppid': 'Parent PID',
      'ev.sha256': 'SHA-256',
      'ev.start_time': 'Process start time',
      'ev.vt_link': 'Look up this hash on VirusTotal ↗',

      'chip.identity_unknown': 'Unidentified',
      'chip.identity_unknown_pid': 'Unidentified · PID {0}',
      'chip.name_pid': '{0} · PID {1}',
      'chip.inherited_suffix': ' (inherited from parent)',
      'chip.signed': 'Signed',
      'chip.signed_by': 'Signed: {0}',
      'chip.unsigned': 'Unsigned',
      'chip.known_browser': 'Known browser',
      'chip.suspicious_path': 'Suspicious path',

      'proc.cant_verify': 'Cannot verify (unidentified)',
      'proc.checking': 'Checking…',
      'proc.exited': 'Exited',
      'proc.running': 'Running',

      'own.own_access': 'Own access',
      'own.non_own_access': 'Non-owner access',

      'cc.probe_failed': 'Probe failed',
      'cc.suspected_intercept': 'Suspected "{0}" interception',
      'cc.not_public_ca': 'Not a public CA',
      'cc.ok_local_av': 'OK (local security software: {0})',
      'cc.issuance_changed': 'Issuance info changed',
      'cc.ok': 'OK',
      'cc.trusted': 'Trusted',
      'cc.untrusted': 'Untrusted',
    },

    de: {
      'header.subtitle': 'Prozessbezogene Netzwerk-/Dateizugriffsüberwachung',

      'settings.title': 'Einstellungen',
      'settings.close': 'Schließen',
      'settings.language': 'Sprache',
      'settings.theme': 'Erscheinungsbild',
      'theme.system': 'System',
      'theme.light': 'Hell',
      'theme.dark': 'Dunkel',
      'settings.autostart': 'Beim Systemstart starten',
      'settings.log_dir': 'Protokollverzeichnis',
      'settings.open_dir_btn': 'Öffnen',
      'settings.clean_logs': 'Protokolle bereinigen',
      'settings.clean_logs_btn': 'Bereinigen',
      'settings.clean_logs_done': '{0} MB Speicherplatz freigegeben.',
      'settings.clean_logs_partial': 'Einige Dateien werden noch von einem anderen Programm verwendet und konnten nicht bereinigt werden – später erneut versuchen.',
      'settings.clean_logs_failed': 'Bereinigung fehlgeschlagen: {0}',
      'settings.autostart_failed': 'Ändern des Autostarts fehlgeschlagen: {0}',
      'settings.monitoring': 'Überwachungsstatus',
      'settings.stop_monitoring': 'Überwachung stoppen',
      'settings.start_monitoring': 'Überwachung starten',
      'settings.monitoring_running': 'Überwachung ist aktiv.',
      'settings.monitoring_stopped': 'Gestoppt – das Programm läuft weiter, es werden aber keine neuen Ereignisse erfasst.',
      'settings.monitoring_toggle_failed': 'Aktion fehlgeschlagen: {0}',
      'settings.quit': 'Programm beenden',
      'settings.quit_btn': 'Programm beenden',
      'settings.quit_hint': 'Dadurch wird das gesamte Programm geschlossen, einschließlich des Tray-Symbols. Um nur die Erfassung zu pausieren, oben „Überwachung stoppen“ verwenden – ein Beenden ist dafür nicht nötig.',
      'settings.quit_confirm': 'Programm wirklich beenden? Dadurch wird das gesamte Programm geschlossen, einschließlich des Tray-Symbols. Um nur die Erfassung zu pausieren, genügt „Überwachung stoppen“.',

      'conn.connecting': 'Verbindung zum Hintergrunddienst wird hergestellt…',
      'conn.connected': 'Verbunden · Live-Überwachung',

      'btn.pause': 'Aktualisierung pausieren',
      'btn.pause_title': 'Neue Ereignisse werden auch während der Pause weiter erfasst, nur die Ansicht wird nicht aktualisiert',
      'btn.resume': 'Aktualisierung fortsetzen',
      'btn.ack': 'Bestätigen',

      'stat.critical': 'Kritische Warnungen',
      'stat.high': 'Hohe Warnungen',
      'stat.conns': 'Netzwerkverbindungen',
      'stat.files': 'Zugriffe auf sensible Dateien',
      'stat.procs': 'Beobachtete Prozesse',

      'tab.alerts': 'Warnungen',
      'tab.conns': 'Verbindungen',
      'tab.files': 'Sensible Dateien',
      'tab.dns': 'DNS-Auflösungen',
      'tab.procs': 'Prozesse',
      'tab.certchecks': 'Zertifikatsprüfung',

      'sev.all': 'Alle Stufen',
      'sev.critical': 'Kritisch',
      'sev.high': 'Hoch',
      'sev.medium': 'Mittel',
      'sev.low': 'Niedrig',
      'sev.info': 'Info',

      'filter.alert_search_ph': 'Suche nach Prozessname / Inhalt…',
      'filter.hide_ack': 'Bestätigte ausblenden',
      'filter.conn_search_ph': 'Suche nach Prozessname / IP / Domain…',
      'filter.ai_only': 'Nur Claude/ChatGPT/Gemini-Datenverkehr',
      'filter.file_search_ph': 'Suche nach Prozessname / App / Pfad…',
      'filter.dns_search_ph': 'Suche nach Prozessname / Domain…',
      'filter.proc_search_ph': 'Suche nach Prozessname / Pfad…',
      'filter.certcheck_search_ph': 'Suche nach Domain…',

      'col.time': 'Zeit',
      'col.process': 'Prozess',
      'col.pid': 'PID',
      'col.ppid': 'PPID',
      'col.direction': 'Richtung',
      'col.proto': 'Protokoll',
      'col.remote_addr': 'Zieladresse',
      'col.port': 'Port',
      'col.domain': 'Zugehörige Domain',
      'col.ai_service': 'KI-Dienst',
      'col.target_app': 'Ziel-App',
      'col.action': 'Aktion',
      'col.own_access': 'Eigenzugriff?',
      'col.path': 'Pfad',
      'col.query': 'Abgefragte Domain',
      'col.results': 'Auflösungsergebnis',
      'col.signature': 'Signatur',
      'col.status': 'Status',
      'col.issuer': 'Zertifikatsaussteller',
      'col.root_cert': 'Root-Zertifikat',
      'col.public_ca_trusted': 'Öffentliche CA vertrauenswürdig',

      'empty.alerts': 'Keine Warnungen · Bisher wurde nichts Verdächtiges erkannt, die Überwachung läuft weiter im Hintergrund.',
      'empty.certchecks': 'Noch keine Zertifikatsprüfungen — die erste Prüfung ist meist innerhalb weniger Sekunden nach dem Start abgeschlossen.',

      'footer.note': 'Alle Daten verbleiben ausschließlich in lokalen .jsonl-Protokolldateien im Datenverzeichnis dieses Rechners — nichts wird an einen Server hochgeladen, und diese Seite lädt auch keine externen Ressourcen. Die Deep-Mode-Erfassung basiert auf Windows-ETW-Kernel-Ereignissen; die eigene Netzwerk-/Dateiaktivität dieses Tools wird automatisch ausgeschlossen. Die Zertifikatsprüfung verbindet sich periodisch mit einigen Domains, um deren HTTPS-Zertifikatskette zu prüfen (zur Erkennung von TLS-Interception) — die einzige Netzwerkverbindung, die dieses Tool selbst aktiv aufbaut; mit -disable-cert-check abschaltbar. Die Erkennung basiert auf Heuristiken — Warnungen sind Hinweise, die eine Prüfung wert sind, keine 100%ig sicheren Schlussfolgerungen.',

      'kind.open': 'Öffnen/Lesen',
      'kind.create': 'Erstellen',
      'kind.write': 'Schreiben',
      'kind.delete': 'Löschen',

      'ev.summary': 'Beweisdetails',
      'ev.image_path': 'Vollständiger Pfad',
      'ev.command_line': 'Befehlszeile',
      'ev.ppid': 'Übergeordnete PID',
      'ev.sha256': 'SHA-256',
      'ev.start_time': 'Prozessstartzeit',
      'ev.vt_link': 'Diesen Hash bei VirusTotal nachschlagen ↗',

      'chip.identity_unknown': 'Nicht identifiziert',
      'chip.identity_unknown_pid': 'Nicht identifiziert · PID {0}',
      'chip.name_pid': '{0} · PID {1}',
      'chip.inherited_suffix': ' (vom übergeordneten Prozess geerbt)',
      'chip.signed': 'Signiert',
      'chip.signed_by': 'Signiert: {0}',
      'chip.unsigned': 'Nicht signiert',
      'chip.known_browser': 'Bekannter Browser',
      'chip.suspicious_path': 'Verdächtiger Pfad',

      'proc.cant_verify': 'Nicht überprüfbar (nicht identifiziert)',
      'proc.checking': 'Wird geprüft…',
      'proc.exited': 'Beendet',
      'proc.running': 'Läuft',

      'own.own_access': 'Eigenzugriff',
      'own.non_own_access': 'Fremdzugriff',

      'cc.probe_failed': 'Prüfung fehlgeschlagen',
      'cc.suspected_intercept': 'Vermutete Interception durch „{0}“',
      'cc.not_public_ca': 'Keine öffentliche CA',
      'cc.ok_local_av': 'OK (lokale Sicherheitssoftware: {0})',
      'cc.issuance_changed': 'Ausstellungsdaten geändert',
      'cc.ok': 'OK',
      'cc.trusted': 'Vertrauenswürdig',
      'cc.untrusted': 'Nicht vertrauenswürdig',
    },
  };

  const LOCALE_TAG = { zh: 'zh-CN', en: 'en-US', de: 'de-DE' };
  const HTML_LANG = { zh: 'zh-CN', en: 'en', de: 'de' };
  const SUPPORTED = Object.keys(DICT);

  let current = 'zh';

  function setLang(lang) {
    current = DICT[lang] ? lang : 'zh';
    document.documentElement.lang = HTML_LANG[current];
  }

  function getLang() {
    return current;
  }

  // BCP-47 tag for Date#toLocaleTimeString/toLocaleDateString, matched to
  // the active dashboard language rather than the OS locale — the two are
  // usually the same but don't have to be (e.g. -lang overriding the
  // detected system language for one run).
  function locale() {
    return LOCALE_TAG[current] || 'en-US';
  }

  // t looks up key in the active language, falling back to Chinese (this
  // catalog's most complete/original language) and then the bare key, so a
  // gap never renders as literally blank. {0}, {1}, ... placeholders are
  // replaced with the corresponding argument.
  function t(key, ...args) {
    const table = DICT[current] || DICT.zh;
    let s = key in table ? table[key] : (key in DICT.zh ? DICT.zh[key] : key);
    args.forEach((a, i) => {
      s = s.split('{' + i + '}').join(a);
    });
    return s;
  }

  // Applies data-i18n[-placeholder|-title] attributes across the document.
  // Plain data-i18n sets textContent, which is only safe on elements whose
  // entire content is the translated string — anywhere an icon or a count
  // badge shares the element (see index.html), the translatable text is
  // wrapped in its own inner <span data-i18n> instead so this never clobbers
  // a sibling.
  function translatePage() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      el.textContent = t(el.getAttribute('data-i18n'));
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      el.title = t(el.getAttribute('data-i18n-title'));
    });
  }

  return { setLang, getLang, locale, t, translatePage, SUPPORTED };
})();

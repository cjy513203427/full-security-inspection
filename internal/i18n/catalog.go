package i18n

// catalog holds every translated message this package serves, keyed by a
// stable, dotted message id and then by language. Grouped below by the area
// of the app each key belongs to (CLI flags, startup/log messages, tray,
// alert text, certcheck findings, config's sensitive-target display names).
//
// Multi-argument templates use explicit argument indices (%[1]s, %[2]d...)
// rather than relying on positional order, since a natural translation
// often needs to reorder words relative to the source Chinese — the index
// lets every language's template pick args in whatever order reads best
// without the call site needing to know or care.
var catalog = map[string]map[Lang]string{
	// ---------- CLI flag descriptions (-h output) ----------

	"flag.data_dir": {
		ZH: "日志/数据保存目录",
		EN: "Directory to store logs/data in",
		DE: "Verzeichnis zum Speichern von Protokollen/Daten",
	},
	"flag.debug_etw": {
		ZH: "可选:把所有原始 ETW 事件的 JSON 写入此文件,用于排查字段映射问题",
		EN: "Optional: write the JSON of every raw ETW event to this file, for troubleshooting field-mapping issues",
		DE: "Optional: JSON aller rohen ETW-Ereignisse in diese Datei schreiben, zur Fehlersuche bei Feldzuordnungen",
	},
	"flag.skip_elevate": {
		ZH: "跳过管理员自提权(仅用于调试界面本身;跳过后将看不到任何文件/网络事件)",
		EN: "Skip automatic Administrator elevation (only for debugging the UI itself; no file/network events will ever arrive if skipped)",
		DE: "Automatische Administrator-Rechteerhöhung überspringen (nur zum Debuggen der Oberfläche selbst; dabei treffen keine Datei-/Netzwerkereignisse ein)",
	},
	"flag.start_hidden": {
		ZH: "启动时不显示窗口,只驻留在系统托盘(用于开机自启动场景,避免每次登录都弹窗)",
		EN: "Don't show the window on startup, stay in the system tray only (for autostart scenarios, to avoid popping up a window at every login)",
		DE: "Fenster beim Start nicht anzeigen, nur im System-Tray bleiben (für Autostart-Szenarien, damit sich bei jeder Anmeldung kein Fenster öffnet)",
	},
	"flag.install_autostart": {
		ZH: "注册开机/登录自启动计划任务,然后退出(不会立刻开始监控)",
		EN: "Register a scheduled task to autostart at login, then exit (does not start monitoring immediately)",
		DE: "Geplante Aufgabe für den Autostart bei Anmeldung registrieren und dann beenden (startet die Überwachung nicht sofort)",
	},
	"flag.uninstall_autostart": {
		ZH: "移除开机自启动计划任务,然后退出",
		EN: "Remove the autostart scheduled task, then exit",
		DE: "Geplante Autostart-Aufgabe entfernen und dann beenden",
	},
	"flag.clean_logs": {
		ZH: "清空历史日志文件(含所有 .jsonl 和已轮转的备份),释放磁盘空间,然后退出。若监控正在运行,请先在托盘图标里「退出监控」再执行",
		EN: "Clear historical log files (all .jsonl files and rotated backups) to free disk space, then exit. If the monitor is currently running, quit it from the tray icon first",
		DE: "Historische Protokolldateien löschen (alle .jsonl-Dateien und rotierten Backups), um Speicherplatz freizugeben, dann beenden. Falls die Überwachung gerade läuft, bitte zuerst über das Tray-Symbol beenden",
	},
	"flag.disable_cert_check": {
		ZH: "关闭证书检测(周期性探测几个域名的 HTTPS 证书链,用于发现是否存在 TLS 中间人拦截)。这是本工具唯一会主动发起的网络连接,默认开启;不放心可以用这个参数关掉",
		EN: "Disable certificate checking (periodic HTTPS certificate-chain probes against a few domains, to detect TLS interception). This is the only outbound connection this tool ever initiates itself, on by default; turn it off with this flag if you're not comfortable with it",
		DE: "Zertifikatsprüfung deaktivieren (periodische HTTPS-Zertifikatsketten-Prüfungen einiger Domains zur Erkennung von TLS-Interception). Dies ist die einzige Netzwerkverbindung, die dieses Tool selbst aktiv aufbaut, standardmäßig aktiviert; bei Bedenken mit diesem Flag abschaltbar",
	},
	"flag.lang": {
		ZH: "覆盖界面语言(zh/en/de),不填则使用已保存的设置或跟随系统语言",
		EN: "Override the UI language (zh/en/de); if unset, uses the saved preference or the system language",
		DE: "Sprache überschreiben (zh/en/de); ohne Angabe wird die gespeicherte Einstellung oder die Systemsprache verwendet",
	},
	"flag.deprecated_no_browser": {
		ZH: "(已废弃,不再生效)",
		EN: "(deprecated, no longer has any effect)",
		DE: "(veraltet, ohne Wirkung)",
	},
	"flag.deprecated_port": {
		ZH: "(已废弃,不再生效——现在是原生窗口,不再监听端口)",
		EN: "(deprecated, no longer has any effect — this is now a native window and no longer listens on a port)",
		DE: "(veraltet, ohne Wirkung – dies ist jetzt ein natives Fenster und lauscht nicht mehr auf einem Port)",
	},

	// ---------- startup / log messages / message boxes ----------

	"log.clean_logs_failed": {
		ZH: "清理日志失败: %v\n(如果监控正在运行,请先在托盘图标里点「退出监控」,再重新执行清理)",
		EN: "Failed to clean logs: %v\n(if the monitor is currently running, quit it from the tray icon first, then re-run the cleanup)",
		DE: "Fehler beim Bereinigen der Protokolle: %v\n(falls die Überwachung gerade läuft, bitte zuerst über das Tray-Symbol beenden und die Bereinigung dann erneut ausführen)",
	},
	"log.clean_logs_done": {
		ZH: "已清空日志历史,释放约 %.1f MB 磁盘空间。",
		EN: "Log history cleared, freeing about %.1f MB of disk space.",
		DE: "Protokollverlauf gelöscht, dabei wurden etwa %.1f MB Speicherplatz freigegeben.",
	},
	"log.requesting_elevation": {
		ZH: "当前不是管理员权限,正在请求 UAC 提权重启…",
		EN: "Not running as Administrator — requesting a UAC-elevated restart…",
		DE: "Nicht als Administrator ausgeführt – fordere Neustart mit UAC-Rechteerhöhung an…",
	},
	"log.elevation_failed": {
		ZH: "提权失败: %v\n请手动以管理员身份运行本程序,或者你在 UAC 弹窗里点了「否」。",
		EN: "Elevation failed: %v\nPlease run this program manually as Administrator, or you clicked \"No\" on the UAC prompt.",
		DE: "Rechteerhöhung fehlgeschlagen: %v\nBitte das Programm manuell als Administrator ausführen, oder du hast im UAC-Dialog auf „Nein\" geklickt.",
	},
	"log.get_self_path_failed": {
		ZH: "获取自身路径失败: %v",
		EN: "Failed to get own executable path: %v",
		DE: "Eigener Programmpfad konnte nicht ermittelt werden: %v",
	},
	"log.install_autostart_failed": {
		ZH: "注册自启动失败: %v",
		EN: "Failed to register autostart: %v",
		DE: "Autostart-Registrierung fehlgeschlagen: %v",
	},
	"log.install_autostart_done": {
		ZH: "已注册开机自启动(登录时以管理员权限自动运行,不再弹 UAC;窗口默认隐藏,只在系统托盘)。可随时用 -uninstall-autostart 移除。",
		EN: "Autostart registered (runs automatically with Administrator rights at logon, no UAC prompt; the window starts hidden, tray only). Remove any time with -uninstall-autostart.",
		DE: "Autostart registriert (wird beim Anmelden automatisch mit Administratorrechten ausgeführt, kein UAC-Dialog; das Fenster startet ausgeblendet, nur im Tray). Kann jederzeit mit -uninstall-autostart entfernt werden.",
	},
	"log.uninstall_autostart_failed": {
		ZH: "移除自启动失败: %v",
		EN: "Failed to remove autostart: %v",
		DE: "Entfernen des Autostarts fehlgeschlagen: %v",
	},
	"log.uninstall_autostart_done": {
		ZH: "已移除开机自启动计划任务。",
		EN: "Autostart scheduled task removed.",
		DE: "Geplante Autostart-Aufgabe wurde entfernt.",
	},
	"log.mkdir_data_dir_failed": {
		ZH: "无法创建数据目录 %[1]s: %[2]v",
		EN: "Could not create data directory %[1]s: %[2]v",
		DE: "Datenverzeichnis %[1]s konnte nicht erstellt werden: %[2]v",
	},
	"log.init_store_failed": {
		ZH: "初始化存储失败: %v",
		EN: "Failed to initialize storage: %v",
		DE: "Initialisierung des Speichers fehlgeschlagen: %v",
	},
	"log.init_etw_failed": {
		ZH: "初始化 ETW 采集器失败: %v",
		EN: "Failed to initialize the ETW collector: %v",
		DE: "Initialisierung des ETW-Collectors fehlgeschlagen: %v",
	},
	"log.etw_start_skipped": {
		ZH: "警告: ETW 采集未启动 (%v) — 因为传入了 -skip-elevate,窗口仍会打开但不会有任何事件。",
		EN: "Warning: ETW collection did not start (%v) — because -skip-elevate was passed, the window will still open but no events will ever arrive.",
		DE: "Warnung: ETW-Erfassung wurde nicht gestartet (%v) – da -skip-elevate übergeben wurde, öffnet sich das Fenster trotzdem, es treffen jedoch keine Ereignisse ein.",
	},
	"log.etw_start_failed": {
		ZH: "启动 ETW 采集失败: %v\n(需要以管理员身份运行;如果你确实是管理员还看到这个,请把 -debug-etw 的输出发给我排查)",
		EN: "Failed to start ETW collection: %v\n(this requires running as Administrator; if you already are and still see this, please send the -debug-etw output for troubleshooting)",
		DE: "Start der ETW-Erfassung fehlgeschlagen: %v\n(erfordert Ausführung als Administrator; falls du das bereits bist und dies trotzdem siehst, sende bitte die -debug-etw-Ausgabe zur Fehlersuche)",
	},
	"log.load_assets_failed": {
		ZH: "加载界面资源失败: %v",
		EN: "Failed to load UI assets: %v",
		DE: "Laden der UI-Ressourcen fehlgeschlagen: %v",
	},
	"log.starting_window": {
		ZH: "NetWatch CookieGuard 正在启动原生窗口界面…",
		EN: "NetWatch CookieGuard is starting the native window UI…",
		DE: "NetWatch CookieGuard startet die native Fensteroberfläche…",
	},
	"log.data_dir": {
		ZH: "数据目录: %s",
		EN: "Data directory: %s",
		DE: "Datenverzeichnis: %s",
	},
	"log.debug_etw_mode": {
		ZH: "调试模式:原始 ETW 事件将写入 %s",
		EN: "Debug mode: raw ETW events will be written to %s",
		DE: "Debug-Modus: Rohe ETW-Ereignisse werden nach %s geschrieben",
	},
	"log.stopping_monitor": {
		ZH: "正在停止监控…",
		EN: "Stopping monitoring…",
		DE: "Überwachung wird gestoppt…",
	},
	"log.monitoring_stopped_by_user": {
		ZH: "已通过控制面板停止监控(程序仍在运行)",
		EN: "Monitoring stopped from the dashboard (the program is still running)",
		DE: "Überwachung über das Dashboard gestoppt (das Programm läuft weiter)",
	},
	"log.monitoring_started_by_user": {
		ZH: "已通过控制面板重新开始监控",
		EN: "Monitoring restarted from the dashboard",
		DE: "Überwachung über das Dashboard neu gestartet",
	},
	"log.window_start_failed": {
		ZH: "启动窗口失败: %v\n(WebView2 运行时可能缺失,下载: https://developer.microsoft.com/microsoft-edge/webview2/)",
		EN: "Failed to start the window: %v\n(the WebView2 runtime may be missing — download: https://developer.microsoft.com/microsoft-edge/webview2/)",
		DE: "Fenster konnte nicht gestartet werden: %v\n(die WebView2-Runtime fehlt möglicherweise – Download: https://developer.microsoft.com/microsoft-edge/webview2/)",
	},
	"log.startup_failed_title": {
		ZH: "NetWatch CookieGuard - 启动失败",
		EN: "NetWatch CookieGuard - Startup Failed",
		DE: "NetWatch CookieGuard – Start fehlgeschlagen",
	},
	"log.open_token_failed": {
		ZH: "警告: 打开进程令牌失败,部分沙箱化子进程(如 Chrome 的网络服务进程)可能无法识别名称: %v",
		EN: "Warning: failed to open the process token — some sandboxed child processes (e.g. Chrome's network-service process) may not be identifiable by name: %v",
		DE: "Warnung: Öffnen des Prozess-Tokens fehlgeschlagen – einige Sandbox-Kindprozesse (z. B. der Netzwerkdienst-Prozess von Chrome) können möglicherweise nicht namentlich identifiziert werden: %v",
	},
	"log.lookup_privilege_failed": {
		ZH: "警告: 查找 SeDebugPrivilege 失败: %v",
		EN: "Warning: failed to look up SeDebugPrivilege: %v",
		DE: "Warnung: Suche nach SeDebugPrivilege fehlgeschlagen: %v",
	},
	"log.enable_privilege_failed": {
		ZH: "警告: 启用 SeDebugPrivilege 失败(可能不是管理员): %v",
		EN: "Warning: failed to enable SeDebugPrivilege (may not be running as Administrator): %v",
		DE: "Warnung: Aktivierung von SeDebugPrivilege fehlgeschlagen (möglicherweise keine Administratorrechte): %v",
	},

	// ---------- system tray ----------

	"tray.tooltip_normal": {
		ZH: "NetWatch CookieGuard - 正常监控中",
		EN: "NetWatch CookieGuard - Monitoring normally",
		DE: "NetWatch CookieGuard – Normale Überwachung",
	},
	"tray.tooltip_alert": {
		ZH: "NetWatch CookieGuard - ⚠ %d 条高危/严重告警待处理",
		EN: "NetWatch CookieGuard - ⚠ %d high/critical alert(s) pending",
		DE: "NetWatch CookieGuard – ⚠ %d unbestätigte hoch-/kritische Warnungen",
	},
	"tray.open": {
		ZH: "打开监控面板",
		EN: "Open Dashboard",
		DE: "Überwachungsfenster öffnen",
	},
	"tray.open_desc": {
		ZH: "显示监控窗口",
		EN: "Show the monitor window",
		DE: "Überwachungsfenster anzeigen",
	},
	"tray.status_normal": {
		ZH: "状态: 正常监控中",
		EN: "Status: Monitoring normally",
		DE: "Status: Normale Überwachung",
	},
	"tray.quit": {
		ZH: "退出程序",
		EN: "Exit Program",
		DE: "Programm beenden",
	},
	"tray.quit_desc": {
		ZH: "停止监控并退出整个程序",
		EN: "Stop monitoring and exit the whole program",
		DE: "Überwachung stoppen und das gesamte Programm beenden",
	},

	// ---------- alert titles/details (internal/correlate) ----------

	"alert.file.title": {
		ZH: "可疑进程读取了 %s",
		EN: "Suspicious process read %s",
		DE: "Verdächtiger Prozess hat %s gelesen",
	},
	"alert.file.title_unknown": {
		ZH: "身份不明的进程读取了 %s",
		EN: "An unidentified process read %s",
		DE: "Ein nicht identifizierter Prozess hat %s gelesen",
	},
	"alert.file.detail_suffix": {
		ZH: "。文件路径: %s",
		EN: ". File path: %s",
		DE: ". Dateipfad: %s",
	},
	"reason.identity_unknown_full": {
		ZH: "未能确认该进程的名称/路径(已尝试直接查询、进程快照枚举、父进程继承三种方式均失败,可能是权限受限的沙箱子进程)",
		EN: "Could not determine this process's name/path (direct query, process-snapshot enumeration, and parent-process inheritance all failed — it may be a permission-restricted sandboxed child process)",
		DE: "Name/Pfad dieses Prozesses konnte nicht ermittelt werden (direkte Abfrage, Prozess-Snapshot-Enumeration und Vererbung vom übergeordneten Prozess sind alle fehlgeschlagen – möglicherweise ein rechtebeschränkter Sandbox-Kindprozess)",
	},
	"reason.non_owner_access": {
		ZH: "进程不是 %[1]s 本身,却访问了它的%[2]s存储文件",
		EN: "This process is not %[1]s itself, yet it accessed its %[2]s store",
		DE: "Dieser Prozess ist nicht %[1]s selbst, hat aber auf dessen %[2]s-Speicher zugegriffen",
	},
	"reason.unsigned": {
		ZH: "该程序没有有效的数字签名",
		EN: "This program has no valid digital signature",
		DE: "Dieses Programm besitzt keine gültige digitale Signatur",
	},
	"reason.suspicious_path_long": {
		ZH: "运行路径位于 Temp/AppData/Downloads 等常见恶意软件藏身目录",
		EN: "Running from a path under Temp/AppData/Downloads — a common malware hiding spot",
		DE: "Wird aus einem Pfad unter Temp/AppData/Downloads ausgeführt – ein verbreitetes Versteck für Malware",
	},
	"reason.identity_unknown_check_pid": {
		ZH: "未能确认该进程的名称/路径,建议在「进程」标签页用 PID 交叉核对",
		EN: "Could not determine this process's name/path — cross-check the PID on the Processes tab",
		DE: "Name/Pfad dieses Prozesses konnte nicht ermittelt werden – bitte die PID auf dem Tab „Prozesse\" abgleichen",
	},
	"reason.unsigned_short": {
		ZH: "程序未签名",
		EN: "Not signed",
		DE: "Nicht signiert",
	},
	"reason.suspicious_path_short": {
		ZH: "运行路径可疑",
		EN: "Suspicious execution path",
		DE: "Verdächtiger Ausführungspfad",
	},
	"reason.no_dns_seen": {
		ZH: "本机未观察到该地址的域名解析过程,可能是硬编码的服务器地址",
		EN: "No DNS resolution for this address was observed locally — it may be a hardcoded server address",
		DE: "Für diese Adresse wurde lokal keine DNS-Auflösung beobachtet – möglicherweise eine fest codierte Serveradresse",
	},
	"alert.exfil.title": {
		ZH: "🚨 疑似窃密回传:读取登录凭据后立即联网",
		EN: "🚨 Suspected credential exfiltration: read login credentials then immediately connected",
		DE: "🚨 Vermuteter Zugangsdaten-Diebstahl: Anmeldedaten gelesen und sofort verbunden",
	},
	"alert.exfil.title_ai": {
		ZH: "🤖 疑似 %s 会话被窃取:读取凭据后立即联网",
		EN: "🤖 Suspected %s session theft: read credentials then immediately connected",
		DE: "🤖 Vermuteter %s-Sitzungsdiebstahl: Zugangsdaten gelesen und sofort verbunden",
	},
	"alert.exfil.detail": {
		ZH: "进程在 %[1]d 秒内读取了: %[2]s;随后连接了 %[3]s:%[4]d。",
		EN: "The process read: %[2]s within %[1]d seconds, then connected to %[3]s:%[4]d.",
		DE: "Der Prozess hat innerhalb von %[1]d Sekunden gelesen: %[2]s; anschließend Verbindung zu %[3]s:%[4]d hergestellt.",
	},
	"alert.suspnet.title": {
		ZH: "可疑位置的未签名程序发起联网",
		EN: "Unsigned program from a suspicious location made a network connection",
		DE: "Unsigniertes Programm aus verdächtigem Pfad hat eine Netzwerkverbindung hergestellt",
	},
	"alert.suspnet.title_ai": {
		ZH: "🤖 可疑程序正在联网到 %s",
		EN: "🤖 Suspicious program is connecting to %s",
		DE: "🤖 Verdächtiges Programm verbindet sich mit %s",
	},
	"alert.suspnet.detail": {
		ZH: "未签名、运行于可疑路径的未知程序主动连接了 %[1]s:%[2]d",
		EN: "An unsigned, unknown program running from a suspicious path actively connected to %[1]s:%[2]d",
		DE: "Ein unsigniertes, unbekanntes Programm aus einem verdächtigen Pfad hat aktiv eine Verbindung zu %[1]s:%[2]d hergestellt",
	},
	"alert.suspnet.detail_ai": {
		ZH: "。目标属于你重点关注的 AI 服务(%s),即使没有先观察到读取凭据文件的动作,也建议优先核实这个进程。",
		EN: ". The destination is one of your watched AI services (%s) — even without an observed credential-file read beforehand, this process is worth checking first.",
		DE: ". Das Ziel gehört zu den überwachten KI-Diensten (%s) – auch ohne vorher beobachtetes Auslesen einer Zugangsdatendatei sollte dieser Prozess vorrangig überprüft werden.",
	},
	"alert.beacon.title": {
		ZH: "检测到规律性心跳联网(可能是恶意软件回连)",
		EN: "Regular heartbeat-style network activity detected (possible malware callback)",
		DE: "Regelmäßige Heartbeat-Netzwerkaktivität erkannt (möglicher Malware-Callback)",
	},
	"alert.beacon.title_ai": {
		ZH: "🤖 检测到规律性心跳联网到 %s",
		EN: "🤖 Regular heartbeat-style connections detected to %s",
		DE: "🤖 Regelmäßige Heartbeat-Verbindungen zu %s erkannt",
	},
	// %[4]/%[6] are pre-formatted whole-number strings (%s), not raw floats
	// rendered with "%[N].0f" — Go's fmt package rejects combining an
	// explicit argument index with a width/precision on the same verb, and
	// doesn't do it loudly: it silently renders "%!f(BADINDEX)" into the
	// alert text instead of erroring anywhere at build or test time. See
	// correlate.trackBeacon's call site, which does the rounding before
	// calling i18n.T.
	"alert.beacon.detail": {
		ZH: "%[1]s (PID %[2]d) 在过去 %[3]d 秒内以约 %[4]s 秒的间隔反复连接 %[5]s,间隔非常规律(抖动 < %[6]s%%),不像正常用户交互产生的流量。",
		EN: "%[1]s (PID %[2]d) repeatedly connected to %[5]s at roughly %[4]s-second intervals over the past %[3]d seconds — the timing is unusually regular (jitter < %[6]s%%), not typical of normal user-driven traffic.",
		DE: "%[1]s (PID %[2]d) hat sich in den letzten %[3]d Sekunden wiederholt in etwa %[4]s-Sekunden-Abständen mit %[5]s verbunden – das Timing ist ungewöhnlich regelmäßig (Schwankung < %[6]s%%), untypisch für normalen, nutzergesteuerten Datenverkehr.",
	},
	"common.list_sep": {
		ZH: "、",
		EN: ", ",
		DE: ", ",
	},

	// ---------- certcheck findings ----------

	"certcheck.no_certificate": {
		ZH: "服务器未返回任何证书",
		EN: "The server did not present any certificate",
		DE: "Der Server hat kein Zertifikat übermittelt",
	},
	"certcheck.vendor.title": {
		ZH: "%[1]s 的证书疑似被「%[2]s」拦截检查",
		EN: "%[1]s's certificate appears to be intercepted by \"%[2]s\"",
		DE: "Das Zertifikat von %[1]s scheint von „%[2]s\" abgefangen zu werden",
	},
	"certcheck.vendor.detail": {
		ZH: "到 %[1]s 的 HTTPS 连接,证书颁发者为「%[2]s / %[3]s」,与已知的企业级 SSL 检查/代理产品特征匹配。这通常意味着这台设备的 HTTPS 流量正在被解密检查(常见于公司/学校等受管网络的出口)。如果你确实处在这类网络下,这可能是预期行为;如果不是,建议核实这台机器最近有没有被安装可疑的根证书。",
		EN: "The HTTPS connection to %[1]s presented a certificate issued by \"%[2]s / %[3]s\", matching a known enterprise SSL-inspection/proxy product's fingerprint. This usually means this device's HTTPS traffic is being decrypted and inspected (common at the network edge of managed corporate/school networks). If you are indeed on such a network, this may be expected; if not, check whether a suspicious root certificate was recently installed on this machine.",
		DE: "Die HTTPS-Verbindung zu %[1]s hat ein Zertifikat des Ausstellers „%[2]s / %[3]s\" vorgelegt, das mit dem Fingerabdruck eines bekannten Enterprise-SSL-Inspection-/Proxy-Produkts übereinstimmt. Das bedeutet in der Regel, dass der HTTPS-Datenverkehr dieses Geräts entschlüsselt und geprüft wird (üblich am Netzwerkübergang verwalteter Firmen-/Schulnetzwerke). Falls du dich tatsächlich in einem solchen Netzwerk befindest, kann das normal sein; falls nicht, prüfe, ob kürzlich ein verdächtiges Root-Zertifikat auf diesem Gerät installiert wurde.",
	},
	"certcheck.untrusted.title": {
		ZH: "%s 的证书链未通过公共 CA 校验",
		EN: "%s's certificate chain did not verify against the public CA list",
		DE: "Die Zertifikatskette von %s konnte nicht gegen die öffentliche CA-Liste verifiziert werden",
	},
	"certcheck.untrusted.detail": {
		ZH: "这台电脑判定到 %[1]s 的 HTTPS 连接可信,但证书颁发者「%[2]s / %[3]s」不在已知的公共证书颁发机构名单里,根证书为「%[4]s」。这通常意味着系统信任库里有一个不属于标准公共 CA 的根证书——可能是 TLS 拦截,也可能是某个软件自行安装的证书,建议核实来源。",
		EN: "This computer trusts the HTTPS connection to %[1]s, but the certificate issuer \"%[2]s / %[3]s\" is not on the known public CA list, and the root certificate is \"%[4]s\". This usually means the system trust store contains a root certificate that isn't a standard public CA — possibly TLS interception, possibly a certificate some software installed itself. Worth verifying its origin.",
		DE: "Dieser Computer stuft die HTTPS-Verbindung zu %[1]s als vertrauenswürdig ein, aber der Zertifikatsaussteller „%[2]s / %[3]s\" steht nicht auf der Liste bekannter öffentlicher Zertifizierungsstellen, und das Root-Zertifikat lautet „%[4]s\". Das bedeutet meist, dass sich im System-Vertrauensspeicher ein Root-Zertifikat befindet, das keine gängige öffentliche CA ist – möglicherweise TLS-Interception, möglicherweise ein von Software selbst installiertes Zertifikat. Die Herkunft sollte geprüft werden.",
	},
	"certcheck.changed.title": {
		ZH: "%s 的证书颁发信息发生了变化",
		EN: "%s's certificate issuance details have changed",
		DE: "Die Zertifikatsausstellungsdaten von %s haben sich geändert",
	},
	"certcheck.changed.detail": {
		ZH: "到 %[1]s 的证书颁发者/根证书与上次检查时不同(现为「%[2]s / %[3]s」)。可能只是网站正常的证书轮换,也可能是网络环境变了(比如新接入了一个会拦截流量的网络),建议留意。",
		EN: "The certificate issuer/root for %[1]s differs from the last check (now \"%[2]s / %[3]s\"). This could just be normal certificate rotation, or the network environment changed (e.g. you're now on a network that intercepts traffic) — worth keeping an eye on.",
		DE: "Der Zertifikatsaussteller/das Root-Zertifikat für %[1]s unterscheidet sich von der letzten Prüfung (jetzt „%[2]s / %[3]s\"). Das kann eine normale Zertifikatsrotation der Website sein oder auf eine geänderte Netzwerkumgebung hindeuten (z. B. ein neues Netzwerk, das den Datenverkehr abfängt) – im Auge behalten.",
	},

	// ---------- config: sensitive-target display names & category labels ----------

	"target.browser_cookies": {
		ZH: "%s Cookies 数据库",
		EN: "%s Cookies Database",
		DE: "%s-Cookie-Datenbank",
	},
	"target.browser_password": {
		ZH: "%s 保存的密码",
		EN: "%s Saved Passwords",
		DE: "%s gespeicherte Passwörter",
	},
	"target.browser_local_storage": {
		ZH: "%s Local Storage(可能含网页 token)",
		EN: "%s Local Storage (may contain web tokens)",
		DE: "%s Local Storage (kann Web-Token enthalten)",
	},
	"target.firefox_cookies": {
		ZH: "Firefox Cookies",
		EN: "Firefox Cookies",
		DE: "Firefox-Cookies",
	},
	"target.firefox_password": {
		ZH: "Firefox 保存的密码",
		EN: "Firefox Saved Passwords",
		DE: "Firefox gespeicherte Passwörter",
	},
	"target.firefox_master_key": {
		ZH: "Firefox 密码主密钥",
		EN: "Firefox Password Master Key",
		DE: "Firefox-Passwort-Hauptschlüssel",
	},
	"target.discord_variant": {
		ZH: "Discord(%s)",
		EN: "Discord(%s)",
		DE: "Discord(%s)",
	},
	"target.steam_login": {
		ZH: "Steam 登录信息",
		EN: "Steam Login Info",
		DE: "Steam-Anmeldeinformationen",
	},
	"target.steam_ssfn": {
		ZH: "Steam 免二次验证凭据(ssfn)",
		EN: "Steam Two-Factor Bypass Credentials (ssfn)",
		DE: "Steam-2FA-Umgehungsdaten (ssfn)",
	},
	"target.ea_app": {
		ZH: "EA App",
		EN: "EA App",
		DE: "EA App",
	},
	"target.origin": {
		ZH: "Origin",
		EN: "Origin",
		DE: "Origin",
	},
	"target.electron_local_storage": {
		ZH: "%s Local Storage",
		EN: "%s Local Storage",
		DE: "%s Local Storage",
	},
	"category.cookie": {
		ZH: "Cookie",
		EN: "cookie",
		DE: "Cookie",
	},
	"category.password": {
		ZH: "密码",
		EN: "password",
		DE: "Passwort",
	},
	"category.token": {
		ZH: "登录令牌",
		EN: "login token",
		DE: "Anmelde-Token",
	},
	"category.config": {
		ZH: "配置",
		EN: "config",
		DE: "Konfiguration",
	},
	"vendor.squid": {
		ZH: "Squid (自建代理)",
		EN: "Squid (self-hosted proxy)",
		DE: "Squid (selbst gehosteter Proxy)",
	},
	"vendor.qihoo360": {
		ZH: "360 安全卫士",
		EN: "360 Total Security",
		DE: "360 Total Security",
	},
}

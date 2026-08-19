# NetWatch CookieGuard

一个跑在本机的 Go 后台监控工具:**进程级**追踪"谁访问了浏览器/客户端的 Cookie、密码库",以及"谁在联网、连去了哪里",并把两者关联起来——专门针对你怀疑的场景:**这台电脑上可能有信息窃取木马(infostealer),正在把你的登录态(cookie)甚至保存的密码打包发走**。

## 这是什么、不是什么

- **不是**抓包工具(不装 Npcap、不需要 C 编译器),而是基于 **Windows ETW(Event Tracing for Windows)内核事件**——和 Sysmon、各家 EDR 产品同一类技术,系统自带,管理员权限即可用,不用装第三方驱动。
- **架构 = Go 后台采集 + 原生窗口(WebView2)可视化**。双击就是一个真正的桌面程序:任务栏有图标、能 Alt+Tab、关窗口不退出(继续在系统托盘后台监控)。界面本身用 HTML/CSS/JS 写(内嵌进 exe,零外部依赖、零 CDN),通过 [Wails](https://wails.io) 用系统自带的 WebView2 控件渲染——不是浏览器标签页,也不监听任何网络端口,前后端之间是进程内直接通信,不是 HTTP。为什么界面不用原生 Win32 控件手写:这个仪表盘要做实时刷新的表格、搜索筛选、可展开的证据面板,HTML/CSS/JS 做这些比 Win32 控件轻松/好看得多,Wails 让你两头都占。

## 核心检测逻辑(它具体在防什么)

1. **进程级文件监控**:持续关注一份"敏感文件清单"——Chrome/Edge/Brave/Vivaldi/Opera/Firefox 的 Cookies 数据库和保存的密码库、Discord 的 token 存储(leveldb)、Steam 的登录凭据(`loginusers.vdf` / `ssfn*`)、EA App/Origin、Slack/Teams 等(完整清单见 [internal/config/config.go](internal/config/config.go))。
2. **每个文件被谁碰过,都会记录**。如果碰它的进程**不是**这个文件本身所属的程序(比如不是 `chrome.exe` 却在读 Chrome 的 Cookies),直接标为可疑,未签名 + 运行在 Temp/AppData/Downloads 等目录会进一步加分。
3. **核心规则(整个工具最重要的一条)**:如果一个非本体进程读取了 Cookie/密码文件,**15 秒内**这个进程又发起了对外网络连接 → 直接标记为 **🚨 严重(critical)**:「疑似窃密回传:读取登录凭据后立即联网」,并把负责的进程名、PID、路径、目标地址全部记录下来。这就是你要的"运行可疑程序,看到诡异请求"的核心功能。
4. **心跳/信标检测**:非知名浏览器的进程,如果按很规律的时间间隔反复连接同一个地址(抖动 <15%),会被标记为"可能是恶意软件的定时回连"。
5. **DNS 关联**:同时监听系统的域名解析事件,把 IP 尽量翻译回域名显示;如果一次连接完全没有对应的域名解析记录(可能是硬编码的服务器地址),会作为加分项。
6. 所有判定都是**打分制**(见 `internal/correlate/engine.go` 的 `scoreToSeverity`),严重程度分 严重/高/中/低/信息 五档,不是非黑即白的规则。

## 使用前必读:关于你提到的情况

你提到 Claude Code、Discord、Instagram、LinkedIn、Steam、EA 等"网页/客户端登录"的账号大面积沦陷,而且**Google 账号收到过异地登录提醒**——这个细节值得单独说一句:异地登录提醒意味着攻击者是**用账号+密码真正登录**的(触发了风控),这更像是**密码本身泄露**(很可能是你说的"复用密码被撞库");而 Discord/Steam 这类如果没触发类似提醒却也顶号,更像是 **cookie 被直接搬走复用**。这两者并不矛盾——真实世界里最常见的元凶(各类 infostealer)通常是**把浏览器"保存的密码"和"cookie"两个库一次性一起偷走**,所以密码撞库和 cookie 顶号很可能是**同一次感染的两个后果**。因此本工具把 Login Data(保存的密码库)和 Cookies 放在同一优先级监控。

**这个工具能做的**:如果木马现在还在这台电脑上、还会再次发作,它会在你运行可疑程序或木马下次读取凭据文件时抓个正着,并明确告诉你是哪个进程。
**这个工具做不到的**:无法找回过去已经发生、且工具还没运行时的历史真相(那次 Google 异地登录之前发生了什么,工具管不到);也不能 100% 排除是密码复用撞库这种和本机无关的原因。建议两条线一起查(见文末"同时建议")。

## 编译

需要 [Go](https://go.dev/dl/)(本机已装 1.26)和 **WebView2 运行时**(Windows 11 自带;Windows 10 也基本都有,因为 Edge 会自动装它;极少数精简版系统没有的话,程序启动时会提示,去 [微软官方页面](https://developer.microsoft.com/microsoft-edge/webview2/) 下一个"Evergreen Runtime",几十秒装完,一次性)。项目根目录下:

```powershell
.\build.ps1
```

会跑 `go vet` + `go test`,然后产出两个文件到 `build\`:

- `netwatch.exe` —— 日常使用,无控制台窗口
- `netwatch-debug.exe` —— 保留控制台窗口、实时打印日志,第一次运行/排查问题时建议用这个

> ⚠️ 如果不用 `build.ps1` 而是手动 `go build`,**必须**加 `-tags production`(debug 版再加 `debug`),这是 [Wails](https://wails.io) 框架的硬性要求——漏了这个标签程序照样能编译过,但一运行就弹一个「Wails applications will not build without the correct build tags」的错误框,而不是真正的界面。

## 运行

直接双击 `netwatch-debug.exe`(建议第一次用这个)。它会:

1. 弹出 UAC 提权确认(ETW 内核事件必须管理员权限才能订阅)——**这是本工具唯一需要你确认的系统弹窗**,除此之外不会有其它弹窗或权限请求。
2. 弹出一个真正的桌面窗口(标题栏、任务栏图标都有),显示监控仪表盘。
3. 系统托盘同时出现一个蓝色圆点图标;一旦出现未处理的高危/严重告警,图标会变红,鼠标悬停/窗口标题栏都能看到告警数量。
4. **关闭窗口(点右上角 ×)不会退出程序**——只是把窗口藏起来,监控继续在后台跑;想真正退出,用托盘图标菜单里的"退出监控"。想把窗口叫回来,点一下托盘图标。

常用参数:

```powershell
.\build\netwatch-debug.exe -install-autostart    # 注册开机自启动(登录时自动以管理员权限运行,窗口默认隐藏只留托盘图标),然后退出
.\build\netwatch-debug.exe -uninstall-autostart  # 取消开机自启动
.\build\netwatch-debug.exe -start-hidden         # 启动时不弹窗口,只进系统托盘(开机自启动用的就是这个)
.\build\netwatch-debug.exe -data-dir "D:\netwatch-data"  # 换个数据保存目录
.\build\netwatch-debug.exe -debug-etw raw.jsonl  # 把所有原始 ETW 事件转存成 JSON,排查检测不到东西时用
```

你在提问里选择的是"后台常驻 + 系统托盘",建议装好后跑一次 `-install-autostart`,以后开机就自动盯着,不用记得手动打开。

## 界面怎么看

- 顶部 5 个统计块:严重告警 / 高危告警 / 网络连接数 / 敏感文件访问次数 / 已观察进程数,前两个带最近 2 小时的迷你趋势图。
- **告警** tab:最核心的地方,新告警实时推到最上面,可以按级别筛选、按进程名/内容搜索、点"确认"消除托盘的红色提醒;每条告警可以展开"🔎 证据详情"看完整路径、命令行、父进程、SHA-256(带一键跳转 VirusTotal 查询)。
- **网络连接 / 敏感文件访问 / DNS 解析 / 进程** 四个 tab:原始明细,供你排查具体是谁干的、干了什么;网络连接和 DNS 解析里还有个"🤖 只看 Claude/ChatGPT/Gemini 相关流量"的筛选。
- 所有事件同时会**追加写入** `<数据目录>\*.jsonl`(逐行 JSON),窗口内存里只留最近几千条,但硬盘上的记录不会因为翻页/重启而丢——这是你要的"详细记录",可以事后用文本编辑器或 `jq` 翻历史。

## 关于误报/漏报,请诚实地知道这些限制

这是一个基于启发式规则的工具,不是杀毒软件,**告警是"值得去查"的线索,不是 100% 确定的结论**:

- ETW 事件里具体字段名是根据公开资料确定的,不同 Windows 版本可能有细微差异。如果长时间一个告警都没有、连正常上网都看不到连接记录,大概率是字段映射需要微调——用 `-debug-etw raw.jsonl` 跑一段时间,把 `raw.jsonl` 发给我,我可以照着真实样本把映射改准。
- 只做**元数据**关联(谁、什么时候、连了哪、读了哪个文件),不解密 TLS、不看请求内容本身——这是刻意的:解密 HTTPS 需要装根证书做中间人代理,对普通用户风险更大,不划算。
- 只从工具**启动那一刻**开始记录,无法还原它运行之前发生的事。
- 覆盖面上,Steam/EA 这类客户端的具体文件名不像浏览器那样有公开文档,用的是相对宽松的目录匹配,可能有遗漏。

## 同时建议(不是这个工具能做的,但和你的情况直接相关)

1. 对**复用过的密码**,尤其是 Google 账号,去 [myaccount.google.com/security](https://myaccount.google.com/security) 查"最近的安全活动",看异地登录的具体时间和 IP;所有复用过同一密码的网站都改成**各不相同**的密码,建议上个密码管理器。
2. Google、Discord、Steam 等能开二次验证(TOTP/passkey)的都开上——即使密码泄露,没有二次验证攻击者也登不进去。
3. Cookie 被偷的账号,改密码通常**不会**自动踢掉攻击者已经拿到的旧 session,去各平台的"设备管理/登录设备"里手动"注销其它所有设备"。
4. 如果这工具真抓到了实锤(某进程读凭据文件后联网),优先做的不是删那个进程,而是**断网后用 Windows Defender 离线扫描或 Malwarebytes 之类工具全盘查杀,必要时重装系统**——木马能读浏览器凭据库,说明它至少有普通用户权限,不能只当它这一个动作处理。

## 项目结构

```
cmd/netwatch/          程序入口:提权、自启动、CLI 参数、Wails 窗口配置、把各模块接起来
cmd/netwatch/app.go     Wails 绑定对象——导出方法会自动变成前端能直接调用的 JS 函数
internal/etwmon/        ETW 采集:Kernel-Process / Kernel-File / Kernel-Network / DNS-Client 四个内核 provider
internal/procinfo/      进程信息缓存:路径、命令行、数字签名校验(Get-AuthenticodeSignature)、可疑路径判断
internal/correlate/     检测核心:打分规则、文件-网络关联、心跳检测(engine_test.go 覆盖了关键场景)
internal/store/         环形缓冲 + 落盘 JSONL + 发布/订阅(被 Wails 事件桥接转发给前端)
internal/web/           内嵌的仪表盘资源(HTML/CSS/JS,零外部依赖,零 CDN),由 Wails 的 WebView2 直接渲染
internal/tray/          系统托盘图标(正常蓝 / 告警红)
internal/config/        敏感文件清单、已知浏览器名单、AI 服务域名、各项阈值——想调整检测范围/灵敏度改这里
tools/genicon/          生成托盘图标用的一次性小工具(正常不需要重跑)
```

## 已做的自测

没有管理员权限的环境里没法真实触发 ETW(会被拒绝访问,这本身也验证了权限检查逻辑是对的),所以额外写了几类测试覆盖其余部分,`go test ./...` 可重跑:

- `internal/store/store_test.go`:发布/订阅机制本身(Wails 事件转发依赖的正是这个)、慢订阅者不阻塞发布者。
- `internal/web/assets_test.go`:内嵌的 index.html/app.js/style.css 确实都在。
- `internal/correlate/engine_test.go`:核心场景——非本体进程读取 Cookies 后联网触发严重告警、浏览器读自己的 Cookies 不告警(含"Chrome 沙箱子进程继承父进程身份"这个实际踩过的坑)、身份无法确认时诚实降级而不是静默丢弃或过度自信、AI 服务域名命中会升级告警、规律心跳连接触发告警、已知浏览器/过快轮询不触发告警。
- `internal/procinfo/procinfo_test.go`:用当前进程自己的真实 PID 验证 OS 查询兜底路径(Observe 在 ETW 事件没给名字、父进程也查不到时,会不会正确退回到直接查系统)。

真正吃 ETW 这部分(内核事件字段解析)和 WebView2 渲染这部分,需要你在管理员权限下实跑才能最终验证——建议先用 `netwatch-debug.exe` 跑一会,正常上网,看"网络连接"和"敏感文件访问" tab 有没有数据进来,确认采集本身工作正常,再去测试可疑程序。

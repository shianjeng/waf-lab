# WAF Toolkit

English | [中文](#中文说明)

Two tools for protecting websites. Neither one sends attack traffic to any outside website.

| Tool | What it does | Where it runs |
|---|---|---|
| [`protect/protect.sh`](#one-click-protection-protectsh) | Puts a WAF in front of the websites on your own server with one command, and lets you allow a wrongly blocked request with one command | Your Linux server |
| [`./waflab`](#waf-comparison-lab-waflab) | Compares open-source WAFs side by side: how many attacks each blocks and how often it blocks legitimate traffic | Your computer (needs Docker) |

---

## One-click protection: protect.sh

On your server, run:

```bash
curl -fsSL https://github.com/shianjeng/waf-lab/releases/latest/download/protect.sh | sudo bash
```

To pass options, put them after `bash -s --`, for example `... | sudo bash -s -- --strict`. If you'd rather check the script before running it, see [Checking the download](#checking-the-download).

It first lists what it is going to do and only starts after you confirm. The script's messages are in Chinese; translated, they look like this:

```
protect.sh 0.1.0 will do the following on this server:
  System: Ubuntu 24.04 LTS · Web server: Nginx 1.24.0
  Protection level: full (requests are checked before they reach the site; attacks get a 403)

  1. Add the official CrowdSec package repository and install CrowdSec
  2. Install the Nginx component and enable virtual patching and generic attack rules
  3. Install the firewall component to ban IPs that attack the site or brute-force SSH
  4. Add these IPs to the allowlist so they are never banned: 198.51.100.7
```

Protection comes from [CrowdSec](https://www.crowdsec.net). Step 4 finds the IP you are logged in over SSH from and allowlists it, so a few mistyped passwords can't lock you out of your own server.

### Checking the download

Piping a script into `sudo bash` means running it unseen. To check it first:

```bash
curl -fsSLO https://github.com/shianjeng/waf-lab/releases/latest/download/protect.sh
curl -fsSLO https://github.com/shianjeng/waf-lab/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
less protect.sh
sudo bash protect.sh
```

`SHA256SUMS` catches a corrupted or swapped download. It's published next to the script, though, so it can't protect against someone who controls the release itself. For that, every release also carries a GitHub provenance attestation, which proves the file was built by this repository's release workflow. To verify it with the [GitHub CLI](https://cli.github.com):

```bash
gh attestation verify protect.sh --repo shianjeng/waf-lab
```

To install a specific version, replace `latest/download` with `download/v0.1.0` in the URLs. `bash protect.sh --version` shows which version you have.

### Two protection levels

| Server | Level | What it does |
|---|---|---|
| Debian, Ubuntu, with Nginx from the system repositories | Full | Checks each request before it reaches the site and answers attacks with a 403; also bans attacking IPs based on the logs |
| CentOS, Rocky, AlmaLinux, Alibaba Cloud Linux, Anolis, OpenCloudOS | Basic | Reads the Nginx logs and bans scanning and attacking IPs at the firewall; Nginx is not changed |
| BaoTa (宝塔) panel | Basic | Same as above, reading the site logs in `/www/wwwlogs` |

Basic mode can't stop a request before it reaches the site. CrowdSec recognizes the attack in the logs, and the firewall blocks that IP about 10 seconds later, so the attacker's first requests still get through. CentOS-family systems get basic mode because their Nginx packages have no Lua module, which CrowdSec's official Nginx component needs. BaoTa gets it because BaoTa compiles its own Nginx, which that component can't plug into.

Both levels also protect SSH against brute-force attacks.

### When a legitimate user gets blocked

```bash
sudo bash protect.sh --blocks
```

Translated output:

```
Recently blocked requests (newest first):

  [2] 10-23 17:15  203.0.113.20  GET /search?q=zsh%20is%20the%20best%21
       Reason: Remote Command Execution: Direct Unix Command Execution

  [1] 10-23 17:15  203.0.113.9  GET /.env
       Reason: Detect access to .env files

Was a legitimate user blocked? Enter a number to allow it (Enter to quit): 2

This block matched 1 rule. Allow it:
  1. Only on the path /search (recommended)
  2. Site-wide
Choose [1/2]: 1
Allowed 1 rule on /search (1 new exception). Other paths are still checked.
To undo it, run sudo bash protect.sh --exceptions and remove it by number.
```

An exception only covers the rules that fired for that block. Other attacks on the same path, such as XSS or command injection, are still blocked.

| Option | What it does |
|---|---|
| `--blocks` | List recent blocks and allow one by number |
| `--allow-block ID` | Allow a block without prompts; add `--site-wide` to allow it everywhere |
| `--exceptions` | List the exceptions, grouped by path |
| `--remove-exception N` | Undo the exception on one path, so those requests are blocked again |
| `--unban IP` | Lift a ban on an IP, and optionally allowlist it |
| `--reset-exceptions` | Remove all exceptions |
| `--status` | Show whether protection is running and the latest attacks |
| `--strict` | At install time, also enable the OWASP CRS rules: more attacks blocked, but more false positives too (see the lab results below) |
| `--allow-ip IP` | At install time, allowlist an extra IP |
| `--uninstall` | Remove everything |
| `--version` | Show the version |

### Good to know

- **It only protects.** The only requests it sends to your site are two to `127.0.0.1` at the end of the install, for the home page and for `/.env`, to confirm that blocking works.
- **It runs CrowdSec's official installer as root.** Step 1 downloads <https://install.crowdsec.net> and runs it to add the package repository, which is the installation method CrowdSec documents. As with any script you run with sudo, read `protect.sh` before running it.
- **CrowdSec shares data with its community by default.** It sends the IPs and attack types it detects to the CrowdSec community and downloads the community blocklist in return. To opt out, see the [CrowdSec documentation](https://docs.crowdsec.net) on disabling the Central API.
- **Servers in mainland China** download from CrowdSec's overseas package repository, which can be slow.
- **The default rules are conservative.** By default only virtual patches for known vulnerabilities and a few generic rules are enabled. They rarely block legitimate traffic, but generic attacks such as path traversal need `--strict`.
- **Tested on** servers simulated in Docker (see `protect/test/run.sh`): Debian 12, Ubuntu 24.04, Rocky Linux 9, Anolis OS 23, and Debian 12 set up with BaoTa's directory layout. Alibaba Cloud Linux and OpenCloudOS take the same path as Anolis but haven't been tested directly. **It has not been verified on a real BaoTa panel yet.**

### Tests

```bash
protect/test/run.sh            # 6 scenarios on servers simulated in Docker: install, blocking, false positives, uninstall
protect/test/run.sh rocky9     # just one
```

The "attacker" in the tests is a few made-up lines written straight into the test server's log file, using IP addresses reserved for documentation. The tests send no attack traffic over the network.

GitHub Actions runs ShellCheck on every push. It runs these scenarios in parallel when something under `protect/` changes, every Monday, or when you start it by hand from the Actions tab.

### Releasing

Change `VERSION` in `protect/protect.sh`, commit, then push a matching tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow runs all the test scenarios first. It only publishes `protect.sh`, `SHA256SUMS` and the provenance attestation if they all pass and the tag matches `VERSION`.

---

## WAF comparison lab: waflab

Four open-source WAFs sit in front of the same backend and get the same test traffic, so you can see which blocks more and which blocks fewer legitimate requests:

| Port | Target | Notes |
|---|---|---|
| 9000 | No WAF | The backend directly, as a baseline |
| 9001 | [Coraza](https://coraza.io) | OWASP CRS 4, running in Caddy |
| 9002 | [CrowdSec AppSec](https://docs.crowdsec.net/docs/next/appsec/intro) | Virtual patching + generic rules + CRS, the same as protect.sh with `--strict` |
| 9003 | [BunkerWeb](https://www.bunkerweb.io) | ModSecurity + OWASP CRS 4 |
| 9004 | [SafeLine (雷池)](https://waf-ce.chaitin.cn) | Chaitin's semantic analysis engine; started and set up separately |

### Running it

You need Docker Desktop (or OrbStack, or Colima); give it 8GB of memory to be safe.

```bash
./waflab run       # start the lab, run the full comparison, write reports/index.html
./waflab smoke     # quick smoke test, results in seconds
./waflab down      # stop, keeping data
./waflab clean     # stop and delete all data
```

The first run downloads about 4GB of images and builds two Caddy plugins, which takes 5 to 10 minutes.

### Test traffic never leaves your computer

- Every port is bound to `127.0.0.1`, so other devices on your network can't reach the lab.
- The full test tool (GoTestWAF) runs on a Docker network, `waflab-test`, that has **no route to the internet** and can only reach the lab's containers. The script checks that the network really is isolated before it runs and refuses to run otherwise.
- The smoke test only sends requests to `localhost` and refuses to run if a target is anything else.

### Adding SafeLine

SafeLine's protected sites can only be set up in its own web console, so it takes one extra step:

```bash
./waflab safeline
```

This starts SafeLine and prints the admin password. Then, as the prompts explain, add an application at <https://localhost:9443> (port `8004`, upstream `http://backend:80`) and run `./waflab run`.

### Keeping it fair

- Every WAF runs at its default detection level; CRS is at paranoia level 1.
- BunkerWeb's features that aren't WAF rules and would skew the test are turned off: Bad Behavior (which would ban the test client), rate limiting, blocklists, DNSBL, BunkerNet and anonymous reporting.
- CrowdSec uses `appsec-crs-inband`, so a CRS match blocks the request (`appsec-crs` only alerts and would score 0). It runs 4 detection workers: with the default of 1, the test's concurrency made some requests time out with a 500.
- SafeLine runs with the community edition's built-in defaults. The official compose file sets `RIVER_CN_CAPABILITY_GATE=off`, which makes paid features skip the license check; this project doesn't set it. Version 9.4.3's startup log shows that the check is off by default even so. That is the vendor's own default; don't turn on paid features in the console when testing.

### Results (2026-10-24)

Apple Silicon, Docker Engine 29.8, GoTestWAF 0.5.8. SafeLine needs its site added by hand and was not tested this time.

| Target | Attacks blocked | Legitimate requests passed | Wrongly blocked |
|---|---:|---:|---:|
| No WAF | 0.0% | 100.0% | 0/141 |
| Coraza | 47.6% | 90.8% | 13/141 |
| CrowdSec | 47.1% | 79.4% | 29/141 |
| BunkerWeb | 48.0% | 90.8% | 13/141 |

- Coraza and BunkerWeb both use OWASP CRS underneath. They block almost exactly the same attacks and wrongly block the same sentences, such as `union was a great select` and `zsh is the best!`.
- CrowdSec (in the strict setup with CRS) blocks about as many attacks but wrongly blocks more than twice as many legitimate requests. The extra false positives come from its own CRS rule package: rule 932260 (Unix command execution), for example, treats an ordinary sentence like `curl and divergence` as a command. That's why protect.sh leaves CRS off by default.
- BunkerWeb does better than the other two on XML injection (28.6%) and template injection (45.8%).
- None of the three stops much LDAP injection, mail injection, or RCE in the URL path.

The per-category breakdown is in `reports/index.html`, written by `./waflab run`.

---

## Layout

```
protect/protect.sh        one-click protection script
protect/test/             tests for protect.sh on servers simulated in Docker
.github/workflows/        GitHub Actions: ShellCheck, the protect.sh tests, and releases
waflab                    entry point for the comparison lab
compose.yaml              backend + Coraza + CrowdSec + BunkerWeb
coraza/ crowdsec/         builds and configs for the two Caddy plugins
safeline/compose.yaml     SafeLine, adapted from the official compose file to run on macOS
scripts/                  test and report scripts for the lab
```

---

# 中文说明

两个工具，都不会往任何外部网站发送攻击请求：

| 工具 | 用来做什么 | 在哪里运行 |
|---|---|---|
| [`protect/protect.sh`](#一键防护protectsh) | 一条命令给自己服务器上的网站加上 WAF 防护，误拦了正常用户也能一条命令放行 | 你自己的 Linux 服务器 |
| [`./waflab`](#waf-对比实验室waflab) | 在本机比较几个开源 WAF 拦得多不多、误报多不多，用来选型 | 你的电脑（需要 Docker） |

---

## 一键防护：protect.sh

在服务器上运行：

```bash
curl -fsSL https://github.com/shianjeng/waf-lab/releases/latest/download/protect.sh | sudo bash
```

要加选项的话，写在 `bash -s --` 后面，比如 `... | sudo bash -s -- --strict`。想先检查脚本再运行，见[校验下载的文件](#校验下载的文件)。

它会先列出要做的事情，你确认之后才会动手：

```
protect.sh 0.1.0 将要在这台服务器上做以下事情：
  系统：Ubuntu 24.04 LTS · Web 服务器：Nginx 1.24.0
  防护级别：完整（请求到达网站之前就检测，攻击请求直接返回 403）

  1. 添加 CrowdSec 官方软件源，安装 CrowdSec
  2. 安装 Nginx 防护组件，启用虚拟补丁和通用攻击规则
  3. 安装防火墙组件，封禁攻击网站和暴力破解 SSH 的 IP
  4. 把这些 IP 加入白名单，永远不会被封：198.51.100.7
```

防护用的是 [CrowdSec](https://www.crowdsec.net)。第 4 步会自动识别你当前 SSH 登录用的 IP 并加入白名单，避免输错几次密码就把自己封在外面。

### 校验下载的文件

把脚本直接交给 `sudo bash`，等于没看内容就运行。想先检查的话：

```bash
curl -fsSLO https://github.com/shianjeng/waf-lab/releases/latest/download/protect.sh
curl -fsSLO https://github.com/shianjeng/waf-lab/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
less protect.sh
sudo bash protect.sh
```

`SHA256SUMS` 能发现下载过程中损坏或被替换的文件。但它和脚本放在同一个地方，如果有人控制了发布本身，它就防不住了。为此，每个版本还附带 GitHub 的来源证明，证明这个文件是由本仓库的发布工作流构建的。用 [GitHub 命令行工具](https://cli.github.com) 验证：

```bash
gh attestation verify protect.sh --repo shianjeng/waf-lab
```

要安装指定版本，把网址里的 `latest/download` 换成 `download/v0.1.0`。`bash protect.sh --version` 可以查看当前版本。

### 两种防护级别

| 服务器 | 防护级别 | 效果 |
|---|---|---|
| Debian、Ubuntu，Nginx 从系统软件源安装 | 完整 | 请求到达网站之前就检测，攻击请求直接返回 403；同时按日志封禁攻击者 IP |
| CentOS、Rocky、AlmaLinux、阿里云 Linux、龙蜥 Anolis、OpenCloudOS | 基础 | 分析 Nginx 日志，发现扫描和攻击后在防火墙封禁 IP，不改动 Nginx |
| 宝塔面板 | 基础 | 同上，读取 `/www/wwwlogs` 下的站点日志 |

基础模式没法在请求到达网站之前拦住它：CrowdSec 从日志里识别出攻击，大约 10 秒后防火墙封掉这个 IP，所以攻击者最先发出的几个请求仍会到达网站。CentOS 系列用基础模式，是因为它们的 Nginx 软件包没有 CrowdSec 官方防护组件需要的 Lua 模块；宝塔用基础模式，是因为宝塔的 Nginx 是自己编译的，官方防护组件接不进去。

两种模式都会保护 SSH，防止暴力破解。

### 正常用户被拦了怎么办

```bash
sudo bash protect.sh --blocks
```

```
最近被拦截的请求（最新的在前）：

  [2] 10-23 17:15  203.0.113.20  GET /search?q=zsh%20is%20the%20best%21
       原因：Remote Command Execution: Direct Unix Command Execution

  [1] 10-23 17:15  203.0.113.9  GET /.env
       原因：Detect access to .env files

是正常用户被误拦了？输入编号放行（直接回车退出）：2

这次拦截命中了 1 条规则。放行范围：
  1. 只在 /search 这个路径放行（推荐）
  2. 全站放行
请选择 [1/2]：1
已在 /search 放行这 1 条规则（新增 1 条例外），其他路径照常检测。
反悔了可以用 sudo bash protect.sh --exceptions 查看，再按编号删除。
```

放行只针对这次拦截命中的那几条规则。同一个路径上的其他攻击（比如 XSS、命令注入）仍然会被拦。

| 命令 | 作用 |
|---|---|
| `--blocks` | 查看最近被拦截的请求，输入编号放行 |
| `--allow-block 编号` | 不用交互直接放行，加 `--site-wide` 全站放行 |
| `--exceptions` | 按路径列出已放行的例外 |
| `--remove-exception 编号` | 撤销某个路径上的放行，这类请求会重新被拦截 |
| `--unban IP` | 解封一个被误封的 IP，可以顺便加入白名单 |
| `--reset-exceptions` | 清除所有放行例外 |
| `--status` | 查看防护状态和最近的攻击 |
| `--strict` | 安装时额外启用 OWASP CRS 规则：拦得更多，误报也更多（见下面的实验室结果） |
| `--allow-ip IP` | 安装时额外把一个 IP 加入白名单 |
| `--uninstall` | 卸载 |
| `--version` | 显示版本号 |

### 需要知道的几件事

- **只做防护。** 它只会向你的网站发两个请求：安装结束时向本机 `127.0.0.1` 请求首页和 `/.env`，确认防护已经生效。
- **它会用 root 权限运行 CrowdSec 的官方安装脚本。** 第 1 步会下载 <https://install.crowdsec.net> 并运行它来添加软件源，这是 CrowdSec 文档里的安装方式。和任何要用 sudo 运行的脚本一样，运行前请先看一遍 `protect.sh`。
- **CrowdSec 默认会和社区共享数据。** 它会把检测到的攻击者 IP 和攻击类型分享给 CrowdSec 社区，同时下载社区黑名单。不想分享可以参考 [CrowdSec 文档](https://docs.crowdsec.net) 关闭 Central API。
- **国内服务器** 安装时要从 CrowdSec 的国外软件源下载，可能比较慢。
- **默认规则偏保守。** 默认只启用针对已知漏洞的虚拟补丁和少量通用规则，误报很少，但像路径穿越这种通用攻击要靠 `--strict`。
- **已测试的环境**（在 Docker 里模拟的服务器上，见 `protect/test/run.sh`）：Debian 12、Ubuntu 24.04、Rocky Linux 9、龙蜥 Anolis OS 23，以及模拟宝塔目录布局的 Debian 12。阿里云 Linux 和 OpenCloudOS 走的是和龙蜥相同的安装路径，但没有直接测试过。**还没有在真实的宝塔面板上验证过。**

### 测试

```bash
protect/test/run.sh            # 在 Docker 里模拟的服务器上跑 6 个场景：安装、拦截、误报处理和卸载
protect/test/run.sh rocky9     # 只测一种
```

测试里的"攻击者"是直接写进测试机日志文件的几行模拟记录，用的是文档专用的 IP 地址段，不会发出任何网络请求。

GitHub Actions 会在每次推送时用 ShellCheck 检查脚本；`protect/` 有改动、每周一，或者在 Actions 页面手动触发时，会并行跑完这些测试场景。

### 发布新版本

修改 `protect/protect.sh` 里的 `VERSION`，提交，然后推送对应的标签：

```bash
git tag v0.1.0
git push origin v0.1.0
```

发布工作流会先跑完所有测试场景。只有全部通过、并且标签和 `VERSION` 一致，才会发布 `protect.sh`、`SHA256SUMS` 和来源证明。

---

## WAF 对比实验室：waflab

把四个开源 WAF 放在同一个后端前面，用同一套流量测试，看谁拦得多、谁误报少：

| 端口 | 目标 | 说明 |
|---|---|---|
| 9000 | 无 WAF | 后端直连，作对照组 |
| 9001 | [Coraza](https://coraza.io) | OWASP CRS 4，跑在 Caddy 里 |
| 9002 | [CrowdSec AppSec](https://docs.crowdsec.net/docs/next/appsec/intro) | 虚拟补丁 + 通用规则 + CRS，相当于 protect.sh 的 `--strict` |
| 9003 | [BunkerWeb](https://www.bunkerweb.io) | ModSecurity + OWASP CRS 4 |
| 9004 | [雷池 SafeLine](https://waf-ce.chaitin.cn) | 长亭的语义分析引擎，需要单独启动和配置 |

### 运行

需要 Docker Desktop（或 OrbStack、Colima），给它 8GB 内存比较稳妥。

```bash
./waflab run       # 启动实验室，跑完整对比，结果写到 reports/index.html
./waflab smoke     # 只跑冒烟测试，几秒钟出结果
./waflab down      # 停止，保留数据
./waflab clean     # 停止并删除所有数据
```

第一次运行要下载约 4GB 镜像，并构建两个 Caddy 插件，大概要 5 到 10 分钟。

### 测试流量不会离开你的电脑

- 所有端口只绑定在 `127.0.0.1`，局域网里的其他设备访问不到。
- 完整测试工具（GoTestWAF）运行在一个**没有外网出口**的 Docker 网络 `waflab-test` 里，只能访问实验室里的容器。运行前脚本会检查这个网络确实是隔离的，否则拒绝运行。
- 冒烟测试只向 `localhost` 发请求，目标地址如果不是本机就拒绝运行。

### 加上雷池

雷池的防护站点只能在它自己的控制台里配置，所以要多一步：

```bash
./waflab safeline
```

它会启动雷池并打印管理员密码，然后按提示在 <https://localhost:9443> 里添加一个防护应用（端口 `8004`，上游 `http://backend:80`），再运行 `./waflab run`。

### 公平性说明

- 所有 WAF 都用默认检测强度，CRS 是 paranoia level 1。
- BunkerWeb 关掉了和 WAF 规则无关、会干扰测试的功能：Bad Behavior（会封掉测试机 IP）、限速、黑名单、DNSBL、BunkerNet 和匿名报告。
- CrowdSec 用 `appsec-crs-inband`，CRS 命中直接拦截（`appsec-crs` 只告警，测出来会是 0）。检测线程开到 4 个：默认 1 个时，测试的并发会让一部分请求超时返回 500。
- 雷池按社区版的内置默认配置运行。官方 compose 文件里的 `RIVER_CN_CAPABILITY_GATE=off` 会让付费功能跳过授权校验，本项目没有设置它。但 9.4.3 版本的启动日志显示，即使不设置，这个校验默认也是关闭的。这是厂商自己的默认行为，测试时不要在控制台里开启付费功能。

### 实测结果（2026-10-24）

Apple Silicon，Docker Engine 29.8，GoTestWAF 0.5.8。雷池需要手动添加站点，这次没有测。

| 目标 | 攻击拦截率 | 正常请求放行率 | 误拦 |
|---|---:|---:|---:|
| 无 WAF | 0.0% | 100.0% | 0/141 |
| Coraza | 47.6% | 90.8% | 13/141 |
| CrowdSec | 47.1% | 79.4% | 29/141 |
| BunkerWeb | 48.0% | 90.8% | 13/141 |

- Coraza 和 BunkerWeb 的底层都是 OWASP CRS，拦截率几乎一样，误报也是同一批文本，比如 `union was a great select`、`zsh is the best!`。
- CrowdSec（加了 CRS 的严格配置）拦截率差不多，但误报是另外两个的两倍多。多出来的误报来自它自带的 CRS 规则包，比如规则 932260（Unix 命令执行）会把 `curl and divergence` 这种普通句子当成命令。这也是 protect.sh 默认不开 CRS 的原因。
- BunkerWeb 在 XML 注入（28.6%）和模板注入（45.8%）上比另外两个高。
- 三个都基本拦不住 LDAP 注入、邮件注入和 URL 路径里的 RCE。

各攻击类型的明细见 `./waflab run` 生成的 `reports/index.html`。

---

## 目录

```
protect/protect.sh        一键防护脚本
protect/test/             在 Docker 里模拟服务器测试 protect.sh
.github/workflows/        GitHub Actions：ShellCheck 检查、protect.sh 测试和发布
waflab                    对比实验室的入口
compose.yaml              后端 + Coraza + CrowdSec + BunkerWeb
coraza/ crowdsec/         两个 Caddy 插件的构建和配置
safeline/compose.yaml     雷池，改编自官方 compose，以便在 macOS 上运行
scripts/                  实验室用的测试和汇总脚本
```

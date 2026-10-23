# 网站防护工具箱

两个工具，都不会往任何外部网站发送攻击请求：

| 工具 | 用来做什么 | 在哪里运行 |
|---|---|---|
| [`protect/protect.sh`](#一键防护-protectsh) | 一条命令给自己服务器上的网站加上 WAF 防护，误拦了正常用户也能一条命令放行 | 你自己的 Linux 服务器 |
| [`./waflab`](#waf-对比实验室-waflab) | 在本机比较几个开源 WAF 拦得多不多、误报多不多，用来选型 | 你的电脑（需要 Docker） |

---

## 一键防护：protect.sh

把 `protect/protect.sh` 传到服务器上，然后运行：

```bash
sudo bash protect.sh
```

它会先列出要做的事情，你确认之后才会动手：

```
将要在这台服务器上做以下事情：
  系统：Ubuntu 24.04 LTS · Web 服务器：Nginx 1.24.0
  防护级别：完整（请求到达网站之前就检测，攻击请求直接返回 403）

  1. 添加 CrowdSec 官方软件源，安装 CrowdSec
  2. 安装 Nginx 防护组件，启用虚拟补丁和通用攻击规则
  3. 安装防火墙组件，封禁攻击网站和暴力破解 SSH 的 IP
  4. 把这些 IP 加入白名单，永远不会被封：198.51.100.7
```

防护用的是 [CrowdSec](https://www.crowdsec.net)。第 4 步会自动识别你当前 SSH 登录用的 IP 并加入白名单，避免输错几次密码就把自己封在外面。

### 两种防护级别

| 服务器 | 防护级别 | 效果 |
|---|---|---|
| Debian、Ubuntu，Nginx 从系统软件源安装 | 完整 | 请求到达网站之前就检测，攻击请求直接返回 403；同时按日志封禁攻击者 IP |
| CentOS、Rocky、AlmaLinux、阿里云 Linux | 基础 | 分析 Nginx 日志，发现扫描和攻击后在防火墙封禁 IP，不改动 Nginx |
| 宝塔面板 | 基础 | 同上，读取 `/www/wwwlogs` 下的站点日志 |

基础模式下，攻击者最先发出的几个请求仍会到达网站，CrowdSec 识别出来以后几秒内封掉它的 IP。CentOS 系列和宝塔的 Nginx 没有 CrowdSec 官方防护组件需要的 Lua 模块，所以只能用基础模式。

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
```

放行只针对这次拦截命中的那几条规则。同一个路径上的其他攻击（比如 XSS、命令注入）仍然会被拦。

| 命令 | 作用 |
|---|---|
| `--blocks` | 查看最近被拦截的请求，输入编号放行 |
| `--allow-block 编号` | 不用交互直接放行，加 `--site-wide` 全站放行 |
| `--unban IP` | 解封一个被误封的 IP，可以顺便加入白名单 |
| `--reset-exceptions` | 清除所有放行例外 |
| `--status` | 查看防护状态和最近的攻击 |
| `--strict` | 安装时额外启用 OWASP CRS 规则：拦得更多，误报也更多（见下面的实验室结果） |
| `--allow-ip IP` | 安装时额外把一个 IP 加入白名单 |
| `--uninstall` | 卸载 |

### 需要知道的几件事

- **只做防护。** 整个过程只有一个"测试请求"：安装结束时向本机 `127.0.0.1` 请求一次 `/.env`，确认防护已经生效。
- **CrowdSec 默认会和社区共享数据。** 它会把检测到的攻击者 IP 和攻击类型分享给 CrowdSec 社区，同时下载社区黑名单。不想分享可以参考 [CrowdSec 文档](https://docs.crowdsec.net) 关闭 Central API。
- **国内服务器** 安装时要从 CrowdSec 的国外软件源下载，可能比较慢。
- **默认规则偏保守。** 默认只启用针对已知漏洞的虚拟补丁和少量通用规则，误报很少，但像路径穿越这种通用攻击要靠 `--strict`。
- **已测试的环境**（在 Docker 里模拟的服务器上，见 `protect/test/run.sh`）：Debian 12、Ubuntu 24.04、Rocky Linux 9，以及模拟宝塔目录布局的 Debian 12。**还没有在真实的宝塔面板上验证过。**

### 测试

```bash
protect/test/run.sh            # 在 Docker 里模拟 5 种服务器，跑安装、拦截、误报处理和卸载
protect/test/run.sh rocky9     # 只测一种
```

测试里的"攻击者"是直接写进测试机日志文件的几行模拟记录，用的是文档专用的 IP 地址段，不会发出任何网络请求。

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
waflab                    对比实验室的入口
compose.yaml              后端 + Coraza + CrowdSec + BunkerWeb
coraza/ crowdsec/         两个 Caddy 插件的构建和配置
safeline/compose.yaml     雷池，改编自官方 compose，以便在 macOS 上运行
scripts/                  实验室用的测试和汇总脚本
```

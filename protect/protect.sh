#!/usr/bin/env bash
# 一键给自己服务器上的网站加上 CrowdSec 防护。只做防护，不会向任何地方发送攻击请求。
#
# 第一次运行时安装防护，同时把自己装成 /usr/local/bin/protect 命令。之后运行
# sudo protect 会打开管理菜单：查看状态、放行误拦、解封 IP、更新、卸载。
# 所有功能也都有对应的选项，见 sudo protect --help。
#
# 支持 Debian、Ubuntu、CentOS、Rocky、AlmaLinux、阿里云 Linux、龙蜥、OpenCloudOS 上的 Nginx，
# 以及宝塔面板的 Nginx。
#
# 两种防护级别：
#   完整：Debian/Ubuntu 上用系统软件源安装的 Nginx。请求到达网站之前就检测，
#         攻击请求直接返回 403；同时分析日志、在防火墙封禁攻击者 IP。
#   基础：其他情况（CentOS 系列、宝塔）。分析 Nginx 日志，发现攻击后在防火墙封禁
#         攻击者 IP，不改动 Nginx。最先到达的几个攻击请求仍会到达网站。
set -euo pipefail

# 整个脚本放在一对大括号里，bash 要先读到最后的 } 才开始执行。通过 curl | bash 运行时
# 脚本来自标准输入，如果边读边执行，中途 cscli、apt-get 这类会读标准输入的命令会把
# 还没执行的脚本读走，后面的代码就会错乱执行
{

# 发布时打的标签必须是 v$VERSION，发布工作流会检查
VERSION=0.2.0

# 装好后的管理命令
BIN=/usr/local/bin/protect
# 新版本从这里下载。测试时用 PROTECT_RELEASES_URL 指到本地目录（file://）
RELEASES=${PROTECT_RELEASES_URL:-https://github.com/shianjeng/waf-lab/releases}

STATE=/etc/crowdsec/protect.env
APPSEC_ACQUIS=/etc/crowdsec/acquis.d/protect-appsec.yaml
BAOTA_ACQUIS=/etc/crowdsec/acquis.d/protect-baota.yaml
NGINX_BOUNCER_CONF=/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf
ALLOWLIST=protect-admin
# 误报例外：每行"路径<TAB>规则"，路径为 * 表示全站。YAML 由它生成，用户不用手写
EXCEPTIONS_LIST=/etc/crowdsec/protect-exceptions.list
EXCEPTIONS_YAML=/etc/crowdsec/appsec-configs/protect-exceptions.yaml

usage() {
	cat <<'EOF'
用法：sudo protect [选项]

  （不加选项）         还没安装时：安装防护，先列出要做的事，确认后才动手
                       已经安装时：打开管理菜单
  --status             查看防护状态和最近拦截的攻击
  --blocks             查看最近被拦截的请求，输入编号把误拦的放行
  --allow-block 编号   不用交互，直接放行某次拦截（只在那个路径；加 --site-wide 全站放行）
  --exceptions         查看已放行的例外
  --remove-exception 编号
                       撤销某个路径上的放行，那类请求会重新被拦截
  --reset-exceptions   清除所有放行例外，恢复默认规则
  --unban IP           解封一个被误封的 IP，可以顺便加入白名单
  --update             更新到最新版本（先校验，保留现有设置和放行例外）
  --reinstall          按现有设置重新安装一遍
  --strict             安装时同时启用 OWASP CRS 规则：拦得更多，误报也更多（仅完整模式）
  --no-strict          关掉严格模式
  --allow-ip IP        安装时额外把一个 IP 加入白名单，可以重复
  --uninstall          卸载
  --version            显示版本号
  -y                   跳过确认
EOF
}

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf '注意：%s\n' "$*" >&2; }
die() { printf '错误：%s\n' "$*" >&2; exit 1; }

# 不指定动作时，已经安装过就打开菜单，否则安装
action=""
assume_yes=0
strict=0
# 记录用户有没有明确指定严格模式。没指定时，重新安装沿用上次的设置
strict_set=0
site_wide=0
extra_ips=()
unban_ip=""
block_id=""
exception_id=""
while [ $# -gt 0 ]; do
	case "$1" in
	-y | --yes) assume_yes=1 ;;
	--strict)
		strict=1
		strict_set=1
		action=install
		;;
	--no-strict)
		strict=0
		strict_set=1
		action=install
		;;
	--allow-ip)
		[ $# -ge 2 ] || die "--allow-ip 后面要跟一个 IP"
		extra_ips+=("$2")
		action=install
		shift
		;;
	--reinstall) action=install ;;
	--update) action=update ;;
	--status) action=status ;;
	--blocks) action=blocks ;;
	--allow-block)
		[ $# -ge 2 ] || die "--allow-block 后面要跟拦截编号（用 --blocks 查看）"
		action=allow_block
		block_id=$2
		shift
		;;
	--site-wide) site_wide=1 ;;
	--unban)
		[ $# -ge 2 ] || die "--unban 后面要跟一个 IP"
		action=unban
		unban_ip=$2
		shift
		;;
	--exceptions) action=exceptions ;;
	--remove-exception)
		[ $# -ge 2 ] || die "--remove-exception 后面要跟例外编号（用 --exceptions 查看）"
		action=remove_exception
		exception_id=$2
		shift
		;;
	--reset-exceptions) action=reset_exceptions ;;
	--uninstall) action=uninstall ;;
	-h | --help)
		usage
		exit 0
		;;
	--version)
		say "protect $VERSION"
		exit 0
		;;
	*) die "不认识的参数：$1（用 --help 查看用法）" ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "需要 root 权限，请在命令前面加 sudo"

# 通过 curl | sudo bash 运行时，标准输入是脚本本身，要从终端读回答。
# 只看 /dev/tty 存不存在不够：没有终端时它存在但打不开
have_tty() { { true >/dev/tty; } 2>/dev/null; }

if [ -z "$action" ]; then
	if [ -f "$STATE" ] && [ "$assume_yes" -eq 0 ] && have_tty; then action=menu; else action=install; fi
fi

confirm() {
	[ "$assume_yes" -eq 1 ] && return 0
	have_tty || die "没有可交互的终端。确认无误后加 -y 重新运行"
	local answer
	printf '%s [y/N] ' "$1" >/dev/tty
	read -r answer </dev/tty || true
	case "$answer" in y | Y | yes | YES) return 0 ;; *) return 1 ;; esac
}

valid_ip() {
	[[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$1" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:.]*$ ]]
}

# 找出当前 SSH 登录用的 IP，加入白名单，避免输错几次密码就把自己封在外面
admin_ip() {
	local ip=""
	ip=$(printf '%s' "${SSH_CONNECTION:-${SSH_CLIENT:-}}" | awk '{print $1}')
	if [ -z "$ip" ]; then
		ip=$(who -m 2>/dev/null | sed -nE 's/.*\(([0-9a-fA-F:.]+)\).*/\1/p' | head -1)
	fi
	if [ -z "$ip" ] && [ -n "${SUDO_USER:-}" ]; then
		ip=$(who 2>/dev/null | awk -v u="$SUDO_USER" '$1 == u' | sed -nE 's/.*\(([0-9a-fA-F:.]+)\).*/\1/p' | tail -1)
	fi
	if [ -n "$ip" ] && valid_ip "$ip"; then printf '%s' "$ip"; fi
	return 0
}

detect_os() {
	[ -r /etc/os-release ] || die "无法识别操作系统（没有 /etc/os-release）"
	# 在子 shell 里读 os-release，只取需要的几个值。直接 source 会覆盖脚本自己的变量：
	# os-release 里也有 VERSION（比如 "12 (bookworm)"）
	local fields
	# shellcheck disable=SC1091
	fields=$(
		. /etc/os-release
		printf '%s\n' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}" "${PRETTY_NAME:-${ID:-}}"
	)
	{
		read -r OS_ID
		read -r OS_LIKE
		read -r OS_VERSION_ID
		read -r OS_NAME
	} <<<"$fields"
	case " $OS_ID $OS_LIKE " in
	*" debian "* | *" ubuntu "*) PKG=apt ;;
	*" rhel "* | *" centos "* | *" fedora "* | *" rocky "* | *" almalinux "* | *" alinux "* | *" anolis "* | *" opencloudos "*)
		if command -v dnf >/dev/null 2>&1; then PKG=dnf; else PKG=yum; fi
		;;
	*) die "暂不支持 $OS_NAME。目前支持 Debian、Ubuntu 和 CentOS/Rocky/AlmaLinux/阿里云 Linux/龙蜥/OpenCloudOS。" ;;
	esac
}

detect_web() {
	if [ -x /www/server/nginx/sbin/nginx ] || [ -d /www/server/panel ]; then
		[ -x /www/server/nginx/sbin/nginx ] ||
			die "检测到宝塔面板，但没有安装 Nginx（可能用的是 Apache 或 OpenLiteSpeed）。目前只支持 Nginx。"
		WEB=baota
		NGINX_BIN=/www/server/nginx/sbin/nginx
		WEB_NAME="宝塔面板的 Nginx"
	elif command -v nginx >/dev/null 2>&1; then
		WEB=nginx
		NGINX_BIN=$(command -v nginx)
		WEB_NAME="Nginx"
	else
		die "没有找到 Nginx。目前只支持 Nginx 和宝塔面板的 Nginx。"
	fi
	if [ -x "$NGINX_BIN" ]; then
		WEB_NAME="$WEB_NAME $("$NGINX_BIN" -v 2>&1 | sed -nE 's|.*nginx/([0-9.]+).*|\1|p')"
	fi
}

# 下载类的步骤遇到网络抖动就重试，最多 3 次。国内服务器访问 CrowdSec 的国外源时很常见
retry() {
	local n
	for n in 1 2 3; do
		"$@" && return 0
		if [ "$n" -lt 3 ]; then
			warn "网络操作失败，$((n * 5)) 秒后重试（第 $n 次）：$*"
			sleep $((n * 5))
		fi
	done
	return 1
}

pkg_install() {
	case "$PKG" in
	apt) retry env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" </dev/null >/dev/null ;;
	*) retry "$PKG" install -y -q "$@" </dev/null >/dev/null ;;
	esac
}

hub_install() { retry cscli collections install "$@" </dev/null >/dev/null; }

pkg_remove() {
	case "$PKG" in
	apt) DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$@" >/dev/null 2>&1 || true ;;
	*) "$PKG" remove -y -q "$@" >/dev/null 2>&1 || true ;;
	esac
}

CROWDSEC_REPO_FILES=(
	/etc/apt/sources.list.d/crowdsec_crowdsec.list
	/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg
	/etc/yum.repos.d/crowdsec_crowdsec.repo
)

repo_present() {
	if [ "$PKG" = apt ]; then
		[ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]
	else
		[ -f /etc/yum.repos.d/crowdsec_crowdsec.repo ]
	fi
}

# 刷新 CrowdSec 软件源。apt-get update 只要有任何一个软件源出错就会失败，所以只看
# 和 CrowdSec 软件源有关的错误，别的软件源的问题不算在它头上
repo_works() {
	if [ "$PKG" = apt ]; then
		local out errors
		out=$(apt-get update 2>&1 || true)
		errors=$(printf '%s\n' "$out" | grep -E '^(E|W):' | grep -c 'packagecloud.io/crowdsec' || true)
		[ "$errors" -eq 0 ]
	else
		"$PKG" -q makecache --disablerepo='*' --enablerepo='crowdsec_crowdsec' >/dev/null 2>&1
	fi
}

add_repo() {
	command -v curl >/dev/null 2>&1 || pkg_install curl
	# 官方安装脚本不认识阿里云 Linux、龙蜥、OpenCloudOS 这些兼容 RHEL 的系统，会直接拒绝。
	# CrowdSec 的 RPM 软件源对 RHEL 系是通用的，所以让它按 RHEL 处理
	local override=() out="" version=${OS_VERSION_ID:-9} n
	if [ "$PKG" != apt ]; then
		case "$OS_ID" in
		centos | rhel | fedora | amzn | cloudlinux | almalinux | rocky | ol) ;;
		*) override=(os=rhel "dist=${version%%.*}") ;;
		esac
	fi
	for n in 1 2 3; do
		if ! repo_present; then
			out=$(curl -fsSL https://install.crowdsec.net | env ${override[@]+"${override[@]}"} sh 2>&1) || true
		fi
		repo_works && return 0
		# 官方脚本下载签名密钥失败时不会报错，会留下一个没有密钥、用不了的软件源，
		# 而且软件源文件已经在了，下次运行也不会重新添加。删掉重来
		rm -f "${CROWDSEC_REPO_FILES[@]}"
		if [ "$n" -lt 3 ]; then
			warn "CrowdSec 软件源没有配置成功，$((n * 5)) 秒后重试（第 $n 次）"
			sleep $((n * 5))
		fi
	done
	[ -n "$out" ] && printf '%s\n' "$out" | tail -n 8 >&2
	die "添加 CrowdSec 软件源失败。多半是网络问题，稍后重新运行即可"
}

# 完整模式需要 Debian/Ubuntu 软件源里的 Nginx Lua 模块。如果装它会替换或删除
# 现在的 Nginx（比如 Nginx 是从 nginx.org 装的），就退回基础模式，不碰 Nginx。
choose_mode() {
	MODE=basic
	MODE_REASON=""
	if [ "$PKG" != apt ]; then
		MODE_REASON="这个系统的 Nginx 没有 CrowdSec 需要的 Lua 模块"
		return
	fi
	if [ "$WEB" = baota ]; then
		MODE_REASON="宝塔的 Nginx 是自己编译的，官方 Nginx 防护组件接不进去"
		return
	fi
	local plan
	plan=$(apt-get install -s crowdsec-nginx-bouncer 2>/dev/null || true)
	if [ -z "$plan" ]; then
		MODE_REASON="软件源里找不到 crowdsec-nginx-bouncer"
	elif printf '%s\n' "$plan" | grep -qE '^Remv |^Inst nginx(-common|-core|-full|-light|-extras)? '; then
		if apt-cache policy nginx 2>/dev/null | grep -q 'nginx\.org'; then
			MODE_REASON="Nginx 是从 nginx.org 安装的，官方 Nginx 防护组件需要系统软件源里的 Nginx"
		else
			MODE_REASON="需要先把 Nginx 升级到系统软件源的最新版本（sudo apt update && sudo apt upgrade nginx），之后重新运行就能用完整模式"
		fi
	else
		MODE=full
	fi
}

show_plan() {
	say ""
	say "protect $VERSION 将要在这台服务器上做以下事情："
	say "  系统：$OS_NAME · Web 服务器：$WEB_NAME"
	if [ "$MODE" = full ]; then
		say "  防护级别：完整（请求到达网站之前就检测，攻击请求直接返回 403）"
	else
		say "  防护级别：基础（分析 Nginx 日志，发现攻击后在防火墙封禁 IP；不改动 Nginx）"
		say "            原因：$MODE_REASON"
	fi
	say ""
	say "  1. 添加 CrowdSec 官方软件源，安装 CrowdSec"
	if [ "$MODE" = full ]; then
		if [ "$strict" -eq 1 ]; then
			say "  2. 安装 Nginx 防护组件，启用虚拟补丁、通用攻击规则和 OWASP CRS（严格模式）"
		else
			say "  2. 安装 Nginx 防护组件，启用虚拟补丁和通用攻击规则"
		fi
	else
		say "  2. 读取 Nginx 日志（${LOG_DESC}），识别扫描、漏洞利用和暴力破解"
		if [ "$strict" -eq 1 ]; then
			say "     （--strict 只在完整模式下有效，这台服务器上会忽略它）"
		fi
	fi
	say "  3. 安装防火墙组件，封禁攻击网站和暴力破解 SSH 的 IP"
	if [ ${#ALLOW_IPS[@]} -gt 0 ]; then
		say "  4. 把这些 IP 加入白名单，永远不会被封：${ALLOW_IPS[*]}"
	else
		say "  4. 没有识别出你当前登录用的 IP。建议加 --allow-ip <你的IP> 重新运行，避免把自己封在外面"
	fi
	say ""
	say "说明：CrowdSec 默认会把检测到的攻击者 IP 和攻击类型分享给 CrowdSec 社区，"
	say "      同时下载社区黑名单。不想分享可以参考 https://docs.crowdsec.net 关闭 Central API。"
	say ""
}

setup_appsec() {
	local configs="  - crowdsecurity/appsec-default"
	hub_install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
	if [ "$strict" -eq 1 ]; then
		hub_install crowdsecurity/appsec-crs-inband
		configs="$configs
  - crowdsecurity/crs-inband"
	fi
	# 放行例外放在最后，对前面所有规则生效
	configs="$configs
  - protect/exceptions"
	write_exceptions
	# 默认只有 1 个检测线程，流量一大请求就会超时并被直接放行。按 CPU 核数开，最多 4 个
	local routines
	routines=$(nproc 2>/dev/null || echo 1)
	[ "$routines" -gt 4 ] && routines=4
	cat >"$APPSEC_ACQUIS" <<EOF
# 由 protect.sh 生成：在本机 7422 端口接收 Nginx 转来的请求并检测
source: appsec
name: protect-appsec
listen_addr: 127.0.0.1:7422
routines: $routines
appsec_configs:
$configs
labels:
  type: appsec
EOF
}

do_install() {
	detect_os
	detect_web

	# 重新安装（包括更新后自动重装）时沿用上次的严格模式设置，
	# 除非这次明确指定了 --strict 或 --no-strict
	if [ -f "$STATE" ] && [ "$strict_set" -eq 0 ]; then
		# shellcheck disable=SC1090
		strict=$(
			. "$STATE"
			printf '%s' "${STRICT:-0}"
		)
	fi

	ALLOW_IPS=()
	local ip
	ip=$(admin_ip)
	[ -n "$ip" ] && ALLOW_IPS+=("$ip")
	for ip in ${extra_ips[@]+"${extra_ips[@]}"}; do
		valid_ip "$ip" || die "不是有效的 IP：$ip"
		ALLOW_IPS+=("$ip")
	done

	if [ "$WEB" = baota ]; then
		LOG_DESC="/www/wwwlogs/*.log"
	else
		LOG_DESC="/var/log/nginx/*.log"
	fi

	step "准备软件源"
	add_repo
	choose_mode
	show_plan
	confirm "确认开始？" || die "已取消，没有做任何改动"

	step "安装 CrowdSec"
	pkg_install crowdsec
	# 安装时会自动识别 Nginx、SSH 并启用对应规则；这里再装一遍确保齐全
	hub_install crowdsecurity/nginx crowdsecurity/base-http-scenarios crowdsecurity/http-cve
	# CrowdSec 自带每天更新规则的定时任务，默认开启。确保它开着，规则才不会过时
	systemctl enable --now crowdsec-hubupdate.timer >/dev/null 2>&1 || true
	if [ "$WEB" = baota ]; then
		cat >"$BAOTA_ACQUIS" <<'EOF'
# 由 protect.sh 生成：宝塔把各站点的日志放在 /www/wwwlogs
filenames:
  - /www/wwwlogs/*.log
labels:
  type: nginx
source: file
EOF
	fi

	if [ "$MODE" = full ]; then
		step "安装 Nginx 防护组件"
		setup_appsec
		pkg_install crowdsec-nginx-bouncer
		sed -i 's|^APPSEC_URL=.*|APPSEC_URL=http://127.0.0.1:7422|' "$NGINX_BOUNCER_CONF"
	fi

	step "安装防火墙组件"
	if command -v nft >/dev/null 2>&1; then
		pkg_install crowdsec-firewall-bouncer-nftables
	else
		pkg_install crowdsec-firewall-bouncer-iptables
	fi

	systemctl reload crowdsec 2>/dev/null || systemctl restart crowdsec
	sleep 3

	if [ ${#ALLOW_IPS[@]} -gt 0 ]; then
		step "设置白名单"
		cscli allowlists create "$ALLOWLIST" -d "protect.sh：管理员 IP，永不封禁" >/dev/null 2>&1 || true
		for ip in "${ALLOW_IPS[@]}"; do
			cscli allowlists add "$ALLOWLIST" "$ip" -d "管理员" >/dev/null 2>&1 || true
			say "已加入白名单：$ip"
		done
	fi

	if [ "$MODE" = full ]; then
		step "检查 Nginx 配置并重新加载"
		if ! nginx -t >/dev/null 2>&1; then
			pkg_remove crowdsec-nginx-bouncer
			nginx -t || true
			die "加上防护组件后 Nginx 配置检查不通过，已经撤掉防护组件，网站不受影响。请把上面的错误发给维护者。"
		fi
		systemctl reload nginx
	fi

	# 这个文件之后会被 source，所以每个值都要转义，免得空格、括号之类的字符变成语法错误
	printf 'MODE=%q\nWEB=%q\nSTRICT=%q\nINSTALLED_VERSION=%q\n' "$MODE" "$WEB" "$strict" "$VERSION" >"$STATE"

	step "安装 protect 管理命令"
	local manage="sudo protect"
	if install_command; then
		say "已安装：$BIN"
	else
		warn "没能安装 protect 命令（下载或校验失败）。以后重新运行一遍安装命令，同样能打开管理菜单"
		manage="重新运行安装命令"
	fi

	step "检查"
	check || warn "有组件没有正常运行，按上面的提示排查"
	cat <<EOF

完成。以后在服务器上运行：

  $manage

就能打开管理菜单：查看状态、放行被误拦的正常用户、解封 IP、更新、卸载。
EOF
}

check() {
	local ok=1 svc
	for svc in crowdsec crowdsec-firewall-bouncer; do
		if systemctl is-active --quiet "$svc"; then
			say "  [正常] $svc 正在运行"
		else
			say "  [异常] $svc 没有运行，用 journalctl -u $svc 查看原因"
			ok=0
		fi
	done
	if [ "${MODE:-}" = full ]; then
		# 先读进变量再查找：直接接 grep -q 的话，grep 提前退出会让 nginx -T 收到
		# SIGPIPE，在 pipefail 下被当成失败
		local conf
		conf=$(nginx -T 2>/dev/null || true)
		if [[ "$conf" != *crowdsec* ]]; then
			say "  [异常] Nginx 没有加载 CrowdSec 防护组件。检查 nginx.conf 里有没有 include /etc/nginx/conf.d/*.conf;"
			ok=0
		fi
		# 只向本机发探测 .env 文件的请求，确认防护已经生效。重新加载后检测组件要
		# 过几秒才就绪，所以最多等 20 秒。先看一眼首页，默认站点如果本来就返回 403，
		# 就没法用它来确认
		local base code=""
		base=$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1/ || true)
		for _ in $(seq 1 20); do
			code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1/.env || true)
			[ "$code" = 403 ] && break
			sleep 1
		done
		if [ "$base" = 403 ]; then
			say "  [未确认] 本机默认站点对所有请求都返回 403，没法用它确认。"
			say "           可以在浏览器里访问 https://你的域名/.env，看到 CrowdSec 拦截页面就说明生效了。"
		elif [ "$code" = 403 ]; then
			say "  [正常] 请求 http://127.0.0.1/.env 被拦截（403），首页正常（$base）"
		else
			say "  [未确认] 请求 http://127.0.0.1/.env 返回 $code。如果默认站点会跳转到 HTTPS，这是正常的。"
			say "           可以在浏览器里访问 https://你的域名/.env，看到 CrowdSec 拦截页面就说明生效了。"
		fi
	else
		# 刚装好时还没有新日志，cscli metrics 里看不到文件，所以直接数日志文件
		local pattern files
		if [ "${WEB:-nginx}" = baota ]; then pattern="/www/wwwlogs/*.log"; else pattern="/var/log/nginx/*.log"; fi
		files=$( (compgen -G "$pattern" || true) | wc -l | tr -d ' ')
		if [ "$files" -gt 0 ]; then
			say "  [正常] 正在监控 $files 个 Nginx 日志文件（$pattern）"
		else
			say "  [异常] 没有找到 Nginx 日志文件（$pattern），基础模式要靠它们发现攻击"
			ok=0
		fi
	fi
	if systemctl is-enabled --quiet crowdsec-hubupdate.timer 2>/dev/null; then
		local last
		last=$(systemctl show -p LastTriggerUSec --value crowdsec-hubupdate.timer 2>/dev/null || true)
		case "$last" in
		"" | n/a | 0) last="每天运行一次，还没运行过" ;;
		*) last="上次：$last" ;;
		esac
		say "  [正常] 规则每天自动更新（$last）"
	else
		say "  [异常] 规则自动更新没有开启，运行 sudo systemctl enable --now crowdsec-hubupdate.timer 打开"
		ok=0
	fi
	[ "$ok" -eq 1 ]
}

load_state() {
	[ -f "$STATE" ] || die "这台服务器还没有安装防护，先运行一遍安装命令"
	# shellcheck disable=SC1090
	. "$STATE"
}

status() {
	load_state
	say "protect $VERSION（安装时的版本：${INSTALLED_VERSION:-未知}）"
	local latest
	latest=$(latest_version)
	if [ -n "$latest" ] && version_gt "$latest" "$VERSION"; then
		say "有新版本 $latest，运行 sudo protect --update 更新"
	fi
	if [ "$MODE" = full ]; then say "防护级别：完整"; else say "防护级别：基础"; fi
	check || true
	say ""
	say "当前封禁的 IP：$(cscli decisions list -o raw 2>/dev/null | tail -n +2 | grep -c . || true) 个"
	if [ "$MODE" = full ]; then
		# 没有例外时 grep -c 输出 0 但返回失败，不能再接 || echo 0，否则会多打一个 0
		local exc
		exc=$(grep -c . "$EXCEPTIONS_LIST" 2>/dev/null || true)
		say "放行例外：${exc:-0} 条"
	fi
	say ""
	say "最近的攻击："
	cscli alerts list -l 10 2>/dev/null || true
}

# ---- protect 命令、更新和菜单 ----

# 从脚本文件里读版本号，不执行它
file_version() { sed -nE 's/^VERSION=([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' "$1" 2>/dev/null; }

version_gt() {
	[ "$1" != "$2" ] && [ "$(printf '%s\n' "$1" "$2" | sort -V | tail -n 1)" = "$1" ]
}

# 最新发布的版本号。只用来提示有没有新版本，拿不到（比如没网）就不提示
latest_version() {
	local v
	v=$(curl -fsSL -m 5 "$RELEASES/latest/download/VERSION" 2>/dev/null || true)
	v=$(printf '%s' "$v" | tr -d '[:space:]')
	if [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then printf '%s' "$v"; fi
	return 0
}

# 下载某个发布版本的 protect.sh，用同一版本的 SHA256SUMS 校验。where 是
# latest/download 或 download/vX.Y.Z。返回 1 表示下载失败，2 表示校验不通过
fetch_release() {
	local where=$1 dir=$2
	retry curl -fsSL -o "$dir/protect.sh" "$RELEASES/$where/protect.sh" || return 1
	retry curl -fsSL -o "$dir/SHA256SUMS" "$RELEASES/$where/SHA256SUMS" || return 1
	(cd "$dir" && sha256sum --check --quiet SHA256SUMS >/dev/null 2>&1) || return 2
}

# 先写到临时文件再改名：正在运行的 protect 命令不会读到写了一半的文件
put_command() { install -m 755 "$1" "$BIN.new" && mv -f "$BIN.new" "$BIN"; }

# 把脚本装成 protect 命令。从文件运行时直接复制自己；通过 curl | bash 运行时脚本
# 不在磁盘上，就下载同一版本的发布文件，校验通过才装
install_command() {
	local src=${BASH_SOURCE[0]:-} tmp ok=0
	if [ -f "$src" ] && [ "$(file_version "$src")" = "$VERSION" ]; then
		[ "$(readlink -f "$src")" = "$(readlink -f "$BIN")" ] && return 0
		put_command "$src"
		return
	fi
	tmp=$(mktemp -d)
	if fetch_release "download/v$VERSION" "$tmp" && [ "$(file_version "$tmp/protect.sh")" = "$VERSION" ]; then
		put_command "$tmp/protect.sh" && ok=1
	fi
	rm -rf "$tmp"
	[ "$ok" -eq 1 ]
}

update() {
	load_state
	local tmp new rc=0
	tmp=$(mktemp -d)
	say "正在下载最新版本并校验……"
	fetch_release latest/download "$tmp" || rc=$?
	if [ "$rc" -ne 0 ]; then
		rm -rf "$tmp"
		if [ "$rc" -eq 2 ]; then
			die "校验不通过：下载到的文件和发布的校验值对不上，可能被篡改或下载损坏。没有做任何改动"
		fi
		die "下载失败，没有做任何改动。多半是网络问题，稍后再试"
	fi
	new=$(file_version "$tmp/protect.sh")
	if [ -z "$new" ] || ! version_gt "$new" "$VERSION"; then
		rm -rf "$tmp"
		say "已经是最新版本（$VERSION）。"
		return 0
	fi
	say "发现新版本：$VERSION → $new"
	say "更新说明：$RELEASES/tag/v$new"
	if ! confirm "现在更新吗？现有的设置和放行例外都会保留"; then
		rm -rf "$tmp"
		die "已取消"
	fi
	put_command "$tmp/protect.sh"
	rm -rf "$tmp"
	say "已更新到 $new，按原有设置重新应用一遍配置……"
	# 换成新版本继续执行，新版本里的配置改动这样才会生效
	exec "$BIN" --reinstall -y
}

pause() {
	have_tty || return 0
	printf '\n按回车返回菜单……' >/dev/tty
	read -r _ </dev/tty || true
}

# 给不想记选项的用户用。每个操作放在子 shell 里跑，出错只结束这一项，回到菜单
menu() {
	load_state
	# 从 0.1.0 升级上来的服务器还没有 protect 命令，顺手补上
	[ -x "$BIN" ] || install_command >/dev/null 2>&1 || true
	local latest choice ip n level
	latest=$(latest_version)
	if [ "$MODE" = full ]; then level="完整"; else level="基础"; fi
	while true; do
		say ""
		say "protect $VERSION · 防护级别：$level"
		if [ -n "$latest" ] && version_gt "$latest" "$VERSION"; then
			say "有新版本 $latest，选 5 更新"
		fi
		say ""
		say "  1. 查看防护状态"
		if [ "$MODE" = full ]; then
			say "  2. 正常用户被拦了，查看并放行"
			say "  3. 查看或撤销已放行的例外"
		fi
		say "  4. 解封一个 IP"
		say "  5. 检查更新"
		say "  6. 卸载"
		say "  0. 退出"
		printf '\n请选择：' >/dev/tty
		read -r choice </dev/tty || return 0
		case "$choice" in
		1) (status) || true ;;
		2) if [ "$MODE" = full ]; then (blocks) || true; fi ;;
		3)
			if [ "$MODE" = full ]; then
				(
					exceptions
					if grep -q . "$EXCEPTIONS_LIST" 2>/dev/null; then
						printf '\n输入编号撤销（直接回车返回）：' >/dev/tty
						read -r n </dev/tty || true
						if [ -n "$n" ]; then remove_exception "$n"; fi
					fi
				) || true
			fi
			;;
		4)
			printf '要解封的 IP：' >/dev/tty
			read -r ip </dev/tty || true
			if [ -n "$ip" ]; then (unban "$ip") || true; fi
			;;
		5)
			(update) || true
			# 更新成功后磁盘上的 protect 已经是新版本，退出菜单，免得继续用旧版本操作
			if [ "$(file_version "$BIN")" != "$VERSION" ]; then
				say "重新运行 sudo protect 打开新版本的菜单。"
				return 0
			fi
			;;
		6)
			(uninstall) || true
			return 0
			;;
		0 | q | Q | "") return 0 ;;
		*)
			say "请输入菜单里的数字"
			continue
			;;
		esac
		pause
	done
}

# ---- 误报处理 ----

# 读取一次拦截记录的上下文字段。同一个字段可能有多行，比如一次命中了多条规则
alert_field() {
	cscli alerts inspect "$1" 2>/dev/null | awk -F'|' -v k="$2" '
		/Context/ { ctx = 1; next }
		/Events/ { ctx = 0 }
		ctx && NF >= 4 {
			key = $2; val = $3
			gsub(/^ +| +$/, "", key); gsub(/^ +| +$/, "", val)
			if (key == k) print val
		}'
}

# 最近的网站拦截记录，每行"编号,IP,时间"。reason 字段里可能有逗号，所以从两头取。
# 条数在 awk 里限制，不接 head：head 提前退出会在 pipefail 下让整个脚本中止
recent_blocks() {
	cscli alerts list -o raw -l 200 2>/dev/null |
		awk -F, 'NR > 1 && $NF == "waf" && n < 15 { print $1 "," $3 "," $(NF - 1); n++ }'
}

join_lines() { awk -v sep="$1" 'NR > 1 { printf "%s", sep } { printf "%s", $0 } END { print "" }'; }

shorten() {
	if [ ${#1} -gt 80 ]; then printf '%s…' "${1:0:80}"; else printf '%s' "$1"; fi
}

# 先把路径里原有的反斜杠转义掉，避免 printf %b 把 \n、\c 这类内容当成转义符
urldecode() {
	local s=${1//\\/\\\\}
	printf '%b' "${s//%/\\x}"
}

# 拦截记录里的内容来自访问者，显示前去掉控制字符，避免干扰终端
clean() { printf '%s' "$1" | tr -d '\000-\037\177'; }

yaml_quote() { printf "'%s'" "${1//\'/\'\'}"; }

expr_string() {
	local s=${1//\\/\\\\}
	printf '"%s"' "${s//\"/\\\"}"
}

rule_call() {
	case "$1" in
	native_rule:*) printf 'RemoveInBandRuleByID(%s)' "${1#native_rule:}" ;;
	*) printf 'RemoveInBandRuleByName(%s)' "$(expr_string "$1")" ;;
	esac
}

# 某个路径上放行的规则。路径通过环境变量交给 awk，因为 awk -v 会把路径里的反斜杠
# 当成转义符，导致匹配不上
rules_for_path() { P="$1" awk -F'\t' '$1 == ENVIRON["P"] { print $2 }' "$EXCEPTIONS_LIST"; }

# 放行过的路径，按第一次放行的顺序，* 表示全站
exception_paths() { awk -F'\t' 'NF && !seen[$1]++ { print $1 }' "$EXCEPTIONS_LIST"; }

write_exceptions() {
	mkdir -p "$(dirname "$EXCEPTIONS_YAML")"
	touch "$EXCEPTIONS_LIST"
	local tab=$'\t' path name
	{
		echo "# 由 protect.sh 生成，不要手动修改。"
		echo "# 用 sudo protect --blocks 添加例外，用 sudo protect --reset-exceptions 全部清除。"
		echo "name: protect/exceptions"
		if grep -q "^\*$tab" "$EXCEPTIONS_LIST"; then
			echo "on_load:"
			echo "  - apply:"
			grep "^\*$tab" "$EXCEPTIONS_LIST" | cut -f2 | while IFS= read -r name; do
				echo "      - $(yaml_quote "$(rule_call "$name")")"
			done
		fi
		if grep -qv "^\*$tab" "$EXCEPTIONS_LIST"; then
			echo "pre_eval:"
			grep -v "^\*$tab" "$EXCEPTIONS_LIST" | cut -f1 | sort -u | while IFS= read -r path; do
				echo "  - filter: $(yaml_quote "req.URL.Path == $(expr_string "$path")")"
				echo "    apply:"
				rules_for_path "$path" | while IFS= read -r name; do
					echo "      - $(yaml_quote "$(rule_call "$name")")"
				done
			done
		fi
	} >"$EXCEPTIONS_YAML"
}

# 改了例外以后重启 CrowdSec 让它生效。重启的几秒内请求会直接放行，不会拦住正常用户
apply_exceptions() {
	write_exceptions
	systemctl restart crowdsec
}

blocks() {
	load_state
	if [ "$MODE" != full ]; then
		say "基础模式下没有网站层面的拦截，只会按 IP 封禁。当前封禁的 IP："
		cscli decisions list 2>/dev/null || true
		say ""
		say "如果正常用户的 IP 被封了：sudo protect --unban <IP>"
		return
	fi
	local rows id ip time t uri method msgs
	rows=$(recent_blocks)
	if [ -z "$rows" ]; then
		say "最近没有被拦截的请求。"
		return
	fi
	say "最近被拦截的请求（最新的在前）："
	while IFS=, read -r id ip time; do
		uri=$(clean "$(alert_field "$id" target_uri | head -1)")
		method=$(clean "$(alert_field "$id" method | head -1)")
		msgs=$(clean "$(alert_field "$id" msg | join_lines "；")")
		t=${time:5:11}
		printf '\n  [%s] %s  %s  %s %s\n' "$id" "${t/T/ }" "$ip" "$method" "$(shorten "$uri")"
		say "       原因：${msgs:-未知}"
	done <<<"$rows"
	say ""
	if ! have_tty; then
		say "放行某次拦截：sudo protect --allow-block <编号>"
		return
	fi
	local choice
	printf '是正常用户被误拦了？输入编号放行（直接回车退出）：' >/dev/tty
	read -r choice </dev/tty || true
	[ -n "$choice" ] || return 0
	printf '%s\n' "$rows" | cut -d, -f1 | grep -qxF "$choice" || die "没有这个编号：$choice"
	allow_block "$choice"
}

allow_block() {
	local id=$1 uri path names ip scope count added=0 name line
	uri=$(alert_field "$id" target_uri | head -1)
	names=$(alert_field "$id" name)
	[ -n "$names" ] || die "读不到这次拦截命中了哪些规则"
	ip=$(cscli alerts list -o raw -l 200 2>/dev/null | awk -F, -v id="$id" '$1 == id { print $3 }')
	path=$(urldecode "${uri%%\?*}")
	case "$path" in
	/*) ;;
	*) die "读不到这次请求的路径，不能放行" ;;
	esac
	# 路径来自访问者能控制的 URL。解码后如果有换行、制表符等控制字符，写进例外列表
	# 会被拆成别的行，变成攻击者指定的全站例外，所以直接拒绝
	if [[ "$path" =~ [[:cntrl:]] ]]; then
		die "这次请求的路径里有换行等控制字符，很可能是故意构造的攻击请求，不能放行"
	fi
	count=$(printf '%s\n' "$names" | grep -c .)

	if printf '%s\n' "$names" | grep -q '^crowdsecurity/vpatch-'; then
		warn "这次拦截命中了针对已知漏洞的规则，这类规则很少误报。请确认这确实是正常用户的请求。"
	fi
	say ""
	say "这次拦截命中了 $count 条规则。放行范围："
	say "  1. 只在 $path 这个路径放行（推荐）"
	say "  2. 全站放行"
	scope=1
	if [ "$site_wide" -eq 1 ]; then
		scope=2
	elif [ "$assume_yes" -ne 1 ] && have_tty; then
		printf '请选择 [1/2]：' >/dev/tty
		read -r scope </dev/tty || true
	fi
	case "$scope" in
	1 | "") scope=$path ;;
	2) scope='*' ;;
	*) die "请输入 1 或 2" ;;
	esac

	touch "$EXCEPTIONS_LIST"
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		line=$(printf '%s\t%s' "$scope" "$name")
		if ! grep -qxF "$line" "$EXCEPTIONS_LIST"; then
			printf '%s\n' "$line" >>"$EXCEPTIONS_LIST"
			added=$((added + 1))
		fi
	done <<<"$names"
	apply_exceptions
	# 连续被拦可能已经触发了封禁，一并解除
	if [ -n "$ip" ]; then cscli decisions delete --ip "$ip" >/dev/null 2>&1 || true; fi
	if [ "$scope" = '*' ]; then
		say "已在全站放行这 $count 条规则（新增 $added 条例外）。"
	else
		say "已在 $path 放行这 $count 条规则（新增 $added 条例外），其他路径照常检测。"
	fi
	say "反悔了可以用 sudo protect --exceptions 查看，再按编号删除。"
}

# 例外里的规则名换成人看得懂的说法
rule_label() {
	case "$1" in
	native_rule:*) printf 'OWASP CRS 规则 %s' "${1#native_rule:}" ;;
	*) printf '%s' "$1" ;;
	esac
}

path_label() { if [ "$1" = '*' ]; then printf '全站'; else clean "$1"; fi; }

# 按路径分组列出。一次放行通常涉及好几条规则，用户要撤销的是"这个路径上的放行"，
# 只删其中一条规则往往不会让拦截恢复
exceptions() {
	load_state
	[ "$MODE" = full ] || die "基础模式没有放行例外"
	touch "$EXCEPTIONS_LIST"
	if ! grep -q . "$EXCEPTIONS_LIST"; then
		say "没有放行例外。"
		return
	fi
	say "放行例外："
	local n=0 path rules
	while IFS= read -r path; do
		n=$((n + 1))
		rules=$(rules_for_path "$path" | while IFS= read -r r; do rule_label "$r"; echo; done | join_lines "、")
		printf '  [%d] %s：%s\n' "$n" "$(path_label "$path")" "$rules"
	done < <(exception_paths)
	say ""
	say "撤销某个路径上的放行：sudo protect --remove-exception <编号>"
}

remove_exception() {
	local n=$1 total path count
	load_state
	[ "$MODE" = full ] || die "基础模式没有放行例外"
	[[ "$n" =~ ^[0-9]+$ ]] || die "编号要是数字（用 --exceptions 查看）"
	touch "$EXCEPTIONS_LIST"
	total=$(exception_paths | grep -c . || true)
	if [ "$n" -lt 1 ] || [ "$n" -gt "${total:-0}" ]; then
		die "没有第 $n 个放行，现在一共 ${total:-0} 个（用 --exceptions 查看）"
	fi
	path=$(exception_paths | sed -n "${n}p")
	count=$(rules_for_path "$path" | grep -c .)
	confirm "撤销 $(path_label "$path") 上的放行（$count 条规则）？之后这类请求会重新被拦截" || die "已取消"
	P="$path" awk -F'\t' '$1 != ENVIRON["P"]' "$EXCEPTIONS_LIST" >"$EXCEPTIONS_LIST.tmp"
	mv "$EXCEPTIONS_LIST.tmp" "$EXCEPTIONS_LIST"
	apply_exceptions
	say "已撤销 $(path_label "$path") 上的放行。"
}

unban() {
	local ip=$1
	valid_ip "$ip" || die "不是有效的 IP：$ip"
	load_state
	cscli decisions delete --ip "$ip" >/dev/null 2>&1 || true
	say "已解封 $ip"
	if confirm "把 $ip 加入白名单，以后永远不封？"; then
		cscli allowlists create "$ALLOWLIST" -d "protect.sh：管理员 IP，永不封禁" >/dev/null 2>&1 || true
		cscli allowlists add "$ALLOWLIST" "$ip" -d "手动加入" >/dev/null 2>&1 || true
		say "已加入白名单：$ip"
	fi
}

reset_exceptions() {
	load_state
	[ "$MODE" = full ] || die "基础模式没有放行例外"
	confirm "清除所有放行例外，恢复默认规则？" || die "已取消"
	: >"$EXCEPTIONS_LIST"
	apply_exceptions
	say "已清除所有放行例外。"
}

uninstall() {
	[ -f "$STATE" ] || warn "没有找到安装记录，仍然尝试卸载"
	detect_os
	confirm "将卸载 CrowdSec 和它的防护组件，网站会失去这层防护。确认吗？" || die "已取消"
	step "卸载"
	if dpkg -s crowdsec-nginx-bouncer >/dev/null 2>&1 || rpm -q crowdsec-nginx-bouncer >/dev/null 2>&1; then
		pkg_remove crowdsec-nginx-bouncer
		if nginx -t >/dev/null 2>&1; then systemctl reload nginx; fi
	fi
	pkg_remove crowdsec-firewall-bouncer-nftables crowdsec-firewall-bouncer-iptables crowdsec
	rm -f "$STATE" "$APPSEC_ACQUIS" "$BAOTA_ACQUIS" "$EXCEPTIONS_LIST" "$EXCEPTIONS_YAML" "$BIN"
	say "已卸载，protect 命令也已删除。CrowdSec 的软件源配置仍然保留，不影响系统使用。"
}

case "$action" in
install) do_install ;;
menu) menu ;;
update) update ;;
status) status ;;
blocks) blocks ;;
allow_block)
	load_state
	[ "$MODE" = full ] || die "基础模式没有网站层面的拦截。误封了 IP 用 --unban"
	allow_block "$block_id"
	;;
unban) unban "$unban_ip" ;;
exceptions) exceptions ;;
remove_exception) remove_exception "$exception_id" ;;
reset_exceptions) reset_exceptions ;;
uninstall) uninstall ;;
esac

# 和开头的 { 配对，见开头的说明
}

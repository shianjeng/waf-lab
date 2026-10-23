#!/usr/bin/env bash
# 一键给自己服务器上的网站加上 CrowdSec 防护。只做防护，不会向任何地方发送攻击请求。
#
#   sudo bash protect.sh               安装（先列出要做的事，确认后才动手）
#   sudo bash protect.sh --strict      同时启用 OWASP CRS 规则：拦得更多，误报也更多
#   sudo bash protect.sh --allow-ip IP 额外把一个 IP 加入白名单（可以重复）
#   sudo bash protect.sh --status      查看防护状态
#   sudo bash protect.sh --blocks      查看最近拦截的请求，把误拦的放行
#   sudo bash protect.sh --unban IP    解封一个被误封的 IP
#   sudo bash protect.sh --uninstall   卸载
#   加 -y 跳过确认
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
用法：sudo bash protect.sh [选项]

  （不加选项）         安装防护，先列出要做的事，确认后才动手
  --strict             同时启用 OWASP CRS 规则：拦得更多，误报也更多（仅完整模式）
  --allow-ip IP        额外把一个 IP 加入白名单，可以重复
  --status             查看防护状态和最近拦截的攻击
  --blocks             查看最近被拦截的请求，输入编号把误拦的放行
  --allow-block 编号   不用交互，直接放行某次拦截（只在那个路径；加 --site-wide 全站放行）
  --unban IP           解封一个被误封的 IP，可以顺便加入白名单
  --reset-exceptions   清除所有放行例外，恢复默认规则
  --uninstall          卸载
  -y                   跳过确认
EOF
}

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
warn() { printf '注意：%s\n' "$*" >&2; }
die() { printf '错误：%s\n' "$*" >&2; exit 1; }

action=install
assume_yes=0
strict=0
site_wide=0
extra_ips=()
unban_ip=""
block_id=""
while [ $# -gt 0 ]; do
	case "$1" in
	-y | --yes) assume_yes=1 ;;
	--strict) strict=1 ;;
	--allow-ip)
		[ $# -ge 2 ] || die "--allow-ip 后面要跟一个 IP"
		extra_ips+=("$2")
		shift
		;;
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
	--reset-exceptions) action=reset_exceptions ;;
	--uninstall) action=uninstall ;;
	-h | --help)
		usage
		exit 0
		;;
	*) die "不认识的参数：$1（用 --help 查看用法）" ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "需要 root 权限，请用 sudo bash protect.sh"

# 通过 curl | sudo bash 运行时，标准输入是脚本本身，要从终端读回答。
# 只看 /dev/tty 存不存在不够：没有终端时它存在但打不开
have_tty() { { true >/dev/tty; } 2>/dev/null; }

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
	# shellcheck disable=SC1091
	. /etc/os-release
	OS_NAME="${PRETTY_NAME:-$ID}"
	case " ${ID:-} ${ID_LIKE:-} " in
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

pkg_install() {
	case "$PKG" in
	apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null ;;
	*) "$PKG" install -y -q "$@" >/dev/null ;;
	esac
}

pkg_remove() {
	case "$PKG" in
	apt) DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$@" >/dev/null 2>&1 || true ;;
	*) "$PKG" remove -y -q "$@" >/dev/null 2>&1 || true ;;
	esac
}

add_repo() {
	command -v curl >/dev/null 2>&1 || pkg_install curl
	if [ "$PKG" = apt ] && [ -f /etc/apt/sources.list.d/crowdsec_crowdsec.list ]; then return 0; fi
	if [ "$PKG" != apt ] && [ -f /etc/yum.repos.d/crowdsec_crowdsec.repo ]; then return 0; fi
	# 官方安装脚本不认识阿里云 Linux、龙蜥、OpenCloudOS 这些兼容 RHEL 的系统，会直接拒绝。
	# CrowdSec 的 RPM 软件源对 RHEL 系是通用的，所以让它按 RHEL 处理
	local override=() out version=${VERSION_ID:-9}
	if [ "$PKG" != apt ]; then
		case "${ID:-}" in
		centos | rhel | fedora | amzn | cloudlinux | almalinux | rocky | ol) ;;
		*) override=(os=rhel "dist=${version%%.*}") ;;
		esac
	fi
	if ! out=$(curl -fsSL https://install.crowdsec.net | env ${override[@]+"${override[@]}"} sh 2>&1); then
		printf '%s\n' "$out" | tail -n 8 >&2
		die "添加 CrowdSec 软件源失败，原因见上面的输出"
	fi
	if [ "$PKG" = apt ]; then apt-get update -qq >/dev/null; fi
	return 0
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
	say "将要在这台服务器上做以下事情："
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
	cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules >/dev/null
	if [ "$strict" -eq 1 ]; then
		cscli collections install crowdsecurity/appsec-crs-inband >/dev/null
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

install() {
	detect_os
	detect_web

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
	cscli collections install crowdsecurity/nginx crowdsecurity/base-http-scenarios crowdsecurity/http-cve >/dev/null
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

	cat >"$STATE" <<EOF
MODE=$MODE
WEB=$WEB
STRICT=$strict
EOF

	step "检查"
	check || warn "有组件没有正常运行，按上面的提示排查"
	cat <<EOF

完成。常用命令：
  sudo bash protect.sh --status          查看防护状态和最近拦截的攻击
  sudo bash protect.sh --blocks          正常用户被拦了？在这里找到那次拦截并放行
  sudo bash protect.sh --unban IP        解封一个被误封的 IP
  sudo bash protect.sh --uninstall       卸载
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
		local base code="" i
		base=$(curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1/ || true)
		for i in $(seq 1 20); do
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
	[ "$ok" -eq 1 ]
}

load_state() {
	[ -f "$STATE" ] || die "这台服务器还没有用 protect.sh 安装防护"
	# shellcheck disable=SC1090
	. "$STATE"
}

status() {
	load_state
	if [ "$MODE" = full ]; then say "防护级别：完整"; else say "防护级别：基础"; fi
	check || true
	say ""
	say "当前封禁的 IP：$(cscli decisions list -o raw 2>/dev/null | tail -n +2 | grep -c . || true) 个"
	if [ "$MODE" = full ]; then
		say "放行例外：$(grep -c . "$EXCEPTIONS_LIST" 2>/dev/null || echo 0) 条"
	fi
	say ""
	say "最近的攻击："
	cscli alerts list -l 10 2>/dev/null || true
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

write_exceptions() {
	mkdir -p "$(dirname "$EXCEPTIONS_YAML")"
	touch "$EXCEPTIONS_LIST"
	local tab=$'\t' path name
	{
		echo "# 由 protect.sh 生成，不要手动修改。"
		echo "# 用 protect.sh --blocks 添加例外，用 protect.sh --reset-exceptions 全部清除。"
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
				awk -F'\t' -v p="$path" '$1 == p { print $2 }' "$EXCEPTIONS_LIST" | while IFS= read -r name; do
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
		say "如果正常用户的 IP 被封了：sudo bash protect.sh --unban <IP>"
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
		say "放行某次拦截：sudo bash protect.sh --allow-block <编号>"
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
	say "反悔了可以用 sudo bash protect.sh --reset-exceptions 清除所有例外。"
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
	rm -f "$STATE" "$APPSEC_ACQUIS" "$BAOTA_ACQUIS" "$EXCEPTIONS_LIST" "$EXCEPTIONS_YAML"
	say "已卸载。CrowdSec 的软件源配置仍然保留，不影响系统使用。"
}

case "$action" in
install) install ;;
status) status ;;
blocks) blocks ;;
allow_block)
	load_state
	[ "$MODE" = full ] || die "基础模式没有网站层面的拦截。误封了 IP 用 --unban"
	allow_block "$block_id"
	;;
unban) unban "$unban_ip" ;;
reset_exceptions) reset_exceptions ;;
uninstall) uninstall ;;
esac

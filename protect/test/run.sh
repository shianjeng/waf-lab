#!/usr/bin/env bash
# 在本机 Docker 里模拟几种服务器，跑一遍 protect.sh 的安装、检查和卸载。
#
#   protect/test/run.sh              测全部
#   protect/test/run.sh rocky9       只测一种
#
# 用到的 IP 都在文档专用地址段（RFC 5737），不属于任何真实主机。
# "攻击"是直接写进测试机日志文件的几行模拟记录，不会发出任何网络请求。
set -euo pipefail
cd "$(dirname "$0")"

ADMIN=198.51.100.7
ATTACKER=203.0.113.77
VERSION=$(sed -nE 's/^VERSION=([0-9]+\.[0-9]+\.[0-9]+)$/\1/p' ../protect.sh)
# 测试机里模拟的"下一个版本"，用来测 --update
NEXT=$(printf '%s' "$VERSION" | awk -F. '{ print $1 "." $2 "." $3 + 1 }')
# protect 命令从这里下载发布文件，指向测试机里模拟的发布目录，不依赖 GitHub 上真实的版本
REL=file:///root/rel
# CI 里用 LOGS_DIR 指定日志目录，失败时把日志上传下来
LOGS=${LOGS_DIR:-$(mktemp -d)}
mkdir -p "$LOGS"
failures=0

build() {
	local name=$1 file=$2 base=${3:-}
	if [ -n "$base" ]; then
		docker build -q -t "waf-lab/test-$name" --build-arg BASE="$base" -f "$file" . >/dev/null
	else
		docker build -q -t "waf-lab/test-$name" -f "$file" . >/dev/null
	fi
}

start() {
	local name=$1 image=${2:-$1} state
	docker rm -f "pt-$name" >/dev/null 2>&1 || true
	docker run -d --name "pt-$name" --privileged --cgroupns=host \
		-v /sys/fs/cgroup:/sys/fs/cgroup:rw "waf-lab/test-$image" >/dev/null
	for _ in $(seq 1 30); do
		state=$(docker exec "pt-$name" systemctl is-system-running 2>/dev/null || true)
		case "$state" in running | degraded) break ;; esac
		sleep 1
	done
	docker cp ../protect.sh "pt-$name:/root/protect.sh"
	fake_release "$name"
}

# 在测试机里做一个和 GitHub Releases 目录结构一样的发布：当前版本 $VERSION，
# 加上一个"最新版本" $NEXT
fake_release() {
	docker exec "pt-$1" bash -c "
		R=/root/rel
		mkdir -p \$R/download/v$VERSION \$R/latest/download
		cp /root/protect.sh \$R/download/v$VERSION/
		(cd \$R/download/v$VERSION && sha256sum protect.sh >SHA256SUMS)
		sed 's/^VERSION=.*/VERSION=$NEXT/' /root/protect.sh >\$R/latest/download/protect.sh
		(cd \$R/latest/download && sha256sum protect.sh >SHA256SUMS && echo $NEXT >VERSION)"
}

in_box() { docker exec -e PROTECT_RELEASES_URL="$REL" "pt-$1" bash -c "$2"; }

expect() {
	local desc=$1
	shift
	if "$@" >/dev/null 2>&1; then
		echo "  ✓ $desc"
	else
		echo "  ✗ $desc"
		failures=$((failures + 1))
	fi
}

http_code() { in_box "$1" "curl -s -o /dev/null -m 5 -w %{http_code} 'http://127.0.0.1$2'"; }

install_protect() {
	local name=$1
	shift
	docker exec -e SSH_CONNECTION="$ADMIN 51000 10.0.0.2 22" -e PROTECT_RELEASES_URL="$REL" "pt-$name" \
		bash /root/protect.sh -y "$@" >"$LOGS/$name.install.log" 2>&1
}

# 模拟 curl ... | sudo bash -s -- -y：脚本从标准输入读进来，而不是从文件运行
install_protect_piped() {
	local name=$1
	docker exec -e SSH_CONNECTION="$ADMIN 51000 10.0.0.2 22" -e PROTECT_RELEASES_URL="$REL" "pt-$name" \
		bash -c 'cat /root/protect.sh | bash -s -- -y' >"$LOGS/$name.install.log" 2>&1
}

uninstall_checks() {
	local name=$1
	in_box "$name" "bash /root/protect.sh --uninstall -y" >"$LOGS/$name.uninstall.log" 2>&1
	expect "卸载后 CrowdSec 已移除" in_box "$name" "! command -v cscli"
	expect "卸载后 protect 命令已删除" in_box "$name" "! test -e /usr/local/bin/protect"
	expect "卸载后网站仍然正常（200）" test "$(http_code "$name" /)" = 200
}

# 往日志里写几行"扫描敏感文件"的记录，模拟一个攻击者，等 CrowdSec 封禁它
simulate_scan() {
	local name=$1 log=$2
	in_box "$name" "
		now=\$(date '+%d/%b/%Y:%H:%M:%S %z')
		for p in /.env /.git/config /wp-config.php.bak /.aws/credentials /config.php.save \
			/backup.sql /.htpasswd /db.sql /.env.bak /phpinfo.php /.git/HEAD /admin/.env; do
			echo \"$ATTACKER - - [\$now] \\\"GET \$p HTTP/1.1\\\" 404 153 \\\"-\\\" \\\"Mozilla/5.0\\\"\" >>$log
		done"
}

banned() {
	local name=$1
	for _ in $(seq 1 30); do
		in_box "$name" "cscli decisions list -o raw | grep -q $ATTACKER" && return 0
		sleep 1
	done
	return 1
}

# 防火墙组件每 10 秒向 CrowdSec 拉一次封禁列表，所以要多等一会儿
in_firewall() {
	local name=$1
	for _ in $(seq 1 30); do
		in_box "$name" "nft list ruleset | grep -q $ATTACKER" && return 0
		sleep 1
	done
	return 1
}

# 模拟官方安装脚本下载签名密钥失败后留下的状态：软件源文件在，密钥文件是空的。
# protect.sh 应该发现软件源用不了，删掉重新添加
break_repo() {
	in_box "$1" "mkdir -p /etc/apt/keyrings
		echo 'deb [signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any/ any main' \
			>/etc/apt/sources.list.d/crowdsec_crowdsec.list
		: >/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg"
}

full_mode() {
	local name=$1 how=${2:-file} prep=${3:-}
	start "$name"
	if [ "$prep" = broken-repo ]; then
		break_repo "$name"
	fi
	if [ "$how" = piped ]; then
		echo "== $name（应为完整模式，用 curl | bash 的方式安装）"
		expect "安装成功" install_protect_piped "$name"
	else
		echo "== $name（应为完整模式）"
		expect "安装成功" install_protect "$name"
	fi
	expect "安装计划显示了版本号 $VERSION" grep -q "protect $VERSION 将要" "$LOGS/$name.install.log"
	if [ "$prep" = broken-repo ]; then
		expect "发现并修复了损坏的软件源" grep -q "CrowdSec 软件源没有配置成功" "$LOGS/$name.install.log"
	fi
	command_works "$name"
	status_works "$name"
	menu_works "$name"
	expect "选择了完整模式" grep -q "防护级别：完整" "$LOGS/$name.install.log"
	expect "自检：/.env 被拦截" grep -q "被拦截（403）" "$LOGS/$name.install.log"
	expect "正常页面不受影响（200）" test "$(http_code "$name" /)" = 200
	expect "管理员 IP 在白名单里" in_box "$name" "cscli allowlists inspect protect-admin | grep -q $ADMIN"
	expect "防火墙组件在运行" in_box "$name" "systemctl is-active --quiet crowdsec-firewall-bouncer"
	crafted_path_rejected "$name"
	uninstall_checks "$name"
}

command_works() {
	expect "装好了 protect 命令（$VERSION）" in_box "$1" "protect --version | grep -qx 'protect $VERSION'"
}

# --status 会读回安装时保存的状态文件，能发现状态文件写坏之类的问题
status_works() {
	expect "protect --status 正常，版本一致" in_box "$1" \
		"protect --status | grep -qF 'protect $VERSION（安装时的版本：$VERSION）'"
}

# 用伪终端操作菜单：选 1 查看状态，回车返回菜单，再选 0 退出
menu_works() {
	expect "sudo protect 打开菜单并能查看状态" in_box "$1" \
		"printf '1\n\n0\n' | script -qec protect /dev/null 2>&1 | grep -q '规则每天自动更新'"
}

# 让 Nginx 认 X-Forwarded-For 里的 IP，模拟不同访客（文档专用地址段）：3 个访客正常打开
# 首页，3 个访客在首页被误拦，3 个扫描者探测 /.env。首页应提示可能误报，/.env 不应该
fp_and_report_works() {
	local name=$1
	in_box "$name" "printf 'set_real_ip_from 127.0.0.1;\nreal_ip_header X-Forwarded-For;\n' >/etc/nginx/conf.d/00-test-realip.conf
		systemctl reload nginx
		# reload 是异步的，旧的 worker 还会处理一小会儿请求，那时还不认 X-Forwarded-For
		sleep 2
		visit() { curl -s -o /dev/null -H \"X-Forwarded-For: 203.0.113.\$1\" \"http://127.0.0.1\$2\"; }
		for i in 11 12 13; do visit \$i '/?ref=home'; done
		for i in 21 22 23; do visit \$i '/?q=zsh%20is%20the%20best%21'; done
		for i in 31 32 33; do visit \$i '/.env'; done"
	sleep 3
	expect "首页被多个访客误拦，提示可能误报" in_box "$name" "protect --status | grep -q '^  /：3 个访客被拦截'"
	expect "/.env 只有扫描，不算误报" in_box "$name" "! protect --status | grep -q '^  /.env：'"
	expect "protect --report 列出拦截和可能的误报" in_box "$name" \
		"protect --report | grep -q '网站防护拦截了' && protect --report | grep -q '可能的误报'"
}

# 每日简报推送：发到测试机里模拟的钉钉机器人（mockbot.sh）
notify_works() {
	local name=$1 send="PROTECT_NOTIFY_ENDPOINT=http://127.0.0.1:8099/"
	docker cp mockbot.sh "pt-$name:/root/mockbot.sh"
	in_box "$name" "(nohup bash /root/mockbot.sh >/dev/null 2>&1 &)"
	in_box "$name" "for i in \$(seq 50); do ss -ltn | grep -q 127.0.0.1:8099 && break; sleep 0.1; done"
	expect "不是官方机器人地址的被拒绝" in_box "$name" "! protect --notify https://example.com/hook"
	# 模拟机器人一直在线，第一次就该发成功。靠重试才发出去，说明发送有问题
	expect "设置推送，收到测试消息" in_box "$name" \
		"$send protect --notify 'https://oapi.dingtalk.com/robot/send?access_token=test' >/root/send.log 2>&1 && ! grep -q 重试 /root/send.log && grep -aq 推送已开启 /root/received.txt"
	expect "每天定时发送已开启" in_box "$name" "systemctl is-enabled --quiet protect-report.timer"
	expect "机器人地址只有 root 能读" in_box "$name" "test \"\$(stat -c %a /etc/crowdsec/protect-notify.env)\" = 600"
	expect "日报发到了机器人" in_box "$name" \
		"$send protect --report --send >/root/send.log 2>&1 && ! grep -q 重试 /root/send.log && grep -aq 防护日报 /root/received.txt"
	expect "关闭推送后定时任务和配置都删掉了" in_box "$name" \
		"protect --notify-off && ! test -e /etc/systemd/system/protect-report.timer && ! test -e /etc/crowdsec/protect-notify.env"
}

# 测试机里的"最新版本"是 $NEXT。更新后严格模式等设置要保留，篡改过的新版本要被拒绝
update_works() {
	local name=$1
	expect "protect --update 更新到 $NEXT" in_box "$name" "protect --update -y"
	expect "更新后版本是 $NEXT" in_box "$name" "protect --version | grep -qx 'protect $NEXT'"
	expect "更新后仍是严格模式" in_box "$name" "grep -q crs-inband /etc/crowdsec/acquis.d/protect-appsec.yaml"
	expect "更新后防护仍然生效" test "$(http_code "$name" /.env)" = 403
	in_box "$name" "echo '# 被篡改' >>/root/rel/latest/download/protect.sh"
	expect "篡改过的新版本被拒绝" in_box "$name" "protect --update -y 2>&1 | grep -q 校验不通过"
	expect "被拒绝后版本没变" in_box "$name" "protect --version | grep -qx 'protect $NEXT'"
}

# 攻击者可以在 URL 路径里编码换行和制表符（%0A、%09），想在管理员放行时顺带写进一条
# "全站关闭 .env 规则"的例外。--allow-block 必须拒绝，例外列表保持为空
crafted_path_rejected() {
	local name=$1 id
	in_box "$name" "curl -s -o /dev/null 'http://127.0.0.1/a%0A*%09crowdsecurity%2Fvpatch-env-access%0A/.env'"
	sleep 2
	id=$(in_box "$name" "cscli alerts list -o raw | awk -F, 'NR == 2 { print \$1 }'")
	# 要看到具体的拒绝原因，而不只是命令失败：别的错误也会让它失败
	expect "构造的路径被识别并拒绝" in_box "$name" "bash /root/protect.sh --allow-block $id 2>&1 | grep -q 控制字符"
	expect "例外列表没有被写入" in_box "$name" "! grep -q . /etc/crowdsec/protect-exceptions.list"
	expect "其他路径的 .env 仍然被拦" test "$(http_code "$name" /b/.env)" = 403
}

# 严格模式（OWASP CRS）下，一句普通的话会被误拦。用 --allow-block 只在那个路径放行，
# 确认其他路径和真实攻击仍然被拦
strict_false_positive() {
	local name=strict benign="/search?q=zsh%20is%20the%20best%21" id
	echo "== debian12 严格模式 + 误报处理"
	start "$name" debian12
	expect "安装成功" install_protect "$name" --strict
	command_works "$name"
	status_works "$name"
	expect "普通句子被 CRS 误拦（403）" test "$(http_code "$name" "$benign")" = 403
	sleep 2
	id=$(in_box "$name" "cscli alerts list -o raw | awk -F, 'NR == 2 { print \$1 }'")
	expect "--blocks 列出了这次拦截" in_box "$name" "bash /root/protect.sh --blocks | grep -q 'zsh%20is'"
	expect "--allow-block 成功" in_box "$name" "bash /root/protect.sh --allow-block $id"
	sleep 6
	expect "放行后 /search 不再拦这句话" test "$(http_code "$name" "$benign")" != 403
	expect "其他路径仍然拦这句话" test "$(http_code "$name" "/other?q=zsh%20is%20the%20best%21")" = 403
	expect "/search 上的 XSS 仍然被拦" test "$(http_code "$name" "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")" = 403
	expect "--exceptions 列出 /search" in_box "$name" "bash /root/protect.sh --exceptions | grep -q '\[1\] /search'"
	expect "--remove-exception 撤销成功" in_box "$name" "bash /root/protect.sh --remove-exception 1 -y"
	sleep 6
	expect "撤销后恢复拦截" test "$(http_code "$name" "$benign")" = 403
	expect "撤销后例外列表为空" in_box "$name" "bash /root/protect.sh --exceptions | grep -q '没有放行例外'"
	sleep 2
	id=$(in_box "$name" "cscli alerts list -o raw | awk -F, 'NR == 2 { print \$1 }'")
	in_box "$name" "bash /root/protect.sh --allow-block $id" >/dev/null 2>&1
	expect "--reset-exceptions 成功" in_box "$name" "bash /root/protect.sh --reset-exceptions -y"
	sleep 6
	expect "清除例外后恢复拦截" test "$(http_code "$name" "$benign")" = 403
	fp_and_report_works "$name"
	notify_works "$name"
	update_works "$name"
	uninstall_checks "$name"
}

basic_mode() {
	local name=$1 log=$2
	echo "== $name（应为基础模式）"
	start "$name"
	expect "安装成功" install_protect "$name"
	expect "选择了基础模式" grep -q "防护级别：基础" "$LOGS/$name.install.log"
	expect "检查结果显示正在监控日志" grep -q "\[正常\] 正在监控" "$LOGS/$name.install.log"
	command_works "$name"
	status_works "$name"
	expect "正常页面不受影响（200）" test "$(http_code "$name" /)" = 200
	simulate_scan "$name" "$log"
	expect "防火墙组件在运行" in_box "$name" "systemctl is-active --quiet crowdsec-firewall-bouncer"
	expect "扫描者被封禁" banned "$name"
	expect "扫描者进了防火墙黑名单" in_firewall "$name"
	expect "管理员 IP 在白名单里" in_box "$name" "cscli allowlists inspect protect-admin | grep -q $ADMIN"
	uninstall_checks "$name"
}

only=${1:-}
want() { [ -z "$only" ] || [ "$only" = "$1" ]; }

want debian12 && { build debian12 Dockerfile.debian debian:12 && full_mode debian12 file broken-repo; }
want ubuntu2404 && { build ubuntu2404 Dockerfile.debian ubuntu:24.04 && full_mode ubuntu2404 piped; }
want strict && { build debian12 Dockerfile.debian debian:12 && strict_false_positive; }
want rocky9 && { build rocky9 Dockerfile.rocky && basic_mode rocky9 /var/log/nginx/access.log; }
want anolis && { build anolis Dockerfile.anolis && basic_mode anolis /var/log/nginx/access.log; }
want baota && { build debian12 Dockerfile.debian debian:12 && build baota Dockerfile.baota && basic_mode baota /www/wwwlogs/default.log; }

for c in pt-debian12 pt-ubuntu2404 pt-strict pt-rocky9 pt-anolis pt-baota; do docker rm -f "$c" >/dev/null 2>&1 || true; done

echo
echo "安装和卸载日志：$LOGS"
if [ "$failures" -eq 0 ]; then
	echo "全部通过"
else
	echo "$failures 项失败"
	exit 1
fi

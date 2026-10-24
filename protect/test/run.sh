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
}

in_box() { docker exec "pt-$1" bash -c "$2"; }

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
	docker exec -e SSH_CONNECTION="$ADMIN 51000 10.0.0.2 22" "pt-$name" \
		bash /root/protect.sh -y "$@" >"$LOGS/$name.install.log" 2>&1
}

uninstall_checks() {
	local name=$1
	in_box "$name" "bash /root/protect.sh --uninstall -y" >"$LOGS/$name.uninstall.log" 2>&1
	expect "卸载后 CrowdSec 已移除" in_box "$name" "! command -v cscli"
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

full_mode() {
	local name=$1
	echo "== $name（应为完整模式）"
	start "$name"
	expect "安装成功" install_protect "$name"
	expect "选择了完整模式" grep -q "防护级别：完整" "$LOGS/$name.install.log"
	expect "自检：/.env 被拦截" grep -q "被拦截（403）" "$LOGS/$name.install.log"
	expect "正常页面不受影响（200）" test "$(http_code "$name" /)" = 200
	expect "管理员 IP 在白名单里" in_box "$name" "cscli allowlists inspect protect-admin | grep -q $ADMIN"
	expect "防火墙组件在运行" in_box "$name" "systemctl is-active --quiet crowdsec-firewall-bouncer"
	crafted_path_rejected "$name"
	uninstall_checks "$name"
}

# 攻击者可以在 URL 路径里编码换行和制表符（%0A、%09），想在管理员放行时顺带写进一条
# "全站关闭 .env 规则"的例外。--allow-block 必须拒绝，例外列表保持为空
crafted_path_rejected() {
	local name=$1 id
	in_box "$name" "curl -s -o /dev/null 'http://127.0.0.1/a%0A*%09crowdsecurity%2Fvpatch-env-access%0A/.env'"
	sleep 2
	id=$(in_box "$name" "cscli alerts list -o raw | awk -F, 'NR == 2 { print \$1 }'")
	expect "构造的路径不能放行" in_box "$name" "! bash /root/protect.sh --allow-block $id"
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
	uninstall_checks "$name"
}

basic_mode() {
	local name=$1 log=$2
	echo "== $name（应为基础模式）"
	start "$name"
	expect "安装成功" install_protect "$name"
	expect "选择了基础模式" grep -q "防护级别：基础" "$LOGS/$name.install.log"
	expect "检查结果显示正在监控日志" grep -q "\[正常\] 正在监控" "$LOGS/$name.install.log"
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

want debian12 && { build debian12 Dockerfile.debian debian:12 && full_mode debian12; }
want ubuntu2404 && { build ubuntu2404 Dockerfile.debian ubuntu:24.04 && full_mode ubuntu2404; }
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

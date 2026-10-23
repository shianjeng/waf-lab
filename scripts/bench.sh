#!/usr/bin/env bash
# 用 GoTestWAF 对每个在线的 WAF 跑完整测试（每个目标约 800 个请求，包括一组
# 正常请求，用来测误报）。报告写到 reports/<名字>/report.json 和 report.html。
#
# 测试容器只接入 waflab-test 网络。这个网络没有外网出口，请求只能到达实验室
# 里的容器。
#
#   scripts/bench.sh              # 测所有在线的目标
#   scripts/bench.sh coraza       # 只测一个
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=wallarm/gotestwaf:0.5.8
NETWORK=waflab-test

if [ "$(docker network inspect -f '{{.Internal}}' "$NETWORK" 2>/dev/null)" != true ]; then
	echo "$NETWORK 网络不存在或者可以访问外网，不运行测试。先运行 ./waflab run" >&2
	exit 1
fi

# 名字  waflab-test 网络内地址  宿主机端口（用来判断是否在线）
TARGETS=(
	"none      http://backend:80          9000"
	"coraza    http://coraza:8080         9001"
	"crowdsec  http://crowdsec-caddy:8080 9002"
	"bunkerweb http://bunkerweb:8080      9003"
	"safeline  http://safeline:8004       9004"
)

only="${1:-}"
for t in "${TARGETS[@]}"; do
	read -r name url port <<<"$t"
	[ -n "$only" ] && [ "$only" != "$name" ] && continue
	if ! curl -s -o /dev/null -m 3 "http://localhost:$port/"; then
		echo "跳过 $name：localhost:$port 不在线"
		[ "$name" = safeline ] && echo "  雷池需要先 ./waflab safeline，再在控制台里添加站点（见 README）"
		continue
	fi

	extra=()
	# 对照组没有 WAF，跳过"先确认有 WAF 在拦截"这一步
	[ "$name" = none ] && extra+=(--skipWAFBlockCheck)

	echo "==> $name ($url)"
	rm -rf "reports/$name"
	mkdir -p "reports/$name"
	docker run --rm --network "$NETWORK" \
		-v "$PWD/reports/$name:/app/reports" \
		"$IMAGE" \
		--url "$url" \
		--wafName "$name" \
		--noEmailReport \
		--skipWAFIdentification \
		--reportFormat json,html \
		--reportPath /app/reports \
		--reportName report \
		--workers 10 \
		--sendDelay 10 \
		--randomDelay 10 \
		--quiet \
		${extra[@]+"${extra[@]}"}
done

echo
python3 scripts/summarize.py

#!/usr/bin/env bash
# 测试用：在测试机的 127.0.0.1:8099 模拟钉钉群机器人。先读完整个请求、追加到
# /root/received.txt，再回复 {"errcode":0}，这样 protect 收到回复时消息一定已经记下了。
# socat 一直在监听，每个连接交给一个子进程处理，连着发两条消息之间不会没人接
if [ "${1:-}" = handle ]; then
	len=0
	while IFS= read -r line; do
		line=${line%$'\r'}
		[ -n "$line" ] || break
		case "${line,,}" in content-length:*) len=${line//[!0-9]/} ;; esac
		printf '%s\n' "$line"
	done >>/root/received.txt
	{
		head -c "$len"
		echo
	} >>/root/received.txt
	printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{"errcode":0}'
	exit
fi
exec socat TCP-LISTEN:8099,bind=127.0.0.1,reuseaddr,fork EXEC:"bash $0 handle"

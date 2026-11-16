"""报告生成：把 DB 里的证据整理成可提交的 Markdown / HTML。"""

from __future__ import annotations

import html
import pathlib
import time
from typing import Dict, List

from .config import Config
from .store import Store
from .util import human_size, ok

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪", "": "⚪"}


def build_markdown(cfg: Config, store: Store, title: str = "") -> str:
    s = store.summary()
    events = store.events(limit=2000)
    findings = [e for e in events if e["kind"] == "finding"]
    backups = store.backups()
    shots = store.shots()
    flags = store.flags()

    L: List[str] = []
    A = L.append
    A(f"# {title or cfg.name + ' 作战报告'}")
    A("")
    A(f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}　"
      f"模式：{'AWD' if cfg.mode == 'awd' else 'CTF'}")
    A("")
    A("## 一、总览")
    A("")
    A("| 指标 | 数值 |")
    A("| --- | --- |")
    A(f"| 涉及靶机 | {len([t for t in cfg.targets if t.enabled])} |")
    A(f"| 发现项 | {s['findings']} |")
    A(f"| FLAG 收集 | {s['flags']}（已提交 {s['flags_submitted']}） |")
    A(f"| 备份包 | {s['backups']} |")
    A(f"| 取证截图 | {s['shots']} |")
    A("")
    if s["severity"]:
        A("严重度分布：" + "　".join(
            f"{SEV_ICON.get(k, '')}{k}×{v}" for k, v in sorted(s["severity"].items())))
        A("")

    A("## 二、靶机与凭据")
    A("")
    A("| 名称 | 地址 | SSH | Web | 备注 |")
    A("| --- | --- | --- | --- | --- |")
    for t in cfg.targets:
        A(f"| {t.name} | {t.host} | {t.user}@{t.host}:{t.ssh_port} | "
          f"{', '.join(t.web) or '-'} | {t.note or '-'} |")
    A("")

    if findings:
        A("## 三、关键发现")
        A("")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
        for f in sorted(findings, key=lambda x: order.get(x["severity"], 9))[:80]:
            d = f["data"] or {}
            A(f"### {SEV_ICON.get(f['severity'], '')} {f['title']}")
            A("")
            A(f"- 靶机：`{f['target'] or '-'}`")
            if d.get("location"):
                A(f"- 位置：`{d['location']}`")
            if d.get("detail"):
                A(f"- 说明：{d['detail']}")
            if d.get("evidence"):
                A("")
                A("```")
                A(str(d["evidence"])[:1500])
                A("```")
            A("")

    if flags:
        A("## 四、FLAG 与提交")
        A("")
        A("| # | FLAG | 来源靶机 | 提交 | 结果 |")
        A("| --- | --- | --- | --- | --- |")
        for i, f in enumerate(flags, 1):
            flag = f["value"]
            shown = flag if len(flag) <= 60 else flag[:57] + "..."
            A(f"| {i} | `{shown}` | {f['target'] or '-'} | "
              f"{'✅' if f['submitted'] else '⏳'} | {(f['submit_result'] or '')[:60]} |")
        A("")

    if backups:
        A("## 五、备份与回滚")
        A("")
        A("| 时间 | 靶机 | 大小 | 文件 | sha256 |")
        A("| --- | --- | --- | --- | --- |")
        for b in backups[:40]:
            A(f"| {b['ts']} | {b['target']} | {human_size(b['size'])} | "
              f"`{pathlib.Path(b['local_path']).name}` | `{b['sha256'][:16]}…` |")
        A("")

    if shots:
        A("## 六、关键步骤")
        A("")
        for i, r in enumerate(shots, 1):
            A(f"{i}. **{r['step']}**（{r['ts']}）{('　' + r['note']) if r.get('note') else ''}")
        A("")
        A("> 完整图文时间线见 `report/timeline.md`")
        A("")

    A("## 七、待办 / 复盘")
    A("")
    pending = [f for f in flags if not f["submitted"]]
    if pending:
        A(f"- [ ] {len(pending)} 个 flag 尚未提交")
    A("- [ ] 核对备份包可还原（抽一台做一次 restore 演练）")
    A("- [ ] 补齐失分点：时区口径、答案唯一性")
    return "\n".join(L)


def write_report(cfg: Config, store: Store, title: str = "") -> List[pathlib.Path]:
    cfg.ensure_dirs()
    md = build_markdown(cfg, store, title)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    md_path = cfg.report_dir / f"report_{stamp}.md"
    md_path.write_text(md, encoding="utf-8")
    latest = cfg.report_dir / "report.md"
    latest.write_text(md, encoding="utf-8")

    html_path = cfg.report_dir / f"report_{stamp}.html"
    html_path.write_text(_to_html(md, title or cfg.name), encoding="utf-8")
    ok(f"报告: {md_path}")
    return [md_path, latest, html_path]


def _to_html(md: str, title: str) -> str:
    """极简 md->html：够看即可，不引第三方。"""
    import re

    lines = md.splitlines()
    out: List[str] = []
    in_code = False
    table_rows: List[List[str]] = []

    def flush_table() -> None:
        nonlocal table_rows
        if not table_rows:
            return
        parts = ["<table>"]
        for i, cells in enumerate(table_rows):
            tag = "th" if i == 0 else "td"
            parts.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
        parts.append("</table>")
        out.append("\n".join(parts))
        table_rows = []

    for line in lines:
        if line.startswith("```"):
            flush_table()
            out.append("<pre><code>" if not in_code else "</code></pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        if line.lstrip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue
            table_rows.append(cells)
            continue
        flush_table()
        if line.startswith("#"):
            lvl = len(line) - len(line.lstrip("#"))
            lvl = min(lvl, 6)
            out.append(f"<h{lvl}>{_inline(line[lvl:].strip())}</h{lvl}>")
        elif line.strip().startswith("- "):
            out.append(f"<li>{_inline(line.strip()[2:])}</li>")
        elif line.strip().startswith("> "):
            out.append(f"<blockquote>{_inline(line.strip()[2:])}</blockquote>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
    flush_table()
    body = "\n".join(out)
    body = re.sub(r"(<li>.*?</li>\n?)+", lambda m: f"<ul>{m.group(0)}</ul>", body, flags=re.S)
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>{html.escape(title)}</title><style>
body{{font-family:-apple-system,"PingFang SC",sans-serif;max-width:960px;margin:40px auto;padding:0 20px;
line-height:1.7;color:#1a1a1a;background:#fff}}
h1{{border-bottom:3px solid #2b6cb0;padding-bottom:10px}} h2{{margin-top:36px;color:#2b6cb0}}
h3{{margin-top:24px;font-size:16px}}
table{{border-collapse:collapse;width:100%;margin:16px 0;font-size:14px}}
th,td{{border:1px solid #d0d7de;padding:7px 10px;text-align:left}} th{{background:#f6f8fa}}
tr:nth-child(even){{background:#fafbfc}}
pre{{background:#f6f8fa;padding:14px;border-radius:6px;overflow:auto;font-size:13px}}
code{{background:#f0f2f5;padding:2px 5px;border-radius:4px;font-size:13px}}
pre code{{background:none;padding:0}} blockquote{{border-left:4px solid #d0d7de;color:#57606a;margin:0;padding-left:14px}}
</style></head><body>{body}</body></html>"""


def _inline(s: str) -> str:
    import re
    s = html.escape(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", r'<img alt="\1" src="\2" style="max-width:100%">', s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    return s

"""CTF 步骤取证：截图 + 时间线。

比赛提交 writeup 时最痛的是"当时怎么打的忘了"，所以这里把每一步做成
"一句话说明 + 一张图 + 一条命令记录"，最后直接生成可粘贴的 timeline.md。

截图三档降级：
1. playwright 无头浏览器（推荐，可指定 URL 与页面元素）
2. macOS `screencapture`（整屏，需人工把关键界面摆好）
3. 仅记录文字步骤（不中断流程）
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

from .config import Config
from .store import Store
from .util import console, ok, safe_name, warn


@dataclass
class Shot:
    step: str
    path: str = ""
    url: str = ""
    note: str = ""
    ts: str = ""


def _playwright_shot(url: str, out: pathlib.Path, full_page: bool = True,
                     wait: float = 1.2, selector: Optional[str] = None) -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 900},
                                    ignore_https_errors=True)
            page.goto(url, timeout=30000, wait_until="networkidle")
            time.sleep(wait)
            if selector:
                el = page.query_selector(selector)
                if el:
                    el.screenshot(path=str(out))
                    browser.close()
                    return True
            page.screenshot(path=str(out), full_page=full_page)
            browser.close()
            return True
    except Exception as e:  # noqa: BLE001
        warn(f"playwright 截图失败: {e}")
        return False


def _mac_screen(out: pathlib.Path) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        r = subprocess.run(["screencapture", "-x", str(out)], capture_output=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False


def capture(cfg: Config, store: Store, step: str, url: str = "",
            note: str = "", selector: Optional[str] = None,
            full_page: bool = True, screen: bool = False) -> Shot:
    cfg.ensure_dirs()
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = f"{ts}_{safe_name(step)}.png"
    out = cfg.evidence_dir / "shots" / name
    done = False
    if url:
        done = _playwright_shot(url, out, full_page=full_page, selector=selector)
    if not done and (screen or not url):
        done = _mac_screen(out)
        if done:
            note = (note + " [整屏截图]").strip()
    if done and out.exists():
        store.add_shot(step, url=url, path=str(out), note=note)
        ok(f"截图已保存 {out.relative_to(cfg.workdir)}")
    else:
        store.add_shot(step, url=url, path="", note=note)
        warn("未生成图片（装 playwright 可自动截图），已仅记录文字步骤")
    return Shot(step, str(out) if done else "", url, note, ts)


def mark(store: Store, step: str, note: str = "", image: str = "", url: str = "") -> None:
    """登记已有截图（比如微信截的图、Burp 导出的图）。"""
    store.add_shot(step, url=url, path=image, note=note)
    ok(f"已登记步骤: {step}")


def write_timeline(cfg: Config, store: Store, title: str = "") -> pathlib.Path:
    rows = store.shots()
    cfg.ensure_dirs()
    out = cfg.report_dir / "timeline.md"
    lines: List[str] = [f"# {title or '作战时间线'}", ""]
    lines.append(f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    if not rows:
        lines.append("_暂无记录_")
    for i, r in enumerate(rows, 1):
        lines.append(f"## {i}. {r['step']}")
        lines.append("")
        lines.append(f"- 时间：`{r['ts']}`")
        if r.get("url"):
            lines.append(f"- 目标：`{r['url']}`")
        if r.get("note"):
            lines.append(f"- 说明：{r['note']}")
        if r.get("path"):
            p = pathlib.Path(r["path"])
            try:
                rel = p.relative_to(cfg.report_dir)
            except ValueError:
                rel = pathlib.Path("..") / "evidence" / "shots" / p.name
            lines.append(f"- 证据：![{r['step']}]({rel.as_posix()})")
        lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    ok(f"时间线已生成 {out}")
    return out


def check_playwright() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False

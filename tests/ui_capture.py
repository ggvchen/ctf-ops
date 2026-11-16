"""UI 截图检查：起一个真实浏览器，按视口截取各页面，用于视觉回归。

    ./.venv/bin/python tests/ui_capture.py [端口] [视口宽] [视口高]
"""

from __future__ import annotations

import pathlib
import sys
import time

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "evidence" / "ui"

VIEWS = ["overview", "targets", "ssh", "term", "backup", "waf", "scan", "exploit",
         "flag", "logs", "traffic", "shots", "ai", "report"]


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8901
    w = int(sys.argv[2]) if len(sys.argv) > 2 else 1440
    h = int(sys.argv[3]) if len(sys.argv) > 3 else 900
    OUT.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": w, "height": h},
                                device_scale_factor=1)
        page.on("console", lambda m: errors.append(f"console.{m.type}: {m.text}")
                if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
        page.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
        time.sleep(0.6)

        for v in VIEWS:
            page.evaluate(f"location.hash = '#{v}'")
            page.wait_for_timeout(500)
            page.screenshot(path=str(OUT / f"{v}.png"), full_page=(v == "overview"))
            print(f"  captured {v}.png")

        size = page.evaluate("({w: window.innerWidth, h: window.innerHeight, "
                             "dpr: window.devicePixelRatio, "
                             "sidebar: document.querySelector('.sidebar').offsetWidth, "
                             "cards: getComputedStyle(document.querySelector('.cards')).gridTemplateColumns})")
        print(f"  viewport={size['w']}x{size['h']} dpr={size['dpr']} "
              f"sidebar={size['sidebar']}px cols={size['cards']}")
        browser.close()

    if errors:
        print("\n前端错误：")
        for e in errors[:20]:
            print("  -", e)
        return 1
    print("\n无前端错误")
    return 0


if __name__ == "__main__":
    sys.exit(main())

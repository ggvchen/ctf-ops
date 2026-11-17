"""页面交互自测：在真实浏览器里点「保存配置」，验证前端确实写到了配置文件。

    ./.venv/bin/python tests/ui_config_e2e.py

起一个独立服务（临时 workdir + 临时 config.yaml），用 Playwright 走一遍：
靶机页统一填写提交接口与 flagserver → 保存 → 回读 YAML；
AI 页改模型并保存 → 回读 YAML。前端只用 DOM 操作，和真人点击一致。
"""

from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


CONFIG = """\
# 页面交互测试配置
name: "UI 自测"
mode: awd
workdir: __WORKDIR__
targets:
  - name: web-01
    host: 10.16.0.73
    user: root
    role: defense
  - name: app-02
    host: 10.16.0.74
    user: root
    role: defense
ssh:
  user: root
  port: 22
# ---------------- 本地 AI ----------------
ai:
  enabled: true
  base_url: http://127.0.0.1:1234/v1     # 保留这句注释
  model: old-model
  api_key: not-needed
  timeout: 240
  temperature: 0.2
  max_tokens: 1600
submit:
  mode: manual
  url: ""
flag_patterns:
  - 'flag\\{[^}\\r\\n]{1,200}\\}'
"""


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ctfops-ui-"))
    cfg_path = tmp / "config.yaml"
    cfg_path.write_text(CONFIG.replace("__WORKDIR__", str(tmp)), encoding="utf-8")
    port = free_port()

    proc = subprocess.Popen(
        [str(ROOT / ".venv" / "bin" / "python"), "-m", "ctfops.cli",
         "--config", str(cfg_path), "dash", "--port", str(port), "--no-open"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            urllib.request.urlopen(base + "/api/overview", timeout=1).read()
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    else:
        proc.terminate()
        print("服务没起来")
        return 1

    from playwright.sync_api import sync_playwright

    errors: list[str] = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(base + "/", wait_until="networkidle")
            page.wait_for_timeout(600)

            print("\n[1] 靶机页：统一填写两个请求格式")
            page.evaluate("location.hash = '#targets'")
            page.wait_for_timeout(700)
            check("接口配置面板存在", page.locator("#ifSubUrl").count() == 1)
            # 大配置表单默认收起（让清单和主操作留在首屏），填之前先展开
            if page.locator('.panel[data-collapse="iface-config"].collapsed').count():
                page.click('.panel[data-collapse="iface-config"] [data-fold]')
                page.wait_for_timeout(300)
            page.fill("#ifSubUrl", "http://platform.local/api/flag")
            page.select_option("#ifSubMethod", "POST")
            page.fill("#ifSubBody", '{"flag":"{flag}"}')
            page.fill("#ifSubHeaders", '{"Content-Type":"application/json"}')
            page.fill("#ifSubSuccess", "success")
            page.fill("#ifFsUrl", "http://10.10.0.1/get?token={token_url}&host={ip}")
            page.fill("#ifFsField", "data.flag")
            page.fill("#ifFsHeaders", '{"X-Token":"{token}"}')
            page.click("#btnIfaceSave")
            page.wait_for_timeout(1200)

            st, g = api(base, "/api/submit/global")
            c = g.get("config") or {}
            check("提交接口已保存", c.get("url") == "http://platform.local/api/flag",
                  str(c.get("url")))
            check("请求体成了 json_body", c.get("json_body") == {"flag": "{flag}"},
                  str(c.get("json_body")))
            check("来源是页面配置", g.get("source") == "页面配置", str(g.get("source")))

            st, f = api(base, "/api/flagserver")
            fc = f.get("conf") or {}
            check("flagserver 地址已保存",
                  fc.get("url", "").endswith("host={ip}"), str(fc.get("url")))
            check("响应字段已保存", fc.get("field") == "data.flag", str(fc.get("field")))
            check("请求头已保存", fc.get("headers") == {"X-Token": "{token}"},
                  str(fc.get("headers")))

            print("\n[2] 逐机 token（表格里直接改）")
            page.fill('#targetTable input[data-token]', "tok-xyz")
            page.keyboard.press("Enter")
            page.wait_for_timeout(800)
            st, f2 = api(base, "/api/flagserver")
            toks = (f2.get("conf") or {}).get("tokens") or {}
            check("token 落到该靶机", list(toks.values()) == ["tok-xyz"], str(toks))

            print("\n[3] AI 页：拉模型列表 → 下拉选择 → 保存")
            page.evaluate("location.hash = '#ai'")
            page.wait_for_timeout(900)
            check("端点预设按钮渲染", page.locator("#aiPresets .chip-btn").count() >= 3,
                  str(page.locator("#aiPresets .chip-btn").count()))
            check("表单带出当前端点",
                  "1234" in (page.input_value("#aiBaseUrl") or ""), page.input_value("#aiBaseUrl"))

            # 拦掉真实端点，用固定清单验下拉（不然有没有装 LM Studio 都会影响结果）
            page.route("**/api/ai/models*", lambda route: route.fulfill(
                status=200, content_type="application/json",
                body=json.dumps({"ok": True, "models": ["mock-a", "mock-b"],
                                 "elapsed": 3, "error": "", "current": ""})))
            page.click("#btnAiModels")
            page.wait_for_timeout(700)
            opts = page.locator("#aiModelSel option").all_inner_texts()
            check("下拉里出现远端模型", any("mock-a" in o for o in opts)
                  and any("mock-b" in o for o in opts), str(opts))
            page.select_option("#aiModelSel", "mock-b")
            page.wait_for_timeout(200)
            check("选中的值同步到模型字段", page.input_value("#aiModel") == "mock-b",
                  page.input_value("#aiModel"))
            check("下拉是真 select（可点开选择）",
                  page.locator("#aiModelSel").evaluate("el => el.tagName") == "SELECT")

            page.click("#btnAiModelHand")          # 手填：清单里没有的模型名
            page.wait_for_timeout(200)
            check("手填框展开", page.locator("#aiModel").is_visible())
            page.fill("#aiModel", "ui-test-model")
            page.fill("#aiMaxTokens", "2048")
            page.click("#btnAiSave")
            page.wait_for_timeout(1200)
            text = cfg_path.read_text(encoding="utf-8")
            check("YAML 里模型已改", "model: ui-test-model" in text,
                  [l for l in text.splitlines() if "model:" in l])
            check("max_tokens 已改", "max_tokens: 2048" in text)
            check("行尾注释还在", "# 保留这句注释" in text)
            check("其它段没被删", "flag_patterns:" in text and "submit:" in text)
            page.unroute("**/api/ai/models*")

            print("\n[4] 非法 JSON 要被前端挡住")
            page.evaluate("location.hash = '#targets'")
            page.wait_for_timeout(700)
            page.fill("#ifFsHeaders", "{不是 json")
            page.click("#btnIfaceSave")
            page.wait_for_timeout(700)
            toast = page.locator("#toasts .toast").last.inner_text()
            check("提示请求头不是合法 JSON", "JSON" in toast, toast)
            before = cfg_path.read_text(encoding="utf-8")
            check("非法输入没有写坏配置", "http://10.10.0.1/get" in before or "model: ui-test-model" in before)

            print("\n[5] flag 页显示配置摘要")
            page.evaluate("location.hash = '#flag'")
            page.wait_for_timeout(900)
            meta = page.locator("#fsMeta").inner_text()
            check("显示地址", "10.10.0.1" in meta, meta[:160])
            check("状态不是未配置", page.locator("#fsPill").inner_text() != "未配置",
                  page.locator("#fsPill").inner_text())

            print("\n[6] 顶栏便签可点击")
            page.evaluate("location.hash = '#overview'")
            page.wait_for_timeout(800)
            chips = page.locator("#statusChips .stat-chip")
            check("便签渲染成按钮", chips.count() >= 4, str(chips.count()))
            page.click('#statusChips [data-nav="targets"]')
            page.wait_for_timeout(500)
            check("靶机便签 → 靶机页", page.evaluate("location.hash") == "#targets",
                  page.evaluate("location.hash"))
            page.click('#statusChips [data-nav="scan"]')
            page.wait_for_timeout(500)
            check("高危便签 → 扫描页", page.evaluate("location.hash") == "#scan",
                  page.evaluate("location.hash"))
            check("顺带把级别过滤设成高危以上",
                  page.input_value("#sevFilter") == "critical,high",
                  page.input_value("#sevFilter"))
            page.click('#statusChips [data-nav="flag"]')
            page.wait_for_timeout(500)
            check("FLAG 便签 → FLAG 页", page.evaluate("location.hash") == "#flag",
                  page.evaluate("location.hash"))
            page.evaluate("location.hash = '#overview'")
            page.wait_for_timeout(600)
            page.click('#statusChips [data-nav="jobs"]')
            page.wait_for_timeout(400)
            toast = page.locator("#toasts .toast").last.inner_text()
            check("空闲便签给出提示而不是空白", "任务" in toast, toast)

            print("\n[7] 配置面板可折叠，刷新后记得住")
            ai_panel = '.panel[data-collapse="ai-config"]'
            page.evaluate("location.hash = '#ai'")
            page.wait_for_timeout(600)
            check("折叠前内容可见", page.locator(ai_panel + " .panel-body").is_visible())
            page.click(ai_panel + " [data-fold]")
            page.wait_for_timeout(300)
            check("折叠后内容隐藏",
                  not page.locator(ai_panel + " .panel-body").is_visible())
            check("折叠状态写成 class",
                  page.locator(ai_panel).evaluate("el => el.classList.contains('collapsed')"))
            page.reload(wait_until="networkidle")
            page.wait_for_timeout(900)
            page.evaluate("location.hash = '#ai'")
            page.wait_for_timeout(700)
            check("刷新后仍保持折叠",
                  page.locator(ai_panel).evaluate("el => el.classList.contains('collapsed')"))
            page.click(ai_panel + " [data-fold]")
            page.wait_for_timeout(300)
            check("再点一下能展开", page.locator(ai_panel + " .panel-body").is_visible())
            iface_panel = '.panel[data-collapse="iface-config"]'
            page.evaluate("location.hash = '#targets'")
            page.wait_for_timeout(700)
            check("靶机页接口配置也能折叠",
                  page.locator(iface_panel + " [data-fold]").count() == 1)
            # 上面 [1] 展开过，localStorage 里已记成"展开"；清掉再刷新才看得到默认值
            page.evaluate("localStorage.removeItem('ctfops.fold.iface-config')")
            page.reload(wait_until="networkidle")
            page.wait_for_timeout(600)
            page.evaluate("location.hash = '#targets'")
            page.wait_for_timeout(700)
            check("接口配置默认收起", page.locator(iface_panel + ".collapsed").count() == 1)
            page.click(iface_panel + " [data-fold]")
            page.wait_for_timeout(300)
            check("点一下能展开", page.locator(iface_panel + " .panel-body").is_visible())
            page.click(iface_panel + " [data-fold]")
            page.wait_for_timeout(300)
            check("再点一下收起",
                  not page.locator(iface_panel + " .panel-body").is_visible())

            print("\n[8] 发现汇总：分页工具条")
            page.evaluate("location.hash = '#scan'")
            page.wait_for_timeout(900)
            check("工具条存在", page.locator("#fdBar").is_visible())
            bar = page.locator("#fdBar").inner_text()
            check("显示总数与页码", "共" in bar and "页" in bar, bar.replace("\n", " | "))
            check("没有数据时上一页禁用",
                  page.locator('#fdBar [data-page="prev"]').is_disabled())
            check("没有勾选时删除按钮禁用", page.locator("#fdDelSel").is_disabled())
            check("有每页条数下拉", page.locator("#fdLimit").count() == 1)

            print("\n[9] 拖拽文件到日志/流量路径框")
            page.evaluate("location.hash = '#logs'")
            page.wait_for_timeout(600)
            # 合成一次 drop：Chromium 里可以用 DataTransfer 造 File 列表，
            # 走的就是和真人拖拽同一条 JS 路径（webkitGetAsEntry 为空则回落 files）
            page.evaluate("""() => {
              const dt = new DataTransfer();
              dt.items.add(new File(['Jan 11 10:00:01 host sshd[1]: Failed password for root from 45.13.22.101'],
                                    'dropped-auth.log', { type: 'text/plain' }));
              window.__dt = dt;
              const el = document.querySelector('#lgPaths');
              el.dispatchEvent(new DragEvent('dragenter', { bubbles: true, dataTransfer: dt }));
            }""")
            page.wait_for_timeout(150)
            check("拖入时输入框高亮",
                  page.locator("#lgPaths").evaluate("el => el.className.includes('drop-hover')"),
                  page.locator("#lgPaths").get_attribute("class"))
            page.evaluate("""() => {
              const el = document.querySelector('#lgPaths');
              el.dispatchEvent(new DragEvent('drop', { bubbles: true, dataTransfer: window.__dt }));
            }""")
            page.wait_for_timeout(1500)
            val = page.input_value("#lgPaths")
            check("拖入后路径已填好", "evidence/uploads/" in val, val)
            check("填的是绝对路径", val.startswith("/") or val.startswith("evidence/"), val)
            up = list((tmp / "evidence" / "uploads").rglob("dropped-auth.log"))
            check("文件已落到 evidence/uploads", len(up) == 1, str(up))
            if up:
                check("内容完整", "45.13.22.101" in up[0].read_text(encoding="utf-8"))

            # 填好的路径要真能跑分析（拖进来 ≠ 只是填个字符串）
            stj, jj = post_json(base + "/api/logs/analyze", {"paths": [val], "ai": False})
            job = wait_job(base, (jj.get("job") or {}).get("id", ""), timeout=60)
            check("拖入的日志能直接被分析", job.get("status") == "done",
                  str(job.get("status")) + " " + str(job.get("error"))[:120])

            # 流量框只收一个文件
            page.evaluate("location.hash = '#traffic'")
            page.wait_for_timeout(600)
            page.evaluate("""() => {
              const dt = new DataTransfer();
              dt.items.add(new File(['pcap'], 'cap1.pcap', { type: 'application/vnd.tcpdump.pcap' }));
              dt.items.add(new File(['pcap'], 'cap2.pcap', { type: 'application/vnd.tcpdump.pcap' }));
              const el = document.querySelector('#tpPath');
              el.dispatchEvent(new DragEvent('drop', { bubbles: true, dataTransfer: dt }));
            }""")
            page.wait_for_timeout(1800)
            tp = page.input_value("#tpPath")
            check("流量框只填一个文件", "cap1.pcap" in tp and "cap2.pcap" not in tp, tp)

            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if errors:
        print("\n页面 JS 错误：")
        for e in errors[:10]:
            print("  -", e)
        FAIL.append("pageerror")

    print("\n" + "=" * 40)
    print(f"通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
    return 1 if FAIL else 0


def wait_job(base: str, job_id: str, timeout: float = 60) -> dict:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            _, d = api(base, f"/api/jobs/{job_id}")
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
            continue
        job = d.get("job") or d
        if job.get("status") in ("done", "failed"):
            return job
        time.sleep(0.3)
    return {"status": "timeout"}


def post_json(url: str, payload: dict):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def api(base: str, path: str):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return r.status, json.loads(r.read() or b"{}")


if __name__ == "__main__":
    sys.exit(main())

"""PHP 版 WAF（watchbird）端到端自测。

    ./.venv/bin/python tests/waf_php_e2e.py

两段：
1) 直接跑 watchbird.php（php -S + auto_prepend_file），验证识别/放行/拦截/自检
2) 通过 mock sshd 走真实部署链路（SFTP 上传 + .user.ini + php -l + 状态/加固/停止）

本机没有 php 时自动跳过（打印 SKIP 并返回 0）。
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from ctfops.waf import (AGENT_PHP, DEFAULT_RULES, PHP_CFG_PATH, PHP_AGENT_PATH,  # noqa: E402
                        WAF_HOME)

PASS, FAIL = 0, []
PHP = shutil.which("php") or os.environ.get("PHP_BIN") or ""


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def setup_waf_home(mode: str = "monitor", block_all: bool = False) -> None:
    home = pathlib.Path(WAF_HOME)
    home.mkdir(parents=True, exist_ok=True)
    (home / "watchbird.php").write_text(AGENT_PHP, encoding="utf-8")
    rules = [dict(r) for r in DEFAULT_RULES]
    if block_all:
        for r in rules:
            r["action"] = "block"
    (home / "watchbird.json").write_text(json.dumps(
        {"mode": mode, "started": int(time.time()), "webroot": "/tmp/x", "rules": rules},
        ensure_ascii=False), encoding="utf-8")
    (home / "audit.jsonl").unlink(missing_ok=True)
    (home / "php_status.json").unlink(missing_ok=True)


def http_get(url: str, ua: str = "Mozilla/5.0") -> "tuple[int, str]":
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=6) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def audits() -> "list[dict]":
    p = pathlib.Path(WAF_HOME) / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def part1_standalone() -> None:
    print("\n[1] watchbird.php 独立运行（php -S）")
    setup_waf_home("monitor")
    webroot = pathlib.Path(tempfile.mkdtemp(prefix="phpweb_"))
    (webroot / "index.php").write_text("<?php echo 'hello-page';", encoding="utf-8")
    port = free_port()
    proc = subprocess.Popen(
        [PHP, "-S", f"127.0.0.1:{port}", "-t", str(webroot),
         "-d", f"auto_prepend_file={PHP_AGENT_PATH}",
         "-d", "display_errors=0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    base = f"http://127.0.0.1:{port}"

    try:
        st, body = http_get(base + "/")
        check("正常页面 200 且内容不变", st == 200 and "hello-page" in body, f"{st} {body[:40]}")
        check("正常请求不产生审计", not audits(), str(audits()[:1]))

        st, body = http_get(base + "/?id=1%20union%20select%201,2,3")
        check("SQL 注入被识别", st == 200 and any(a["rule_id"] == "sqli" for a in audits()),
              str([a["rule_id"] for a in audits()]))
        check("monitor 模式仍放行", st == 200 and "hello-page" in body)

        http_get(base + "/", ua="sqlmap/1.7")
        check("扫描器 UA 被识别", any(a["rule_id"] == "scanner" for a in audits()),
              str([a["rule_id"] for a in audits()]))

        st, body = http_get(base + "/?__wb_probe=1")
        check("自检探针可用", st == 200 and "WB_OK" in body, body[:40])

        rec = audits()[-1]
        check("审计含 engine=php", rec.get("engine") == "php", str(rec)[:120])
        check("审计含来源 IP", rec.get("ip") == "127.0.0.1", rec.get("ip"))

        # 切加固
        setup_waf_home("enforce", block_all=True)
        st, body = http_get(base + "/?id=1%20union%20select%201,2,3")
        check("enforce 模式拦截 403", st == 403, f"{st} {body[:40]}")
        check("拦截响应有标记", "blocked by watchbird" in body, body[:60])
        st, body = http_get(base + "/")
        check("加固后正常请求仍放行", st == 200 and "hello-page" in body, f"{st}")

        status = json.loads((pathlib.Path(WAF_HOME) / "php_status.json").read_text())
        check("状态文件累计命中", status.get("matched", 0) >= 2, str(status))
        check("状态记录拦截数", status.get("blocked", 0) >= 1, str(status))
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def part2_via_ssh() -> None:
    print("\n[2] 经 mock sshd 真实部署链路")
    import term_e2e as mock
    from ctfops.waf import deploy, enforce, status, stop

    stop_evt = threading.Event()
    threading.Thread(target=mock.serve_once, args=(stop_evt,), daemon=True).start()
    time.sleep(0.8)

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="phpdeploy_"))
    cfg = mock.build_cfg(workdir, count=1)
    target = cfg.targets[0]

    webroot = pathlib.Path(tempfile.mkdtemp(prefix="web_"))
    (webroot / "index.php").write_text("<?php echo 'site';", encoding="utf-8")
    target.webroot = str(webroot)

    shutil.rmtree(WAF_HOME, ignore_errors=True)

    r = deploy(cfg, target, mode="monitor", engine="php")
    check("部署成功", r.get("ok"), str(r)[:200])
    check("选了 PHP 引擎", r.get("engine") == "php", str(r.get("engine")))
    check("探测到 php", (r.get("stack") or {}).get("php") is True, str(r.get("stack"))[:150])
    ini = webroot / ".user.ini"
    check("写入 .user.ini", ini.exists() and "auto_prepend_file" in ini.read_text(),
          ini.read_text() if ini.exists() else "missing")
    check("watchbird.php 已上传", pathlib.Path(PHP_AGENT_PATH).exists())

    st = status(cfg, target)
    check("状态可读且 running", st.running is True and st.engine == "php", str(st)[:150])

    # 已有的 .user.ini 内容要保留
    ini.write_text("memory_limit=256M\n", encoding="utf-8")
    deploy(cfg, target, mode="monitor", engine="php")
    content = ini.read_text()
    check("保留原有 .user.ini 内容", "memory_limit=256M" in content, content)
    check("追加了 auto_prepend", "auto_prepend_file" in content)

    e = enforce(cfg, target)
    check("加固成功", e.get("ok") and e.get("mode") == "enforce", str(e)[:150])
    conf = json.loads(pathlib.Path(PHP_CFG_PATH).read_text())
    check("watchbird.json 切到 enforce", conf.get("mode") == "enforce", conf.get("mode"))
    check("规则标记为 block",
          all(r.get("action") == "block" for r in conf.get("rules", []) if r.get("id") in
              {"sqli", "traversal"}))

    s = stop(cfg, target)
    check("停止成功", s.get("ok") is True)
    left = ini.read_text() if ini.exists() else ""
    check("摘掉了 auto_prepend", "auto_prepend_file" not in left, left)
    check("原有内容仍在", "memory_limit=256M" in left, left)

    stop_evt.set()


def main() -> int:
    if not PHP:
        print("SKIP: 本机没有 php（可用 PHP_BIN=/path/to/php 指定），跳过 PHP agent 测试")
        return 0
    print(f"使用 {PHP}")
    lint = subprocess.run([PHP, "-l", PHP_AGENT_PATH if pathlib.Path(PHP_AGENT_PATH).exists()
                           else str(ROOT / "ctfops" / "agents" / "watchbird.php")],
                          capture_output=True)
    check("watchbird.php 语法正确", lint.returncode == 0,
          (lint.stdout + lint.stderr).decode()[:200])

    part1_standalone()
    part2_via_ssh()

    print(f"\n{'=' * 40}\n通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

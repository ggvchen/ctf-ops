"""WAF agent 端到端自测：本机跑真实 agent 进程，喂日志，验证"只监听→加固"。

    ./.venv/bin/python tests/waf_e2e.py

不依赖靶机：agent 是独立 python3 脚本，日志用本地文件模拟访问日志，
封禁命令用 `echo` 代替 iptables（--ban-cmd 可配就是这个目的）。
"""

from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctfops.waf import AGENT_SRC, DEFAULT_RULES  # noqa: E402

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


def line(ip: str, path: str, ua: str = "Mozilla/5.0", status: int = 200) -> str:
    return (f'{ip} - - [16/Nov/2026:13:20:00 +0800] "GET {path} HTTP/1.1" '
            f'{status} 1234 "-" "{ua}"\n')


def main() -> int:
    home = pathlib.Path(tempfile.mkdtemp(prefix="waf_"))
    log = home / "access.log"
    log.write_text(line("9.9.9.9", "/"), encoding="utf-8")
    (home / "agent.py").write_text(AGENT_SRC, encoding="utf-8")
    (home / "rules.json").write_text(json.dumps(DEFAULT_RULES, ensure_ascii=False),
                                    encoding="utf-8")
    bans = home / "bans.out"
    conf = {
        "mode": "monitor", "autoban": False, "logs": [str(log)],
        "ban_cmd": f"echo {{ip}} >> {bans}",
    }
    (home / "config.json").write_text(json.dumps(conf), encoding="utf-8")

    py = sys.executable
    proc = subprocess.Popen([py, str(home / "agent.py"), "--home", str(home)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1.2)

    print("\n[1] 只监听模式：识别但不阻断")
    st = json.loads((home / "status.json").read_text())
    check("agent 已启动", st.get("running") is True, str(st)[:120])
    check("默认 monitor 模式", st.get("mode") == "monitor", st.get("mode"))

    with open(log, "a", encoding="utf-8") as f:
        f.write(line("1.2.3.4", "/?id=1%20union%20select%201,2,3", "Mozilla/5.0"))
        f.write(line("1.2.3.4", "/../../etc/passwd", "curl/8.0"))
        f.write(line("7.7.7.7", "/", "sqlmap/1.7"))
        f.write(line("5.5.5.5", "/index.php", "Mozilla/5.0"))
    time.sleep(1.6)

    audits = [json.loads(x) for x in
              (home / "audit.jsonl").read_text().strip().splitlines() if x.strip()]
    rules_hit = {a["rule_id"] for a in audits}
    check("SQL 注入被记录", "sqli" in rules_hit, str(rules_hit))
    check("路径穿越被记录", "traversal" in rules_hit, str(rules_hit))
    check("扫描器 UA 被记录", "scanner" in rules_hit, str(rules_hit))
    check("正常请求不误报", all(a["path"] != "/index.php" for a in audits))
    # 规则不能宽到把 CMS 正常动态 URL 拦掉（曾用 ".php?x=" 导致整站 403）
    import re as _re
    _rules = {r["id"]: _re.compile(r["pattern"]) for r in DEFAULT_RULES}
    _benign = ["/index.php?m=home&c=Lists&a=index&tid=2&sort=new&sort_asc=asc",
               "/index.php?m=home&c=View&a=index&aid=89",
               "/uploads/2024/0617/demo.jpg", "/login.php"]
    for _u in _benign:
        _hit = [k for k, v in _rules.items() if v.search(_u)]
        check(f"正常 URL 不命中规则 {_u[:36]}", not _hit, str(_hit))
    for _bad, _want in ((("/index.php?id=1&x=1,(SELECT 1 FROM (SELECT(SLEEP(2)))x)-- -"), "sqli"),
                        ("/uploads/shell.php", "webshell"),
                        ("/index.php?f=../../etc/passwd", "traversal")):
        check(f"攻击 URL 命中 {_want}", bool(_rules[_want].search(_bad)), _bad[:40])
    check("monitor 模式不写封禁", not bans.exists() or not bans.read_text().strip())
    check("action 标为 monitor", all(a["action"] == "monitor" for a in audits))

    st = json.loads((home / "status.json").read_text())
    check("状态累计命中", st.get("matched", 0) >= 3, str(st.get("matched")))

    print("\n[2] 加固模式：命中即封禁（SIGHUP 热加载）")
    conf.update({"mode": "enforce", "autoban": True})
    (home / "config.json").write_text(json.dumps(conf), encoding="utf-8")
    rules = json.loads((home / "rules.json").read_text())
    for r in rules:
        r["action"] = "block"
    (home / "rules.json").write_text(json.dumps(rules, ensure_ascii=False), encoding="utf-8")
    proc.send_signal(signal.SIGHUP)
    time.sleep(1.2)

    st = json.loads((home / "status.json").read_text())
    check("模式已切到 enforce", st.get("mode") == "enforce", st.get("mode"))

    with open(log, "a", encoding="utf-8") as f:
        f.write(line("6.6.6.6", "/?id=1%20and%20sleep(5)", "sqlmap/1.8"))
    time.sleep(1.6)

    st = json.loads((home / "status.json").read_text())
    check("封禁计数 +1", st.get("banned", 0) >= 1, str(st.get("banned")))
    banned_ips = bans.read_text().split() if bans.exists() else []
    check("封禁执行到了目标 IP", "6.6.6.6" in banned_ips, str(banned_ips))

    audits = [json.loads(x) for x in
              (home / "audit.jsonl").read_text().strip().splitlines() if x.strip()]
    last = [a for a in audits if a["ip"] == "6.6.6.6"]
    check("封禁记录 action=block", bool(last) and last[-1]["action"] == "block",
          str(last[-1:])[:160])

    print("\n[3] 停止")
    proc.terminate()
    proc.wait(timeout=5)
    check("进程退出", proc.poll() is not None)

    print(f"\n{'=' * 40}\n通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

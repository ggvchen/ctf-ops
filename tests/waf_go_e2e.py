"""Go 版 WAF agent 端到端自测（免运行时的静态二进制）。

    ./.venv/bin/python tests/waf_go_e2e.py

两段：
1) 直接跑本机二进制（darwin/arm64 或 linux 本机架构），验证识别/放行/封禁
2) 经 mock sshd 走真实部署链路（上传二进制 + 启动 + 状态 + 加固 + 停止）

没有对应平台的二进制时会先尝试用 go 现场构建；都没有则 SKIP。
"""

from __future__ import annotations

import json
import os
import pathlib
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from ctfops.waf import DEFAULT_RULES, WAF_HOME, go_binary  # noqa: E402

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


def local_binary() -> str:
    osname = "darwin" if platform.system() == "Darwin" else "linux"
    arch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine(),
                                                                        platform.machine())
    b = go_binary(osname, arch)
    return str(b) if b else ""


def log_line(ip: str, path: str, ua: str = "Mozilla/5.0") -> str:
    return (f'{ip} - - [16/Nov/2026:14:00:00 +0800] "GET {path} HTTP/1.1" '
            f'200 1234 "-" "{ua}"\n')


def load_audit(home: pathlib.Path) -> "list[dict]":
    p = home / "audit.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def part1(binary: str) -> None:
    print("\n[1] 直接运行二进制（日志模式）")
    home = pathlib.Path(tempfile.mkdtemp(prefix="golf_"))
    log = home / "access.log"
    log.write_text(log_line("9.9.9.9", "/"), encoding="utf-8")
    (home / "rules.json").write_text(json.dumps(DEFAULT_RULES, ensure_ascii=False),
                                     encoding="utf-8")
    ban_out = home / "banned.out"
    (home / "config.json").write_text(json.dumps({
        "mode": "monitor", "autoban": False, "logs": [str(log)],
        "ban_cmd": f"echo {{ip}} >> {ban_out}",
    }), encoding="utf-8")

    proc = subprocess.Popen([binary, "--home", str(home)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(1.0)
    st = json.loads((home / "status.json").read_text())
    check("启动并写状态", st.get("running") is True and st.get("engine") == "go", str(st)[:120])
    check("默认 monitor", st.get("mode") == "monitor", st.get("mode"))

    with open(log, "a", encoding="utf-8") as f:
        f.write(log_line("1.2.3.4", "/?id=1%20union%20select%201,2"))
        f.write(log_line("1.2.3.4", "/../../etc/passwd"))
        f.write(log_line("5.5.5.5", "/", "sqlmap/1.7"))
        f.write(log_line("6.6.6.6", "/shell.php?cmd=whoami"))
        f.write(log_line("8.8.8.8", "/index.php"))
    time.sleep(1.6)

    audits = load_audit(home)
    rules_hit = {a["rule_id"] for a in audits}
    check("识别 SQL 注入", "sqli" in rules_hit, str(rules_hit))
    check("识别路径穿越", "traversal" in rules_hit, str(rules_hit))
    check("识别扫描器 UA", "scanner" in rules_hit, str(rules_hit))
    check("识别命令注入", "cmdi" in rules_hit, str(rules_hit))
    check("正常请求不误报", all("/index.php" not in a["path"] for a in audits))
    check("审计标记 engine=go", all(a.get("engine") == "go" for a in audits))
    check("monitor 不封禁", not ban_out.exists() or not ban_out.read_text().strip())

    st = json.loads((home / "status.json").read_text())
    check("计数正确", st.get("requests") == 5 and st.get("matched") == 4,
          f"{st.get('requests')}/{st.get('matched')}")

    # 加固
    conf = json.loads((home / "config.json").read_text())
    conf.update({"mode": "enforce", "autoban": True})
    (home / "config.json").write_text(json.dumps(conf), encoding="utf-8")
    rules = json.loads((home / "rules.json").read_text())
    for r in rules:
        r["action"] = "block"
    (home / "rules.json").write_text(json.dumps(rules, ensure_ascii=False), encoding="utf-8")
    proc.send_signal(signal.SIGHUP)
    time.sleep(0.8)

    with open(log, "a", encoding="utf-8") as f:
        f.write(log_line("7.7.7.7", "/?id=1%20and%20sleep(5)"))
    time.sleep(1.4)

    st = json.loads((home / "status.json").read_text())
    check("SIGHUP 后切到 enforce", st.get("mode") == "enforce", st.get("mode"))
    banned = ban_out.read_text().split() if ban_out.exists() else []
    check("命中即封禁", "7.7.7.7" in banned, str(banned))
    last = [a for a in load_audit(home) if a["ip"] == "7.7.7.7"]
    check("封禁记录 action=block", bool(last) and last[-1]["action"] == "block",
          str(last[-1:])[:120])

    proc.terminate()
    proc.wait(timeout=5)
    check("进程正常退出", proc.poll() is not None)


def part2(binary: str) -> None:
    print("\n[2] 经 mock sshd 真实部署（engine=go）")
    import term_e2e as mock
    from ctfops.waf import deploy, enforce, read_audit, status, stop

    stop_evt = threading.Event()
    threading.Thread(target=mock.serve_once, args=(stop_evt,), daemon=True).start()
    time.sleep(0.8)

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="godeploy_"))
    cfg = mock.build_cfg(workdir, count=1)
    target = cfg.targets[0]

    access = pathlib.Path(tempfile.mkdtemp(prefix="golog_")) / "access.log"
    access.write_text(log_line("9.9.9.9", "/"), encoding="utf-8")

    shutil.rmtree(WAF_HOME, ignore_errors=True)

    r = deploy(cfg, target, logs=[str(access)], mode="monitor", engine="go")
    check("部署成功", r.get("ok"), str(r)[:200])
    check("引擎为 go", r.get("engine") == "go", str(r.get("engine")))
    check("上传了二进制", pathlib.Path(f"{WAF_HOME}/waf-go").exists())

    st = status(cfg, target)
    check("状态可读", st.running and st.engine == "go", str(st)[:150])

    with open(access, "a", encoding="utf-8") as f:
        f.write(log_line("1.1.1.1", "/?id=1%20union%20select%201"))
    time.sleep(1.4)
    rows = read_audit(cfg, target, limit=20)
    check("审计里能看到命中", any(x.get("rule_id") == "sqli" for x in rows),
          str([x.get("rule_id") for x in rows]))

    e = enforce(cfg, target)
    check("加固成功", e.get("ok") and e.get("mode") == "enforce", str(e)[:150])

    s = stop(cfg, target)
    check("停止成功", s.get("ok") is True)
    time.sleep(0.4)
    check("二进制已清理", not pathlib.Path(f"{WAF_HOME}/waf-go").exists())

    stop_evt.set()


def main() -> int:
    binary = local_binary()
    if not binary:
        print("SKIP: 当前平台没有预编译的 Go agent，"
              "先跑 ./scripts/build-agents.sh（需要 go 1.21+）")
        return 0
    print(f"使用二进制 {binary}")
    check("二进制可执行", os.access(binary, os.X_OK))

    part1(binary)
    part2(binary)

    print(f"\n{'=' * 40}\n通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

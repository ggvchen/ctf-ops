"""流量分析自测：用 text2pcap 造一个最小 pcap，跑真实解析链路。

    ./.venv/bin/python tests/traffic_e2e.py

覆盖两件事：
1. HTTP 请求能解析、UA 判定生效；
2. **响应体里的 flag 能扫到，且默认不落盘** —— 之前是导出全部对象再清理，
   一个 19MB 的包导出 4 万多个文件（200MB+），清理时的成批 unlink 会被宿主的
   安全删除守卫打断，任务于是永远停在 running。

需要 tshark / text2pcap / mergecap（同属 Wireshark，缺了自动跳过）。
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from ctfops.config import load_config      # noqa: E402
from ctfops.traffic import analyze_pcap    # noqa: E402
from ctfops.util import which              # noqa: E402

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


FLAG = "flag{pcap_body_scan_0123456789}"
REQ = (b"POST /upload.php HTTP/1.1\r\nHost: victim.local\r\n"
       b"User-Agent: sqlmap/1.7.2\r\nContent-Length: 10\r\n\r\nname=x&a=1")
RESP = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(FLAG) + 3}"
        f"\r\n\r\nok:{FLAG}").encode()


def hexdump(data: bytes, path: pathlib.Path) -> None:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        lines.append("%06x %s" % (i, " ".join("%02x" % b for b in chunk)))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_pcap(tmp: pathlib.Path, out: pathlib.Path) -> bool:
    """两个方向的单包 pcap 再合并 —— 比手搓 TCP 会话稳定得多。"""
    hexdump(REQ, tmp / "req.hex")
    hexdump(RESP, tmp / "resp.hex")
    r1 = subprocess.run(["text2pcap", "-T", "44444,80", "-4", "10.0.0.1,10.0.0.2",
                         str(tmp / "req.hex"), str(tmp / "req.pcap")],
                        capture_output=True)
    r2 = subprocess.run(["text2pcap", "-T", "80,44444", "-4", "10.0.0.2,10.0.0.1",
                         str(tmp / "resp.hex"), str(tmp / "resp.pcap")],
                        capture_output=True)
    if r1.returncode or r2.returncode:
        print("  text2pcap 失败:", (r1.stderr or r2.stderr).decode()[:200])
        return False
    r3 = subprocess.run(["mergecap", "-w", str(out), str(tmp / "req.pcap"),
                         str(tmp / "resp.pcap")], capture_output=True)
    if r3.returncode:
        print("  mergecap 失败:", r3.stderr.decode()[:200])
        return False
    return out.is_file()


def main() -> int:
    missing = [t for t in ("tshark", "text2pcap", "mergecap") if not which(t)]
    if missing:
        print(f"跳过：缺少 {', '.join(missing)}（brew install wireshark）")
        return 0

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ctfops-pcap-"))
    pcap = tmp / "mini.pcap"
    print("\n[1] 造包")
    check("生成 pcap", build_pcap(tmp, pcap), str(pcap))
    if not pcap.is_file():
        return 1
    print(f"  {pcap.name}: {pcap.stat().st_size} 字节")

    cfg = load_config()
    cfg.workdir = tmp / "work"
    cfg.ensure_dirs()
    cfg.ai.enabled = False

    print("\n[2] 解析")
    rep = analyze_pcap(cfg, str(pcap), ai=False)
    check("识别出 HTTP 请求", rep.stats.get("HTTP 请求数") == 1,
          str(rep.stats.get("HTTP 请求数")))
    check("扫到了响应体", "段" in str(rep.stats.get("响应体扫描", "")),
          str(rep.stats.get("响应体扫描")))
    titles = [f.title for f in rep.findings]
    check("UA 命中扫描器", any("扫描器" in t for t in titles), str(titles))
    check("拿到响应体里的 flag", any("flag" in t.lower() for t in titles), str(titles))
    ev = [f.evidence for f in rep.findings if "flag" in f.title.lower()]
    check("flag 内容正确", any(FLAG in (e or "") for e in ev), str(ev)[:120])

    print("\n[3] 默认不落盘（4 万个导出文件就是这么来的）")
    check("没有建立 evidence/pcap 目录",
          not (cfg.evidence_dir / "pcap").exists(),
          str(list(cfg.evidence_dir.iterdir())))
    check("export_dir 为空", not rep.export_dir, rep.export_dir)

    print("\n[4] 报告")
    text = rep.text()
    check("报告含请求源", "10.0.0.1" in text, text[:160])
    check("报告含 flag", FLAG in text or "flag" in text.lower())

    print("\n" + "=" * 40)
    print(f"通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

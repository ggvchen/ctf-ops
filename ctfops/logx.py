"""日志分析：Linux 主机溯源 + Web 访问日志研判。

规则引擎先跑（离线可用、结果确定），再可选叠加本地大模型做"结论 + 下一步命令"。
"""

from __future__ import annotations

import gzip
import io
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .config import Config, Target
from .scan import Finding
from .util import console, read_text

# ----------------------------------------------------------------- 正则
RE_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
RE_ACCEPT = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")
RE_INVALID = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")
RE_SUDO = re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.*)")
RE_NEWUSER = re.compile(r"useradd|adduser|new user.*name=(\S+)")
RE_ROOTLOGIN = re.compile(r"session opened for user root|Accepted .* for root")

RE_ACCESS = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^ ]*) [^"]*" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

SUSPICIOUS_URI = [
    (r"union\s+select|information_schema|sleep\(\d|benchmark\(", "SQL 注入", "high"),
    (r"\.\./\.\./|%2e%2e%2f", "路径穿越", "high"),
    (r"\$\{jndi:|ldap://|rmi://", "Log4j/JNDI 注入", "critical"),
    (r"(eval|assert|system|exec|passthru|shell_exec)\s*\(", "代码执行特征", "high"),
    (r"(cmd|exec|command|shell)=(whoami|id|ls|cat|uname)", "命令执行参数", "critical"),
    (r"/(upload|uploads?|file).*(\.php|\.jsp|\.aspx)", "上传点访问", "medium"),
    (r"\.(php|jsp|asp|aspx)$", "动态脚本访问", "low"),
    (r"(\.git|\.svn|\.env|\.DS_Store|backup|www\.zip|\.sql$)", "敏感文件探测", "medium"),
    (r"(phpmyadmin|adminer|\.\.;/etc/passwd)", "管理面板/敏感探测", "medium"),
    (r"(whoami|uname|ipconfig|net\s+user)", "命令探测", "high"),
]

UA_BAD = ["sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "acunetix",
          "awvs", "xray", "goby", "dirsearch", "gobuster", "ffuf", "wpscan", "python-requests"]


@dataclass
class LogReport:
    target: str = ""
    kind: str = ""                       # auth | web | audit | evtx | generic | mixed
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, object] = field(default_factory=dict)
    timeline: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    ai_text: str = ""
    detail: List[str] = field(default_factory=list)    # 逐条明细（时间线之外的全部）
    samples: List[str] = field(default_factory=list)   # 未识别格式时的原始样本

    def text(self) -> str:
        parts = [f"# 日志分析 {self.target}（{self.kind or '未知格式'}）", ""]
        if self.files:
            parts.append("## 文件")
            for f in self.files[:50]:
                try:
                    size = Path(f).stat().st_size
                    parts.append(f"- {f}（{size:,} 字节）")
                except OSError:
                    parts.append(f"- {f}")
            parts.append("")
        if self.stats:
            parts.append("## 统计")
            for k, v in self.stats.items():
                parts.append(f"- {k}: {v}")
        if self.timeline:
            parts.append("\n## 时间线")
            parts.extend(f"- {t}" for t in self.timeline[:80])
        if self.findings:
            parts.append("\n## 发现")
            for f in self.findings:
                line = f"- [{f.severity}] {f.title}"
                if f.location:
                    line += f" | {f.location}"
                if f.detail:
                    line += f" | {f.detail}"
                parts.append(line)
                if f.evidence:
                    for ln in str(f.evidence).splitlines()[:4]:
                        parts.append(f"    {ln[:300]}")
        if self.detail:
            parts.append(f"\n## 明细（前 {min(len(self.detail), 200)} 条）")
            parts.extend(f"- {d}" for d in self.detail[:200])
        if self.samples:
            parts.append("\n## 原始样本")
            parts.extend(f"    {s[:300]}" for s in self.samples[:30])
        if self.ai_text:
            parts.append("\n## AI 研判\n" + self.ai_text)
        return "\n".join(parts)



# ------------------------------------------------------------ 文件读取
def _read_maybe_gz(p: Path, limit: int = 30_000_000) -> str:
    try:
        if p.suffix == ".gz":
            with gzip.open(p, "rb") as f:
                return f.read(limit).decode("utf-8", "replace")
        return read_text(p, limit)
    except Exception:
        return ""


def _walk(paths: Iterable[str]) -> List[Path]:
    out: List[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.stat().st_size < 60_000_000:
                    low = f.name.lower()
                    if (f.suffix.lower() in (".log", ".txt", ".gz", ".evtx", ".xml", ".json", ".csv")
                            or any(k in low for k in ("access", "auth", "secure", "syslog",
                                                      "audit", "evtx", "message", "history",
                                                      "dpkg", "yum", "dnf", "cron", "w3c"))):
                        out.append(f)
    return out[:400]


# ------------------------------------------------------------ auth 分析
def analyze_auth(text: str, target: str = "") -> LogReport:
    rep = LogReport(target=target, kind="auth")
    fails: Counter = Counter()
    users: Counter = Counter()
    accepts: Counter = Counter()
    accepted_users: Counter = Counter()
    invalid_users: Counter = Counter()
    sudo_cmds: Counter = Counter()

    for line in text.splitlines():
        m = RE_FAIL.search(line)
        if m:
            users[m.group(1)] += 1
            fails[m.group(2)] += 1
            continue
        m = RE_INVALID.search(line)
        if m:
            invalid_users[m.group(1)] += 1
            fails[m.group(2)] += 1
            continue
        m = RE_ACCEPT.search(line)
        if m:
            accepted_users[m.group(1)] += 1
            accepts[m.group(2)] += 1
            rep.timeline.append(_timeline(line, f"登录成功 {m.group(1)}@{m.group(2)}"))
            continue
        m = RE_SUDO.search(line)
        if m:
            sudo_cmds[m.group(2)[:120]] += 1
            rep.timeline.append(_timeline(line, f"sudo {m.group(1)}: {m.group(2)[:80]}"))

    total_fail = sum(fails.values())
    rep.stats.update({
        "失败登录次数": total_fail,
        "成功登录次数": sum(accepts.values()),
        "暴力破解源 IP 数": len(fails),
        "被尝试用户名数": len(users),
    })

    # 爆破判定
    for ip, n in fails.most_common(10):
        if n >= 20:
            rep.findings.append(Finding(
                target, f"SSH 爆破源 {ip}（{n} 次失败）", "high", "log",
                detail=f"尝试用户名: {', '.join(u for u, _ in users.most_common(6))}",
                location=ip, tags=["brute-force"]))
        elif n >= 5:
            rep.findings.append(Finding(
                target, f"可疑爆破尝试 {ip}（{n} 次）", "medium", "log", location=ip))

    # 爆破后登录成功 = 高置信失陷
    for ip, n in accepts.most_common(20):
        if fails.get(ip, 0) >= 5:
            rep.findings.append(Finding(
                target, f"爆破成功后登录 {ip}", "critical", "log",
                detail=f"失败 {fails[ip]} 次后成功 {n} 次，账号: "
                       f"{', '.join(accepted_users)}",
                location=ip, tags=["compromised"]))

    if len(accepted_users) > 1:
        rep.findings.append(Finding(
            target, "多账号登录", "low", "log",
            detail=", ".join(f"{u}×{n}" for u, n in accepted_users.most_common(8))))

    if invalid_users:
        rep.findings.append(Finding(
            target, "用户名字典枚举", "medium", "log",
            detail=", ".join(f"{u}×{n}" for u, n in invalid_users.most_common(10))))

    if RE_NEWUSER.search(text):
        rep.findings.append(Finding(target, "存在新增用户记录", "high", "log",
                                    detail="检查 /etc/passwd 中的 UID=0 与新建账号"))
    if sudo_cmds:
        rep.stats["sudo 命令种类"] = len(sudo_cmds)
        for cmd, n in sudo_cmds.most_common(5):
            if re.search(r"(chmod\s+777|chown|visudo|passwd|/etc/shadow|crontab)", cmd):
                rep.findings.append(Finding(target, "可疑 sudo 提权操作", "high", "log",
                                            detail=f"{cmd} ×{n}"))
    return rep


# ------------------------------------------------------------ web 分析
def analyze_web(text: str, target: str = "") -> LogReport:
    rep = LogReport(target=target, kind="web")
    ips: Counter = Counter()
    paths: Counter = Counter()
    status: Counter = Counter()
    uas: Counter = Counter()
    hits: List[Tuple[str, str, str, str]] = []
    by_ip_susp: Dict[str, Counter] = defaultdict(Counter)

    for line in text.splitlines():
        m = RE_ACCESS.search(line)
        if not m:
            continue
        d = m.groupdict()
        ips[d["ip"]] += 1
        paths[d["path"]] += 1
        status[d["status"]] += 1
        ua = (d.get("ua") or "")[:60]
        if ua:
            uas[ua] += 1
        for pat, label, sev in SUSPICIOUS_URI:
            if re.search(pat, d["path"] or "", re.I):
                # 404 的动态脚本访问只是扫描噪声，不提级
                if label == "动态脚本访问" and d["status"] in ("404", "403", "400"):
                    continue
                hits.append((d["ip"], label, sev, f"{d['method']} {d['path'][:120]} [{d['status']}]"))
                by_ip_susp[d["ip"]][label] += 1
                break
        if any(b in ua.lower() for b in UA_BAD):
            hits.append((d["ip"], "扫描器 UA", "high", ua))
            by_ip_susp[d["ip"]]["扫描器 UA"] += 1

    rep.stats.update({
        "请求总数": sum(ips.values()),
        "独立 IP": len(ips),
        "状态码分布": dict(status.most_common(8)),
        "Top IP": dict(ips.most_common(8)),
        "Top 路径": dict(paths.most_common(8)),
    })

    # 404 洪水 = 目录扫描
    c404 = status.get("404", 0)
    if c404 > 100:
        rep.findings.append(Finding(target, f"目录扫描特征（404×{c404}）", "medium", "log",
                                    detail="关注同一 IP 的高频 404"))

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    agg: Dict[Tuple[str, str], Dict[str, object]] = {}
    for ip, label, sev, sample in hits:
        key = (ip, label)
        rec = agg.setdefault(key, {"n": 0, "sev": sev, "samples": []})
        rec["n"] = int(rec["n"]) + 1  # type: ignore[arg-type]
        if len(rec["samples"]) < 3:  # type: ignore[arg-type]
            rec["samples"].append(sample)  # type: ignore[union-attr]
        if sev_rank.get(sev, 9) < sev_rank.get(str(rec["sev"]), 9):
            rec["sev"] = sev

    for (ip, label), rec in sorted(agg.items(),
                                   key=lambda kv: (sev_rank.get(str(kv[1]["sev"]), 9),
                                                   -int(kv[1]["n"])))[:25]:
        rep.findings.append(Finding(
            target, f"{label} @ {ip}（{rec['n']} 次）", str(rec["sev"]), "log",
            evidence="\n".join(rec["samples"]),  # type: ignore[arg-type]
            location=ip))

    # 上传后的 webshell 访问：POST 到 .php 且返回 200
    shells = [h for h in hits if h[1] == "上传点访问"]
    if shells:
        rep.findings.append(Finding(target, "疑似 webshell 上传访问", "critical", "log",
                                    evidence="\n".join(s[3] for s in shells[:10]),
                                    location=shells[0][0]))
    # 200 的大响应 POST 也是上传特征
    return rep


# ------------------------------------------------------------ 通用 syslog
# 同时覆盖 rsyslog 的 /var/log/messages、syslog，以及 journalctl -o short-iso 的导出
RE_SYSLOG = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)"
    r"\s+(?P<host>\S+)\s+(?P<svc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")

SYSLOG_SIGNALS: List[Tuple[str, str, str]] = [
    (r"Failed password|Invalid user|authentication failure|pam_unix.*auth",
     "认证失败", "medium"),
    (r"Accepted (?:password|publickey)", "认证成功", "low"),
    (r"sudo:.*COMMAND=|su(?:\[\d+\])?:.*session opened", "提权/sudo 执行", "high"),
    (r"useradd|adduser|usermod|new user|groupadd", "账号变更", "high"),
    (r"CRON.*(?:curl|wget|bash\s+-i|base64|/dev/tcp|nc\s)", "可疑计划任务", "high"),
    (r"segfault|oom-killer|Out of memory|kernel panic", "服务/内核异常", "medium"),
    (r"kernel:.*(?:UFW BLOCK|DROP IN=|REJECT)", "防火墙拦截", "low"),
    (r"session opened for user root|root.*session", "root 会话", "medium"),
    (r"(?:auditd|systemd).*(?:stop|disabled|halted)", "审计/服务被停", "high"),
]


def analyze_syslog(text: str, target: str = "") -> LogReport:
    rep = LogReport(target=target, kind="syslog")
    svcs: Counter = Counter()
    hosts: Counter = Counter()
    levels: Counter = Counter()
    hits: Dict[str, List[str]] = defaultdict(list)
    sev_hit: Dict[str, str] = {}
    stamps: List[str] = []
    parsed = 0

    for line in text.splitlines():
        m = RE_SYSLOG.match(line)
        if not m:
            continue
        parsed += 1
        svc = m.group("svc")
        msg = m.group("msg") or ""
        svcs[svc] += 1
        hosts[m.group("host")] += 1
        stamps.append(m.group("ts"))
        low = msg.lower()
        lvl = ("error" if any(k in low for k in ("error", "fail", "crit", "alert"))
               else "warn" if "warn" in low else "info")
        levels[lvl] += 1
        for pat, label, sev in SYSLOG_SIGNALS:
            if re.search(pat, f"{svc} {msg}", re.I):
                line_s = f"{m.group('ts')} {svc}: {msg[:160]}"
                if line_s not in hits[label]:
                    hits[label].append(line_s)
                sev_hit[label] = sev
                break

    rep.stats["日志行"] = parsed
    if stamps:
        rep.stats["时间范围"] = f"{min(stamps)} ~ {max(stamps)}"
    rep.stats["Top 服务"] = dict(svcs.most_common(8))
    rep.stats["主机"] = dict(hosts.most_common(3))
    rep.stats["级别分布"] = dict(levels)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for label, lines in sorted(hits.items(),
                               key=lambda kv: (order.get(sev_hit.get(kv[0], ""), 9), -len(kv[1])))[:12]:
        rep.findings.append(Finding(rep.target, f"{label}（{len(lines)} 条）",
                                    sev_hit.get(label, "medium"), "syslog",
                                    detail=lines[0][:160], evidence="\n".join(lines[:3])))
        if sev_hit.get(label) in ("critical", "high"):
            rep.timeline.extend(lines[:3])

    # 认证失败连成串就是爆破，按 IP 数
    fail_ips = Counter()
    for line in text.splitlines():
        m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            fail_ips[m.group(2)] += 1
    for ip, n in fail_ips.most_common(5):
        if n >= 10:
            rep.findings.append(Finding(rep.target, f"疑似 SSH 爆破 {ip}（{n} 次失败）",
                                        "high", "syslog", location=ip))
    if fail_ips:
        rep.stats["失败登录 Top IP"] = dict(fail_ips.most_common(5))

    rep.detail = [ln for ln in text.splitlines()
                  if any(re.search(p, ln, re.I) for p, _, _ in SYSLOG_SIGNALS)][:200]
    return rep


# ------------------------------------------------- W3C（IIS / Windows 防火墙）
def analyze_w3c(text: str, target: str = "") -> LogReport:
    """IIS 访问日志与 Windows 防火墙日志都是 W3C 扩展格式，靠 #Fields 区分。"""
    fields: List[str] = []
    rows: List[Dict[str, str]] = []
    for line in text.splitlines():
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].split()
            continue
        if not line.strip() or line.startswith("#"):
            continue
        if not fields:
            continue
        vals = line.split(" ")
        rows.append({fields[i]: (vals[i] if i < len(vals) else "")
                     for i in range(len(fields))})

    is_fw = bool(fields) and "action" in fields and "src-ip" in fields
    kind = "w3c-fw" if is_fw else "w3c-iis"
    rep = LogReport(target=target, kind=kind)
    if not rows:
        rep.findings.append(Finding(rep.target, "W3C 日志没有数据行", "info", kind))
        return rep

    ips: Counter = Counter()
    status: Counter = Counter()
    uris: Counter = Counter()
    uas: Counter = Counter()
    actions: Counter = Counter()
    hits: Dict[str, List[str]] = defaultdict(list)
    sev_hit: Dict[str, str] = {}

    for r in rows:
        ip = r.get("c-ip") or r.get("src-ip") or ""
        if ip:
            ips[ip] += 1
        code = r.get("sc-status") or r.get("sc_status") or ""
        if code:
            status[code] += 1
        uri = (r.get("cs-uri-stem") or "") + (
            "?" + r["cs-uri-query"] if r.get("cs-uri-query") not in (None, "", "-") else "")
        if uri:
            uris[uri[:120]] += 1
        ua = (r.get("cs(User-Agent)") or "").replace("+", " ")[:80]
        if ua and ua != "-":
            uas[ua] += 1
        if is_fw:
            act = r.get("action", "")
            actions[act] += 1
            if act.upper().startswith("DROP") and ip:
                pass
            continue
        # IIS：可疑 URI / 扫描器 UA 与 Linux 访问日志同一套规则
        for pat, label, sev in SUSPICIOUS_URI:
            if re.search(pat, uri, re.I):
                if label == "动态脚本访问" and code in ("404", "403", "400"):
                    continue
                line = f"{ip} {r.get('cs-method', '')} {uri[:100]} [{code}]"
                if line not in hits[label]:
                    hits[label].append(line)
                sev_hit[label] = sev
                break
        if any(b in ua.lower() for b in UA_BAD):
            line = f"{ip} UA={ua[:60]}"
            if line not in hits["扫描器 UA"]:
                hits["扫描器 UA"].append(line)
            sev_hit["扫描器 UA"] = "high"

    rep.stats["记录数"] = len(rows)
    rep.stats["独立 IP"] = len(ips)
    if is_fw:
        rep.stats["动作分布"] = dict(actions.most_common(5))
        rep.stats["Top 源 IP"] = dict(ips.most_common(8))
        drops = sum(n for a, n in actions.items() if a.upper().startswith("DROP"))
        if drops:
            rep.findings.append(Finding(rep.target, f"防火墙拦截 {drops} 条", "low",
                                        "w3c-fw",
                                        detail=f"Top 源 IP {dict(ips.most_common(3))}"))
    else:
        rep.stats["状态码分布"] = dict(status.most_common(8))
        rep.stats["Top 客户端 IP"] = dict(ips.most_common(8))
        rep.stats["Top URI"] = dict(uris.most_common(8))
        if uas:
            rep.stats["Top UA"] = dict(uas.most_common(5))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for label, lines in sorted(hits.items(),
                               key=lambda kv: (order.get(sev_hit.get(kv[0], ""), 9), -len(kv[1])))[:12]:
        rep.findings.append(Finding(rep.target, f"{label}（{len(lines)} 次）",
                                    sev_hit.get(label, "medium"), kind,
                                    detail=lines[0][:160], evidence="\n".join(lines[:3])))
        if sev_hit.get(label) in ("critical", "high"):
            rep.timeline.extend(lines[:3])

    c404 = status.get("404", 0)
    if c404 > 100:
        rep.findings.append(Finding(rep.target, f"目录扫描特征（404×{c404}）", "medium", kind))
    rep.detail = [f"{r.get('date', '')} {r.get('time', '')} {r.get('c-ip', '')} "
                  f"{r.get('cs-method', '')} {r.get('cs-uri-stem', '')} "
                  f"{r.get('sc-status', '')}".strip() for r in rows[:200]]
    return rep


# --------------------------------------------------- wevtutil / XML 导出的事件
RE_WEVTUTIL_TEXT = re.compile(r"Event\[\d+\]:")


def _parse_wevtutil_text(text: str) -> List[Dict[str, str]]:
    events: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    in_desc = False
    for line in text.splitlines():
        if RE_WEVTUTIL_TEXT.match(line.strip()):
            if cur:
                events.append(cur)
            cur = {}
            in_desc = False
            continue
        if not cur and not line.strip():
            continue
        stripped = line.strip()
        if stripped.lower().startswith("description:"):
            in_desc = True
            continue
        m = re.match(r"^([A-Za-z][\w ]{1,40}):\s*(.*)$", stripped)
        if m and not in_desc:
            key, val = m.group(1).strip(), m.group(2).strip()
            if key == "Event ID":
                cur["EventID"] = val
            elif key == "Date":
                cur["Time"] = val
            elif key == "Computer":
                cur["Computer"] = val
            elif key in ("Source", "Log Name", "Level", "User"):
                cur[key.replace(" ", "")] = val
            continue
        if in_desc and ":" in stripped:
            k, v = stripped.split(":", 1)
            cur.setdefault(k.strip(), v.strip())
            if k.strip().lower() == "account name":
                cur.setdefault("TargetUserName", v.strip())
            if "source network address" in k.strip().lower():
                cur.setdefault("IpAddress", v.strip())
    if cur:
        events.append(cur)
    return [e for e in events if e.get("EventID")]


def _parse_wevtutil_xml(text: str) -> List[Dict[str, str]]:
    import xml.etree.ElementTree as ET
    out: List[Dict[str, str]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # 多份 XML 拼在一起（wevtutil 逐条导出）时逐个解析
        for chunk in re.findall(r"<Event\b.*?</Event>", text, re.S):
            try:
                root0 = ET.fromstring(chunk)
            except ET.ParseError:
                continue
            out.append(_evtx_fields(ET.tostring(root0, encoding="unicode")))
        return [e for e in out if e.get("EventID")]
    evs = [root] if root.tag.split("}")[-1] == "Event" else [
        el for el in root.iter() if el.tag.split("}")[-1] == "Event"]
    for el in evs:
        out.append(_evtx_fields(ET.tostring(el, encoding="unicode")))
    return [e for e in out if e.get("EventID")]


# ------------------------------------------------------------ shell 历史
HISTORY_RULES: List[Tuple[str, str, str]] = [
    (r"(?:curl|wget)[^|]*\|\s*(?:ba)?sh", "远程脚本直接执行", "critical"),
    (r"\b(?:nc|ncat|socat)\b.*-e|\bnc\s+-\w*l", "反弹 shell", "critical"),
    (r"base64\s+-d|xxd\s+-r|openssl\s+enc\s+-d", "解码后执行（免杀）", "high"),
    (r"chmod\s+(?:4[0-7]{3}|[ug]\+s)\b|chown\s+root", "SUID/属主修改", "high"),
    (r"useradd|adduser|passwd\s+\S+|echo\s+\S+\|chpasswd", "账号变更", "high"),
    (r"crontab\s+-|>>\s*/etc/cron|systemctl\s+enable", "持久化", "high"),
    (r"history\s+-c|unset\s+HISTFILE|rm\s+-rf?\s+/var/log|shred\b", "痕迹清理", "high"),
    (r"cat\s+/etc/(?:shadow|passwd)|\.ssh/id_", "敏感文件读取", "medium"),
    (r"tar\s+-?c\w*\s+.*(?:/data|/home|/var/www|/root)", "打包敏感目录", "medium"),
    (r"auditctl\s+.*-e\s*0|service\s+auditd\s+stop", "关闭审计", "critical"),
]


def analyze_history(text: str, target: str = "") -> LogReport:
    rep = LogReport(target=target, kind="history")
    cmds: List[Tuple[str, str]] = []      # (时间, 命令)
    ts = ""
    for line in text.splitlines():
        if re.match(r"^#\d{9,}$", line.strip()):
            import time as _t
            ts = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(int(line.strip()[1:])))
            continue
        if line.strip():
            cmds.append((ts, line.strip()))
    if not cmds:
        rep.findings.append(Finding(rep.target, "历史记录为空", "info", "history"))
        return rep

    hits: Dict[str, List[str]] = defaultdict(list)
    sev_hit: Dict[str, str] = {}
    for t, cmd in cmds:
        for pat, label, sev in HISTORY_RULES:
            if re.search(pat, cmd, re.I):
                entry = f"{t} {cmd[:160]}".strip()
                if entry not in hits[label]:
                    hits[label].append(entry)
                sev_hit[label] = sev
                break

    top = Counter(c.split()[0] for _, c in cmds if c.split())
    rep.stats["命令数"] = len(cmds)
    if any(t for t, _ in cmds):
        rep.stats["时间范围"] = f"{next(t for t, _ in cmds if t)} ~ {[t for t, _ in cmds if t][-1]}"
    rep.stats["Top 命令"] = dict(top.most_common(8))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for label, lines in sorted(hits.items(),
                               key=lambda kv: (order.get(sev_hit.get(kv[0], ""), 9), -len(kv[1]))):
        rep.findings.append(Finding(rep.target, f"{label}（{len(lines)} 条）",
                                    sev_hit.get(label, "medium"), "history",
                                    detail=lines[0][:160], evidence="\n".join(lines[:3])))
        if sev_hit.get(label) in ("critical", "high"):
            rep.timeline.extend(lines[:3])
        rep.detail.extend(lines[:20])
    if not hits:
        rep.detail = [f"{t} {c[:160]}" for t, c in cmds[:120]]
    return rep


# ------------------------------------------------------- 包管理日志（装后门常用）
PKG_RULES: List[Tuple[str, str, str]] = [
    (r"\b(?:netcat|ncat|nmap|socat|telnet|hydra|sqlmap|metasploit|john|hashcat|"
     r"gcc|make|python3?-dev|bind9|vsftpd)\b", "安装可疑/攻击工具", "high"),
    (r"\b(?:openssh-server|nginx|apache2|httpd|mysql-server|redis)\b", "安装服务组件", "low"),
]


def analyze_pkg(text: str, target: str = "") -> LogReport:
    rep = LogReport(target=target, kind="pkg")
    installed: Counter = Counter()
    hits: Dict[str, List[str]] = defaultdict(list)
    sev_hit: Dict[str, str] = {}
    entries = 0
    for line in text.splitlines():
        low = line.lower()
        if not any(k in low for k in ("install", "upgrade", "update", "installed",
                                      "erased", "remove")):
            continue
        entries += 1
        m = re.search(r"(?:install|installed|upgrade|更新的软件包|安装)[:\s]+(\S+)", line, re.I)
        pkg = (m.group(1) if m else line.split()[-1]).split(":")[0].strip()
        if pkg:
            installed[pkg] += 1
        for pat, label, sev in PKG_RULES:
            if re.search(pat, line, re.I):
                entry = line.strip()[:160]
                if entry not in hits[label]:
                    hits[label].append(entry)
                sev_hit[label] = sev
                break
    rep.stats["条目数"] = entries
    if installed:
        rep.stats["Top 包"] = dict(installed.most_common(10))
    for label, lines in sorted(hits.items(), key=lambda kv: -len(kv[1]))[:6]:
        rep.findings.append(Finding(rep.target, f"{label}（{len(lines)} 个）",
                                    sev_hit.get(label, "medium"), "pkg",
                                    detail=lines[0][:160], evidence="\n".join(lines[:5])))
        if sev_hit.get(label) == "high":
            rep.timeline.extend(lines[:3])
    rep.detail = [ln.strip()[:160] for ln in text.splitlines()
                  if any(k in ln.lower() for k in ("install", "installed", "升级", "安装"))][:120]
    return rep


# ------------------------------------------------- Web 错误日志（nginx/apache）
RE_WEBERR = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+(?:\[(?P<lvl>\w+)\]\s+)?(?:\[pid\s+\d+(?::tid\s+\d+)?\]\s+)?"
    r"(?:\[client\s+(?P<ip>[\d.:a-fA-F]+)\]\s+)?(?P<msg>.*)$")


def analyze_web_error(text: str, target: str = "") -> LogReport:
    rep = LogReport(target=target, kind="web-error")
    ips: Counter = Counter()
    kinds: Counter = Counter()
    rows: List[str] = []
    for line in text.splitlines():
        m = RE_WEBERR.match(line.strip())
        if not m:
            continue
        ip = m.group("ip") or ""
        if ip:
            ips[ip] += 1
        msg = m.group("msg") or ""
        label = ("PHP 致命错误" if "PHP Fatal" in msg
                 else "包含文件失败" if "File does not exist" in msg or "include" in msg.lower()
                 else "拒绝访问" if "access forbidden" in msg.lower() or "Permission denied" in msg
                 else "上游/连接失败" if "upstream" in msg.lower() or "Connection refused" in msg
                 else "脚本错误" if "error" in (m.group("lvl") or "").lower() else "")
        if label:
            kinds[label] += 1
        rows.append(line.strip()[:200])
    rep.stats["错误行"] = len(rows)
    if ips:
        rep.stats["Top 客户端 IP"] = dict(ips.most_common(8))
    if kinds:
        rep.stats["错误类型"] = dict(kinds.most_common(8))
        for label, n in kinds.most_common(4):
            sev = "high" if label in ("PHP 致命错误", "脚本错误") else "medium"
            rep.findings.append(Finding(rep.target, f"{label}（{n} 次）", sev, "web-error"))
    if ips:
        top_ip, n = ips.most_common(1)[0]
        if n >= 30:
            rep.findings.append(Finding(rep.target, f"同一客户端高频报错 {top_ip}（{n} 次）",
                                        "medium", "web-error", location=top_ip))
    rep.detail = rows[:200]
    return rep


# ------------------------------------------------------------ auditd 分析
# 形如：Nov  6 22:03:12 SRV-FS01 audispd[12000]: type=SYSCALL msg=audit(19:88201): comm="tar" ...
# 一条命令会拆成 SYSCALL/EXECVE/CWD/PATH/PROCTITLE 多条记录，共用一个 serial，
# 所以必须按 serial 合并后再看参数，否则只能看到 comm="tar" 不知道在打包什么。
RE_AUDIT_BODY = re.compile(r"(?:^|\s)(type=[A-Z_]+ .*)$")
RE_AUDIT_MSG = re.compile(r"msg=audit\(([\d.]+):(\d+)\)")
RE_AUDIT_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|\S+)')

AUDIT_RULES: List[Tuple[str, str, str]] = [
    (r"\b(?:tar|zip|7z|rar|gzip|bzip2|xz)\b", "数据打包归档", "medium"),
    (r"\b(?:curl|wget|nc|ncat|socat|scp|rsync|sftp|lftp|ftp)\b", "可能的对外传输", "high"),
    (r"\bbase64\b|\bxxd\b.*-r", "base64/编码处理（常见绕过）", "medium"),
    (r"chmod\s+(?:4[0-7]{3}|[ug]\+s)\b|setcap\b", "SUID 权限修改", "high"),
    (r"\b(?:useradd|usermod|adduser|passwd|chpasswd|chage|groupadd)\b", "账号变更", "high"),
    (r"\bshred\b|rm\s+-rf?\s+/var/log|truncate\s+-s\s*0|history\s+-c", "痕迹清理", "high"),
    (r"auditctl\s+.*-e\s*0|systemctl\s+(?:stop|disable)\s+auditd|service\s+auditd\s+stop",
     "关闭审计", "critical"),
    (r"\b(?:crontab|systemctl\s+enable|at\s+\d)\b", "持久化动作", "medium"),
    (r"/etc/(?:shadow|passwd|sudoers)|\.ssh/|/root/\.", "敏感文件访问", "high"),
    (r"\b(?:whoami|id|uname|hostname|ip\s+a)\b", "主机信息收集", "low"),
]


def _audit_ts(epoch: float, line: str) -> str:
    if epoch:
        import time as _t
        return _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(epoch))
    m = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    return m.group(1) if m else ""


def parse_audit(text: str) -> List[Dict[str, object]]:
    """把 auditd 日志拆成"以一次 syscall 为单位"的执行记录。

    真实 auditd 里同一事件的多条记录共用一个 serial，但也见过每个 type 各自递增的
    导出（样例就是），所以不能只按 serial 分组 —— 改成"遇到 type=SYSCALL 就开新事件"，
    后面的 EXECVE/CWD/PATH/PROCTITLE 都挂到这条上，两种格式都能正确合并。
    """
    events: List[Dict[str, object]] = []
    cur: Optional[Dict[str, object]] = None

    def flush() -> None:
        nonlocal cur
        if not cur:
            return
        argv = cur.get("argv") or {}
        cmd = " ".join(argv[i] for i in sorted(argv)) if argv else str(
            cur.get("proctitle") or cur.get("exe") or cur.get("comm") or "")
        cur["cmd"] = cmd.strip()
        events.append(cur)
        cur = None

    for line in text.splitlines():
        m = RE_AUDIT_BODY.search(line)
        if not m:
            continue
        body = m.group(1)
        t = re.match(r"type=(\w+)", body)
        if not t:
            continue
        typ = t.group(1)
        mm = RE_AUDIT_MSG.search(body)
        epoch = float(mm.group(1)) if mm else 0.0
        if typ == "SYSCALL" or cur is None:
            flush()
            cur = {"serial": mm.group(2) if mm else "", "epoch": epoch,
                   "ts": _audit_ts(epoch, line), "types": [], "argv": {},
                   "paths": [], "raw": []}
        kv: Dict[str, str] = {}
        for k, v in RE_AUDIT_KV.findall(body):
            kv[k] = v[1:-1] if len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v
        cur["types"].append(typ)                       # type: ignore[union-attr]
        if not cur.get("epoch") and epoch:
            cur["epoch"] = epoch                       # type: ignore[assignment]
            cur["ts"] = _audit_ts(epoch, line)          # type: ignore[assignment]
        for k, v in kv.items():
            if k.startswith("a") and k[1:].isdigit():
                cur["argv"][int(k[1:])] = v             # type: ignore[index]
            elif k == "proctitle" and re.fullmatch(r"[0-9A-Fa-f]+", v or ""):
                try:
                    cur["proctitle"] = bytes.fromhex(v).replace(b"\x00", b" ").decode(
                        "utf-8", "replace").strip()
                except ValueError:
                    pass
            elif k == "name" and typ == "PATH":
                cur["paths"].append(v)                  # type: ignore[union-attr]
            elif k in ("comm", "exe", "cwd", "auid", "uid", "euid", "key", "acct",
                       "addr", "terminal", "res", "pid", "ppid"):
                cur[k] = v
        cur["raw"].append(line.strip())                 # type: ignore[union-attr]
    flush()
    return events


def analyze_audit(text: str, target: str = "") -> LogReport:
    rep = LogReport(target=target, kind="audit")
    events = parse_audit(text)
    if not events:
        rep.findings.append(Finding(rep.target, "audit 日志为空或格式不符", "info", "log"))
        return rep

    types: Counter = Counter()
    comms: Counter = Counter()
    users: Counter = Counter()
    hits: Dict[str, List[str]] = defaultdict(list)
    sev_hit: Dict[str, str] = {}
    stamps = [str(e.get("ts") or "") for e in events if e.get("ts")]

    for e in events:
        types.update(e["types"] or [])
        cmd = str(e.get("cmd") or "")
        comm = str(e.get("comm") or "")
        if comm:
            comms[comm] += 1
        auid = str(e.get("auid") or "")
        uid = str(e.get("uid") or "")
        if auid and auid not in ("4294967295", "unset"):
            users[f"auid={auid}"] += 1
        elif uid:
            users[f"uid={uid}"] += 1
        blob = f"{comm} {cmd} {' '.join(str(x) for x in (e.get('paths') or []))}"
        for pat, label, sev in AUDIT_RULES:
            if re.search(pat, blob, re.I):
                line = (cmd or comm)[:200]
                if line not in hits[label]:
                    hits[label].append(line)
                sev_hit[label] = sev
                if label in ("关闭审计", "痕迹清理", "账号变更", "SUID 权限修改"):
                    rep.timeline.append(f"[{label}] {e.get('ts')} {line[:120]}")

    for label, lines in sorted(hits.items(), key=lambda kv: -len(kv[1]))[:16]:
        rep.findings.append(Finding(
            rep.target, f"{label}（{len(lines)} 次）", sev_hit.get(label, "medium"),
            "audit", detail=f"`{lines[0][:140]}`",
            evidence="\n".join(lines[:3])))

    rep.stats["事件数"] = len(events)
    if stamps:
        rep.stats["时间范围"] = f"{min(stamps)} ~ {max(stamps)}"
    rep.stats["记录类型"] = dict(types.most_common(8))
    rep.stats["Top 进程"] = dict(comms.most_common(8))
    rep.stats["Top 用户"] = dict(users.most_common(6))
    keys = Counter(str(e.get("key")) for e in events if e.get("key") and e.get("key") != "unset")
    if keys:
        rep.stats["审计键"] = dict(keys.most_common(6))
    rep.stats["判定"] = ("发现数据打包/外传类动作，重点看 exe 与目标路径"
                        if any(k in ("数据打包归档", "可能的对外传输") for k in hits)
                        else "未见明显高危动作")

    # 全量执行清单（时间线不够用时翻这里）
    # 去重（SYSCALL/EXECVE 合并后同一个动作可能被记两次）
    seen_tl, tl = set(), []
    for t in rep.timeline:
        if t in seen_tl:
            continue
        seen_tl.add(t)
        tl.append(t)
    rep.timeline = tl[:80]
    if len(rep.timeline) < 10:
        for e in events[:40]:
            if e.get("cmd"):
                rep.timeline.append(f"{e.get('ts')} {e.get('cmd')[:150]}")
    rep.detail = [f"{e.get('ts')} [{','.join(str(t) for t in (e.get('types') or [])[:3])}] "
                  f"{str(e.get('cmd') or '')[:200]}"
                  for e in events[:200]]
    return rep


# ------------------------------------------------------------ Windows EVTX
EVTX_EIDS = {
    "4625": ("登录失败", "medium"),
    "4624": ("登录成功", "info"),
    "4634": ("注销", "info"),
    "4672": ("分配特权（管理员登录）", "medium"),
    "4688": ("进程创建", "info"),
    "4720": ("新建账号", "high"),
    "4726": ("删除账号", "high"),
    "4728": ("加入全局特权组", "high"),
    "4732": ("加入本地管理员组", "high"),
    "7045": ("安装服务（持久化）", "critical"),
    "1102": ("审计日志被清空", "critical"),
    "104": ("日志被清空", "critical"),
    "4697": ("安装服务（旧接口）", "high"),
    "4698": ("创建计划任务", "high"),
    "4648": ("显式凭据登录（横向）", "high"),
    "4673": ("特权服务调用", "medium"),
    "4104": ("PowerShell 脚本块", "high"),
    "4103": ("PowerShell 模块日志", "low"),
}

SYSMON_EIDS = {
    "1": ("进程创建", "info"),
    "3": ("网络连接", "info"),
    "7": ("镜像加载", "medium"),
    "8": ("远程线程注入", "critical"),
    "10": ("进程访问（凭据窃取）", "critical"),
    "11": ("文件创建", "info"),
    "13": ("注册表修改（持久化）", "medium"),
    "22": ("DNS 查询", "info"),
    "23": ("文件删除", "medium"),
}

SUSPECT_CMDLINE = [
    (r"(?:iex|invoke-expression|downloadstring|downloadfile|frombase64string)", 
     "PowerShell 下载/执行", "high"),
    (r"powershell.*(-enc|-e\s|-w\s+hidden|-nop|-noprofile)", "PowerShell 编码/隐藏执行", "high"),
    (r"schtasks\s+/create", "命令行建计划任务", "high"),
    (r"reg\s+add.*(?:\\run|\\services|\\currentversion\\run)",
     "注册表持久化", "high"),
    (r"net\s+localgroup\s+administrators.*/add", "加入本地管理员组", "high"),
    (r"certutil.*(-urlcache|-decode|-encode)", "certutil 下载/解码", "high"),
    (r"bitsadmin\s+/transfer", "bitsadmin 下载", "high"),
    (r"(mshta|rundll32|regsvr32).*(http|javascript:|scrobj)", "LOLBin 远程执行", "critical"),
    (r"wmic\s+process\s+call\s+create", "WMIC 起进程", "high"),
    (r"net\s+user\s+\S+\s+\S+\s+/add", "命令行建账号", "high"),
    (r"vssadmin\s+delete\s+shadows|wbadmin\s+delete", "删除卷影副本", "critical"),
    (r"whoami|net\s+group\s+\"domain admins\"", "主机/域信息收集", "low"),
]


def _user_site() -> List[str]:
    import site
    import sysconfig
    cands = []
    try:
        cands += site.getusersitepackages() if isinstance(site.getusersitepackages(), list) \
            else [site.getusersitepackages()]
    except Exception:  # noqa: BLE001
        pass
    for ver in ("3.13", "3.12", "3.11"):
        cands.append(str(Path.home() / ".local" / "lib" / f"python{ver}" / "site-packages"))
    cands.append(sysconfig.get_paths().get("purelib", ""))
    return [c for c in cands if c]


def evtx_reader():
    """拿到 python-evtx 的 Evtx 类；装到用户站点里也认（比赛机上往往只装了 pip --user）。"""
    import sys
    try:
        from Evtx.Evtx import Evtx  # noqa: WPS433
        return Evtx
    except ImportError:
        pass
    for cand in _user_site():
        if cand and cand not in sys.path and Path(cand).is_dir():
            sys.path.append(cand)
    try:
        from Evtx.Evtx import Evtx  # noqa: WPS433
        return Evtx
    except ImportError:
        return None


def _evtx_fields(xml_text: str) -> Dict[str, str]:
    import xml.etree.ElementTree as ET
    out: Dict[str, str] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag == "EventID":
            out["EventID"] = (el.text or "").strip()
        elif tag == "TimeCreated":
            out.setdefault("Time", el.attrib.get("SystemTime", ""))
        elif tag == "Computer":
            out.setdefault("Computer", (el.text or "").strip())
        elif tag == "Provider":
            out.setdefault("Provider", el.attrib.get("Name", ""))
        elif tag == "Data" and el.attrib.get("Name") and el.attrib["Name"] not in out:
            out[el.attrib["Name"]] = (el.text or "").strip()
    return out


def _judge_windows(events: List[Dict[str, str]], target: str, kind: str = "evtx") -> LogReport:
    """Windows 事件的统一研判：EVTX 二进制、wevtutil 文本/XML 导出都走这里。"""
    rep = LogReport(target=target, kind=kind)
    if not events:
        rep.findings.append(Finding(target, "没有可读事件", "info", kind))
        return rep

    eids: Counter = Counter()
    users: Counter = Counter()
    ips: Counter = Counter()
    fails: Counter = Counter()
    hosts: Counter = Counter()
    times: List[str] = []
    interesting: List[str] = []
    suspicious: Dict[str, List[str]] = defaultdict(list)
    sev_sus: Dict[str, str] = {}

    for f in events:
        eid = f.get("EventID", "")
        if not eid:
            continue
        eids[eid] += 1
        ts = (f.get("Time") or "")[:19].replace("T", " ")
        if ts:
            times.append(ts)
        if f.get("Computer"):
            hosts[f["Computer"]] += 1
        user = f.get("TargetUserName") or f.get("SubjectUserName") or ""
        if user and user != "-":
            users[user] += 1
        ip = f.get("IpAddress") or f.get("IpAddresses") or f.get("SourceIp") or ""
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            ips[ip] += 1

        label, sev = EVTX_EIDS.get(eid, ("", ""))
        provider = f.get("Provider", "")
        # Sysmon 的 1/3/11/13/22 要按 provider 认，否则 System 日志里的同号事件会误判
        if "Sysmon" in provider:
            label, sev = SYSMON_EIDS.get(eid, ("Sysmon 事件", "info"))
        cmd = (f.get("CommandLine") or f.get("NewProcessName") or
               f.get("ScriptBlockText") or "")
        if eid == "4625":
            fails[(user or "?", ip or "?")] += 1
        if eid in ("4688", "4104", "1") and cmd:
            for pat, plabel, psev in SUSPECT_CMDLINE:
                if re.search(pat, cmd, re.I):
                    if cmd[:200] not in suspicious[plabel]:
                        suspicious[plabel].append(cmd[:200])
                    sev_sus[plabel] = psev
                    break
        if sev in ("high", "critical") and label:
            detail = (f.get("ServiceName") or f.get("TaskName") or
                      f.get("SubjectUserName") or cmd or user or "")
            interesting.append(f"[{label}] {ts} {str(detail)[:120]}")

    rep.stats["事件数"] = len(events)
    if times:
        rep.stats["时间范围"] = f"{min(times)} ~ {max(times)}"
    rep.stats["Top EventID"] = {
        f"{k} {EVTX_EIDS.get(k, SYSMON_EIDS.get(k, ('', '')))[0]}".strip(): v
        for k, v in eids.most_common(6)}
    if hosts:
        rep.stats["主机"] = dict(hosts.most_common(5))
    if users:
        rep.stats["Top 账号"] = dict(users.most_common(6))
    if ips:
        rep.stats["Top 源 IP"] = dict(ips.most_common(5))

    for (user, ip), n in sorted(fails.items(), key=lambda kv: -kv[1])[:6]:
        if n >= 5:
            rep.findings.append(Finding(
                rep.target, f"登录爆破嫌疑 {user}@{ip}（{n} 次 4625）", "high", kind,
                location=ip, detail=f"账号 {user} 失败 {n} 次"))
    for label, lines in sorted(suspicious.items(), key=lambda kv: -len(kv[1]))[:10]:
        rep.findings.append(Finding(
            rep.target, f"{label}（{len(lines)} 次）", sev_sus.get(label, "high"), kind,
            detail=f"`{lines[0][:140]}`", evidence="\n".join(lines[:3])))
    for eid in ("1102", "104", "7045", "4720", "4728", "4732", "4698", "4697",
                "4648", "4673", "4104"):
        n = eids.get(eid, 0)
        if not n or eid not in EVTX_EIDS:
            continue
        label, sev = EVTX_EIDS[eid]
        sample = next((t for t in interesting if label in t), "")
        rep.findings.append(Finding(rep.target, f"{label}（EventID {eid}，{n} 次）",
                                    sev, kind, detail=sample[:300]))

    rep.timeline = interesting[:80]
    rep.detail = interesting[:200]
    return rep


def analyze_evtx(path: str, target: str = "", limit: int = 300000) -> LogReport:
    """解析 .evtx 二进制（Security/System/Application/Sysmon/PowerShell 都一样）。"""
    name = target or Path(path).name
    Evtx = evtx_reader()
    if Evtx is None:
        rep = LogReport(target=name, kind="evtx")
        rep.findings.append(Finding(
            rep.target, "缺少 EVTX 解析库", "info", "evtx",
            detail="pip install python-evtx ；或用 Windows 自带 wevtutil 导出成文本再拖进来"))
        rep.stats["提示"] = "未解析（缺 python-evtx）"
        return rep

    events: List[Dict[str, str]] = []
    err = ""
    try:
        with Evtx(path) as log:
            for i, rec in enumerate(log.records()):
                if i >= limit:
                    break
                try:
                    f = _evtx_fields(rec.xml())
                except Exception:  # noqa: BLE001
                    continue
                if f.get("EventID"):
                    events.append(f)
    except Exception as e:  # noqa: BLE001
        err = str(e)[:200]
    rep = _judge_windows(events, name, "evtx")
    if err:
        rep.findings.append(Finding(rep.target, "EVTX 解析异常", "medium", "evtx", detail=err))
    return rep


def analyze_wevtutil(text: str, target: str = "") -> LogReport:
    """wevtutil / PowerShell 导出的事件：文本（Event[N]: ...）或 XML。"""
    stripped = text.lstrip()
    if stripped.startswith("<?xml") or "<Event" in text[:2000]:
        events = _parse_wevtutil_xml(text)
        kind = "wevtutil-xml"
    else:
        events = _parse_wevtutil_text(text)
        kind = "wevtutil-text"
    rep = _judge_windows(events, target or "wevtutil", kind)
    if not events:
        rep.findings.append(Finding(rep.target, "导出文本里没找到事件", "info", kind,
                                    detail="支持 wevtutil qe /f:text 与 /f:xml 两种导出"))
        rep.samples = [ln for ln in text.splitlines() if ln.strip()][:20]
    return rep


def _timeline(line: str, action: str) -> str:
    m = re.match(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
    ts = m.group(1) if m else ""
    return f"{ts} {action}"


# ------------------------------------------------------------ 通用入口
def detect_kind(p: Path, text: str) -> str:
    """按内容优先、文件名兜底判断日志类型。顺序很关键：越特有的越靠前。"""
    name = p.name.lower()
    head = text[:4000]
    if p.suffix.lower() == ".evtx":
        return "evtx"
    # IEC/IIS 与 Windows 防火墙都是 W3C 扩展格式，靠 #Fields 一行区分字段
    if "#Fields:" in head or "cs-uri-stem" in head \
            or head.lstrip().startswith("#Software: Microsoft"):
        return "w3c"
    if head.lstrip().startswith("<?xml") and "<Event" in head:
        return "wevtutil"
    if "Event[0]:" in head[:2000] or "Event ID:" in head or "事件 ID:" in head:
        return "wevtutil"
    if "type=SYSCALL" in head or "msg=audit(" in head or "audispd[" in head:
        return "audit"
    if re.search(r"^(?:Start-Date:|Commandline:|Install:)", head, re.M) \
            or re.search(r"^(?:Installed|Updated|Erased):\s", head, re.M):
        return "pkg"
    # /var/log/messages 里也夹着 sshd 行，所以 auth 要看"认证类行占比"：
    # 全是认证行才是 auth.log，混着 CRON/kernel/systemd 就该走通用 syslog
    auth_lines = len(re.findall(
        r"(Failed password|Accepted |Invalid user|sudo:|session opened|pam_unix)",
        head, re.I))
    total_lines = max(1, len([ln for ln in head.splitlines() if ln.strip()]))
    if any(k in name for k in ("auth", "secure", "sshd")) \
            or auth_lines / total_lines > 0.5:
        return "auth"
    if "HTTP/1." in head or RE_ACCESS.search(text[:5000]):
        return "web"
    if re.search(r"^\[\w{3} \w{3} \d+ [\d:]+ [\d]{4}\] \[\w+\]", head, re.M) \
            or "client:" in head and "[error]" in head.lower():
        return "web-error"
    if RE_SYSLOG.search(head) or any(k in name for k in (
            "messages", "syslog", "cron", "daemon.log", "kern.log", "journal")):
        return "syslog"
    if any(k in name for k in ("history", "histfile")) or re.match(r"^#\d{9,}\s*$", head, re.M):
        return "history"
    if any(k in name for k in ("dpkg", "yum", "dnf", "apt", "pacman")):
        return "pkg"
    return "generic"


def analyze_file(path: str, cfg: Config, target: str = "", ai: bool = True) -> LogReport:
    p = Path(path).expanduser()
    if p.suffix.lower() == ".evtx":
        rep = analyze_evtx(str(p), target or p.name)
        rep.files = [str(p)]
        if ai and rep.stats.get("事件数"):
            rep.ai_text = _ai_pass(
                cfg, "\n".join([f"{k}: {v}" for k, v in rep.stats.items()]
                               + rep.timeline[:60]), f"{p.name}（Windows EVTX）")
        return rep

    text = _read_maybe_gz(p)
    if not text:
        return LogReport(target=target or p.name, kind="empty")
    kind = detect_kind(p, text)
    name = target or p.name

    if kind == "w3c":
        rep = analyze_w3c(text, name)
    elif kind == "wevtutil":
        rep = analyze_wevtutil(text, name)
    elif kind == "audit":
        rep = analyze_audit(text, name)
    elif kind == "auth":
        rep = analyze_auth(text, name)
    elif kind == "web":
        rep = analyze_web(text, name)
    elif kind == "web-error":
        rep = analyze_web_error(text, name)
    elif kind == "syslog":
        rep = analyze_syslog(text, name)
    elif kind == "history":
        rep = analyze_history(text, name)
    elif kind == "pkg":
        rep = analyze_pkg(text, name)
    else:
        rep = LogReport(target=name, kind="generic")
        rep.findings.append(Finding(rep.target, "未识别日志格式", "info", "log",
                                    detail=f"{len(text)} 字符，已交给 AI 通用研判"))
        rep.samples = [ln for ln in text.splitlines() if ln.strip()][:30]
        rep.stats["字符数"] = len(text)
        rep.stats["行数"] = text.count("\n") + 1
        rep.stats["首行"] = (rep.samples[0][:200] if rep.samples else "")

    rep.files = [str(p)]
    if ai and kind not in ("evtx",):
        rep.ai_text = _ai_pass(cfg, text, f"{p.name} ({rep.kind})")
    return rep


def analyze_paths(paths: Iterable[str], cfg: Config, target: str = "",
                  log=None) -> LogReport:
    """多文件分析：逐个走规则引擎，最后只做**一次** AI 综合研判。

    早先是每个文件一次 AI、合并后再一次 —— 两个文件就是 3 次大模型调用，
    本地 35B 要跑两三分钟，界面上看着像卡死。
    """
    def say(msg: str, level: str = "info") -> None:
        if not log:
            return
        try:
            log(msg, level)
        except TypeError:
            log(msg)

    files = _walk(paths)
    if not files:
        return LogReport(target=target, kind="empty")
    merged = LogReport(target=target or str(paths), kind="")
    merged.files = [str(f) for f in files]
    texts: List[str] = []
    kinds: set = set()
    for idx, f in enumerate(files, 1):
        say(f"[{idx}/{len(files)}] 分析 {f.name}（{f.stat().st_size:,} 字节）")
        r = analyze_file(str(f), cfg, target=target, ai=False)
        if r.kind:
            say(f"  {f.name}: {r.kind}，发现 {len(r.findings)} 项", 
                "ok" if r.findings else "info")
        if r.kind and r.kind != "empty":
            kinds.add(r.kind)
        merged.findings.extend(r.findings)
        merged.timeline.extend(r.timeline)
        merged.detail.extend(f"[{f.name}] {d}" for d in r.detail[:200])
        merged.samples.extend(f"[{f.name}] {sv}" for sv in r.samples[:10])
        for k, v in r.stats.items():
            merged.stats[f"{f.name}:{k}"] = v
        if f.suffix.lower() == ".evtx":
            texts.append(f"== {f} ==\n(Windows EVTX 二进制，已按事件解析)")
        else:
            texts.append(f"== {f} ==\n{_read_maybe_gz(f)[:20000]}")
    merged.kind = "mixed" if len(kinds) > 1 else (next(iter(kinds)) if kinds else "")
    # 去重
    seen = set()
    uniq = []
    for f in merged.findings:
        key = (f.title, f.location)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    merged.findings = uniq
    if cfg.ai.enabled:
        say(f"AI 综合研判 {len(files)} 个文件（本地模型可能要 1-2 分钟）...")
    merged.ai_text = _ai_pass(cfg, "\n\n".join(texts)[:60000],
                              f"多点日志合并（{len(files)} 个文件）")
    say("分析完成", "ok")
    return merged


def _ai_pass(cfg: Config, text: str, hint: str, max_chars: int = 12000) -> str:
    if not text.strip():
        return ""
    try:
        from .aiclient import AIClient
        ai = AIClient(cfg)
        if not ai.available():
            return ""
        res = ai.analyze_log(text[:max_chars], hint)
        return res.text if res.ok else ""
    except Exception:
        return ""


# ------------------------------------------------------------ 远端取证
def pull_logs(cfg: Config, target: Target, local_dir: Optional[Path] = None) -> List[str]:
    """把靶机关键日志拉回本地，不改动远端。"""
    from .sshx import SSHSession

    local_dir = local_dir or (cfg.evidence_dir / "logs" / target.name)
    local_dir.mkdir(parents=True, exist_ok=True)
    wanted = [
        "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
        "/var/log/messages", "/var/log/cron", "/var/log/lastlog",
        "/var/log/wtmp", "/var/log/btmp",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    ]
    saved: List[str] = []
    with SSHSession(target, cfg) as sess:
        listing = sess.exec("ls -1 " + " ".join(wanted) + " 2>/dev/null", timeout=20)
        existing = [x.strip() for x in listing.out.splitlines() if x.strip()]
        if not existing:
            existing = [x.strip() for x in sess.exec(
                "find /var/log -type f -size -80M 2>/dev/null | head -40", timeout=30
            ).out.splitlines() if x.strip()]
        for remote in existing:
            name = remote.strip("/").replace("/", "_")
            local = local_dir / name
            if sess.download(remote, str(local), timeout=180):
                saved.append(str(local))
        # 现场快照：进程、网络、账号、持久化 —— 溯源必备
        snap = sess.exec(
            "echo '== ps =='; ps auxww 2>/dev/null | head -120;"
            "echo '== netstat =='; (ss -antp || netstat -antp) 2>/dev/null | head -80;"
            "echo '== passwd =='; cat /etc/passwd;"
            "echo '== shadow-uid0 =='; awk -F: '$3==0{print $1}' /etc/passwd;"
            "echo '== crontab =='; for f in /var/spool/cron/* /etc/cron.d/*; do [ -f \"$f\" ] && echo \"--$f\" && cat \"$f\"; done 2>/dev/null;"
            "echo '== last =='; last -n 30 2>/dev/null;"
            "echo '== tmp =='; ls -la /tmp /dev/shm 2>/dev/null | head -60",
            timeout=90)
        snap_path = local_dir / "_snapshot.txt"
        snap_path.write_text(snap.text, encoding="utf-8")
        saved.append(str(snap_path))
    console.print(f"  [dim]已拉取 {len(saved)} 个文件 -> {local_dir}[/dim]")
    return saved

"""流量分析：tshark 驱动的 pcap 研判。

只做只读解析，绝不改写原始 pcap；导出对象落 evidence/pcap/<name>/ 便于二次取证。
"""

from __future__ import annotations

import base64
import pathlib
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import Config
from .flag import extract_flags
from .scan import Finding
from .util import console, human_size, trunc, which, warn

BAD_UA = ["sqlmap", "nikto", "nmap scripting", "masscan", "zgrab", "nuclei",
          "dirsearch", "gobuster", "ffuf", "xray", "awvs", "acunetix", "python-requests"]
SHELL_PORTS = {4444, 5555, 1337, 8888, 9001, 31337, 12345, 6666}


@dataclass
class TrafficReport:
    path: str = ""
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, object] = field(default_factory=dict)
    timeline: List[str] = field(default_factory=list)
    http: List[Dict[str, str]] = field(default_factory=list)
    ai_text: str = ""
    export_dir: str = ""

    def text(self) -> str:
        parts = [f"# 流量分析 {self.path}", ""]
        for k, v in self.stats.items():
            parts.append(f"- {k}: {v}")
        if self.timeline:
            parts.append("\n## 疑似攻击时序")
            parts.extend(f"- {t}" for t in self.timeline[:60])
        if self.findings:
            parts.append("\n## 发现")
            for f in self.findings:
                parts.append(f"- [{f.severity}] {f.title} | {f.location} | {f.detail}")
        if self.ai_text:
            parts.append("\n## AI 研判\n" + self.ai_text)
        return "\n".join(parts)


def _tshark(cfg: Config, args: List[str], timeout: int = 900) -> str:
    binary = which("tshark") or "tshark"
    cmd = [binary, "-n"] + args
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        warn("tshark 未安装：brew install wireshark")
        return ""
    except subprocess.TimeoutExpired:
        warn("tshark 执行超时")
        return ""


def analyze_pcap(cfg: Config, path: str, ai: bool = True, log=None) -> TrafficReport:
    """log(msg, level)：可选进度回调。18MB 的包带 AI 要跑 3 分钟，
    中间一条日志都没有的话，人只会以为卡死了。"""
    def say(msg: str, level: str = "info") -> None:
        if not log:
            return
        try:
            log(msg, level)
        except TypeError:
            log(msg)

    p = pathlib.Path(path).expanduser()
    rep = TrafficReport(path=str(p))
    if not p.exists():
        rep.findings.append(Finding(p.name, "pcap 不存在", "info", "pcap"))
        return rep
    size = p.stat().st_size
    rep.stats["文件大小"] = human_size(size)

    # 1) 协议分布
    say("读协议分布 ...")
    phs = _tshark(cfg, ["-r", str(p), "-q", "-z", "io,phs"], timeout=900)
    rep.stats["协议层级"] = trunc(phs, 1200) if phs else "N/A"

    # 2) HTTP 请求
    fields = ["frame.time", "ip.src", "ip.dst", "tcp.dstport",
              "http.request.method", "http.request.uri", "http.host",
              "http.user_agent", "http.response.code"]
    raw = _tshark(cfg, ["-r", str(p), "-Y", "http.request", "-T", "fields",
                        "-E", "separator=|", "-E", "occurrence=f"]
                  + sum([["-e", f] for f in fields], []), timeout=1200)
    reqs: List[Dict[str, str]] = []
    for line in raw.splitlines():
        cols = (line.split("|") + [""] * len(fields))[:len(fields)]
        rec = dict(zip(fields, cols))
        if rec.get("http.request.method"):
            reqs.append(rec)
    rep.http = reqs[:800]
    rep.stats["HTTP 请求数"] = len(reqs)
    say(f"HTTP 请求 {len(reqs)} 条", "ok" if reqs else "warn")

    src_counter: Counter = Counter()
    uri_hits: List[Tuple[str, str, str, str]] = []
    for r in reqs:
        src = r.get("ip.src", "")
        src_counter[src] += 1
        uri = r.get("http.request.uri", "")
        ua = (r.get("http.user_agent") or "").lower()
        full = f"{r.get('ip.src')} -> {r.get('http.host')}{uri}"
        if any(b in ua for b in BAD_UA):
            uri_hits.append((src, "扫描器/工具 UA", "high", f"{full} UA={ua[:50]}"))
        if re.search(r"(union\s+select|information_schema|sleep\(\d|benchmark\()", uri, re.I):
            uri_hits.append((src, "SQL 注入", "critical", full))
        if re.search(r"(\.\./|%2e%2e)", uri, re.I):
            uri_hits.append((src, "路径穿越", "high", full))
        if re.search(r"(cmd|exec|shell)=|whoami|uname", uri, re.I):
            uri_hits.append((src, "命令执行", "critical", full))
        if re.search(r"\.(php|jsp|aspx?)$", uri, re.I) and r.get("http.request.method") == "POST":
            uri_hits.append((src, "动态脚本 POST（疑似上传/webshell）", "high", full))
        if re.search(r"(flag|\.git|\.env|backup|www\.zip)", uri, re.I):
            uri_hits.append((src, "敏感目标访问", "medium", full))

    # 3) 爆破 / 扫描判定（SYN 计数）
    say("统计 SYN 判断扫描/爆破 ...")
    syn = _tshark(cfg, ["-r", str(p), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
                        "-T", "fields", "-e", "ip.src", "-e", "tcp.dstport"], timeout=900)
    syn_map: Dict[str, Counter] = defaultdict(Counter)
    for line in syn.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            syn_map[parts[0]][parts[1]] += 1
    for src, ports in sorted(syn_map.items(), key=lambda kv: -sum(kv[1].values()))[:8]:
        total = sum(ports.values())
        if len(ports) >= 50:
            rep.findings.append(Finding(p.name, f"端口扫描 {src}（{len(ports)} 个端口）",
                                        "high", "pcap",
                                        detail=f"SYN {total}，Top: {dict(ports.most_common(8))}",
                                        location=src, tags=["scan"]))
            rep.timeline.append(f"[扫描] {src} 探测 {len(ports)} 个端口")

    # 4) 凭据泄露
    say("查明文凭据（Basic / FTP）...")
    auth_raw = _tshark(cfg, ["-r", str(p), "-Y", "http.authorization",
                             "-T", "fields", "-e", "ip.src", "-e", "http.authorization",
                             "-e", "http.host"], timeout=600)
    seen_cred = set()
    for line in auth_raw.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and "basic" in parts[1].lower():
            try:
                dec = base64.b64decode(parts[1].split()[-1]).decode("utf-8", "replace")
            except Exception:
                continue
            key = (parts[0], dec)
            if key in seen_cred:
                continue
            seen_cred.add(key)
            rep.findings.append(Finding(p.name, "HTTP Basic 凭据泄露", "high", "pcap",
                                        detail=f"{parts[0]} -> {parts[2] if len(parts) > 2 else ''}: {dec}",
                                        location=parts[0]))
        if len(seen_cred) >= 20:
            break
    ftp = _tshark(cfg, ["-r", str(p), "-Y", "ftp.request.command==\"PASS\"",
                        "-T", "fields", "-e", "ip.src", "-e", "ftp.request.arg"], timeout=600)
    for line in ftp.splitlines()[:20]:
        if line.strip():
            rep.findings.append(Finding(p.name, "FTP 明文口令", "high", "pcap",
                                        detail=line.replace("\t", " PASS ")))

    # 5) 可疑端口（反弹 shell）
    ports_raw = _tshark(cfg, ["-r", str(p), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
                              "-T", "fields", "-e", "tcp.dstport"], timeout=600)
    pcount = Counter(x.strip() for x in ports_raw.splitlines() if x.strip())
    for port, n in pcount.items():
        try:
            if int(port) in SHELL_PORTS and n > 2:
                rep.findings.append(Finding(p.name, f"疑似反弹 shell 端口 {port}", "high",
                                            "pcap", detail=f"连接尝试 {n} 次"))
        except ValueError:
            continue

    # 6) HTTP 响应体里的 flag：默认直接读字段、不落盘
    #    以前是 --export-objects 导出全部对象再清理，一个 19MB 的包能导出 4 万多个文件、
    #    占 200MB+，而且清理时的成批 unlink 会被宿主的安全删除守卫打断，线程直接死掉
    #    （表现就是任务永远 running）。所以默认走"读 http.file_data 扫一遍"，
    #    需要人工翻文件时再用 cfg.extra.export_objects: true 打开导出。
    flags = set()
    rep.export_dir = ""
    say("扫响应体里的 flag（不落盘）...")
    bodies = _tshark(cfg, ["-r", str(p), "-Y", "http.file_data", "-T", "fields",
                           "-e", "ip.src", "-e", "http.content_type",
                           "-e", "http.file_data"], timeout=1800)
    scanned = 0
    for line in bodies.splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or not parts[-1].strip():
            continue
        try:
            raw = bytes.fromhex(parts[-1].replace(":", ""))
        except ValueError:
            continue
        scanned += 1
        for fl in extract_flags(raw.decode("utf-8", "replace"), cfg, limit=5):
            if fl in flags:
                continue
            flags.add(fl)
            rep.findings.append(Finding(p.name, "流量中提取到 flag", "critical", "pcap",
                                        evidence=fl,
                                        location=f"{parts[0]} {parts[1][:40]}"))
    if scanned:
        rep.stats["响应体扫描"] = f"{scanned} 段（不落盘）"

    if cfg.extra.get("export_objects"):
        export_dir = cfg.evidence_dir / "pcap" / p.stem
        export_dir.mkdir(parents=True, exist_ok=True)
        _tshark(cfg, ["-r", str(p), "--export-objects", f"http,{export_dir}"], timeout=2400)
        kept_files, skipped_n = _prune_objects(
            export_dir,
            max_files=int(cfg.extra.get("max_objects", 3000)),
            max_bytes=int(cfg.extra.get("max_objects_bytes", 200 << 20)))
        rep.stats["导出对象"] = (f"共 {len(kept_files) + skipped_n} 个，扫描前 {len(kept_files)} 个"
                                 f"（全部保留在 evidence/pcap/{p.stem}/）")
        rep.export_dir = str(export_dir)
        for f in kept_files:
            try:
                data = f.read_bytes()[:2_000_000]
            except Exception:
                continue
            for fl in extract_flags(data.decode("utf-8", "replace"), cfg, limit=5):
                if fl in flags:
                    continue
                flags.add(fl)
                rep.findings.append(Finding(p.name, "流量中提取到 flag", "critical", "pcap",
                                            evidence=fl, location=str(f)))

    # 7) flag 全文搜索（含 tcp 流重组）
    stream_flags = _search_flags_in_streams(cfg, p)
    flags.update(stream_flags)

    # 8) 聚合发现
    agg: Dict[Tuple[str, str], int] = Counter()
    for src, label, sev, sample in uri_hits:
        agg[(src, label)] += 1
    for (src, label), n in agg.most_common(20):
        sev = next((s for a, l, s, _ in uri_hits if a == src and l == label), "medium")
        samples = [s for a, l, _, s in uri_hits if a == src and l == label][:3]
        rep.findings.append(Finding(p.name, f"{label} @ {src}（{n} 次）", sev, "pcap",
                                    evidence="\n".join(samples), location=src))
        rep.timeline.append(f"[{label}] {src} {samples[0] if samples else ''}")

    if src_counter:
        rep.stats["Top 请求源"] = dict(src_counter.most_common(8))
    if any("扫描" in f.title for f in rep.findings):
        rep.stats["判定"] = "存在扫描行为，疑似渗透测试/攻击前期"

    # 9) AI
    if ai:
        say("AI 研判中（本地模型可能要 1-3 分钟）...")
        try:
            from .aiclient import AIClient
            client = AIClient(cfg)
            brief = "\n".join([
                f"文件: {p.name} ({human_size(size)})",
                "协议统计:\n" + trunc(phs, 800),
                "可疑请求:\n" + "\n".join(f"- {s}" for s in rep.timeline[:40]),
                "发现:\n" + "\n".join(f"- [{f.severity}] {f.title} {f.detail[:120]}"
                                     for f in rep.findings[:30]),
            ])
            res = client.analyze_pcap(brief)
            rep.ai_text = res.text if res.ok else ""
        except Exception:
            rep.ai_text = ""
    return rep


def _search_flags_in_streams(cfg: Config, p: pathlib.Path, limit: int = 40) -> List[str]:
    """对 TCP 流做 follow 重组后匹配 flag。"""
    raw = _tshark(cfg, ["-r", str(p), "-q", "-z", "follow,tcp,ascii,0"], timeout=600)
    found = extract_flags(raw, cfg, limit=limit)
    if found:
        return found
    # 再扫一遍 http 流
    out = _tshark(cfg, ["-r", str(p), "-Y", "http", "-T", "fields", "-e", "http.file_data"],
                  timeout=900)
    return extract_flags(out, cfg, limit=limit)


HIGH_VALUE_EXT = {".php", ".jsp", ".jspx", ".asp", ".aspx", ".zip", ".tar", ".gz",
                  ".sql", ".txt", ".log", ".conf", ".env", ".bak", ".doc", ".docx",
                  ".xls", ".xlsx", ".pdf", ".png", ".jpg", ".jpeg", ".key", ".pem"}


def _prune_objects(d: pathlib.Path, max_files: int = 3000,
                  max_bytes: int = 200 << 20) -> Tuple[List[pathlib.Path], int]:
    """从导出的 HTTP 对象里挑出"值得扫 flag"的那批。

    导出的对象可能上万（每个穿越请求一个文件），但**这里不删任何文件**：
    一来删除是纯副作用，二来成批 unlink 会被宿主的安全删除守卫拦掉，
    整个分析线程会被打断（表现为任务永远停在 running）。
    所以改成"只挑选不删除"：返回 (要扫的文件, 跳过的数量)，文件留在
    evidence/pcap/<name>/ 供人工翻。
    """
    files = [f for f in d.iterdir() if f.is_file()]
    if not files:
        return [], 0

    def score(f: pathlib.Path) -> Tuple[int, int]:
        ext = f.suffix.lower()
        return (0 if ext in HIGH_VALUE_EXT else 1, -(f.stat().st_size))

    files.sort(key=score)
    kept: List[pathlib.Path] = []
    total = 0
    for f in files:
        try:
            sz = f.stat().st_size
        except OSError:
            continue
        if len(kept) >= max_files or total + sz > max_bytes:
            continue
        kept.append(f)
        total += sz
    return kept, len(files) - len(kept)


def pcap_overview(path: str) -> str:
    p = pathlib.Path(path).expanduser()
    if not p.exists():
        return "文件不存在"
    return f"{p.name} {human_size(p.stat().st_size)}"

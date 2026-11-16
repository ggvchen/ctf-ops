"""资产与漏洞扫描：nmap / nuclei / HTTP 指纹，结果统一成 Finding。"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from .config import Config, Target
from .util import console, pmap, which

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}


@dataclass
class Finding:
    target: str
    title: str
    severity: str = "info"
    kind: str = "scan"           # port | vuln | web | exploit | log | pcap
    detail: str = ""
    evidence: str = ""
    location: str = ""           # host:port / url / file:line
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "title": self.title, "severity": self.severity,
            "kind": self.kind, "detail": self.detail, "evidence": self.evidence[:4000],
            "location": self.location, "tags": self.tags,
        }


# --------------------------------------------------------------------- nmap
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 3306: "mysql", 3389: "rdp", 4444: "shell", 5432: "postgres",
    5601: "kibana", 5672: "rabbitmq", 5900: "vnc", 6379: "redis",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}
RISKY_PORTS = {2375, 6379, 11211, 27017, 9200, 9000, 4444, 5900, 21, 23}


def tool_ok(binary: str, expect: str = "") -> tuple:
    """判断工具是否真的能跑（识别 OrbStack/Docker 包装器失效的情况）。"""
    try:
        r = subprocess.run([binary, "--version"] if "nuclei" not in binary
                           else [binary, "-version"],
                           capture_output=True, timeout=8)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
        if "docker API" in out or "docker.sock" in out:
            return False, "是 Docker 包装器但 Docker 未启动"
        if r.returncode != 0 and not out.strip():
            return False, f"退出码 {r.returncode}"
        if expect and expect.lower() not in out.lower():
            return False, out.splitlines()[0][:80] if out.strip() else "无输出"
        return True, out.splitlines()[0][:80] if out.strip() else "ok"
    except FileNotFoundError:
        return False, "未安装"
    except subprocess.TimeoutExpired:
        return False, "执行超时"
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:80]


def parse_port_spec(spec: str) -> List[int]:
    ports: List[int] = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                ports.extend(range(int(a), min(int(b), 65535) + 1))
            except ValueError:
                continue
        elif part.isdigit():
            ports.append(int(part))
        elif part.lower() in ("top", "common"):
            ports.extend(COMMON_SERVICES.keys())
    return sorted(set(p for p in ports if 0 < p < 65536))


def python_port_scan(host: str, ports: List[int], timeout: float = 0.6,
                     workers: int = 400) -> List[int]:
    """无 nmap 时的纯 TCP connect 扫描（不需要 root）。"""
    import socket

    def probe(port: int) -> Optional[int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return port if s.connect_ex((host, port)) == 0 else None
        except Exception:
            return None
        finally:
            s.close()

    res = pmap(probe, ports, workers=workers)
    return sorted(p for p in res if isinstance(p, int))


def banner_grab(host: str, port: int, timeout: float = 1.5) -> str:
    import socket

    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        except Exception:
            pass
        try:
            data = s.recv(256)
        except Exception:
            data = b""
        s.close()
        return data.decode("utf-8", "replace").strip().splitlines()[0][:120] if data else ""
    except Exception:
        return ""


def nmap_scan(cfg: Config, targets: List[Target], ports: Optional[str] = None,
              extra: Optional[List[str]] = None, workers: int = 4) -> Dict[str, List[Finding]]:
    binary = cfg.scan.nmap if os.path.sep in cfg.scan.nmap else (which(cfg.scan.nmap) or cfg.scan.nmap)
    ports = ports or cfg.scan.nmap_top_ports
    ok_tool, why = tool_ok(binary, "Nmap")
    out: Dict[str, List[Finding]] = {}

    if not ok_tool:
        console.print(f"[yellow]![/yellow] nmap 不可用（{why}），回退到内置 TCP 扫描")
        return fallback_scan(cfg, targets, ports, workers=min(8, len(targets) or 1))

    def one(t: Target) -> tuple:
        fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
        os.close(fd)
        args = [binary, "-sT", "-Pn", "-T4", "-p", ports, "--open",
                "-sV", "--version-light", "-oX", xml_path, t.host]
        args += extra or []
        try:
            r = subprocess.run(args, capture_output=True, timeout=1800)
            findings = parse_nmap_xml(xml_path, t.name)
            if not findings and os.path.getsize(xml_path) == 0:
                err = (r.stderr or b"").decode("utf-8", "replace")[:200]
                return t.name, [Finding(t.name, "nmap 无结果", "info", "scan",
                                        detail=err or f"rc={r.returncode}")]
            return t.name, findings
        except FileNotFoundError:
            return t.name, [Finding(t.name, "nmap 未安装", "info", "scan",
                                    detail="请安装 nmap 或修改 config.scan.nmap")]
        except subprocess.TimeoutExpired:
            return t.name, [Finding(t.name, "nmap 超时", "low", "scan", location=t.host)]
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

    for name, findings in pmap(one, targets, workers=max(1, workers), label="nmap"):
        if isinstance(findings, Exception):
            out[str(name)] = [Finding(str(name), f"nmap 异常: {findings}", "low", "scan")]
        else:
            out[name] = findings
    return out


def fallback_scan(cfg: Config, targets: List[Target], ports: str,
                  workers: int = 8) -> Dict[str, List[Finding]]:
    """内置扫描：TCP connect + 轻量 banner，nmap 缺失时兜底。"""
    port_list = parse_port_spec(ports)
    if len(port_list) > 20000:
        console.print(f"[yellow]![/yellow] 端口数 {len(port_list)} 较多，回退扫描将较慢")
    out: Dict[str, List[Finding]] = {}

    def one(t: Target) -> tuple:
        open_ports = python_port_scan(t.host, port_list,
                                      timeout=cfg.extra.get("connect_timeout", 0.6),
                                      workers=int(cfg.extra.get("connect_workers", 400)))
        findings: List[Finding] = []
        for p in open_ports:
            svc = COMMON_SERVICES.get(p, "")
            banner = banner_grab(t.host, p) if p in COMMON_SERVICES or p < 10000 else ""
            sev = "high" if p in RISKY_PORTS else ("medium" if p in (3306, 5432, 6379, 27017) else "info")
            findings.append(Finding(
                target=t.name,
                title=f"开放端口 {p}/tcp {svc}".strip(),
                severity=sev, kind="port",
                detail=banner or svc,
                location=f"{t.host}:{p}",
                tags=[svc] if svc else []))
        if not findings:
            findings.append(Finding(t.name, "未发现开放端口", "info", "scan",
                                    detail=f"扫描 {len(port_list)} 个端口（内置引擎）"))
        return t.name, findings

    for name, findings in pmap(one, targets, workers=max(1, workers), label="tcp-scan"):
        out[name] = ([Finding(str(name), f"扫描异常: {findings}", "low", "scan")]
                     if isinstance(findings, Exception) else findings)
    return out


def parse_nmap_xml(path: str, target_name: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return findings
    for host in root.findall("host"):
        addr_el = host.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else ""
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pnum = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            extra = svc.get("extrainfo", "") if svc is not None else ""
            banner = " ".join(x for x in (product, version, extra) if x).strip()
            sev = "info"
            if pnum in ("6379", "27017", "9200", "11211", "3306", "5432", "2375", "9000"):
                sev = "medium"
            if pnum in ("2375", "11211", "6379") and not banner:
                sev = "high"
            findings.append(Finding(
                target=target_name,
                title=f"开放端口 {pnum}/{proto} {name}".strip(),
                severity=sev, kind="port",
                detail=banner or name,
                location=f"{host_addr}:{pnum}",
                tags=[name] if name else []))
    return findings


# ------------------------------------------------------------------- nuclei
NUCLEI_SEV = {"critical": "critical", "high": "high", "medium": "medium",
              "low": "low", "info": "info", "unknown": "info"}


def is_docker_wrapper(binary: str) -> bool:
    """判断这个"可执行文件"是不是 docker exec 包装脚本。

    本机就是这样：nuclei 进 redteam-kali 容器执行，于是容器里的 127.0.0.1
    是容器自己，扫不到宿主上的靶机——必须换成 host.docker.internal。
    """
    try:
        if not os.path.isfile(binary):
            return False
        head = open(binary, "rb").read(600)
        return b"docker exec" in head or b"docker run" in head
    except OSError:
        return False


def rewrite_for_container(url: str) -> str:
    for loop in ("127.0.0.1", "localhost", "0.0.0.0"):
        url = url.replace(f"//{loop}", "//host.docker.internal")
    return url


def nuclei_scan(cfg: Config, urls: List[str], target_map: Dict[str, str],
                severity: Optional[str] = None, templates: Optional[str] = None,
                workers: int = 4, tags: Optional[str] = None) -> List[Finding]:
    binary = cfg.scan.nuclei if os.path.sep in cfg.scan.nuclei else (which(cfg.scan.nuclei) or cfg.scan.nuclei)
    if not urls:
        return []
    ok_tool, why = tool_ok(binary, "nuclei")
    if not ok_tool:
        return [Finding("all", "nuclei 不可用", "info", "scan",
                        detail=f"{why}；请安装 nuclei 或改用 exploit 插件手工验证")]
    args = [binary, "-jsonl", "-silent", "-nc",
            "-severity", severity or cfg.scan.nuclei_severity,
            "-rl", "80", "-timeout", "8", "-retries", "1"]
    if templates:
        args += ["-t", templates]
    else:
        use_tags = tags if tags is not None else (cfg.scan.nuclei_tags or "")
        if use_tags:
            args += ["-tags", use_tags]
    args += cfg.scan.nuclei_extra_args
    findings: List[Finding] = []
    scan_urls = list(urls)
    back: Dict[str, str] = {}
    if is_docker_wrapper(binary):
        scan_urls = [rewrite_for_container(u) for u in urls]
        back = {rewrite_for_container(u): u for u in urls}
    try:
        # 结果走 stdout：-o 写的是"执行侧"的路径，当 nuclei 是 docker 包装器时
        # （容器内 /root），宿主机读不到那个文件，会静默得到 0 条结果
        proc = subprocess.run(args, input="\n".join(scan_urls).encode(),
                              capture_output=True, timeout=2400)
        if True:
            for line in (proc.stdout or b"").decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = rec.get("host") or ""
                matched = rec.get("matched-at") or rec.get("url") or host
                # 还原成用户配置里的地址，报告里别出现 host.docker.internal
                for k, v in back.items():
                    if k and k in (host, matched):
                        host = host.replace(k, v) if k in host else host
                        matched = matched.replace(k, v) if k in matched else matched
                if host.startswith("host.docker.internal"):
                    host = "http://" + host
                tname = target_map.get(host) or _owner(target_map, matched) or host
                info = rec.get("info") or {}
                sev = NUCLEI_SEV.get(str(info.get("severity", "info")).lower(), "info")
                findings.append(Finding(
                    target=tname,
                    title=info.get("name") or rec.get("template-id", "nuclei"),
                    severity=sev, kind="vuln",
                    detail="; ".join(info.get("tags") or []) if isinstance(info.get("tags"), list) else str(info.get("tags", "")),
                    evidence=(rec.get("extracted-results") and
                              json.dumps(rec["extracted-results"], ensure_ascii=False)) or
                             (rec.get("matcher-name") or ""),
                    location=matched,
                    tags=[rec.get("template-id", "")]))
    except FileNotFoundError:
        findings.append(Finding("all", "nuclei 未安装", "info", "scan",
                                detail="请安装 nuclei 或修改 config.scan.nuclei"))
    except subprocess.TimeoutExpired:
        findings.append(Finding("all", "nuclei 扫描超时", "low", "scan"))
    return findings


def _owner(target_map: Dict[str, str], url: str) -> Optional[str]:
    for host, name in target_map.items():
        if host and host in (url or ""):
            return name
    return None


# ---------------------------------------------------------------------- web
INTERESTING = {
    "/.git/config": ("Git 源码泄露", "high"),
    "/.svn/entries": ("SVN 泄露", "medium"),
    "/.env": ("环境变量泄露(.env)", "high"),
    "/backup.zip": ("备份文件可下载", "high"),
    "/www.zip": ("站点源码包可下载", "high"),
    "/phpinfo.php": ("phpinfo 暴露", "medium"),
    "/actuator/env": ("Spring Actuator 暴露", "high"),
    "/console": ("管理控制台暴露", "medium"),
    "/server-status": ("Apache status 暴露", "low"),
    "/admin/": ("后台入口", "info"),
    "/robots.txt": ("robots.txt", "info"),
    "/flag": ("疑似 flag 路径", "info"),
    "/flag.txt": ("疑似 flag 文件", "info"),
}


def _body_sig(content: bytes) -> str:
    import hashlib
    return hashlib.sha256((content or b"")[:65536]).hexdigest()[:16]


def soft_404_baseline(sess: requests.Session, base: str, timeout: int) -> Dict[str, object]:
    """取一个"肯定不存在"的路径作为基准响应。

    框架站点（ThinkPHP/Laravel/Spring）常把所有路径重写到 index.php，
    于是 /anything 都返回 200——不比对基准就会把 13 个敏感路径全报一遍。
    """
    import uuid
    rnd = f"/ctfops-{uuid.uuid4().hex[:10]}-not-found"
    try:
        r = sess.get(urljoin(base, rnd), timeout=timeout, allow_redirects=True)
    except Exception:  # noqa: BLE001
        return {}
    return {"status": r.status_code, "len": len(r.content or b""),
            "sig": _body_sig(r.content or b""), "url": r.url}


def web_probe(cfg: Config, target: Target, timeout: Optional[int] = None) -> List[Finding]:
    findings: List[Finding] = []
    timeout = timeout or cfg.scan.http_timeout
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; ctf-ops/1.0)"
    sess.verify = False
    sess.trust_env = False        # 靶机直连，避免被 HTTP_PROXY 劫持
    for base in target.web:
        try:
            r = sess.get(base, timeout=timeout, allow_redirects=True)
        except Exception as e:  # noqa: BLE001
            findings.append(Finding(target.name, "Web 不可达", "info", "web",
                                    detail=str(e), location=base))
            continue
        server = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        findings.append(Finding(
            target.name, f"Web 存活 {r.status_code}", "info", "web",
            detail=f"Server={server} X-Powered-By={powered} title={title}",
            location=r.url,
            tags=[x for x in (server, powered) if x]))
        # 前端线索：注释里的 hint / 表单 / 上传点
        hints = re.findall(r"<!--(.*?)-->", r.text or "", re.S)
        for h in hints[:20]:
            h = h.strip()
            if len(h) > 4 and re.search(r"(?i)(flag|todo|hint|admin|pass|debug|api)", h):
                findings.append(Finding(target.name, "页面注释含线索", "low", "web",
                                        evidence=h[:500], location=r.url))
        if re.search(r"<input[^>]+type=[\"']?file", r.text or "", re.I):
            findings.append(Finding(target.name, "存在文件上传点", "medium", "web",
                                    evidence=_snippet(r.text, r"<form.{0,400}", re.I),
                                    location=r.url))

        base_info = soft_404_baseline(sess, base, timeout)
        if base_info and base_info.get("status") == 200:
            findings.append(Finding(target.name, "站点使用统一路由（软 404 过滤已启用）", "info",
                                    "web", detail="任意路径都返回同样内容，敏感路径按响应相似度过滤",
                                    location=base))

        def probe(path_sev: tuple) -> List[Finding]:
            path, (label, sev) = path_sev
            url = urljoin(base, path)
            try:
                rr = sess.get(url, timeout=timeout, allow_redirects=False)
            except Exception:
                return []
            if rr.status_code in (200, 301, 302, 403) and len(rr.content or b"") > 0:
                if rr.status_code == 404:
                    return []
                # 软 404：状态码相同、且响应体一致或长度几乎一样 → 不是真的存在
                if base_info:
                    same_status = rr.status_code == base_info.get("status")
                    same_body = _body_sig(rr.content or b"") == base_info.get("sig")
                    blen = int(base_info.get("len") or 0)
                    near = blen > 0 and abs(len(rr.content or b"") - blen) <= max(32, blen * 0.02)
                    if same_status and (same_body or near):
                        return []
                detail = f"HTTP {rr.status_code} len={len(rr.content)}"
                if path in ("/flag", "/flag.txt") and rr.status_code == 200:
                    from .flag import extract_flags
                    got = extract_flags(rr.text or "", cfg)
                    if got:
                        detail += f" 捕获: {', '.join(got)}"
                return [Finding(target.name, label, sev, "web", detail=detail,
                                evidence=_snippet(rr.text, r".{0,300}")[:600], location=url)]
            return []

        for f in pmap(probe, list(INTERESTING.items()), workers=6):
            if isinstance(f, Exception):
                continue
            findings.extend(f)
    return findings


def _snippet(text: str, pattern: str, flags: int = 0) -> str:
    m = re.search(pattern, text or "", flags | re.S)
    return re.sub(r"\s+", " ", m.group(0)).strip() if m else ""


def urls_of(targets: List[Target]) -> List[str]:
    urls: List[str] = []
    for t in targets:
        urls.extend(t.web or [])
    return list(dict.fromkeys(urls))


def target_map_of(targets: List[Target]) -> Dict[str, str]:
    m: Dict[str, str] = {}
    for t in targets:
        m[t.host] = t.name
        for u in t.web:
            h = urlparse(u)
            m[f"{h.scheme}://{h.netloc}"] = t.name
            m[h.netloc] = t.name
    return m


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.target, f.title))

"""WAF 传感器：默认"只监听"，不碰业务流量。

为什么做成日志旁路而不是反向代理：
- AWD 里把业务端口挪到代理后面，极易把服务搞挂，风险不可接受
- 访问日志里已经有完整的 攻击源 / 方法 / 路径 / UA / 状态码，足够识别攻击并留证
- 加固阶段再按需执行 iptables 封禁源 IP（或切换到 inline 代理，见 README 说明）

部署形态：单个 python3 脚本 + rules.json + config.json，跑在 /tmp/ctfops-waf，
通过 SIGHUP 热重载规则，因此"一键加固"不需要重启业务。
"""

from __future__ import annotations

import json
import pathlib
import posixpath
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .config import Config, Target
from .sshx import SSHSession
from .util import console, trunc, warn

WAF_HOME = "/tmp/ctfops-waf"
# 封禁规则带 comment，撤销时只删自己加的，绝不 -F INPUT（那会把平台规则一起清掉）
BAN_CMD_DEFAULT = "iptables -I INPUT -s {ip} -j DROP -m comment --comment ctf-ops-ban"
AGENT_PHP = (pathlib.Path(__file__).parent / "agents" / "watchbird.php").read_text(encoding="utf-8")
GO_BIN_DIR = pathlib.Path(__file__).parent / "agents" / "bin"
PHP_AGENT_PATH = f"{WAF_HOME}/watchbird.php"
PHP_CFG_PATH = f"{WAF_HOME}/watchbird.json"
DEPLOYED_PATH = f"{WAF_HOME}/deployed.json"

# ------------------------------------------------------------------ 默认规则
DEFAULT_RULES: List[Dict[str, Any]] = [
    {"id": "sqli", "name": "SQL 注入", "severity": "critical", "scope": "url",
     "pattern": r"(?i)(union[\s/*]+select|information_schema|sleep\(\s*\d|benchmark\(|extractvalue\(|updatexml\(|'\s*or\s*'?\d)", "action": "monitor"},
    {"id": "traversal", "name": "路径穿越", "severity": "high", "scope": "url",
     "pattern": r"(?i)(\.\./|%2e%2e%2f|%252e%252e|/etc/passwd|/etc/shadow|win\.ini)", "action": "monitor"},
    {"id": "cmdi", "name": "命令注入", "severity": "critical", "scope": "url",
     "pattern": r"(?i)([;|&`]\s*(cat|ls|id|whoami|uname|curl|wget|nc|bash|sh)\b|\$\(|\b(cmd|exec|command|shell)=)", "action": "monitor"},
    {"id": "phpcode", "name": "PHP 代码注入", "severity": "critical", "scope": "url",
     "pattern": r"(?i)(eval|assert|system|passthru|shell_exec|popen)\s*\(", "action": "monitor"},
    {"id": "xss", "name": "XSS", "severity": "medium", "scope": "url",
     "pattern": r"(?i)(<script|%3cscript|onerror\s*=|onload\s*=|javascript:)", "action": "monitor"},
    {"id": "log4j", "name": "Log4j/JNDI", "severity": "critical", "scope": "any",
     "pattern": r"(?i)(\$\{jndi:|ldap://|rmi://)", "action": "monitor"},
    {"id": "webshell", "name": "webshell 访问", "severity": "critical", "scope": "url",
     "pattern": r"(?i)/(shell|cmd|c99|b374k|wso|upload)\.(php|jsp|aspx?)\b|\.(php|jsp)\?[a-z]{1,3}=", "action": "monitor"},
    {"id": "sensitive", "name": "敏感文件探测", "severity": "medium", "scope": "url",
     "pattern": r"(?i)(/\.git/|/\.svn/|/\.env|/\.DS_Store|/backup\.(zip|sql|tar|gz)|/www\.zip|/db\.sql)", "action": "monitor"},
    {"id": "scanner", "name": "扫描器 UA", "severity": "medium", "scope": "ua",
     "pattern": r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|dirsearch|gobuster|ffuf|xray|awvs|acunetix|nuclei)", "action": "monitor"},
    {"id": "ssrf", "name": "SSRF 探测", "severity": "high", "scope": "url",
     "pattern": r"(?i)(url|uri|target|dest|redirect)=(https?|file|gopher|dict)://", "action": "monitor"},
]

# ------------------------------------------------------------------ Agent 源码
AGENT_SRC = r'''#!/usr/bin/env python3
"""ctf-ops WAF agent —— 旁路日志传感器（只监听 / 加固封禁）。

用法: python3 agent.py --home /tmp/ctfops-waf
文件: config.json(运行参数) rules.json(规则) audit.jsonl(命中记录) status.json(状态) bans.txt(封禁)
信号: kill -HUP <pid> 热重载 config.json + rules.json
"""
import json
import os
import re
import signal
import subprocess
import sys
import time
from urllib.parse import unquote

HOME = "/tmp/ctfops-waf"
RELOAD = {"flag": False}

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>[^"]*?)'
    r'(?: [^"]*)?" (?P<status>\d{3}) (?P<size>\S+)(?: "[^"]*" "(?P<ua>[^"]*)")?')


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def on_hup(signum, frame):
    RELOAD["flag"] = True


class Agent:
    def __init__(self, home):
        self.home = home
        self.started = time.time()
        self.requests = 0
        self.matched = 0
        self.banned = 0
        self.bans = set()
        self.handles = {}
        self.rules = []
        self.cfg = {}
        self.dirty_status = 0
        self.reload()

    def reload(self):
        self.cfg = load_json(os.path.join(self.home, "config.json"), {})
        self.rules = load_json(os.path.join(self.home, "rules.json"), [])
        self.mode = self.cfg.get("mode", "monitor")
        self.autoban = bool(self.cfg.get("autoban"))
        self.ban_cmd = self.cfg.get("ban_cmd") or BAN_CMD_DEFAULT
        self.logs = self.cfg.get("logs") or []
        self.bans_path = os.path.join(self.home, "bans.txt")
        try:
            with open(self.bans_path, "r", encoding="utf-8") as f:
                self.bans = set(x.strip() for x in f if x.strip())
        except Exception:
            self.bans = set()

    def write_status(self):
        data = {
            "running": True, "pid": os.getpid(), "mode": self.mode,
            "autoban": self.autoban, "started": self.started,
            "uptime": round(time.time() - self.started, 1),
            "requests": self.requests, "matched": self.matched,
            "banned": self.banned, "logs": self.logs,
            "rules": len(self.rules), "version": 1,
        }
        tmp = os.path.join(self.home, "status.json.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            os.replace(tmp, os.path.join(self.home, "status.json"))
        except Exception:
            pass

    def audit(self, rec):
        try:
            with open(os.path.join(self.home, "audit.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def do_ban(self, ip):
        if not ip or ip in ("-", "127.0.0.1", "::1") or ip in self.bans:
            return
        cmd = self.ban_cmd.format(ip=ip)
        try:
            rc = subprocess.call(cmd, shell=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=8)
            if rc == 0:
                self.bans.add(ip)
                self.banned += 1
                with open(self.bans_path, "a", encoding="utf-8") as f:
                    f.write(ip + "\n")
        except Exception:
            pass

    def match(self, line, ip, method, path, ua, status):
        raw_url = path or ""
        # 解码一次不够就两次（%252e%252e 这类双层编码）
        hay_url = unquote(raw_url)
        for _ in range(2):
            again = unquote(hay_url)
            if again == hay_url:
                break
            hay_url = again
        hay_ua = ua or ""
        for r in self.rules:
            try:
                pat = re.compile(r["pattern"])
            except Exception:
                continue
            scope = r.get("scope", "any")
            hay = hay_url if scope == "url" else (hay_ua if scope == "ua"
                                                 else hay_url + " " + hay_ua)
            m = pat.search(hay)
            if not m:
                continue
            rec = {
                "ts": time.time(), "ip": ip, "method": method,
                "path": (path or "")[:1200], "ua": (hay_ua or "")[:300],
                "status": status, "rule_id": r.get("id", ""),
                "name": r.get("name", ""), "severity": r.get("severity", "medium"),
                "matched": m.group(0)[:200],
                "action": "block" if (r.get("action") == "block"
                                      and self.mode == "enforce") else "monitor",
            }
            self.matched += 1
            self.audit(rec)
            if rec["action"] == "block" and self.autoban:
                self.do_ban(ip)
            return rec
        return None

    def tail_once(self):
        for path in list(self.logs):
            fh = self.handles.get(path)
            try:
                if fh is None:
                    if not os.path.exists(path):
                        continue
                    fh = open(path, "r", encoding="utf-8", errors="replace")
                    fh.seek(0, os.SEEK_END)
                    self.handles[path] = fh
                lines = fh.readlines()
                if not lines:
                    continue
            except Exception:
                try:
                    fh.close()
                except Exception:
                    pass
                self.handles.pop(path, None)
                continue
            for line in lines[-500:]:
                m = LOG_RE.match(line.strip())
                if not m:
                    continue
                self.requests += 1
                self.match(line, m.group("ip"), m.group("method"),
                           m.group("path"), m.group("ua"), m.group("status"))

    def run(self):
        signal.signal(signal.SIGHUP, on_hup)
        self.write_status()
        last = 0
        while True:
            if RELOAD["flag"]:
                RELOAD["flag"] = False
                self.reload()
                self.write_status()
            try:
                self.tail_once()
            except Exception:
                pass
            now = time.time()
            if now - last > 2:
                self.write_status()
                last = now
            time.sleep(0.4)


if __name__ == "__main__":
    for i, a in enumerate(sys.argv):
        if a == "--home" and i + 1 < len(sys.argv):
            HOME = sys.argv[i + 1]
    Agent(HOME).run()
'''


@dataclass
class WafState:
    running: bool = False
    mode: str = ""
    requests: int = 0
    matched: int = 0
    banned: int = 0
    uptime: float = 0.0
    logs: Optional[List[str]] = None
    rules: int = 0
    engine: str = ""
    webroot: str = ""
    error: str = ""


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def guess_logs(sess: SSHSession) -> List[str]:
    """在靶机上猜访问日志路径。"""
    candidates = [
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
        "/var/log/nginx/access_log",
        "/www/wwwlogs/access.log",
    ]
    found = []
    for c in candidates:
        r = sess.exec(f"[ -f {_q(c)} ] && echo yes", timeout=10)
        if "yes" in r.out:
            found.append(c)
    if not found:
        r = sess.exec("ls -1 /var/log/nginx/*.log /var/log/apache2/*access* 2>/dev/null | head -5",
                      timeout=10)
        found = [x.strip() for x in r.out.splitlines() if x.strip()]
    return found


def detect_stack(sess: SSHSession, webroot: str) -> Dict[str, Any]:
    """探测站点技术栈，决定用哪个 agent（PHP 还是 python）。

    注意：只能用 ``ps -eo comm=``（纯进程名）。用 ``ps auxww`` 会把我们自己的
    shell 命令行也列出来，而那条命令里就写着 nginx/php-fpm 等关键字——
    结果每个站点的探测都"像"同时跑着 nginx 和 php-fpm（踩过这个坑）。
    """
    probe = sess.exec(
        "echo '###PROCS'; ps -eo comm= 2>/dev/null | tr -d ' ' | sort -u | head -60; "
        "echo '###BINS'; for b in python3 python php php-fpm php-fpm8.2 nginx apache2 httpd; do "
        "printf '%s=' \"$b\"; command -v \"$b\" 2>/dev/null || echo -; done; "
        "echo '###PHPVER'; php -v 2>/dev/null | head -1; "
        "echo '###LISTEN'; (ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null) | head -30; "
        "echo '###FILES'; find {w} -maxdepth 2 -type f -name '*.php' 2>/dev/null | head -5".format(
            w=_q(webroot)),
        timeout=30)
    out = probe.out or ""
    sections: Dict[str, List[str]] = {}
    cur = ""
    for line in out.splitlines():
        if line.startswith("###"):
            cur = line[3:].strip()
            sections[cur] = []
        elif cur:
            sections[cur].append(line.strip())

    procs = [x for x in sections.get("PROCS", []) if x]
    bins: Dict[str, str] = {}
    for line in sections.get("BINS", []):
        if "=" in line:
            name, path = line.split("=", 1)
            if path.strip() and path.strip() != "-":
                bins[name.strip()] = path.strip()

    listen = " ".join(sections.get("LISTEN", []))
    php_files = [x for x in sections.get("FILES", []) if x]

    has_index_php = bool(php_files)
    php = has_index_php or "php" in bins or any(p.startswith("php") for p in procs)
    # 只有真的起了 fpm 进程 / 监听 9000 才算 fpm；否则是 mod_php
    php_fpm = any("php-fpm" in p for p in procs) or ":9000" in listen
    apache = any(p in ("apache2", "httpd") for p in procs) or \
        ("apache2" in bins) or ("httpd" in bins)
    nginx = "nginx" in procs or "nginx" in bins
    py = bins.get("python3") or bins.get("python") or ""

    return {
        "webroot": webroot,
        "php": php,
        "php_fpm": php_fpm,
        "apache": apache,
        "nginx": nginx,
        "python3": py,
        "sapi": "php-fpm" if php_fpm else ("mod_php" if (php and apache) else ""),
        "php_version": (sections.get("PHPVER") or [""])[0],
        "files": php_files[:8],
        "php_files": php_files[:5],
        "procs": procs[:12],
    }


ARCH_MAP = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
            "i386": "386", "i686": "386", "armv7l": "arm"}


def detect_arch(sess: SSHSession) -> Dict[str, str]:
    r = sess.exec("uname -s; uname -m", timeout=10)
    lines = [x.strip() for x in (r.out or "").splitlines() if x.strip()]
    os_name = (lines[0] if lines else "").lower()
    machine = (lines[1] if len(lines) > 1 else "").lower()
    return {"os": "linux" if "linux" in os_name else ("darwin" if "darwin" in os_name else os_name),
            "arch": ARCH_MAP.get(machine, machine)}


def go_binary(os_name: str, arch: str) -> Optional[pathlib.Path]:
    p = GO_BIN_DIR / f"waf-go-{os_name}-{arch}"
    return p if p.is_file() else None


def _guess_webroot(sess: SSHSession, target: Target) -> str:
    from .backup import _remote_webroot
    return target.webroot or _remote_webroot(sess, target)


def _write_deployed(sess: SSHSession, payload: Dict[str, Any]) -> None:
    sess.write_file(DEPLOYED_PATH, json.dumps(payload, ensure_ascii=False, indent=1))


def _read_deployed(sess: SSHSession) -> Dict[str, Any]:
    raw = sess.exec(f"cat {DEPLOYED_PATH} 2>/dev/null", timeout=10).out or ""
    if raw.strip().startswith("{"):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    return {}


def deploy(cfg: Config, target: Target, logs: Optional[List[str]] = None,
           mode: str = "monitor", autoban: bool = False,
           extra_rules: Optional[List[Dict[str, Any]]] = None,
           engine: str = "auto") -> Dict[str, Any]:
    """按站点语言部署：PHP 站点用 watchbird，其它用 python 日志 agent。"""
    rules = list(DEFAULT_RULES)
    if extra_rules:
        ids = {r.get("id") for r in rules}
        rules += [r for r in extra_rules if r.get("id") not in ids]

    with SSHSession(target, cfg) as sess:
        webroot = _guess_webroot(sess, target)
        stack = detect_stack(sess, webroot)
        arch = detect_arch(sess)
        stack.update(arch)
        gobin = go_binary(arch["os"], arch["arch"])

        if engine in ("php", "python", "go"):
            chosen = engine
        elif gobin:
            chosen = "go"          # 免运行时，优先
        elif stack["php"]:
            chosen = "php"
        elif stack["python3"]:
            chosen = "python"
        else:
            chosen = ""

        if not chosen:
            return {"ok": False, "engine": "", "stack": stack,
                    "error": "该站点没有 PHP 运行时、没有 python3，且当前平台没有预编译的 "
                             f"Go agent（{arch['os']}/{arch['arch']}）；"
                             "可在本机执行 scripts/build-agents.sh 生成对应二进制"}
        if chosen == "go" and not gobin:
            return {"ok": False, "engine": "go", "stack": stack,
                    "error": f"没有 {arch['os']}/{arch['arch']} 的 Go agent 二进制，"
                             "请在本机跑 scripts/build-agents.sh"}

        if engine == "php" and not stack["php"]:
            return {"ok": False, "engine": "php", "stack": stack,
                    "error": "指定了 PHP 引擎，但没探测到 PHP 站点"}

        sess.exec(f"mkdir -p {WAF_HOME} && chmod 755 {WAF_HOME} && "
                  f"rm -f {WAF_HOME}/status.json {WAF_HOME}/php_status.json", timeout=15)
        sess.write_file(f"{WAF_HOME}/rules.json",
                        json.dumps(rules, ensure_ascii=False, indent=1))

        if chosen == "php":
            res = _deploy_php(sess, target, webroot, rules, mode, stack)
        elif chosen == "go":
            res = _deploy_go(sess, target, gobin, logs, mode, autoban, rules)
        else:
            res = _deploy_python(sess, target, logs, mode, autoban, rules)
        res.update({"engine": chosen, "stack": stack, "webroot": webroot})
        if res.get("ok"):
            _write_deployed(sess, {"engine": chosen, "mode": mode,
                                   "webroot": webroot, "logs": logs or [],
                                   "deployed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                   "php_ini": res.get("ini_path", "")})
        return res


def _deploy_python(sess: SSHSession, target: Target, logs: Optional[List[str]],
                   mode: str, autoban: bool, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    py = sess.exec("command -v python3 || command -v python 2>/dev/null", timeout=15)
    if not (py.out or "").strip():
        return {"ok": False, "error": "靶机没有 python3"}

    if not logs:
        logs = guess_logs(sess)
    if not logs:
        return {"ok": False, "error": "没找到访问日志，请手动指定 logs（如 /var/log/nginx/access.log）"}

    if not sess.write_file(f"{WAF_HOME}/agent.py", AGENT_SRC, perm=0o700):
        return {"ok": False, "error": "上传 agent 失败"}
    conf = {"mode": mode, "autoban": bool(autoban and mode == "enforce"),
            "ban_cmd": BAN_CMD_DEFAULT, "logs": logs}
    sess.write_file(f"{WAF_HOME}/config.json", json.dumps(conf, ensure_ascii=False, indent=1))

    sess.exec("pkill -f 'ctfops-waf/agent.py' 2>/dev/null; sleep 0.3; true", timeout=15)
    start = ("cd {h} && ( nohup python3 agent.py --home {h} "
             "</dev/null > agent.log 2>&1 & echo $! > {h}/agent.pid ) ; sleep 1.2; "
             "cat {h}/agent.pid 2>/dev/null").format(h=WAF_HOME)
    sess.exec(start, timeout=30)
    time.sleep(1.2)
    st = _read_status(sess)
    if not st.running:
        tail = sess.exec(f"tail -n 20 {WAF_HOME}/agent.log 2>/dev/null", timeout=10)
        return {"ok": False, "error": "agent 未起来", "log": trunc(tail.out, 1200)}
    return {"ok": True, "mode": st.mode, "logs": st.logs, "rules": st.rules}


def _deploy_go(sess: SSHSession, target: Target, binary: pathlib.Path,
               logs: Optional[List[str]], mode: str, autoban: bool,
               rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """上传静态二进制并启动（不依赖目标机任何运行时）。"""
    if not logs:
        logs = guess_logs(sess)
    if not logs:
        return {"ok": False, "error": "没找到访问日志，请手动指定 logs（如 /var/log/nginx/access.log）"}

    remote = f"{WAF_HOME}/waf-go"
    if not sess.upload(str(binary), remote, timeout=300):
        return {"ok": False, "error": "上传 Go agent 失败"}
    sess.exec(f"chmod 755 {remote}", timeout=10)

    conf = {"mode": mode, "autoban": bool(autoban and mode == "enforce"),
            "ban_cmd": BAN_CMD_DEFAULT, "logs": logs}
    sess.write_file(f"{WAF_HOME}/config.json", json.dumps(conf, ensure_ascii=False, indent=1))

    sess.exec("pkill -f 'ctfops-waf/waf-go' 2>/dev/null; sleep 0.3; true", timeout=15)
    start = ("cd {h} && ( nohup {h}/waf-go --home {h} </dev/null > go.log 2>&1 & "
             "echo $! > {h}/agent.pid ) ; sleep 1").format(h=WAF_HOME)
    sess.exec(start, timeout=30)
    time.sleep(1.0)
    st = _read_status(sess)
    if not st.running:
        tail = sess.exec(f"tail -n 20 {WAF_HOME}/go.log 2>/dev/null; "
                         f"file {remote} 2>/dev/null; uname -m", timeout=10)
        return {"ok": False, "error": "Go agent 未起来（架构不匹配？）",
                "log": trunc(tail.out, 1200)}
    return {"ok": True, "mode": st.mode, "logs": st.logs, "rules": st.rules}


def _deploy_php(sess: SSHSession, target: Target, webroot: str,
                rules: List[Dict[str, Any]], mode: str,
                stack: Dict[str, Any]) -> Dict[str, Any]:
    """装 watchbird.php，并挂到 auto_prepend_file。

    挂载方式取决于 SAPI，这个区别很关键：
      * **php-fpm / cgi**：`.user.ini` 有效（但受 user_ini.cache_ttl 缓存影响）
      * **mod_php（Apache）**：`.user.ini` **完全无效**，必须用 `.htaccess` 的 php_value
    """
    sapi = stack.get("sapi") or ("php-fpm" if stack.get("php_fpm") else "mod_php")
    if not sess.write_file(PHP_AGENT_PATH, AGENT_PHP, perm=0o644):
        return {"ok": False, "error": "上传 watchbird.php 失败"}
    conf = {"mode": mode, "started": int(time.time()), "webroot": webroot,
            "rules": rules}
    sess.write_file(PHP_CFG_PATH, json.dumps(conf, ensure_ascii=False))
    # PHP 以 www-data 跑，而 WAF_HOME 是 root 建的：不放开写权限，agent 只能"看"
    # 不能记（审计文件写不进去，表现就是"部署成功但一条命中都没有"）
    sess.exec(f"chmod 777 {WAF_HOME}; chmod 644 {PHP_AGENT_PATH} {PHP_CFG_PATH}; "
              f"touch {WAF_HOME}/audit.jsonl; chmod 666 {WAF_HOME}/audit.jsonl; "
              f"chmod 666 {PHP_CFG_PATH}", timeout=10)

    # 语法自检
    lint = sess.exec(f"php -l {PHP_AGENT_PATH} 2>&1 | head -3", timeout=15)
    lint_out = (lint.out or "").strip()
    if lint_out and "No syntax errors" not in lint_out:
        return {"ok": False, "error": f"watchbird.php 语法检查失败: {lint_out[:200]}"}

    ini_path = posixpath.join(webroot, ".user.ini")
    ht_path = posixpath.join(webroot, ".htaccess")
    written: List[str] = []
    problems: List[str] = []

    def ensure_line(path: str, anchor: str, line: str, header: str) -> bool:
        old = sess.read_file(path) or ""
        if anchor in old:
            return True
        new = (old.rstrip("\n") + "\n" if old.strip() else "")
        new += f"{header}{line}\n"
        if not sess.write_file(path, new, perm=0o644):
            problems.append(f"写入 {path} 失败")
            return False
        written.append(path)
        return True

    # 1) php-fpm / cgi：.user.ini
    if sapi != "mod_php":
        ensure_line(ini_path, "auto_prepend_file",
                    f"auto_prepend_file={PHP_AGENT_PATH}",
                    "; ctf-ops watchbird（只监听，不改业务逻辑）\n")
    # 2) mod_php：.htaccess（同时保留 .user.ini 兼容以后切到 fpm）
    if stack.get("apache"):
        ensure_line(ht_path, "auto_prepend_file",
                    f"php_value auto_prepend_file {PHP_AGENT_PATH}",
                    "\n# ctf-ops watchbird\n")
        if sapi == "mod_php":
            ensure_line(ini_path, "auto_prepend_file",
                        f"auto_prepend_file={PHP_AGENT_PATH}",
                        "; ctf-ops watchbird（mod_php 下不生效，切 fpm 时用）\n")

    if not written and problems:
        return {"ok": False, "error": "；".join(problems)}

    # 3) 真的跑一下：请求带 __wb_probe 应返回 WB_OK
    verify = sess.exec(
        "curl -s -m 5 'http://127.0.0.1/?__wb_probe=1' 2>/dev/null | head -c 40", timeout=20)
    verified = "WB_OK" in (verify.out or "")

    note = ""
    if not verified:
        tips = []
        if sapi == "mod_php":
            tips.append("Apache 需要 AllowOverride All 才会读 .htaccess")
        if sapi == "php-fpm":
            tips.append("PHP 对 .user.ini 有缓存（user_ini.cache_ttl 默认 300s），"
                        "可重载 php-fpm 加速生效")
        tips.append("也可确认 open_basedir 是否限制访问 /tmp/ctfops-waf")
        note = "自检未通过（可能需要重启 php-fpm/Apache 或调整配置）：" + "；".join(tips)

    # 报"真正生效的那个"文件，别让人以为改 .user.ini 就能调 mod_php
    effective = ht_path if sapi == "mod_php" else ini_path
    return {"ok": True, "mode": mode, "rules": len(rules), "sapi": sapi,
            "ini_path": effective,
            "htaccess": ht_path if ht_path in written else "",
            "written": written, "verified": verified, "note": note}


def _read_status(sess: SSHSession) -> WafState:
    deployed = _read_deployed(sess)
    engine = deployed.get("engine", "")
    if engine == "php":
        raw = sess.exec(f"cat {WAF_HOME}/php_status.json 2>/dev/null", timeout=10).out or ""
        if raw.strip().startswith("{"):
            d = json.loads(raw)
            return WafState(
                running=True, mode=d.get("mode", ""),
                requests=int(d.get("requests") or 0),
                matched=int(d.get("matched") or 0),
                banned=int(d.get("blocked") or 0),
                uptime=round(time.time() - float(d.get("started") or time.time()), 1),
                rules=int(d.get("rules") or 0), engine="php",
                webroot=d.get("webroot", ""))
        # 没有命中过就没有状态文件，只要配置在就算已部署
        exists = sess.exec(f"[ -f {PHP_CFG_PATH} ] && echo yes", timeout=10)
        if "yes" in (exists.out or ""):
            return WafState(running=True, mode=deployed.get("mode", "monitor"),
                            rules=len(DEFAULT_RULES), engine="php",
                            webroot=deployed.get("webroot", ""))
        return WafState(running=False, engine="php")

    raw = sess.exec(f"cat {WAF_HOME}/status.json 2>/dev/null", timeout=15)
    text = (raw.out or "").strip()
    if not text.startswith("{"):
        return WafState(running=False, engine=engine or "python")
    try:
        d = json.loads(text)
    except json.JSONDecodeError:
        return WafState(running=False)
    st = WafState(
        running=bool(d.get("running")),
        mode=d.get("mode", ""),
        requests=int(d.get("requests") or 0),
        matched=int(d.get("matched") or 0),
        banned=int(d.get("banned") or 0),
        uptime=float(d.get("uptime") or 0),
        logs=d.get("logs") or [],
        rules=int(d.get("rules") or 0),
        engine=d.get("engine") or "python",
        webroot="",
    )
    st.__dict__["pid"] = d.get("pid", 0)
    return st


def status(cfg: Config, target: Target) -> WafState:
    try:
        with SSHSession(target, cfg, retries=0) as sess:
            st = _read_status(sess)
            if not st.running or st.engine == "php":
                return st
            alive = sess.exec(f"[ -f {WAF_HOME}/agent.pid ] && kill -0 "
                              f"$(cat {WAF_HOME}/agent.pid) 2>/dev/null && echo alive", timeout=10)
            if "alive" not in alive.out:
                st.running = False
            return st
    except Exception as e:  # noqa: BLE001
        return WafState(error=str(e))


def read_audit(cfg: Config, target: Target, limit: int = 200) -> List[Dict[str, Any]]:
    try:
        with SSHSession(target, cfg, retries=0) as sess:
            r = sess.exec(f"tail -n {int(limit)} {WAF_HOME}/audit.jsonl 2>/dev/null", timeout=20)
            out = []
            for line in (r.out or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return out
    except Exception as e:  # noqa: BLE001
        warn(f"{target.name} 读取审计失败: {e}")
        return []


def enforce(cfg: Config, target: Target, rule_ids: Optional[List[str]] = None,
            autoban: bool = True) -> Dict[str, Any]:
    """切到加固模式：命中即封禁（python 版）或直接 403（php 版）。"""
    with SSHSession(target, cfg) as sess:
        deployed = _read_deployed(sess)
        engine = deployed.get("engine", "python")

        raw = sess.exec(f"cat {WAF_HOME}/rules.json 2>/dev/null", timeout=15).out or ""
        try:
            rules = json.loads(raw) if raw.strip().startswith("[") else list(DEFAULT_RULES)
        except json.JSONDecodeError:
            rules = list(DEFAULT_RULES)
        target_ids = set(rule_ids or [])
        for r in rules:
            if not target_ids or r.get("id") in target_ids:
                r["action"] = "block"
        sess.write_file(f"{WAF_HOME}/rules.json", json.dumps(rules, ensure_ascii=False, indent=1))

        blocked = [r["id"] for r in rules if r.get("action") == "block"]

        if engine == "php":
            conf = {"mode": "enforce", "started": int(time.time()),
                    "webroot": deployed.get("webroot", ""), "rules": rules}
            sess.write_file(PHP_CFG_PATH, json.dumps(conf, ensure_ascii=False))
            sess.exec(f"chmod 644 {PHP_CFG_PATH}", timeout=10)
            return {"ok": True, "engine": "php", "mode": "enforce",
                    "blocked_rules": blocked, "banned": 0,
                    "note": "PHP 版直接在请求内返回 403，不做 IP 封禁"}

        conf_raw = sess.exec(f"cat {WAF_HOME}/config.json 2>/dev/null", timeout=15).out or ""
        try:
            conf = json.loads(conf_raw) if conf_raw.strip().startswith("{") else {}
        except json.JSONDecodeError:
            conf = {}
        conf.update({"mode": "enforce", "autoban": bool(autoban)})
        sess.write_file(f"{WAF_HOME}/config.json", json.dumps(conf, ensure_ascii=False, indent=1))
        sess.exec(f"[ -f {WAF_HOME}/agent.pid ] && kill -HUP $(cat {WAF_HOME}/agent.pid)", timeout=10)
        time.sleep(0.8)
        st = _read_status(sess)
        return {"ok": st.running, "engine": engine or "python", "mode": st.mode,
                "banned": st.banned, "blocked_rules": blocked}


def stop(cfg: Config, target: Target, unban: bool = False) -> Dict[str, Any]:
    """停止 agent；PHP 版会把 .user.ini 里的 auto_prepend 摘掉。"""
    with SSHSession(target, cfg) as sess:
        deployed = _read_deployed(sess)
        engine = deployed.get("engine", "")
        if engine == "php":
            ini_path = deployed.get("php_ini") or ""
            if ini_path:
                old = sess.read_file(ini_path) or ""
                kept = [ln for ln in old.splitlines()
                        if not ln.strip().startswith("auto_prepend_file")
                        and "ctf-ops watchbird" not in ln]
                sess.write_file(ini_path, ("\n".join(kept).rstrip() + "\n") if kept else "")
            sess.exec(f"rm -f {PHP_AGENT_PATH}", timeout=10)
        sess.exec(f"pkill -f 'ctfops-waf/agent.py' 2>/dev/null; "
                  f"pkill -f 'ctfops-waf/waf-go' 2>/dev/null; "
                  f"rm -f {WAF_HOME}/agent.pid {WAF_HOME}/waf-go", timeout=15)
        if unban:
            # 只删带 ctf-ops-ban 标记的规则；iptables -F INPUT 会把宿主/平台的规则一起清空
            sess.exec("iptables -S INPUT 2>/dev/null | grep -F 'ctf-ops-ban' "
                      "| sed 's/^-A/-D/' | sh 2>/dev/null; true", timeout=20)
            sess.exec(f"rm -f {WAF_HOME}/bans.txt", timeout=10)
        sess.exec(f"rm -f {DEPLOYED_PATH} {WAF_HOME}/status.json {WAF_HOME}/php_status.json",
                  timeout=10)
        return {"ok": True, "engine": engine}


# --------------------------------------------------------------- 封禁后端
# 现实里大多数站只有普通用户权限，iptables 根本动不了。所以封禁做成"能力自适应"：
#   iptables（root/sudo）> php403（watchbird 在请求内拒绝）> htaccess（Apache 局部文件）
# 每条路径都会明确回报用了哪种、为什么失败，绝不静默。
BAN_MARK = "# >>> ctf-ops ban (auto) >>>"
BAN_MARK_END = "# <<< ctf-ops ban <<<"


@dataclass
class BanCaps:
    uid: int = -1
    root: bool = False
    sudo: bool = False
    iptables: bool = False
    nft: bool = False
    php_agent: bool = False
    web_server: str = ""
    webroot: str = ""
    webroot_writable: bool = False
    allow_override: bool = False
    backlog: str = ""

    def best(self) -> str:
        if self.iptables and (self.root or self.sudo):
            return "iptables"
        if self.php_agent:
            return "php403"
        if self.allow_override and self.webroot_writable:
            return "htaccess"
        return ""

    def to_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        d["best"] = self.best()
        return d


def detect_ban_caps(cfg: Config, target: Target, sess: Optional[SSHSession] = None) -> BanCaps:
    """一次 SSH 摸清"能怎么封"：uid、sudo、iptables、PHP 传感器、Apache 是否允许 .htaccess。"""
    own = sess is None
    caps = BanCaps()
    try:
        sess = sess or SSHSession(target, cfg)
        if own:
            sess.__enter__()
        script = (
            'echo "UID=$(id -u)"\n'
            'sudo -n true 2>/dev/null && echo SUDO=1 || echo SUDO=0\n'
            'command -v iptables >/dev/null 2>&1 && echo IPT=1\n'
            'command -v nft >/dev/null 2>&1 && echo NFT=1\n'
            f'[ -f {PHP_AGENT_PATH} ] && echo PHPAGENT=1\n'
            "ps -eo comm= 2>/dev/null | grep -E '^(nginx|apache2|httpd)$' | head -1 "
            "| sed 's/^/SRV=/'\n"
            'for w in "$WEBROOT"; do [ -n "$w" ] && [ -w "$w" ] && echo WEBROOT_W=1; done\n'
            'grep -rls "AllowOverride[[:space:]]*All" /etc/apache2 /etc/httpd 2>/dev/null '
            '| head -1 | sed "s/^/OVERRIDE=/"\n'
        )
        webroot = (target.webroot or "").strip()
        if not webroot:
            try:
                webroot = json.loads(sess.read_file(DEPLOYED_PATH) or "{}").get("webroot", "")
            except Exception:  # noqa: BLE001
                webroot = ""
        r = sess.exec(f"export WEBROOT={webroot or ''}; bash -c {_shq(script)}", timeout=25)
        caps.webroot = webroot
        caps.backlog = (r.out or "")[:600]
        for line in (r.out or "").splitlines():
            line = line.strip()
            if line.startswith("UID="):
                try:
                    caps.uid = int(line[4:])
                except ValueError:
                    pass
            elif line == "SUDO=1":
                caps.sudo = True
            elif line == "IPT=1":
                caps.iptables = True
            elif line == "NFT=1":
                caps.nft = True
            elif line == "PHPAGENT=1":
                caps.php_agent = True
            elif line.startswith("SRV="):
                caps.web_server = line[4:].strip()
            elif line == "WEBROOT_W=1":
                caps.webroot_writable = True
            elif line.startswith("OVERRIDE="):
                caps.allow_override = True
        caps.root = caps.uid == 0
    except Exception as e:  # noqa: BLE001
        caps.backlog = f"探测失败: {e}"
    finally:
        if own and sess is not None:
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass
    return caps


def _shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def _norm_ips(ips) -> List[str]:
    out = []
    for ip in ips or []:
        ip = str(ip).strip()
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip) and ip not in out \
                and ip not in ("0.0.0.0", "127.0.0.1"):
            out.append(ip)
    return out


def ban(cfg: Config, target: Target, ips, backend: str = "auto") -> Dict[str, Any]:
    """按可用能力封禁一批 IP。返回用了哪个后端、成功/失败明细。"""
    want = _norm_ips(ips)
    if not want:
        return {"ok": False, "backend": "", "error": "没有有效的 IPv4 地址",
                "banned": [], "failed": []}
    res: Dict[str, Any] = {"ok": False, "backend": "", "banned": [], "failed": [],
                           "detail": []}
    try:
        with SSHSession(target, cfg) as sess:
            caps = detect_ban_caps(cfg, target, sess)
            pick = backend if backend not in ("", "auto") else caps.best()
            res["caps"] = caps.to_dict()
            if not pick:
                res["error"] = ("这台机器既没有可用的 iptables/sudo，也没有部署 PHP 传感器、"
                                "Apache 也不允许 .htaccess —— 只能走 WAF 规则拦截 payload")
                return res
            res["backend"] = pick

            if pick == "iptables":
                prefix = "" if caps.root else "sudo -n "
                for ip in want:
                    cmd = (prefix + BAN_CMD_DEFAULT).format(ip=ip)
                    r = sess.exec(cmd, timeout=15)
                    if r.rc == 0:
                        res["banned"].append(ip)
                    elif not caps.root and target.password:
                        # sudo -n 失败时用口令走 sudo -S
                        r2 = sess.exec(BAN_CMD_DEFAULT.format(ip=ip), timeout=20, sudo=True)
                        (res["banned"] if r2.rc == 0 else res["failed"]).append(ip)
                        if r2.rc != 0:
                            res["detail"].append(f"{ip}: {(r2.err or r.err or '')[:120]}")
                    else:
                        res["failed"].append(ip)
                        res["detail"].append(f"{ip}: {(r.err or r.out or '')[:120]}")

            elif pick == "php403":
                cur = (sess.read_file(f"{WAF_HOME}/bans.txt") or "").split()
                merged = list(dict.fromkeys(cur + want))
                sess.exec(f"mkdir -p {WAF_HOME}; chmod 777 {WAF_HOME} 2>/dev/null; true",
                          timeout=10)
                okw = sess.write_file(f"{WAF_HOME}/bans.txt", "\n".join(merged) + "\n", perm=0o666)
                if okw:
                    sess.exec(f"chmod 666 {WAF_HOME}/bans.txt 2>/dev/null; true", timeout=10)
                    res["banned"] = want
                else:
                    res["failed"] = want
                    res["detail"].append("bans.txt 写不进去（目录权限？）")

            elif pick == "htaccess":
                path = posixpath.join(caps.webroot.rstrip("/"), ".htaccess")
                old = sess.read_file(path) or ""
                keep = re.sub(BAN_MARK + r".*?" + BAN_MARK_END + r"\n?", "", old, flags=re.S)
                lines = [ln for ln in keep.splitlines()]
                block = [BAN_MARK] + [f"Require not ip {ip}" for ip in want] + [BAN_MARK_END]
                body = "\n".join(lines + block).strip("\n") + "\n"
                if sess.write_file(path, body):
                    res["banned"] = want
                else:
                    res["failed"] = want
                    res["detail"].append(".htaccess 写入失败")

            res["ok"] = bool(res["banned"]) and not res["failed"]
            if res["failed"]:
                res["error"] = f"{len(res['failed'])} 个 IP 封禁失败"
    except Exception as e:  # noqa: BLE001
        res["error"] = str(e)
    return res


def unban(cfg: Config, target: Target, ips=None) -> Dict[str, Any]:
    """只撤销我们加的封禁，绝不整链清空。"""
    res: Dict[str, Any] = {"ok": True, "removed": [], "detail": []}
    try:
        with SSHSession(target, cfg) as sess:
            caps = detect_ban_caps(cfg, target, sess)
            targets = _norm_ips(ips) if ips else None
            if not targets:
                raw = (sess.read_file(f"{WAF_HOME}/bans.txt") or "").split()
                targets = _norm_ips(raw)
            if caps.iptables and (caps.root or caps.sudo):
                prefix = "" if caps.root else "sudo -n "
                if targets:
                    for ip in targets:
                        r = sess.exec(prefix + f"iptables -D INPUT -s {ip} -j DROP "
                                      "-m comment --comment ctf-ops-ban", timeout=12)
                        if r.rc == 0:
                            res["removed"].append(ip)
                else:
                    # 不知道具体 IP 时，按 comment 精准清理
                    sess.exec("iptables -S INPUT 2>/dev/null | grep -F 'ctf-ops-ban' "
                              "| sed 's/^-A/-D/' | sh 2>/dev/null; true", timeout=25)
                    res["detail"].append("按 ctf-ops-ban 标记清理全部规则")
            sess.exec(f"rm -f {WAF_HOME}/bans.txt", timeout=10)
            if caps.allow_override and caps.webroot:
                path = posixpath.join(caps.webroot.rstrip("/"), ".htaccess")
                old = sess.read_file(path) or ""
                if BAN_MARK in old:
                    sess.write_file(path, re.sub(
                        BAN_MARK + r".*?" + BAN_MARK_END + r"\n?", "", old, flags=re.S))
                    res["detail"].append(".htaccess 里的封禁段已移除")
            res["bans_left"] = list_bans(cfg, target).get("bans", [])
    except Exception as e:  # noqa: BLE001
        res["ok"] = False
        res["error"] = str(e)
    return res


def list_bans(cfg: Config, target: Target) -> Dict[str, Any]:
    """看这台机器现在封了谁（PHP 黑名单 + iptables 里带标记的规则）。"""
    out: Dict[str, Any] = {"bans": [], "iptables": [], "php": []}
    try:
        with SSHSession(target, cfg) as sess:
            php = _norm_ips((sess.read_file(f"{WAF_HOME}/bans.txt") or "").split())
            ipt = []
            r = sess.exec("iptables -S INPUT 2>/dev/null | grep -F 'ctf-ops-ban' "
                          "|| sudo -n iptables -S INPUT 2>/dev/null | grep -F 'ctf-ops-ban'",
                          timeout=15)
            for line in (r.out or "").splitlines():
                m = re.search(r"-s (\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ipt.append(m.group(1))
            out["php"] = php
            out["iptables"] = ipt
            out["bans"] = list(dict.fromkeys(ipt + php))
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
    return out


def collect(cfg: Config, store, targets: List[Target], limit: int = 300) -> Dict[str, Any]:
    """拉取审计 → 落库为攻击事件，返回按规则聚合的结果。"""
    summary: List[Dict[str, Any]] = []
    # 并行拉取：串行时一台不可达就要等一个 SSH 超时，5 台就是 30 秒以上
    if len(targets) > 1:
        from .util import pmap
        raw = pmap(lambda t: (t, read_audit(cfg, t, limit=limit)), targets,
                   workers=min(6, max(2, len(targets))))
        pairs = [r for r in raw if isinstance(r, tuple)]
    else:
        pairs = [(t, read_audit(cfg, t, limit=limit)) for t in targets]

    for t, rows in pairs:
        agg: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            key = r.get("rule_id") or "unknown"
            rec = agg.setdefault(key, {"rule_id": key, "name": r.get("name", ""),
                                       "severity": r.get("severity", "medium"),
                                       "count": 0, "last_ip": "", "last_ts": 0,
                                       "sample": None})
            rec["count"] += 1
            if r.get("ts", 0) >= rec["last_ts"]:
                rec["last_ts"] = r.get("ts", 0)
                rec["last_ip"] = r.get("ip", "")
                rec["sample"] = r
        for rec in agg.values():
            # 同一个规则在同靶机上反复命中，30 分钟内只记一条，避免刷满发现表
            store.event("finding", target=t.name,
                        title=f"WAF 命中: {rec['name']}",
                        severity=rec["severity"], dedupe_minutes=30,
                        data={"rule_id": rec["rule_id"], "location": rec["last_ip"],
                              "detail": f"最近来自 {rec['last_ip']}，共 {rec['count']} 次",
                              "evidence": json.dumps(rec["sample"], ensure_ascii=False)[:2000]})
            summary.append({"target": t.name,
                            **{k: v for k, v in rec.items() if k != "sample"},
                            "sample": rec["sample"]})
    return {"targets": len(targets), "hits": summary}

"""漏洞修补：把"扫出来的发现"变成"能落地的修补动作"。

为什么单独一层：
WAF 只能拦 payload，扫出来的洞还在。真正的防护要按发现改配置/改服务/升版本。
但现场权限往往只有普通用户，所以每个动作都标了三件事：

    level      app / service / system   —— 改动的影响面
    needs_root 需要 root 或 sudo 吗
    auto       允许自动执行吗（改 sshd/升内核这类只出建议，不自动动）

应用时按靶机实际能力（root? sudo? Apache 允许 .htaccess?）决定
"自动做 / 降级做 / 只给命令"，绝不假装成功。

安全边界（刻意的取舍）：
* 自动写入只允许落在**站点目录内的局部文件**（.htaccess / uploads/.htaccess），
  系统级配置（nginx.conf、php.ini、sshd_config、redis.conf）只输出片段和命令，由人确认；
* 每条改动都带 `# >>> ctf-ops harden >>>` 标记，可精确回滚，不做全文覆盖。
"""

from __future__ import annotations

import json
import posixpath
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import Config, Target
from .store import Store
from .util import iso_now, trunc

MARK = "# >>> ctf-ops harden"
MARK_END = "# <<< ctf-ops harden"
ADMIN_PATHS = ("phpmyadmin", "pma", "adminer", "admin", "manager/html")


@dataclass
class Action:
    id: str
    target: str
    title: str
    severity: str = "medium"
    level: str = "app"
    reason: str = ""
    needs_root: bool = False
    auto: bool = True
    files: List[Tuple[str, str]] = field(default_factory=list)   # (远端路径, 追加内容)
    cmds: List[str] = field(default_factory=list)                # 需要 root 的命令
    rollback: List[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "target": self.target, "title": self.title,
                "severity": self.severity, "level": self.level, "reason": self.reason,
                "needs_root": self.needs_root, "auto": self.auto,
                "files": [{"path": p, "content": c} for p, c in self.files],
                "cmds": self.cmds, "rollback": self.rollback,
                "evidence": trunc(self.evidence, 500)}


# ------------------------------------------------------------------ 片段模板
HT_SENSITIVE = f"""{MARK}:sensitive >>>
<FilesMatch "(\\.(bak|old|orig|save|swp|sql|tar|gz|zip|log|ini)$|^\\.(env|git|svn|hg|DS_Store))">
  Require all denied
</FilesMatch>
RedirectMatch 404 /\\.git
{MARK_END}:sensitive <<<"""

HT_UPLOADS = f"""{MARK}:uploads >>>
RemoveHandler .php .phtml .php3 .php4 .php5 .php7 .phps
AddType text/plain .php .phtml .php3 .php4 .php5 .php7 .phps
<FilesMatch "\\.(php|phtml|php[3-7])$">
  Require all denied
</FilesMatch>
{MARK_END}:uploads <<<"""

HT_NOINDEX = f"""{MARK}:indexes >>>
Options -Indexes
{MARK_END}:indexes <<<"""

HT_ADMIN = f"""{MARK}:admin >>>
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteRule ^(phpmyadmin|pma|adminer)/? - [R=404,L]
</IfModule>
{MARK_END}:admin <<<"""

NGINX_SNIPPET = """\
# 放到 server{} 里（需要 root 改配置并 reload）
location ~ /\\.(git|svn|env|DS_Store) { deny all; }
location ~* \\.(bak|old|sql|tar|gz|zip|log|ini)$ { deny all; }
location ~* ^/uploads/.*\\.(php|phtml|php[3-7])$ { deny all; }
autoindex off;
"""


def _match(blob: str, *pats: str) -> bool:
    return any(re.search(p, blob, re.I) for p in pats)


def _has_htaccess(caps: Dict[str, Any]) -> bool:
    return bool(caps.get("allow_override")) and bool(caps.get("webroot_writable"))


def _webroot(caps: Dict[str, Any]) -> str:
    return (caps.get("webroot") or "").rstrip("/")


# ------------------------------------------------------------------ 规则引擎
def plan_for_target(target: str, findings: Sequence[Dict[str, Any]],
                    caps: Optional[Dict[str, Any]] = None,
                    webroot_hint: str = "") -> List[Action]:
    """按发现生成修补动作。纯函数，方便离线测试。"""
    caps = dict(caps or {})
    if webroot_hint and not caps.get("webroot"):
        caps["webroot"] = webroot_hint
    # 只把有位置的发现原文拼起来做匹配，避免标题同义反复
    blob = "\n".join(
        " ".join(str(f.get(k) or "") for k in ("title", "detail", "location", "evidence"))
        for f in findings)
    acts: List[Action] = []
    root = _webroot(caps)
    ht_ok = _has_htaccess(caps)
    srv = (caps.get("web_server") or "").lower()
    apache = "apache" in srv or "httpd" in srv

    def ht_action(aid: str, title: str, content: str, rel: str, reason: str,
                  sev: str = "medium", ev: str = "") -> Action:
        path = posixpath.join(root, rel) if root else ""
        a = Action(id=f"{aid}@{target}", target=target, title=title, severity=sev,
                   level="app", reason=reason, needs_root=False, auto=True,
                   evidence=ev)
        if ht_ok and path:
            a.files = [(path, content)]
        else:
            # 不能自动写就退化成"给 nginx/apache 片段 + 需要 root"
            a.auto = False
            a.needs_root = not apache
            a.cmds = []
            a.reason += "（当前无法自动写入，见下方片段：需要 AllowOverride All 或 root 改站点配置）"
            a.files = []
            a.rollback = []
            a.evidence = (a.evidence + "\n\n" + NGINX_SNIPPET).strip()
        return a

    if _match(blob, r"敏感目标访问", r"敏感文件", r"\.git", r"\.env", r"www\.zip",
              r"backup", r"\.sql\b"):
        acts.append(ht_action("deny_sensitive", "拒绝访问敏感文件（.git/.env/备份包/日志）",
                              HT_SENSITIVE, ".htaccess",
                              "扫描发现站点上能直接下载源码/备份，这是最快拿数据或拿库的入口",
                              "high",
                              next((f.get("location") or "" for f in findings
                                    if _match(str(f.get("location") or ""),
                                              r"\.git", r"\.env", r"backup")), "")))

    if _match(blob, r"上传", r"upload", r"后门文件", r"webshell", r"一句话"):
        uploads = posixpath.join(root, "uploads") if root else ""
        a = Action(id=f"block_upload_exec@{target}", target=target,
                   title="上传目录禁止执行脚本", severity="critical", level="app",
                   reason="上传点 + 可执行目录就是一句话木马的标准落地路径；禁用执行比删文件更稳",
                   auto=True)
        if ht_ok and uploads:
            a.files = [(posixpath.join(uploads, ".htaccess"), HT_UPLOADS)]
        else:
            a.auto = False
            a.needs_root = not apache
            a.reason += "（需要 root 改站点配置或 AllowOverride All）"
            a.evidence = NGINX_SNIPPET
        acts.append(a)

    if _match(blob, r"目录扫描", r"目录列表", r"autoindex", r"Index of /", r"404×"):
        acts.append(ht_action("disable_autoindex", "关闭目录索引", HT_NOINDEX, ".htaccess",
                              "目录列表会把整个上传/备份目录摊开，扫描器最喜欢",
                              "medium"))

    if _match(blob, r"phpmyadmin", r"adminer", r"管理面板", r"/admin", r"manager/html"):
        acts.append(ht_action("hide_admin", "隐藏管理后台入口", HT_ADMIN, ".htaccess",
                              "后台暴露在公网等于给对方一个可爆破的入口", "medium"))

    if _match(blob, r"WAF 命中", r"SQL 注入", r"命令注入", r"路径穿越", r"文件包含"):
        acts.append(Action(
            id=f"waf_enforce@{target}", target=target, title="WAF 切加固模式（拦 payload）",
            severity="high", level="app", reason="已有攻击 payload 命中记录，先把已知攻击面拦住",
            needs_root=False, auto=True,
            cmds=["ops:waf_enforce"],       # 内部指令，由 apply 翻译成 waf.enforce()
            evidence=next((f.get("title") or "" for f in findings
                           if _match(str(f.get("title") or ""), r"WAF 命中")), "")))

    if _match(blob, r"redis", r"未授权访问") and _match(blob, r"redis"):
        acts.append(Action(
            id=f"redis_auth@{target}", target=target, title="Redis 加认证并只监听本机",
            severity="critical", level="service", needs_root=True, auto=False,
            reason="Redis 未授权 = 直接写 crontab/ssh key 拿 root，比 webshell 还快",
            cmds=["redis-cli CONFIG SET requirepass '<强口令>'",
                  "# 配置文件：bind 127.0.0.1 ::1  +  requirepass <强口令>",
                  "systemctl restart redis  # 或 redis-server 重启"],
            rollback=["redis-cli CONFIG SET requirepass ''"]))

    if _match(blob, r"mysql", r"数据库", r"3306"):
        acts.append(Action(
            id=f"mysql_bind@{target}", target=target, title="MySQL 只监听本机 + 去掉空口令账号",
            severity="high", level="service", needs_root=True, auto=False,
            reason="3306 对外 + 弱口令是最常见的二次入口",
            cmds=["# my.cnf: bind-address = 127.0.0.1",
                  "ALTER USER 'root'@'%' IDENTIFIED BY '<强口令>';",
                  "systemctl restart mysqld"]))

    if _match(blob, r"SSH 爆破", r"暴力破解", r"弱口令", r"Failed password"):
        acts.append(Action(
            id=f"ssh_hardening@{target}", target=target, title="收紧 SSH（禁 root 直登 / 改密钥）",
            severity="high", level="system", needs_root=True, auto=False,
            reason="爆破已经在发生；改配置前务必确认自己有可用密钥，否则会把自己锁在外面",
            cmds=["# /etc/ssh/sshd_config:",
                  "#   PermitRootLogin prohibit-password",
                  "#   PasswordAuthentication no",
                  "sshd -t && systemctl reload sshd"],
            rollback=["# 保留一个已登录会话，改错了用它回滚"],
            evidence=next((f.get("title") or "" for f in findings
                           if _match(str(f.get("title") or ""), r"爆破|弱口令")), "")))

    if _match(blob, r"CVE-\d{4}", r"版本", r"nuclei"):
        cve = next((m.group(0) for f in findings
                    for m in [re.search(r"CVE-\d{4}-\d{3,7}", json.dumps(f, ensure_ascii=False))] if m), "")
        pkg = ("apt-get" if caps.get("pkg") == "debian" else "yum")
        acts.append(Action(
            id=f"patch_component@{target}", target=target,
            title=f"升级受影响组件{f'（{cve}）' if cve else ''}",
            severity="high", level="system", needs_root=True, auto=False,
            reason="版本类漏洞只能靠升级/打补丁，WAF 规则只是临时缓解",
            cmds=[f"{pkg} update && {pkg} upgrade -y   # 或按官方公告升级具体包",
                  "# 升级前：先备份（ops backup run），确认业务能重启"],
            rollback=["# 版本升级不可自动回滚，升级前必须有备份"],
            evidence=cve))

    # 同一条动作只留一个（同一靶机上可能被多条发现触发）
    seen, uniq = set(), []
    for a in acts:
        if a.id in seen:
            continue
        seen.add(a.id)
        uniq.append(a)
    return uniq


def plan(cfg: Config, store: Store, targets: Optional[Sequence[Target]] = None,
         caps_map: Optional[Dict[str, Dict[str, Any]]] = None,
         log=None) -> List[Action]:
    """从库里的发现 + 漏洞库生成整场修补计划。"""
    from .util import pmap

    ts = list(targets or [t for t in cfg.targets if t.enabled and not t.is_attack])
    rows = store.events(kind="finding", limit=2000)
    acts: List[Action] = []
    for t in ts:
        mine = [r for r in rows if (r.get("target") or "") == t.name]
        # 漏洞库（WAF 重放用）也算"待修"的证据
        mine += [{"title": v.get("name", ""), "severity": v.get("severity", ""),
                  "location": v.get("path", ""), "detail": v.get("rule_id", "")}
                 for v in store.vulns() if (v.get("target") or "") == t.name]
        if not mine:
            continue
        caps = (caps_map or {}).get(t.name)
        if log:
            log(f"[{t.name}] {len(mine)} 条发现，生成修补动作 ...")
        acts.extend(plan_for_target(t.name, mine, caps, webroot_hint=t.webroot or ""))
    return acts


# ------------------------------------------------------------------ 执行
def _append_block(sess, path: str, content: str) -> Tuple[bool, str]:
    """把带标记的片段追加进文件；已存在同标记段则整体替换（幂等）。"""
    key = content.splitlines()[0].strip()
    old = sess.read_file(path) or ""
    keep = re.sub(re.escape(key) + r".*?" + re.escape(MARK_END) + r"[^\n]*\n?",
                  "", old, flags=re.S)
    body = (keep.rstrip("\n") + "\n\n" + content.strip("\n") + "\n").lstrip("\n")
    ok = sess.write_file(path, body)
    return ok, ("已写入" if ok else "写入失败")


def apply(cfg: Config, store: Store, target: Target, actions: Sequence[Action],
          caps: Optional[Dict[str, Any]] = None, dry_run: bool = False,
          log=None) -> List[Dict[str, Any]]:
    """执行（或演练）一批动作，按能力自动降级，逐条回报结果。"""
    from . import waf as waf_mod
    from .sshx import SSHSession

    out: List[Dict[str, Any]] = []
    caps = caps or {}
    is_root = int(caps.get("uid", -1) or -1) == 0
    can_sudo = bool(caps.get("sudo")) or is_root
    webroot = _webroot(caps) or (target.webroot or "").rstrip("/")

    with SSHSession(target, cfg) as sess:
        for a in actions:
            row = {"id": a.id, "title": a.title, "target": a.target,
                   "level": a.level, "ok": False, "status": "", "detail": ""}
            if dry_run:
                row.update(ok=True, status="dry-run",
                           detail="；".join([f"写 {p}" for p, _ in a.files]
                                           + [f"跑 {c}" for c in a.cmds]) or a.reason)
                out.append(row)
                continue

            if a.cmds == ["ops:waf_enforce"]:
                try:
                    r = waf_mod.enforce(cfg, target, autoban=True)
                    row.update(ok=bool(r.get("ok")), status="done",
                               detail=f"WAF 加固：拦截 {', '.join(r.get('blocked_rules') or [])}")
                except Exception as e:  # noqa: BLE001
                    row.update(status="failed", detail=str(e)[:200])
                out.append(row)
                continue

            if not a.auto:
                row.update(status="manual", detail="需人工确认（改系统/服务配置有风险）")
                out.append(row)
                continue

            if a.needs_root and not can_sudo:
                row.update(status="skipped", detail="需要 root/sudo，当前账号没有权限")
                out.append(row)
                continue

            # 文件类：只允许落在站点目录内
            done_msgs, failed = [], False
            for path, content in a.files:
                if webroot and not path.startswith(webroot):
                    row.update(status="skipped", detail=f"拒绝写到站点目录外：{path}")
                    failed = True
                    break
                okw, msg = _append_block(sess, path, content)
                if okw:
                    done_msgs.append(f"{path} {msg}")
                else:
                    failed = True
                    done_msgs.append(f"{path} 失败（权限？）")
            # 命令类：需要 root 的走 sudo
            for cmd in a.cmds:
                if cmd.strip().startswith("#"):
                    continue
                r = sess.exec(cmd, timeout=60, sudo=(a.needs_root and not is_root))
                done_msgs.append(f"{cmd[:60]} → rc={r.rc}")
                if r.rc != 0:
                    failed = True
            row.update(ok=not failed, status="failed" if failed else "done",
                       detail="；".join(done_msgs)[:600])
            out.append(row)
            if log:
                log(f"[{target.name}] {a.title}: {row['status']}", 
                    "ok" if row["ok"] else "warn")

    try:
        store.event("action", target=target.name, title="harden.apply",
                    data={"items": out, "dry_run": dry_run, "ts": iso_now()})
    except Exception:  # noqa: BLE001
        pass
    return out


def write_plan_md(cfg: Config, actions: Sequence[Action], title: str = "漏洞修补方案") -> str:
    """把计划落成 markdown，便于交付/复盘。"""
    lines = [f"# {title}", "", f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
             f"动作总数：{len(actions)}", ""]
    by_target: Dict[str, List[Action]] = {}
    for a in actions:
        by_target.setdefault(a.target, []).append(a)
    for t, acts in by_target.items():
        lines.append(f"## {t}（{len(acts)} 项）")
        for a in acts:
            tag = "自动" if a.auto else "需人工"
            root = " / 需 root" if a.needs_root else ""
            lines.append(f"### [{a.severity}] {a.title}  · {a.level} · {tag}{root}")
            lines.append(f"- 为什么：{a.reason}")
            if a.evidence:
                lines.append(f"- 证据：`{trunc(a.evidence, 200)}`")
            for p, c in a.files:
                lines.append(f"- 写入 `{p}`：")
                lines.append("```apache")
                lines.extend(c.splitlines())
                lines.append("```")
            if a.cmds:
                lines.append("- 命令：")
                lines.append("```bash")
                lines.extend(a.cmds)
                lines.append("```")
            if a.rollback:
                lines.append("- 回滚：" + "；".join(a.rollback))
            lines.append("")
    text = "\n".join(lines)
    path = cfg.report_dir / f"harden_{time.strftime('%Y%m%d_%H%M%S')}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path)

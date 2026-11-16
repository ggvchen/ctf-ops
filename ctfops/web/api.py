"""Web API：把 CLI 的每个动作暴露成 HTTP 接口，重活丢进任务队列。

约定：
- 返回 (http_status, dict)
- 会跑超过 1 秒的动作一律返回 {"job": {...}}，前端轮询 /api/jobs/{id}
- 密码永远不出网关（_public_target 统一脱敏）
"""

from __future__ import annotations

import json
import mimetypes
import os
import pathlib
import urllib.parse
import re
import shutil
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from ..config import Config, Target, load_config
from ..util import human_size, iso_now, trunc

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

ROUTES: List[Tuple[str, "re.Pattern[str]", Any]] = []

_AI_CACHE: Dict[str, Any] = {"ts": 0.0, "alive": False}


def route(method: str, pattern: str):
    def deco(fn):
        ROUTES.append((method.upper(), re.compile("^" + pattern + "$"), fn))
        return fn
    return deco


def _public_target(t: Target) -> Dict[str, Any]:
    d = {
        "name": t.name, "host": t.host, "ssh_port": t.ssh_port, "user": t.user,
        "auth": "key" if t.key_file else ("password" if t.password else "none"),
        "key_file": t.key_file or "", "web": t.web, "tags": t.tags,
        "note": t.note, "webroot": t.webroot or "", "enabled": t.enabled,
        "role": "attack" if t.is_attack else "defense",
        "role_label": t.role_label,
    }
    return d


def _resolve(app, names: Optional[List[str]]) -> List[Target]:
    try:
        return app.cfg.resolve(names or ["all"])
    except KeyError as e:
        raise ValueError(str(e)) from e


def _store_findings(app, findings: List[Any], source: str) -> int:
    for f in findings:
        app.store.event("finding", target=f.target, title=f.title,
                        severity=f.severity, data={**f.to_dict(), "source": source})
    return len(findings)


def _job_reply(job) -> Dict[str, Any]:
    return {"job": {"id": job.id, "kind": job.kind, "title": job.title,
                    "status": job.status}}


# ------------------------------------------------------------------ 总览
def _ai_alive(app, ttl: float = 60.0) -> bool:
    """带缓存 + 后台探测：总览每 15 秒刷新，不能每次都等 3 秒超时。"""
    now = time.time()
    if now - _AI_CACHE["ts"] < ttl:
        return bool(_AI_CACHE["alive"])
    if not _AI_CACHE.get("probing"):
        _AI_CACHE["probing"] = True

        def probe() -> None:
            try:
                from ..aiclient import AIClient
                alive = AIClient(app.cfg).available(force=True)
            except Exception:
                alive = False
            _AI_CACHE.update({"ts": time.time(), "alive": alive, "probing": False})

        threading.Thread(target=probe, daemon=True, name="ai-probe").start()
    return bool(_AI_CACHE["alive"])


@route("GET", r"/api/overview")
def overview(app, p, q, b):
    s = app.store.summary()
    # 卡片上的"靶机"应为配置数量：DB 里的 target 字段还包含 log/pcap 这类伪目标
    s["targets"] = sum(1 for t in app.cfg.targets if t.enabled)
    return 200, {
        "name": app.cfg.name,
        "mode": app.cfg.mode,
        "workdir": str(app.cfg.workdir),
        "config": str(app.cfg.path),
        "summary": s,
        "severity": s.get("severity") or {},
        "targets": [_public_target(t) for t in app.cfg.targets],
        "active_jobs": app.jobs.active(),
        "ai": {"enabled": app.cfg.ai.enabled, "model": app.cfg.ai.model,
               "base_url": app.cfg.ai.base_url, "alive": _ai_alive(app)},
        "submit": {"mode": app.cfg.submit.mode, "url": app.cfg.submit.url},
        "plugins": len(_plugins()),
        "server": app.stale(),
        "now": iso_now(),
    }


def _plugins():
    from ..exploit import load_plugins
    return load_plugins()


@route("GET", r"/api/targets")
def targets_list(app, p, q, b):
    return 200, {"targets": [_public_target(t) for t in app.cfg.targets],
                 "config": str(app.cfg.path)}


@route("POST", r"/api/targets")
def targets_add(app, p, q, b):
    name = (b.get("name") or "").strip()
    host = (b.get("host") or "").strip()
    if not host:
        raise ValueError("host 必填")
    t = {
        "name": name or host,
        "host": host,
        "user": (b.get("user") or "root").strip(),
        "ssh_port": int(b.get("ssh_port") or 22),
        "password": b.get("password") or "",
        "web": [x.strip() for x in str(b.get("web") or "").split(",") if x.strip()],
        "tags": [x.strip() for x in str(b.get("tags") or "").split(",") if x.strip()],
        "note": b.get("note") or "",
        "role": "attack" if b.get("role") == "attack" else "defense",
    }
    if b.get("webroot"):
        wr = str(b["webroot"]).strip()
        if wr and not wr.startswith("/"):
            raise ValueError("备份源要写远端绝对路径")
        t["webroot"] = wr
    _append_target_yaml(app.cfg, t)
    app.reload()
    return 200, {"ok": True, "targets": [_public_target(x) for x in app.cfg.targets]}


def _yaml_str(v: str) -> str:
    return json.dumps(str(v), ensure_ascii=False)


def _append_targets_yaml(cfg: Config, items: List[Dict[str, Any]]) -> None:
    """一次写入多条，避免 200 条时反复读写文件。"""
    import yaml

    try:
        raw_cfg = yaml.safe_load(cfg.path.read_text(encoding="utf-8")) or {}
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"读取配置失败: {e}") from e

    tf = raw_cfg.get("targets_file")
    if tf:
        path = pathlib.Path(tf)
        if not path.is_absolute():
            path = cfg.path.parent / path
    else:
        path = cfg.path
    if not path.exists():
        path.write_text("targets:\n", encoding="utf-8")

    body = path.read_text(encoding="utf-8").splitlines()
    tgt_line = None
    for i, line in enumerate(body):
        m = re.match(r"^targets:\s*(\[\])?\s*(#.*)?$", line)
        if m:
            tgt_line = i
            if m.group(1):
                body[i] = "targets:"
            break
    if tgt_line is None:
        raise ValueError(f"{path.name} 不是标准结构（缺少顶层 targets:），请手动编辑")

    # 探测已有列表项缩进：yaml.safe_dump 生成的是 0 缩进，手写配置通常是 2
    item_indent = "  "
    for i in range(tgt_line + 1, len(body)):
        line = body[i]
        if not line.strip():
            continue
        if line.lstrip().startswith("-"):
            item_indent = line[:len(line) - len(line.lstrip())]
        break
    sub = item_indent + "  "

    block: List[str] = []
    for t in items:
        block += [
            f"{item_indent}- name: {_yaml_str(t['name'])}",
            f"{sub}host: {_yaml_str(t['host'])}",
            f"{sub}ssh_port: {t.get('ssh_port', 22)}",
            f"{sub}user: {_yaml_str(t.get('user', 'root'))}",
            f"{sub}role: {t.get('role', 'defense')}",
        ]
        if t.get("password"):
            block.append(f"{sub}password: {_yaml_str(t['password'])}")
        if t.get("web"):
            block.append(f"{sub}web:")
            block += [f"{sub}  - {_yaml_str(u)}" for u in t["web"]]
        if t.get("tags"):
            block.append(f"{sub}tags: [" + ", ".join(_yaml_str(x) for x in t["tags"]) + "]")
        if t.get("note"):
            block.append(f"{sub}note: {_yaml_str(t['note'])}")
        if t.get("webroot"):
            block.append(f"{sub}webroot: {_yaml_str(t['webroot'])}")

    insert_at = len(body)
    for i in range(tgt_line + 1, len(body)):
        line = body[i]
        if line and not line.startswith((" ", "\t", "-")):
            insert_at = i
            break
    new_lines = body[:insert_at] + block + body[insert_at:]
    path.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")


def _append_target_yaml(cfg: Config, t: Dict[str, Any]) -> None:
    _append_targets_yaml(cfg, [t])


# ------------------------------------------------------------------ 数据
@route("GET", r"/api/events")
def events(app, p, q, b):
    kind = q.get("kind") or None
    target = q.get("target") or None
    try:
        limit = min(int(q.get("limit") or 100), 1000)
    except ValueError:
        limit = 100
    rows = app.store.events(kind=kind, target=target, limit=limit)
    return 200, {"events": rows}


@route("GET", r"/api/findings")
def findings(app, p, q, b):
    """发现汇总：分页 + 按级别过滤。severity 支持 critical,high 这种多值。"""
    sev = (q.get("severity") or "").strip()
    sevs = [s.strip() for s in sev.split(",") if s.strip()]
    target = q.get("target") or None
    try:
        offset = max(0, int(q.get("offset") or 0))
    except ValueError:
        offset = 0
    try:
        limit = int(q.get("limit") or 50)
    except ValueError:
        limit = 50
    limit = min(500, max(1, limit))
    total = app.store.count_events(kind="finding", target=target, severities=sevs)
    rows = app.store.events(kind="finding", target=target, severities=sevs,
                            limit=limit, offset=offset, severity_first=True)
    return 200, {"findings": rows, "total": total, "offset": offset, "limit": limit}


def _trash_dir(app) -> pathlib.Path:
    d = app.cfg.evidence_dir / "trash"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _dump_findings(app, rows: List[Dict[str, Any]], why: str) -> str:
    """删前先落盘。发现是证据，误删一次就说不清了 —— 留个 JSON 就能原样回填。"""
    import time as _t
    d = _trash_dir(app)
    path = d / f"findings-{_t.strftime('%Y%m%d-%H%M%S')}-{why}.json"
    payload = {"ts": iso_now(), "why": why, "count": len(rows),
               "rows": [{"ts": r.get("ts"), "kind": r.get("kind", "finding"),
                         "target": r.get("target", ""), "title": r.get("title", ""),
                         "severity": r.get("severity", ""),
                         "data": json.dumps(r.get("data") or {}, ensure_ascii=False)}
                        for r in rows]}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return path.name


@route("POST", r"/api/findings/delete")
def findings_delete(app, p, q, b):
    """批量删除发现。给 ids 就删指定行；给 filter 就删当前筛选条件下的全部。

    删之前一律先写 evidence/trash/*.json，返回文件名，可用 /api/findings/restore 还原。
    """
    ids = b.get("ids") or []
    if isinstance(ids, str):
        ids = [ids]
    ids = [int(i) for i in ids if str(i).strip().isdigit()]
    sev = (b.get("severity") or "").strip()
    sevs = [s.strip() for s in sev.split(",") if s.strip()]
    target = (b.get("target") or "").strip() or None

    if ids:
        victims = [r for r in app.store.events(kind="finding", limit=20000)
                   if r["id"] in set(ids)]
        why = "选中"
    elif b.get("all"):
        victims = app.store.events(kind="finding", target=target, severities=sevs, limit=20000)
        why = "筛选"
    else:
        raise ValueError("要么给 ids，要么给 all=true（按当前筛选清空）")

    trash = _dump_findings(app, victims, why)
    n = app.store.delete_events([r["id"] for r in victims])
    app.store.event("action", target="local", title="findings.delete",
                    data={"removed": n, "trash": trash, "mode": "ids" if ids else "filter"})
    return 200, {"ok": True, "removed": n, "trash": trash,
                 "mode": "ids" if ids else "filter"}


@route("GET", r"/api/findings/trash")
def findings_trash(app, p, q, b):
    """最近的删除快照，倒序列出，供页面"撤销"用。"""
    rows = []
    for f in sorted(_trash_dir(app).glob("*.json"), reverse=True)[:20]:
        try:
            meta = json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        rows.append({"file": f.name, "ts": meta.get("ts", ""),
                     "count": meta.get("count", 0), "why": meta.get("why", ""),
                     # recovered-* 是从空闲页抢救出来的，不属于"撤销删除"，别混进按钮
                     "kind": "delete" if f.name.startswith("findings-") else "recovered"})
    return 200, {"files": rows}


@route("POST", r"/api/findings/restore")
def findings_restore(app, p, q, b):
    """从回收站快照回填发现（id 会重新分配，内容原样）。"""
    name = (b.get("file") or "").strip()
    if not name:
        raise ValueError("file 必填")
    if "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("文件名不合法")
    path = _trash_dir(app) / name
    if not path.is_file():
        raise ValueError(f"快照不存在: {name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("rows") or []
    have = {(r.get("ts"), r.get("target"), r.get("title"))
            for r in app.store.events(kind="finding", limit=20000)}
    n = 0
    for r in rows:
        key = (r.get("ts"), r.get("target"), r.get("title"))
        if key in have:
            continue
        app.store.event("finding", target=r.get("target") or "",
                        title=r.get("title") or "", severity=r.get("severity") or "",
                        data=json.loads(r.get("data") or "{}"))
        n += 1
    app.store.event("action", target="local", title="findings.restore",
                    data={"file": name, "restored": n})
    return 200, {"ok": True, "restored": n, "total": len(rows)}



@route("GET", r"/api/flags")
def flags_list(app, p, q, b):
    rows = app.store.flags()
    return 200, {"flags": rows, "total": len(rows),
                 "pending": sum(1 for r in rows if not r["submitted"])}


@route("GET", r"/api/backups")
def backups(app, p, q, b):
    rows = []
    for r in app.store.backups():
        r = dict(r)
        r["size_h"] = human_size(r["size"])
        r["file"] = pathlib.Path(r["local_path"]).name
        r["exists"] = pathlib.Path(r["local_path"]).exists()
        rows.append(r)
    return 200, {"backups": rows}


@route("GET", r"/api/shots")
def shots(app, p, q, b):
    rows = []
    for r in app.store.shots():
        r = dict(r)
        pth = pathlib.Path(r["path"]) if r.get("path") else None
        r["exists"] = bool(pth and pth.exists())
        try:
            r["rel"] = pth.relative_to(app.cfg.workdir).as_posix() if pth and r["exists"] else ""
        except ValueError:
            r["rel"] = ""
        rows.append(r)
    return 200, {"shots": rows}


@route("GET", r"/api/backup/config")
def backup_config(app, p, q, b):
    from ..backup import backup_root
    root = backup_root(app.cfg, app.store)
    info = {
        "path": str(root),
        "default": str(app.cfg.backup_dir),
        "exists": root.exists(),
        "writable": False,
        "free": 0,
        "free_h": "",
    }
    try:
        root.mkdir(parents=True, exist_ok=True)
        du = shutil.disk_usage(str(root))
        probe = root / ".ctfops_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        info.update({"exists": True, "writable": True,
                     "free": du.free, "free_h": human_size(du.free),
                     "total_h": human_size(du.total)})
    except Exception as e:  # noqa: BLE001
        info["error"] = str(e)
    # 历史备份是否还在该目录里
    rows = app.store.backups()
    if rows:
        info["legacy"] = [r["ts"] + " " + pathlib.Path(r["local_path"]).name
                          for r in rows[:5]
                          if pathlib.Path(r["local_path"]).parent != root]
    return 200, info


@route("POST", r"/api/backup/config")
def backup_config_set(app, p, q, b):
    from ..backup import SETTING_KEY, backup_root
    raw = (b.get("path") or "").strip()
    if not raw:
        raise ValueError("路径不能为空")
    target = pathlib.Path(raw).expanduser()
    if not target.is_absolute():
        target = app.cfg.workdir / target
    try:
        target.mkdir(parents=True, exist_ok=True)
        probe = target / ".ctfops_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"目录不可写: {e}") from e
    # 与默认目录一致时清空设置，避免以后 workdir 变了还留旧绝对路径
    store_value = "" if target.resolve() == app.cfg.backup_dir.resolve() else str(target)
    app.store.set_setting(SETTING_KEY, store_value)
    root = backup_root(app.cfg, app.store)
    return 200, {"ok": True, "path": str(root),
                 "free_h": human_size(shutil.disk_usage(str(root)).free)}


# --------------------------------------------------------------- 文件浏览
ARTIFACT_DIRS = ["report", "evidence/shots", "evidence/logs", "evidence/snapshot",
                 "evidence/pcap", "evidence/pulled", "backups", "outbox", "logs"]


@route("GET", r"/api/artifacts")
def artifacts(app, p, q, b):
    want = q.get("dir") or ""
    root = app.cfg.workdir
    dirs = [want] if want else list(ARTIFACT_DIRS)
    from ..backup import backup_root
    broot = backup_root(app.cfg, app.store)
    if not want:
        try:
            rel = broot.resolve().relative_to(app.cfg.workdir.resolve()).as_posix()
            if rel not in dirs:
                dirs.append(rel)
        except ValueError:
            pass
    out: List[Dict[str, Any]] = []
    for d in dirs:
        base = (root / d)
        if not base.exists():
            continue
        try:
            entries = sorted(base.rglob("*"), key=lambda x: -x.stat().st_mtime)
        except Exception:
            continue
        for f in entries[:400]:
            if not f.is_file():
                continue
            st = f.stat()
            out.append({
                "path": f.relative_to(root).as_posix(),
                "name": f.name,
                "dir": d,
                "size": st.st_size,
                "size_h": human_size(st.st_size),
                "mtime": time.strftime("%m-%d %H:%M", time.localtime(st.st_mtime)),
                "ext": f.suffix.lower(),
            })
    # 备份目录可能被改到外置盘，单独纳入（标记 external，供下载接口放行）
    try:
        inside = str(broot.resolve()).startswith(str(app.cfg.workdir.resolve()))
    except Exception:
        inside = True
    if not inside and broot.exists():
        for f in sorted(broot.glob("*"), key=lambda x: -x.stat().st_mtime)[:120]:
            if not f.is_file():
                continue
            st = f.stat()
            out.append({
                "path": str(f), "name": f.name, "dir": "备份（外部）",
                "size": st.st_size, "size_h": human_size(st.st_size),
                "mtime": time.strftime("%m-%d %H:%M", time.localtime(st.st_mtime)),
                "ext": f.suffix.lower(), "external": True,
            })
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return 200, {"artifacts": out[:300], "backup_dir": str(broot)}


def safe_path(cfg: Config, rel: str) -> pathlib.Path:
    root = cfg.workdir.resolve()
    p = (root / rel.lstrip("/")).resolve()
    if not str(p).startswith(str(root)):
        raise ValueError("路径越界")
    return p


# -------------------------------------------------------------------- SSH
@route("POST", r"/api/ssh/exec")
def ssh_exec(app, p, q, b):
    cmd = (b.get("cmd") or "").strip()
    if not cmd:
        raise ValueError("命令不能为空")
    ts = _resolve(app, b.get("targets"))
    sudo = bool(b.get("sudo"))
    timeout = min(int(b.get("timeout") or 60), 600)

    def work(job):
        from ..sshx import batch_exec
        job.log(f"在 {len(ts)} 台靶机执行：{cmd}")
        res = batch_exec(app.cfg, ts, cmd, timeout=timeout, sudo=sudo,
                         workers=min(8, len(ts)))
        rows = []
        for r in res:
            app.store.event("action", target=r.target, title="ssh exec",
                            data={"cmd": cmd, "rc": r.rc,
                                  "out": trunc(r.text, 2000), "error": r.error})
            rows.append({"target": r.target, "host": r.host, "rc": r.rc,
                         "out": r.out, "err": r.err, "error": r.error,
                         "elapsed": round(r.elapsed, 2),
                         "ok": r.ok})
            if r.ok:
                job.log(f"[{r.target}] rc=0 {r.out.strip()[:300]}", "ok")
            else:
                job.log(f"[{r.target}] 失败 {r.error or r.err[:300]}", "error")
        return {"results": rows, "ok": sum(1 for r in rows if r["ok"])}

    return 202, _job_reply(app.jobs.submit("ssh", f"SSH 执行 · {cmd[:40]}", work,
                                           {"targets": [t.name for t in ts]}))


@route("POST", r"/api/ssh/snapshot")
def ssh_snapshot(app, p, q, b):
    ts = _resolve(app, b.get("targets"))

    def work(job):
        from ..sshx import SSHSession
        outdir = app.cfg.evidence_dir / "snapshot"
        outdir.mkdir(parents=True, exist_ok=True)
        cmd = (
            "echo '### host'; hostname; date;"
            "echo '### ps'; ps auxww 2>/dev/null | head -150;"
            "echo '### net'; (ss -antp || netstat -antp) 2>/dev/null | head -100;"
            "echo '### users'; cat /etc/passwd; echo '### uid0'; awk -F: '$3==0{print $1}' /etc/passwd;"
            "echo '### sudoers'; grep -vE '^#|^$' /etc/sudoers 2>/dev/null | head -40;"
            "echo '### cron'; for f in /etc/crontab /var/spool/cron/* /etc/cron.d/*;"
            " do [ -f \"$f\" ] && echo \"--$f\" && cat \"$f\"; done 2>/dev/null;"
            "echo '### tmp'; ls -la /tmp /dev/shm /var/tmp 2>/dev/null;"
            "echo '### last'; last -n 30 2>/dev/null;"
            "echo '### listen'; (ss -lntp || netstat -lntp) 2>/dev/null"
        )
        saved = []
        for t in ts:
            with SSHSession(t, app.cfg) as s:
                r = s.exec(cmd, timeout=120)
                f = outdir / f"{t.name}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                f.write_text(r.text, encoding="utf-8")
                saved.append(f.relative_to(app.cfg.workdir).as_posix())
                app.store.event("action", target=t.name, title="现场快照",
                                data={"path": str(f)})
                job.log(f"[{t.name}] 快照 {human_size(len(r.text))}", "ok"
                        if r.ok else "error")
        return {"files": saved}
    return 202, _job_reply(app.jobs.submit("ssh", f"现场快照 · {len(ts)} 台", work))


# ----------------------------------------------------------------- 备份
@route("POST", r"/api/backup/run")
def backup_run(app, p, q, b):
    ts = _resolve(app, b.get("targets"))
    tag = (b.get("tag") or "snapshot").strip()
    with_db = bool(b.get("db", True))

    overrides = b.get("sources") or {}

    def work(job):
        from ..backup import backup_root, backup_target
        from ..util import pmap
        dest = backup_root(app.cfg, app.store)
        dest.mkdir(parents=True, exist_ok=True)
        job.log(f"备份 {len(ts)} 台，tag={tag}，DB={with_db} → {dest}")

        def one(t):
            src = (overrides.get(t.name) or "").strip() or None
            job.log(f"[{t.name}] 打包中 ...（源：{src or t.webroot or '自动探测'}）")
            r = backup_target(app.cfg, t, dest_dir=dest, tag=tag, with_db=with_db, src=src)
            app.store.add_backup(r.target, r.remote_path, r.local_path,
                                 r.size, r.sha256, r.ok, r.note)
            app.store.event("backup", target=r.target, title="备份",
                            data={"ok": r.ok, "path": r.local_path,
                                  "size": r.size, "sha256": r.sha256})
            job.log(f"[{t.name}] {'成功 ' + human_size(r.size) if r.ok else '失败 ' + r.note}"
                    + (f"（源 {r.source}）" if r.source else ""),
                    "ok" if r.ok else "error")
            return {"target": r.target, "ok": r.ok, "path": r.local_path,
                    "name": pathlib.Path(r.local_path).name, "size": r.size,
                    "size_h": human_size(r.size), "sha256": r.sha256,
                    "note": r.note, "source": r.source}

        rows = [x for x in pmap(one, ts, workers=min(4, len(ts))) if isinstance(x, dict)]
        return {"backups": rows, "ok": sum(1 for r in rows if r["ok"])}
    return 202, _job_reply(app.jobs.submit("backup", f"业务备份 · {tag}", work))



@route("GET", r"/api/backup/sources")
def backup_sources(app, p, q, b):
    """列出可备份的靶机与其源目录（防守角色）。"""
    rows = []
    for t in app.cfg.targets:
        if t.is_attack:
            continue
        rows.append({
            "target": t.name, "host": t.host, "user": t.user,
            "configured": t.webroot or "",
            "detected": _SRC_CACHE.get(t.name, ""),
            "mode": "manual" if t.webroot else "auto",
        })
    return 200, {"sources": rows}


_SRC_CACHE: Dict[str, str] = {}


@route("POST", r"/api/backup/sources/detect")
def backup_sources_detect(app, p, q, b):
    """远程探测各靶机的业务目录（读 nginx/apache 配置）。"""
    names = b.get("targets")
    ts = _resolve(app, names) if names else app.cfg.resolve_role("defense")
    ts = [t for t in ts if not t.is_attack]
    from ..backup import detect_webroot
    from ..util import pmap

    def one(t):
        path = detect_webroot(app.cfg, t)
        if path:
            _SRC_CACHE[t.name] = path
        return {"target": t.name, "detected": path}

    rows = pmap(one, ts, workers=min(6, max(1, len(ts))))
    return 200, {"results": [r if isinstance(r, dict) else {"target": "?", "detected": ""}
                             for r in rows]}


@route("POST", r"/api/backup/source")
def backup_source_set(app, p, q, b):
    """修改某台靶机的备份源目录，写回 targets.yaml。"""
    name = (b.get("target") or "").strip()
    path = (b.get("path") or "").strip()
    if not name:
        raise ValueError("target 必填")
    if path and not path.startswith("/"):
        raise ValueError("请填绝对路径，例如 /www/wwwroot/site 或 /var/www/html")
    if "\n" in path or len(path) > 300:
        raise ValueError("路径不合法")

    try:
        target = app.cfg.target(name)
    except KeyError as e:
        raise ValueError(str(e)) from e
    if target.is_attack:
        raise ValueError("攻击目标不参与备份")

    # 远端校验（靶机暂时不通也允许保存，只是标记未验证）
    verified = None
    detail = ""
    warning = ""
    if path:
        try:
            from ..sshx import SSHSession
            with SSHSession(target, app.cfg, retries=0) as sess:
                r = sess.exec(f"[ -d {_shq(path)} ] && echo DIR || ([ -f {_shq(path)} ] "
                              f"&& echo FILE || echo MISSING)", timeout=12)
                if r.error:
                    warning = f"靶机暂不可达，已保存但未验证（{str(r.error)[:60]}）"
                    mark = ""
                else:
                    mark = (r.out or "").strip().splitlines()[-1] if r.out.strip() else ""
                verified = (mark == "DIR") if mark else None
                if mark == "MISSING":
                    raise ValueError(f"靶机上不存在该路径: {path}")
                if mark == "FILE":
                    raise ValueError(f"该路径是文件不是目录: {path}")
                listing = sess.exec(f"ls -1A {_shq(path)} 2>/dev/null | head -5; "
                                    f"du -sh {_shq(path)} 2>/dev/null | cut -f1", timeout=20)
                detail = " / ".join(x.strip() for x in listing.out.splitlines() if x.strip())
        except ValueError:
            raise
        except Exception as e:  # noqa: BLE001
            warning = f"靶机暂不可达，已保存但未验证（{type(e).__name__}）"

    from .. import yamledit
    file_path = yamledit.targets_path(app.cfg)
    before = file_path.read_text(encoding="utf-8")
    try:
        yamledit.set_target_field(app.cfg, name, "webroot", path)
        app.reload()
        after = app.cfg.target(name)
        if (after.webroot or "") != path:
            raise RuntimeError("写入后回读不一致")
    except Exception as e:  # noqa: BLE001
        try:
            yamledit.restore(file_path, before)
            app.reload()
        except Exception:
            pass
        raise ValueError(f"保存失败，已回滚: {e}") from e

    return 200, {"ok": True, "target": name, "path": path,
                 "verified": verified, "detail": detail, "warning": warning,
                 "mode": "manual" if path else "auto"}


@route("GET", r"/api/backup/source/diff")
def backup_source_diff(app, p, q, b):
    """看一眼配置文件里的变化（调试用）。"""
    from .. import yamledit
    path = yamledit.targets_path(app.cfg)
    return 200, {"path": str(path), "content": path.read_text(encoding="utf-8")[:20000]}


@route("POST", r"/api/backup/restore")
def backup_restore(app, p, q, b):
    archive = (b.get("archive") or "").strip()
    if not archive:
        raise ValueError("archive 必填")
    path = safe_path(app.cfg, archive) if not archive.startswith("/") else pathlib.Path(archive)
    if not path.exists():
        raise ValueError(f"备份不存在: {path}")
    if not b.get("confirm"):
        raise ValueError("还原会覆盖靶机 web 目录，需要 confirm=true")
    ts = _resolve(app, b.get("targets"))
    webroot = b.get("webroot") or None

    def work(job):
        from ..backup import restore_target
        for t in ts:
            job.log(f"[{t.name}] 还原 {path.name} -> {webroot or '自动探测'}")
            r = restore_target(app.cfg, t, str(path), webroot)
            job.log(f"[{t.name}] {'完成' if r.ok else '失败：' + r.note}",
                    "ok" if r.ok else "error")
        return {"archive": str(path)}
    return 202, _job_reply(app.jobs.submit("backup", f"回滚 · {path.name}", work))


# ----------------------------------------------------------------- 扫描
@route("POST", r"/api/scan/ports")
def scan_ports(app, p, q, b):
    ts = _resolve(app, b.get("targets"))
    ports = (b.get("ports") or "").strip() or None

    def work(job):
        from ..scan import nmap_scan, sort_findings
        job.log(f"端口扫描 {len(ts)} 台，范围 {ports or '默认'}")
        allf = []
        # 逐台扫描：进度可观测，避免长时间无输出
        for i, t in enumerate(ts, 1):
            job.log(f"[{t.name}] 扫描中 ...（{i}/{len(ts)}）")
            res = nmap_scan(app.cfg, [t], ports=ports)
            fs = sort_findings(res.get(t.name, []))
            opened = [f for f in fs if f.kind == "port"]
            for f in fs:
                allf.append(f)
                if f.kind == "port":
                    job.log(f"[{t.name}] {f.location} {f.title} {f.detail[:60]}",
                            "warn" if f.severity in ("high", "medium") else "info")
            job.log(f"[{t.name}] 完成，{len(opened)} 个开放端口",
                    "ok" if opened else "warn")
        _store_findings(app, allf, "scan-ports")
        return {"count": len(allf),
                "findings": [f.to_dict() for f in allf[:300]]}
    return 202, _job_reply(app.jobs.submit("scan", f"端口扫描 · {len(ts)} 台", work))


@route("POST", r"/api/scan/web")
def scan_web(app, p, q, b):
    ts = _resolve(app, b.get("targets"))

    def work(job):
        from ..flag import extract_flags
        from ..scan import sort_findings, web_probe
        from ..util import pmap
        job.log(f"Web 指纹 {len(ts)} 台 ...")

        def one(t):
            fs = web_probe(app.cfg, t)
            for f in fs:
                job.log(f"[{t.name}] [{f.severity}] {f.title} {f.location}",
                        "warn" if f.severity in ("high", "medium") else "info")
            return fs

        raw = pmap(one, ts, workers=min(6, len(ts)))
        allf = []
        for r in raw:
            if isinstance(r, Exception):
                job.log(f"探测异常: {r}", "error")
                continue
            allf.extend(r)
        allf = sort_findings(allf)
        _store_findings(app, allf, "scan-web")
        new_flags = 0
        for f in allf:
            for fl in extract_flags(f"{f.evidence}\n{f.detail}", app.cfg):
                if app.store.add_flag(fl, target=f.target, source="web-probe"):
                    new_flags += 1
                    job.log(f"捕获 FLAG {fl}", "ok")
        return {"count": len(allf), "flags": new_flags,
                "findings": [f.to_dict() for f in allf[:300]]}
    return 202, _job_reply(app.jobs.submit("scan", f"Web 指纹 · {len(ts)} 台", work))



# ------------------------------------------------------------ WebShell 查杀
@route("GET", r"/api/scan/shell/rules")
def shell_rules(app, p, q, b):
    """看看规则库长什么样（现场调规则用）。"""
    from ..webscan import load_rules, rules_path
    rules, extra = load_rules(app.cfg)
    return 200, {
        "path": str(rules_path(app.cfg)),
        "count": len(rules),
        "names": extra.get("names") or [],
        "rules": [{"id": r["id"], "name": r["name"], "severity": r["severity"],
                   "score": r["score"], "category": r["category"], "mode": r["mode"],
                   "patterns": r.get("patterns")} for r in rules],
    }


@route("POST", r"/api/scan/shell")
def scan_shell(app, p, q, b):
    """静态查杀：本地目录 / 备份包，或从靶机 webroot 拉回脚本再扫。"""
    from ..webscan import scan_path, scan_remote, summarize

    path = (b.get("path") or "").strip()
    names = b.get("targets")
    ts = [] if path else (_resolve(app, names) if names else app.cfg.resolve_role("defense"))
    if not path and not ts:
        raise ValueError("没有可扫描的目标：填一个本地路径，或选择靶机")

    max_files = min(int(b.get("max_files") or 20000), 50000)

    def work(job):
        rows, allf = [], []
        if path:
            local = pathlib.Path(path)
            if not local.is_absolute():
                local = app.cfg.workdir / local
            job.log(f"扫描本地路径 {local}")
            rep = scan_path(app.cfg, local, max_files=max_files)
            job.log(summarize(rep), "ok" if not rep.error else "error")
            for r in rep.results:
                if r.verdict != "clean":
                    job.log(f"[{r.verdict}] {r.path} 得分 {r.score} "
                            f"({r.hits[0].name if r.hits else ''})",
                            "error" if r.verdict == "malicious" else "warn")
            rows.append({"target": "local", **rep.to_dict()})
            allf.extend(rep.findings("local", "shell"))
        else:
            for t in ts:
                job.log(f"[{t.name}] 打包脚本文件并拉回 ...")
                rep = scan_remote(app.cfg, t, max_files=max_files)
                if rep.error:
                    job.log(f"[{t.name}] {rep.error}", "error")
                else:
                    job.log(f"[{t.name}] {summarize(rep)}",
                            "warn" if (rep.malicious or rep.suspicious) else "ok")
                    for r in rep.results[:40]:
                        if r.verdict != "clean":
                            job.log(f"[{t.name}] {r.verdict} {r.path} 得分 {r.score}",
                                    "error" if r.verdict == "malicious" else "warn")
                rows.append({"target": t.name, **rep.to_dict()})
                allf.extend(rep.findings(t.name, "shell"))
        _store_findings(app, allf, "shellscan")
        bad = sum(1 for r in rows if r.get("malicious") or r.get("suspicious"))
        return {"rows": rows, "findings": len(allf), "affected": bad,
                "files": sum(r.get("files") or 0 for r in rows)}
    return 202, _job_reply(app.jobs.submit("shell", "WebShell 查杀", work))


@route("POST", r"/api/scan/vulns")
def scan_vulns(app, p, q, b):
    ts = _resolve(app, b.get("targets"))
    severity = (b.get("severity") or "").strip() or None
    templates = (b.get("templates") or "").strip() or None

    def work(job):
        from ..scan import nuclei_scan, sort_findings, target_map_of, urls_of
        urls = urls_of(ts)
        if not urls:
            raise ValueError("没有配置 web 地址")
        job.log(f"nuclei 扫描 {len(urls)} 个 URL（severity={severity or '默认'}）")
        fs = sort_findings(nuclei_scan(app.cfg, urls, target_map_of(ts),
                                       severity=severity, templates=templates))
        for f in fs:
            job.log(f"[{f.target}] [{f.severity}] {f.title} {f.location}",
                    "warn" if f.severity in ("critical", "high") else "info")
        _store_findings(app, fs, "scan-vulns")
        return {"count": len(fs), "findings": [f.to_dict() for f in fs[:300]]}
    return 202, _job_reply(app.jobs.submit("scan", "漏洞模板扫描", work))


# ----------------------------------------------------------------- 利用
@route("GET", r"/api/exploit/plugins")
def exploit_plugins(app, p, q, b):
    from ..exploit import load_plugins
    plugins = load_plugins()
    return 200, {"plugins": [{"name": x.name, "kind": x.kind,
                              "severity": x.severity,
                              "description": x.description} for x in plugins.values()]}


@route("POST", r"/api/exploit/run")
def exploit_run(app, p, q, b):
    plugin = (b.get("plugin") or "").strip()
    if not plugin:
        raise ValueError("plugin 必填")
    ts = _resolve(app, b.get("targets"))
    check_only = bool(b.get("check_only"))

    def work(job):
        from ..exploit import load_plugins, run_batch
        plugins = load_plugins()
        if plugin == "all":
            chosen = list(plugins.values())
        else:
            if plugin not in plugins:
                raise ValueError(f"未找到插件 {plugin}")
            chosen = [plugins[plugin]]
        rows = []
        for pl in chosen:
            job.log(f"▶ {pl.name} — {pl.description}", "step")
            results = run_batch(app.cfg, pl, ts, workers=min(6, len(ts)),
                                dry_run=check_only)
            for r in results:
                app.store.event("finding" if r.ok else "action", target=r.target,
                                title=f"exploit:{pl.name}",
                                severity=pl.severity if r.ok else "info",
                                data={"ok": r.ok, "evidence": trunc(r.evidence, 4000),
                                      "flags": r.flags, "error": r.error})
                for fl in r.flags:
                    if app.store.add_flag(fl, target=r.target, source=f"exploit:{pl.name}"):
                        job.log(f"FLAG {fl}", "ok")
                rows.append({"target": r.target, "plugin": pl.name, "ok": r.ok,
                             "evidence": trunc(r.evidence, 1200), "error": r.error,
                             "flags": r.flags, "elapsed": round(r.elapsed, 2)})
                job.log(f"[{r.target}] {'命中' if r.ok else '失败'}"
                        f"{' · ' + (r.error or '')[:120] if r.error else ''}",
                        "ok" if r.ok else "warn")
        return {"results": rows, "ok": sum(1 for r in rows if r["ok"])}
    return 202, _job_reply(app.jobs.submit("exploit", f"利用 · {plugin}", work))


# ------------------------------------------------------------------ FLAG
@route("POST", r"/api/flag/hunt")
def flag_hunt(app, p, q, b):
    ts = _resolve(app, b.get("targets"))
    do_submit = bool(b.get("submit"))
    local = [x for x in (b.get("local") or []) if x]

    def work(job):
        from ..flag import Submitter, hunt_local, hunt_remote
        from ..util import pmap
        job.log(f"在 {len(ts)} 台靶机检索 FLAG ...")

        def one(t):
            flags = hunt_remote(app.cfg, t)
            job.log(f"[{t.name}] 命中 {len(flags)} 个", "ok" if flags else "info")
            return t.name, flags

        total_new = 0
        for name, flags in pmap(one, ts, workers=min(8, len(ts))):
            if isinstance(flags, Exception):
                job.log(f"检索异常: {flags}", "error")
                continue
            for fl in flags:
                if app.store.add_flag(fl, target=name, source="ssh-hunt"):
                    total_new += 1
                    job.log(f"新增 {fl}", "ok")
        local_items = hunt_local(local, app.cfg).items() if local else []
        for path, flags in local_items:
            for fl in flags:
                if app.store.add_flag(fl, target=path, source="local-scan"):
                    total_new += 1
                    job.log(f"新增 {fl}（{path}）", "ok")
        res = {"new": total_new}
        if do_submit and total_new:
            sub = Submitter(app.cfg, app.store)
            rs = sub.submit_all(only_pending=True, workers=1)
            res["submitted"] = [{"flag": x.flag, "ok": x.ok, "msg": x.message} for x in rs]
            job.log(f"提交 {sum(1 for x in rs if x.ok)}/{len(rs)} 成功", "ok")
        return res
    return 202, _job_reply(app.jobs.submit("flag", f"FLAG 检索 · {len(ts)} 台", work))


@route("POST", r"/api/flag/submit")
def flag_submit(app, p, q, b):
    only_pending = not bool(b.get("all"))

    def work(job):
        from ..flag import Submitter
        rows = app.store.flags(only_pending=only_pending)
        job.log(f"待提交 {len(rows)} 个（mode={app.cfg.submit.mode}）")
        rs = Submitter(app.cfg, app.store).submit_all(only_pending=only_pending, workers=1)
        for x in rs:
            job.log(f"{'✓' if x.ok else '✗'} {x.flag[:50]} — {x.message[:80]}",
                    "ok" if x.ok else "error")
        return {"total": len(rs), "ok": sum(1 for x in rs if x.ok)}
    return 202, _job_reply(app.jobs.submit("flag", "提交 FLAG", work))


# -------------------------------------------------- FLAG 服务器（经靶机拉）
@route("GET", r"/api/flagserver")
def flagserver_get(app, p, q, b):
    from .. import flagserver as fs
    conf = fs.load_conf(app.cfg, app.store)
    return 200, {
        "conf": conf,
        "defaults": fs.defaults(),
        "yaml": (getattr(app.cfg, "extra", {}) or {}).get("flagserver") or {},
        "last": fs.last_run(app.store),
        "targets": [{"name": t.name, "host": t.host,
                     "role": "attack" if t.is_attack else "defense",
                     "enabled": t.enabled} for t in app.cfg.targets],
        "submit_mode": app.cfg.submit.mode,
        "profile": (app.store.active_submit_profile() or {}).get("name", ""),
    }


@route("PUT", r"/api/flagserver")
def flagserver_save(app, p, q, b):
    from .. import flagserver as fs
    conf = fs.load_conf(app.cfg, app.store)
    conf.update({k: v for k, v in (b.get("conf") or b).items() if k in fs.DEFAULTS})
    if conf.get("mode") not in ("http", "cmd"):
        raise ValueError("mode 只能是 http 或 cmd")
    if conf.get("mode") == "http" and not (conf.get("url") or "").strip():
        raise ValueError("http 模式必须填 flag 服务器地址")
    if conf.get("mode") == "cmd" and not (conf.get("cmd") or "").strip():
        raise ValueError("cmd 模式必须填命令")
    conf["timeout"] = min(120, max(2, int(conf.get("timeout") or 10)))
    conf["workers"] = min(16, max(1, int(conf.get("workers") or 4)))
    if not isinstance(conf.get("headers"), dict):
        raise ValueError("headers 必须是 JSON 对象")
    if not isinstance(conf.get("tokens"), dict):
        raise ValueError("tokens 必须是 JSON 对象（靶机名 -> token）")
    saved = fs.save_conf(app.store, conf)
    app.store.event("action", target="local", title="flagserver.config",
                    data={"mode": saved["mode"], "url": saved.get("url", ""),
                          "scope": saved.get("scope")})
    return 200, {"ok": True, "conf": saved}


@route("POST", r"/api/flagserver/token")
def flagserver_token(app, p, q, b):
    """逐机 token：靶机表格里直接改，只动这一台，不动其它配置。"""
    from .. import flagserver as fs
    name = (b.get("target") or "").strip()
    if not name:
        raise ValueError("target 必填")
    conf = fs.load_conf(app.cfg, app.store)
    tokens = dict(conf.get("tokens") or {})
    value = (b.get("token") or "").strip()
    if value:
        tokens[name] = value
    else:
        tokens.pop(name, None)
    conf["tokens"] = tokens
    fs.save_conf(app.store, conf)
    return 200, {"ok": True, "target": name, "token_set": bool(value),
                 "tokens": {k: ("***" if v else "") for k, v in tokens.items()}}


@route("POST", r"/api/flagserver/fetch")
def flagserver_fetch(app, p, q, b):
    from .. import flagserver as fs
    names = b.get("targets") or None
    if isinstance(names, str):
        names = [names]
    submit = b.get("submit")
    submit = None if submit is None else bool(submit)

    def work(job):
        conf = fs.load_conf(app.cfg, app.store)
        if b.get("conf"):
            conf.update({k: v for k, v in b["conf"].items() if k in fs.DEFAULTS})
        res = fs.fetch_all(app.cfg, app.store, conf=conf, names=names,
                           submit=submit, log=job.log)
        job.log(f"共新增 {res['new']} 个 flag，提交成功 {res['submitted']['ok']} 个",
                "ok" if res["new"] else "warn")
        return res
    return 202, _job_reply(app.jobs.submit("flag", "经靶机拉取 FLAG", work))


@route("POST", r"/api/flagserver/test")
def flagserver_test(app, p, q, b):
    """单机调试：只跑一台，把命令、原始响应、退出码都摊开给人看。"""
    from .. import flagserver as fs

    def work(job):
        conf = fs.load_conf(app.cfg, app.store)
        if b.get("conf"):
            conf.update({k: v for k, v in b["conf"].items() if k in fs.DEFAULTS})
        name = (b.get("target") or "").strip()
        targets = fs.pick_targets(app.cfg, conf, [name] if name else None)
        if not targets:
            raise ValueError("没有可用靶机")
        t = targets[0]
        job.log(f"在 {t.name}({t.host}) 上访问 flag 服务器 ...")
        r = fs.fetch_one(app.cfg, t, conf)
        job.log(f"执行：{trunc(r.cmd, 300)}")
        if r.out:
            for line in r.out.splitlines()[:40]:
                job.log(f"  │ {line}")
        job.log(f"退出码 {r.rc}，工具 {r.tool or '-'}，命中 {len(r.flags)} 个",
                "ok" if r.flags else ("warn" if r.ok else "err"))
        if r.flags:
            for f in r.flags:
                job.log(f"FLAG {f}", "ok")
        return r.to_dict()
    return 202, _job_reply(app.jobs.submit("flag", "flagserver 调试", work))


# ------------------------------------------------------------------ 日志
@route("POST", r"/api/logs/pull")
def logs_pull(app, p, q, b):
    ts = _resolve(app, b.get("targets"))
    do_analyze = bool(b.get("analyze", True))

    def work(job):
        from ..logx import analyze_paths, pull_logs
        out = []
        for t in ts:
            job.log(f"[{t.name}] 拉取 /var/log ...")
            files = pull_logs(app.cfg, t)
            job.log(f"[{t.name}] {len(files)} 个文件", "ok" if files else "warn")
            if do_analyze and files:
                rep = analyze_paths([str(app.cfg.evidence_dir / "logs" / t.name)],
                                    app.cfg, target=t.name)
                md = app.cfg.evidence_dir / "logs" / t.name / "analysis.md"
                md.write_text(rep.text(), encoding="utf-8")
                for f in rep.findings:
                    app.store.event("finding", target=t.name, title=f.title,
                                    severity=f.severity, data=f.to_dict())
                    job.log(f"[{t.name}] [{f.severity}] {f.title}",
                            "warn" if f.severity in ("high", "critical") else "info")
                out.append({"target": t.name, "files": len(files),
                            "findings": len(rep.findings),
                            "report": md.relative_to(app.cfg.workdir).as_posix(),
                            "text": trunc(rep.text(), 6000)})
        return {"targets": out}
    return 202, _job_reply(app.jobs.submit("logs", f"日志取证 · {len(ts)} 台", work))


@route("POST", r"/api/logs/analyze")
def logs_analyze(app, p, q, b):
    paths = b.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        default_dir = app.cfg.evidence_dir / "logs"
        if default_dir.exists():
            paths = [str(default_dir)]
    if not paths:
        raise ValueError("没有可分析的日志路径")
    ai = bool(b.get("ai", True))

    def work(job):
        from ..logx import analyze_paths
        job.log(f"分析 {len(paths)} 个路径（AI={'开' if ai else '关'}）")
        cfg = app.cfg
        if not ai:
            cfg.ai.enabled = False
        rep = analyze_paths(paths, cfg, target=b.get("target") or "", log=job.log)
        for f in rep.findings:
            app.store.event("finding", target=b.get("target") or "log", title=f.title,
                            severity=f.severity, data=f.to_dict())
            job.log(f"[{f.severity}] {f.title} {f.detail[:100]}",
                    "warn" if f.severity in ("high", "critical") else "info")
        md = app.cfg.report_dir / f"log_{time.strftime('%Y%m%d_%H%M%S')}.md"
        md.write_text(rep.text(), encoding="utf-8")
        job.log(f"报告 {md.name}", "ok")
        return {"kind": rep.kind, "files": rep.files, "stats": rep.stats,
                "timeline": rep.timeline[:60],
                "findings": [f.to_dict() for f in rep.findings[:200]],
                "text": trunc(rep.text(), 40000),
                "detail": rep.detail[:200],
                "samples": rep.samples[:30],
                "report": md.relative_to(app.cfg.workdir).as_posix()}
    return 202, _job_reply(app.jobs.submit("logs", "日志分析", work))


# ------------------------------------------------------------------ 流量
@route("POST", r"/api/traffic/analyze")
def traffic_analyze(app, p, q, b):
    pcap = (b.get("path") or "").strip()
    if not pcap:
        raise ValueError("pcap 路径必填")
    path = pathlib.Path(pcap).expanduser()
    if not path.is_absolute():
        path = app.cfg.workdir / pcap
    if not path.exists():
        raise ValueError(f"文件不存在: {path}")
    ai = bool(b.get("ai", True))

    def work(job):
        from ..traffic import analyze_pcap
        job.log(f"解析 {path.name}（{human_size(path.stat().st_size)}）")
        if path.stat().st_size > 50 << 20:
            job.log("大文件：需多趟 tshark 解析，可能 1-2 分钟，请勿关闭页面", "warn")
        rep = analyze_pcap(app.cfg, str(path), ai=ai, log=job.log)
        for f in rep.findings:
            app.store.event("finding", target="pcap", title=f.title,
                            severity=f.severity, data=f.to_dict())
            job.log(f"[{f.severity}] {f.title}", "warn"
                    if f.severity in ("high", "critical") else "info")
        md = app.cfg.report_dir / f"pcap_{path.stem}_{time.strftime('%H%M%S')}.md"
        md.write_text(rep.text(), encoding="utf-8")
        job.log(f"报告 {md.name}", "ok")
        return {"stats": rep.stats, "timeline": rep.timeline[:60],
                "findings": [f.to_dict() for f in rep.findings[:200]],
                "http": rep.http[:200],
                "text": trunc(rep.text(), 12000),
                "report": md.relative_to(app.cfg.workdir).as_posix(),
                "export_dir": rep.export_dir}
    return 202, _job_reply(app.jobs.submit("traffic", f"流量分析 · {path.name}", work))


# ------------------------------------------------------------------ 取证
@route("POST", r"/api/shot/capture")
def shot_capture(app, p, q, b):
    step = (b.get("step") or "").strip()
    if not step:
        raise ValueError("步骤名必填")
    from ..shot import capture
    shot = capture(app.cfg, app.store, step, url=b.get("url") or "",
                   note=b.get("note") or "", selector=b.get("selector") or None,
                   screen=bool(b.get("screen")))
    rel = ""
    if shot.path:
        try:
            rel = pathlib.Path(shot.path).relative_to(app.cfg.workdir).as_posix()
        except ValueError:
            rel = shot.path
    kind = "ok" if shot.path else "warn"
    msg = "已截图" if shot.path else "未生成图片（未安装 playwright），仅记录步骤"
    return 200, {"ok": bool(shot.path), "msg": msg, "path": shot.path, "rel": rel,
                 "step": step, "level": kind}


@route("POST", r"/api/shot/mark")
def shot_mark(app, p, q, b):
    step = (b.get("step") or "").strip()
    if not step:
        raise ValueError("步骤名必填")
    from ..shot import mark
    mark(app.store, step, note=b.get("note") or "",
         image=b.get("image") or "", url=b.get("url") or "")
    return 200, {"ok": True, "msg": "已登记"}


@route("POST", r"/api/shot/timeline")
def shot_timeline(app, p, q, b):
    from ..shot import write_timeline
    path = write_timeline(app.cfg, app.store, b.get("title") or "作战时间线")
    return 200, {"ok": True, "path": str(path),
                 "content": path.read_text(encoding="utf-8")[:8000]}


# ------------------------------------------------------------------ 报告
@route("POST", r"/api/report")
def report_build(app, p, q, b):
    from ..report import build_markdown, write_report
    files = write_report(app.cfg, app.store, b.get("title") or "")
    return 200, {"ok": True,
                 "files": [f.relative_to(app.cfg.workdir).as_posix() for f in files],
                 "markdown": build_markdown(app.cfg, app.store, b.get("title") or "")[:12000]}


# -------------------------------------------------------------------- AI
# 页面上的"本地模型"配置面板：读写 config.yaml 的 ai 段。
# 本地模型五花八门（LM Studio / Ollama / vLLM / llama.cpp），端点、模型名、上下文
# 长度都要能现场调，所以这几个字段必须可写；写的是 YAML 原文件，改完就地生效，
# 不重启服务、不断开已连的终端。
AI_FIELDS = ("enabled", "base_url", "model", "api_key", "timeout",
             "temperature", "max_tokens")

AI_PRESETS = [
    {"name": "LM Studio", "base_url": "http://127.0.0.1:1234/v1"},
    {"name": "Ollama", "base_url": "http://127.0.0.1:11434/v1"},
    {"name": "vLLM", "base_url": "http://127.0.0.1:8000/v1"},
    {"name": "llama.cpp", "base_url": "http://127.0.0.1:8080/v1"},
]


def _ai_public(cfg: Config) -> Dict[str, Any]:
    ai = cfg.ai
    key = ai.api_key or ""
    plain = key in ("", "not-needed")
    return {
        "enabled": bool(ai.enabled),
        "base_url": ai.base_url,
        "model": ai.model,
        "api_key": key if plain else "",       # 真 key 不下发，只给"已设置"标记
        "api_key_set": bool(key) and not plain,
        "timeout": ai.timeout,
        "temperature": ai.temperature,
        "max_tokens": ai.max_tokens,
        "config": str(cfg.path),
    }


def _probe_models(base_url: str, api_key: str = "", timeout: int = 6) -> Dict[str, Any]:
    """问 OpenAI 兼容端点要模型清单。返回 {ok, models, elapsed, error}。"""
    import time as _t
    import requests
    base = (base_url or "").rstrip("/")
    if not base:
        return {"ok": False, "models": [], "elapsed": 0, "error": "未填写端点"}
    t0 = _t.time()
    sess = requests.Session()
    sess.trust_env = False          # 本地模型绝不能走系统代理
    try:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        r = sess.get(f"{base}/models", headers=headers, timeout=timeout)
        elapsed = round((_t.time() - t0) * 1000)
        if r.status_code >= 400:
            return {"ok": False, "models": [], "elapsed": elapsed,
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        data = r.json() or {}
        rows = data.get("data") if isinstance(data, dict) else None
        if rows is None and isinstance(data, list):
            rows = data
        models = []
        for m in rows or []:
            mid = (m or {}).get("id") if isinstance(m, dict) else str(m)
            if mid:
                models.append(str(mid))
        return {"ok": True, "models": sorted(models), "elapsed": elapsed, "error": ""}
    except requests.Timeout:
        return {"ok": False, "models": [], "elapsed": round((_t.time() - t0) * 1000),
                "error": "连接超时（服务没起来，或端口不对）"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "models": [], "elapsed": round((_t.time() - t0) * 1000),
                "error": str(e)}
    finally:
        sess.close()


@route("GET", r"/api/ai/config")
def ai_config_get(app, p, q, b):
    return 200, {"ai": _ai_public(app.cfg), "fields": list(AI_FIELDS),
                 "presets": AI_PRESETS}


@route("PUT", r"/api/ai/config")
def ai_config_save(app, p, q, b):
    from .. import yamledit
    from ..config import AIConfig

    changes: Dict[str, Any] = {}

    def _num(value, cast, low, high, label):
        try:
            v = cast(value)
        except (TypeError, ValueError):
            raise ValueError(f"{label} 必须是数字") from None
        if not (low <= v <= high):
            raise ValueError(f"{label} 要在 {low} ~ {high} 之间")
        return v

    if "enabled" in b:
        changes["enabled"] = bool(b["enabled"])
    if "base_url" in b:
        url = (b.get("base_url") or "").strip().rstrip("/")
        if not url:
            raise ValueError("端点不能为空")
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        changes["base_url"] = url
    if "model" in b:
        model = (b.get("model") or "").strip()
        if not model:
            raise ValueError("模型名不能为空（可先点「拉取模型」选一个）")
        changes["model"] = model
    if b.get("api_key"):
        changes["api_key"] = str(b["api_key"]).strip()
    if b.get("clear_api_key"):
        changes["api_key"] = "not-needed"
    if "timeout" in b and b.get("timeout") is not None:
        changes["timeout"] = _num(b.get("timeout"), int, 5, 1800, "超时(秒)")
    if "temperature" in b and b.get("temperature") is not None:
        changes["temperature"] = _num(b.get("temperature"), float, 0.0, 2.0, "temperature")
    if "max_tokens" in b and b.get("max_tokens") is not None:
        changes["max_tokens"] = _num(b.get("max_tokens"), int, 64, 32768, "max_tokens")
    if not changes:
        raise ValueError("没有要修改的字段")

    # 配置文件里的 api_key 可能是 ${ENV} 占位；值没变就别把明文写回去
    raw = app.cfg.path.read_text(encoding="utf-8") if app.cfg.path.exists() else ""
    for f in ("api_key", "base_url"):
        if f in changes and f"${{{f.upper()}}}" in raw:
            if changes[f] == getattr(app.cfg.ai, f):
                changes.pop(f)
    if not changes:
        return 200, {"ok": True, "changed": [], "msg": "值没变化",
                     "ai": _ai_public(app.cfg)}

    res = yamledit.update_section(app.cfg, "ai", changes)

    # 就地改运行时副本：AutoLoop / RoundWatcher 持有的是同一个 cfg 对象，
    # 这样保存后立刻生效，也不必重建 Store（重建会把终端会话一起清掉）
    for k, v in changes.items():
        setattr(app.cfg.ai, k, v)
    app.cfg.ai = AIConfig(**{k: getattr(app.cfg.ai, k) for k in AI_FIELDS})
    _AI_CACHE.update({"ts": 0.0, "alive": False, "probing": False})

    app.store.event("action", target="local", title="ai.config",
                    data={k: ("***" if k == "api_key" else v) for k, v in changes.items()})
    return 200, {"ok": True, "changed": sorted(changes), "ai": _ai_public(app.cfg),
                 "diff": res.get("diff", ""), "path": res.get("path", "")}


@route("GET", r"/api/ai/models")
def ai_models(app, p, q, b):
    """按当前或指定端点列模型。改端点前先看看有没有连上，比盲猜强。"""
    base = (q.get("base_url") or "").strip() or app.cfg.ai.base_url
    key = (q.get("api_key") or "").strip()
    if not key and app.cfg.ai.api_key not in ("", "not-needed"):
        key = app.cfg.ai.api_key
    out = _probe_models(base, key, timeout=int(q.get("timeout") or 6))
    out["base_url"] = base
    out["current"] = app.cfg.ai.model
    return 200, out


@route("POST", r"/api/ai/test")
def ai_test(app, p, q, b):
    """真跑一次补全：有的端点 /models 能通但模型名写错，只有真请求才暴露。"""
    base = (b.get("base_url") or "").strip().rstrip("/") or app.cfg.ai.base_url
    model = (b.get("model") or "").strip() or app.cfg.ai.model
    key = (b.get("api_key") or "").strip() or app.cfg.ai.api_key

    def work(job):
        import time as _t
        import requests
        job.log(f"端点 {base} · 模型 {model}")
        probe = _probe_models(base, key, timeout=6)
        if not probe["ok"]:
            job.log(f"/models 不通：{probe['error']}", "warn")
        else:
            job.log(f"/models 可用（{probe['elapsed']}ms，{len(probe['models'])} 个模型）")
            if model and probe["models"] and model not in probe["models"]:
                job.log(f"注意：模型清单里没有 {model}", "warn")
        payload = {"model": model,
                   "messages": [{"role": "user", "content": "只回复两个字：可用"}],
                   "max_tokens": 32, "temperature": 0, "stream": False}
        headers = {"Content-Type": "application/json"}
        if key and key != "not-needed":
            headers["Authorization"] = f"Bearer {key}"
        t0 = _t.time()
        job.log("发送一次真实补全 ...")
        sess = requests.Session()
        sess.trust_env = False
        try:
            r = sess.post(f"{base}/chat/completions", json=payload, headers=headers,
                          timeout=min(180, int(b.get("timeout") or 120)))
            ms = round((_t.time() - t0) * 1000)
            if r.status_code >= 400:
                job.log(f"补全失败 HTTP {r.status_code}: {r.text[:200]}", "err")
                return {"ok": False, "ms": ms, "models": probe["models"],
                        "error": f"HTTP {r.status_code}: {r.text[:200]}"}
            data = r.json() or {}
            msg = ((data.get("choices") or [{}])[0].get("message") or {})
            text = (msg.get("content") or "").strip()
            usage = data.get("usage") or {}
            if not text:
                job.log("返回正文为空（多是 max_tokens 被思考过程吃光）", "warn")
            job.log(f"补全成功 {ms}ms，输出 {len(text)} 字")
            return {"ok": True, "ms": ms, "text": text[:200], "model": model,
                    "models": probe["models"], "usage": usage,
                    "models_ms": probe["elapsed"], "models_error": probe["error"]}
        except requests.Timeout:
            job.log("补全超时", "err")
            return {"ok": False, "ms": round((_t.time() - t0) * 1000),
                    "models": probe["models"], "error": "补全请求超时"}
        except Exception as e:  # noqa: BLE001
            job.log(f"补全异常：{e}", "err")
            return {"ok": False, "ms": round((_t.time() - t0) * 1000),
                    "models": probe["models"], "error": str(e)}
        finally:
            sess.close()

    return 202, _job_reply(app.jobs.submit("ai", f"模型连通测试 · {model}", work))


@route("GET", r"/api/ai/health")
def ai_health(app, p, q, b):
    from ..aiclient import AIClient
    import time as _t
    ai = AIClient(app.cfg)
    t0 = _t.time()
    alive = ai.available(force=True)
    ms = round((_t.time() - t0) * 1000)
    probe = _probe_models(app.cfg.ai.base_url, app.cfg.ai.api_key, timeout=4) if alive else {
        "models": [], "error": "端点不可达", "elapsed": ms}
    _AI_CACHE.update({"ts": _t.time(), "alive": alive, "probing": False})
    return 200, {"enabled": app.cfg.ai.enabled, "alive": alive, "ms": ms,
                 "model": app.cfg.ai.model, "base_url": app.cfg.ai.base_url,
                 "models": probe.get("models") or [],
                 "models_ms": probe.get("elapsed"),
                 "model_present": (app.cfg.ai.model in (probe.get("models") or []))
                 if probe.get("models") else None,
                 "error": probe.get("error") or ""}



@route("POST", r"/api/ai/ask")
def ai_ask(app, p, q, b):
    prompt = (b.get("prompt") or "").strip()
    if not prompt:
        raise ValueError("prompt 必填")
    files = b.get("files") or []
    if isinstance(files, str):
        files = [files]

    def work(job):
        from ..aiclient import AIClient
        text = prompt
        for rel in files:
            fp = safe_path(app.cfg, rel)
            if fp.is_file():
                body = fp.read_text(encoding="utf-8", errors="replace")
                text += f"\n\n--- {fp.name} ---\n{trunc(body, 12000)}"
                job.log(f"注入 {fp.name}（{human_size(fp.stat().st_size)}）")
        job.log("请求本地模型 ...")
        res = AIClient(app.cfg).chat(text)
        if not res.ok:
            job.log(f"模型不可用：{res.error}", "warn")
        return {"ok": res.ok, "text": res.text, "model": res.model, "error": res.error}
    return 202, _job_reply(app.jobs.submit("ai", "AI 研判", work))


@route("POST", r"/api/ai/audit")
def ai_audit(app, p, q, b):
    rel = (b.get("path") or "").strip()
    if not rel:
        raise ValueError("path 必填")
    fp = safe_path(app.cfg, rel) if not rel.startswith("/") else pathlib.Path(rel)
    if not fp.is_file():
        raise ValueError(f"文件不存在: {fp}")

    def work(job):
        from ..aiclient import AIClient
        code = fp.read_text(encoding="utf-8", errors="replace")
        job.log(f"审计 {fp.name}（{human_size(fp.stat().st_size)}）")
        res = AIClient(app.cfg).explain_code(code, fp.name)
        return {"ok": res.ok, "text": res.text, "error": res.error}
    return 202, _job_reply(app.jobs.submit("ai", f"源码审计 · {fp.name}", work))


# ------------------------------------------------------------------ 终端
@route("GET", r"/api/term/status")
def term_status(app, p, q, b):
    return 200, {"sessions": app.term_pool.status()}


@route("POST", r"/api/term/exec")
def term_exec(app, p, q, b):
    cmd = (b.get("cmd") or "").rstrip("\n")
    if not cmd.strip():
        raise ValueError("命令不能为空")
    ts = _resolve(app, b.get("targets"))
    timeout = min(int(b.get("timeout") or 30), 120)
    reset = bool(b.get("reset"))
    pool = app.term_pool

    from ..util import pmap
    raw = pmap(lambda t: pool.run(t, cmd, timeout=timeout, reset=reset), ts,
               workers=min(6, max(1, len(ts))))
    rows = []
    for r in raw:
        row = r.to_dict() if hasattr(r, "to_dict") else {
            "target": "?", "ok": False, "output": "", "rc": -1,
            "error": str(r), "elapsed": 0}
        rows.append(row)
        app.store.event("action", target=str(row["target"]), title="term",
                        data={"cmd": cmd, "rc": row["rc"],
                              "out": trunc(str(row.get("output") or ""), 1500)})
    return 200, {"results": rows}


@route("POST", r"/api/term/reset")
def term_reset(app, p, q, b):
    names = b.get("targets")
    closed = 0
    if names:
        for t in _resolve(app, names):
            closed += app.term_pool.reset(t.name)
    else:
        closed += app.term_pool.reset()
    return 200, {"ok": True, "closed": closed,
                 "sessions": app.term_pool.status()}




# --------------------------------------------------------------- 修改 / 删除
def _norm_web(value) -> List[str]:
    if isinstance(value, str):
        value = [x.strip() for x in value.split(",") if x.strip()]
    out = []
    for u in value or []:
        u = str(u).strip()
        if not u:
            continue
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        out.append(u.rstrip("/"))
    return out


@route("PUT", r"/api/targets/(?P<name>[^/]+)")
def targets_update(app, p, q, b):
    """修改一台靶机（可改名），写回 YAML 并级联历史记录。"""
    import urllib.parse as _up
    old = _up.unquote(p["name"])
    try:
        target = app.cfg.target(old)
    except KeyError as e:
        raise KeyError(str(e)) from e

    changes: Dict[str, Any] = {}
    new_name = (b.get("name") or "").strip()
    if new_name and new_name != old:
        if re.search(r"[\s:/#]", new_name):
            raise ValueError("名称不能包含空格、冒号、斜杠或井号")
        if any(t.name == new_name for t in app.cfg.targets):
            raise ValueError(f"名称已存在: {new_name}")
        changes["name"] = new_name

    host = (b.get("host") or "").strip()
    if not host:
        raise ValueError("地址不能为空")
    changes["host"] = host

    try:
        port = int(b.get("ssh_port") or 22)
    except ValueError:
        raise ValueError("SSH 端口必须是数字")
    if not (0 < port < 65536):
        raise ValueError("SSH 端口超出范围")
    changes["ssh_port"] = port

    user = (b.get("user") or "root").strip() or "root"
    changes["user"] = user
    changes["role"] = "attack" if b.get("role") == "attack" else "defense"

    if "web" in b:
        changes["web"] = _norm_web(b.get("web"))
    if "tags" in b:
        raw = b.get("tags")
        tags = [x.strip() for x in (raw if isinstance(raw, list) else str(raw or "").split(","))
                if x.strip()]
        changes["tags"] = tags
    if "note" in b:
        changes["note"] = (b.get("note") or "").strip()
    if "webroot" in b:
        wr = (b.get("webroot") or "").strip()
        if wr and not wr.startswith("/"):
            raise ValueError("备份源要写远端绝对路径")
        changes["webroot"] = wr

    # 凭据：留空=不改；勾了清除=删字段
    if b.get("clear_credentials"):
        changes["password"] = None
        changes["key_file"] = None
    else:
        if b.get("password"):
            changes["password"] = b["password"]
        if b.get("key_file"):
            changes["key_file"] = (b.get("key_file") or "").strip()

    from .. import yamledit
    file_path = yamledit.targets_path(app.cfg)
    before = file_path.read_text(encoding="utf-8")
    try:
        yamledit.update_target(app.cfg, old, changes)
        app.reload()
        after = app.cfg.target(changes.get("name", old))
        if after.host != host or after.ssh_port != port:
            raise RuntimeError("写入后回读不一致")
    except Exception as e:  # noqa: BLE001
        try:
            yamledit.restore(file_path, before)
            app.reload()
        except Exception:
            pass
        raise ValueError(f"保存失败，已回滚: {e}") from e

    renamed = None
    if changes.get("name") and changes["name"] != old:
        renamed = {"from": old, "to": changes["name"],
                   "records": app.store.rename_target(old, changes["name"])}
        try:
            app.term_pool.reset(old)
        except Exception:
            pass

    return 200, {"ok": True, "name": changes.get("name", old), "renamed": renamed,
                 "target": _public_target(after),
                 "targets": [_public_target(t) for t in app.cfg.targets]}


@route("DELETE", r"/api/targets/(?P<name>[^/]+)")
def targets_delete(app, p, q, b):
    """从配置里删除靶机（历史记录保留，可追溯）。"""
    import urllib.parse as _up
    name = _up.unquote(p["name"])
    try:
        target = app.cfg.target(name)
    except KeyError as e:
        raise KeyError(str(e)) from e

    stats = app.store.target_stats(name)
    if b.get("purge"):
        stats["purged"] = 0  # 预留：暂不删历史证据

    try:
        app.term_pool.reset(name)
    except Exception:
        pass

    from .. import yamledit
    file_path = yamledit.targets_path(app.cfg)
    before = file_path.read_text(encoding="utf-8")
    try:
        yamledit.remove_target(app.cfg, name)
        app.reload()
        if any(t.name == name for t in app.cfg.targets):
            raise RuntimeError("删除后仍能读到该靶机")
    except Exception as e:  # noqa: BLE001
        try:
            yamledit.restore(file_path, before)
            app.reload()
        except Exception:
            pass
        raise ValueError(f"删除失败，已回滚: {e}") from e

    return 200, {"ok": True, "removed": name, "kept": stats,
                 "targets": [_public_target(t) for t in app.cfg.targets]}



@route("POST", r"/api/targets/batch")
def targets_batch(app, p, q, b):
    """批量操作：改角色 / 改备份源 / 改标签 / 删除。一次写盘、一次重载。"""
    op = (b.get("op") or "").strip()
    names = b.get("names") or []
    if isinstance(names, str):
        names = [x.strip() for x in names.split(",") if x.strip()]
    names = [str(x) for x in names if str(x).strip()]
    if not names:
        raise ValueError("请先勾选要操作的靶机")

    existing = [t.name for t in app.cfg.targets if t.name in names]
    missing = [n for n in names if n not in existing]
    if not existing:
        raise ValueError("勾选的靶机都不存在")

    changes: Dict[str, Any] = {}
    if op == "role":
        role = "attack" if b.get("value") == "attack" else "defense"
        changes["role"] = role
    elif op == "webroot":
        wr = (b.get("value") or "").strip()
        if wr and not wr.startswith("/"):
            raise ValueError("备份源要写远端绝对路径")
        changes["webroot"] = wr
    elif op == "tags":
        raw = b.get("value")
        changes["tags"] = [x.strip() for x in
                           (raw if isinstance(raw, list) else str(raw or "").split(","))
                           if x.strip()]
    elif op != "delete":
        raise ValueError(f"不支持的批量操作: {op}")

    from .. import yamledit
    file_path = yamledit.targets_path(app.cfg)
    before = file_path.read_text(encoding="utf-8")
    kept: Dict[str, int] = {}
    try:
        if op == "delete":
            for n in existing:
                for k, v in app.store.target_stats(n).items():
                    kept[k] = kept.get(k, 0) + v
            yamledit.remove_many(app.cfg, existing)
            app.reload()
            left = [t.name for t in app.cfg.targets if t.name in existing]
            if left:
                raise RuntimeError(f"删除后仍存在: {left}")
            for n in existing:
                try:
                    app.term_pool.reset(n)
                except Exception:
                    pass
        else:
            yamledit.update_many(app.cfg, existing, changes)
            app.reload()
            for n in existing:
                t = app.cfg.target(n)
                if op == "role" and t.role != changes["role"]:
                    raise RuntimeError(f"{n} 角色未生效")
                if op == "webroot" and (t.webroot or "") != changes["webroot"]:
                    raise RuntimeError(f"{n} 备份源未生效")
    except Exception as e:  # noqa: BLE001
        try:
            yamledit.restore(file_path, before)
            app.reload()
        except Exception:
            pass
        raise ValueError(f"批量操作失败，已回滚: {e}") from e

    label = {"role": "改角色", "webroot": "改备份源", "tags": "改标签",
             "delete": "删除"}[op]
    return 200, {"ok": True, "op": op, "label": label,
                 "affected": len(existing), "names": existing, "missing": missing,
                 "kept": kept if op == "delete" else {},
                 "targets": [_public_target(t) for t in app.cfg.targets]}


# --------------------------------------------------------------- 批量靶机
def _parse_bulk(text: str, default_port: int = 22) -> "tuple[list, list]":
    """把 IP/域名 列表解析成待添加项。

    支持：一行一个、逗号/分号分隔、scheme://、host:port、行尾备注（空格后忽略）、# 注释。
    """
    import re as _re

    items, errors = [], []
    seen = set()
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for token in _re.split(r"[,;]+", line):
            token = token.strip()
            if not token:
                continue
            # 空格后面通常是备注（如 "10.0.0.5 政务门户"）
            token = token.split()[0]
            scheme = "http"
            if "://" in token:
                scheme, token = token.split("://", 1)
                scheme = scheme.lower() if scheme.lower() in ("http", "https") else "http"
            token = token.split("/")[0]
            port = ""
            if token.count(":") == 1:
                token, port = token.split(":")
                if not port.isdigit():
                    errors.append({"entry": raw_line, "reason": f"端口非法: {port}"})
                    continue
            host = token.strip().rstrip(".")
            if not host:
                continue
            is_ip = _re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)
            is_domain = (_re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,24}", host)
                         or host == "localhost")
            if not (is_ip or is_domain):
                errors.append({"entry": raw_line, "reason": f"非法主机: {host}"})
                continue
            key = (host.lower(), port)
            if key in seen:
                errors.append({"entry": host, "reason": "列表内重复"})
                continue
            seen.add(key)
            web = f"{scheme}://{host}" + (f":{port}" if port and port not in ("80", "443") else "")
            items.append({"host": host, "port": port, "web": web})
    return items, errors


@route("POST", r"/api/targets/bulk")
def targets_bulk(app, p, q, b):
    text = b.get("text") or ""
    if not text.strip():
        raise ValueError("请输入 IP 或域名列表")
    role = "attack" if b.get("role") == "attack" else "defense"
    user = (b.get("user") or "root").strip()
    password = b.get("password") or ""
    ssh_port = int(b.get("ssh_port") or 22)
    note = (b.get("note") or "").strip()

    parsed, errors = _parse_bulk(text, ssh_port)
    if not parsed:
        raise ValueError("没有解析出有效的主机")
    if len(parsed) > 300:
        raise ValueError("一次最多 300 个，请分批")

    existing_hosts = {(t.host.lower(), str(t.ssh_port)) for t in app.cfg.targets}
    existing_names = {t.name for t in app.cfg.targets}
    added, skipped = [], []
    for item in parsed:
        key = (item["host"].lower(), str(ssh_port))
        if key in existing_hosts:
            skipped.append({"host": item["host"], "reason": "已存在"})
            continue
        base = re.sub(r"[^A-Za-z0-9._-]+", "-", item["host"]).strip("-")[:40] or "target"
        name = base
        i = 2
        while name in existing_names:
            name = f"{base}-{i}"
            i += 1
        existing_names.add(name)
        added.append({
            "name": name, "host": item["host"], "ssh_port": ssh_port,
            "user": user, "password": password, "role": role,
            "web": [item["web"]], "tags": ["attack" if role == "attack" else "defense"],
            "note": note,
        })
        existing_hosts.add(key)

    if added:
        _append_targets_yaml(app.cfg, added)
        app.reload()
    return 200, {"ok": True, "added": [a["name"] for a in added],
                 "added_count": len(added), "skipped": skipped,
                 "errors": errors,
                 "targets": [_public_target(t) for t in app.cfg.targets]}


# -------------------------------------------------------------------- WAF
@route("GET", r"/api/waf/status")
def waf_status(app, p, q, b):
    names = [x for x in (q.get("targets") or "").split(",") if x]
    ts = _resolve(app, names) if names else app.cfg.resolve_role("defense")
    from ..util import pmap
    from ..waf import status as wst

    def one(t):
        st = wst(app.cfg, t)
        return {"target": t.name, "host": t.host, **st.__dict__}

    rows = pmap(one, ts, workers=min(6, max(1, len(ts))))
    return 200, {"targets": [r if isinstance(r, dict) else
                             {"target": "?", "running": False, "error": str(r)} for r in rows]}


@route("POST", r"/api/waf/deploy")
def waf_deploy(app, p, q, b):
    names = b.get("targets")
    ts = _resolve(app, names) if names else app.cfg.resolve_role("defense")
    defense = [t for t in ts if not t.is_attack]
    if not defense:
        raise ValueError("WAF 只能部署在防守靶机上")
    mode = "enforce" if b.get("mode") == "enforce" else "monitor"
    logs = [x for x in (b.get("logs") or []) if x]
    autoban = bool(b.get("autoban"))
    engine = (b.get("engine") or "auto").lower()
    if engine not in ("auto", "php", "python", "go"):
        raise ValueError("engine 只能是 auto / go / php / python")

    def work(job):
        from ..waf import deploy
        rows = []
        for t in defense:
            job.log(f"[{t.name}] 部署 WAF（{mode}，engine={engine}）...")
            r = deploy(app.cfg, t, logs=logs or None, mode=mode, autoban=autoban,
                       engine=engine)
            if r.get("ok"):
                eng = r.get("engine", "")
                detail = (f"日志 {', '.join(r.get('logs') or [])}"
                          if eng in ("python", "go")
                          else f"auto_prepend 写入 {r.get('ini_path', '')}")
                job.log(f"[{t.name}] 已启动（{eng}），规则 {r.get('rules')}，{detail}", "ok")
                if r.get("note"):
                    job.log(f"[{t.name}] {r['note']}", "warn")
            else:
                job.log(f"[{t.name}] 失败：{r.get('error')}", "error")
                st = r.get("stack") or {}
                if st:
                    job.log(f"[{t.name}] 探测到：php={st.get('php')} "
                            f"php-fpm={st.get('php_fpm')} python3={st.get('python3') or '无'}",
                            "warn")
            rows.append({"target": t.name, **r})
        return {"results": rows}
    return 202, _job_reply(app.jobs.submit("waf", f"部署 WAF · {len(defense)} 台", work))


@route("POST", r"/api/waf/audit")
def waf_audit(app, p, q, b):
    names = b.get("targets")
    ts = _resolve(app, names) if names else app.cfg.resolve_role("defense")
    limit = min(int(b.get("limit") or 300), 2000)
    from ..waf import collect
    res = collect(app.cfg, app.store, [t for t in ts if not t.is_attack], limit=limit)
    return 200, res


@route("POST", r"/api/waf/enforce")
def waf_enforce(app, p, q, b):
    names = b.get("targets")
    ts = _resolve(app, names) if names else app.cfg.resolve_role("defense")
    defense = [t for t in ts if not t.is_attack]
    if not defense:
        raise ValueError("只能对防守靶机加固")
    rule_ids = b.get("rule_ids") or None
    autoban = bool(b.get("autoban", True))

    def work(job):
        from ..waf import enforce
        rows = []
        for t in defense:
            job.log(f"[{t.name}] 切换加固模式（封禁 {rule_ids or '全部高危规则'}）...")
            r = enforce(app.cfg, t, rule_ids=rule_ids, autoban=autoban)
            job.log(f"[{t.name}] {'已加固' if r.get('ok') else '失败'}"
                    f"，已封禁 {r.get('banned', 0)} 个 IP", "ok" if r.get("ok") else "error")
            rows.append({"target": t.name, **r})
        return {"results": rows}
    return 202, _job_reply(app.jobs.submit("waf", f"加固 · {len(defense)} 台", work))


@route("POST", r"/api/waf/stop")
def waf_stop(app, p, q, b):
    names = b.get("targets")
    ts = _resolve(app, names) if names else app.cfg.resolve_role("defense")

    def work(job):
        from ..waf import stop
        for t in ts:
            stop(app.cfg, t, unban=bool(b.get("unban")))
            job.log(f"[{t.name}] 已停止", "ok")
        return {"ok": True}
    return 202, _job_reply(app.jobs.submit("waf", "停止 WAF", work))


# ------------------------------------------------------------------ 漏洞列表
@route("GET", r"/api/vulns")
def vulns_list(app, p, q, b):
    rows = app.store.vulns(limit=int(q.get("limit") or 300))
    return 200, {"vulns": rows, "total": len(rows)}


@route("POST", r"/api/vulns/add")
def vulns_add(app, p, q, b):
    """来源一：WAF 审计样本；来源二：手工填写。"""
    items = b.get("items") or []
    if not items:
        raise ValueError("没有可添加的条目")
    source = (b.get("source") or "waf").strip()
    added, dup = 0, 0
    for it in items[:200]:
        name = (it.get("name") or it.get("title") or "WAF 命中").strip()
        ok = app.store.add_vuln(
            name=name,
            method=(it.get("method") or "GET"),
            path=(it.get("path") or "/"),
            severity=(it.get("severity") or "medium"),
            source=source,
            target=it.get("target") or "",
            headers={"User-Agent": (it.get("ua") or "Mozilla/5.0 (compatible; ctf-ops)")},
            body=it.get("body") or "",
            rule_id=it.get("rule_id") or "",
            tags=it.get("rule_id") or "",
        )
        added += 1 if ok else 0
        dup += 0 if ok else 1
        if ok:
            app.store.event("finding", target=it.get("target") or "waf",
                            title=f"漏洞入库: {name}",
                            severity=it.get("severity") or "medium",
                            data={"location": f"{it.get('method','GET')} {it.get('path','')}",
                                  "detail": f"来源 {source}，可重放 / 可加固",
                                  "evidence": it.get("matched") or ""})
    return 200, {"ok": True, "added": added, "duplicated": dup,
                 "vulns": app.store.vulns(limit=50)}


@route("DELETE", r"/api/vulns/(?P<vid>\d+)")
def vulns_delete(app, p, q, b):
    app.store.delete_vuln(int(p["vid"]))
    return 200, {"ok": True}


@route("POST", r"/api/vulns/replay")
def vulns_replay(app, p, q, b):
    ids = b.get("ids") or []
    if ids == "all" or ids == ["all"]:
        vulns = app.store.vulns(limit=100)
    else:
        vulns = [v for v in (app.store.vuln(int(i)) for i in ids) if v]
    if not vulns:
        raise ValueError("没有选中漏洞")
    names = b.get("targets")
    ts = _resolve(app, names) if names else app.cfg.resolve_role("attack")
    attack = [t for t in ts if t.is_attack]
    if not attack:
        raise ValueError("没有攻击目标，请先把靶机标为 attack 或批量添加攻击目标")

    def work(job):
        from ..replay import replay_many
        job.log(f"{len(vulns)} 条漏洞 × {len(attack)} 个攻击目标")
        rows = replay_many(app.cfg, vulns, attack, workers=int(b.get("workers") or 6))
        ok = 0
        for r in rows:
            app.store.event("action", target=str(r.get("target")),
                            title=f"重放 {r.get('name')}",
                            severity="high" if r.get("ok") else "info",
                            data={"url": r.get("url"), "status": r.get("status"),
                                  "flags": r.get("flags"), "error": r.get("error")})
            if r.get("ok"):
                ok += 1
            for fl in r.get("flags") or []:
                if app.store.add_flag(fl, target=str(r.get("target")), source="replay"):
                    job.log(f"FLAG {fl}", "ok")
            job.log(f"[{r.get('target')}] {r.get('method')} {r.get('url')} -> "
                    f"{r.get('status')} ({r.get('length')}B)", "ok" if r.get("ok") else "warn")
        for v in vulns:
            app.store.mark_replay(int(v["id"]), any(
                r.get("ok") for r in rows if int(r.get("vuln_id") or 0) == int(v["id"])))
        return {"results": rows, "ok": ok}
    return 202, _job_reply(app.jobs.submit("replay", f"批量重放 · {len(vulns)} 条", work))


# --------------------------------------------------------------- AI 写插件
@route("POST", r"/api/ai/plugin/generate")
def ai_plugin_generate(app, p, q, b):
    info = (b.get("info") or "").strip()
    if not info:
        raise ValueError("请填写漏洞信息（CVE / 描述 / 请求特征）")

    def work(job):
        from ..aipl import generate
        job.log("请求本地模型编写插件 ...")
        r = generate(app.cfg, info)
        if r.get("ok"):
            job.log(f"生成成功：{r['name']}（{r.get('severity')}）", "ok")
        else:
            job.log(f"生成失败：{r.get('error')}", "error")
        return r
    return 202, _job_reply(app.jobs.submit("ai", "AI 写插件", work))


@route("GET", r"/api/ai/plugin/drafts")
def ai_plugin_drafts(app, p, q, b):
    from ..aipl import list_drafts
    return 200, {"drafts": list_drafts()}


@route("POST", r"/api/ai/plugin/install")
def ai_plugin_install(app, p, q, b):
    from ..aipl import install
    slug = (b.get("slug") or "").strip()
    if not slug:
        raise ValueError("slug 必填")
    r = install(slug, overwrite=bool(b.get("overwrite")))
    if not r.get("ok"):
        raise ValueError(r.get("error") or "安装失败")
    return 200, r




# ------------------------------------------------- 提交接口：从浏览器 cURL 导入
@route("POST", r"/api/submit/parse")
def submit_parse(app, p, q, b):
    """只解析，不保存：给界面做预览。"""
    from ..curlparse import parse_to_profile
    curl = (b.get("curl") or "").strip()
    if not curl:
        raise ValueError("请粘贴浏览器里 Copy as cURL 的内容")
    prof = parse_to_profile(curl, flag_key=(b.get("flag_key") or "").strip() or None)
    errs = prof["preview"].get("errors") or []
    if errs:
        raise ValueError("；".join(errs))
    return 200, prof


@route("GET", r"/api/submit/global")
def submit_global(app, p, q, b):
    """靶机页"接口配置"卡片的读取口：返回当前生效的提交接口（已脱敏）。

    生效顺序与 Submitter 一致：库里激活的导入配置 > config.yaml 的 submit 段。
    """
    from ..flag import Submitter
    sub = Submitter(app.cfg, app.store)
    s = sub.s
    token = s.token or ""
    return 200, {
        "source": sub.profile_name or ("config.yaml" if s.url else "manual"),
        "profile": sub.profile_name,
        "config": {
            "url": s.url, "method": s.method,
            "json_body": s.json_body, "form_body": s.form_body, "raw_body": s.raw_body,
            "headers": s.headers or {},
            "token": "", "token_set": bool(token),
            "success_key": s.success_key, "success_value": s.success_value,
            "message_key": s.message_key, "strict": bool(s.strict),
            "mode": s.mode, "interval": s.interval, "retries": s.retries,
            "timeout": s.timeout,
        },
        "profiles": [{"name": r["name"], "active": bool(r["active"]),
                      "host": r.get("host") or "", "url": (r.get("config") or {}).get("url")}
                     for r in app.store.submit_profiles()],
    }


@route("GET", r"/api/submit/profiles")
def submit_profiles(app, p, q, b):
    rows = app.store.submit_profiles()
    out = []
    for r in rows:
        conf = r.get("config") or {}
        out.append({
            "name": r["name"], "host": r["host"], "active": bool(r["active"]),
            "ts": r["ts"], "note": r["note"],
            "method": conf.get("method"), "url": conf.get("url"),
            "flag_at": conf.get("flag_at") or [],
        })
    active = next((x["name"] for x in out if x["active"]), "")
    return 200, {"profiles": out, "active": active}


@route("POST", r"/api/submit/profile")
def submit_profile_save(app, p, q, b):
    """保存导入的提交接口（可同时激活）。"""
    from ..curlparse import parse_to_profile
    name = (b.get("name") or "").strip()
    if not name:
        raise ValueError("请给这个接口起个名字（比如平台域名）")
    if re.search(r"[\s/\\]", name):
        raise ValueError("名字里不要有空格或斜杠")

    conf = b.get("config")
    if not conf:
        curl = (b.get("curl") or "").strip()
        if not curl:
            raise ValueError("缺少 curl 或 config")
        prof = parse_to_profile(curl, flag_key=(b.get("flag_key") or "").strip() or None)
        if not prof.get("has_placeholder"):
            raise ValueError("没能在请求里找到 flag 的位置；请手动指定字段名（flag_key）")
        conf = {k: prof[k] for k in ("url", "method", "headers", "json_body",
                                     "form_body", "raw_body", "success_key",
                                     "success_value", "message_key", "flag_at")}
        conf["strict"] = True

    if not conf.get("url"):
        raise ValueError("配置里没有 URL")
    host = urllib.parse.urlsplit(conf["url"]).netloc
    pid = app.store.save_submit_profile(name, conf, host=host,
                                        note=(b.get("note") or ""),
                                        activate=bool(b.get("activate", True)))
    app.store.event("action", target="-", title=f"导入提交接口: {name}",
                    data={"host": host, "url": conf.get("url")})
    return 200, {"ok": True, "id": pid, "name": name,
                 "active": app.store.active_submit_profile()["name"]
                 if app.store.active_submit_profile() else ""}


@route("POST", r"/api/submit/activate")
def submit_activate(app, p, q, b):
    name = (b.get("name") or "").strip()
    if not app.store.activate_submit_profile(name):
        raise ValueError(f"没有这个配置: {name}")
    return 200, {"ok": True, "active": name}


@route("DELETE", r"/api/submit/profile/(?P<name>[^/]+)")
def submit_profile_delete(app, p, q, b):
    import urllib.parse as _up
    name = _up.unquote(p["name"])
    app.store.delete_submit_profile(name)
    active = app.store.active_submit_profile()
    return 200, {"ok": True, "active": active["name"] if active else ""}


@route("POST", r"/api/submit/test")
def submit_test(app, p, q, b):
    """拿一个真 flag 打一次，验证导入的接口确实能用。"""
    from ..flag import Submitter
    flag = (b.get("flag") or "").strip()
    if not flag:
        raise ValueError("请填一个真实 flag 做测试（提交成功会消耗它）")
    name = (b.get("name") or "").strip() or None
    sub = Submitter(app.cfg, app.store, profile=name)
    res = sub.submit(flag, b.get("target") or "test")
    return 200, {"ok": res.ok, "message": res.message,
                 "elapsed": round(res.elapsed, 2),
                 "profile": sub.profile_name,
                 "url": sub.s.url, "method": sub.s.method,
                 "raw": (res.raw or "")[:600]}



# ---------------------------------------------------------------- 自动作战
@route("POST", r"/api/auto/run")
def auto_run(app, p, q, b):
    """一键自动作战：防守靶机自动守、攻击目标自动打、最后提交。"""
    raw = b.get("phases")
    if raw is None:
        phases = ["defense", "attack", "submit"]
    else:
        phases = [x for x in raw if x in ("defense", "attack", "submit")]
    if not phases:
        raise ValueError("至少选一个阶段（defense / attack / submit）")
    plugins = b.get("plugins") or None
    do_backup = bool(b.get("backup", True))
    do_shell = bool(b.get("shell", True))
    do_replay = bool(b.get("replay", True))

    def work(job):
        from ..autopilot import AutoPilot, summarize
        ap = AutoPilot(app.cfg, app.store, log=lambda msg, lv="info": job.log(msg, lv))
        out: Dict[str, Any] = {"phases": phases}

        if "defense" in phases:
            ts = app.cfg.resolve_role("defense")
            job.log(f"防守靶机 {len(ts)} 台：{'、'.join(t.name for t in ts) or '无'}")
            out["defense"] = ap.defend(do_backup=do_backup, do_scan=do_shell).to_dict()
        if "attack" in phases:
            ts = app.cfg.resolve_role("attack")
            job.log(f"攻击目标 {len(ts)} 台：{'、'.join(t.name for t in ts) or '无'}")
            ar = ap.attack(plugins=plugins, do_replay=do_replay)
            out["attack"] = ar.to_dict()
            out["flags"] = ar.flags
        if "submit" in phases:
            out["submit"] = ap.submit(out.get("flags") or None).to_dict()

        out["summary_text"] = summarize(out)
        job.log(out["summary_text"], "ok")
        app.store.set_setting("auto.last", json.dumps(out, ensure_ascii=False))
        app.store.event("action", target="-", title="自动作战",
                        data={"phases": phases, "summary": out["summary_text"]})
        return out
    return 202, _job_reply(app.jobs.submit("auto", "自动作战", work))


@route("GET", r"/api/auto/last")
def auto_last(app, p, q, b):
    raw = app.store.get_setting("auto.last", "")
    if not raw:
        return 200, {"report": None}
    try:
        return 200, {"report": json.loads(raw)}
    except json.JSONDecodeError:
        return 200, {"report": None}



@route("GET", r"/api/auto/schedule")
def auto_schedule_state(app, p, q, b):
    return 200, app.auto_loop.state()


@route("POST", r"/api/auto/schedule/start")
def auto_schedule_start(app, p, q, b):
    interval = int(b.get("interval") or 300)
    if interval < 60:
        raise ValueError("间隔至少 60 秒（一轮本身就要几十秒）")
    if interval > 24 * 3600:
        raise ValueError("间隔过大，确认单位是秒")
    # 注意别用 `or None`：空数组会变成 None，"传了空阶段"就被当成"没传"
    phases = b.get("phases") if "phases" in b else None
    st = app.auto_loop.start(interval=interval, phases=phases)
    app.store.event("action", target="-", title=f"启动定时自动作战（{interval}s）",
                    data={"phases": st["phases"]})
    return 200, st


@route("POST", r"/api/auto/schedule/stop")
def auto_schedule_stop(app, p, q, b):
    st = app.auto_loop.stop()
    app.store.event("action", target="-", title="停止定时自动作战", data={})
    return 200, st


@route("GET", r"/api/ai/triage/last")
def ai_triage_last(app, p, q, b):
    raw = app.store.get_setting("ai.last_triage", "")
    if not raw:
        return 200, {"result": None}
    try:
        return 200, {"result": json.loads(raw)}
    except json.JSONDecodeError:
        return 200, {"result": None}


@route("POST", r"/api/ai/triage")
def ai_triage_api(app, p, q, b):
    """对已入库发现做攻击路径排序（给页面按钮用，异步）。"""
    from ..aiclient import AIClient, parse_triage

    def work(job):
        rows = app.store.events(kind="finding", limit=int(b.get("limit") or 120))
        if not rows:
            raise ValueError("库里还没有发现，先跑一次扫描")
        items = [{"severity": r.get("severity"), "target": r.get("target"),
                  "title": r.get("title"),
                  "location": (r.get("data") or {}).get("location", ""),
                  "detail": (r.get("data") or {}).get("detail", "")} for r in rows]
        job.log(f"用 {len(items)} 条已入库发现做排序 ...")
        res = AIClient(app.cfg).triage_findings(items)
        if not res.ok:
            raise ValueError(res.error or "模型无输出")
        parsed = parse_triage(res.text)
        out = {"triage": parsed, "raw": res.text[:4000],
               "count": len(items), "model": app.cfg.ai.model,
               "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        # 缓存一份：模型一次要一两分钟，刷页面不该重跑
        app.store.set_setting("ai.last_triage", json.dumps(out, ensure_ascii=False))
        return out
    return 202, _job_reply(app.jobs.submit("ai", "AI 攻击路径排序", work))


# ---------------------------------------------------------------- AWD 轮次
@route("GET", r"/api/round/state")
def round_state(app, p, q, b):
    return 200, app.round.state()


@route("POST", r"/api/round/start")
def round_start(app, p, q, b):
    interval = int(b.get("interval") or 300)
    if interval < 20:
        raise ValueError("间隔至少 20 秒（太密会把靶机拖死）")
    if interval > 7200:
        raise ValueError("间隔太大（>2 小时），确认一下单位是秒")
    names = b.get("targets")
    st = app.round.start(targets=names, interval=interval,
                         auto_submit=bool(b.get("auto_submit", True)),
                         deep=bool(b.get("deep")))
    app.store.event("action", target="-", title=f"启动轮次监控（{interval}s）",
                    data={"targets": st.get("targets"), "auto_submit": st.get("auto_submit")})
    return 200, st


@route("POST", r"/api/round/stop")
def round_stop(app, p, q, b):
    st = app.round.stop()
    app.store.event("action", target="-", title="停止轮次监控", data={})
    return 200, st


@route("POST", r"/api/round/tick")
def round_tick(app, p, q, b):
    """手动检查一轮（比赛里想立刻确认换没换 flag 时用）。"""
    names = b.get("targets")
    ts = None
    if names:
        ts = _resolve(app, names)
    events = app.round.tick(ts)
    return 200, {"events": [{"target": e.target, "new_flags": e.new_flags,
                             "all_flags": e.all_flags, "changed": e.changed,
                             "submitted": e.submitted, "note": e.note} for e in events],
                 "state": app.round.state()}


@route("GET", r"/api/round/history")
def round_history(app, p, q, b):
    limit = min(int(q.get("limit") or 200), 1000)
    rows = app.store.rounds(limit=limit)
    return 200, {"rounds": rows, "stats": app.store.round_stats()}


@route("POST", r"/api/round/reset")
def round_reset(app, p, q, b):
    """清空已知 flag（换场次/重开一局时用，避免把旧 flag 当新的）。"""
    app.round.reset()
    return 200, {"ok": True, "state": app.round.state()}


# ------------------------------------------------------------------ 任务
@route("GET", r"/api/jobs")
def jobs(app, p, q, b):
    return 200, {"jobs": app.jobs.list(limit=int(q.get("limit") or 20)),
                 "active": app.jobs.active()}


@route("GET", r"/api/jobs/(?P<jid>[0-9a-f]+)")
def job_detail(app, p, q, b):
    job = app.jobs.get(p["jid"])
    if not job:
        raise KeyError("任务不存在")
    offset = q.get("offset")
    return 200, {"job": job.to_dict(offset=int(offset) if offset else 0)}


# ------------------------------------------------------------- 文件内容
@route("GET", r"/api/file")
def file_read(app, p, q, b):
    rel = q.get("path") or ""
    if not rel:
        raise ValueError("path 必填")
    fp = safe_path(app.cfg, rel)
    if not fp.is_file():
        raise KeyError("文件不存在")
    if fp.stat().st_size > 4 << 20:
        raise ValueError("文件超过 4MB，请直接用编辑器打开")
    text = fp.read_text(encoding="utf-8", errors="replace")
    return 200, {"path": rel, "text": text[:200000],
                 "size_h": human_size(fp.stat().st_size)}


def guess_type(path: pathlib.Path) -> str:
    if path.suffix.lower() in (".md", ".txt", ".log", ".json", ".yaml", ".yml",
                               ".py", ".html", ".css", ".js"):
        return mimetypes.guess_type(str(path))[0] or "text/plain"
    return mimetypes.guess_type(str(path))[0] or "application/octet-stream"


def _shq(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"

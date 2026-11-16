"""业务系统备份：远端打包 → 拉回 → 校验 → 记录。

AWD 的核心是"改坏了能一分钟回到开局状态"，所以备份必须：
1) 幂等可复跑；2) 带 sha256；3) 保留最后一次可用副本指针。
"""

from __future__ import annotations

import os
import pathlib
import posixpath
import tarfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import Config, Target
from .sshx import SSHSession
from .util import console, human_size, ok, sha256_file, warn


@dataclass
class BackupResult:
    target: str
    ok: bool
    local_path: str = ""
    remote_path: str = ""
    size: int = 0
    sha256: str = ""
    note: str = ""
    source: str = ""          # 实际打包的远端目录


DEFAULT_EXCLUDES = ["cache", "*.log", "*.tmp", "node_modules/.cache", "*.swp",
                    "proc", "sys", "dev", ".git/objects",
                    "._*", ".DS_Store", "__MACOSX"]

SETTING_KEY = "backup_dir"


def backup_root(cfg: Config, store=None) -> pathlib.Path:
    """备份落盘目录，优先级：运行时设置(DB) > config.backup.path > workdir/backups。

    支持外置盘（如 /Volumes/USB4T），比赛现场把包写到大容量盘上很常见。
    """
    value = ""
    if store is not None:
        try:
            value = store.get_setting(SETTING_KEY, "")
        except Exception:
            value = ""
    if not value:
        value = str((cfg.backup or {}).get("path") or "")
    if not value:
        return cfg.backup_dir
    p = pathlib.Path(value).expanduser()
    return p if p.is_absolute() else (cfg.workdir / p)


def prepare_backup_root(cfg: Config, store=None) -> pathlib.Path:
    root = backup_root(cfg, store)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _remote_webroot(sess: SSHSession, target: Target) -> str:
    """靶机没写 webroot 时按常见部署探测。"""
    if target.webroot:
        return target.webroot
    candidates = ["/var/www/html", "/var/www", "/app", "/opt/www",
                  "/usr/local/nginx/html", "/www/wwwroot", "/data/www"]
    # 优先读 nginx/apache 配置
    probe = sess.exec(
        "for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/httpd/conf.d/*.conf;"
        " do [ -f \"$f\" ] && grep -hoE 'root\\s+[^;]+' \"$f\"; done 2>/dev/null | head -5",
        timeout=20)
    for line in probe.out.splitlines():
        p = line.replace("root", "", 1).strip()
        if p.startswith("/") and sess.exists(p):
            return p
    for c in candidates:
        if sess.exists(c):
            return c
    return "/var/www/html"


def detect_webroot(cfg: Config, target: Target) -> str:
    """远程探测业务目录（读 nginx/apache 配置，再退回常见路径）。"""
    from .sshx import SSHSession
    try:
        with SSHSession(target, cfg, retries=0) as sess:
            return _remote_webroot(sess, target)
    except Exception:
        return ""


def backup_target(cfg: Config, target: Target, dest_dir: Optional[pathlib.Path] = None,
                  tag: str = "snapshot", with_db: bool = True,
                  src: Optional[str] = None) -> BackupResult:
    dest = dest_dir or backup_root(cfg)
    dest.mkdir(parents=True, exist_ok=True)
    stamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{target.name}_{tag}_{stamp}"
    remote_tar = f"/tmp/{base}.tar.gz"
    local_tar = dest / f"{base}.tar.gz"

    try:
        with SSHSession(target, cfg) as sess:
            # 优先级：本次指定 > 配置里的 webroot > 自动探测
            webroot = src or _remote_webroot(sess, target)
            # 先确认源路径真的存在：否则 tar 会生成一个空包，看起来"成功"了
            probe = sess.exec(
                f"[ -d {_sh.quote(webroot)} ] && echo DIR || "
                f"([ -f {_sh.quote(webroot)} ] && echo FILE || echo MISSING)", timeout=20)
            mark = (probe.out or "").strip().splitlines()[-1] if (probe.out or "").strip() else ""
            if mark == "MISSING":
                return BackupResult(target.name, False, source=webroot,
                                    note=f"源路径不存在: {webroot}")
            if mark == "FILE":
                return BackupResult(target.name, False, source=webroot,
                                    note=f"源路径是文件不是目录: {webroot}")

            excludes = cfg.backup.get("excludes") or _DEFAULTS
            exc = " ".join(f"--exclude={_sh.quote(e)}" for e in excludes)
            parent = posixpath.dirname(webroot.rstrip("/")) or "/"
            base_name = posixpath.basename(webroot.rstrip("/"))
            tar_cmd = (f"tar czf {remote_tar} {exc} -C {_sh.quote(parent)} "
                       f"{_sh.quote(base_name)} 2>/dev/null && echo TAR_OK; "
                       f"ls -l {remote_tar} 2>/dev/null | awk '{{print $5}}'")
            r = sess.exec(tar_cmd, timeout=600, sudo=True)
            if "TAR_OK" not in (r.out or ""):
                # sudo 失败时再裸跑一次（很多比赛镜像本来就是 root）
                r = sess.exec(tar_cmd.replace("2>/dev/null", ""), timeout=600)
            if "TAR_OK" not in (r.out or ""):
                return BackupResult(target.name, False, source=webroot,
                                    note=f"远端打包失败: {(r.error or r.err or r.out)[:200]}")

            if with_db:
                db_cfg = target.db or cfg.backup.get("db") or {}
                if db_cfg.get("type") == "mysql":
                    user = db_cfg.get("user", "root")
                    pwd = db_cfg.get("password", "")
                    dbn = db_cfg.get("database") or _guess_db(sess)
                    dump = f"/tmp/{base}.sql"
                    pw = f"-p{_sh.quote(pwd)}" if pwd else ""
                    sess.exec(f"mysqldump -u{user} {pw} {dbn} > {dump} 2>/dev/null "
                              f"|| mysqldump -u{user} {pw} --all-databases > {dump}",
                              timeout=600)
                    if sess.exists(dump):
                        local_sql = dest / f"{base}.sql"
                        sess.download(dump, str(local_sql), timeout=600)
                        sess.exec(f"rm -f {dump}")
                        if local_sql.exists():
                            console.print(f"  [dim]MySQL 备份: {local_sql.name} "
                                          f"{human_size(local_sql.stat().st_size)}[/dim]")

            if not sess.download(remote_tar, str(local_tar), timeout=900):
                return BackupResult(target.name, False, note="回传失败")
            sess.exec(f"rm -f {remote_tar}")
            size = local_tar.stat().st_size
            digest = sha256_file(local_tar)
            return BackupResult(target.name, True, str(local_tar), remote_tar,
                                size, digest, note=f"webroot={webroot}", source=webroot)
    except Exception as e:  # noqa: BLE001
        return BackupResult(target.name, False, note=str(e))


def restore_target(cfg: Config, target: Target, archive: str,
                   webroot: Optional[str] = None) -> BackupResult:
    """把备份包还原回靶机，用于 AWD 被打挂后的快速回滚。"""
    if not os.path.exists(archive):
        return BackupResult(target.name, False, note=f"备份不存在: {archive}")
    try:
        with SSHSession(target, cfg) as sess:
            root = webroot or target.webroot or _remote_webroot(sess, target)
            remote = f"/tmp/restore_{os.path.basename(archive)}"
            if not sess.upload(archive, remote):
                return BackupResult(target.name, False, note="上传失败")
            parent = posixpath.dirname(root)
            r = sess.exec(
                f"tar xzf {remote} -C {_sh.quote(parent)} && echo RESTORE_OK",
                timeout=600)
            size = os.path.getsize(archive)
            return BackupResult(target.name, r.ok and "RESTORE_OK" in r.out,
                                archive, remote, size, sha256_file(archive),
                                note=f"restored into {parent}")
    except Exception as e:  # noqa: BLE001
        return BackupResult(target.name, False, note=str(e))


def backup_local(path: str, dest_dir: pathlib.Path, tag: str) -> BackupResult:
    """离线备份（例如赛前拿到的源码 AWD1/www）。"""
    src = pathlib.Path(path).expanduser()
    if not src.exists():
        return BackupResult(str(src), False, note="路径不存在")
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    out = dest_dir / f"{src.name}_{tag}_{stamp}.tar.gz"
    with tarfile.open(out, "w:gz") as tf:
        tf.add(src, arcname=src.name, filter=_skip_cache)
    return BackupResult(str(src), True, str(out), "", out.stat().st_size,
                        sha256_file(out), note="local")


def _skip_cache(ti: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
    bad = ("node_modules", ".git", "__pycache__", ".venv")
    if any(part in bad for part in ti.name.split("/")):
        return None
    return ti


def _guess_db(sess: SSHSession) -> str:
    r = sess.exec("ls /var/lib/mysql 2>/dev/null | grep -vE '^(mysql|sys|performance_schema|information_schema)$' | head -1")
    return r.out.strip() or "mysql"


# 避免 util 依赖，独立小引用
class _sh:
    @staticmethod
    def quote(s: str) -> str:
        return "'" + s.replace("'", "'\"'\"'") + "'"


_DEFAULTS = DEFAULT_EXCLUDES

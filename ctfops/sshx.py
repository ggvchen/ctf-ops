"""SSH 会话封装：批量执行、上传下载、sudo、断线重试。

刻意不做交互式 shell —— 比赛现场需要的是可复跑的一条命令。
"""

from __future__ import annotations

import io
import os
import posixpath
import socket
import stat
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import Config, Target
from .util import console, human_size, pmap, trunc, warn


@dataclass
class ExecResult:
    target: str
    host: str
    rc: int
    out: str
    err: str
    elapsed: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.rc == 0

    @property
    def text(self) -> str:
        return (self.out or "") + (("\n" + self.err) if self.err else "")

    @classmethod
    def fail(cls, target: str, host: str, err: str) -> "ExecResult":
        return cls(target=target, host=host, rc=-1, out="", err="", error=err)


class SSHSession:
    """一台靶机的可复用连接。"""

    def __init__(self, target: Target, cfg: Config, retries: int = 2):
        self.target = target
        self.cfg = cfg
        self.retries = retries
        self._client = None
        self._sftp = None

    # ---------- 连接 ----------
    def connect(self):
        import paramiko

        if self._client is not None:
            try:
                tr = self._client.get_transport()
                if tr and tr.is_active():
                    return self._client
            except Exception:
                pass
            self.close()

        last: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = dict(
                hostname=self.target.host,
                port=self.target.ssh_port,
                username=self.target.user,
                timeout=self.cfg.ssh.timeout,
                banner_timeout=self.cfg.ssh.banner_timeout,
                auth_timeout=self.cfg.ssh.banner_timeout,
                allow_agent=self.cfg.ssh.allow_agent,
                look_for_keys=self.cfg.ssh.look_for_keys,
            )
            if self.target.key_file:
                kwargs["key_filename"] = os.path.expanduser(self.target.key_file)
                kwargs["look_for_keys"] = False
            if self.target.password:
                kwargs["password"] = self.target.password
            try:
                cli.connect(**kwargs)
                self._client = cli
                return cli
            except Exception as e:  # noqa: BLE001
                last = e
                try:
                    cli.close()
                except Exception:
                    pass
                if attempt < self.retries:
                    time.sleep(1.2 * (attempt + 1))
        raise ConnectionError(f"{self.target.ssh_label} 连接失败: {last}")

    @property
    def client(self):
        return self.connect()

    def sftp(self):
        if self._sftp is None:
            self._sftp = self.connect().open_sftp()
        return self._sftp

    def close(self) -> None:
        for obj in (self._sftp, self._client):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        self._sftp = None
        self._client = None

    def __enter__(self) -> "SSHSession":
        return self

    def __exit__(self, *a) -> None:
        self.close()

    # ---------- 执行 ----------
    def exec(self, cmd: str, timeout: int = 60, sudo: bool = False,
             use_pty: bool = False) -> ExecResult:
        t0 = time.time()
        full = cmd
        if sudo and self.target.user != "root":
            if self.target.password:
                # -S 从 stdin 读密码，避免依赖 NOPASSWD
                full = f"sudo -S -p '' bash -lc {_shq(cmd)}"
            else:
                full = f"sudo -n bash -lc {_shq(cmd)}"
        try:
            cli = self.client
            stdin, stdout, stderr = cli.exec_command(
                full, timeout=timeout, get_pty=use_pty)
            if sudo and self.target.user != "root" and self.target.password:
                stdin.write(self.target.password + "\n")
                stdin.flush()
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            return ExecResult(self.target.name, self.target.host, rc, out, err,
                              time.time() - t0)
        except Exception as e:  # noqa: BLE001
            self.close()
            return ExecResult.fail(self.target.name, self.target.host, str(e))

    # ---------- 传输 ----------
    def upload(self, local: str, remote: str, timeout: int = 300) -> bool:
        try:
            sftp = self.sftp()
            sftp.get_channel().settimeout(timeout)
            self.exec(f"mkdir -p {_shq(posixpath.dirname(remote))}", timeout=15)
            sftp.put(os.path.expanduser(local), remote)
            return True
        except Exception as e:  # noqa: BLE001
            warn(f"上传失败 {self.target.name}: {local} -> {remote}: {e}")
            return False

    def download(self, remote: str, local: str, timeout: int = 600) -> bool:
        try:
            sftp = self.sftp()
            sftp.get_channel().settimeout(timeout)
            os.makedirs(os.path.dirname(os.path.abspath(local)) or ".", exist_ok=True)
            sftp.get(remote, local)
            return True
        except Exception as e:  # noqa: BLE001
            warn(f"下载失败 {self.target.name}: {remote} -> {local}: {e}")
            return False

    def read_file(self, remote: str, limit: int = 2_000_000) -> Optional[str]:
        try:
            with self.sftp().open(remote, "rb") as f:
                return f.read(limit).decode("utf-8", "replace")
        except Exception:
            return None

    def write_file(self, remote: str, content: str, perm: int = 0o644) -> bool:
        try:
            sftp = self.sftp()
            self.exec(f"mkdir -p {_shq(posixpath.dirname(remote))}", timeout=15)
            with sftp.open(remote, "wb") as f:
                f.write(content.encode("utf-8"))
            sftp.chmod(remote, perm)
            return True
        except Exception as e:  # noqa: BLE001
            warn(f"写入失败 {self.target.name}: {remote}: {e}")
            return False

    def exists(self, remote: str) -> bool:
        try:
            self.sftp().stat(remote)
            return True
        except Exception:
            return False

    def listdir(self, remote: str, depth: int = 1) -> List[Dict[str, object]]:
        """浅层列目录，用于找 webroot / 备份目标。"""
        out: List[Dict[str, object]] = []

        def walk(path: str, d: int) -> None:
            try:
                entries = self.sftp().listdir_attr(path)
            except Exception:
                return
            for e in entries:
                rec = {
                    "path": posixpath.join(path, e.filename),
                    "name": e.filename,
                    "size": e.st_size or 0,
                    "mode": oct(stat.S_IMODE(e.st_mode or 0)),
                    "is_dir": bool((e.st_mode or 0) & stat.S_IFDIR),
                }
                out.append(rec)
                if rec["is_dir"] and d > 1 and e.filename not in (".", ".."):
                    walk(str(rec["path"]), d - 1)

        walk(remote, depth)
        return out


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def open_session(target: Target, cfg: Config, retries: int = 2) -> SSHSession:
    return SSHSession(target, cfg, retries=retries)


def batch_exec(cfg: Config, targets: List[Target], cmd: str, timeout: int = 60,
               sudo: bool = False, workers: int = 8) -> List[ExecResult]:
    def one(t: Target) -> ExecResult:
        with SSHSession(t, cfg) as s:
            return s.exec(cmd, timeout=timeout, sudo=sudo)

    res = pmap(one, targets, workers=workers, label="ssh")
    return [r if isinstance(r, ExecResult) else ExecResult.fail(
        getattr(r, "target", "?"), "", repr(r)) for r in res]


def print_results(results: List[ExecResult], max_lines: int = 25) -> None:
    for r in results:
        status = "[green]OK[/green]" if r.ok else f"[red]RC={r.rc}[/red]"
        head = f"[bold]{r.target}[/bold] {r.host} {status} {r.elapsed:.1f}s"
        console.print(head)
        if r.error:
            console.print(f"  [red]{r.error}[/red]")
            continue
        body = r.text.strip()
        if body:
            lines = body.splitlines()
            for line in lines[:max_lines]:
                console.print(f"  {line}")
            if len(lines) > max_lines:
                console.print(f"  [dim]... 还有 {len(lines) - max_lines} 行[/dim]")

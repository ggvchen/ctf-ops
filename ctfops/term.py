"""多机终端：每台靶机一条常驻交互式 shell，供 Web 端网格使用。

为什么用 invoke_shell 而不是 exec_command：
- 网格里要连续敲命令（cd / ls / cat），状态必须保留
- 每次 exec 都新建通道，延迟明显，且 cwd/env 不连续

可靠性靠哨兵行：命令后追加 `printf 'MARK rc'`，读到哨兵才认为这条命令结束。
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional

from .config import Config, Target
from .sshx import SSHSession
from .util import console, trunc, warn


@dataclass
class TermResult:
    target: str
    ok: bool
    output: str = ""
    rc: int = -1
    error: str = ""
    elapsed: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return {"target": self.target, "ok": self.ok, "output": self.output,
                "rc": self.rc, "error": self.error,
                "elapsed": round(self.elapsed, 2)}


class ShellSession:
    def __init__(self, target: Target, cfg: Config):
        self.target = target
        self.cfg = cfg
        self._lock = threading.Lock()
        self._sess = SSHSession(target, cfg)
        client = self._sess.client
        self.chan = client.invoke_shell(term="xterm-256color", width=210, height=48)
        self.chan.settimeout(0.0)
        self.opened = time.time()
        self.last_used = time.time()
        self._drain(0.35)          # 吃掉 banner / MOTD
        # 安静化：不要提示符、不要 ZLE 行编辑回显、不要分页器
        # （zsh/bash 都要照顾，失败也不影响后续）
        self.run(
            "export PAGER=cat SYSTEMD_PAGER=cat TERM=dumb NO_COLOR=1;"
            "export PS1= PS2= PROMPT= RPROMPT=;"
            "unsetopt zle prompt_sp prompt_cr 2>/dev/null; set +o emacs 2>/dev/null;"
            "export PROMPT_EOL_MARK=; stty -echo 2>/dev/null; true",
            timeout=8)

    # ---------- 基础 ----------
    def _drain(self, wait: float = 0.1) -> str:
        end = time.time() + wait
        buf = []
        while time.time() < end:
            if self.chan.recv_ready():
                buf.append(self.chan.recv(65535).decode("utf-8", "replace"))
                end = time.time() + 0.05   # 有数据就再多等一会
            elif self.chan.closed:
                break
            else:
                time.sleep(0.02)
        return "".join(buf)

    @property
    def alive(self) -> bool:
        return bool(self.chan and not self.chan.closed)

    # ---------- 执行 ----------
    def run(self, cmd: str, timeout: int = 30) -> TermResult:
        t0 = time.time()
        if not self.alive:
            return TermResult(self.target.name, False, error="会话已断开", elapsed=0)
        marker = f"__CTF_{uuid.uuid4().hex[:8]}__"
        payload = f"{cmd}\nprintf '%s %d\\n' {marker} $?\n"
        with self._lock:
            try:
                self.chan.send(payload.encode("utf-8"))
            except Exception as e:  # noqa: BLE001
                return TermResult(self.target.name, False, error=f"发送失败: {e}")

            buf = ""
            deadline = time.time() + max(2, timeout)
            pattern = re.compile(re.escape(marker) + r"\s+(\d+)")
            match = None
            while time.time() < deadline:
                if self.chan.recv_ready():
                    buf += self.chan.recv(65536).decode("utf-8", "replace")
                    match = pattern.search(buf)
                    if match:
                        time.sleep(0.05)
                        if self.chan.recv_ready():
                            buf += self.chan.recv(65536).decode("utf-8", "replace")
                        break
                elif self.chan.closed:
                    break
                else:
                    time.sleep(0.025)

            self.last_used = time.time()
            if match is None:
                return TermResult(self.target.name, False, trunc(_clean(buf, cmd, marker), 8000),
                                  rc=-1, error="命令超时或被阻塞", elapsed=time.time() - t0)
            rc = int(match.group(1))
            out = _clean(buf[: match.start()], cmd, marker)
            return TermResult(self.target.name, True, trunc(out, 20000), rc=rc,
                              elapsed=time.time() - t0)

    def close(self) -> None:
        try:
            self.chan.close()
        except Exception:
            pass
        self._sess.close()


ANSI_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"      # CSI 序列
    r"|\x1b\][^\x07]*\x07"            # OSC 序列
    r"|\x1b[=><]"
    r"|\x1b[()][A-Za-z0-9]")


def _strip_control(text: str) -> str:
    """去 ANSI、处理退格、丢掉其它控制字符（保留 \n \t）。"""
    text = ANSI_RE.sub("", text)
    out = []
    for ch in text:
        if ch == "\x08":
            if out and out[-1] != "\n":
                out.pop()
        elif ch == "\r":
            continue
        elif ch == "\x07":
            continue
        elif ord(ch) < 32 and ch not in "\n\t":
            continue
        else:
            out.append(ch)
    return "".join(out)


def _clean(raw: str, cmd: str, marker: str) -> str:
    text = _strip_control(raw).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    # 去掉哨兵回显行与命令回显行
    lines = [ln for ln in lines if marker not in ln]
    first = cmd.strip().split("\n")[0]
    while lines and first and lines[0].strip().endswith(first[:60]):
        lines.pop(0)
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    # zsh 的部分行标记，避免污染结果
    while lines and lines[-1].strip() in ("%", "%%", "$", "#"):
        lines.pop()
    return "\n".join(lines)


class ShellPool:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._map: Dict[str, ShellSession] = {}
        self._lock = threading.RLock()

    def get(self, target: Target) -> ShellSession:
        with self._lock:
            sess = self._map.get(target.name)
            if sess and sess.alive:
                return sess
            if sess:
                sess.close()
            console.print(f"  [dim]打开终端 {target.name} ({target.ssh_label})[/dim]")
            sess = ShellSession(target, self.cfg)
            self._map[target.name] = sess
            return sess

    def run(self, target: Target, cmd: str, timeout: int = 30,
            reset: bool = False) -> TermResult:
        try:
            if reset:
                self.reset(target.name)
            sess = self.get(target)
            res = sess.run(cmd, timeout=timeout)
            if not res.ok and not sess.alive:
                warn(f"{target.name} 终端断开，已回收")
                self.reset(target.name)
            return res
        except Exception as e:  # noqa: BLE001
            self.reset(target.name)
            return TermResult(target.name, False, error=str(e))

    def reset(self, name: Optional[str] = None) -> int:
        with self._lock:
            names = [name] if name else list(self._map)
            n = 0
            for key in names:
                sess = self._map.pop(key, None)
                if sess:
                    sess.close()
                    n += 1
            return n

    def status(self) -> List[Dict[str, object]]:
        with self._lock:
            return [{"target": k, "alive": v.alive,
                     "idle": round(time.time() - v.last_used, 1),
                     "opened": round(v.opened, 1)} for k, v in self._map.items()]

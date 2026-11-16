"""AWD 轮次监控：定时检测 flag 是否已刷新，刷新后自动获取并提交。

AWD 的节奏是"每 N 分钟一轮、每轮换 flag、换完要重新提交"。人工盯着既累又容易漏，
所以这里做成一个常驻的轮询器：

    ┌─ 每 interval 秒 ───────────────────────────────────┐
    │ 1. 逐台读 flag（先看 /flag 这类固定路径，快）        │
    │ 2. 和上一轮的值比对                                │
    │ 3. 有新值 → 记为新一轮 → 入库 → 提交                │
    └──────────────────────────────────────────────────┘

关键设计：

* **只认"变了"**：flag 内容是判断是否换轮的唯一依据（平台不会通知），
  所以每台靶机维护一个已知集合，差集就是新 flag。
* **先快后慢**：先探固定路径（一次 exec），没有才退回全盘 grep——
  grep 在几十台机器上每小时跑一次还好，每分钟跑会把靶机拖死。
* **幂等**：同一个 flag 即使被重复读到，`add_flag` 的 digest 唯一索引也会挡住。
* **状态落盘**：已知集合存 settings 表，进程重启后不会把旧 flag 当新 flag 再交一遍。
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .config import Config, Target
from .store import Store
from .util import info, pmap, warn

STATE_KEY = "round.state"
DEFAULT_INTERVAL = 300          # 5 分钟一轮，AWD 常见节奏
MIN_INTERVAL = 20

# 固定落点：便宜且命中率最高
FAST_PATHS = ("/flag", "/flag.txt", "/root/flag", "/root/flag.txt",
              "/tmp/flag", "/tmp/flag.txt", "/home/*/flag*", "/var/www/html/flag",
              "/var/www/html/flag.txt")


@dataclass
class RoundConfig:
    interval: int = DEFAULT_INTERVAL
    auto_submit: bool = True
    deep: bool = False           # 每次都用全盘 grep（慢但全）
    max_seconds: int = 60


@dataclass
class RoundEvent:
    target: str
    new_flags: List[str] = field(default_factory=list)
    all_flags: List[str] = field(default_factory=list)
    changed: bool = False
    submitted: Dict[str, bool] = field(default_factory=dict)
    note: str = ""


@dataclass
class RoundStatus:
    running: bool = False
    interval: int = DEFAULT_INTERVAL
    round_no: int = 0
    ticks: int = 0
    started_at: float = 0.0
    last_tick: float = 0.0
    next_tick: float = 0.0
    auto_submit: bool = True
    deep: bool = False
    targets: List[str] = field(default_factory=list)
    known: Dict[str, List[str]] = field(default_factory=dict)
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        now = time.time()
        return {
            "running": self.running, "interval": self.interval,
            "round_no": self.round_no, "ticks": self.ticks,
            "started_at": self.started_at,
            "uptime": round(now - self.started_at, 1) if self.started_at else 0,
            "last_tick": self.last_tick,
            "next_in": max(0, round(self.next_tick - now, 1)) if self.running else 0,
            "auto_submit": self.auto_submit, "deep": self.deep,
            "targets": self.targets, "known": self.known,
            "last_error": self.last_error,
        }


def probe_fast(cfg: Config, target: Target, timeout: int = 20) -> List[str]:
    """只踩固定落点，一次 exec 搞定（每轮都用这个，代价很低）。"""
    from .flag import extract_flags
    from .sshx import SSHSession

    paths = " ".join(FAST_PATHS)
    cmd = (f'for f in {paths}; do [ -f "$f" ] && echo "== $f" && head -c 2000 "$f"; done '
           f'2>/dev/null')
    try:
        with SSHSession(target, cfg, retries=0) as sess:
            r = sess.exec(cmd, timeout=timeout)
            return extract_flags(r.out or "", cfg)
    except Exception:  # noqa: BLE001
        return []


def probe_target(cfg: Config, target: Target, deep: bool = False,
                 max_seconds: int = 60) -> List[str]:
    """读一台靶机的 flag：先快探，deep 或快探无果时再全盘 grep。"""
    flags = probe_fast(cfg, target)
    if flags and not deep:
        return flags
    from .flag import hunt_remote
    got = hunt_remote(cfg, target, max_seconds=max_seconds)
    merged = list(dict.fromkeys(flags + got))
    return merged


class RoundWatcher:
    """轮次监控器。线程安全，可启停，状态可持久化。"""

    def __init__(self, cfg: Config, store: Store):
        self.cfg = cfg
        self.store = store
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.rc = RoundConfig()
        self.status = RoundStatus()
        self._targets: List[Target] = []
        self._known: Dict[str, Set[str]] = {}
        self._load_state()

    # ---------------- 持久化 ----------------
    def _load_state(self) -> None:
        raw = self.store.get_setting(STATE_KEY, "") if hasattr(self.store, "get_setting") else ""
        if not raw:
            return
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            return
        self._known = {k: set(v or []) for k, v in (d.get("known") or {}).items()}
        self.status.round_no = int(d.get("round_no") or 0)
        self.status.ticks = int(d.get("ticks") or 0)

    def _save_state(self) -> None:
        if not hasattr(self.store, "set_setting"):
            return
        payload = {"known": {k: sorted(v) for k, v in self._known.items()},
                   "round_no": self.status.round_no, "ticks": self.status.ticks}
        self.store.set_setting(STATE_KEY, json.dumps(payload, ensure_ascii=False))

    # ---------------- 生命周期 ----------------
    def start(self, targets: Optional[List[str]] = None, interval: int = DEFAULT_INTERVAL,
              auto_submit: bool = True, deep: bool = False) -> Dict[str, Any]:
        with self._lock:
            if self.status.running:
                return self.state()
            ts = self._resolve(targets)
            if not ts:
                raise ValueError("没有可监控的靶机（默认只监控防守靶机）")
            self._targets = ts
            self.rc = RoundConfig(interval=max(MIN_INTERVAL, int(interval)),
                                  auto_submit=bool(auto_submit), deep=bool(deep))
            self.status = RoundStatus(
                running=True, interval=self.rc.interval, round_no=self.status.round_no,
                ticks=self.status.ticks, started_at=time.time(),
                auto_submit=self.rc.auto_submit, deep=self.rc.deep,
                targets=[t.name for t in ts],
                known={k: sorted(v) for k, v in self._known.items()})
            # 先给一个"下次检测"的预期值：界面倒计时在首轮跑完之前也有得显示
            self.status.next_tick = time.time() + self.rc.interval
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="round-watcher",
                                            daemon=True)
            self._thread.start()
        return self.state()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._stop.set()
            self.status.running = False
            self.status.next_tick = 0
        return self.state()

    def state(self) -> Dict[str, Any]:
        with self._lock:
            d = self.status.to_dict()
            d["stats"] = self.store.round_stats()
            return d

    def _resolve(self, names: Optional[List[str]]) -> List[Target]:
        if names:
            # 显式指定就必须匹配到：静默回退会让用户以为在监控 A，其实在监控 B
            return self.cfg.resolve(names)
        return self.cfg.resolve_role("defense")

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001
                with self._lock:
                    self.status.last_error = f"{type(e).__name__}: {e}"
                warn(f"轮次检测异常: {e}")
            with self._lock:
                self.status.next_tick = time.time() + self.rc.interval
            if self._stop.wait(self.rc.interval):
                break

    # ---------------- 一轮 ----------------
    def tick(self, targets: Optional[List[Target]] = None) -> List[RoundEvent]:
        """检查一轮：读 flag → 比对 → 新 flag 入库并提交。"""
        ts = targets or self._targets
        deep = self.rc.deep
        events: List[RoundEvent] = []

        def one(t: Target) -> RoundEvent:
            try:
                flags = probe_target(self.cfg, t, deep=deep)
            except Exception as e:  # noqa: BLE001
                return RoundEvent(target=t.name, note=f"读取失败: {e}")
            if flags:
                return RoundEvent(target=t.name, all_flags=flags)
            # 机器上没有 flag 文件时（flag 只在内网服务器上），改走 flagserver
            try:
                from . import flagserver as fs
                conf = fs.load_conf(self.cfg, self.store)
                if (conf.get("url") or conf.get("cmd")) and conf.get("enabled", True):
                    r = fs.fetch_one(self.cfg, t, conf)
                    if r.flags:
                        return RoundEvent(target=t.name, all_flags=r.flags,
                                          note=f"flagserver({r.tool})")
            except Exception as e:  # noqa: BLE001
                return RoundEvent(target=t.name, note=f"flagserver 失败: {e}")
            return RoundEvent(target=t.name, all_flags=[])

        results = pmap(one, ts, workers=min(4, max(1, len(ts)))) if ts else []
        got = [r for r in results if isinstance(r, RoundEvent)]
        for r in results:
            if isinstance(r, Exception):
                events.append(RoundEvent(target="?", note=str(r)))

        # 计算新 flag
        with self._lock:
            for ev in got:
                known = self._known.setdefault(ev.target, set())
                new = [f for f in ev.all_flags if f not in known]
                ev.new_flags = new
                ev.changed = bool(new)
                known.update(ev.all_flags)
            self.status.ticks += 1
            self.status.last_tick = time.time()

            any_change = any(e.changed for e in got)
            if any_change:
                self.status.round_no += 1
            round_no = self.status.round_no
            self.status.known = {k: sorted(v) for k, v in self._known.items()}
        self._save_state()

        # 入库 + 提交
        submitter = None
        if self.rc.auto_submit:
            from .flag import Submitter
            submitter = Submitter(self.cfg, self.store)

        for ev in got:
            if not ev.new_flags:
                if ev.all_flags:
                    self.store.add_round(round_no, ev.target, ev.all_flags[0],
                                         changed=False, note="内容未变")
                continue
            for flag in ev.new_flags:
                fresh = self.store.add_flag(flag, target=ev.target, source="round")
                done, ok_flag, msg = False, False, ""
                if fresh and submitter is not None:
                    try:
                        res = submitter.submit(flag, ev.target)
                        done, ok_flag, msg = True, res.ok, res.message
                        rows = self.store.flags(target=ev.target)
                        for row in rows:
                            if row["value"] == flag:
                                self.store.mark_flag(row["id"], res.message, res.ok)
                                break
                        if self.cfg.submit.interval:
                            time.sleep(self.cfg.submit.interval)
                    except Exception as e:  # noqa: BLE001
                        msg = f"提交异常: {e}"
                elif not fresh:
                    msg = "重复 flag，跳过"
                self.store.add_round(round_no, ev.target, flag, changed=True,
                                     submitted=done, ok=ok_flag, note=msg or "新 flag")
                self.store.event("flag", target=ev.target,
                                 title=f"第 {round_no} 轮新 FLAG",
                                 severity="high",
                                 data={"flag": flag, "submitted": done, "ok": ok_flag,
                                       "note": msg})
                ev.submitted[flag] = ok_flag
            events.append(ev)

        for ev in got:
            if not ev.changed and ev.all_flags:
                events.append(ev)
        return events

    # ---------------- 手动控制 ----------------
    def set_known(self, target: str, flags: List[str]) -> None:
        """把某台靶机的已知集合清空/重设（换场次时用）。"""
        with self._lock:
            self._known[target] = set(flags)
            self.status.known = {k: sorted(v) for k, v in self._known.items()}
        self._save_state()

    def reset(self) -> None:
        with self._lock:
            self._known.clear()
            self.status.known = {}
            self.status.round_no = 0
            self.status.ticks = 0
        self._save_state()

"""轻量任务引擎：扫描/备份/利用这类动作要跑几十秒，必须异步 + 可观测。

设计：单例 JobManager 持有线程池，每个 Job 有独立日志缓冲；
前端轮询 /api/jobs/{id} 拿增量日志，避免 WebSocket 在离线环境里的复杂度。
"""

from __future__ import annotations

import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Job:
    id: str
    kind: str
    title: str
    status: str = "queued"          # queued | running | done | failed
    created: float = field(default_factory=time.time)
    started: Optional[float] = None
    ended: Optional[float] = None
    logs: List[Dict[str, Any]] = field(default_factory=list)
    result: Any = None
    error: str = ""
    params: Dict[str, Any] = field(default_factory=dict)

    def log(self, msg: str, level: str = "info") -> None:
        entry = {"ts": round(time.time(), 3), "level": level, "msg": str(msg)[:4000]}
        with _LOCK:
            self.logs.append(entry)
            if len(self.logs) > 4000:
                del self.logs[:1000]
        BUS.publish({"type": "log", "job": self.id, "title": self.title,
                     "kind": self.kind, "entry": entry})

    def to_dict(self, tail: int = 0, offset: int = 0) -> Dict[str, Any]:
        with _LOCK:
            logs = self.logs[offset:] if offset else (self.logs[-tail:] if tail else self.logs)
        return {
            "id": self.id, "kind": self.kind, "title": self.title,
            "status": self.status, "created": self.created,
            "started": self.started, "ended": self.ended,
            "elapsed": round((self.ended or time.time()) - (self.started or self.created), 2),
            "logs": list(logs), "log_count": len(self.logs),
            "result": self.result, "error": self.error, "params": self.params,
        }


_LOCK = threading.RLock()


class EventBus:
    """极简发布订阅：任务日志/状态变化推给 WebSocket 连接。

    订阅者是 WS 连接对象，publish 时只做入队，不能在这里做阻塞 IO，
    否则会把任务线程拖住。
    """

    def __init__(self) -> None:
        self._subs: List[Any] = []
        self._lock = threading.RLock()

    def subscribe(self, fn) -> Any:
        with self._lock:
            self._subs.append(fn)

        def unsub() -> None:
            with self._lock:
                if fn in self._subs:
                    self._subs.remove(fn)
        return unsub

    def publish(self, msg: Dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(msg)
            except Exception:  # 订阅者异常不能影响任务
                pass


BUS = EventBus()


class JobManager:
    def __init__(self, workers: int = 3, keep: int = 120):
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="job")
        self._jobs: Dict[str, Job] = {}
        self._order: List[str] = []
        self._keep = keep

    # ---------- 提交 ----------
    def submit(self, kind: str, title: str,
               fn: Callable[[Job], Any], params: Optional[Dict[str, Any]] = None) -> Job:
        job = Job(id=uuid.uuid4().hex[:10], kind=kind, title=title,
                  params=params or {})
        with _LOCK:
            self._jobs[job.id] = job
            self._order.append(job.id)
            if len(self._order) > self._keep:
                for old in self._order[:-self._keep]:
                    self._jobs.pop(old, None)
                self._order = self._order[-self._keep:]
        self._pool.submit(self._run, job, fn)
        return job

    def _run(self, job: Job, fn: Callable[[Job], Any]) -> None:
        job.status = "running"
        job.started = time.time()
        self._notify(job)
        try:
            job.result = fn(job)
            job.status = "done"
            job.log("任务完成", "ok")
        except Exception as e:  # noqa: BLE001
            job.status = "failed"
            job.error = f"{type(e).__name__}: {e}"
            job.log(job.error, "error")
            job.log(traceback.format_exc()[-1500:], "debug")
        except BaseException as e:  # noqa: BLE001
            # 被外部打断（审计钩子 / 安全删除守卫 / SystemExit）也要落到 failed，
            # 否则界面永远显示"执行中"，只能重启服务
            job.status = "failed"
            job.error = f"任务被中断: {type(e).__name__}: {e}"
            job.log(job.error, "error")
        finally:
            job.ended = time.time()
            self._notify(job)

    @staticmethod
    def _notify(job: Job) -> None:
        BUS.publish({"type": "job", "job": {
            "id": job.id, "kind": job.kind, "title": job.title,
            "status": job.status,
            "elapsed": round((job.ended or time.time()) - (job.started or job.created), 2),
            "error": job.error, "log_count": len(job.logs),
        }})

    # ---------- 查询 ----------
    def get(self, job_id: str) -> Optional[Job]:
        with _LOCK:
            return self._jobs.get(job_id)

    def list(self, limit: int = 30) -> List[Dict[str, Any]]:
        with _LOCK:
            ids = list(reversed(self._order))[:limit]
            return [self._jobs[i].to_dict(tail=3) for i in ids if i in self._jobs]

    def active(self) -> int:
        with _LOCK:
            return sum(1 for j in self._jobs.values() if j.status in ("queued", "running"))

    def wait(self, job_id: str, timeout: float = 600) -> Optional[Job]:
        """同步等待（CLI/测试用）。"""
        t0 = time.time()
        while time.time() - t0 < timeout:
            j = self.get(job_id)
            if j and j.status in ("done", "failed"):
                return j
            time.sleep(0.05)
        return self.get(job_id)

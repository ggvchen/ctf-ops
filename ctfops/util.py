"""通用工具：日志、时间、截断、并发、脱敏。"""

from __future__ import annotations

import concurrent.futures as futures
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional, Sequence, TypeVar

from rich.console import Console

# emoji=False：靶机返回的证据里常有 root:x:0:0 这种串，Rich 会把 :x: 当表情，
# 渲染成 root❌0:0 —— 取证输出必须原样
console = Console(emoji=False)
err_console = Console(stderr=True, emoji=False)
T = TypeVar("T")
R = TypeVar("R")

TS_FMT = "%Y-%m-%d %H:%M:%S"


def now() -> str:
    return datetime.now().strftime(TS_FMT)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime(TS_FMT)


def iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def sha256_file(p: str | Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def human_size(n: int | float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


def trunc(s: str, limit: int = 4000, tail: bool = False) -> str:
    if not s:
        return ""
    if len(s) <= limit:
        return s
    body = s[-limit:] if tail else s[:limit]
    return f"{'...[截断前缀]' if tail else ''}{body}\n...[共 {len(s)} 字符，已截断]"


def jdump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def jload(s: Optional[str], default: Any = None) -> Any:
    if not s:
        return default if default is not None else {}
    try:
        return json.loads(s)
    except Exception:
        return default if default is not None else {}


def pmap(fn: Callable[[T], R], items: Sequence[T], workers: int = 8,
         label: str = "") -> List[R]:
    """并发 map，保持顺序，异常转成 Exception 结果不炸全场。"""
    out: List[Optional[R]] = [None] * len(items)
    if not items:
        return []
    if workers <= 1 or len(items) == 1:
        for i, it in enumerate(items):
            try:
                out[i] = fn(it)
            except Exception as e:  # noqa: BLE001
                out[i] = e  # type: ignore[assignment]
                if label:
                    err_console.print(f"[red]{label} 失败[/red] {it}: {e}")
        return [r if not isinstance(r, Exception) else r for r in out]  # type: ignore[list-item]
    with futures.ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        futs = {ex.submit(fn, it): i for i, it in enumerate(items)}
        for fut in futures.as_completed(futs):
            i = futs[fut]
            try:
                out[i] = fut.result()
            except Exception as e:  # noqa: BLE001
                out[i] = e  # type: ignore[assignment]
                if label:
                    err_console.print(f"[red]{label} 失败[/red] {items[i]}: {e}")
    return out  # type: ignore[return-value]


PWD_RE = re.compile(
    r"(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key)\s*[:=]\s*[\"']?([^\s\"',;]{3,})")


def mask_secret(s: str) -> str:
    def repl(m: re.Match) -> str:
        return f"{m.group(1)}={'*' * min(8, len(m.group(3)))}"
    return PWD_RE.sub(repl, s)


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80]


def sleep_between(i: int, n: int, interval: float) -> None:
    if i < n - 1 and interval > 0:
        time.sleep(interval)


def read_text(p: str | Path, limit: int = 5_000_000) -> str:
    data = Path(p).read_bytes()[:limit]
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def which(cmd: str) -> Optional[str]:
    import shutil
    return shutil.which(cmd)


def die(msg: str, code: int = 1) -> None:
    err_console.print(f"[bold red]✗[/bold red] {msg}")
    sys.exit(code)


def info(msg: str) -> None:
    console.print(f"[cyan]›[/cyan] {msg}")


def ok(msg: str) -> None:
    console.print(f"[green]✓[/green] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow]![/yellow] {msg}")


def iter_lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield line

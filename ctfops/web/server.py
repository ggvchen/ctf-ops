"""Web 控制台服务：静态页面 + JSON API，单文件进程，127.0.0.1 绑定。

刻意只用标准库：
- 比赛现场常断网，不能依赖 CDN 或 npm 构建
- 一条命令启动，不需要 node/打包
"""

from __future__ import annotations

import json
import mimetypes
import pathlib
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from ..config import Config, load_config
from ..store import Store
from ..util import console, ok
from . import api
from .jobs import JobManager

STATIC_DIR = pathlib.Path(__file__).parent / "static"

_CODE_DIR = pathlib.Path(__file__).resolve().parent.parent
_CODE_CACHE: Dict[str, Any] = {"ts": 0.0, "mtime": 0.0}


def code_mtime(max_age: float = 20.0) -> float:
    """后端代码最后一次被改动的时间。

    用途只有一个：改了 .py 但没重启进程时，页面能直接说"服务端是旧的"。
    没这行提示，表现就是"未知接口 GET /api/xxx"，很容易以为接口没写。
    """
    now = time.time()
    if now - _CODE_CACHE["ts"] < max_age:
        return float(_CODE_CACHE["mtime"])
    newest = 0.0
    try:
        for p in _CODE_DIR.rglob("*.py"):
            if "/.venv/" in p.as_posix() or "/tests/" in p.as_posix():
                continue
            m = p.stat().st_mtime
            if m > newest:
                newest = m
    except OSError:
        pass
    _CODE_CACHE.update({"ts": now, "mtime": newest})
    return newest


class AppState:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.store = Store(cfg.db_path)
        self.jobs = JobManager(workers=3)
        self.shells = None          # 延迟创建，避免启动就 import paramiko
        self.rounds = None          # 轮次监控器，延迟创建
        self.autoloop = None        # 定时自动作战，延迟创建
        self._lock = threading.Lock()
        # 上次开着的定时自动作战，重启后接回来（进程挂了不该让定时悄悄停摆）
        try:
            self.auto_loop.restore()
        except Exception:  # noqa: BLE001
            pass
        self.started_at = time.time()
        self.started_at_iso = time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(self.started_at))

    def stale(self) -> Dict[str, Any]:
        """后端代码是否比当前进程新（改了没重启）。"""
        cm = code_mtime()
        return {"started_at": self.started_at_iso,
                "code_mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cm))
                if cm else "",
                "stale": bool(cm and cm > self.started_at + 1.0)}

    @property
    def term_pool(self):
        if self.shells is None:
            from ..term import ShellPool
            self.shells = ShellPool(self.cfg)
        return self.shells

    @property
    def round(self):
        if self.rounds is None:
            from ..round import RoundWatcher
            self.rounds = RoundWatcher(self.cfg, self.store)
        return self.rounds

    @property
    def auto_loop(self):
        if self.autoloop is None:
            from ..autopilot import AutoLoop
            self.autoloop = AutoLoop(self.cfg, self.store)
        return self.autoloop

    def reload(self) -> None:
        with self._lock:
            if self.shells is not None:
                try:
                    self.shells.reset()
                except Exception:
                    pass
                self.shells = None
            self.cfg = load_config(str(self.cfg.path))
            self.cfg.ensure_dirs()
            self.store = Store(self.cfg.db_path)


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")


def make_handler(app: AppState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ctf-ops/1.0"
        protocol_version = "HTTP/1.1"

        # ---------- 基础设施 ----------
        def log_message(self, fmt, *args):  # 静音，避免刷屏
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json",
                  extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype + ("; charset=utf-8"
                                                      if ctype.startswith(("application/json", "text/")) else ""))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _err(self, code: int, msg: str) -> None:
            self._send(code, _json_bytes({"error": msg}))

        def _body(self) -> Dict[str, Any]:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return {}
            if n <= 0:
                return {}
            if n > 20 << 20:
                raise ValueError("请求体过大")
            raw = self.rfile.read(n)
            if not raw:
                return {}
            try:
                data = json.loads(raw.decode("utf-8"))
                return data if isinstance(data, dict) else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise ValueError("请求体必须是 JSON")

        # ---------- 路由 ----------
        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def do_DELETE(self) -> None:  # noqa: N802
            self._dispatch("DELETE")

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch("PUT")

        def _dispatch(self, method: str) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = urllib.parse.unquote(parsed.path)
            query = {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}

            if path == "/artifact":
                return self._artifact(query)
            if path == "/api/upload" and method in ("PUT", "POST"):
                # 拖进来的文件是二进制，不能走 _body() 的 JSON 解析，这里流式落盘
                return self._upload(query)
            if path == "/api/upload/exists" and method == "GET":
                return self._upload_exists(query)
            if path in ("/ws", "/ws/jobs"):
                from .ws import serve_ws
                if not serve_ws(self, app):
                    return self._err(400, "需要 WebSocket 升级请求")
                return
            if not path.startswith("/api/"):
                return self._static(path)

            try:
                body = self._body() if method in ("POST", "PUT", "DELETE") else {}
            except ValueError as e:
                return self._err(400, str(e))

            for m, pattern, fn in api.ROUTES:
                if m != method:
                    continue
                match = pattern.match(path)
                if not match:
                    continue
                try:
                    status, payload = fn(app, match.groupdict(), query, body)
                    return self._send(status, _json_bytes(payload))
                except ValueError as e:
                    return self._err(400, str(e))
                except KeyError as e:
                    return self._err(404, str(e).strip("'\""))
                except Exception as e:  # noqa: BLE001
                    traceback.print_exc()
                    return self._err(500, f"{type(e).__name__}: {e}")
            self._err(404, f"未知接口 {method} {path}")

        # ---------- 静态 ----------
        def _static(self, path: str) -> None:
            if path in ("/", "/index.html"):
                f = STATIC_DIR / "index.html"
            else:
                rel = path.lstrip("/")
                if rel.startswith("static/"):
                    rel = rel[len("static/"):]
                f = (STATIC_DIR / rel).resolve()
                if not str(f).startswith(str(STATIC_DIR.resolve())):
                    return self._err(403, "forbidden")
            if not f.is_file():
                return self._err(404, "not found")
            ctype = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
            if f.suffix == ".js":
                ctype = "application/javascript"
            if f.suffix == ".css":
                ctype = "text/css"
            self._send(200, f.read_bytes(), ctype)

        # ---------- 拖拽上传 ----------
        def _upload_exists(self, query: Dict[str, str]) -> None:
            """同一个 pcap 反复拖进来时别再复制一份（37MB 的包拖三次就 100MB+）。"""
            name = pathlib.PurePosixPath((query.get("name") or "").replace("\\", "/")).name
            try:
                size = int(query.get("size") or 0)
            except ValueError:
                size = 0
            if not name or size <= 0:
                return self._send(200, _json_bytes({"path": ""}))
            root = app.cfg.workdir / "evidence" / "uploads"
            if root.is_dir():
                for f in root.glob(f"*/{name}"):
                    try:
                        if f.is_file() and f.stat().st_size == size:
                            # resolve 一下：macOS 上 /var 是 /private/var 的软链，
                            # 不解析会和上传返回的路径字符串对不上
                            f = f.resolve()
                            rel = f.relative_to(app.cfg.workdir.resolve()).as_posix()
                            return self._send(200, _json_bytes(
                                {"path": str(f), "rel": rel, "reused": True}))
                    except OSError:
                        continue
            return self._send(200, _json_bytes({"path": ""}))

        def _upload(self, query: Dict[str, str]) -> None:
            """把浏览器拖进来的文件写到 workdir/evidence/uploads/<rel>。

            浏览器（非 Electron）拿不到本地绝对路径，所以拖拽只能"上传一份"：
            落到 evidence 下再按相对路径分析。分块读写，避免把几百 MB 的 pcap 读进内存。
            """
            rel = (query.get("path") or "").strip().lstrip("/")
            if not rel:
                return self._err(400, "path 必填")
            if rel.startswith("..") or "/../" in rel or "\\" in rel:
                return self._err(400, "路径不合法")
            if not rel.startswith("evidence/uploads/"):
                return self._err(400, "只能写 evidence/uploads/ 下")
            try:
                size = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._err(400, "Content-Length 不合法")
            limit = 2 << 30
            if size <= 0:
                return self._err(400, "空文件")
            if size > limit:
                return self._err(413, "单个文件超过 2GB，请先切分")
            dest = api.safe_path(app.cfg, rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            got = 0
            try:
                with open(dest, "wb") as fh:
                    while got < size:
                        chunk = self.rfile.read(min(1 << 20, size - got))
                        if not chunk:
                            break
                        fh.write(chunk)
                        got += len(chunk)
            except Exception as e:  # noqa: BLE001
                return self._err(500, f"写入失败: {e}")
            return self._send(200, _json_bytes({
                "ok": True, "rel": rel, "path": str(dest), "size": got}))

        # ---------- 产物文件 ----------
        def _artifact(self, query: Dict[str, str]) -> None:
            rel = query.get("path") or ""
            if not rel:
                return self._err(400, "path 必填")
            if rel.startswith("/"):
                # 外部备份目录（如外置盘）单独放行，其它绝对路径一律拒绝
                from ..backup import backup_root
                try:
                    broot = backup_root(app.cfg, app.store).resolve()
                except Exception:
                    return self._err(403, "备份目录不可用")
                f = pathlib.Path(rel).resolve()
                if broot != f.parent and broot not in f.parents:
                    return self._err(403, "路径越界")
            else:
                try:
                    f = api.safe_path(app.cfg, rel)
                except ValueError as e:
                    return self._err(403, str(e))
            if not f.is_file():
                return self._err(404, "文件不存在")
            ctype = mimetypes.guess_type(str(f))[0] or "application/octet-stream"
            disp = "attachment" if query.get("download") else "inline"
            self._send(200, f.read_bytes(), ctype,
                       {"Content-Disposition": f'{disp}; filename="{f.name}"'})

    return Handler


def serve(cfg: Config, port: int = 8899, open_browser: bool = True,
          host: str = "127.0.0.1") -> None:
    app = AppState(cfg)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.daemon_threads = True
    url = f"http://{host}:{port}"
    ok(f"控制台已启动 {url}")
    console.print(f"  [dim]靶机 {len(cfg.targets)} 台 · 配置 {cfg.path.name} · "
                  f"数据 {cfg.db_path.parent}[/dim]")
    console.print("  [dim]Ctrl-C 退出[/dim]")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]已停止[/dim]")
    finally:
        httpd.server_close()

"""WebSocket 推送：标准库手写 RFC 6455，不引第三方。

用途：任务日志与状态变化实时推给前端，替代 900ms 轮询。

设计要点：
- 每个连接一个发送队列 + 一个发送线程，任务线程 publish 时只入队，绝不阻塞
- 客户端消息只支持 ping/close（本系统不需要上行指令）
- 读循环阻塞在 rfile 上；浏览器关页会发 close 或断 TCP，据此清理订阅
"""

from __future__ import annotations

import base64
import hashlib
import json
import queue
import socket
import struct
import threading
from typing import Any, Dict, Optional

from .jobs import BUS

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT = 0x1
OP_BIN = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def _accept_key(key: str) -> str:
    return base64.b64encode(
        hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")


def _frame(payload: bytes, opcode: int = OP_TEXT) -> bytes:
    n = len(payload)
    head = bytes([0x80 | opcode])
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    return head + payload


class WSConnection:
    """一条连接：入队 → 发送线程 → 客户端；同时读客户端帧。"""

    def __init__(self, handler, max_queue: int = 2000):
        self.handler = handler
        self.sock: socket.socket = handler.connection
        self.rfile = handler.rfile
        self.wfile = handler.wfile
        self.alive = True
        self._q: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=max_queue)
        self._send_lock = threading.Lock()
        self._dropped = 0
        self._unsub = None
        self._sender: Optional[threading.Thread] = None

    # ---------- 收 ----------
    def _read_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.rfile.read(n - len(data))
            if not chunk:
                raise ConnectionError("client closed")
            data += chunk
        return data

    def _read_frame(self) -> "tuple[int, bytes]":
        b1, b2 = self._read_exact(2)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._read_exact(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._read_exact(8))[0]
        mask = self._read_exact(4) if masked else b""
        payload = self._read_exact(n) if n else b""
        if mask:
            payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        return opcode, payload

    # ---------- 发 ----------
    def _write(self, data: bytes) -> None:
        with self._send_lock:
            self.wfile.write(data)
            self.wfile.flush()

    def send_json(self, obj: Dict[str, Any]) -> None:
        if not self.alive:
            return
        try:
            self._q.put_nowait(_frame(json.dumps(obj, ensure_ascii=False,
                                                default=str).encode("utf-8")))
        except queue.Full:
            # 客户端太慢：丢掉最老的，保证新消息还能进
            self._dropped += 1
            try:
                self._q.get_nowait()
                self._q.put_nowait(_frame(json.dumps(obj, ensure_ascii=False,
                                                    default=str).encode("utf-8")))
            except Exception:
                pass

    def _sender_loop(self) -> None:
        while self.alive:
            try:
                data = self._q.get(timeout=1.0)
            except queue.Empty:
                continue
            if data is None:
                break
            try:
                self._write(data)
            except Exception:
                self.alive = False
                break

    # ---------- 生命周期 ----------
    def start(self, hello: Dict[str, Any]) -> None:
        self._sender = threading.Thread(target=self._sender_loop,
                                        name="ws-sender", daemon=True)
        self._sender.start()
        self.send_json(hello)
        self._unsub = BUS.subscribe(self.send_json)

    def recv_loop(self) -> None:
        self.sock.settimeout(None)
        try:
            while self.alive:
                opcode, payload = self._read_frame()
                if opcode == OP_CLOSE:
                    try:
                        self._write(_frame(b"", OP_CLOSE))
                    except Exception:
                        pass
                    break
                if opcode == OP_PING:
                    self._write(_frame(payload, OP_PONG))
                elif opcode in (OP_TEXT, OP_BIN):
                    try:
                        msg = json.loads(payload.decode("utf-8", "replace"))
                    except Exception:
                        continue
                    if msg.get("type") == "ping":
                        self.send_json({"type": "pong"})
        except (ConnectionError, OSError):
            pass
        finally:
            self.close()

    def close(self) -> None:
        self.alive = False
        if self._unsub:
            try:
                self._unsub()
            except Exception:
                pass
            self._unsub = None
        try:
            self._q.put_nowait(None)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


def serve_ws(handler, app) -> bool:
    """在 BaseHTTPRequestHandler 里升级连接；返回 False 表示不是 WS 请求。"""
    key = handler.headers.get("Sec-WebSocket-Key")
    upgrade = (handler.headers.get("Upgrade") or "").lower()
    if not key or upgrade != "websocket":
        return False

    handler.send_response(101, "Switching Protocols")
    handler.send_header("Upgrade", "websocket")
    handler.send_header("Connection", "Upgrade")
    handler.send_header("Sec-WebSocket-Accept", _accept_key(key))
    handler.end_headers()
    handler.wfile.flush()

    conn = WSConnection(handler)
    conn.start({
        "type": "hello",
        "server": "ctf-ops",
        "jobs": app.jobs.list(limit=10),
        "active": app.jobs.active(),
    })
    handler.close_connection = True
    conn.recv_loop()
    return True

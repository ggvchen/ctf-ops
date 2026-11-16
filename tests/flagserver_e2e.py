"""flagserver 端到端自测：经「靶机」访问 flag 服务器 → 入库 → 提交。

不依赖真靶机：起一个 mock sshd（exec 走本机 subprocess）+ 一个 mock flag 服务
+ 一个 mock 提交平台，然后把完整链路跑一遍。

    ./.venv/bin/python tests/flagserver_e2e.py
"""

from __future__ import annotations

import json
import pathlib
import socket
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import paramiko  # noqa: E402

from ctfops import flagserver as fs  # noqa: E402
from ctfops.config import Config, SubmitConfig, Target  # noqa: E402
from ctfops.store import Store  # noqa: E402

USER, PWD = "test", "test"
TOKEN = "tK9;$(id)&x+y"      # 故意带分号/子 shell/URL 保留字符：验证不注入、且查询串正确转义
FLAG = "flag{flagserver_e2e_0123456789}"

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} {detail}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ------------------------------------------------------------------ mock flag 服务
class FlagHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen: list = []

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        token = (q.get("token") or [""])[0]
        FlagHandler.seen.append(("GET", u.path, token, self.headers.get("X-Token", "")))
        if u.path == "/api/flag":
            if token != TOKEN:
                return self._send(403, b'{"code":403,"msg":"bad token"}')
            return self._send(200, json.dumps(
                {"code": 0, "data": {"flag": FLAG}}, ensure_ascii=False).encode())
        if u.path == "/plain":
            return self._send(200, f"your flag is {FLAG}\n".encode(), "text/plain")
        if u.path == "/broken":
            return self._send(500, b"internal error", "text/plain")
        return self._send(404, b"{}")

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        FlagHandler.seen.append(("POST", self.path, body, self.headers.get("X-Token", "")))
        data = json.loads(body or "{}")
        token = data.get("token") or self.headers.get("X-Token", "")
        if token != TOKEN:
            return self._send(403, b'{"code":403,"msg":"bad token"}')
        return self._send(200, json.dumps(
            {"code": 0, "data": {"flag": FLAG}}).encode())


# ------------------------------------------------------------------ mock 提交平台
class SubmitHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    got: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        SubmitHandler.got.append(body)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}
        ok = data.get("flag") == FLAG
        out = json.dumps({"success": ok, "message": "+100" if ok else "wrong flag"})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out.encode())))
        self.end_headers()
        self.wfile.write(out.encode())


# ------------------------------------------------------------------ mock sshd
class MockSSH(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == (USER, PWD) \
            else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" \
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", "replace") if isinstance(command, bytes) else command
        threading.Thread(target=self._exec, args=(channel, cmd), daemon=True).start()
        return True

    def check_channel_pty_request(self, *a, **kw):
        return True

    def _exec(self, channel, cmd):
        import subprocess
        try:
            cp = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
            if cp.stdout:
                channel.sendall(cp.stdout)
            if cp.stderr:
                channel.sendall_stderr(cp.stderr)
            channel.send_exit_status(cp.returncode)
        finally:
            channel.close()


def start_sshd(port: int) -> socket.socket:
    host_key = paramiko.RSAKey.generate(2048)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(20)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn, host_key), daemon=True).start()

    def _handle(conn, key):
        try:
            tr = paramiko.Transport(conn)
            tr.add_server_key(key)
            tr.start_server(server=MockSSH())
            while tr.is_active():
                time.sleep(0.1)
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=loop, daemon=True).start()
    return srv


def serve(handler) -> ThreadingHTTPServer:
    port = free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main() -> int:
    flagd = serve(FlagHandler)
    subd = serve(SubmitHandler)
    ssh_port = free_port()
    start_sshd(ssh_port)
    time.sleep(0.6)

    print("mock：flag 服务 :%d · 提交平台 :%d · sshd :%d"
          % (flagd.server_address[1], subd.server_address[1], ssh_port))

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ctfops-fs-"))
    (tmp / "evidence").mkdir(parents=True, exist_ok=True)
    token_file = tmp / "flag_token"
    token_file.write_text(TOKEN + "\n", encoding="utf-8")

    cfg = Config(path=tmp / "config.yaml", workdir=tmp)
    cfg.flag_patterns = [r"flag\{[^}\r\n]{1,200}\}"]
    cfg.submit = SubmitConfig(
        mode="generic_http", url=f"http://127.0.0.1:{subd.server_address[1]}/submit",
        method="POST", json_body={"flag": "{flag}"},
        headers={"Content-Type": "application/json"},
        success_key="success", success_value=True, message_key="message",
        interval=0, retries=1, strict=True)
    t = Target(name="web-01", host="127.0.0.1", ssh_port=ssh_port,
               user=USER, password=PWD)
    cfg.targets = [t]
    store = Store(cfg.db_path)

    print("\n[1] 命令拼装：token 里的引号/分号不能破坏命令")
    conf = fs.defaults()
    conf.update({
        "url": "http://127.0.0.1:%d/api/flag?token={token_url}" % flagd.server_address[1],
        "field": "data.flag",
        "token_cmd": f"cat {token_file}",
        "submit_after": True,
    })
    cmd = fs.build_commands(conf, t)[0][1]
    check("URL 里的 {token_url} 变成 $TKU", '"$TKU"' in cmd, cmd)
    check("没有把 token 明文拼进命令", TOKEN not in cmd, cmd)

    print("\n[2] 经靶机 GET，token 来自靶机文件")
    r = fs.fetch_one(cfg, t, conf)
    check("命令成功", r.ok, r.error)
    check("解析出 flag", FLAG in r.flags, str(r.flags))
    check("工具为 curl", r.tool == "curl", r.tool)
    check("服务端收到的 token 与文件一致",
          any(x[2] == TOKEN for x in FlagHandler.seen), str(FlagHandler.seen)[:200])

    print("\n[3] 无字段配置时靠正则从纯文本里抠")
    plain = dict(conf, url="http://127.0.0.1:%d/plain" % flagd.server_address[1], field="")
    r2 = fs.fetch_one(cfg, t, plain)
    check("纯文本响应也能命中", r2.ok and FLAG in r2.flags, str(r2.flags))

    print("\n[4] POST + 请求头带 token")
    post = dict(conf, url="http://127.0.0.1:%d/api/flag" % flagd.server_address[1],
                method="POST", body='{"token":"{token}"}',
                headers={"X-Token": "{token}"}, field="data.flag")
    r3 = fs.fetch_one(cfg, t, post)
    hit = [x for x in FlagHandler.seen if x[0] == "POST"]
    check("POST 拿到 flag", r3.ok and FLAG in r3.flags, str(r3.flags) + r3.error)
    check("请求头里的 token 被替换", hit and hit[-1][3] == TOKEN, str(hit[-1:]))
    check("body 里的 token 被替换", hit and TOKEN in hit[-1][2], str(hit[-1:]))

    print("\n[5] 服务端报错时不误判成功")
    bad = dict(conf, url="http://127.0.0.1:%d/api/flag?token=wrong" % flagd.server_address[1])
    r4 = fs.fetch_one(cfg, t, bad)
    check("403 判定为失败", not r4.ok, f"ok={r4.ok} flags={r4.flags}")
    check("带上原始错误信息", "403" in (r4.error or "") or "bad" in (r4.out or ""), r4.error)

    print("\n[6] cmd 模式：平台给的是本地命令")
    cmdf = dict(conf, mode="cmd", cmd=f"echo '{FLAG}'")
    r5 = fs.fetch_one(cfg, t, cmdf)
    check("本地命令输出被解析成 flag", r5.ok and FLAG in r5.flags, str(r5.flags))

    print("\n[7] 全流程：入库 → 去重 → 提交")
    res = fs.fetch_all(cfg, store, conf=conf, submit=True)
    check("新增 1 个 flag", res["new"] == 1, str(res["new"]))
    rows = store.flags()
    check("库里记了来源 flagserver", rows and rows[0]["source"] == "flagserver",
          str(rows[:1]))
    check("提交成功", res["submitted"]["ok"] == 1, str(res["submitted"]))
    check("平台收到的 flag 正确",
          SubmitHandler.got and json.loads(SubmitHandler.got[-1]).get("flag") == FLAG,
          str(SubmitHandler.got[:1]))
    check("提交后标记为已完成", store.flags(only_pending=True) == [], "还有待提交")

    print("\n[8] 再跑一次不会重复提交")
    res2 = fs.fetch_all(cfg, store, conf=conf, submit=True)
    check("没有新增", res2["new"] == 0, str(res2["new"]))
    check("没有重复提交", res2["submitted"]["ok"] == 0, str(res2["submitted"]))

    print("\n[9] 逐机 token 优先于全局 / 文件")
    per = dict(conf, tokens={"web-01": TOKEN}, token_cmd="cat /nonexistent")
    r6 = fs.fetch_one(cfg, t, per)
    check("逐机 token 生效", r6.ok and FLAG in r6.flags, str(r6.flags) + r6.error)

    print("\n[10] 配置读写（settings 存档）")
    fs.save_conf(store, dict(conf, field="data.flag", scope="all"))
    back = fs.load_conf(cfg, store)
    check("字段落盘", back["field"] == "data.flag", str(back.get("field")))
    check("范围落盘", back["scope"] == "all", str(back.get("scope")))
    check("未设置的键保留默认", back["trust_field"] is False, str(back.get("trust_field")))

    print("\n[11] 上次执行摘要")
    last = fs.last_run(store)
    check("有 last 记录", bool(last.get("ts")), str(last)[:120])
    check("rows 不带完整命令（防刷屏）",
          all("cmd" not in r for r in last.get("rows", [])), str(last.get("rows"))[:120])

    print("\n" + "=" * 40)
    print(f"通过 {PASS} 项，失败 {FAIL} 项")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

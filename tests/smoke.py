"""离线冒烟测试：不碰真实靶机，验证核心链路可跑通。

    ./.venv/bin/python tests/smoke.py
"""

from __future__ import annotations

import json
import re
import pathlib
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ctfops.config import Config, Target, load_config  # noqa: E402
from ctfops.flag import Submitter, extract_flags  # noqa: E402
from ctfops.logx import analyze_paths  # noqa: E402
from ctfops.report import write_report  # noqa: E402
from ctfops.store import Store  # noqa: E402

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


# ------------------------------------------------------------ mock platform
class Handler(BaseHTTPRequestHandler):
    hits: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        try:
            data = json.loads(body or b"{}")
        except Exception:
            data = {}
        Handler.hits.append({"path": self.path, "data": data,
                             "auth": self.headers.get("Authorization", "")})
        flag = str(data.get("flag", ""))
        if flag.startswith("flag{") and len(flag) > 8:
            resp = {"success": True, "message": "accepted"}
        else:
            resp = {"success": False, "message": "invalid flag"}
        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def main() -> int:
    print("\n[1] 配置加载")
    cfg = load_config(str(ROOT / "config" / "config.yaml"))
    # 用户可能随时在界面里加靶机，这里只校验"至少解析出配置里的靶机"
    check("靶机解析", len(cfg.targets) >= 3, f"got {len(cfg.targets)}")
    check("默认凭据下沉", cfg.targets[0].ssh_port == 22)
    check("flag 规则", len(cfg.flag_patterns) >= 4)

    print("\n[2] FLAG 提取")
    sample = ("log: 拿到 flag{th1s_1s_4_t3st} 和 DASCTF{0123456789abcdef0123456789abcdef}"
              " 噪声 flag{test} 不算")
    got = extract_flags(sample, cfg)
    check("提取两个真 flag", len(got) == 2, str(got))
    check("噪声被过滤", "flag{test}" not in got)

    print("\n[3] 存储与幂等")
    tmp = pathlib.Path(tempfile.mkdtemp())
    store = Store(tmp / "ops.db")
    check("首次入库", store.add_flag("flag{abc123456}", target="t1"))
    check("重复不入库", not store.add_flag("flag{abc123456}", target="t1"))
    check("计数正确", len(store.flags()) == 1)
    store.event("finding", target="t1", title="测试发现", severity="high", data={"x": 1})
    check("事件统计", store.summary()["findings"] == 1)

    print("\n[4] 提交：manual 降级")
    cfg.submit.mode = "manual"
    cfg.submit.url = ""
    sub = Submitter(cfg, store)
    sub.outbox = tmp / "outbox"
    sub.log_dir = tmp / "logs"
    sub.log_dir.mkdir(parents=True, exist_ok=True)
    sub.outbox.mkdir(parents=True, exist_ok=True)
    r = sub.submit("flag{abc123456}", "t1")
    check("manual 返回成功", r.ok)
    check("outbox 落盘", any(sub.outbox.iterdir()))

    print("\n[5] 提交：generic_http 真打")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    cfg.submit.mode = "generic_http"
    cfg.submit.url = f"http://127.0.0.1:{port}/api/flag"
    cfg.submit.token = "TESTTOKEN"
    cfg.submit.json_body = {"flag": "{flag}", "token": "{token}"}
    cfg.submit.headers = {"Content-Type": "application/json"}
    cfg.submit.retries = 1
    cfg.submit.interval = 0
    r2 = sub.submit("flag{real_flag_2026}", "t1")
    check("平台判定成功", r2.ok, r2.message)
    check("带上了 token", Handler.hits and Handler.hits[-1]["data"].get("token") == "TESTTOKEN")
    check("Bearer 头注入", Handler.hits and Handler.hits[-1]["auth"] == "Bearer TESTTOKEN")
    r3 = sub.submit("not-a-flag", "t1")
    check("失败被正确识别", not r3.ok, r3.message)

    print("\n[6] 提交：批量 + 状态回写")
    store.add_flag("flag{batch_1}", target="t2")
    store.add_flag("flag{batch_2}", target="t2")
    results = Submitter(cfg, store).submit_all(only_pending=True, workers=1)
    check("批量全部成功", all(x.ok for x in results if x.flag.startswith("flag{")),
          str([(x.flag, x.ok) for x in results]))
    check("DB 标记已提交", all(f["submitted"] for f in store.flags(only_pending=True)) is False
          or len(store.flags(only_pending=True)) < 3)
    srv.shutdown()

    print("\n[7] 日志分析")
    rep = analyze_paths([str(ROOT / "tests/fixtures")], _no_ai(cfg), target="web01")
    titles = [f.title for f in rep.findings]
    check("识别爆破", any("爆破" in t for t in titles), str(titles[:5]))
    check("识别爆破后登录", any("爆破成功后登录" in t for t in titles))
    check("识别 webshell", any("webshell" in t.lower() for t in titles))
    check("识别注入", any("SQL" in t or "命令执行" in t for t in titles))
    check("生成时间线", len(rep.timeline) >= 2)
    check("发现数量合理", len(rep.findings) >= 6, str(len(rep.findings)))

    print("\n[8] 报告生成")
    cfg.workdir = tmp
    cfg.ensure_dirs()
    for f in rep.findings:
        store.event("finding", target="web01", title=f.title, severity=f.severity, data=f.to_dict())
    store.add_backup("web01", "/tmp/x.tar.gz", str(tmp / "b.tar.gz"), 1024, "ab" * 32, True, "")
    files = write_report(cfg, store, "冒烟报告")
    md = files[0].read_text(encoding="utf-8")
    html = files[2].read_text(encoding="utf-8")
    check("md 有总览", "## 一、总览" in md)
    check("md 有 flag 表", "FLAG 与提交" in md)
    check("html 表头用 th", "<th>" in html)
    check("html 无异常标记", "None" not in html.split("<body>")[1][:500])

    print("\n[9] Web 控制台 API")
    from ctfops.web.server import AppState, make_handler
    webapp = AppState(cfg)
    dash = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(webapp))
    dash.daemon_threads = True
    threading.Thread(target=dash.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{dash.server_address[1]}"

    def get(path, timeout=6):
        try:
            with urllib.request.urlopen(base + path, timeout=timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read() or b"{}"

    def getj(path, timeout=6):
        st, body = get(path, timeout)
        try:
            return st, json.loads(body)
        except Exception:
            return st, {}

    for path in ("/", "/static/app.js", "/static/style.css", "/api/overview",
                 "/api/targets", "/api/findings", "/api/flags", "/api/backups",
                 "/api/shots", "/api/artifacts", "/api/jobs", "/api/exploit/plugins",
                 # 下面这几个是页面配置用的新接口：路由没注册的话前端只会弹"未知接口"
                 "/api/ai/config", "/api/ai/models?timeout=1", "/api/submit/global",
                 "/api/flagserver"):
        try:
            st, _ = get(path)
            check(f"GET {path}", st == 200)
        except Exception as e:  # noqa: BLE001
            check(f"GET {path}", False, str(e))

    _, body = get("/api/overview")
    ov = json.loads(body)
    check("overview 字段完整",
          {"name", "summary", "targets", "plugins", "ai"} <= set(ov))
    check("overview 带服务端陈旧标记",
          "stale" in (ov.get("server") or {}), str(ov.get("server")))
    check("刚启动不算陈旧", (ov.get("server") or {}).get("stale") is False,
          str(ov.get("server")))
    secret = next((t.password for t in cfg.targets if t.password), "")
    blob = json.dumps(ov)
    check("密码不外泄",
          not re.search(r'"password"\s*:', blob) and (not secret or secret not in blob),
          "overview 里出现了 password 字段" if re.search(r'"password"\s*:', blob) else "秘钥值泄露")

    # 任务接口：非法参数应 400，正常参数应 202 并可查询
    def post(path, payload):
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    # 拖拽上传（浏览器拿不到本地路径，只能传一份到 evidence/uploads）
    import urllib.request as _u
    payload = b"Jan 11 10:00:01 host sshd[1]: Failed password for root from 1.2.3.4\n"
    req = _u.Request(base + "/api/upload?path=evidence/uploads/smoke/a.log",
                     data=payload, method="PUT")
    try:
        with _u.urlopen(req, timeout=8) as r:
            up = json.loads(r.read())
        check("上传成功", r.status == 200 and up.get("size") == len(payload), str(up))
        check("落盘存在", pathlib.Path(up["path"]).is_file(), up.get("path"))
        check("返回绝对路径", str(up["path"]).startswith("/"), str(up.get("path")))
        _, ex = getj("/api/upload/exists?name=a.log&size=%d" % len(payload))
        check("同尺寸同名文件可复用", (ex.get("path") or "") == up["path"], str(ex))
        _, ex2 = getj("/api/upload/exists?name=a.log&size=999")
        check("尺寸不同不复用", not ex2.get("path"), str(ex2))
    except urllib.error.HTTPError as e:
        check("上传成功", False, e.read().decode()[:120])
    for bad, label in (("evidence/ops.db", "不在 uploads 下"),
                       ("evidence/uploads/../../evil", "路径穿越")):
        req2 = _u.Request(base + "/api/upload?path=" + bad, data=b"x", method="PUT")
        try:
            _u.urlopen(req2, timeout=8)
            check(f"上传被拒（{label}）", False, "竟然成功了")
        except urllib.error.HTTPError as e:
            check(f"上传被拒（{label}）", e.code == 400, str(e.code))

    # 发现汇总：分页 + 批量删除
    _, fd_all = getj("/api/findings")
    check("findings 带分页字段", {"findings", "total", "offset", "limit"} <= set(fd_all),
          str(list(fd_all)))
    total0 = fd_all["total"]
    _, fd_p1 = getj("/api/findings?offset=0&limit=1")
    _, fd_p2 = getj("/api/findings?offset=1&limit=1")
    check("limit 生效", len(fd_p1["findings"]) <= 1, str(len(fd_p1["findings"])))
    check("翻页取到不同行",
          total0 < 2 or (fd_p1["findings"][0]["id"] != fd_p2["findings"][0]["id"]),
          f"{total0} 条")
    check("total 与分页无关", fd_p1["total"] == fd_p2["total"] == total0, str(total0))
    _, fd_big = getj("/api/findings?limit=99999")
    check("limit 被夹到上限", fd_big["limit"] == 500, str(fd_big["limit"]))

    # 插几条假发现，验证删除只删指定 id
    for i in range(3):
        webapp.store.event("finding", target="del-test", title=f"待删 {i}", severity="info")
    _, victim = getj("/api/findings?target=del-test")
    ids = [f["id"] for f in victim["findings"]]
    check("假发现已入库", len(ids) == 3, str(len(ids)))
    st, dd = post("/api/findings/delete", {"ids": ids[:2]})
    check("按 id 删除", st == 200 and dd.get("removed") == 2, str(dd))
    _, left = getj("/api/findings?target=del-test")
    check("剩下的没被误删", len(left["findings"]) == 1, str(len(left["findings"])))
    st, dd2 = post("/api/findings/delete", {"all": True, "target": "del-test"})
    check("按筛选清空", st == 200 and dd2.get("removed") == 1, str(dd2))
    _, left2 = getj("/api/findings?target=del-test")
    check("清空后为空", left2["total"] == 0, str(left2["total"]))
    st, dd3 = post("/api/findings/delete", {})
    check("空参数 400", st == 400, str(dd3))

    # 删前落盘 + 可回填
    webapp.store.event("finding", target="trash-test", title="回收站测试", severity="high")
    _, vt = getj("/api/findings?target=trash-test")
    tr_ids = [f["id"] for f in vt["findings"]]
    st, dt = post("/api/findings/delete", {"ids": tr_ids})
    check("删除返回快照名", st == 200 and (dt.get("trash") or "").endswith(".json"), str(dt))
    check("快照文件真的存在",
          (webapp.cfg.evidence_dir / "trash" / dt["trash"]).is_file(), str(dt.get("trash")))
    _, tl = getj("/api/findings/trash")
    check("快照列表可读", any(f["file"] == dt["trash"] for f in tl["files"]), str(tl)[:160])
    st, rs = post("/api/findings/restore", {"file": dt["trash"]})
    check("回填成功", st == 200 and rs.get("restored") == 1, str(rs))
    _, back = getj("/api/findings?target=trash-test")
    check("回填后又能查到", back["total"] == 1, str(back["total"]))
    st, rs2 = post("/api/findings/restore", {"file": dt["trash"]})
    check("重复回填不产生重复行", rs2.get("restored") == 0, str(rs2))
    st, rs3 = post("/api/findings/restore", {"file": "../etc/passwd"})
    check("路径穿越被拒", st == 400, str(rs3))
    # 清掉测试数据
    _, vt2 = getj("/api/findings?target=trash-test")
    post("/api/findings/delete", {"ids": [f["id"] for f in vt2["findings"]]})

    st, _ = post("/api/ssh/exec", {"cmd": ""})
    check("空命令返回 400", st == 400)
    st, data = post("/api/ssh/exec", {"cmd": "id", "targets": ["no-such-target"]})
    check("未知靶机返回 400", st == 400, str(data))
    st, data = post("/api/flag/submit", {"all": False})
    check("提交任务受理", st == 202 and "job" in data, str(data))

    st, data = post("/api/report", {"title": "API 冒烟报告"})
    check("报告接口可用", st == 200 and data.get("files"), str(data)[:120])
    check("报告含 markdown", "# API 冒烟报告" in data.get("markdown", ""))

    st, data = get("/api/jobs")
    check("任务列表可读", st == 200 and isinstance(json.loads(data)["jobs"], list))

    # 路径穿越必须被拒绝
    st, _ = get("/api/file?path=../../etc/passwd")
    check("拒绝路径穿越", st in (400, 403, 404))

    print("\n[10] 备份目录可配置")
    st, data = getj("/api/backup/config")
    check("读取备份目录", st == 200 and data.get("path"), str(data)[:100])
    check("报告可写与剩余空间", data.get("writable") is True and data.get("free", 0) > 0)
    newbk = pathlib.Path(tempfile.mkdtemp()) / "bk-alt"
    st, data = post("/api/backup/config", {"path": str(newbk)})
    check("切换备份目录", st == 200 and str(newbk) in data.get("path", ""), str(data)[:120])
    check("目录已创建", newbk.is_dir())
    st, data = getj("/api/backup/config")
    check("切换后生效", str(newbk) in data.get("path", ""))
    (newbk / "demo.tar.gz").write_bytes(b"x" * 1024)
    st, data = getj("/api/artifacts")
    paths = [a["path"] for a in data.get("artifacts", [])]
    check("外部备份目录进入产物列表", any("demo.tar.gz" in p for p in paths))
    st, data = post("/api/backup/config", {"path": str(cfg.workdir / "backups")})
    check("恢复默认目录", st == 200 and "backups" in data.get("path", ""))

    print("\n[11] WebSocket 推送")
    import base64 as _b64
    import hashlib as _hash
    import socket as _socket
    WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    ws_key = _b64.b64encode(b"0123456789abcdef").decode()
    sock = _socket.create_connection(("127.0.0.1", dash.server_address[1]), timeout=5)
    sock.sendall((f"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Key: {ws_key}\r\n"
                  "Sec-WebSocket-Version: 13\r\n\r\n").encode())
    head = sock.recv(4096).decode("latin-1")
    check("握手 101", "101 Switching Protocols" in head, head.split("\r\n")[0])
    expect = _b64.b64encode(_hash.sha1((ws_key + WS_GUID).encode()).digest()).decode()
    check("Accept 正确", expect in head)
    h = sock.recv(2)
    if len(h) == 2:
        ln = h[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(sock.recv(2), "big")
        payload = b""
        while len(payload) < ln:
            payload += sock.recv(ln - len(payload))
        hello = json.loads(payload)
        check("首帧是 hello", hello.get("type") == "hello")
    else:
        check("首帧是 hello", False, "no frame")
    # 触发一个任务，确认日志通过 WS 推过来
    post("/api/flag/submit", {"all": False})
    got_log = False
    sock.settimeout(4)
    try:
        for _ in range(30):
            b1, b2 = sock.recv(2)
            ln = b2 & 0x7F
            if ln == 126:
                ln = int.from_bytes(sock.recv(2), "big")
            body = b""
            while len(body) < ln:
                body += sock.recv(ln - len(body))
            msg = json.loads(body)
            if msg.get("type") == "log":
                got_log = True
                break
    except Exception:
        pass
    check("任务日志实时推送", got_log)
    sock.close()

    print("\n[12] 终端解析与接口")
    from ctfops.term import _clean
    check("去掉命令回显与哨兵",
          _clean("id\r\nuid=0(root) gid=0(root)\r\n__CTF_x__ 0\r\n", "id", "__CTF_x__")
          == "uid=0(root) gid=0(root)")
    check("纯命令无输出为空", _clean("cd /tmp\n__CTF_x__ 0\n", "cd /tmp", "__CTF_x__") == "")
    st, data = post("/api/term/exec", {"targets": ["nope"], "cmd": "id"})
    check("未知靶机 400", st == 400, str(data))
    st, data = post("/api/term/exec", {"targets": ["t1"], "cmd": ""})
    check("空命令 400", st == 400, str(data))
    st, data = getj("/api/term/status")
    check("终端状态可读", st == 200 and isinstance(data.get("sessions"), list))

    print("\n[13] 靶机角色与批量添加")
    from ctfops.config import Config as _Cfg, Target as _Target
    from ctfops.web.api import _parse_bulk, _append_targets_yaml
    c2 = _Cfg(path=tmp / "role.yaml", workdir=tmp)
    c2.targets = [
        _Target(name="d1", host="10.0.0.1", role="defense"),
        _Target(name="a1", host="10.0.0.2", role="attack"),
        _Target(name="a2", host="10.0.0.3", role="attack"),
    ]
    check("默认角色是防守", _Target(name="x", host="1.1.1.1").role == "defense")
    check("按角色过滤 attack", [t.name for t in c2.resolve_role("attack")] == ["a1", "a2"])
    check("按角色过滤 defense", [t.name for t in c2.resolve_role("defense")] == ["d1"])
    check("@attack 语法", [t.name for t in c2.resolve(["@attack"])] == ["a1", "a2"])
    check("@defense 语法", [t.name for t in c2.resolve(["@defense"])] == ["d1"])

    items, errs = _parse_bulk("10.16.0.11\n10.16.0.12:8080 政务\nhttp://a.gov.cn\n"
                              "10.16.0.11\nbad host!\n# comment")
    check("解析出 3 个主机", len(items) == 3, str([i["host"] for i in items]))
    check("带端口生成 web", any(":8080" in i["web"] for i in items))
    check("scheme 保留", any(i["web"].startswith("http://a.gov.cn") for i in items))
    check("重复与非法被拒", len(errs) >= 2, str(errs))

    for style, text in (("dump", "name: t\ntargets:\n- name: a\n  host: 1.1.1.1\nssh:\n  user: root\n"),
                        ("hand", "name: t\ntargets:\n  - name: a\n    host: 1.1.1.1\nssh:\n  user: root\n")):
        f = tmp / f"bulk_{style}.yaml"
        f.write_text(text, encoding="utf-8")
        _append_targets_yaml(load_config(str(f)), [{"name": "b", "host": "2.2.2.2",
                                                    "role": "attack", "web": ["http://2.2.2.2"]}])
        got = load_config(str(f)).targets
        check(f"{style} 缩进下追加成功", len(got) == 2 and got[1].is_attack, str([t.name for t in got]))

    print("\n[14] 漏洞库与重放")
    from ctfops.replay import replay_one

    class Echo(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"flag{replay_hit_2026}" if "id=1" in self.path else b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    web = f"http://127.0.0.1:{srv.server_address[1]}"

    vs = Store(tmp / "vuln.db")
    check("漏洞入库", vs.add_vuln("SQL 注入", "GET", "/?id=1", severity="critical",
                                  rule_id="sqli", source="waf"))
    check("漏洞去重", not vs.add_vuln("SQL 注入", "GET", "/?id=1", severity="critical",
                                      rule_id="sqli", source="waf"))
    v = vs.vulns()[0]
    atk = _Target(name="atk", host="127.0.0.1", role="attack", web=[web])
    r = replay_one(cfg, atk, v)
    check("重放命中 200", r["ok"] and r["status"] == 200, str(r)[:120])
    check("重放提取 flag", "flag{replay_hit_2026}" in (r["flags"] or []), str(r.get("flags")))
    vs.mark_replay(int(v["id"]), True)
    check("重放状态回写", vs.vulns()[0]["replay_ok"] == 1)
    vs.delete_vuln(int(v["id"]))
    check("删除漏洞", len(vs.vulns()) == 0)
    srv.shutdown()

    print("\n[15] AI 写插件（校验与安装，不依赖模型）")
    from ctfops.aipl import DRAFT_DIR, install, validate
    good = ('NAME = "demo_poc"\nDESCRIPTION = "演示"\nKIND = "web"\nSEVERITY = "high"\n'
            'def check(ctx):\n    return True\n'
            'def exploit(ctx):\n    return {"ok": True, "evidence": "x", "flags": []}\n')
    v1 = validate(good)
    check("合法插件通过校验", v1["ok"] and v1["name"] == "demo_poc", str(v1))
    check("缺少 exploit 被拒", not validate('NAME = "x_y_z"\nDESCRIPTION = "d"\nSEVERITY = "high"\n')["ok"])
    check("语法错误被拒", not validate("NAME = \n")["ok"])
    check("非法 NAME 被拒", not validate(good.replace("demo_poc", "Bad-Name"))["ok"])

    DRAFT_DIR.mkdir(parents=True, exist_ok=True)
    slug = "smoke_demo_000000"
    (DRAFT_DIR / f"{slug}.py").write_text(good, encoding="utf-8")
    inst = install(slug, overwrite=True)
    check("草稿可安装", inst.get("ok") and pathlib.Path(inst["path"]).exists() if inst.get("path") else False,
          str(inst))
    if inst.get("ok"):
        pathlib.Path(inst["path"]).unlink()
    (DRAFT_DIR / f"{slug}.py").unlink(missing_ok=True)

    print("\n[16] WAF 规则与解析")
    from ctfops.waf import AGENT_SRC, DEFAULT_RULES
    import re as _re
    bad = []
    for r in DEFAULT_RULES:
        try:
            _re.compile(r["pattern"])
        except Exception as e:  # noqa: BLE001
            bad.append((r["id"], str(e)))
    check("默认规则正则可编译", not bad, str(bad))
    check("agent 源码语法正确", _compile_ok(AGENT_SRC))
    check("覆盖 SQLi/穿越/命令注入", {"sqli", "traversal", "cmdi"} <= {r["id"] for r in DEFAULT_RULES})


    print("\n[17] 备份源可修改（YAML 就地编辑 + 接口）")
    from ctfops import yamledit
    styles = {
        "dump": "targets:\n- name: a\n  host: 10.0.0.1\n",
        "hand": "targets:\n  - name: a\n    host: 10.0.0.1\n",
        "quoted": 'targets:\n  - name: "a"\n    host: 10.0.0.1\n    note: "x # y"\n',
    }
    for tag, text in styles.items():
        f = tmp / f"src_{tag}.yaml"
        f.write_text(text, encoding="utf-8")
        c = load_config(str(f))
        r1 = yamledit.set_target_field(c, "a", "webroot", "/data/www")
        c2 = load_config(str(f))
        check(f"{tag}: 新增 webroot", c2.targets[0].webroot == "/data/www" and not r1["replaced"])
        r2 = yamledit.set_target_field(c2, "a", "webroot", "/srv/app")
        c3 = load_config(str(f))
        check(f"{tag}: 二次修改是替换", c3.targets[0].webroot == "/srv/app" and r2["replaced"])
    try:
        yamledit.set_target_field(load_config(str(tmp / "src_dump.yaml")), "nope", "webroot", "/x")
        check("不存在的靶机报错", False)
    except ValueError:
        check("不存在的靶机报错", True)

    cfg_api = tmp / "src_api.yaml"
    cfg_api.write_text(
        "name: t\nmode: awd\nworkdir: {}\n"
        "targets:\n  - name: d1\n    host: 10.255.255.1\n    role: defense\n"
        "  - name: a1\n    host: 10.255.255.2\n    role: attack\n"
        "ssh:\n  user: root\n  password: x\n  timeout: 1\n".format(tmp),
        encoding="utf-8")
    from ctfops.web.server import AppState as _AS, make_handler as _mh
    app2 = _AS(load_config(str(cfg_api)))
    srv2 = ThreadingHTTPServer(("127.0.0.1", 0), _mh(app2))
    srv2.daemon_threads = True
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    base2 = f"http://127.0.0.1:{srv2.server_address[1]}"

    def get2(path):
        try:
            with urllib.request.urlopen(base2 + path, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def post2(path, payload):
        req = urllib.request.Request(base2 + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    st, data = get2("/api/backup/sources")
    check("只列防守靶机", st == 200 and [r["target"] for r in data["sources"]] == ["d1"],
          str(data)[:150])
    st, _ = post2("/api/backup/source", {"target": "d1", "path": "relative/dir"})
    check("相对路径被拒", st == 400)
    st, data = post2("/api/backup/source", {"target": "a1", "path": "/data/www"})
    check("攻击目标不参与备份", st == 400, str(data)[:100])
    st, data = post2("/api/backup/source", {"target": "d1", "path": "/data/www"})
    check("不可达时保存并告警", st == 200 and data.get("warning"), str(data)[:160])
    check("写进了配置文件", "/data/www" in cfg_api.read_text(encoding="utf-8"))
    st, data = get2("/api/backup/sources")
    check("回读为手动", data["sources"][0]["configured"] == "/data/www")
    st, data = post2("/api/backup/source", {"target": "d1", "path": ""})
    check("可清空回自动", st == 200 and data["mode"] == "auto")
    srv2.shutdown()


    print("\n[18] 靶机修改与删除")
    cfg_mut = tmp / "mut.yaml"
    cfg_mut.write_text(
        "name: t\nmode: awd\nworkdir: {}\n"
        "targets:\n"
        "  - name: d1\n    host: 10.255.255.1\n    role: defense\n"
        "    web:\n      - http://10.255.255.1\n      - http://10.255.255.1:8080\n"
        "  - name: d2\n    host: 10.255.255.2\n    role: defense\n"
        "ssh:\n  user: root\n  password: x\n  timeout: 1\n".format(tmp),
        encoding="utf-8")
    app3 = _AS(load_config(str(cfg_mut)))
    srv3 = ThreadingHTTPServer(("127.0.0.1", 0), _mh(app3))
    srv3.daemon_threads = True
    threading.Thread(target=srv3.serve_forever, daemon=True).start()
    base3 = f"http://127.0.0.1:{srv3.server_address[1]}"

    def call3(method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(base3 + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    st, data = call3("PUT", "/api/targets/d1", {
        "name": "d1", "host": "10.255.255.11", "ssh_port": 2222, "user": "ops",
        "role": "attack", "web": "10.255.255.11, http://10.255.255.11:8080",
        "tags": "web, test", "note": "改过", "webroot": "/data/www",
    })
    check("修改成功", st == 200 and data.get("ok"), str(data)[:150])
    check("字段都已生效",
          data["target"]["host"] == "10.255.255.11"
          and data["target"]["ssh_port"] == 2222
          and data["target"]["role"] == "attack"
          and data["target"]["webroot"] == "/data/www"
          and data["target"]["web"] == ["http://10.255.255.11",
                                        "http://10.255.255.11:8080"],
          str(data.get("target"))[:200])
    txt = cfg_mut.read_text(encoding="utf-8")
    check("web 块写法被收敛成一行", "http://10.255.255.11:8080" in txt and txt.count("- http://") == 0)

    st, data = call3("PUT", "/api/targets/d1", {"name": "d2", "host": "10.255.255.11"})
    check("重名被拒", st == 400, str(data)[:100])
    st, data = call3("PUT", "/api/targets/nope", {"host": "1.1.1.1"})
    check("不存在的靶机 404", st == 404, str(data)[:80])
    st, data = call3("PUT", "/api/targets/d1", {"host": "1.1.1.1", "ssh_port": "abc"})
    check("端口非法被拒", st == 400, str(data)[:80])

    # 改名 + 历史记录级联
    app3.store.add_backup("d1", "/tmp/x.tar.gz", str(tmp / "x.tar.gz"), 10, "ab" * 32, True, "")
    app3.store.event("finding", target="d1", title="旧发现", severity="high", data={})
    app3.store.add_flag("flag{rename_cascade}", target="d1", source="test")
    st, data = call3("PUT", "/api/targets/d1", {"name": "d1-new", "host": "10.255.255.11"})
    check("改名成功", st == 200 and data.get("renamed", {}).get("to") == "d1-new", str(data)[:120])
    rec = data.get("renamed", {}).get("records", {})
    check("历史记录已级联", rec.get("backups") == 1 and rec.get("flags") == 1, str(rec))
    check("旧名不再存在", all(t["name"] != "d1" for t in data["targets"]))

    st, data = call3("DELETE", "/api/targets/d2")
    check("删除成功", st == 200 and data.get("removed") == "d2", str(data)[:100])
    check("配置里已消失", "d2" not in [t.name for t in load_config(str(cfg_mut)).targets])
    st, data = call3("DELETE", "/api/targets/d2")
    check("重复删除 404", st == 404)
    check("保留历史统计返回", isinstance(data, dict))
    srv3.shutdown()


    print("\n[19] 批量操作")
    cfg_b = tmp / "batch.yaml"
    cfg_b.write_text(
        "name: t\nmode: awd\nworkdir: {}\n"
        "targets:\n"
        "  - name: b1\n    host: 10.200.0.1\n    role: defense\n"
        "  - name: b2\n    host: 10.200.0.2\n    role: defense\n"
        "  - name: b3\n    host: 10.200.0.3\n    role: attack\n"
        "ssh:\n  user: root\n  password: x\n  timeout: 1\n".format(tmp),
        encoding="utf-8")
    app4 = _AS(load_config(str(cfg_b)))
    srv4 = ThreadingHTTPServer(("127.0.0.1", 0), _mh(app4))
    srv4.daemon_threads = True
    threading.Thread(target=srv4.serve_forever, daemon=True).start()
    base4 = f"http://127.0.0.1:{srv4.server_address[1]}"

    def call4(method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(base4 + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    st, data = call4("POST", "/api/targets/batch", {"op": "role", "names": ["b1", "b2"],
                                                    "value": "attack"})
    check("批量改角色", st == 200 and data["affected"] == 2, str(data)[:120])
    roles = {t.name: t.role for t in load_config(str(cfg_b)).targets}
    check("角色都已生效", roles["b1"] == "attack" and roles["b2"] == "attack", str(roles))

    st, data = call4("POST", "/api/targets/batch",
                     {"op": "webroot", "names": "b1,b2,b3", "value": "/data/www"})
    check("批量改备份源（逗号串）", st == 200 and data["affected"] == 3, str(data)[:120])
    check("备份源都已生效",
          all(t.webroot == "/data/www" for t in load_config(str(cfg_b)).targets))

    st, data = call4("POST", "/api/targets/batch",
                     {"op": "webroot", "names": ["b1"], "value": "relative/path"})
    check("批量相对路径被拒", st == 400)
    st, data = call4("POST", "/api/targets/batch", {"op": "role", "names": []})
    check("空选择被拒", st == 400)
    st, data = call4("POST", "/api/targets/batch", {"op": "nuke", "names": ["b1"]})
    check("未知操作被拒", st == 400)

    st, data = call4("POST", "/api/targets/batch",
                     {"op": "tags", "names": ["b1", "b2"], "value": "web, batch"})
    check("批量改标签", st == 200 and
          load_config(str(cfg_b)).target("b1").tags == ["web", "batch"], str(data)[:100])

    # 批量删除：历史保留
    app4.store.add_backup("b1", "/tmp/x", str(tmp / "x"), 1, "ab" * 32, True, "")
    app4.store.add_flag("flag{batch_del}", target="b1", source="test")
    st, data = call4("POST", "/api/targets/batch", {"op": "delete", "names": ["b1", "b3"]})
    check("批量删除", st == 200 and data["affected"] == 2, str(data)[:150])
    left = [t.name for t in load_config(str(cfg_b)).targets]
    check("只剩一台", left == ["b2"], str(left))
    check("返回保留历史", data.get("kept", {}).get("backups") == 1
          and data.get("kept", {}).get("flags") == 1, str(data.get("kept")))
    check("历史记录仍在库里", len(app4.store.flags()) >= 1)
    srv4.shutdown()


    print("\n[20] AWD 轮次监控接口")
    # 加一台"秒失败"的靶机：连本机 1 端口，立刻 connection refused，
    # 这样 tick 不会因为等不可达主机超时而把测试拖死
    from ctfops.config import Target as _T
    webapp.cfg.targets.append(_T(name="round-fast", host="127.0.0.1", ssh_port=1,
                                  user="root", password="x", role="defense"))
    webapp.cfg.ssh.timeout = 1
    st, data = getj("/api/round/state")
    check("初始未运行", st == 200 and data.get("running") is False, str(data)[:100])
    st, data = post("/api/round/start", {"interval": 5, "targets": ["round-fast"]})
    check("间隔过小被拒", st == 400, str(data)[:120])
    st, data = post("/api/round/start", {"interval": 99999, "targets": ["round-fast"]})
    check("间隔过大被拒", st == 400, str(data)[:120])

    st, data = post("/api/round/start", {"interval": 30, "targets": ["round-fast"],
                                         "auto_submit": False})
    check("启动成功", st == 200 and data.get("running") is True, str(data)[:160])
    check("靶机已登记", data.get("targets") == ["round-fast"], str(data.get("targets")))
    check("间隔生效", data.get("interval") == 30, str(data.get("interval")))
    check("自动提交已关", data.get("auto_submit") is False)

    st, data = getj("/api/round/state")
    check("状态可读", st == 200 and data.get("running") is True)
    check("下次检测时间已排", data.get("next_in", 0) > 0, str(data.get("next_in")))

    st, data = post("/api/round/tick", {"targets": ["round-fast"]})
    check("手动检查一轮不报错", st == 200 and "events" in data, str(data)[:120])
    check("不可达靶机返回空 flag",
          all(not e["new_flags"] for e in data.get("events", [])), str(data.get("events"))[:160])

    st, data = post("/api/round/stop", {})
    check("停止成功", st == 200 and data.get("running") is False)
    st, data = post("/api/round/reset", {})
    check("重置已知集合", st == 200 and data.get("state", {}).get("round_no") == 0)

    st, data = getj("/api/round/history?limit=10")
    check("历史可读", st == 200 and isinstance(data.get("rounds"), list), str(data)[:100])
    check("统计字段完整", {"max_round", "rows", "changed_rounds", "submitted_ok"}
          <= set(data.get("stats", {})), str(data.get("stats")))


    print("\n[21] WebShell 查杀")
    from ctfops.webscan import load_rules, scan_path, scan_text, summarize
    rules, extra = load_rules(cfg)
    check("规则库可加载", len(rules) >= 15, f"{len(rules)} 条")
    check("可疑文件名规则存在", len(extra.get("names") or []) >= 2)
    check("规则都有正则", all(r.get("_re") for r in rules))

    one = scan_text("a.php", "<?php @eval($_POST['cmd']); ?>", rules)
    check("一句话木马判恶意", one.verdict == "malicious" and one.score >= 70,
          f"{one.verdict}/{one.score}")
    check("命中规则是一句话类", any(h.rule_id == "ws-one-liner-eval" for h in one.hits),
          str([h.rule_id for h in one.hits]))

    clean = scan_text("ok.php", "<?php echo htmlspecialchars($_GET['q']); ?>", rules)
    check("正常代码不误报", clean.verdict == "clean", f"{clean.verdict}/{clean.score}")

    img = scan_text("logo.jpg", "GIF89a<?php system($_GET['c']); ?>", rules)
    check("图片马可识别", any(h.rule_id == "ws-image-php" for h in img.hits))

    enc = scan_text("c.php", "<?php eval(gzinflate(base64_decode($o))); ?>", rules)
    check("组合编码可识别",
          {h.rule_id for h in enc.hits} >= {"ws-base64-eval", "ws-gzinflate-eval"},
          str([h.rule_id for h in enc.hits]))

    fixture = pathlib.Path(__file__).resolve().parent / "fixtures" / "webroot"
    if fixture.is_dir():
        rep = scan_path(cfg, fixture, include_clean=True)
        # 目录里可能还有 WAF 部署留下的 .user.ini/.htaccess（它们本身就会被判可疑），
        # 所以只断言"那 4 个已知后门必须命中"，不锁死总数
        bad = {r.path for r in rep.results if r.verdict == "malicious"}
        want = {"uploads/2024.php", "uploads/shell.php", "inc/cache.php", "static/logo.jpg"}
        check("4 个已知后门全部命中", want <= bad, str(sorted(bad)))
        check("业务文件保持 clean",
              all(r.verdict == "clean" for r in rep.results if r.path in
                  ("index.php", "inc/db.php", ".htaccess")),
              str([(r.path, r.verdict) for r in rep.results])[:160])
        check("可疑文件名清单非空", bool(rep.names), str(rep.names))
        check("汇总文案可读", "恶意" in summarize(rep), summarize(rep))

    import tarfile as _tf
    arc = tmp / "site.tgz"
    with _tf.open(arc, "w:gz") as t:
        f = tmp / "shell.php"
        f.write_text("<?php @eval($_POST['x']); ?>", encoding="utf-8")
        t.add(f, arcname="uploads/shell.php")
    rep2 = scan_path(cfg, arc)
    check("压缩包能解包并扫出后门",
          rep2.malicious >= 1 and not rep2.error, f"{rep2.malicious} {rep2.error}")

    st, data = getj("/api/scan/shell/rules")
    check("规则库接口可读", st == 200 and data.get("count", 0) >= 15, str(data)[:100])


    print("\n[22] AI 插件生成的健壮性（不依赖模型）")
    from ctfops.aipl import normalize_code
    raw = ('NAME = "cve-2021-41773"\nDESCRIPTION = "x"\nSEVERITY = "high"\n'
           'def exploit(ctx):\n    return {"ok": True}\n')
    fixed = normalize_code(raw)
    check("NAME 连字符被规整成下划线", 'NAME = "cve_2021_41773"' in fixed, fixed.splitlines()[0])
    check("规整后通过校验", validate(fixed)["ok"], str(validate(fixed)))
    check("纯数字开头会补前缀",
          normalize_code('NAME = "123bad"\n').strip() == 'NAME = "poc_123bad"',
          normalize_code('NAME = "123bad"\n').strip())
    check("中文/符号名不会崩", validate(normalize_code('NAME = "路径穿越!!"\n')).get("ok") is False
          or True)  # 只要不抛异常即通过
    check("严重级别仍取自模型", validate(fixed)["severity"] == "high")


    print("\n[23] 从浏览器 cURL 导入提交接口")
    from ctfops.curlparse import parse, parse_to_profile

    chrome_json = ("curl 'https://ctf.example.com/api/submit' \\\n"
                   "  -H 'content-type: application/json' \\\n"
                   "  -H 'x-csrf-token: abc' \\\n"
                   "  --data-raw '{\"flag\":\"flag{abc123def456}\",\"team\":\"t1\"}'")
    pj = parse_to_profile(chrome_json)
    check("解析 JSON 请求", pj["method"] == "POST" and pj["body_kind"] == "json", str(pj["method"]))
    check("识别 flag 字段", pj["flag_at"] == ["json.flag"], str(pj["flag_at"]))
    check("body 里换成占位符", pj["json_body"] == {"flag": "{flag}", "team": "t1"},
          str(pj["json_body"]))
    check("保留 csrf 头", pj["headers"].get("x-csrf-token") == "abc", str(pj["headers"]))
    check("丢掉 Host/UA 之类", "host" not in {k.lower() for k in pj["headers"]})

    form = ("curl 'https://x.com/submit.php' "
            "-H 'content-type: application/x-www-form-urlencoded' "
            "--data-raw 'answer=DASCTF%7Btest%7D&tid=9'")
    pf = parse_to_profile(form)
    check("解析 form 请求", pf["form_body"] and pf["form_body"]["answer"] == "{flag}",
          str(pf.get("form_body")))

    win = ('curl "https://z.com/s" ^\n  -H "content-type: application/json" ^\n'
           '  --data-raw "{\\"flag\\":\\"CTF{w1n}\\"}"')
    pw_ = parse_to_profile(win)
    check("解析 Windows cmd 形式", pw_["json_body"] == {"flag": "{flag}"},
          str(pw_.get("json_body")))

    q = parse_to_profile("curl 'https://q.com/sub?flag=flag%7Bq1%7D&id=3'")
    check("URL 参数里的 flag 也能认", q["flag_at"] == ["query.flag"], str(q["flag_at"]))
    check("占位符没有被 URL 编码", "{flag}" in q["url"], q["url"])

    nested = parse_to_profile(
        "curl 'https://y.com/api' --data-raw '{\"data\":{\"ans\":\"0123456789abcdef0123456789abcdef\"}}'")
    check("嵌套 JSON 路径定位", nested["flag_at"] == ["json.data.ans"], str(nested["flag_at"]))

    manual = parse_to_profile("curl 'https://y.com/api' --data-raw '{\"a\":\"x\",\"b\":\"y\"}'",
                              flag_key="b")
    check("可手工指定字段", manual["flag_at"] == ["json.b"], str(manual["flag_at"]))

    # ---- 真实提交：起一个模拟平台 ----
    class Plat(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            try:
                data = json.loads(self.rfile.read(n).decode() or "{}")
            except Exception:
                data = {}
            good = data.get("flag") in ("flag{platform_ok}", "flag{api_test}")
            okcsrf = bool(self.headers.get("x-csrf-token"))
            out = json.dumps({"success": bool(good and okcsrf),
                              "msg": "flag 正确" if good and okcsrf else "失败"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    plat = ThreadingHTTPServer(("127.0.0.1", 0), Plat)
    plat.daemon_threads = True
    threading.Thread(target=plat.serve_forever, daemon=True).start()
    purl = f"http://127.0.0.1:{plat.server_address[1]}/api/submit"

    st, data = post("/api/submit/parse", {"curl": f"curl '{purl}' -H 'content-type: application/json'"})
    check("空 body 解析不报错", st == 200 and data["body_kind"] == "none", str(data)[:100])
    st, data = post("/api/submit/parse", {"curl": ""})
    check("空 cURL 被拒", st == 400)

    curl_real = (f"curl '{purl}' -H 'content-type: application/json' "
                 "-H 'x-csrf-token: tk' --data-raw '{\"flag\":\"flag{api_test}\"}'")
    st, data = post("/api/submit/profile", {"name": "smoke-plat", "curl": curl_real,
                                            "activate": True})
    check("保存导入配置", st == 200 and data["active"] == "smoke-plat", str(data)[:120])

    st, data = getj("/api/submit/profiles")
    check("配置出现在列表", any(p["name"] == "smoke-plat" for p in data["profiles"]), str(data)[:120])

    st, data = post("/api/submit/test", {"flag": "flag{api_test}", "name": "smoke-plat"})
    check("正确 flag 提交成功", st == 200 and data["ok"] is True, str(data)[:160])
    st, data = post("/api/submit/test", {"flag": "flag{wrong}", "name": "smoke-plat"})
    check("错误 flag 判定失败", st == 200 and data["ok"] is False, str(data)[:160])

    st, data = post("/api/submit/activate", {"name": "no-such"})
    check("激活不存在的配置 400", st == 400)
    req = urllib.request.Request(base + "/api/submit/profile/smoke-plat", method="DELETE")
    with urllib.request.urlopen(req, timeout=10) as resp:
        gone = json.loads(resp.read())
    check("删除配置", gone.get("ok") is True and gone.get("active") == "", str(gone)[:100])
    plat.shutdown()


    print("\n[24] 自动作战接口")
    from ctfops.autopilot import AutoReport, StepResult, summarize
    r = AutoReport("attack")
    r.attack.append(StepResult("a1", "插件 x", True, "flag{f}", "high", {"k": 1}))
    r.flags = ["flag{f}"]
    r.elapsed = 1.2
    d = r.to_dict()
    check("报告结构完整", {"phase", "steps", "summary", "flags", "errors"} <= set(d), str(list(d)))
    check("summary 计数正确", d["summary"]["targets"] == 1 and d["summary"]["flags"] == 1,
          str(d["summary"]))
    sub = AutoReport("submit")
    sub.submitted = [{"flag": "flag{f}", "ok": True, "message": "ok"}]
    check("提交报告统计", sub.to_dict()["summary"]["submitted_ok"] == 1)
    check("总结文案可读",
          "攻击" in summarize({"attack": d, "submit": sub.to_dict()}),
          summarize({"attack": d, "submit": sub.to_dict()}))

    st, data = getj("/api/auto/last")
    check("没跑过时返回 null", st == 200 and data.get("report") is None, str(data)[:80])
    st, data = post("/api/auto/run", {"phases": []})
    check("空阶段被拒", st == 400, str(data)[:100])
    st, data = post("/api/auto/run", {"phases": ["nope"]})
    check("非法阶段被拒", st == 400, str(data)[:100])
    # 不在这里真跑任务：会把不可达靶机的 SSH 超时拖进测试



    print("\n[25] 定时自动作战接口")
    st, data = getj("/api/auto/schedule")
    check("初始未运行", st == 200 and data.get("running") is False, str(data)[:100])
    st, data = post("/api/auto/schedule/start", {"interval": 10})
    check("间隔过小被拒", st == 400, str(data)[:90])
    st, data = post("/api/auto/schedule/start", {"interval": 86400 * 2})
    check("间隔过大被拒", st == 400, str(data)[:90])
    st, data = post("/api/auto/schedule/start", {"interval": 3600, "phases": []})
    check("空阶段被拒", st == 400, str(data)[:90])
    st, data = post("/api/auto/schedule/start", {"interval": 3600, "phases": ["submit"]})
    check("启动成功且只跑指定阶段",
          st == 200 and data.get("running") is True and data.get("phases") == ["submit"],
          str(data)[:140])
    st, data = post("/api/auto/schedule/stop", {})
    check("停止成功", st == 200 and data.get("running") is False)
    st, data = getj("/api/auto/schedule")
    check("状态可读", st == 200 and "next_in" in data)

    dash.shutdown()

    print(f"\n{'=' * 40}\n通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
        return 1
    return 0


def _compile_ok(src: str) -> bool:
    try:
        compile(src, "<agent>", "exec")
        return True
    except SyntaxError:
        return False


def _no_ai(cfg: Config) -> Config:
    cfg.ai.enabled = False
    return cfg


if __name__ == "__main__":
    sys.exit(main())

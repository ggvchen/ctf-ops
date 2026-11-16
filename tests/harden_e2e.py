"""漏洞修补与封禁后端自测。

    ./.venv/bin/python tests/harden_e2e.py

两块内容：
1. 规则引擎（纯函数）：同样的发现，在有/无 .htaccess 权限时应该给出不同方案；
   改系统/服务的动作必须标"需人工 + 需 root"，不能自动动。
2. 封禁后端：普通用户动不了 iptables 时，要能退到 PHP 传感器（bans.txt），
   并且解封只清自己写的那份，不碰宿主防火墙。
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import paramiko  # noqa: E402

from ctfops import harden as H                      # noqa: E402
from ctfops import waf as W                         # noqa: E402
from ctfops.config import Config, Target            # noqa: E402
from ctfops.store import Store                      # noqa: E402

PASS, FAIL = 0, []
USER, PWD = "test", "test"


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


FINDINGS = [
    {"title": "敏感目标访问 @ 1.2.3.4（225 次）", "location": "/.git/config",
     "severity": "medium"},
    {"title": "上传点访问 @ 1.2.3.4", "location": "/uploads/shell.php", "severity": "high"},
    {"title": "目录扫描特征（404×1200）", "location": "", "severity": "medium"},
    {"title": "WAF 命中: SQL 注入", "detail": "union select", "severity": "critical"},
]


# ------------------------------------------------------------------ mock sshd
class StubSFTP(paramiko.SFTPServerInterface):
    """最小 SFTP：写文件 / 读文件 / chmod 就够了（write_file 走的是这条）。"""

    def _h(self, flags, fh):
        h = paramiko.SFTPHandle(flags)
        if flags & (os.O_WRONLY | os.O_RDWR):
            h.writefile = fh
        else:
            h.readfile = fh
        return h

    def open(self, path, flags, attr):
        try:
            mode = "wb" if flags & (os.O_WRONLY | os.O_RDWR) else "rb"
            return self._h(flags, open(path, mode))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chmod(self, path, mode):
        try:
            os.chmod(path, mode)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    # paramiko 服务端把 CMD_SETSTAT 派给 chattr（不是 setstat）；
    # 不实现 chattr 的话 sftp.chmod 会报 Operation unsupported
    def chattr(self, path, attr):
        return self.setstat(path, attr)

    def setstat(self, path, attr):
        try:
            if attr.st_mode is not None:
                os.chmod(path, attr.st_mode)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        return self.stat(path)

    def remove(self, path):
        try:
            os.remove(path)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def mkdir(self, path, attr):
        try:
            os.mkdir(path)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


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
            cp = subprocess.run(cmd, shell=True, capture_output=True, timeout=60)
            if cp.stdout:
                channel.sendall(cp.stdout)
            if cp.stderr:
                channel.sendall_stderr(cp.stderr)
            channel.send_exit_status(cp.returncode)
        finally:
            channel.close()


def start_sshd(port: int) -> socket.socket:
    key = paramiko.RSAKey.generate(2048)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(10)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn, key), daemon=True).start()

    def handle(conn, host_key):
        try:
            tr = paramiko.Transport(conn)
            tr.add_server_key(host_key)
            tr.set_subsystem_handler("sftp", paramiko.SFTPServer, StubSFTP)
            tr.start_server(server=MockSSH())
            while tr.is_active():
                time.sleep(0.1)
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=loop, daemon=True).start()
    return srv


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ctfops-harden-"))
    cfg = Config(path=tmp / "config.yaml", workdir=tmp)
    cfg.workdir = tmp
    cfg.ensure_dirs()
    store = Store(cfg.db_path)

    print("\n[1] 规则引擎：有 .htaccess 权限（Apache + AllowOverride All）")
    caps_apache = {"uid": 33, "root": False, "sudo": False, "web_server": "apache2",
                   "webroot": "/var/www/html", "webroot_writable": True,
                   "allow_override": True}
    acts = H.plan_for_target("web-01", FINDINGS, caps_apache)
    ids = [a.id for a in acts]
    check("生成 4 个动作", len(acts) == 4, str(ids))
    check("敏感文件拒绝", any("deny_sensitive" in i for i in ids), str(ids))
    check("上传目录禁执行", any("block_upload_exec" in i for i in ids), str(ids))
    check("WAF 加固", any("waf_enforce" in i for i in ids), str(ids))
    sane = [a for a in acts if "waf_enforce" not in a.id]
    check("文件类都可自动执行", all(a.auto and not a.needs_root for a in sane),
          str([(a.id, a.auto, a.needs_root) for a in sane]))
    check("动作写的是站点目录内的文件",
          all(p.startswith("/var/www/html") for a in sane for p, _ in a.files),
          str([p for a in sane for p, _ in a.files]))
    check("上传片段禁 PHP 执行",
          any("Require all denied" in c for a in acts for p, c in a.files
              if "uploads" in p))

    print("\n[2] 规则引擎：没有 htaccess 权限（nginx / 普通用户）")
    acts2 = H.plan_for_target("web-01", FINDINGS,
                              {"uid": 1000, "web_server": "nginx", "webroot": "/srv/www"})
    no_root = [a for a in acts2 if "waf_enforce" not in a.id]
    check("文件类全部转人工", all(not a.auto for a in no_root), str([a.id for a in no_root]))
    check("标注需要 root", all(a.needs_root for a in no_root), str([a.id for a in no_root]))
    check("给出 nginx 片段", any("deny all" in (a.evidence or "") for a in no_root),
          str([a.evidence for a in no_root])[:200])
    check("WAF 加固仍然可以自动", any(a.auto for a in acts2 if "waf_enforce" in a.id))

    print("\n[3] 危险动作必须人工确认")
    risky = H.plan_for_target("db-01", [
        {"title": "Redis 未授权访问", "detail": "redis 6379 无密码", "severity": "critical"},
        {"title": "SSH 爆破 45.13.22.101", "detail": "Failed password ×200"},
        {"title": "nuclei: CVE-2021-41773 Apache 穿越", "severity": "high"},
    ], {"uid": 0, "root": True, "webroot": "/var/www/html"})
    by = {a.id.split("@")[0]: a for a in risky}
    check("redis 动作存在", "redis_auth" in by, str(list(by)))
    check("redis 不自动执行", by["redis_auth"].auto is False)
    check("redis 标需 root", by["redis_auth"].needs_root is True)
    check("SSH 收紧不自动执行", by["ssh_hardening"].auto is False, str(by.keys()))
    check("CVE 走升级路线", "patch_component" in by, str(list(by)))
    check("升级带 CVE 编号", "CVE-2021-41773" in (by["patch_component"].title
                                                 + by["patch_component"].evidence),
          by["patch_component"].title)
    check("升级不自动执行", by["patch_component"].auto is False)

    print("\n[4] 方案落盘")
    md = H.write_plan_md(cfg, acts + risky)
    text = pathlib.Path(md).read_text(encoding="utf-8")
    check("生成 md", pathlib.Path(md).is_file())
    check("含片段代码块", "```apache" in text or "```bash" in text)
    check("含回滚说明或命令", "回滚" in text or "sshd_config" in text)

    print("\n[5] 封禁后端优先级 / IP 清洗")
    check("root 有 iptables → iptables",
          W.BanCaps(uid=0, root=True, iptables=True).best() == "iptables")
    check("普通用户 + PHP 传感器 → php403",
          W.BanCaps(uid=33, php_agent=True, iptables=True).best() == "php403")
    check("只有 Apache 可写 → htaccess",
          W.BanCaps(uid=33, allow_override=True, webroot_writable=True,
                    webroot="/var/www").best() == "htaccess")
    check("什么都没有 → 空（只能拦 payload）",
          W.BanCaps(uid=33).best() == "")
    check("非法 IP 被过滤", W._norm_ips(["1.2.3.4", "abc", "127.0.0.1", "::1"]) == ["1.2.3.4"],
          str(W._norm_ips(["1.2.3.4", "abc", "127.0.0.1", "::1"])))

    print("\n[6] 无 root 封禁：走 PHP 传感器（真跑一次 mock sshd）")
    ssh_port = free_port()
    start_sshd(ssh_port)
    time.sleep(0.5)
    t = Target(name="web-01", host="127.0.0.1", ssh_port=ssh_port, user=USER, password=PWD)
    cfg.targets = [t]
    home = pathlib.Path(W.WAF_HOME)
    created_dir = not home.exists()
    home.mkdir(parents=True, exist_ok=True)
    agent = home / "watchbird.php"
    agent.write_text("<?php // mock\n", encoding="utf-8")
    bans = home / "bans.txt"
    bans.write_text("", encoding="utf-8")

    caps = W.detect_ban_caps(cfg, t)
    check("探测到 PHP 传感器", caps.php_agent is True, str(caps.to_dict()))
    check("探测到当前不是 root", caps.root is False, str(caps.uid))
    r = W.ban(cfg, t, ["45.13.22.101", "45.13.22.102"], backend="php403")
    check("封禁成功", r.get("ok") is True, json.dumps(r, ensure_ascii=False)[:200])
    check("用的是 php403 后端", r.get("backend") == "php403", str(r.get("backend")))
    check("bans.txt 写入两条", len(bans.read_text().split()) == 2, bans.read_text())
    check("列出现在封了谁", "45.13.22.101" in W.list_bans(cfg, t).get("bans", []),
          str(W.list_bans(cfg, t)))
    r2 = W.unban(cfg, t)
    check("解封后黑名单清空", not (bans.read_text() if bans.exists() else '').strip())
    check("解封返回 ok", r2.get("ok") is True, str(r2)[:120])

    print("\n[7] 接口：没有方案时 apply 要报错而不是空跑")
    from http.server import ThreadingHTTPServer
    from ctfops.web.server import AppState, make_handler

    app = AppState(cfg)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"

    def get(path):
        try:
            with urllib.request.urlopen(base + path, timeout=8) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def post(path, payload):
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    st, d = get("/api/harden/last")
    check("last 为空时返回对象", st == 200 and isinstance(d, dict), str(d))
    st, d2 = post("/api/harden/apply", {"ids": ["x"]})
    check("没方案时 apply 400", st == 400, str(d2))
    st, d3 = post("/api/waf/ban", {"target": "web-01", "ips": []})
    check("空 IP 400", st == 400, str(d3))
    st, d4 = get("/api/waf/ban/caps?target=nope")
    check("不存在的靶机 404", st == 404, str(d4))
    st, d5 = get("/api/waf/bans?target=web-01")
    check("封禁列表可查", st == 200 and "bans" in d5, str(d5)[:120])

    # 清理本机 /tmp/ctfops-waf（被测路径）
    try:
        agent.unlink()
        bans.unlink()
        if created_dir:
            home.rmdir()
    except OSError:
        pass

    print("\n" + "=" * 40)
    print(f"通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

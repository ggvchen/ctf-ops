"""终端端到端自测：起一个本地 mock sshd（paramiko 实现），跑真实 ShellSession。

    ./.venv/bin/python tests/term_e2e.py              # 只跑断言
    ./.venv/bin/python tests/term_e2e.py --serve 8900  # 顺带起控制台，用真靶机截图

用 mock 而不是真靶机，是为了让这个测试在任何机器上都能跑（CI/队友电脑）。
"""

from __future__ import annotations

import argparse
import os
import pathlib
import pty
import select
import socket
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import paramiko  # noqa: E402

from ctfops.config import Config, Target  # noqa: E402
from ctfops.term import ShellPool  # noqa: E402

HOST, PORT = "127.0.0.1", 2222
USER, PWD = "test", "test"


class MockServer(paramiko.ServerInterface):
    """每个通道起一个线程处理，支持 shell / exec / sftp 并发。"""

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == (USER, PWD) \
            else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a, **kw):
        return True

    def check_channel_window_change_request(self, *a, **kw):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self._run_shell, args=(channel,), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", "replace") if isinstance(command, bytes) else command
        threading.Thread(target=self._run_exec, args=(channel, cmd), daemon=True).start()
        return True

    def _run_exec(self, channel, cmd):
        import subprocess
        try:
            cp = subprocess.run(cmd, shell=True, capture_output=True, timeout=300)
            if cp.stdout:
                channel.sendall(cp.stdout)
            if cp.stderr:
                channel.sendall_stderr(cp.stderr)
            channel.send_exit_status(cp.returncode)
        except Exception as e:  # noqa: BLE001
            try:
                channel.sendall(f"mock sshd error: {e}\n".encode())
                channel.send_exit_status(1)
            except Exception:
                pass
        finally:
            try:
                channel.close()
            except Exception:
                pass

    def _run_shell(self, channel):
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["PS1"] = "mock$ "
            os.execv("/bin/zsh", ["zsh", "-f", "-i"])
        _relay(channel, fd)


class StubSFTPServer(paramiko.SFTPServerInterface):
    """最小可用 SFTP：直接映射到本机文件系统（测试用，不做 chroot）。"""

    def _realpath(self, path):
        return os.path.expanduser(path)

    def list_folder(self, path):
        try:
            out = []
            for fn in sorted(os.listdir(path)):
                attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(path, fn)))
                attr.filename = fn
                out.append(attr)
            return out
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        mode = 0o644
        if attr is not None and getattr(attr, "st_mode", None):
            mode = attr.st_mode & 0o777
        try:
            fd = os.open(path, flags, mode)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        except Exception:
            return paramiko.SFTP_FAILURE
        if flags & os.O_WRONLY:
            mode = "wb"
        elif flags & os.O_RDWR:
            mode = "r+b"
        else:
            mode = "rb"
        try:
            f = os.fdopen(fd, mode)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        h = paramiko.SFTPHandle(flags)
        h.filename = path
        h.readfile = f
        h.writefile = f if mode != "rb" else None
        return h

    def remove(self, path):
        try:
            os.remove(path)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rename(self, oldpath, newpath):
        try:
            os.rename(oldpath, newpath)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def mkdir(self, path, attr):
        try:
            os.mkdir(path)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rmdir(self, path):
        try:
            os.rmdir(path)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chattr(self, path, attr):
        try:
            paramiko.SFTPServer.set_file_attr(path, attr)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


def _relay(chan, fd):
    """PTY <-> SSH 通道双向搬运。"""
    while True:
        try:
            r, _, _ = select.select([chan, fd], [], [], 0.2)
        except (OSError, ValueError):
            break
        if chan in r:
            try:
                data = chan.recv(4096)
            except Exception:
                break
            if not data:
                break
            try:
                os.write(fd, data)
            except OSError:
                break
        if fd in r:
            try:
                out = os.read(fd, 4096)
            except OSError:
                break
            if not out:
                break
            try:
                chan.sendall(out)
            except Exception:
                break
    try:
        chan.close()
    except Exception:
        pass


def serve_once(stop: threading.Event):
    """接受一个连接并发起一个交互 shell。"""
    key = paramiko.RSAKey.generate(2048)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    srv.settimeout(0.5)
    while not stop.is_set():
        try:
            client, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        def handle(c):
            tr = paramiko.Transport(c)
            tr.add_server_key(key)
            try:
                tr.set_subsystem_handler("sftp", paramiko.SFTPServer, StubSFTPServer)
                tr.start_server(server=MockServer())
            except Exception:
                return
            while tr.is_active():
                time.sleep(0.2)

        threading.Thread(target=handle, args=(client,), daemon=True).start()
    srv.close()


def build_cfg(workdir: pathlib.Path, count: int = 1) -> Config:
    cfg = Config(path=workdir / "config.yaml", workdir=workdir, name="terminal-e2e")
    cfg.targets = [Target(name=f"mock-{i:02d}", host=HOST, ssh_port=PORT, user=USER,
                          password=PWD, web=[], tags=["mock"])
                   for i in range(1, max(1, count) + 1)]
    cfg.ssh.timeout = 6
    cfg.ssh.banner_timeout = 8
    cfg.ensure_dirs()
    # 落一份真实配置文件，控制台的"添加靶机"才写得上
    import yaml
    cfg.path.write_text(yaml.safe_dump({
        "name": cfg.name, "mode": "awd", "workdir": str(workdir),
        "targets": [{"name": t.name, "host": t.host, "ssh_port": t.ssh_port,
                     "user": t.user, "password": t.password,
                     "web": t.web, "role": t.role} for t in cfg.targets],
        "ssh": {"user": USER, "password": PWD, "timeout": 6},
        "ai": {"enabled": False},
        "submit": {"mode": "manual"},
    }, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", type=int, default=0, help="起控制台的端口")
    ap.add_argument("--count", type=int, default=3, help="演示用靶机数量（默认 3）")
    args = ap.parse_args()

    stop = threading.Event()
    threading.Thread(target=serve_once, args=(stop,), daemon=True).start()
    time.sleep(0.8)

    workdir = pathlib.Path(os.environ.get("TMPDIR", "/tmp")) / "ctfops-term-e2e"
    workdir.mkdir(parents=True, exist_ok=True)
    cfg = build_cfg(workdir, count=args.count if args.serve else 1)
    pool = ShellPool(cfg)
    target = cfg.targets[0]

    print("\n[1] 常驻会话")
    r = pool.run(target, "id", timeout=20)
    print("   id ->", repr(r.output[:80]), "rc=", r.rc)
    ok1 = r.ok and "uid=" in r.output

    print("\n[2] 会话状态保留（cd 后 pwd）")
    pool.run(target, "cd /tmp", timeout=15)
    r2 = pool.run(target, "pwd", timeout=15)
    print("   pwd ->", repr(r2.output.strip()))
    ok2 = r2.ok and r2.output.strip().endswith("/tmp")

    print("\n[3] 多行输出与退出码")
    r3 = pool.run(target, "sh -c 'printf \"a\\nb\\nc\\n\"; exit 3'", timeout=15)
    print("   输出行数:", len(r3.output.splitlines()), "rc=", r3.rc)
    ok3 = r3.output.count("\n") >= 2 and r3.rc == 3

    print("\n[4] 错误输入不破坏会话")
    r4 = pool.run(target, "nosuchcommand-xyz", timeout=15)
    r5 = pool.run(target, "echo alive", timeout=15)
    print("   rc=", r4.rc, "| 后续:", repr(r5.output.strip()))
    ok4 = r5.ok and "alive" in r5.output

    print("\n[5] 会话复用（同一对象）")
    s1 = pool.get(target)
    s2 = pool.get(target)
    print("   同一会话:", s1 is s2)
    ok5 = s1 is s2

    print("\n[6] 断开与重连")
    pool.reset("mock-01")
    r6 = pool.run(target, "echo reconnected", timeout=20)
    print("   重连后:", repr(r6.output.strip()))
    ok6 = r6.ok and "reconnected" in r6.output

    checks = [("常驻会话可用", ok1), ("cwd 状态保留", ok2), ("多行输出+退出码", ok3),
              ("错误后会话存活", ok4), ("会话复用", ok5), ("断开可重连", ok6)]
    print()
    for name, cond in checks:
        print(("  ✓ " if cond else "  ✗ ") + name)
    bad = [n for n, c in checks if not c]

    if args.serve:
        from ctfops.web.server import serve
        print(f"\n控制台（mock 靶机已接入）：http://127.0.0.1:{args.serve}")
        serve(cfg, port=args.serve, open_browser=False)
        return 0

    print(f"\n通过 {len(checks) - len(bad)}/{len(checks)}")
    stop.set()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

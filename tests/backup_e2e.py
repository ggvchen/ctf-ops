"""备份端到端自测：可配置备份源 + 真实打包 + 回传校验。

    ./.venv/bin/python tests/backup_e2e.py

复用 tests/term_e2e.py 的 mock sshd（支持 exec + SFTP），
因此不需要真靶机也能验证"指定任意源目录 → 打包 → 拉回 → sha256"。
"""

from __future__ import annotations

import pathlib
import sys
import tarfile
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import term_e2e as mock  # noqa: E402

from ctfops.backup import backup_target, detect_webroot  # noqa: E402
from ctfops.util import sha256_file  # noqa: E402

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


def make_site(root: pathlib.Path, tag: str) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.php").write_text(f"<?php echo '{tag}';", encoding="utf-8")
    (root / "config").mkdir(exist_ok=True)
    (root / "config" / "db.php").write_text(f"// {tag} db config", encoding="utf-8")
    (root / "static").mkdir(exist_ok=True)
    (root / "static" / "app.js").write_text("console.log(1)", encoding="utf-8")
    return root


def main() -> int:
    stop = threading.Event()
    threading.Thread(target=mock.serve_once, args=(stop,), daemon=True).start()
    time.sleep(0.8)

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="bk_"))
    cfg = mock.build_cfg(workdir, count=1)
    target = cfg.targets[0]
    dest = workdir / "backups"

    site_a = make_site(pathlib.Path(tempfile.mkdtemp()) / "www", "site-a")
    site_b = make_site(pathlib.Path(tempfile.mkdtemp()) / "www", "site-b")

    print("\n[1] 未配置源时自动探测")
    auto = detect_webroot(cfg, target)
    check("探测返回字符串（本机无 nginx 时应为空）", isinstance(auto, str), repr(auto))

    print("\n[2] 指定源 A 并备份")
    r1 = backup_target(cfg, target, dest_dir=dest, tag="custom-a", with_db=False,
                       src=str(site_a))
    check("备份成功", r1.ok, r1.note)
    check("记录了打包源", r1.source == str(site_a), r1.source)
    check("产物存在且非空", pathlib.Path(r1.local_path).exists() and r1.size > 0,
          f"{r1.size}B")
    check("sha256 一致", r1.sha256 == sha256_file(r1.local_path))
    with tarfile.open(r1.local_path) as tf:
        names = tf.getnames()
    check("包含源 A 的 index.php", any(n.endswith("index.php") for n in names), str(names[:6]))
    check("包含子目录文件", any(n.endswith("db.php") for n in names), str(names[:8]))

    print("\n[3] 换一个源 B，验证源可改")
    r2 = backup_target(cfg, target, dest_dir=dest, tag="custom-b", with_db=False,
                       src=str(site_b))
    check("第二次备份成功", r2.ok, r2.note)
    check("源已切换", r2.source == str(site_b), r2.source)
    with tarfile.open(r2.local_path) as tf:
        # 注意排除 macOS 的 ._ 资源分叉文件
        member = next(n for n in tf.getnames()
                      if n.endswith("/index.php") or n == "index.php")
        f = tf.extractfile(member)
        body = f.read().decode("utf-8", "replace") if f else ""
    check("内容来自源 B", "site-b" in body, body[:60])

    print("\n[4] 配置里的 webroot 生效（不传 src）")
    target.webroot = str(site_a)
    r3 = backup_target(cfg, target, dest_dir=dest, tag="from-config", with_db=False)
    check("用配置里的源", r3.ok and r3.source == str(site_a), r3.source)

    print("\n[5] 源不存在时报错而不是打包空包")
    r4 = backup_target(cfg, target, dest_dir=dest, tag="bad", with_db=False,
                       src="/no/such/dir/xyz")
    check("失败被识别", not r4.ok, r4.note)
    check("报错说明源不存在", "不存在" in (r4.note or ""), r4.note)

    print(f"\n{'=' * 40}\n通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
    stop.set()
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

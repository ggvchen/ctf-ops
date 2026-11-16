"""命令行入口：ops <子命令>。

一条命令可复跑是硬要求 —— 所有子命令都幂等、都有 --json 便于二次处理。
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from typing import List, Optional

import typer
from rich import box
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from .config import PROJECT_ROOT, Config, load_config
from .util import (console, die, err_console, human_size, info, jdump, mask_secret, ok,
                   trunc, warn)

app = typer.Typer(
    name="ops",
    help="CTF / AWD 作战辅助系统 —— SSH 运维、备份、扫描、批量利用、自动交 flag、日志与流量分析、步骤取证。",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

_STATE: dict = {"cfg_path": None, "cfg": None}


def cfg_opt() -> str:
    return _STATE.get("cfg_path") or str(PROJECT_ROOT / "config" / "config.yaml")


def get_cfg() -> Config:
    if _STATE["cfg"] is None:
        try:
            cfg = load_config(_STATE.get("cfg_path"))
        except FileNotFoundError as e:
            die(str(e))
        cfg.ensure_dirs()
        _STATE["cfg"] = cfg
    return _STATE["cfg"]


def get_store():
    from .store import Store
    return Store(get_cfg().db_path)


def _targets(names: List[str]):
    cfg = get_cfg()
    try:
        return cfg, cfg.resolve(names or ["all"])
    except KeyError as e:
        die(str(e))
        raise


def _json_flag(data) -> None:
    console.print_json(json.dumps(data, ensure_ascii=False, default=str))


@app.callback()
def main(config: Optional[str] = typer.Option(
        None, "--config", "-c", help="配置文件路径，默认 config/config.yaml")):
    """全局参数。"""
    _STATE["cfg_path"] = config


# --------------------------------------------------------------------- init
@app.command()
def init(force: bool = typer.Option(False, "--force", help="覆盖已存在的配置")):
    """初始化工作目录与配置文件。"""
    cfg_dir = PROJECT_ROOT / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    for name in ("config.example.yaml", "targets.example.yaml"):
        src = cfg_dir / name
        dst = cfg_dir / name.replace(".example", "")
        if not src.exists():
            continue
        if dst.exists() and not force:
            warn(f"{dst.name} 已存在，跳过（--force 覆盖）")
            continue
        shutil.copy(src, dst)
        ok(f"生成 {dst.relative_to(PROJECT_ROOT)}")
    for d in ("evidence/shots", "backups", "report", "logs", "outbox", "config"):
        (PROJECT_ROOT / d).mkdir(parents=True, exist_ok=True)
    try:
        cfg = load_config(_STATE.get("cfg_path"))
        cfg.ensure_dirs()
        info(f"识别到 {len(cfg.targets)} 台靶机，DB: {cfg.db_path}")
    except Exception as e:  # noqa: BLE001
        warn(f"配置校验未通过: {e}")
    ok("初始化完成，编辑 config/config.yaml 填写靶机与账号后执行 ops doctor")


# ------------------------------------------------------------------- doctor
@app.command()
def doctor():
    """环境自检：工具链 / 依赖 / 靶机连通性 / AI 端点 / 提交配置。"""
    import importlib

    t = Table(title="环境自检", box=box.SIMPLE_HEAD)
    t.add_column("项目", style="cyan")
    t.add_column("状态")
    t.add_column("说明", overflow="fold")

    def row(name: str, good: bool, detail: str = "", hard: bool = True) -> None:
        mark = "[green]OK[/green]" if good else ("[red]缺失[/red]" if hard else "[yellow]可选[/yellow]")
        t.add_row(name, mark, detail)

    row("Python", sys.version_info >= (3, 10), sys.version.split()[0])
    for mod in ("paramiko", "requests", "typer", "rich", "yaml"):
        try:
            importlib.import_module(mod)
            row(f"依赖 {mod}", True)
        except Exception:
            row(f"依赖 {mod}", False, "pip install -r requirements.txt")
    from .scan import tool_ok
    for tool, expect, tip, hard in (("nmap", "Nmap", "brew install nmap", True),
                                    ("nuclei", "nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", True),
                                    ("tshark", "TShark", "brew install wireshark", False)):
        path = shutil.which(tool) or shutil.which(tool, path="/Users/ggvchen/.local/bin")
        if not path:
            row(f"工具 {tool}", False, tip, hard)
            continue
        good, why = tool_ok(path, expect)
        row(f"工具 {tool}", good, path if good else f"{path} — {why}", hard)
    try:
        import playwright  # noqa: F401
        row("截图 playwright", True)
    except Exception:
        row("截图 playwright", False, "pip install playwright && playwright install chromium", False)

    cfg = None
    try:
        cfg = get_cfg()
        row("配置文件", True, str(cfg.path))
    except SystemExit:
        row("配置文件", False, "先执行 ops init")
    except Exception as e:  # noqa: BLE001
        row("配置文件", False, str(e))

    if cfg:
        row("靶机数量", len(cfg.targets) > 0, f"{len(cfg.targets)} 台")
        if cfg.ai.enabled:
            from .aiclient import AIClient
            ai = AIClient(cfg)
            alive = ai.available(force=True)
            row("本地 AI", alive,
                f"{cfg.ai.model} @ {cfg.ai.base_url}" if alive
                else f"端点为 {cfg.ai.base_url}，未响应（不影响主流程）", hard=False)
        row("FLAG 提交", bool(cfg.submit.url) or cfg.submit.mode == "manual",
            f"mode={cfg.submit.mode} {cfg.submit.url or '人工 outbox'}", hard=False)
        try:
            from .shot import check_playwright
            check_playwright()
        except Exception:
            pass
    console.print(t)

    if cfg and cfg.targets:
        info("测试 SSH 连通性 ...")
        from .sshx import batch_exec
        res = batch_exec(cfg, cfg.targets, "id; hostname", timeout=15, workers=8)
        t2 = Table(box=box.SIMPLE_HEAD)
        t2.add_column("靶机"); t2.add_column("SSH"); t2.add_column("身份")
        for r in res:
            t2.add_row(r.target,
                       "[green]通[/green]" if r.ok else "[red]失败[/red]",
                       (r.out.strip().splitlines()[0] if r.ok and r.out.strip() else
                        (r.error or "")[:60]))
        console.print(t2)


# ------------------------------------------------------------------ targets
targets_app = typer.Typer(help="靶机管理：列表 / 添加 / 修改 / 删除。",
                          invoke_without_command=True, no_args_is_help=False)
app.add_typer(targets_app, name="targets")


def _print_targets(cfg, as_json: bool = False) -> None:
    if as_json:
        _json_flag([t.__dict__ for t in cfg.targets])
        return
    t = Table(title=f"靶机清单（{len(cfg.targets)}）", box=box.SIMPLE_HEAD)
    for col in ("角色", "名称", "地址", "SSH", "认证", "Web", "备份源", "标签"):
        t.add_column(col, overflow="fold")
    for x in cfg.targets:
        t.add_row(f"[{'red' if x.is_attack else 'green'}]{x.role_label}[/]",
                  x.name, x.host, f"{x.user}:{x.ssh_port}",
                  "密钥" if x.key_file else ("口令" if x.password else "无"),
                  "\n".join(x.web) or "-", x.webroot or "自动",
                  ",".join(x.tags) or "-")
    console.print(t)


@targets_app.callback()
def targets_root(ctx: typer.Context,
                 json_out: bool = typer.Option(False, "--json", help="输出 JSON")):
    """不带子命令时列出全部靶机。"""
    if ctx.invoked_subcommand is None:
        _print_targets(get_cfg(), json_out)


@targets_app.command("list")
def targets_list(json_out: bool = typer.Option(False, "--json")):
    """列出靶机。"""
    _print_targets(get_cfg(), json_out)


@targets_app.command("add")
def targets_add(
    host: str = typer.Argument(..., help="IP 或域名，可带 :port"),
    name: Optional[str] = typer.Option(None, "--name", "-n"),
    role: str = typer.Option("defense", "--role", help="defense / attack"),
    user: str = typer.Option("root", "--user", "-u"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
    ssh_port: int = typer.Option(22, "--ssh-port"),
    web: Optional[str] = typer.Option(None, "--web", help="逗号分隔的 URL"),
    webroot: Optional[str] = typer.Option(None, "--webroot", help="备份源绝对路径"),
    tags: Optional[str] = typer.Option(None, "--tags"),
    note: str = typer.Option("", "--note"),
):
    """添加一台靶机。"""
    from .web.api import _append_target_yaml
    cfg = get_cfg()
    hostname = host.split("://")[-1].split("/")[0]
    port_part = ""
    if hostname.count(":") == 1:
        hostname, port_part = hostname.split(":")
    # 同主机不同端口是合法的（一台机器挂多个站点/服务），只有
    # 主机+SSH端口+首个 web 全都一样才算重复
    new_web = [x.strip() for x in (web or "").split(",") if x.strip()] \
        or [f"http://{hostname}" + (f":{port_part}" if port_part else "")]
    dup = [t for t in cfg.targets
           if t.host == hostname and int(t.ssh_port or 22) == int(ssh_port)
           and (t.web or [])[:1] == new_web[:1]]
    if dup:
        die(f"已存在相同靶机: {dup[0].name}（{hostname}:{ssh_port} {new_web[0]}）")
    final_name = name or hostname
    if any(t.name == final_name for t in cfg.targets):
        die(f"名称已存在: {final_name}")
    item = {
        "name": final_name, "host": hostname, "ssh_port": ssh_port,
        "user": user, "password": password or "",
        "role": "attack" if role.lower() in ("attack", "atk") else "defense",
        "web": [x.strip() for x in (web or "").split(",") if x.strip()]
        or [f"http://{hostname}" + (f":{port_part}" if port_part else "")],
        "tags": [x.strip() for x in (tags or "").split(",") if x.strip()],
        "note": note,
    }
    if webroot:
        if not webroot.startswith("/"):
            die("webroot 要写远端绝对路径")
        item["webroot"] = webroot
    _append_target_yaml(cfg, item)
    ok(f"已添加 {final_name}（{item['role']}）")


@targets_app.command("edit")
def targets_edit(
    name: str = typer.Argument(...),
    new_name: Optional[str] = typer.Option(None, "--name", "-n", help="改名"),
    host: Optional[str] = typer.Option(None, "--host"),
    user: Optional[str] = typer.Option(None, "--user", "-u"),
    password: Optional[str] = typer.Option(None, "--password", "-p"),
    role: Optional[str] = typer.Option(None, "--role"),
    ssh_port: Optional[int] = typer.Option(None, "--ssh-port"),
    web: Optional[str] = typer.Option(None, "--web"),
    webroot: Optional[str] = typer.Option(None, "--webroot"),
    tags: Optional[str] = typer.Option(None, "--tags"),
    note: Optional[str] = typer.Option(None, "--note"),
    clear_credentials: bool = typer.Option(False, "--clear-credentials", help="删除口令与密钥"),
):
    """修改靶机字段（只改你传了的）。"""
    from . import yamledit
    cfg = get_cfg()
    try:
        cfg.target(name)
    except KeyError as e:
        die(str(e))
    changes = {}
    if new_name:
        if any(t.name == new_name for t in cfg.targets):
            die(f"名称已存在: {new_name}")
        changes["name"] = new_name
    for key, val in (("host", host), ("user", user), ("password", password),
                     ("ssh_port", ssh_port), ("note", note)):
        if val is not None:
            changes[key] = val
    if role:
        changes["role"] = "attack" if role.lower() in ("attack", "atk") else "defense"
    if web is not None:
        changes["web"] = ["http://" + x.strip() if not x.strip().startswith("http")
                          else x.strip() for x in web.split(",") if x.strip()]
    if tags is not None:
        changes["tags"] = [x.strip() for x in tags.split(",") if x.strip()]
    if webroot is not None:
        if webroot and not webroot.startswith("/"):
            die("webroot 要写远端绝对路径")
        changes["webroot"] = webroot
    if clear_credentials:
        changes["password"] = None
        changes["key_file"] = None
    if not changes:
        die("没有要修改的字段")
    yamledit.update_target(cfg, name, changes)
    cfg = get_cfg()
    if changes.get("name"):
        n = get_store().rename_target(name, changes["name"])
        ok(f"已改名 {name} -> {changes['name']}（同步 {sum(n.values())} 条历史记录）")
    else:
        ok(f"已更新 {name}")


@targets_app.command("batch")
def targets_batch_cmd(
    target: List[str] = typer.Option(..., "--target", "-t",
                                     help="靶机名 / 标签 / @attack / @defense，可多次给"),
    role: Optional[str] = typer.Option(None, "--role", help="批量改角色 defense/attack"),
    webroot: Optional[str] = typer.Option(None, "--webroot",
                                          help="批量改备份源；给空串表示恢复自动"),
    delete: bool = typer.Option(False, "--delete", help="批量删除"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """批量改角色 / 备份源，或批量删除。"""
    from . import yamledit
    cfg = get_cfg()
    # 允许 -t a,b,c 这种写法
    flat = [x.strip() for item in target for x in str(item).split(",") if x.strip()]
    ts = cfg.resolve(flat)
    names = [t.name for t in ts if t.enabled]
    if not names:
        die("没有匹配到靶机")

    actions = sum(1 for x in (role, webroot, delete) if x not in (None, False))
    if actions != 1:
        die("一次只能指定一个动作：--role / --webroot / --delete")

    file_path = yamledit.targets_path(cfg)
    before = file_path.read_text(encoding="utf-8")
    try:
        if delete:
            if not yes:
                die(f"确认删除 {len(names)} 台请加 --yes：{', '.join(names)}")
            yamledit.remove_many(cfg, names)
            ok(f"已删除 {len(names)} 台: {', '.join(names)}")
        elif role is not None:
            value = "attack" if role.lower() in ("attack", "atk") else "defense"
            r = yamledit.update_many(cfg, names, {"role": value})
            ok(f"已设 {len(r['updated'])} 台为 {value}")
        else:
            wr = (webroot or "").strip()
            if wr and not wr.startswith("/"):
                die("备份源要写远端绝对路径；传空串表示恢复自动探测")
            r = yamledit.update_many(cfg, names, {"webroot": wr})
            ok(f"已设 {len(r['updated'])} 台备份源为 {wr or '（自动探测）'}")
    except Exception as e:  # noqa: BLE001
        yamledit.restore(file_path, before)
        die(f"失败已回滚: {e}")


@targets_app.command("rm")
def targets_rm(name: str = typer.Argument(...),
               yes: bool = typer.Option(False, "--yes", "-y")):
    """删除靶机（历史记录保留）。"""
    from . import yamledit
    cfg = get_cfg()
    try:
        cfg.target(name)
    except KeyError as e:
        die(str(e))
    if not yes:
        stats = get_store().target_stats(name)
        die(f"确认删除请加 --yes（历史：{stats}）")
    yamledit.remove_target(cfg, name)
    ok(f"已删除 {name}")


# ---------------------------------------------------------------------- ssh
ssh_app = typer.Typer(help="SSH 运维：批量执行、传文件、拉日志、现场快照。", no_args_is_help=True)
app.add_typer(ssh_app, name="ssh")


@ssh_app.command("exec")
def ssh_exec(
    cmd: str = typer.Argument(..., help="要执行的命令"),
    target: List[str] = typer.Option(["all"], "--target", "-t", help="靶机名/标签/all"),
    timeout: int = typer.Option(60, "--timeout"),
    sudo: bool = typer.Option(False, "--sudo"),
    workers: int = typer.Option(8, "--workers"),
    json_out: bool = typer.Option(False, "--json"),
):
    """在靶机批量执行命令。"""
    from .sshx import batch_exec, print_results
    cfg, ts = _targets(target)
    res = batch_exec(cfg, ts, cmd, timeout=timeout, sudo=sudo, workers=workers)
    store = get_store()
    for r in res:
        store.event("action", target=r.target, title="ssh exec",
                    data={"cmd": cmd, "rc": r.rc, "out": trunc(r.text, 2000), "error": r.error})
    if json_out:
        _json_flag([r.__dict__ for r in res])
    else:
        print_results(res)


@ssh_app.command("upload")
def ssh_upload(
    local: str = typer.Argument(...),
    remote: str = typer.Argument(...),
    target: List[str] = typer.Option(["all"], "--target", "-t"),
):
    """上传本地文件到靶机。"""
    from .sshx import SSHSession
    cfg, ts = _targets(target)
    for t in ts:
        with SSHSession(t, cfg) as s:
            good = s.upload(local, remote)
            (ok if good else warn)(f"{t.name}: {local} -> {remote}")


@ssh_app.command("download")
def ssh_download(
    remote: str = typer.Argument(...),
    local: Optional[str] = typer.Argument(None),
    target: List[str] = typer.Option(["all"], "--target", "-t"),
):
    """从靶机下载文件（不给本地路径则存到 evidence/pulled/）。"""
    from .sshx import SSHSession
    cfg, ts = _targets(target)
    for t in ts:
        dst = local or str(cfg.evidence_dir / "pulled" / t.name / os.path.basename(remote))
        with SSHSession(t, cfg) as s:
            good = s.download(remote, dst)
            (ok if good else warn)(f"{t.name}: {remote} -> {dst}")


@ssh_app.command("snapshot")
def ssh_snapshot(target: List[str] = typer.Option(["all"], "--target", "-t")):
    """现场取证快照：进程/网络/账号/持久化/最近登录。"""
    from .sshx import SSHSession
    cfg, ts = _targets(target)
    outdir = cfg.evidence_dir / "snapshot"
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = (
        "echo '### hostname'; hostname; date;"
        "echo '### ps'; ps auxww 2>/dev/null | head -150;"
        "echo '### net'; (ss -antp || netstat -antp) 2>/dev/null | head -100;"
        "echo '### users'; cat /etc/passwd; echo '### uid0'; awk -F: '$3==0{print $1}' /etc/passwd;"
        "echo '### sudoers'; grep -vE '^#|^$' /etc/sudoers 2>/dev/null | head -40;"
        "echo '### cron'; for f in /etc/crontab /var/spool/cron/* /etc/cron.d/*; do [ -f \"$f\" ] && echo \"--$f\" && cat \"$f\"; done 2>/dev/null;"
        "echo '### rc'; ls -la /etc/rc.local ~/.bashrc ~/.bash_profile /etc/profile.d 2>/dev/null;"
        "echo '### tmp'; ls -la /tmp /dev/shm /var/tmp 2>/dev/null;"
        "echo '### last'; last -n 30 2>/dev/null;"
        "echo '### listen'; (ss -lntp || netstat -lntp) 2>/dev/null"
    )
    for t in ts:
        with SSHSession(t, cfg) as s:
            r = s.exec(cmd, timeout=120)
            p = outdir / f"{t.name}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            p.write_text(r.text, encoding="utf-8")
            store = get_store()
            store.event("action", target=t.name, title="现场快照", data={"path": str(p)})
            ok(f"{t.name} -> {p}")


@ssh_app.command("logs")
def ssh_logs(
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    analyze: bool = typer.Option(True, "--analyze/--no-analyze", help="拉回后立即分析"),
):
    """拉取靶机日志并分析。"""
    from .logx import analyze_paths, pull_logs
    cfg, ts = _targets(target)
    store = get_store()
    for t in ts:
        info(f"拉取 {t.name} 日志 ...")
        files = pull_logs(cfg, t)
        if not files:
            warn(f"{t.name} 未拉到日志")
            continue
        if not analyze:
            continue
        rep = analyze_paths([str(cfg.evidence_dir / "logs" / t.name)], cfg, target=t.name)
        out = cfg.evidence_dir / "logs" / t.name / "analysis.md"
        out.write_text(rep.text(), encoding="utf-8")
        ok(f"{t.name} 分析完成: {out}（发现 {len(rep.findings)} 项）")
        for f in rep.findings[:10]:
            console.print(f"  [{'red' if f.severity in ('critical', 'high') else 'yellow'}]"
                          f"{f.severity}[/] {f.title} {f.detail[:80]}")
            store.event("finding", target=t.name, title=f.title, severity=f.severity,
                        data=f.to_dict())
        if rep.ai_text:
            from rich.markdown import Markdown
            console.print(Panel(Markdown(rep.ai_text), title="AI 溯源研判", border_style="cyan"))


# ------------------------------------------------------------------- backup
backup_app = typer.Typer(help="业务系统备份与回滚。", no_args_is_help=True)
app.add_typer(backup_app, name="backup")


@backup_app.command("run")
def backup_run(
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    tag: str = typer.Option("snapshot", "--tag", help="标记，如 pre-patch / baseline"),
    db: bool = typer.Option(True, "--db/--no-db", help="是否一并 mysqldump"),
    workers: int = typer.Option(4, "--workers"),
):
    """备份靶机业务系统（web 目录 + 可选数据库）。"""
    from .backup import backup_root, backup_target
    from .util import pmap
    cfg, ts = _targets(target)
    store = get_store()
    dest = backup_root(cfg, store)
    dest.mkdir(parents=True, exist_ok=True)
    console.print(f"[dim]备份目录: {dest}[/dim]")
    res = pmap(lambda t: backup_target(cfg, t, dest_dir=dest, tag=tag, with_db=db),
               ts, workers=workers)
    t = Table(title="备份结果", box=box.SIMPLE_HEAD)
    t.add_column("靶机"); t.add_column("结果"); t.add_column("大小"); t.add_column("文件/说明", overflow="fold")
    for r in res:
        if isinstance(r, Exception):
            t.add_row("?", "[red]异常[/red]", "-", str(r)[:80])
            continue
        store.add_backup(r.target, r.remote_path, r.local_path, r.size, r.sha256, r.ok, r.note)
        store.event("backup", target=r.target, title="备份",
                    data={"ok": r.ok, "path": r.local_path, "size": r.size,
                          "sha256": r.sha256, "note": r.note})
        t.add_row(r.target,
                  "[green]成功[/green]" if r.ok else "[red]失败[/red]",
                  human_size(r.size) if r.ok else "-",
                  pathlib.Path(r.local_path).name if r.ok else r.note)
    console.print(t)


@backup_app.command("list")
def backup_list():
    """查看备份记录。"""
    store = get_store()
    rows = store.backups()
    t = Table(box=box.SIMPLE_HEAD)
    for c in ("时间", "靶机", "大小", "文件", "sha256"):
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(r["ts"], r["target"], human_size(r["size"]),
                  pathlib.Path(r["local_path"]).name, r["sha256"][:16])
    console.print(t if rows else "[dim]暂无备份[/dim]")


@backup_app.command("restore")
def backup_restore(
    archive: str = typer.Argument(..., help="备份包路径"),
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    webroot: Optional[str] = typer.Option(None, "--webroot"),
    yes: bool = typer.Option(False, "--yes", "-y", help="确认覆盖远端目录"),
):
    """把备份还原回靶机（会覆盖 web 目录，谨慎）。"""
    from .backup import restore_target
    if not yes:
        die("将覆盖靶机 web 目录。确认后加 --yes 执行", 2)
    cfg, ts = _targets(target)
    for x in ts:
        r = restore_target(cfg, x, archive, webroot)
        (ok if r.ok else warn)(f"{x.name}: {r.note}")


@backup_app.command("source")
def backup_source_cmd(
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    set_path: Optional[str] = typer.Option(None, "--set", help="设为该绝对路径（远端目录）"),
    detect: bool = typer.Option(False, "--detect", help="远程探测 nginx/apache 目录"),
    reset: bool = typer.Option(False, "--reset", help="清除手动设置，恢复自动探测"),
):
    """查看 / 修改备份源目录（要打包的远端目录）。"""
    from .backup import detect_webroot
    from .yamledit import set_target_field
    cfg, ts = _targets(target)

    if set_path or reset:
        new_value = "" if reset else (set_path or "").strip()
        if new_value and not new_value.startswith("/"):
            die("请填绝对路径，例如 /www/wwwroot/site")
        names = [t.name for t in ts if not t.is_attack]
        if not names:
            die("没有可设置的防守靶机")
        for name in names:
            r = set_target_field(cfg, name, "webroot", new_value)
            ok(f"{name}: webroot = {new_value or '（自动探测）'}"
               f"{'（替换）' if r['replaced'] else '（新增）'}")
        return

    t = Table(box=box.SIMPLE_HEAD)
    for c in ("靶机", "配置的源", "探测结果"):
        t.add_column(c, overflow="fold")
    for x in ts:
        if x.is_attack:
            continue
        detected = detect_webroot(cfg, x) if detect else ""
        t.add_row(x.name, x.webroot or "（自动）", detected or ("-" if detect else "未探测"))
    console.print(t)
    if not detect:
        info("加 --detect 可远程探测实际业务目录")


@backup_app.command("local")
def backup_local_cmd(
    path: str = typer.Argument(..., help="本地源码/目录，如 AWD1/www"),
    tag: str = typer.Option("local", "--tag"),
):
    """离线备份本地目录（赛前源码留档）。"""
    from .backup import backup_local
    cfg = get_cfg()
    r = backup_local(path, cfg.backup_dir, tag)
    (ok if r.ok else warn)(f"{r.note} {r.local_path} {human_size(r.size)}")


# --------------------------------------------------------------------- scan
scan_app = typer.Typer(help="扫描：端口 / Web 指纹 / 漏洞模板。", no_args_is_help=True)
app.add_typer(scan_app, name="scan")


def _save_findings(cfg, store, findings, kind: str = "scan") -> None:
    for f in findings:
        store.event("finding", target=f.target, title=f.title,
                    severity=f.severity, data=f.to_dict())


@scan_app.command("ports")
def scan_ports(
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    ports: Optional[str] = typer.Option(None, "--ports", help="如 1-65535 或 22,80,443"),
    extra: Optional[List[str]] = typer.Option(None, "--arg", help="附加 nmap 参数"),
):
    """nmap 端口与服务识别。"""
    from .scan import nmap_scan, sort_findings
    cfg, ts = _targets(target)
    store = get_store()
    info(f"nmap 扫描 {len(ts)} 台 ...")
    result = nmap_scan(cfg, ts, ports=ports, extra=extra)
    allf = []
    t = Table(box=box.SIMPLE_HEAD)
    t.add_column("靶机"); t.add_column("端口"); t.add_column("服务", overflow="fold")
    for name, findings in result.items():
        for f in sort_findings(findings):
            allf.append(f)
            t.add_row(f.target, f.location.split(":")[-1], f"{f.title} {f.detail}".strip())
    console.print(t)
    _save_findings(cfg, store, allf, "port")
    ok(f"入库 {len(allf)} 条端口记录")


@scan_app.command("web")
def scan_web(target: List[str] = typer.Option(["all"], "--target", "-t"),
             workers: int = typer.Option(6, "--workers")):
    """Web 指纹 + 敏感路径探测。"""
    from .scan import sort_findings, web_probe
    from .util import pmap
    cfg, ts = _targets(target)
    store = get_store()
    allf = []
    for f in pmap(lambda x: web_probe(cfg, x), ts, workers=workers):
        if isinstance(f, Exception):
            warn(str(f))
            continue
        allf.extend(f)
    t = Table(box=box.SIMPLE_HEAD)
    t.add_column("靶机"); t.add_column("严重度"); t.add_column("发现", overflow="fold"); t.add_column("位置", overflow="fold")
    for f in sort_findings(allf):
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "dim")
        t.add_row(f.target, f"[{color}]{f.severity}[/{color}]", f.title, f.location)
    console.print(t)
    _save_findings(cfg, store, allf, "web")
    # 探测过程中命中 /flag 之类的直接入账
    from .flag import extract_flags
    new_flags = 0
    for f in allf:
        for fl in extract_flags(f"{f.evidence}\n{f.detail}", cfg):
            if store.add_flag(fl, target=f.target, source="web-probe"):
                new_flags += 1
                console.print(f"[green]+ FLAG[/green] {f.target} {fl}")
    ok(f"入库 {len(allf)} 条 Web 发现" + (f"，捕获 {new_flags} 个 flag" if new_flags else ""))


@scan_app.command("vulns")
def scan_vulns(
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    severity: Optional[str] = typer.Option(None, "--severity"),
    templates: Optional[str] = typer.Option(None, "--templates",
                                            help="模板目录/单个模板；不给就用标签收敛"),
    tags: Optional[str] = typer.Option(None, "--tags",
                                       help="模板标签，如 cve,rce,sqli（默认取配置 nuclei_tags）"),
    ai: bool = typer.Option(True, "--ai/--no-ai", help="用本地模型做攻击路径排序"),
):
    """nuclei 漏洞模板扫描（默认按标签收敛，避免全量模板跑几分钟）。"""
    from .scan import nuclei_scan, sort_findings, target_map_of, urls_of
    cfg, ts = _targets(target)
    store = get_store()
    urls = urls_of(ts)
    if not urls:
        die("没有配置 web 地址")
    info(f"nuclei 扫描 {len(urls)} 个 URL ...")
    findings = sort_findings(nuclei_scan(cfg, urls, target_map_of(ts),
                                         severity=severity, templates=templates,
                                         tags=tags))
    t = Table(box=box.SIMPLE_HEAD)
    t.add_column("靶机"); t.add_column("级别"); t.add_column("漏洞", overflow="fold"); t.add_column("位置", overflow="fold")
    for f in findings:
        color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "dim")
        t.add_row(f.target, f"[{color}]{f.severity}[/{color}]", f.title, f.location)
    console.print(t if findings else "[dim]未发现匹配漏洞[/dim]")
    _save_findings(cfg, store, findings, "vuln")
    if ai and findings:
        from .aiclient import AIClient
        info("AI 正在排序攻击路径（本地模型，约 30-60 秒）...")
        _render_triage(AIClient(cfg).triage_findings([f.to_dict() for f in findings]))


@scan_app.command("shell")
def scan_shell(
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    path: Optional[str] = typer.Option(None, "--path", help="扫本地目录 / 备份包，而不是靶机"),
    max_files: int = typer.Option(20000, "--max-files"),
    quiet: bool = typer.Option(False, "--quiet", help="只打印汇总"),
):
    """WebShell 静态查杀（看文件内容，不用靶机有运行时）。

    默认从靶机 webroot 打包脚本拉回本地扫；也可以直接扫本地的备份包/源码目录。
    """
    from .webscan import scan_path, scan_remote, summarize

    cfg = get_cfg()
    store = get_store()
    reps = []

    if path:
        local = pathlib.Path(path).expanduser()
        if not local.is_absolute():
            local = cfg.workdir / local
        info(f"扫描 {local}")
        reps.append(("local", scan_path(cfg, local, max_files=max_files)))
    else:
        _, ts = _targets(target)
        for t in ts:
            if t.is_attack:
                continue
            info(f"[{t.name}] 打包脚本文件 ...")
            reps.append((t.name, scan_remote(cfg, t, max_files=max_files)))

    total_bad = 0
    for name, rep in reps:
        if rep.error:
            warn(f"{name}: {rep.error}")
            continue
        console.print(f"[bold]{name}[/bold] · {summarize(rep)}")
        if quiet:
            continue
        rows = [r for r in rep.results if r.verdict != "clean"]
        if not rows:
            continue
        # 判定/分数并进文件名一列：窄终端下 Rich 会直接丢掉挤不下的列
        tbl = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False)
        tbl.add_column("文件 / 得分", width=36, overflow="fold")
        tbl.add_column("命中规则", overflow="fold")
        for r in rows[:25]:
            tag = "[red]恶意[/red]" if r.verdict == "malicious" else "[yellow]可疑[/yellow]"
            line = r.hits[0].line if r.hits else 0
            tbl.add_row(
                f"{tag} [bold]{r.score}[/bold]  {r.path}" + (f":{line}" if line else ""),
                "\n".join(f"{h.name}(+{h.score})" for h in r.hits[:3]))
        console.print(tbl)
        if rep.names:
            info("可疑文件名: " + ", ".join(rep.names[:10]))
        total_bad += len(rows)

    # 入库，报告里能看到
    for name, rep in reps:
        for f in rep.findings(name, "shell"):
            store.event("finding", target=f.target, title=f.title,
                        severity=f.severity,
                        data={**f.to_dict(), "source": "shellscan"})

    if total_bad:
        warn(f"共 {total_bad} 个文件可疑/恶意，逐个看过再决定是否删除")
    else:
        ok("未发现后门特征")


@scan_app.command("all")
def scan_all(
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    ai: bool = typer.Option(True, "--ai/--no-ai"),
):
    """端口 + Web + 漏洞一条龙。"""
    scan_ports(target=target, ports=None, extra=None)
    scan_web(target=target, workers=6)
    scan_vulns(target=target, severity=None, templates=None, ai=ai)


# ------------------------------------------------------------------ exploit
exp_app = typer.Typer(help="漏洞利用：插件式批量打击。", no_args_is_help=True)
app.add_typer(exp_app, name="exploit")


@exp_app.command("list")
def exploit_list():
    """列出可用 PoC 插件。"""
    from .exploit import load_plugins
    plugins = load_plugins()
    t = Table(box=box.SIMPLE_HEAD)
    for c in ("名称", "类型", "级别", "说明"):
        t.add_column(c, overflow="fold")
    for p in plugins.values():
        t.add_row(p.name, p.kind, p.severity, p.description)
    console.print(t)


@exp_app.command("run")
def exploit_run(
    plugin: str = typer.Argument(..., help="插件名，或 all 全部"),
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    workers: int = typer.Option(6, "--workers"),
    dry_run: bool = typer.Option(False, "--check-only", help="只跑 check 不动手"),
    sleep: float = typer.Option(0.0, "--sleep", help="每台间隔秒数"),
    submit: bool = typer.Option(True, "--submit/--no-submit", help="拿到 flag 立即提交"),
):
    """批量执行 PoC。"""
    from .exploit import load_plugins, run_batch
    from .flag import Submitter
    cfg, ts = _targets(target)
    store = get_store()
    plugins = load_plugins()
    if plugin == "all":
        chosen = list(plugins.values())
    else:
        if plugin not in plugins:
            die(f"未找到插件 {plugin}，可用: {', '.join(plugins)}")
        chosen = [plugins[plugin]]

    total_new = 0
    for p in chosen:
        console.print(f"[bold cyan]▶ {p.name}[/bold cyan] [dim]{p.description}[/dim]")
        results = run_batch(cfg, p, ts, workers=workers, dry_run=dry_run, sleep=sleep)
        t = Table(box=box.SIMPLE_HEAD)
        for c in ("靶机", "结果", "耗时", "证据/错误"):
            t.add_column(c, overflow="fold")
        for r in results:
            t.add_row(r.target,
                      "[green]成功[/green]" if r.ok else "[red]失败[/red]",
                      f"{r.elapsed:.1f}s",
                      (r.error or r.evidence or "")[:160].replace("\n", " "))
            store.event("finding" if r.ok else "action", target=r.target,
                        title=f"exploit:{p.name}",
                        severity=p.severity if r.ok else "info",
                        data={"ok": r.ok, "evidence": trunc(r.evidence, 4000),
                              "flags": r.flags, "error": r.error})
            for fl in r.flags:
                if store.add_flag(fl, target=r.target, source=f"exploit:{p.name}"):
                    total_new += 1
                    console.print(f"  [green]+ FLAG[/green] {fl}")
        console.print(t)
    if submit and total_new:
        Submitter(cfg, store).submit_all(only_pending=True)


# ---------------------------------------------------------------------- flag
flag_app = typer.Typer(help="FLAG 收集与提交。", no_args_is_help=True)
app.add_typer(flag_app, name="flag")


@flag_app.command("hunt")
def flag_hunt(
    target: List[str] = typer.Option(["all"], "--target", "-t"),
    submit: bool = typer.Option(False, "--submit", help="发现后立即提交"),
    local: Optional[List[str]] = typer.Option(None, "--local", help="本地目录/文件一并扫描"),
    workers: int = typer.Option(8, "--workers"),
):
    """SSH 上机 grep + 本地扫描，收集 flag。"""
    from .flag import hunt_local, hunt_remote
    from .util import pmap
    cfg, ts = _targets(target)
    store = get_store()
    new = 0
    for name, flags in pmap(lambda t: (t.name, hunt_remote(cfg, t)), ts,
                            workers=min(workers, max(1, len(ts))), label="hunt"):
        if isinstance(flags, Exception):
            warn(f"{name}: {flags}")
            continue
        for fl in flags:
            if store.add_flag(fl, target=name, source="ssh-hunt"):
                new += 1
                console.print(f"[green]+[/green] {name}  {fl}")
    if local:
        for path, flags in hunt_local(local, cfg).items():
            for fl in flags:
                if store.add_flag(fl, target=path, source="local-scan"):
                    new += 1
                    console.print(f"[green]+[/green] {path}  {fl}")
    (ok if new else info)(f"新增 {new} 个 flag")
    if submit and new:
        from .flag import Submitter
        Submitter(cfg, store).submit_all(only_pending=True)


@flag_app.command("server")
def flag_server(
    url: Optional[str] = typer.Option(None, "--url", help="flag 服务器地址（从靶机上能访问的那个）"),
    mode: Optional[str] = typer.Option(None, "--mode", help="http / cmd"),
    cmd: Optional[str] = typer.Option(None, "--cmd", help="cmd 模式：如 ./readflag"),
    token: Optional[str] = typer.Option(None, "--token", help="本队 token（留空则从靶机文件读）"),
    token_cmd: Optional[str] = typer.Option(None, "--token-cmd", help="在靶机上取 token 的命令"),
    field: Optional[str] = typer.Option(None, "--field", help="响应 JSON 里 flag 的路径，如 data.flag"),
    header: Optional[List[str]] = typer.Option(None, "--header", "-H", help="形如 X-Token:{token}"),
    method: Optional[str] = typer.Option(None, "--method"),
    scope: Optional[str] = typer.Option(None, "--scope", help="defense / attack / all"),
    tool: Optional[str] = typer.Option(None, "--tool", help="auto / curl / wget / python3"),
    timeout: Optional[int] = typer.Option(None, "--timeout"),
    show: bool = typer.Option(False, "--show", help="只打印当前配置"),
    target: Optional[List[str]] = typer.Option(None, "--target", "-t"),
    submit: Optional[bool] = typer.Option(None, "--submit/--no-submit",
                                          help="拉到后是否自动提交"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只跑一台看原始响应"),
):
    """经靶机访问 flag 服务器取 flag（内网接口，本机直连不到）。"""
    from . import flagserver as fs
    from .util import jdump
    import json as _json

    cfg = get_cfg()
    store = get_store()
    conf = fs.load_conf(cfg, store)
    given = {k: v for k, v in {
        "url": url, "mode": mode, "cmd": cmd, "token": token,
        "token_cmd": token_cmd, "field": field, "method": method,
        "scope": scope, "tool": tool, "timeout": timeout,
    }.items() if v is not None}
    if header:
        hdrs = dict(conf.get("headers") or {})
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                hdrs[k.strip()] = v.strip()
        given["headers"] = hdrs
    if submit is not None:
        given["submit_after"] = submit

    if show and not given:
        console.print(jdump(conf))
        return
    if given:
        conf.update(given)
        fs.save_conf(store, conf)
        info(f"已保存 flagserver 配置（{conf.get('mode')} · {conf.get('url') or conf.get('cmd')}）")
    if not (conf.get("url") or conf.get("cmd")):
        warn("还没配置地址：用 ops flag server --url http://... 或 --cmd './readflag'")
        return

    if dry_run:
        targets = fs.pick_targets(cfg, conf, target)
        if not targets:
            warn("没有可用靶机")
            return
        r = fs.fetch_one(cfg, targets[0], conf)
        console.print(f"[dim]在 {r.target}({r.host}) 执行：[/dim]\n{r.cmd}")
        console.print(r.out or "[dim]（无输出）[/dim]")
        (ok if r.flags else warn)(f"退出码 {r.rc}，命中 {len(r.flags)} 个 flag")
        return

    res = fs.fetch_all(cfg, store, conf=conf, names=target, submit=submit,
                       log=lambda msg, level="info": console.print(
                           f"[dim]{msg}[/dim]" if level == "info" else msg))
    (ok if res["new"] else warn)(
        f"新增 {res['new']} 个 flag，提交成功 {res['submitted']['ok']} / "
        f"失败 {res['submitted']['fail']}")


@flag_app.command("submit")
def flag_submit(
    all_: bool = typer.Option(False, "--all", help="重提全部（含已成功）"),
    workers: int = typer.Option(1, "--workers"),
):
    """提交待提交的 flag。"""
    from .flag import Submitter
    cfg = get_cfg()
    Submitter(cfg, get_store()).submit_all(only_pending=not all_, workers=workers)


@flag_app.command("curl")
def flag_curl(
    curl: str = typer.Argument(..., help="浏览器里 Copy as cURL 的整段内容（用单引号裹住）"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="保存成这个名字并激活"),
    flag_key: Optional[str] = typer.Option(None, "--flag-key",
                                           help="flag 所在的字段名/JSON 路径，如 data.answer"),
    test: Optional[str] = typer.Option(None, "--test", help="用这个真 flag 打一次验证"),
):
    """把浏览器复制的 cURL 变成提交接口（自动找 flag 位置）。

    用法：Network 面板 → 右键提交请求 → Copy as cURL → 粘贴到单引号里。
    """
    import json as _json

    from .curlparse import parse_to_profile

    cfg = get_cfg()
    store = get_store()
    prof = parse_to_profile(curl, flag_key=flag_key)
    prev = prof["preview"]

    if prev.get("errors"):
        die("；".join(prev["errors"]))

    console.print(f"[bold]解析结果[/bold]  {prev['method']}  {prev['url']}")
    if prev.get("headers"):
        console.print("  headers: " + ", ".join(prev["headers"]))
    if prof["body_kind"] != "none":
        body = prof["json_body"] or prof["form_body"] or prof["raw_body"]
        console.print(f"  body({prof['body_kind']}): "
                      + _json.dumps(body, ensure_ascii=False)[:200]
                      if isinstance(body, (dict, list)) else f"  body: {str(body)[:200]}")
    if prof["has_placeholder"]:
        ok(f"flag 位置: {', '.join(prof['flag_at'])} → 已替换为 {{flag}}")
    else:
        warn("没找到 flag 的位置：请用 --flag-key 指定字段名（body 里的 JSON 路径或 form 键名）")

    if name:
        conf = {k: prof[k] for k in ("url", "method", "headers", "json_body",
                                     "form_body", "raw_body", "success_key",
                                     "success_value", "message_key", "flag_at")}
        conf["strict"] = True
        import urllib.parse as _up
        store.save_submit_profile(name, conf,
                                  host=_up.urlsplit(prof["url"]).netloc,
                                  note="curl 导入", activate=True)
        ok(f"已保存并激活提交接口: {name}")

    if test:
        from .flag import Submitter
        sub = Submitter(cfg, store, profile=name)
        res = sub.submit(test, "cli-test")
        (ok if res.ok else warn)(f"测试提交: {'成功' if res.ok else '失败'} · {res.message[:100]}")


@flag_app.command("watch")
def flag_watch(
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    interval: int = typer.Option(300, "--interval", help="检测间隔（秒），AWD 通常 300"),
    once: bool = typer.Option(False, "--once", help="只检查一轮，不常驻"),
    no_submit: bool = typer.Option(False, "--no-submit", help="只检测不提交"),
    deep: bool = typer.Option(False, "--deep", help="每轮都全盘 grep（慢，但不会漏）"),
):
    """AWD 轮次监控：定时检测 flag 是否刷新，刷新后自动获取并提交。"""
    import time as _t

    from .round import MIN_INTERVAL, RoundWatcher

    cfg = get_cfg()
    store = get_store()
    ts = cfg.resolve([x for item in target for x in str(item).split(",") if x.strip()])
    if not ts:
        die("没有可监控的靶机")

    watcher = RoundWatcher(cfg, store)
    if once:
        events = watcher.tick(ts)
        total = 0
        for e in events:
            if e.changed:
                total += len(e.new_flags)
                ok(f"[{e.target}] 新 flag {len(e.new_flags)} 个: "
                   f"{', '.join(f[:38] for f in e.new_flags)}")
            elif e.note:
                warn(f"[{e.target}] {e.note}")
            else:
                info(f"[{e.target}] {len(e.all_flags)} 个 flag，无变化")
        (ok if total else info)(f"本轮结束：新增 {total} 个")
        return

    st = watcher.start(targets=[t.name for t in ts], interval=max(MIN_INTERVAL, interval),
                       auto_submit=not no_submit, deep=deep)
    info(f"轮次监控已启动：{len(st['targets'])} 台，每 {st['interval']} 秒检查一次"
         f"（提交={'开' if not no_submit else '关'}）")
    info("Ctrl-C 停止")
    try:
        while True:
            _t.sleep(5)
            cur = watcher.state()
            if not cur["running"]:
                break
            if cur.get("last_error"):
                warn(cur["last_error"])
    except KeyboardInterrupt:
        watcher.stop()
        warn("已停止")
        rows = store.rounds(limit=10)
        if rows:
            t = Table(box=box.SIMPLE_HEAD)
            for c in ("轮次", "靶机", "FLAG", "提交"):
                t.add_column(c, overflow="fold")
            for r in rows:
                t.add_row(str(r["round_no"]), r["target"], (r["flag"] or "")[:40],
                          "✓" if r["ok"] else ("已提交" if r["submitted"] else "-"))
            console.print(t)


@flag_app.command("list")
def flag_list():
    """查看 flag 收集与提交状态。"""
    rows = get_store().flags()
    t = Table(box=box.SIMPLE_HEAD)
    for c in ("#", "时间", "靶机", "FLAG", "提交", "结果"):
        t.add_column(c, overflow="fold")
    for i, r in enumerate(rows, 1):
        t.add_row(str(i), r["ts"][5:19], r["target"], r["value"],
                  "[green]✓[/green]" if r["submitted"] else "[yellow]待提交[/yellow]",
                  (r["submit_result"] or "")[:60])
    console.print(t if rows else "[dim]暂无 flag[/dim]")


@flag_app.command("test")
def flag_submit_test(flag: str = typer.Argument("flag{test_submit_probe}")):
    """用假 flag 验证提交接口连通性（不会真的得分）。"""
    from .flag import Submitter
    cfg = get_cfg()
    res = Submitter(cfg, get_store()).submit(flag, "probe")
    (ok if res.ok else warn)(f"{res.ok} | {res.message}\n{res.raw[:500]}")


# ---------------------------------------------------------------------- logs
logs_app = typer.Typer(help="日志分析。", no_args_is_help=True)
app.add_typer(logs_app, name="logs")


@logs_app.command("analyze")
def logs_analyze(
    path: List[str] = typer.Argument(..., help="日志文件或目录"),
    target: str = typer.Option("", "--target", help="关联靶机名，仅用于归档"),
    ai: bool = typer.Option(True, "--ai/--no-ai"),
    save: bool = typer.Option(True, "--save/--no-save"),
):
    """离线日志研判（auth.log / access.log / syslog）。"""
    from .logx import analyze_paths
    from .scan import sort_findings
    cfg = get_cfg()
    rep = analyze_paths(path, cfg if ai else _no_ai(cfg), target=target)
    console.print(f"[bold]分析 {len(rep.files)} 个文件，类型 {rep.kind or 'mixed'}[/bold]")
    st = Table(box=box.SIMPLE_HEAD)
    st.add_column("指标"); st.add_column("值", overflow="fold")
    for k, v in list(rep.stats.items())[:20]:
        st.add_row(k, str(v)[:200])
    console.print(st)
    if rep.findings:
        ft = Table(title="发现", box=box.SIMPLE_HEAD)
        ft.add_column("级别"); ft.add_column("标题", overflow="fold"); ft.add_column("细节", overflow="fold")
        for f in sort_findings(rep.findings):
            color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "dim")
            ft.add_row(f"[{color}]{f.severity}[/{color}]", f.title, (f.detail or f.evidence)[:120])
        console.print(ft)
        store = get_store()
        for f in rep.findings:
            store.event("finding", target=target or "log", title=f.title,
                        severity=f.severity, data=f.to_dict())
    if rep.timeline:
        console.print(Panel("\n".join(rep.timeline[:30]), title="时间线", border_style="blue"))
    if rep.ai_text:
        from rich.markdown import Markdown
        console.print(Panel(Markdown(rep.ai_text), title="AI 溯源研判", border_style="cyan"))
    if save:
        out = cfg.report_dir / f"log_{time.strftime('%Y%m%d_%H%M%S')}.md"
        out.write_text(rep.text(), encoding="utf-8")
        ok(f"已保存 {out}")


def _no_ai(cfg: Config) -> Config:
    cfg.ai.enabled = False
    return cfg


# ------------------------------------------------------------------- traffic
traffic_app = typer.Typer(help="流量分析（pcap）。", no_args_is_help=True)
app.add_typer(traffic_app, name="traffic")


@traffic_app.command("analyze")
def traffic_analyze(
    pcap: str = typer.Argument(..., help="pcap/pcapng 文件"),
    ai: bool = typer.Option(True, "--ai/--no-ai"),
    save: bool = typer.Option(True, "--save/--no-save"),
    export: bool = typer.Option(True, "--export/--no-export"),
):
    """tshark 解析 pcap：扫描/注入/上传/凭据/flag。"""
    from .scan import sort_findings
    from .traffic import analyze_pcap
    cfg = get_cfg()
    if not export:
        cfg.extra["skip_export"] = True
    info(f"解析 {pcap} ...")
    rep = analyze_pcap(cfg, pcap, ai=ai)
    st = Table(box=box.SIMPLE_HEAD)
    st.add_column("指标"); st.add_column("值", overflow="fold")
    for k, v in rep.stats.items():
        st.add_row(k, str(v)[:300])
    console.print(st)
    if rep.findings:
        ft = Table(title="发现", box=box.SIMPLE_HEAD)
        ft.add_column("级别"); ft.add_column("标题", overflow="fold"); ft.add_column("证据", overflow="fold")
        for f in sort_findings(rep.findings):
            color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "dim")
            ft.add_row(f"[{color}]{f.severity}[/{color}]", f.title,
                       (f.evidence or f.detail)[:120].replace("\n", " "))
        console.print(ft)
        store = get_store()
        for f in rep.findings:
            store.event("finding", target="pcap", title=f.title,
                        severity=f.severity, data=f.to_dict())
    if rep.ai_text:
        from rich.markdown import Markdown
        console.print(Panel(Markdown(rep.ai_text), title="AI 流量研判", border_style="cyan"))
    if save:
        out = cfg.report_dir / f"pcap_{pathlib.Path(pcap).stem}_{time.strftime('%H%M%S')}.md"
        out.write_text(rep.text(), encoding="utf-8")
        ok(f"已保存 {out}")


# ---------------------------------------------------------------------- shot
shot_app = typer.Typer(help="CTF 步骤取证（截图 + 时间线）。", no_args_is_help=True)
app.add_typer(shot_app, name="shot")


@shot_app.command("capture")
def shot_capture(
    step: str = typer.Argument(..., help="步骤名，如 3-上传webshell"),
    url: Optional[str] = typer.Option(None, "--url", help="要截图的页面"),
    note: str = typer.Option("", "--note", help="一句话说明"),
    selector: Optional[str] = typer.Option(None, "--selector", help="只截某个元素"),
    screen: bool = typer.Option(False, "--screen", help="改截整屏（macOS）"),
):
    """自动截图并登记到时间线。"""
    from .shot import capture
    cfg = get_cfg()
    capture(cfg, get_store(), step, url=url or "", note=note,
            selector=selector, screen=screen)


@shot_app.command("mark")
def shot_mark(
    step: str = typer.Argument(...),
    image: str = typer.Option("", "--image", help="已有截图路径"),
    note: str = typer.Option("", "--note"),
    url: str = typer.Option("", "--url"),
):
    """登记一张已有截图（手动截的图）。"""
    from .shot import mark
    mark(get_store(), step, note=note, image=image, url=url)


@shot_app.command("timeline")
def shot_timeline(title: str = typer.Option("作战时间线", "--title")):
    """生成 report/timeline.md。"""
    from .shot import write_timeline
    write_timeline(get_cfg(), get_store(), title)


# -------------------------------------------------------------------- report

# ----------------------------------------------------------------------- WAF
waf_app = typer.Typer(help="WAF：旁路监听、攻击取证、加固封禁。", no_args_is_help=True)
app.add_typer(waf_app, name="waf")


@waf_app.command("deploy")
def waf_deploy_cmd(
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    mode: str = typer.Option("monitor", "--mode", help="monitor 只监听 / enforce 拦截"),
    logs: Optional[List[str]] = typer.Option(None, "--logs", help="访问日志路径，可多次指定"),
    autoban: bool = typer.Option(False, "--autoban", help="enforce 时命中即封禁 IP"),
    engine: str = typer.Option("auto", "--engine",
                               help="auto / go / php / python；auto 优先用免运行时的 Go agent"),
):
    """在防守靶机部署 WAF agent（默认只监听）。"""
    from .waf import deploy
    cfg, ts = _targets(target)
    for t in ts:
        if t.is_attack:
            warn(f"{t.name} 是攻击目标，跳过")
            continue
        r = deploy(cfg, t, logs=logs or None, mode=mode, autoban=autoban,
                   engine=engine)
        if r.get("ok"):
            eng = r.get("engine", "")
            extra = (f"日志 {', '.join(r.get('logs') or [])}" if eng in ("python", "go")
                     else f"auto_prepend → {r.get('ini_path', '')}")
            ok(f"{t.name}: {eng} · {r['mode']} · 规则 {r['rules']} · {extra}")
            if r.get("note"):
                warn(f"  {r['note']}")
        else:
            warn(f"{t.name}: {r.get('error')}")
            st = r.get("stack") or {}
            if st:
                info(f"  探测：php={st.get('php')} php-fpm={st.get('php_fpm')} "
                     f"python3={st.get('python3') or '无'} webroot={st.get('webroot')}")


@waf_app.command("status")
def waf_status_cmd(target: List[str] = typer.Option(["@defense"], "--target", "-t")):
    """查看 agent 运行状态。"""
    from .waf import status
    cfg, ts = _targets(target)
    t = Table(box=box.SIMPLE_HEAD)
    for c in ("靶机", "状态", "引擎", "模式", "请求", "命中", "封禁", "运行"):
        t.add_column(c)
    for x in ts:
        st = status(cfg, x)
        t.add_row(x.name, "运行中" if st.running else "未部署", st.engine or "-", st.mode or "-",
                  str(st.requests), str(st.matched), str(st.banned),
                  f"{int(st.uptime)}s" if st.uptime else "-")
    console.print(t)


@waf_app.command("audit")
def waf_audit_cmd(
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    to_vuln: bool = typer.Option(False, "--to-vuln", help="命中直接写入漏洞库"),
):
    """拉取攻击命中记录。"""
    from .waf import collect
    cfg, ts = _targets(target)
    store = get_store()
    res = collect(cfg, store, ts)
    rows = res["hits"]
    if not rows:
        info("没有命中记录")
        return
    t = Table(box=box.SIMPLE_HEAD)
    for c in ("级别", "规则", "靶机", "次数", "最近来源", "样例"):
        t.add_column(c, overflow="fold")
    for h in rows:
        t.add_row(h["severity"], h["name"], h["target"], str(h["count"]),
                  h["last_ip"], ((h.get("sample") or {}).get("path") or "")[:70])
    console.print(t)
    if to_vuln:
        n = 0
        for h in rows:
            sample = h.get("sample") or {}
            if store.add_vuln(h["name"], sample.get("method", "GET"), sample.get("path", "/"),
                              severity=h["severity"], source="waf", target=h["target"],
                              headers={"User-Agent": sample.get("ua", "")},
                              rule_id=h["rule_id"], tags=h["rule_id"]):
                n += 1
        ok(f"入库 {n} 条")


@waf_app.command("enforce")
def waf_enforce_cmd(
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    rule: Optional[str] = typer.Option(None, "--rule", help="只对这些规则拦截，逗号分隔，如 sqli,cmdi"),
    no_ban: bool = typer.Option(False, "--no-ban"),
):
    """切到加固模式：命中即封禁源 IP。"""
    from .waf import enforce
    cfg, ts = _targets(target)
    ids = [x.strip() for x in rule.split(",")] if rule else None
    for t in ts:
        if t.is_attack:
            continue
        r = enforce(cfg, t, rule_ids=ids, autoban=not no_ban)
        (ok if r.get("ok") else warn)(
            f"{t.name}: {r.get('mode')} · 已封禁 {r.get('banned', 0)} · 规则 {', '.join(r.get('blocked_rules') or [])}")


@waf_app.command("stop")
def waf_stop_cmd(target: List[str] = typer.Option(["@defense"], "--target", "-t"),
                 unban: bool = typer.Option(False, "--unban", help="同时清空 iptables 规则")):
    """停止 agent。"""
    from .waf import stop
    cfg, ts = _targets(target)
    for t in ts:
        stop(cfg, t, unban=unban)
        ok(f"{t.name}: 已停止")


@waf_app.command("ban")
def waf_ban_cmd(
    ips: List[str] = typer.Argument(..., help="要封的 IP，可多个"),
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    backend: str = typer.Option("auto", "--backend",
                                help="auto / iptables / php403 / htaccess"),
):
    """封禁 IP：按靶机权限自动选 iptables / PHP 403 / .htaccess。"""
    from .waf import ban
    cfg, ts = _targets(target)
    for t in ts:
        r = ban(cfg, t, ips, backend=backend)
        if r.get("error"):
            warn(f"{t.name}: {r['error']}")
        (ok if r.get("ok") else warn)(
            f"{t.name}: 方式 {r.get('backend') or '-'}，成功 {len(r.get('banned') or [])}，"
            f"失败 {len(r.get('failed') or [])}")
        for d in r.get("detail") or []:
            console.print(f"  [dim]{d}[/dim]")


@waf_app.command("unban")
def waf_unban_cmd(
    ips: Optional[List[str]] = typer.Argument(None, help="留空则清掉本工具加的全部"),
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
):
    """解封：只删带 ctf-ops-ban 标记的规则，不动其它防火墙策略。"""
    from .waf import unban
    cfg, ts = _targets(target)
    for t in ts:
        r = unban(cfg, t, ips or None)
        (ok if r.get("ok") else warn)(
            f"{t.name}: 解封 {len(r.get('removed') or [])} 个"
            + (f"（{'；'.join(r['detail'])}）" if r.get("detail") else ""))


@waf_app.command("bans")
def waf_bans_cmd(target: List[str] = typer.Option(["@defense"], "--target", "-t")):
    """看现在封了谁（iptables 标记 + PHP 黑名单）。"""
    from .waf import list_bans
    cfg, ts = _targets(target)
    for t in ts:
        r = list_bans(cfg, t)
        console.print(f"[bold]{t.name}[/bold] 共 {len(r.get('bans') or [])} 个")
        for ip in r.get("bans") or []:
            console.print(f"  - {ip}")


@waf_app.command("caps")
def waf_caps_cmd(target: List[str] = typer.Option(["@defense"], "--target", "-t")):
    """探测靶机能用哪种封禁方式（普通用户通常只能走应用层）。"""
    from .waf import detect_ban_caps
    cfg, ts = _targets(target)
    for t in ts:
        c = detect_ban_caps(cfg, t)
        console.print(f"[bold]{t.name}[/bold] uid={c.uid} root={c.root} sudo={c.sudo} "
                      f"iptables={c.iptables} php={c.php_agent} "
                      f"web={c.web_server or '-'} htaccess={c.allow_override} "
                      f"→ 推荐 [cyan]{c.best() or '无（只能靠 WAF 规则拦 payload）'}[/cyan]")


# --------------------------------------------------------------------- 漏洞修补
harden_app = typer.Typer(help="漏洞修补：按扫出来的发现生成并应用修复动作。",
                         no_args_is_help=True)
app.add_typer(harden_app, name="harden")


@harden_app.command("plan")
def harden_plan_cmd(
    target: List[str] = typer.Option(["@defense"], "--target", "-t"),
    apply_: bool = typer.Option(False, "--apply", help="生成后立刻执行免 root 的动作"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """从发现/漏洞库生成修补方案（附命令与配置片段）。"""
    from . import harden as harden_mod
    from .waf import detect_ban_caps
    from .util import pmap
    cfg, ts = _targets(target)
    store = get_store()
    caps = {name: c.to_dict() for name, c in
            [(t.name, detect_ban_caps(cfg, t)) for t in ts]}
    acts = harden_mod.plan(cfg, store, ts, caps,
                           log=lambda m, l="info": console.print(f"[dim]{m}[/dim]"))
    if not acts:
        warn("没有需要修补的发现（先跑扫描/查杀）")
        return
    md = harden_mod.write_plan_md(cfg, acts)
    store.set_setting("harden.last", json.dumps(
        {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "caps": caps,
         "actions": [a.to_dict() for a in acts]}, ensure_ascii=False))
    ok(f"生成 {len(acts)} 个动作，方案：{md}")
    for a in acts:
        tag = "自动" if a.auto else "人工"
        console.print(f"[{a.severity}] {a.target} · {a.title} （{a.level} / {tag}"
                      f"{' / 需 root' if a.needs_root else ''}）")
    if not apply_:
        return
    if not yes and not typer.confirm("直接应用免 root 的自动动作？", default=False):
        return
    for t in ts:
        mine = [a for a in acts if a.target == t.name]
        if not mine:
            continue
        for row in harden_mod.apply(cfg, store, t, mine, caps.get(t.name),
                                    log=lambda m, l="info": console.print(f"  {m}")):
            (ok if row.get("ok") else warn)(
                f"{t.name}: {row['title']} → {row['status']} {row['detail'][:100]}")


# --------------------------------------------------------------------- 漏洞库
vuln_app = typer.Typer(help="漏洞库：WAF 命中的可复现请求，可用于加固与重放。", no_args_is_help=True)
app.add_typer(vuln_app, name="vuln")


@vuln_app.command("list")
def vuln_list_cmd():
    """列出漏洞库。"""
    store = get_store()
    rows = store.vulns()
    t = Table(box=box.SIMPLE_HEAD)
    for c in ("#", "级别", "漏洞", "请求", "来源", "重放"):
        t.add_column(c, overflow="fold")
    for v in rows:
        t.add_row(str(v["id"]), v["severity"], v["name"],
                  f"{v['method']} {v['path']}"[:70], v["source"] or "-",
                  "有响应" if v["replay_ok"] == 1 else "失败" if v["replay_ok"] == 0 else "-")
    console.print(t if rows else "[dim]漏洞库为空[/dim]")


@vuln_app.command("replay")
def vuln_replay_cmd(
    vid: Optional[List[int]] = typer.Option(None, "--id", help="漏洞 id，可多次指定"),
    all_: bool = typer.Option(False, "--all"),
    target: List[str] = typer.Option(["@attack"], "--target", "-t"),
    workers: int = typer.Option(6, "--workers"),
):
    """把漏洞库里的请求批量打到攻击目标。"""
    from .replay import replay_many
    cfg, ts = _targets(target)
    attack = [t for t in ts if t.is_attack]
    if not attack:
        die("没有攻击目标：把靶机标为 role: attack，或用 @attack")
    store = get_store()
    vulns = store.vulns(limit=100) if (all_ or not vid) else \
        [v for v in (store.vuln(i) for i in vid) if v]
    if not vulns:
        die("没有可重放的漏洞")
    rows = replay_many(cfg, vulns, attack, workers=workers)
    t = Table(box=box.SIMPLE_HEAD)
    for c in ("目标", "方法", "URL", "状态", "长度", "FLAG"):
        t.add_column(c, overflow="fold")
    new_flags = 0
    for r in rows:
        for fl in r.get("flags") or []:
            if store.add_flag(fl, target=str(r.get("target")), source="replay"):
                new_flags += 1
        t.add_row(str(r.get("target")), str(r.get("method")), str(r.get("url"))[:70],
                  str(r.get("status")), str(r.get("length")),
                  " ".join(r.get("flags") or []) or "-")
    console.print(t)
    ok(f"重放 {len(rows)} 次，新增 flag {new_flags}")


@app.command()
def report(title: str = typer.Option("", "--title")):
    """生成 Markdown + HTML 报告。"""
    from .report import write_report
    cfg = get_cfg()
    files = write_report(cfg, get_store(), title)
    for f in files:
        console.print(f"  {f}")


@app.command()
def status():
    """当前战况一览。"""
    cfg = get_cfg()
    s = get_store().summary()
    t = Table(title=f"{cfg.name} 战况", box=box.SIMPLE_HEAD)
    t.add_column("指标"); t.add_column("数值")
    for k, v in s.items():
        if k == "severity":
            v = " ".join(f"{a}×{b}" for a, b in v.items()) or "-"
        t.add_row(k, str(v))
    console.print(t)


# ----------------------------------------------------------------------- ai
ai_app = typer.Typer(help="本地 AI 辅助分析。", no_args_is_help=True)
app.add_typer(ai_app, name="ai")


@ai_app.command("ask")
def ai_ask(prompt: str = typer.Argument(..., help="问题，支持 @文件 引用")):
    """直接问本地模型（支持 @路径 注入文件内容）。"""
    from .aiclient import AIClient, print_ai
    cfg = get_cfg()
    text = prompt
    for token in prompt.split():
        if token.startswith("@"):
            p = pathlib.Path(token[1:]).expanduser()
            if p.exists():
                text = text.replace(token, f"\n\n--- {p.name} ---\n" + trunc(
                    p.read_text(encoding="utf-8", errors="replace"), 12000))
    print_ai(AIClient(cfg).chat(text))


@ai_app.command("audit")
def ai_audit(path: str = typer.Argument(..., help="源码文件")):
    """源码审计：漏洞点 + payload。"""
    from .aiclient import AIClient, print_ai
    cfg = get_cfg()
    p = pathlib.Path(path).expanduser()
    if not p.exists():
        die(f"文件不存在: {p}")
    code = p.read_text(encoding="utf-8", errors="replace")
    print_ai(AIClient(cfg).explain_code(code, p.name))


@ai_app.command("check")
def ai_check():
    """检查 AI 端点。"""
    from .aiclient import AIClient
    cfg = get_cfg()
    ai = AIClient(cfg)
    alive = ai.available(force=True)
    (ok if alive else warn)(f"{cfg.ai.base_url} model={cfg.ai.model} "
                            f"{'可用' if alive else '不可用'}")
    if alive:
        r = ai.chat("只回复：pong", max_tokens=16)
        console.print(f"  -> {r.text[:100]}")


def _render_triage(res, title: str = "AI 攻击路径") -> None:
    """AI 返回结构化 JSON 就画表，否则退回原文（模型偶尔不听话）。"""
    from .aiclient import parse_triage
    if not res.ok:
        warn(f"{title} 不可用：{res.error}（规则引擎结果仍然有效）")
        return
    data = parse_triage(res.text)
    if not data:
        from .aiclient import print_ai
        print_ai(res, title)
        return
    if not data["paths"]:
        info(f"{title}：模型没给出可执行路径")
        return
    console.print(f"[bold]{title}[/bold]")
    t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False)
    t.add_column("#", width=2)
    t.add_column("靶机", width=16, overflow="fold")
    t.add_column("类型", width=5)
    t.add_column("动作", overflow="fold")
    t.add_column("命令", overflow="fold")
    for p in data["paths"]:
        kind = p["kind"] or "-"
        color = "yellow" if kind.startswith("处置") else "cyan"
        t.add_row(str(p["rank"]), p["target"], f"[{color}]{kind}[/{color}]",
                  p["action"], f"[dim]{p['command']}[/dim]")
    console.print(t)
    if data["skip"]:
        console.print("[dim]可放弃：" + "、".join(data["skip"]) + "[/dim]")


# ------------------------------------------------------------------ AI 写插件
@ai_app.command("triage")
def ai_triage(limit: int = typer.Option(200, "--limit", help="取多少条历史发现")):
    """对已入库的扫描发现做攻击路径排序（不用重扫）。"""
    from .aiclient import AIClient
    cfg = get_cfg()
    store = get_store()
    rows = store.events(kind="finding", limit=limit)
    if not rows:
        die("库里还没有发现，先跑一次扫描")
    items = [{"severity": r.get("severity"), "target": r.get("target"),
              "title": r.get("title"),
              "location": (r.get("data") or {}).get("location", ""),
              "detail": (r.get("data") or {}).get("detail", "")} for r in rows]
    info(f"用 {len(items)} 条已入库发现做排序（本地模型，约 30-60 秒）...")
    _render_triage(AIClient(cfg).triage_findings(items))


@ai_app.command("plugin")
def ai_plugin_cmd(desc: str = typer.Argument(..., help="漏洞描述 / CVE / 请求特征"),
                  install: bool = typer.Option(False, "--install", help="校验通过后直接启用")):
    """让本地模型按框架契约写一个 PoC 插件。"""
    from .aipl import generate, install as do_install
    cfg = get_cfg()
    # 注意：参数不能叫 info —— 会把 util.info() 这个打印函数遮住
    res = generate(cfg, desc)
    if not res.get("ok"):
        die(f"生成失败：{res.get('error')}")
    console.print(Syntax(res["code"], "python", theme="ansi_light", line_numbers=False))
    ok(f"{res['name']} · {res['severity']} · 草稿 {res['slug']}")
    if install:
        r = do_install(res["slug"])
        (ok if r.get("ok") else warn)(r.get("path") or r.get("error"))
    else:
        info(f"启用：ops --config {cfg.path} 用 API 或前端点「保存并启用」")


# --------------------------------------------------------------------- auto
auto_app = typer.Typer(help="自动作战：防守靶机自动守，攻击目标自动打，最后提交 FLAG。",
                       no_args_is_help=True)
app.add_typer(auto_app, name="auto")


def _print_auto(report: dict) -> None:
    for phase, title in (("defense", "防守"), ("attack", "攻击")):
        rows = (report.get(phase) or {}).get("steps") or []
        if not rows:
            continue
        t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False,
                  title=f"{title}动作")
        t.add_column("靶机", width=16, overflow="fold")
        t.add_column("动作", width=16, overflow="fold")
        t.add_column("结果", width=4)
        t.add_column("说明", overflow="fold")
        for r in rows:
            icon = "[green]✓[/green]" if r["ok"] else "[red]✗[/red]"
            t.add_row(r["target"], r["action"], icon, r["detail"][:90])
        console.print(t)

    flags = report.get("flags") or []
    if flags:
        console.print(f"[bold]本轮拿到 {len(flags)} 个 FLAG[/bold]")
        for f in flags:
            console.print(f"  [green]{f}[/green]")

    sub = (report.get("submit") or {}).get("submitted") or []
    if sub:
        t = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, title="提交结果")
        t.add_column("FLAG", overflow="fold")
        t.add_column("结果", width=4)
        t.add_column("平台返回", overflow="fold")
        for r in sub:
            t.add_row(r["flag"], "[green]✓[/green]" if r["ok"] else "[red]✗[/red]",
                      (r.get("message") or "")[:80])
        console.print(t)

    errs = report.get("errors") or []
    if errs:
        warn(f"{len(errs)} 处异常：" + "；".join(str(e)[:60] for e in errs[:5]))


@auto_app.command("run")
def auto_run(
    defense: bool = typer.Option(True, "--defense/--no-defense", help="跑防守流程"),
    attack: bool = typer.Option(True, "--attack/--no-attack", help="跑攻击流程"),
    submit: bool = typer.Option(True, "--submit/--no-submit", help="跑完自动提交"),
    plugin: Optional[List[str]] = typer.Option(None, "--plugin", help="只跑指定插件，可多次"),
    no_backup: bool = typer.Option(False, "--no-backup", help="跳过基线备份"),
    no_shell: bool = typer.Option(False, "--no-shell", help="跳过静态查杀"),
    no_replay: bool = typer.Option(False, "--no-replay", help="跳过漏洞重放"),
    dry_run: bool = typer.Option(False, "--dry-run", help="只打印将要做的事"),
):
    """一键：防守靶机自检 + 加固，攻击目标扫描 + 打点 + 提交。"""
    from .autopilot import AutoPilot, summarize

    cfg = get_cfg()
    store = get_store()
    phases = []
    if defense:
        phases.append("defense")
    if attack:
        phases.append("attack")
    if submit:
        phases.append("submit")

    defs = cfg.resolve_role("defense")
    atks = cfg.resolve_role("attack")
    info(f"防守 {len(defs)} 台: {', '.join(t.name for t in defs) or '无'}")
    info(f"攻击 {len(atks)} 台: {', '.join(t.name for t in atks) or '无'}")
    if dry_run:
        for t in defs:
            console.print(f"  防守 {t.name}: WAF 检查/部署 → 基线备份 → 后门查杀 → 加固 → 入库")
        for t in atks:
            console.print(f"  攻击 {t.name}: Web 指纹 → 插件{'(指定: ' + ','.join(plugin) + ')' if plugin else '全量'} → 漏洞重放 → 收 flag")
        info("提交：" + ("新 flag 自动提交" if submit else "不提交"))
        return

    ap = AutoPilot(cfg, store, log=lambda m, lv="info": console.print(
        f"[dim]{m}[/dim]" if lv == "info" else
        (f"[green]{m}[/green]" if lv == "ok" else
         (f"[yellow]{m}[/yellow]" if lv == "warn" else f"[red]{m}[/red]"))))

    out: dict = {"phases": phases}
    if defense:
        info("== 自动防守 ==")
        out["defense"] = ap.defend(do_backup=not no_backup, do_scan=not no_shell).to_dict()
    if attack:
        info("== 自动攻击 ==")
        ar = ap.attack(plugins=plugin, do_replay=not no_replay)
        out["attack"] = ar.to_dict()
        out["flags"] = ar.flags
    if submit:
        info("== 提交 FLAG ==")
        out["submit"] = ap.submit(out.get("flags") or None).to_dict()

    _print_auto(out)
    ok(summarize(out))


# ---------------------------------------------------------------------- dash
@app.command()
def dash(port: int = typer.Option(8899, "--port"),
         host: str = typer.Option("127.0.0.1", "--host", help="默认只监听本机"),
         open_browser: bool = typer.Option(True, "--open/--no-open")):
    """启动 Web 作战控制台（总览/运维/备份/扫描/利用/FLAG/日志/流量/取证/AI/报告）。"""
    from .web.server import serve
    serve(get_cfg(), port=port, open_browser=open_browser, host=host)


@app.command()
def version():
    """版本信息。"""
    console.print(f"ctf-ops {__version__}")


if __name__ == "__main__":
    app()

"""自动作战：防守靶机自动守，攻击目标自动打，最后统一提交 flag。

角色决定动作，这是整套系统的分工原则：

    防守靶机（role=defense）        攻击目标（role=attack）
    ├─ 确认 WAF 在跑，没跑就装      ├─ Web 指纹 / 存活探测
    ├─ 打一次基线备份（当天只一次）  ├─ 逐个跑 PoC 插件（先 check 再打）
    ├─ 静态查杀 webroot 找后门      ├─ 把 WAF 抓到的 payload 重放过去
    ├─ 查到后门 → WAF 切加固模式    └─ 收集响应里的 flag
    └─ 把 WAF 命中写进漏洞库
                 └──────────┬──────────┘
                       统一提交（新 flag → 平台）

几条刻意的取舍：

* **不自动删文件**。查到后门只加固 + 报警，删文件交给人在界面确认——
  自动删错一个业务文件，AWD 直接掉分，比被挂马还亏。
* **幂等**。WAF 已在跑就不重装；当天已有备份就不再备份；同一 flag 入库去重。
* **失败不中断**。任何一步异常都记进报告的 errors，继续做下一步——
  比赛里时间比"流程完整"重要。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .config import Config, Target
from .store import Store
from .util import console, info, ok, warn


@dataclass
class StepResult:
    target: str
    action: str
    ok: bool = True
    detail: str = ""
    severity: str = "info"
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"target": self.target, "action": self.action, "ok": self.ok,
                "detail": self.detail, "severity": self.severity, "data": self.data}


@dataclass
class AutoReport:
    phase: str
    defense: List[StepResult] = field(default_factory=list)
    attack: List[StepResult] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    submitted: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        steps = self.defense if self.phase == "defense" else self.attack
        d: Dict[str, Any] = {"phase": self.phase,
                             "elapsed": round(self.elapsed, 1),
                             "errors": self.errors,
                             "flags": self.flags,
                             "submitted": self.submitted}
        if self.phase == "submit":
            d["summary"] = {"submitted_ok": sum(1 for x in self.submitted if x.get("ok")),
                            "total": len(self.submitted)}
        else:
            d["steps"] = [s.to_dict() for s in steps]
            # flagserver 这类"整批"步骤的 target 不是主机名，不计入靶机数
            hosts = {s.target for s in steps if s.ok and s.target not in ("flagserver", "-", "")}
            d["summary"] = {"targets": len(hosts),
                            "steps": len(steps),
                            "failed": sum(1 for s in steps if not s.ok)}
            if self.phase == "attack":
                d["summary"]["flags"] = len(self.flags)
        return d


class AutoPilot:
    """把"守"和"打"编排成一次可复现的行动。"""

    def __init__(self, cfg: Config, store: Store, log: Optional[Callable[[str, str], None]] = None):
        self.cfg = cfg
        self.store = store
        self._log = log or (lambda msg, level="info": console.print(f"[dim]{msg}[/dim]"))

    def log(self, msg: str, level: str = "info") -> None:
        try:
            self._log(msg, level)
        except TypeError:
            self._log(msg)

    # ------------------------------------------------------------ 防守
    def defend(self, targets: Optional[List[Target]] = None, *,
               do_backup: bool = True, do_scan: bool = True,
               do_harden: bool = True, max_scan_files: int = 20000) -> AutoReport:
        from . import backup as backup_mod
        from . import waf as waf_mod
        from . import webscan

        rep = AutoReport("defense")
        t0 = time.time()
        ts = targets if targets is not None else self.cfg.resolve_role("defense")
        if not ts:
            rep.errors.append("没有防守靶机（role=defense）")
            return rep

        vuln_rules: List[str] = []
        for t in ts:
            self.log(f"[{t.name}] 自动防守开始")
            # 1) WAF 是否在跑
            try:
                st = waf_mod.status(self.cfg, t)
                if st.running:
                    rep.defense.append(StepResult(t.name, "WAF 状态", True,
                                                  f"{st.engine or ''} {st.mode} 已运行",
                                                  data={"engine": st.engine, "mode": st.mode}))
                    self.log(f"[{t.name}] WAF 已在运行（{st.engine} {st.mode}）")
                else:
                    r = waf_mod.deploy(self.cfg, t, mode="monitor")
                    if r.get("ok"):
                        rep.defense.append(StepResult(t.name, "部署 WAF", True,
                                                      f"{r.get('engine')} {r.get('mode')}",
                                                      data=r))
                        self.log(f"[{t.name}] WAF 部署完成（{r.get('engine')}）", "ok")
                    else:
                        rep.defense.append(StepResult(t.name, "部署 WAF", False,
                                                      str(r.get("error"))[:200], "high", r))
                        self.log(f"[{t.name}] WAF 部署失败: {r.get('error')}", "error")
            except Exception as e:  # noqa: BLE001
                rep.errors.append(f"{t.name} WAF: {e}")
                rep.defense.append(StepResult(t.name, "部署 WAF", False, str(e)[:200], "high"))

            # 2) 当天是否已有备份，没有就打一个基线
            if do_backup:
                try:
                    today = time.strftime("%Y-%m-%d")
                    exists = [b for b in self.store.backups()
                              if b.get("target") == t.name and str(b.get("ts", "")).startswith(today)]
                    if exists:
                        rep.defense.append(StepResult(t.name, "基线备份", True,
                                                      f"今天已有 {len(exists)} 份"))
                    else:
                        dest = backup_mod.backup_root(self.cfg, self.store)
                        dest.mkdir(parents=True, exist_ok=True)
                        r = backup_mod.backup_target(self.cfg, t, dest_dir=dest, tag="auto-baseline")
                        if r.ok:
                            # 必须入库，否则"当天已备份"的幂等判断永远不成立
                            try:
                                self.store.add_backup(t.name, r.remote_path, r.local_path,
                                                      r.size, r.sha256, r.ok,
                                                      f"[auto] {r.note}")
                            except Exception as e:  # noqa: BLE001
                                rep.errors.append(f"{t.name} 备份入库: {e}")
                        rep.defense.append(StepResult(
                            t.name, "基线备份", r.ok,
                            r.note if r.ok else (r.note or "失败"),
                            "info" if r.ok else "high",
                            {"size": r.size, "path": r.local_path, "source": r.source}))
                        self.log(f"[{t.name}] 备份{'完成' if r.ok else '失败'}: "
                                 f"{r.note}", "ok" if r.ok else "error")
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"{t.name} 备份: {e}")
                    rep.defense.append(StepResult(t.name, "基线备份", False, str(e)[:200], "high"))

            # 3) 静态查杀 webroot
            mal = 0
            if do_scan:
                try:
                    sr = webscan.scan_remote(self.cfg, t, max_files=max_scan_files)
                    if sr.error:
                        rep.defense.append(StepResult(t.name, "后门查杀", False,
                                                      sr.error[:200], "medium"))
                        self.log(f"[{t.name}] 查杀失败: {sr.error}", "warn")
                    else:
                        mal = sr.malicious
                        samples = [x.path for x in sr.results
                                   if x.verdict == "malicious"][:3]
                        rep.defense.append(StepResult(
                            t.name, "后门查杀", True,
                            f"扫 {sr.files} 个文件，恶意 {sr.malicious} / 可疑 {sr.suspicious}"
                            + (f"：{'、'.join(samples)}" if samples else ""),
                            "critical" if mal else "info",
                            {"files": sr.files, "malicious": sr.malicious,
                             "suspicious": sr.suspicious,
                             "samples": [x.path for x in sr.results
                                         if x.verdict == "malicious"][:10]}))
                        self.log(f"[{t.name}] 查杀：{sr.files} 文件，恶意 {sr.malicious}",
                                 "error" if mal else "ok")
                        # 注意：查杀结果是"文件有后门"的证据，不是 flag，
                        # 早先这里误把它当 flag 入库，结果一堆代码片段被反复提交
                        for f in sr.findings(t.name, "shell")[:20]:
                            self.store.event("finding", target=t.name, title=f.title,
                                             severity=f.severity,
                                             data={**f.to_dict(), "source": "auto-defend"})
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"{t.name} 查杀: {e}")
                    rep.defense.append(StepResult(t.name, "后门查杀", False, str(e)[:200], "medium"))

            # 4) 有后门就加固（不删文件，只拦截 + 上报）
            if mal and do_harden:
                try:
                    ids = ["webshell", "phpcode", "cmdi"]
                    r = waf_mod.enforce(self.cfg, t, rule_ids=ids, autoban=True)
                    eng = r.get("engine", "")
                    tail = ("（PHP 版在请求内直接 403，不封 IP）" if eng == "php"
                            else f"（已封禁 {r.get('banned', 0)} 个源 IP）")
                    rep.defense.append(StepResult(
                        t.name, "自动加固", bool(r.get("ok")),
                        f"拦截规则 {', '.join(r.get('blocked_rules') or ids)}{tail}",
                        "high", r))
                    self.log(f"[{t.name}] 已切加固模式，注意还有后门文件待人工确认", "warn")
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"{t.name} 加固: {e}")
                    rep.defense.append(StepResult(t.name, "自动加固", False, str(e)[:200], "high"))

            # 5) WAF 命中写进漏洞库（供攻击侧重放）
            try:
                res = waf_mod.collect(self.cfg, self.store, [t], limit=200)
                hits = res.get("hits") or []
                added = 0
                for h in hits:
                    sample = h.get("sample") or {}
                    if self.store.add_vuln(h["name"], sample.get("method", "GET"),
                                           sample.get("path", "/"),
                                           severity=h.get("severity", "medium"),
                                           source="waf", target=t.name,
                                           headers={"User-Agent": sample.get("ua", "")},
                                           rule_id=h.get("rule_id", ""),
                                           tags=h.get("rule_id", "")):
                        added += 1
                        vuln_rules.append(h.get("rule_id", ""))
                rep.defense.append(StepResult(t.name, "攻击入库", True,
                                              f"命中 {len(hits)} 类，新增 {added} 条",
                                              "high" if hits else "info",
                                              {"hits": len(hits), "added": added}))
            except Exception as e:  # noqa: BLE001
                rep.errors.append(f"{t.name} WAF 审计: {e}")

        # 6) 经靶机问 flag 服务器（配了才做）—— AWD 里自己的 flag 要交上去
        try:
            from . import flagserver as fs
            conf = fs.load_conf(self.cfg, self.store)
            if (conf.get("url") or conf.get("cmd")) and conf.get("enabled", True):
                self.log("经靶机访问 flag 服务器 ...")
                res = fs.fetch_all(self.cfg, self.store, conf=conf,
                                   names=[t.name for t in ts],
                                   log=self.log)
                rep.defense.append(StepResult(
                    "flagserver", "拉取 FLAG", True,
                    f"新增 {res['new']} 个，提交成功 {res['submitted']['ok']} 个",
                    "info" if res["new"] else "info",
                    {"new": res["new"], "submitted": res["submitted"],
                     "rows": [{k: v for k, v in r.items() if k != "cmd"}
                              for r in res["rows"]]}))
                rep.flags.extend(f for r in res["rows"] for f in (r.get("flags") or []))
            else:
                self.log("未配置 flag 服务器，跳过该步骤")
        except Exception as e:  # noqa: BLE001
            rep.errors.append(f"flagserver: {e}")
            rep.defense.append(StepResult("flagserver", "拉取 FLAG", False, str(e)[:200], "medium"))

        rep.elapsed = time.time() - t0
        return rep

    # ------------------------------------------------------------ 攻击
    def attack(self, targets: Optional[List[Target]] = None, *,
               plugins: Optional[Sequence[str]] = None,
               do_scan: bool = True, do_replay: bool = True,
               max_plugins: int = 6, sleep: float = 0.0) -> AutoReport:
        from . import scan as scan_mod
        from .exploit import load_plugins, run_plugin
        from .replay import replay_many

        rep = AutoReport("attack")
        t0 = time.time()
        ts = targets if targets is not None else self.cfg.resolve_role("attack")
        if not ts:
            rep.errors.append("没有攻击目标（role=attack）")
            return rep

        all_plugins = load_plugins()
        if plugins:
            todo = [all_plugins[n] for n in plugins if n in all_plugins]
            missing = [n for n in plugins if n not in all_plugins]
            if missing:
                rep.errors.append(f"插件不存在: {', '.join(missing)}")
        else:
            todo = sorted(all_plugins.values(), key=lambda p: p.name)
        todo = todo[:max_plugins]

        for t in ts:
            self.log(f"[{t.name}] 自动攻击开始（{len(todo)} 个插件）")
            # 1) 指纹
            if do_scan:
                try:
                    fs = scan_mod.web_probe(self.cfg, t)
                    alive = [f for f in fs if f.title.startswith("Web 存活")]
                    for f in fs:
                        self.store.event("finding", target=t.name, title=f.title,
                                         severity=f.severity,
                                         data={**f.to_dict(), "source": "auto-attack"})
                    rep.attack.append(StepResult(
                        t.name, "Web 指纹", bool(alive),
                        (alive[0].detail if alive else "不可达")[:160],
                        "info", {"findings": len(fs)}))
                    self.log(f"[{t.name}] 指纹：{'存活' if alive else '不可达'}")
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"{t.name} 指纹: {e}")

            # 2) 逐个插件（check 不中会自己跳过）
            hit_any = False
            for p in todo:
                try:
                    r = run_plugin(self.cfg, p, t, sleep=sleep)
                    rep.attack.append(StepResult(
                        t.name, f"插件 {p.name}", r.ok,
                        (r.error or r.evidence or "")[:200],
                        "high" if r.ok else "info",
                        {"flags": r.flags, "elapsed": r.elapsed}))
                    if r.ok:
                        hit_any = True
                        self.log(f"[{t.name}] {p.name} 命中", "ok")
                    if r.flags:
                        rep.flags += r.flags
                        for fl in r.flags:
                            self.store.add_flag(fl, target=t.name, source=f"exploit:{p.name}")
                        self.log(f"[{t.name}] 拿到 flag: {', '.join(r.flags)}", "ok")
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"{t.name} {p.name}: {e}")

            # 3) 把 WAF 抓到的请求重放过来
            if do_replay:
                try:
                    vulns = [v for v in self.store.vulns(limit=60) if v.get("method")]
                    if vulns:
                        rows = replay_many(self.cfg, vulns, [t], workers=4)
                        good = sum(1 for r in rows if r.get("ok"))
                        rep.attack.append(StepResult(
                            t.name, "漏洞重放", good > 0,
                            f"{len(rows)} 次请求，{good} 次有响应",
                            "high" if good else "info", {"rows": rows[:20]}))
                        for r in rows:
                            for fl in r.get("flags") or []:
                                rep.flags.append(fl)
                                self.store.add_flag(fl, target=t.name, source="replay")
                        self.log(f"[{t.name}] 重放 {len(rows)} 次，命中 {good}")
                except Exception as e:  # noqa: BLE001
                    rep.errors.append(f"{t.name} 重放: {e}")

            if not hit_any:
                self.log(f"[{t.name}] 本轮没有命中，建议补插件或手工打", "warn")

        rep.flags = list(dict.fromkeys(rep.flags))
        rep.elapsed = time.time() - t0
        return rep

    # ------------------------------------------------------------ 提交
    def submit(self, flags: Optional[List[str]] = None, target: str = "auto") -> AutoReport:
        from .flag import Submitter

        rep = AutoReport("submit")
        t0 = time.time()
        sub = Submitter(self.cfg, self.store)
        if sub.profile_name:
            self.log(f"提交使用导入的接口: {sub.profile_name}")
        try:
            if flags:
                # 已经提交成功过的就别再交了：平台会判"重复"，还可能触发风控
                done = {f["value"] for f in self.store.flags() if f.get("submitted")}
                todo = [f for f in flags if f not in done]
                skipped = len(flags) - len(todo)
                if skipped:
                    self.log(f"跳过 {skipped} 个已提交过的 flag")
                for fl in todo:
                    r = sub.submit(fl, target)
                    rep.submitted.append({"flag": fl, "ok": r.ok, "message": r.message})
                    # 明确提交的 flag 也要回写状态，否则下一轮会被当成"待提交"再交一次
                    if r.ok:
                        try:
                            # 不按 target 过滤：flag 入库时的 target 是攻击目标名，
                            # 而这里提交用的 target 是 "auto"，按 target 找会一条都匹配不上
                            for row in self.store.flags():
                                if row["value"] == fl:
                                    self.store.mark_flag(row["id"], r.message, True)
                                    break
                        except Exception:  # noqa: BLE001
                            pass
                    self.log(f"{'成功' if r.ok else '失败'} {fl[:32]}: {r.message[:60]}",
                             "ok" if r.ok else "warn")
            else:
                rows = self.store.flags(only_pending=True)
                if not rows:
                    self.log("没有待提交的 flag")
                else:
                    res = sub.submit_all(only_pending=True)
                    rep.submitted = [{"flag": r.flag, "ok": r.ok, "message": r.message}
                                     for r in res]
        except Exception as e:  # noqa: BLE001
            rep.errors.append(f"提交失败: {e}")
        rep.elapsed = time.time() - t0
        return rep

    # ------------------------------------------------------------ 全流程
    def run(self, phases: Sequence[str] = ("defense", "attack", "submit")) -> Dict[str, Any]:
        t0 = time.time()
        out: Dict[str, Any] = {"phases": list(phases)}
        if "defense" in phases:
            out["defense"] = self.defend().to_dict()
        if "attack" in phases:
            ar = self.attack()
            out["attack"] = ar.to_dict()
            out["flags"] = ar.flags
        if "submit" in phases:
            out["submit"] = self.submit(out.get("flags") or None).to_dict()
        out["elapsed"] = round(time.time() - t0, 1)
        return out


def summarize(report: Dict[str, Any]) -> str:
    parts = []
    d = report.get("defense")
    if d:
        sm = d.get("summary") or {}
        parts.append(f"防守 {sm.get('targets', 0)} 台（{sm.get('failed', 0)} 步失败）")
    a = report.get("attack")
    if a:
        sm = a.get("summary") or {}
        parts.append(f"攻击 {sm.get('targets', 0)} 台，拿 {sm.get('flags', 0)} 个 flag")
    sub = report.get("submit")
    if sub:
        sm = sub.get("summary") or {}
        parts.append(f"提交成功 {sm.get('submitted_ok', 0)}/{sm.get('total', 0)}")
    return " · ".join(parts) if parts else "无动作"


class AutoLoop:
    """定时自动作战：每 N 分钟跑一轮"守 + 打 + 交"。

    和 AutoPilot 分开是因为职责不同：AutoPilot 是"做一轮"，AutoLoop 是"按节奏反复做"。
    循环里不抛异常也不退出——比赛现场任何一次失败都不该让定时器停掉。
    """

    def __init__(self, cfg: Config, store: Store):
        import threading
        self.cfg = cfg
        self.store = store
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[Any] = None
        self.running = False
        self.interval = 300
        self.phases: List[str] = ["defense", "attack", "submit"]
        self.rounds = 0
        self.started = 0.0
        self.last_run = 0.0
        self.next_run = 0.0
        self.last_summary = ""
        self.last_error = ""

    def state(self) -> Dict[str, Any]:
        now = time.time()
        return {"running": self.running, "interval": self.interval,
                "phases": self.phases, "rounds": self.rounds,
                "started": self.started,
                "last_run": self.last_run,
                "next_in": max(0, round(self.next_run - now, 1)) if self.running else 0,
                "last_summary": self.last_summary,
                "last_error": self.last_error}

    def start(self, interval: int = 300, phases: Optional[List[str]] = None) -> Dict[str, Any]:
        import threading
        with self._lock:
            if self.running:
                return self.state()
            self.interval = max(60, int(interval))
            if phases is not None:
                picked = [x for x in phases if x in ("defense", "attack", "submit")]
                # 空数组要报错：不传(None)才表示"沿用默认全流程"
                if not picked:
                    raise ValueError("至少选一个阶段（defense / attack / submit）")
                self.phases = picked
            self.running = True
            self.rounds = 0
            self.started = time.time()
            self.next_run = time.time()
            self.last_error = ""
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="auto-loop", daemon=True)
            self._thread.start()
            return self.state()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._stop.set()
            self.running = False
            self.next_run = 0
        return self.state()

    def _loop(self) -> None:
        import json as _json
        while not self._stop.is_set():
            try:
                ap = AutoPilot(self.cfg, self.store, log=lambda m, lv="info": None)
                report = ap.run(tuple(self.phases))
                self.rounds += 1
                self.last_run = time.time()
                self.last_summary = summarize(report)
                report["summary_text"] = self.last_summary
                self.store.set_setting("auto.last", _json.dumps(report, ensure_ascii=False))
                self.store.event("action", target="-", title=f"定时自动作战 · 第 {self.rounds} 轮",
                                 data={"summary": self.last_summary})
            except Exception as e:  # noqa: BLE001
                self.last_error = f"{type(e).__name__}: {e}"
                self.store.event("action", target="-", title="定时自动作战失败",
                                 severity="high", data={"error": self.last_error})
            with self._lock:
                self.next_run = time.time() + self.interval
            if self._stop.wait(self.interval):
                break

"""自动作战编排的离线测试：不连网，全部用假的模块替身。

真正容易出错的是**判断**而不是连接：WAF 在跑就不该重装、查到后门才加固、
同一个 flag 不该重复提交。这些用替身测最快。
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import ctfops.autopilot as A            # noqa: E402
import ctfops.backup as B               # noqa: E402
import ctfops.exploit as E              # noqa: E402
import ctfops.flag as F                 # noqa: E402
import ctfops.replay as R               # noqa: E402
import ctfops.waf as W                 # noqa: E402
import ctfops.webscan as WS             # noqa: E402
from ctfops.config import Config, Target  # noqa: E402
from ctfops.store import Store            # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}" + (f"  [{detail}]" if detail else ""))


class Calls:
    def __init__(self) -> None:
        self.log: list = []

    def add(self, name: str, **kw) -> None:
        self.log.append((name, kw))

    def names(self) -> list:
        return [x[0] for x in self.log]

    def kw(self, name: str) -> dict:
        for n, k in self.log:
            if n == name:
                return k
        return {}


def build(tmp: pathlib.Path) -> Config:
    cfg = Config(path=tmp / "config.yaml", workdir=tmp, name="auto-test")
    cfg.targets = [
        Target(name="d1", host="10.0.0.1", role="defense", webroot="/var/www/html"),
        Target(name="a1", host="10.0.0.2", role="attack", web=["http://10.0.0.2"]),
    ]
    cfg.submit.mode = "manual"
    cfg.submit.interval = 0
    cfg.ensure_dirs()
    return cfg


def patch(calls: Calls, *, waf_running: bool, malicious: int) -> None:
    W.status = lambda cfg, t: W.WafState(running=waf_running, engine="php", mode="enforce")
    W.deploy = lambda cfg, t, **kw: (calls.add("deploy", **kw) or
                                     {"ok": True, "engine": "php", "mode": "monitor"})
    W.enforce = lambda cfg, t, **kw: (calls.add("enforce", **kw) or
                                      {"ok": True, "engine": "php",
                                       "blocked_rules": kw.get("rule_ids") or [],
                                       "banned": 0})
    W.collect = lambda cfg, store, ts, **kw: (calls.add("collect") or
                                              {"targets": len(ts),
                                               "hits": [{"rule_id": "sqli", "name": "SQL 注入",
                                                         "severity": "critical", "count": 2,
                                                         "last_ip": "1.1.1.1",
                                                         "sample": {"method": "GET",
                                                                    "path": "/?id=1",
                                                                    "ua": "sqlmap"}}]})

    B.backup_root = lambda cfg, store: cfg.workdir / "backups"
    B.backup_target = lambda cfg, t, **kw: (calls.add("backup") or
                                            B.BackupResult(t.name, True, "/tmp/x.tgz",
                                                           "/tmp/x.tgz", 1024, "ab" * 32,
                                                           "ok", source="/var/www/html"))

    def fake_scan(cfg, t, **kw):
        calls.add("scan")
        rep = WS.ShellReport(root=f"{t.name}:/var/www/html", files=8,
                             malicious=malicious, suspicious=0)
        if malicious:
            from ctfops.exploit import Finding
            pass
        return rep

    WS.scan_remote = fake_scan

    E.load_plugins = lambda include=None: {
        "p_ok": E.Plugin(name="p_ok", description="", kind="web", severity="high",
                         tags=[], path="p_ok.py", exploit=lambda ctx: {"ok": True,
                                                       "evidence": "flag{auto_1}",
                                                       "flags": ["flag{auto_1}"]},
                         check=lambda ctx: True),
        "p_miss": E.Plugin(name="p_miss", description="", kind="web", severity="high",
                           tags=[], path="p_miss.py", exploit=lambda ctx: {"ok": True},
                           check=lambda ctx: False),
    }
    E.run_plugin = lambda cfg, plugin, target, **kw: (
        calls.add(f"plugin:{plugin.name}") or
        E.ExploitResult(target.name, plugin.name,
                        bool(plugin.name == "p_ok"),
                        "RCE ok, flag{auto_1} leaked" if plugin.name == "p_ok" else "evidence",
                        ["flag{auto_1}"] if plugin.name == "p_ok" else [], elapsed=0.1))

    R.replay_many = lambda cfg, vulns, ts, **kw: (calls.add("replay") or
                                                  [{"target": ts[0].name, "ok": True,
                                                    "method": "GET", "url": "/?id=1",
                                                    "status": 200, "length": 10,
                                                    "flags": []}])


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="autotest_"))
    cfg = build(tmp)
    store = Store(tmp / "evidence" / "ops.db")
    calls = Calls()

    print("[1] 防守：WAF 没跑 → 部署；查到后门 → 加固")
    patch(calls, waf_running=False, malicious=2)
    ap = A.AutoPilot(cfg, store, log=lambda m, lv="info": None)
    rep = ap.defend()
    names = calls.names()
    check("部署了 WAF", "deploy" in names, str(names))
    check("做了备份", "backup" in names)
    check("做了查杀", "scan" in names)
    check("查杀后自动加固", "enforce" in names, str(names))
    check("把 WAF 命中入库", "collect" in names)
    check("没有异常", not rep.errors, str(rep.errors))
    steps = {s.action: s for s in rep.defense}
    check("步骤齐全", {"部署 WAF", "基线备份", "后门查杀", "自动加固", "攻击入库"} <= set(steps),
          str(list(steps)))
    check("入库写进漏洞库", len(store.vulns()) >= 1, str(len(store.vulns())))

    print("[2] 防守：WAF 已在跑、无后门 → 不重装、不加固")
    calls2 = Calls()
    patch(calls2, waf_running=True, malicious=0)
    rep2 = A.AutoPilot(cfg, store, log=lambda m, lv="info": None).defend()
    names2 = calls2.names()
    check("没有重复部署", "deploy" not in names2, str(names2))
    check("没有误加固", "enforce" not in names2, str(names2))
    steps2 = {s.action: s for s in rep2.defense}
    check("WAF 状态标为已运行", steps2["WAF 状态"].detail.startswith("php"), 
          steps2["WAF 状态"].detail)

    print("[3] 防守：当天已有备份就不再备")
    calls3 = Calls()
    patch(calls3, waf_running=True, malicious=0)
    A.AutoPilot(cfg, store, log=lambda m, lv="info": None).defend(do_backup=True)
    again = Calls()
    patch(again, waf_running=True, malicious=0)
    A.AutoPilot(cfg, store, log=lambda m, lv="info": None).defend(do_backup=True)
    steps4 = {s.action: s for s in
              A.AutoPilot(cfg, store, log=lambda m, lv="info": None).defend().defense}
    check("备份步显示已有", "今天已有" in steps4["基线备份"].detail, steps4["基线备份"].detail)

    print("[4] 攻击：check 不中的插件不打，命中的收 flag")
    calls5 = Calls()
    patch(calls5, waf_running=True, malicious=0)
    ar = A.AutoPilot(cfg, store, log=lambda m, lv="info": None).attack(do_replay=True)
    pnames = [n for n in calls5.names() if n.startswith("plugin:")]
    check("两个插件都试了 check", set(pnames) == {"plugin:p_ok", "plugin:p_miss"}, str(pnames))
    check("收到 flag", ar.flags == ["flag{auto_1}"], str(ar.flags))
    check("flag 入库", any(f["value"] == "flag{auto_1}" for f in store.flags()))
    check("做了漏洞重放", "replay" in calls5.names(), str(calls5.names()))
    steps5 = {s.action: s for s in ar.attack}
    check("失败的插件标红", steps5["插件 p_miss"].ok is False)
    check("成功插件带证据", "flag{auto_1}" in steps5["插件 p_ok"].detail)

    print("[5] 提交：走 Submitter，成功/失败都能记录")
    sent = []

    class FakeSub:
        profile_name = "fake-platform"
        s = type("X", (), {"url": "http://x/{flag}", "method": "POST"})()

        def __init__(self, cfg, store, profile=None):
            pass

        def submit(self, flag, target=""):
            sent.append(flag)
            return F.SubmitResult(flag, flag.endswith("_ok"), "mock: " + flag)

        def submit_all(self, only_pending=True):
            return []

    F.Submitter = FakeSub
    sr = A.AutoPilot(cfg, store, log=lambda m, lv="info": None).submit(["flag{auto_1}"])
    check("提交被调用", sent == ["flag{auto_1}"], str(sent))
    check("提交结果有记录", sr.submitted and "ok" in sr.submitted[0], str(sr.submitted))

    print("[6] 报告结构 + 一句话总结")
    d = ar.to_dict()
    check("报告字段完整", {"phase", "steps", "summary", "flags", "errors"} <= set(d), str(list(d)))
    text = A.summarize({"defense": rep.to_dict(), "attack": d,
                        "submit": sr.to_dict()})
    check("总结可读", "防守" in text and "攻击" in text and "提交" in text, text)

    print("[7] 没有对应角色的靶机时不炸")
    cfg2 = Config(path=tmp / "c2.yaml", workdir=tmp, name="empty")
    cfg2.ensure_dirs()
    ap2 = A.AutoPilot(cfg2, Store(tmp / "e2.db"), log=lambda m, lv="info": None)
    r1 = ap2.defend()
    r2 = ap2.attack()
    check("无防守靶机给出提示", r1.errors and "防守靶机" in r1.errors[0], str(r1.errors))
    check("无攻击目标给出提示", r2.errors and "攻击目标" in r2.errors[0], str(r2.errors))

    print(f"\n结果：{PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""AWD 轮次监控自测：不连真靶机，用假 probe 驱动"换 flag"场景。

覆盖的是真正容易出错的地方：
  - 同一批 flag 重复读到，不能重复计轮、不能重复提交
  - flag 内容变了，必须识别为新一轮
  - 进程重启后，已知集合要能从库里恢复（否则会把旧 flag 当新 flag 再交一遍）
  - 关掉自动提交时，只入库不提交
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import ctfops.round as R                       # noqa: E402
from ctfops.config import Config, Target        # noqa: E402
from ctfops.store import Store                  # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}" + (f"  [{detail}]" if detail else ""))


def build_cfg(tmp: pathlib.Path) -> Config:
    cfg = Config(path=tmp / "config.yaml", workdir=tmp, name="round-test")
    cfg.targets = [Target(name="d1", host="10.9.9.1", role="defense"),
                   Target(name="d2", host="10.9.9.2", role="defense"),
                   Target(name="a1", host="10.9.9.3", role="attack")]
    cfg.submit.mode = "manual"
    cfg.submit.url = ""
    cfg.submit.interval = 0
    cfg.ensure_dirs()
    return cfg


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="roundtest_"))
    cfg = build_cfg(tmp)
    store = Store(tmp / "evidence" / "ops.db")

    # 假靶机：这张表就是"平台上当前的 flag"
    world = {"d1": ["flag{round1_a}"], "d2": ["flag{round1_b}"]}
    R.probe_target = lambda cfg_, t, deep=False, max_seconds=60: list(world.get(t.name, []))

    print("[1] 第一轮：发现全部 flag")
    w = R.RoundWatcher(cfg, store)
    ev = {e.target: e for e in w.tick(cfg.resolve(["d1", "d2"]))}
    check("d1 判定为变化", ev["d1"].changed, str(ev["d1"]))
    check("d1 新 flag 正确", ev["d1"].new_flags == ["flag{round1_a}"], str(ev["d1"].new_flags))
    check("轮次推进到 1", w.state()["round_no"] == 1, str(w.state()["round_no"]))
    check("提交结果已记录",
          all(len(e.submitted) == len(e.new_flags) for e in ev.values()),
          str({k: v.submitted for k, v in ev.items()}))
    check("入库 2 个 flag", len(store.flags()) == 2, str([f["value"] for f in store.flags()]))
    outbox = list((cfg.workdir / "outbox").glob("flags_*.txt"))
    check("outbox 已写入", bool(outbox) and
          "flag{round1_a}" in outbox[0].read_text(encoding="utf-8"))

    print("[2] 第二轮：内容没变，不能重复计轮/提交")
    ev2 = {e.target: e for e in w.tick(cfg.resolve(["d1", "d2"]))}
    check("d1 未变化", not ev2["d1"].changed)
    check("轮次仍是 1", w.state()["round_no"] == 1, str(w.state()["round_no"]))
    check("flag 总数没变", len(store.flags()) == 2, str(len(store.flags())))
    unchanged = [r for r in store.rounds() if r["changed"] == 0]
    check("记录了未变化行", len(unchanged) >= 2, str(len(unchanged)))

    print("[3] 第三轮：平台换了 flag")
    world["d1"] = ["flag{round2_a}"]
    ev3 = {e.target: e for e in w.tick(cfg.resolve(["d1", "d2"]))}
    check("d1 识别为刷新", ev3["d1"].changed and ev3["d1"].new_flags == ["flag{round2_a}"],
          str(ev3["d1"].new_flags))
    check("轮次推进到 2", w.state()["round_no"] == 2, str(w.state()["round_no"]))
    check("flag 入库到 3 个", len(store.flags()) == 3, str(len(store.flags())))
    # d2 的旧 flag 依然在，不应该被当成新的
    check("未变的靶机不产生新 flag", not ev3["d2"].changed)

    print("[4] 进程重启：已知集合从库里恢复")
    w2 = R.RoundWatcher(cfg, store)
    check("恢复后已知 d1 集合", "flag{round2_a}" in w2._known.get("d1", set()),
          str(w2._known))
    ev4 = {e.target: e for e in w2.tick(cfg.resolve(["d1", "d2"]))}
    check("重启后不误判", not ev4["d1"].changed and not ev4["d2"].changed)
    check("轮次没变", w2.state()["round_no"] == 2, str(w2.state()["round_no"]))

    print("[5] 关闭自动提交：只入库，不动 outbox")
    before = len(list((cfg.workdir / "outbox").glob("flags_*.txt"))[0].read_text().splitlines())
    w3 = R.RoundWatcher(cfg, store)
    w3.rc.auto_submit = False
    world["d2"] = ["flag{round3_b}"]
    ev5 = {e.target: e for e in w3.tick(cfg.resolve(["d1", "d2"]))}
    check("d2 识别为刷新", ev5["d2"].changed, str(ev5["d2"].new_flags))
    check("入库成功", any(f["value"] == "flag{round3_b}" for f in store.flags()))
    after = len(list((cfg.workdir / "outbox").glob("flags_*.txt"))[0].read_text().splitlines())
    check("outbox 没增加", after == before, f"{before} -> {after}")

    print("[6] 多 flag 同一台机器（一次扫出多个）")
    world["d1"] = ["flag{multi_1}", "flag{multi_2}"]
    ev6 = {e.target: e for e in w3.tick(cfg.resolve(["d1"]))}
    check("两个都识别为新", sorted(ev6["d1"].new_flags) == ["flag{multi_1}", "flag{multi_2}"],
          str(ev6["d1"].new_flags))
    check("total 入库正确", len([f for f in store.flags()
                               if f["value"].startswith("flag{multi")]) == 2)

    print("[7] 重置已知（换场次）")
    w3.reset()
    check("已知清空", not w3.state()["known"])
    check("轮次归零", w3.state()["round_no"] == 0)
    ev7 = {e.target: e for e in w3.tick(cfg.resolve(["d1"]))}
    check("重置后旧 flag 又算'新'（预期行为）", ev7["d1"].changed)

    print("[8] 全库统计")
    st = store.round_stats()
    check("统计有行", st["rows"] > 0, str(st))
    check("有刷新的轮次数 >= 3", st["changed_rounds"] >= 3, str(st["changed_rounds"]))

    print(f"\n结果：{PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

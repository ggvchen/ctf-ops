"""FLAG 提取 / 收集 / 自动提交。

三个不变量：
1. 去重——同一个 flag 只提交一次（DB 唯一索引兜底）。
2. 可审计——每次提交的请求与响应都落盘。
3. 可降级——平台没有 API 时退化为 manual，写 outbox 文件提示人工粘贴。
"""

from __future__ import annotations

import json
import pathlib
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set

import requests

from .config import Config, Target
from .store import Store
from .util import console, iso_now, jdump, ok, pmap, sha256_text, warn

# 明确不是 flag 的噪声（正则误报过滤）
NOISE = {
    "flag{test}", "flag{demo}", "flag{example}", "flag{xxxx}",
    "flag{your_flag_here}", "flag{flag}",
}


def extract_flags(text: str, cfg: Config, limit: int = 50) -> List[str]:
    if not text:
        return []
    found: List[str] = []
    seen: Set[str] = set()
    for pat in cfg.flag_patterns:
        try:
            rx = re.compile(pat)
        except re.error:
            continue
        for m in rx.finditer(text):
            v = m.group(0).strip().strip("\"'`<>()[]")
            if v.lower() in NOISE or len(v) < 6:
                continue
            if v in seen:
                continue
            seen.add(v)
            found.append(v)
            if len(found) >= limit:
                return found
    return found


# ------------------------------------------------------------------ 收集
def hunt_remote(cfg: Config, target: Target, roots: Optional[List[str]] = None,
                max_seconds: int = 120) -> List[str]:
    """SSH 上去 grep flag —— AWD 里最快拿分的方式（flag 通常落在 /flag、/tmp、web 目录）。"""
    from .sshx import SSHSession

    roots = roots or cfg.log_roots
    roots = [r for r in roots if r]
    # grep -r 在所有 root 上，限制文件大小与时间
    pat = "|".join(f"({p})" for p in cfg.flag_patterns[:4])
    grep = (
        "timeout {t} grep -rEa --binary-files=text -I "
        "--include='*' -m1 --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev "
        "-e {pat} {roots} 2>/dev/null | head -200"
    ).format(t=max_seconds, pat=_shq(pat), roots=" ".join(_shq(r) for r in roots))
    try:
        with SSHSession(target, cfg) as sess:
            r = sess.exec(grep, timeout=max_seconds + 30)
            text = r.out
            # 常见固定位置补充探测
            extra = sess.exec(
                "for f in /flag /flag.txt /root/flag /root/flag.txt /tmp/flag /home/*/flag*;"
                " do [ -f \"$f\" ] && echo \"== $f\" && head -c 2000 \"$f\"; done 2>/dev/null",
                timeout=30)
            return extract_flags(text + "\n" + extra.out, cfg)
    except Exception as e:  # noqa: BLE001
        warn(f"{target.name} flag 检索失败: {e}")
        return []


def hunt_http(urls: Iterable[str], cfg: Config, timeout: int = 8) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    sess = requests.Session()
    sess.verify = False
    sess.trust_env = False        # 靶机直连，避免被 HTTP_PROXY 劫持
    sess.headers["User-Agent"] = "Mozilla/5.0 (compatible; ctf-ops/1.0)"
    for u in urls:
        try:
            r = sess.get(u, timeout=timeout, allow_redirects=True)
            got = extract_flags(r.text or "", cfg)
            if got:
                out[u] = got
        except Exception:
            continue
    return out


def hunt_local(paths: Iterable[str], cfg: Config, max_bytes: int = 8 << 20) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for p in paths:
        root = pathlib.Path(p).expanduser()
        files = [root] if root.is_file() else list(root.rglob("*"))[:20000] if root.exists() else []
        for f in files:
            if not f.is_file() or f.stat().st_size > max_bytes:
                continue
            try:
                data = f.read_bytes()[:1 << 20]
            except Exception:
                continue
            text = data.decode("utf-8", "replace")
            got = extract_flags(text, cfg, limit=5)
            if got:
                out[str(f)] = got
    return out


# ------------------------------------------------------------------ 提交
@dataclass
class SubmitResult:
    flag: str
    ok: bool
    message: str
    raw: str = ""
    elapsed: float = 0.0


class Submitter:
    """提交器。

    配置来源有两处，优先级：**库里激活的导入配置** > `config.yaml` 的 submit 段。
    这样从浏览器 cURL 导入的接口可以直接生效，不用去改 YAML。
    """

    def __init__(self, cfg: Config, store: Store, profile: Optional[str] = None):
        self.cfg = cfg
        self.store = store
        self.s = cfg.submit
        self.profile_name = ""
        try:
            prof = None
            if profile:
                prof = next((p for p in store.submit_profiles() if p["name"] == profile), None)
            else:
                prof = store.active_submit_profile()
            if prof and isinstance(prof.get("config"), dict):
                self._apply_profile(prof["config"])
                self.profile_name = prof["name"]
        except Exception:  # noqa: BLE001
            # 配置读不到就退回 YAML，不能因为导入配置把提交流程搞挂
            self.s = cfg.submit
        self.outbox = cfg.workdir / "outbox"
        self.log_dir = cfg.workdir / "logs" / "submit"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.outbox.mkdir(parents=True, exist_ok=True)

    def _apply_profile(self, conf: Dict[str, Any]) -> None:
        import copy

        s = copy.deepcopy(self.cfg.submit)
        s.mode = "generic_http"
        for key in ("url", "method", "json_body", "form_body", "raw_body",
                    "headers", "success_key", "success_value", "message_key",
                    "token", "strict"):
            if key in conf and conf[key] is not None:
                setattr(s, key, conf[key])
        self.s = s

    # ---------- 单次 ----------
    def _looks_like_flag(self, flag: str) -> bool:
        """提交前先看形状对不对。

        库里混进过"查杀证据片段"这种垃圾数据，如果不过滤，每轮提交都要
        为它们各等一次超时重试，把定时任务彻底拖死。
        """
        pats = getattr(self.cfg, "flag_patterns", None) or []
        if not pats:
            return True
        for p in pats:
            try:
                if re.search(p, flag):
                    return True
            except re.error:
                continue
        return False

    def submit(self, flag: str, target: str = "", force: bool = False) -> SubmitResult:
        t0 = time.time()
        if not force and not self._looks_like_flag(flag):
            return SubmitResult(flag, False,
                                 "不像 flag（不符合配置里的 flag_patterns），已跳过",
                                 elapsed=time.time() - t0)
        if self.s.mode == "manual" or not self.s.url:
            self._to_outbox(flag, target)
            return SubmitResult(flag, True,
                                "manual: 已写入 outbox，需人工粘贴", elapsed=time.time() - t0)
        last: Optional[SubmitResult] = None
        for attempt in range(1, self.s.retries + 1):
            try:
                res = self._http(flag, target)
                self._audit(flag, target, res.raw, res.message)
                if res.ok:
                    return res
                last = res
            except Exception as e:  # noqa: BLE001
                last = SubmitResult(flag, False, f"异常: {e}", elapsed=time.time() - t0)
                self._audit(flag, target, repr(e), "exception")
            if attempt < self.s.retries:
                time.sleep(1.5 * attempt)
        return last or SubmitResult(flag, False, "未知失败")

    def _http(self, flag: str, target: str) -> SubmitResult:
        t0 = time.time()
        mapping = {"flag": flag, "target": target, "host": target, "token": self.s.token}
        # URL 里的 flag 必须转义（flag{..} 里的花括号会破坏查询串）
        url_map = dict(mapping, flag=urllib.parse.quote(flag, safe=""))
        url = self.s.url.format(**url_map) if "{" in (self.s.url or "") else self.s.url
        headers = {k: (v.format(**mapping) if "{" in str(v) else v)
                   for k, v in (self.s.headers or {}).items()}
        if self.s.token and not any(k.lower() == "authorization" for k in headers):
            headers["Authorization"] = f"Bearer {self.s.token}"
        body_json = _fmt_dict(self.s.json_body, mapping)
        body_form = _fmt_dict(self.s.form_body, mapping)

        sess = requests.Session()
        sess.trust_env = bool(self.s.use_proxy)
        raw_body = self.s.raw_body or ""
        if raw_body:
            raw_body = raw_body.replace("{flag}", flag).replace("{target}", target)

        if body_json is not None:
            r = sess.request(self.s.method.upper(), url, json=body_json,
                             headers=headers, timeout=self.s.timeout, verify=False)
        elif raw_body:
            r = sess.request(self.s.method.upper(), url, data=raw_body.encode("utf-8"),
                             headers=headers, timeout=self.s.timeout, verify=False)
        elif body_form is not None:
            r = sess.request(self.s.method.upper(), url, data=body_form,
                             headers=headers, timeout=self.s.timeout, verify=False)
        else:
            r = sess.request(self.s.method.upper(), url, headers=headers,
                             timeout=self.s.timeout, verify=False)
        sess.close()
        okflag, msg = _judge(r, self.s)
        return SubmitResult(flag, okflag, msg, raw=_raw(r), elapsed=time.time() - t0)

    # ---------- 批量 ----------
    def submit_all(self, only_pending: bool = True, workers: int = 1) -> List[SubmitResult]:
        rows = self.store.flags(only_pending=only_pending)
        if not rows:
            console.print("[dim]没有待提交的 flag[/dim]")
            return []
        results: List[SubmitResult] = []

        def one(row: Dict[str, Any]) -> SubmitResult:
            res = self.submit(row["value"], row.get("target", ""))
            self.store.mark_flag(row["id"], res.message, res.ok)
            icon = "[green]✓[/green]" if res.ok else "[red]✗[/red]"
            console.print(f"{icon} [bold]{row['value'][:40]}[/bold] "
                          f"({row.get('target','-')}) {res.message[:80]}")
            return res

        for res in pmap(one, rows, workers=max(1, workers), label="submit"):
            if isinstance(res, Exception):
                warn(str(res))
                continue
            results.append(res)
            if self.s.mode != "manual" and self.s.interval:
                time.sleep(self.s.interval)
        good = sum(1 for r in results if r.ok)
        ok(f"提交完成: {good}/{len(results)} 成功")
        return results

    # ---------- 落盘 ----------
    def _to_outbox(self, flag: str, target: str) -> None:
        f = self.outbox / f"flags_{time.strftime('%Y%m%d')}.txt"
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(f"{iso_now()}\t{target or '-'}\t{flag}\n")

    def _audit(self, flag: str, target: str, raw: str, msg: str) -> None:
        rec = {"ts": iso_now(), "flag": flag, "target": target, "msg": msg, "raw": raw[:4000]}
        with open(self.log_dir / f"submit_{time.strftime('%Y%m%d')}.jsonl", "a",
                  encoding="utf-8") as fh:
            fh.write(jdump(rec) + "\n")


def _fmt_dict(d: Optional[Dict[str, Any]], mapping: Dict[str, str]) -> Optional[Dict[str, Any]]:
    if d is None:
        return None
    out: Dict[str, Any] = {}
    for k, v in d.items():
        out[k] = v.format(**mapping) if isinstance(v, str) and "{" in v else v
    return out


def _judge(r: requests.Response, s) -> tuple:
    txt = (r.text or "")[:2000]
    if r.status_code >= 400:
        return False, f"HTTP {r.status_code} {txt[:120]}"
    try:
        data = r.json()
    except Exception:
        low = txt.lower()
        if any(k in low for k in ("success", "correct", "right", "accepted", "ok")):
            return True, f"HTTP {r.status_code} 文本判定成功"
        if any(k in low for k in ("wrong", "fail", "error", "invalid", "duplicate", "already")):
            return False, f"HTTP {r.status_code} 文本判定失败: {txt[:80]}"
        if getattr(s, "strict", False):
            return False, f"HTTP {r.status_code} 响应无明确成功标志: {txt[:100]}"
        return True, f"HTTP {r.status_code} 无 JSON，按成功处理"
    val = _dig(data, s.success_key)
    if val is None:
        # 平台常见字段兜底
        for k in ("success", "correct", "status", "code", "ret"):
            if k in data:
                val = data[k]
                break
    success = _loose_true(val)
    msg = _dig(data, s.message_key) or data.get("msg") or data.get("message") or txt[:120]
    return success, f"{msg}"


def _dig(data: Any, key: str) -> Any:
    if not key:
        return None
    cur = data
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _loose_true(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v in (1, 200, 0)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "success", "ok", "correct", "accepted", "200")
    return False


def _raw(r: requests.Response) -> str:
    return f"{r.request.method} {r.request.url}\n--- resp {r.status_code} ---\n{r.text[:1500]}"


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


# ------------------------------------------------------------------ 编排
def collect_and_submit(cfg: Config, store: Store, targets: List[Target],
                       submit: bool = True, workers: int = 8) -> Dict[str, List[str]]:
    """AWD 模式一键：远端找 flag -> 入库 -> 提交。"""
    found: Dict[str, List[str]] = {}

    def one(t: Target) -> tuple:
        return t.name, hunt_remote(cfg, t)

    for name, flags in pmap(one, targets, workers=min(workers, max(1, len(targets))),
                            label="flag-hunt"):
        if isinstance(flags, Exception):
            warn(f"{name}: {flags}")
            continue
        found[name] = flags

    total_new = 0
    for name, flags in found.items():
        for f in flags:
            if store.add_flag(f, target=name, source="ssh-hunt"):
                total_new += 1
                console.print(f"[green]+[/green] {name}  {f}")
    if total_new == 0:
        console.print("[dim]本轮未发现新 flag[/dim]")
    else:
        ok(f"新增 {total_new} 个 flag")
    if submit and total_new:
        Submitter(cfg, store).submit_all(only_pending=True)
    return found

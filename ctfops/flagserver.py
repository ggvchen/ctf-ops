"""经靶机访问 flag 服务器取 flag。

为什么要在靶机上执行，而不是本机直接 requests：
AWD 的 flag 接口几乎都只对内网开放（10.x / 172.16.x），而且多数要求用
**本队 token**、甚至要求请求来自靶机自己的 IP。本机直连拿不到，SSH 到靶机
上 curl 一下才有。所以这里的核心动作是"在靶机上跑一条 HTTP 请求"。

三种取法，按靶机上有什么自动降级：
  1. curl     —— 绝大多数镜像都有
  2. wget     —— 精简镜像常见（busybox）
  3. python3  —— 只有 python 的镜像
另外留一个 cmd 模式：平台给的是 ./readflag 这类本地命令时直接写命令。

token 有两个来源：配置里写死，或从靶机上读（token_cmd，比如 cat /flag_token）。
后者更贴近实际：平台会把每队 token 落到靶机文件里。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .config import Config, Target
from .store import Store
from .util import iso_now, trunc

SETTING_KEY = "flagserver"
LAST_KEY = "flagserver.last"

DEFAULTS: Dict[str, Any] = {
    "enabled": True,
    "mode": "http",                  # http | cmd
    # ---- http 模式 ----
    "url": "",                       # 如 http://10.10.0.1/api/flag?token={token}&host={ip}
    "method": "GET",
    "headers": {},                   # {"X-Token": "{token}"}
    "body": "",                      # POST 内容，同样支持占位符
    "field": "",                     # 响应 JSON 里 flag 的位置，如 data.flag；留空=正则扫全文
    "insecure": True,                # curl -k，跳过 https 证书校验
    # ---- cmd 模式 ----
    "cmd": "",                       # 如 ./readflag 或 cat /flag
    # ---- 凭据 ----
    "token": "",
    "token_cmd": "cat /flag_token 2>/dev/null || cat /token 2>/dev/null || cat /etc/flag_token 2>/dev/null",
    "tokens": {},                    # 逐机 token：{"web-01": "xxx"}
    "trust_field": False,            # True: field 取到的值即使不像 flag 也照收（自定义格式平台）
    # ---- 运行 ----
    "tool": "auto",                  # auto | curl | wget | python3
    "timeout": 10,
    "use_proxy": False,              # 靶机侧是否带本机代理变量（内网一般 False）
    "workers": 6,
    "submit_after": True,            # 拉到就提交
    "scope": "defense",              # defense | attack | all
}

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_]+)\}")
# {token} 原样、{token_url} 做 URL 编码（base64 里的 + / = 进查询串必须转义）
VAR_EXPR = {"token": "$TK", "tk": "$TK",
            "token_url": "$TKU", "token_enc": "$TKU", "tkurl": "$TKU"}
_VAR_KEYS = set(VAR_EXPR)
_URLENCODE_KEYS = {"token_url", "token_enc", "tkurl"}


def _shq(s: str) -> str:
    """单引号包裹，内部单引号按 shell 规矩拼接。"""
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


# ------------------------------------------------------------------ 配置
def defaults() -> Dict[str, Any]:
    return json.loads(json.dumps(DEFAULTS))


def load_conf(cfg: Config, store: Store) -> Dict[str, Any]:
    """DB 里页面保存的配置 > config.yaml 的 flagserver 段 > 内置默认。"""
    conf = defaults()
    yaml_conf = (getattr(cfg, "extra", {}) or {}).get("flagserver")
    if isinstance(yaml_conf, dict):
        conf.update({k: v for k, v in yaml_conf.items() if v is not None})
    try:
        raw = store.get_setting(SETTING_KEY, "")
        if raw:
            saved = json.loads(raw)
            if isinstance(saved, dict):
                conf.update({k: v for k, v in saved.items() if v is not None})
    except Exception:  # noqa: BLE001
        pass
    return conf


def save_conf(store: Store, conf: Dict[str, Any]) -> Dict[str, Any]:
    clean = defaults()
    clean.update({k: v for k, v in (conf or {}).items() if k in DEFAULTS})
    store.set_setting(SETTING_KEY, json.dumps(clean, ensure_ascii=False))
    return clean


# ------------------------------------------------------------------ 结果
@dataclass
class FetchResult:
    target: str
    host: str
    ok: bool = False
    flags: List[str] = field(default_factory=list)
    cmd: str = ""
    out: str = ""
    error: str = ""
    rc: int = -1
    tool: str = ""
    elapsed: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "host": self.host, "ok": self.ok,
            "flags": self.flags, "cmd": self.cmd, "out": trunc(self.out, 4000),
            "error": self.error, "rc": self.rc, "tool": self.tool,
            "elapsed": round(self.elapsed, 2),
        }


# ------------------------------------------------------------------ 命令拼装
def _join_quoted(tpl: str, values: Dict[str, str]) -> str:
    """把模板切成"字面量 + 变量"片段，各自加引号后拼接。

    'http://h/api?token='"$TK"'&host=10.1.1.1'
    这样 token 里的特殊字符不会破坏命令，URL 里原有的 $ 也不会被 shell 二次展开。
    相邻字面量会合并成一段，生成的命令人也能读。
    """
    if tpl is None:
        return "''"
    out: List[str] = []
    buf: List[str] = []

    def flush() -> None:
        if buf:
            out.append(_shq("".join(buf)))
            buf.clear()

    for part in _PLACEHOLDER_RE.split(tpl or ""):
        if not part:
            continue
        if _PLACEHOLDER_RE.fullmatch("{" + part + "}"):
            key = part.lower()
            if key in _VAR_KEYS:
                flush()
                out.append('"' + VAR_EXPR[key] + '"')
            else:
                buf.append(values.get(key, ""))
        else:
            buf.append(part)
    flush()
    return "".join(out) or "''"


def _target_values(t: Target) -> Dict[str, str]:
    return {"ip": t.host, "host": t.host, "name": t.name, "target": t.name}


def _needs_urlenc(conf: Dict[str, Any]) -> bool:
    blob = " ".join(str(conf.get(k) or "") for k in ("url", "body"))
    blob += " " + " ".join(str(v) for v in (conf.get("headers") or {}).values())
    return any("{" + k + "}" in blob for k in _URLENCODE_KEYS)


# 只转义真会破坏查询串的字符：POSIX sed 就能做，目标机不需要 python
_URLENC_SED = (
    "sed -e 's/%/%25/g' -e 's/ /%20/g' -e 's/#/%23/g' -e 's/&/%26/g' "
    "-e 's/+/%2B/g' -e 's/?/%3F/g' -e 's/=/%3D/g'"
)


def _token_prefix(conf: Dict[str, Any], t: Target) -> str:
    """在靶机上把 TK（原样）与 TKU（URL 编码后）准备好。

    优先级：逐机 token > 全局 token > 靶机文件（token_cmd）。
    """
    per = (conf.get("tokens") or {}).get(t.name) or (conf.get("tokens") or {}).get(t.host)
    if per:
        head = f"TK={_shq(per)}; "
    elif conf.get("token"):
        head = f"TK={_shq(conf['token'])}; "
    elif conf.get("token_cmd"):
        # head -c 兜住某些镜像上会无限输出的怪文件
        head = "TK=$({{ {cmd} ; }} 2>/dev/null | head -c 512 | tr -d '\\r\\n'); ".format(
            cmd=conf["token_cmd"])
    else:
        head = "TK=''; "
    out = head + "export TK; "
    if _needs_urlenc(conf):
        out += f'TKU=$(printf %s "$TK" | {_URLENC_SED}); export TKU; '
    return out


def _wrap(inner: str) -> str:
    """包一层：输出落临时文件，拿到真实 rc，顺带限长。

    inner 可能带 heredoc（python3 那条），所以命令块必须换行收尾，
    不能写成 `{ ... ; }` 一行 —— heredoc 结束符后面跟着 `; }` 就终止不了。
    """
    return (
        "TMP=$(mktemp 2>/dev/null || echo /tmp/.ctfops.$$)\n"
        "{\n"
        f"{inner}\n"
        "} >\"$TMP\" 2>&1\n"
        "rc=$?\n"
        "head -c 8000 \"$TMP\"\n"
        "rm -f \"$TMP\"\n"
        "printf '\\n__RC__%s\\n' \"$rc\""
    )


def _headers(conf: Dict[str, Any], values: Dict[str, str]) -> List[str]:
    out = []
    for k, v in (conf.get("headers") or {}).items():
        out.append((str(k), _join_quoted(str(v), values)))
    return out


def _http_commands(conf: Dict[str, Any], t: Target) -> List[Tuple[str, str]]:
    """生成 [(工具, 命令)]，顺序即降级顺序。"""
    values = _target_values(t)
    url = (conf.get("url") or "").strip()
    if not url:
        raise ValueError("flagserver 地址为空（http 模式必须填 url）")
    method = (conf.get("method") or "GET").upper()
    timeout = max(2, int(conf.get("timeout") or 10))
    hdrs = _headers(conf, values)
    body = conf.get("body") or ""
    proxy = "" if conf.get("use_proxy") else "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY; "
    url_q = _join_quoted(url, values)
    cmds: List[Tuple[str, str]] = []

    # ---- curl ----（-w 把状态码带出来：rc=0 但 403 不能算成功）
    parts = ["curl", "-sS", "-m", str(timeout)]
    if conf.get("insecure", True):
        parts.append("-k")
    if method != "GET":
        parts += ["-X", method]
    for k, v in hdrs:
        parts += ["-H", f"{_shq(k + ': ')}{v}"]
    if body:
        parts += ["--data-binary", _join_quoted(body, values)]
    parts += ["-w", _shq("\\n__HTTP__%{http_code}")]
    cmds.append(("curl", " ".join(parts) + " " + url_q))

    # ---- wget ----
    w = ["wget", "-q", "-O", "-", f"--timeout={timeout}"]
    if conf.get("insecure", True):
        w.append("--no-check-certificate")
    for k, v in hdrs:
        w.append(f"--header={_shq(k + ': ')}{v}")
    if body:
        w.append("--post-data=" + _join_quoted(body, values))
        if method not in ("POST", "GET"):
            w.append(f"--method={method}")
    elif method != "GET":
        w.append(f"--method={method}")
    cmds.append(("wget", " ".join(w) + " " + url_q))

    # ---- python3 ----
    py = _python_script(conf, t, timeout)
    cmds.append(("python3", py))

    order = (conf.get("tool") or "auto").lower()
    if order in ("curl", "wget", "python3"):
        cmds = [c for c in cmds if c[0] == order] or cmds
    # 代理变量统一在工具前面清掉
    return [(tool, proxy + cmd) for tool, cmd in cmds]


def _python_script(conf: Dict[str, Any], t: Target, timeout: int) -> str:
    """只有 python3 的镜像用这个。token 通过环境变量 TK / TKU 传进来。"""
    values = _target_values(t)
    tk, tku = "__TK__", "__TKU__"

    def render(raw: str) -> str:
        def rep(m: re.Match) -> str:
            key = m.group(1).lower()
            if key in _URLENCODE_KEYS:
                return tku
            return tk if key in _VAR_KEYS else values.get(key, "")
        return _PLACEHOLDER_RE.sub(rep, str(raw or ""))

    url = render(conf.get("url") or "")
    headers = {str(k): render(v) for k, v in (conf.get("headers") or {}).items()}
    body = render(conf.get("body") or "")
    method = (conf.get("method") or "GET").upper()
    src = [
        "import os,ssl,json,urllib.request",
        "TK=os.environ.get('TK','')",
        "TKU=os.environ.get('TKU','')",
        f"def sub(s): return s.replace({tk!r},TK).replace({tku!r},TKU)",
        f"url=sub({url!r})",
        f"headers={{k:sub(v) for k,v in {json.dumps(headers, ensure_ascii=False)}.items()}}",
        f"data=sub({body!r}).encode() if {bool(body)} else None",
        f"req=urllib.request.Request(url,data=data,headers=headers,method={method!r})",
        "ctx=ssl._create_unverified_context()" if conf.get("insecure", True) else "ctx=None",
        f"r=urllib.request.urlopen(req,timeout={timeout},context=ctx)",
        "print(r.read().decode('utf-8','replace'))",
    ]
    return "python3 - <<'__CTFOPS_PY__'\n" + "\n".join(src) + "\n__CTFOPS_PY__"


def build_commands(conf: Dict[str, Any], t: Target) -> List[Tuple[str, str]]:
    mode = (conf.get("mode") or "http").lower()
    if mode == "cmd":
        cmd = (conf.get("cmd") or "").strip()
        if not cmd:
            raise ValueError("cmd 模式必须填命令（如 ./readflag 或 cat /flag）")
        values = _target_values(t)
        return [("cmd", _PLACEHOLDER_RE.sub(
            lambda m: values.get(m.group(1).lower(), ""), cmd))]
    return _http_commands(conf, t)


# ------------------------------------------------------------------ 解析
def looks_like_flag(cfg: Config, value: str) -> bool:
    pats = getattr(cfg, "flag_patterns", None) or []
    if not pats:
        return True
    for p in pats:
        try:
            if re.search(p, value or ""):
                return True
        except re.error:
            continue
    return False


def _dig(data: Any, path: str) -> Any:
    cur = data
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _as_flags(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple)):
        out: List[str] = []
        for v in value:
            out.extend(_as_flags(v))
        return out
    if isinstance(value, dict):
        out = []
        for k in ("flag", "value", "data", "content"):
            if k in value:
                out.extend(_as_flags(value[k]))
        return out
    return [str(value).strip()]


def parse_flags(text: str, conf: Dict[str, Any], cfg: Config) -> List[str]:
    from .flag import extract_flags

    found: List[str] = []
    field = (conf.get("field") or "").strip()
    body = (text or "").strip()
    if body:
        # 掐头去尾：有些平台返回 JSON + 一段 HTML，直接 loads 会失败，退化成截取 {}
        for candidate in (body, _slice_json(body)):
            if not candidate:
                continue
            try:
                data = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                continue
            val = _dig(data, field) if field else None
            if val is None and not field:
                for k in ("flag", "data", "msg", "message", "result"):
                    hit = _dig(data, k)
                    if hit:
                        found.extend(_as_flags(hit))
                        break
            else:
                found.extend(_as_flags(val))
            break
    for f in extract_flags(text or "", cfg):
        found.append(f)
    out, seen = [], set()
    for f in found:
        f = (f or "").strip().strip("\"'`<>()[]")
        if not f or f in seen:
            continue
        if len(f) > 300:
            continue
        if not looks_like_flag(cfg, f) and not conf.get("trust_field"):
            continue
        seen.add(f)
        out.append(f)
    return out[:20]


def _slice_json(text: str) -> str:
    i, j = text.find("{"), text.rfind("}")
    return text[i:j + 1] if 0 <= i < j else ""


def _split_rc(out: str) -> Tuple[str, int]:
    m = re.search(r"__RC__(-?\d+)\s*$", out or "")
    if not m:
        return (out or ""), -1
    return (out or "")[:m.start()], int(m.group(1))


def _split_http(out: str) -> Tuple[str, int]:
    """剥掉 curl -w 带出来的状态码。"""
    m = re.search(r"__HTTP__(\d{3})\s*$", out or "")
    if not m:
        return (out or ""), 0
    return (out or "")[:m.start()], int(m.group(1))


# ------------------------------------------------------------------ 执行
def fetch_one(cfg: Config, t: Target, conf: Dict[str, Any]) -> FetchResult:
    from .sshx import SSHSession

    res = FetchResult(t.name, t.host)
    t0 = time.time()
    try:
        cands = build_commands(conf, t)
    except ValueError as e:
        res.error = str(e)
        return res
    prefix = _token_prefix(conf, t)
    timeout = max(5, int(conf.get("timeout") or 10)) + 10
    try:
        with SSHSession(t, cfg) as sess:
            for tool, inner in cands:
                cmd = prefix + _wrap(inner)
                r = sess.exec("bash -lc " + _shq(cmd), timeout=timeout + 8)
                out, rc = _split_rc((r.out or "") + (r.err or ""))
                out, http_code = _split_http(out)
                res.cmd, res.tool, res.rc, res.out = cmd, tool, rc, out
                # 只认"命令不存在"这种硬失败，不要把响应体里的 not found 当成缺工具
                missing = rc == 127 or "command not found" in (out or "").lower()
                if missing and tool != cands[-1][0]:
                    res.error = f"{tool} 不可用，降级到下一个"
                    continue
                res.ok = rc == 0 and (http_code == 0 or http_code < 400)
                res.flags = parse_flags(out, conf, cfg)
                if http_code >= 400:
                    res.error = f"HTTP {http_code}: {trunc((out or '').strip(), 200)}"
                elif not res.ok:
                    res.error = trunc((out or "").strip() or f"退出码 {rc}", 300)
                return res
    except Exception as e:  # noqa: BLE001
        res.error = str(e)
    finally:
        res.elapsed = time.time() - t0
    return res


def pick_targets(cfg: Config, conf: Dict[str, Any],
                 names: Optional[List[str]] = None) -> List[Target]:
    if names:
        return cfg.resolve(names)
    scope = (conf.get("scope") or "defense").lower()
    if scope == "all":
        return [t for t in cfg.targets if t.enabled]
    if scope == "attack":
        return cfg.resolve_role("attack")
    return cfg.resolve_role("defense")


def fetch_all(cfg: Config, store: Store, conf: Optional[Dict[str, Any]] = None,
              names: Optional[List[str]] = None, submit: Optional[bool] = None,
              log=None) -> Dict[str, Any]:
    from .util import pmap

    conf = conf or load_conf(cfg, store)
    targets = pick_targets(cfg, conf, names)
    if not targets:
        raise ValueError("没有可用的靶机（检查 flagserver.scope 与靶机启停状态）")
    say = log or (lambda *a, **k: None)
    say(f"目标 {len(targets)} 台，模式 {conf.get('mode')}，工具 {conf.get('tool')}")

    def one(t: Target) -> Dict[str, Any]:
        r = fetch_one(cfg, t, conf)
        row = r.to_dict()
        new = 0
        for f in r.flags:
            if store.add_flag(f, target=t.name, source="flagserver"):
                new += 1
        row["new"] = new
        icon = "✓" if r.ok else "✗"
        say(f"{icon} {t.name}: {len(r.flags)} 个 flag（新增 {new}）"
            + (f" · {r.error[:80]}" if r.error and not r.flags else ""),
            "ok" if r.flags else ("warn" if r.ok else "err"))
        if r.flags:
            store.event("flag", target=t.name, title="flagserver",
                        data={"flags": r.flags, "tool": r.tool})
        return row

    rows = []
    for row in pmap(one, targets, workers=min(int(conf.get("workers") or 4),
                                              max(1, len(targets))), label="flagserver"):
        if isinstance(row, Exception):
            say(str(row), "err")
            continue
        rows.append(row)

    total_new = sum(r.get("new") or 0 for r in rows)
    do_submit = conf.get("submit_after", True) if submit is None else submit
    submitted = {"ok": 0, "fail": 0, "skipped": 0}
    if do_submit and total_new:
        from .flag import Submitter
        sub = Submitter(cfg, store)
        pending = [r for r in store.flags(only_pending=True) if r.get("source") == "flagserver"]
        say(f"提交 {len(pending)} 个待提交 flag")
        for row in pending:
            res = sub.submit(row["value"], row.get("target", ""), force=True)
            store.mark_flag(row["id"], res.message, res.ok)
            submitted["ok" if res.ok else "fail"] += 1
            say(f"{'✓' if res.ok else '✗'} {row['value'][:40]} {res.message[:80]}",
                "ok" if res.ok else "err")
            if sub.s.interval:
                time.sleep(sub.s.interval)

    summary = {"rows": rows, "new": total_new, "submitted": submitted,
               "targets": len(targets), "ts": iso_now()}
    try:
        store.set_setting(LAST_KEY, json.dumps(
            {"ts": summary["ts"], "new": total_new, "submitted": submitted,
             "rows": [{k: v for k, v in r.items() if k != "cmd"} for r in rows]},
            ensure_ascii=False))
    except Exception:  # noqa: BLE001
        pass
    return summary


def last_run(store: Store) -> Dict[str, Any]:
    try:
        return json.loads(store.get_setting(LAST_KEY, "{}") or "{}")
    except Exception:  # noqa: BLE001
        return {}

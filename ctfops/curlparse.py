"""把浏览器开发者工具里「Copy as cURL」的请求，变成可直接用的提交配置。

比赛平台的提交接口千奇百怪：有的 POST JSON、有的 form、有的带一串自定义
header 和 CSRF token。手工在 YAML 里拼这些东西很容易错，而浏览器里
"Network → 右键 → Copy as cURL" 是现成的、100% 准确的请求描述。

所以这里做三件事：

1. **解析 cURL**：支持 Chrome / Edge 的 bash 形式（含 `$'...'`、反斜杠续行）、
   Firefox 的 bash 形式、以及 Windows 的 cmd 形式（`^` 续行 + 双引号）。
2. **找 flag 的位置**：在 URL 参数、form 字段、JSON 字段里认出"哪个值是 flag"
   （按 key 名 + 值的形状双重判断），把它替换成 `{flag}` 占位符。
3. **产出提交配置**：url / method / headers / body / body_kind，
   直接喂给 `Submitter`。

不追求解析所有 curl 参数，只要能覆盖"浏览器复制出来的那种"即可；
遇到不认识的参数直接忽略，不报错。
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

# flag 值可能长这样
FLAG_VALUE_PATTERNS = [
    r"[A-Za-z0-9_]{2,24}\{[^}\s]{4,120}\}",      # flag{...} / CTF{...} / DASCTF{...}
    r"[0-9a-fA-F]{32}",                            # md5
    r"[0-9a-fA-F]{40}",                            # sha1
    r"[0-9a-fA-F]{64}",                            # sha256
    r"[A-Za-z0-9+/]{24,}={0,2}",                   # base64
]
FLAG_VALUE_RE = re.compile("|".join(f"(?:{p})" for p in FLAG_VALUE_PATTERNS))

# 这些 key 一看就是放 flag 的（优先级从高到低）
FLAG_KEY_HINTS = ("flag", "answer", "content", "submit_flag", "flagvalue",
                  "flag_value", "key", "code", "value", "data")
# 这些 key 绝对不碰（认证/会话类）
SKIP_KEYS = {"token", "csrf", "csrf_token", "_token", "session", "sessionid",
             "authorization", "cookie", "password", "username", "user"}

# 复制出来的 header 里这些没用甚至有副作用，丢掉
DROP_HEADERS = {"host", "content-length", "connection", "accept-encoding",
                "origin", "referer", "sec-fetch-mode", "sec-fetch-site",
                "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile",
                "sec-ch-ua-platform", "accept-language", "cache-control",
                "pragma", "priority", "dnt", "upgrade-insecure-requests"}

PLACEHOLDER = "{flag}"


# ------------------------------------------------------------------ 分词
def _split_args(cmd: str) -> List[str]:
    """把一条 shell 命令切成参数，处理引号、转义和续行。

    比 shlex 多照顾两种情况：Chrome 的 ``$'...'``（含 \\xNN 转义）
    和 Windows cmd 的 ``^`` 续行。
    """
    text = cmd.replace("\\\r\n", " ").replace("\\\n", " ")
    text = text.replace("^\r\n", " ").replace("^\n", " ").replace("^ ", " ")
    text = text.strip()
    if text.lower().startswith("curl"):
        text = text[4:].lstrip()

    out: List[str] = []
    buf: List[str] = []
    i, n = 0, len(text)
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            if quote == "'" and ch == "'":
                quote = ""
            elif quote == '"' and ch == '"':
                quote = ""
            elif quote == '"' and ch == "\\" and i + 1 < n:
                i += 1
                nxt = text[i]
                buf.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
            elif quote == "ansi" and ch == "'":
                quote = ""
            elif quote == "ansi" and ch == "\\" and i + 1 < n:
                i += 1
                esc = text[i]
                if esc == "x" and i + 2 < n:
                    try:
                        buf.append(chr(int(text[i + 1:i + 3], 16)))
                        i += 2
                    except ValueError:
                        buf.append("\\x")
                elif esc in "ntr":
                    buf.append({"n": "\n", "t": "\t", "r": "\r"}[esc])
                else:
                    buf.append(esc)
            else:
                buf.append(ch)
        else:
            if ch in "'\"":
                quote = ch
            elif ch == "$" and i + 1 < n and text[i + 1] == "'":
                quote = "ansi"
                i += 1
            elif ch.isspace():
                if buf:
                    out.append("".join(buf))
                    buf = []
            else:
                buf.append(ch)
        i += 1
    if buf:
        out.append("".join(buf))
    return out


# ------------------------------------------------------------------ 解析
def parse(curl: str) -> Dict[str, Any]:
    """解析 curl 命令 → 结构化请求。"""
    args = _split_args(curl)
    url = ""
    method = ""
    headers: Dict[str, str] = {}
    body_parts: List[str] = []
    cookie = ""
    errors: List[str] = []

    i = 0
    while i < len(args):
        a = args[i]
        low = a.lower()
        val = ""
        # 先处理 --opt=value 形式
        if a.startswith("--") and "=" in a:
            a, val = a.split("=", 1)
            low = a.lower()

        def take() -> str:
            nonlocal i
            if val:
                return val
            if i + 1 < len(args):
                i += 1
                return args[i]
            return ""

        if low in ("-x", "--request"):
            method = take().upper()
        elif low in ("-h", "--header"):
            h = take()
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        elif low in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
            body_parts.append(take())
        elif low == "--data-urlencode":
            v = take()
            body_parts.append(v if "=" in v else urllib.parse.quote(v))
        elif low in ("-b", "--cookie"):
            cookie = take()
        elif low == "--url":
            url = take()
        elif low in ("-a", "--user-agent"):
            headers["User-Agent"] = take()
        elif low in ("-e", "--referer"):
            headers["Referer"] = take()
        elif low in ("-k", "--insecure", "--compressed", "-s", "--silent",
                     "-l", "--location", "-i", "--include", "-v", "--verbose",
                     "--http1.1", "--http2", "-g", "--globoff"):
            pass
        elif low in ("-o", "--output", "-m", "--max-time", "-w", "--write-out",
                     "-u", "--user", "--connect-timeout", "--retry"):
            take()  # 有值但用不上
        elif a.startswith("-"):
            if not val and i + 1 < len(args) and not args[i + 1].startswith("-"):
                i += 1  # 未知选项，保守地跳掉它的值
        elif not url:
            url = a
        i += 1

    if not url:
        errors.append("命令里没有 URL")
    if not method:
        method = "POST" if body_parts else "GET"
    headers = {k: v for k, v in headers.items() if k.lower() not in DROP_HEADERS}
    if cookie:
        headers["Cookie"] = cookie

    body = "&".join(body_parts) if body_parts else ""
    kind = "none"
    parsed_body: Any = None
    if body:
        stripped = body.lstrip()
        if stripped[:1] in "{[":
            try:
                parsed_body = json.loads(body)
                kind = "json"
            except json.JSONDecodeError:
                kind = "raw"
        elif re.fullmatch(r"[^\s=&]+=[^\s&]*(&[^\s=&]+=[^\s&]*)*", body):
            kind = "form"
        else:
            kind = "raw"

    return {"url": url, "method": method, "headers": headers,
            "body": body, "body_kind": kind, "parsed_body": parsed_body,
            "errors": errors}


# ------------------------------------------------------------ flag 定位
def _looks_like_flag(value: str) -> bool:
    v = (value or "").strip()
    return 8 <= len(v) <= 200 and bool(FLAG_VALUE_RE.fullmatch(v))


def _pick_flag_key(keys: List[str], values: Dict[str, str]) -> Optional[str]:
    """在候选 key 里挑最像放 flag 的那个：先看 key 名，再看值形状。"""
    lowered = {k: k.lower() for k in keys}
    for hint in FLAG_KEY_HINTS:
        for k, lk in lowered.items():
            if lk in SKIP_KEYS:
                continue
            if lk == hint or hint in lk:
                return k
    for k, v in values.items():
        if lowered[k] in SKIP_KEYS:
            continue
        if _looks_like_flag(v):
            return k
    return None


def _walk_json(node: Any, path: Tuple[str, ...] = ()) -> List[Tuple[Tuple[str, ...], str]]:
    """把所有"字符串叶子"连路径一起收集，便于定位并替换。"""
    out: List[Tuple[Tuple[str, ...], str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += _walk_json(v, path + (str(k),))
    elif isinstance(node, list):
        for idx, v in enumerate(node):
            out += _walk_json(v, path + (str(idx),))
    elif isinstance(node, str):
        out.append((path, node))
    return out


def _set_json(node: Any, path: Tuple[str, ...], value: str) -> None:
    cur = node
    for p in path[:-1]:
        cur = cur[int(p)] if isinstance(cur, list) else cur[p]
    last = path[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def build_profile(req: Dict[str, Any], flag_key: Optional[str] = None) -> Dict[str, Any]:
    """把解析出的请求变成"带 {flag} 占位符"的提交配置。

    flag_key 为了兼容手工指定：JSON 用点号路径（如 ``data.answer``），
    form/query 用字段名。
    """
    url = req["url"]
    method = req["method"]
    headers = dict(req["headers"])
    body_kind = req["body_kind"]
    parsed = req["parsed_body"]
    body = req["body"]

    placeholder_at: List[str] = []
    json_body = None
    form_body = None
    raw_body = None

    # 1) URL 查询参数里的 flag
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if query:
        qmap = {k: v for k, v in query}
        key = flag_key if flag_key in qmap else _pick_flag_key(list(qmap), qmap)
        if key:
            # 注意：占位符必须原样保留，用 urlencode 会变成 %7Bflag%7D，
            # 后面 str.format 就认不出来了
            chunks = []
            for k, v in query:
                if k == key:
                    chunks.append(f"{urllib.parse.quote(k)}={PLACEHOLDER}")
                else:
                    chunks.append(f"{urllib.parse.quote(k)}={urllib.parse.quote(v, safe='')}")
            url = urllib.parse.urlunsplit((
                parts.scheme, parts.netloc, parts.path, "&".join(chunks), parts.fragment))
            placeholder_at.append(f"query.{key}")

    # 2) body 里的 flag
    if body_kind == "json" and isinstance(parsed, (dict, list)):
        leaves = _walk_json(parsed)
        target_path = None
        if flag_key:
            want = tuple(flag_key.split("."))
            for path, _ in leaves:
                if path == want or ".".join(path) == flag_key:
                    target_path = path
                    break
        if target_path is None:
            named = {str(p[-1]): v for p, v in leaves if p}
            picked = _pick_flag_key(list(named), named)
            if picked is not None:
                for path, _ in leaves:
                    if str(path[-1]) == picked:
                        target_path = path
                        break
        if target_path is None:
            for path, v in leaves:
                if _looks_like_flag(v):
                    target_path = path
                    break
        if target_path is not None:
            _set_json(parsed, target_path, PLACEHOLDER)
            placeholder_at.append("json." + ".".join(target_path))
        json_body = parsed if isinstance(parsed, dict) else {"_": parsed}

    elif body_kind == "form":
        pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
        fmap = {k: v for k, v in pairs}
        key = flag_key if flag_key in fmap else _pick_flag_key(list(fmap), fmap)
        if key:
            form_body = {k: (PLACEHOLDER if k == key else v) for k, v in pairs}
            placeholder_at.append(f"form.{key}")
        else:
            form_body = dict(pairs)

    elif body_kind == "raw":
        m = FLAG_VALUE_RE.search(body)
        if m:
            raw_body = body[:m.start()] + PLACEHOLDER + body[m.end():]
            placeholder_at.append("raw")
        else:
            raw_body = body

    # 3) 成功判定：先按常见 JSON 字段，判断不到就靠关键词兜底
    success = {"success_key": "success", "success_value": True,
               "message_key": "message"}
    return {
        "url": url,
        "method": method,
        "headers": headers,
        "json_body": json_body,
        "form_body": form_body,
        "raw_body": raw_body,
        "body_kind": body_kind,
        "flag_at": placeholder_at,
        "has_placeholder": bool(placeholder_at),
        **success,
    }


def parse_to_profile(curl: str, flag_key: Optional[str] = None) -> Dict[str, Any]:
    """一步到位：cURL → 提交配置（含预览用信息）。"""
    req = parse(curl)
    prof = build_profile(req, flag_key=flag_key)
    prof["preview"] = {
        "method": req["method"],
        "url": req["url"],
        "headers": req["headers"],
        "body_kind": req["body_kind"],
        "body": (req["body"][:600] if req["body"] else ""),
        "errors": req["errors"],
    }
    return prof

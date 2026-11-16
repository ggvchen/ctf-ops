"""让本地模型按框架契约写 PoC 插件。

安全边界：
- 生成 → 先写 `_drafts/`（加载器不碰这个目录），必须人工确认才 install
- 校验只做 AST 静态检查（语法、必备变量、exploit 函数），不 exec 模型给的代码
- 安装后才进入 plugins/exploits/，由插件加载器正常导入
"""

from __future__ import annotations

import ast
import json
import pathlib
import re
import time
from typing import Any, Dict, Optional

from .config import Config
from .util import safe_name

PLUGIN_DIR = pathlib.Path(__file__).parent / "plugins" / "exploits"
DRAFT_DIR = PLUGIN_DIR / "_drafts"

SYSTEM = (
    "你是给 ctf-ops 漏洞利用框架写 PoC 插件的工程师。只输出一个 Python 代码块，不要解释。"
)

TEMPLATE_HINT = '''插件必须长这样（严格遵循）：

```python
NAME = "唯一标识，小写下划线"
DESCRIPTION = "一句话说明"
KIND = "web"          # web | ssh | local
SEVERITY = "high"     # critical/high/medium/low
TAGS = ["rce"]

def check(ctx):
    """可选：廉价探活，返回 True 表示目标存在该漏洞。"""
    r = ctx.get(ctx.base + "/probe")
    return "signature" in (r.text or "")

def exploit(ctx):
    """必须：利用并返回结果。"""
    r = ctx.get(ctx.base + "/exploit?id=1")
    return {"ok": True, "evidence": r.text[:2000], "flags": []}
```

可用 API：
- ctx.base 目标 web 根地址；ctx.get(url, **kw) / ctx.post(url, **kw)（requests 语义）
- ctx.target（Target 对象，有 host/name/web）；ctx.cfg（全局配置）
- ctx.run(cmd, timeout=60, sudo=False) 通过 SSH 在靶机执行命令并返回输出
- ctx.put(remote_path, content) 写远程文件
- ctx.log(msg) 记录过程
- 返回 {"ok": bool, "evidence": str, "flags": [str]}；flag 会被框架自动正则提取

要求：
- 只用标准库 + requests，不要引入其它依赖
- 不要写死目标 IP，一律用 ctx.base / ctx.target.host
- check() 要快（<5s），失败要返回 False 而不是抛异常
- exploit() 捕获异常，失败返回 {"ok": False, "evidence": 错误信息}
'''


def build_prompt(info: str) -> str:
    return (f"{TEMPLATE_HINT}\n\n漏洞信息：\n{info.strip()}\n\n"
            "请写一个可直接运行的完整插件。")


def extract_code(text: str) -> str:
    m = re.search(r"```(?:python)?\s*\n(.*?)```", text or "", re.S)
    code = m.group(1) if m else (text or "")
    # 去掉模型偶尔加的前后客套
    lines = code.splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if re.match(r"^(NAME|DESCRIPTION|import|from)\b", ln.strip())), 0)
    return "\n".join(lines[start:]).strip() + "\n"


def _fix_name(raw: str) -> str:
    name = re.sub(r"[^a-z0-9_]+", "_", (raw or "").strip().lower()).strip("_")
    if not name:
        return "ai_poc"
    if name[0].isdigit():
        name = "poc_" + name
    return name


def normalize_code(code: str) -> str:
    """把模型常见的"不规范但可修"的地方就地修掉。

    最典型的是 NAME：模型看到 CVE 编号就写成 ``cve-2021-41773``，
    而插件名要当模块名用，只能是 ``[a-z0-9_]``。这种错不值得回炉重生成。
    """
    return re.sub(
        r'^(\s*NAME\s*=\s*)(["\'])([^"\']*)\2',
        lambda m: f'{m.group(1)}"{_fix_name(m.group(3))}"',
        code, flags=re.M)


def validate(code: str) -> Dict[str, Any]:
    """静态检查：语法 + 必备字段 + exploit 函数。"""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return {"ok": False, "error": f"语法错误第 {e.lineno} 行: {e.msg}"}

    assigns: Dict[str, Any] = {}
    funcs = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and isinstance(node.value, ast.Constant):
                    assigns[tgt.id] = node.value.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if isinstance(node.value, ast.Constant):
                assigns[node.target.id] = node.value.value
        elif isinstance(node, ast.FunctionDef):
            funcs.add(node.name)

    missing = [k for k in ("NAME", "DESCRIPTION", "SEVERITY") if k not in assigns]
    if missing:
        return {"ok": False, "error": f"缺少字段: {', '.join(missing)}"}
    if "exploit" not in funcs:
        return {"ok": False, "error": "缺少 exploit(ctx) 函数"}
    name = str(assigns.get("NAME", "")).strip()
    if not re.fullmatch(r"[a-z0-9_]{3,48}", name):
        return {"ok": False, "error": f"NAME 需为小写字母数字下划线: {name!r}"}
    return {"ok": True, "name": name,
            "description": str(assigns.get("DESCRIPTION", ""))[:120],
            "severity": str(assigns.get("SEVERITY", "medium")),
            "has_check": "check" in funcs}


def generate(cfg: Config, info: str) -> Dict[str, Any]:
    from .aiclient import AIClient
    ai = AIClient(cfg)
    if not ai.cfg.enabled:
        return {"ok": False, "error": "AI 已在配置中关闭"}
    # 先探活：端点没起来就别让用户干等两分钟
    if not ai.available():
        return {"ok": False, "alive": False,
                "error": f"本地模型未启动或不可达（{ai.cfg.base_url}）"}
    res = ai.chat(build_prompt(info), system=SYSTEM, temperature=0.15, max_tokens=2200)
    if not res.ok:
        # 判断是否端点不可用
        return {"ok": False, "error": res.error or "模型无输出",
                "alive": ai.available()}
    code = normalize_code(extract_code(res.text))
    v = validate(code)

    # 校验没过就把错误回喂模型，让它自己改一次（本地模型很吃这一套）
    repaired = False
    if not v["ok"]:
        fix_prompt = (
            f"你上一版插件没通过静态校验：{v['error']}\n\n"
            f"这是你写的代码：\n```python\n{code}\n```\n\n"
            "请修正后重新输出**完整**插件代码，只用一个 ```python 代码块，"
            "不要解释。务必满足：NAME 为 [a-z0-9_]、有 DESCRIPTION/SEVERITY、"
            "有 exploit(ctx) 返回 dict。")
        res2 = ai.chat(fix_prompt, system=SYSTEM, temperature=0.1, max_tokens=2200)
        if res2.ok:
            code2 = normalize_code(extract_code(res2.text))
            v2 = validate(code2)
            if v2["ok"]:
                code, v, repaired = code2, v2, True

    draft, slug = "", ""
    if v["ok"]:
        p, slug = save_draft(code, v["name"])
        draft = str(p)
    return {"ok": bool(v["ok"]), "code": code, "draft": draft, "slug": slug,
            "repaired": repaired, "raw": res.text[:4000], **v}


def save_draft(code: str, name: str) -> "tuple[pathlib.Path, str]":
    DRAFT_DIR.mkdir(parents=True, exist_ok=True)
    slug = f"{safe_name(name)}_{time.strftime('%H%M%S')}"
    p = DRAFT_DIR / f"{slug}.py"
    p.write_text(code, encoding="utf-8")
    return p, slug


def list_drafts() -> list:
    out = []
    if DRAFT_DIR.exists():
        for f in sorted(DRAFT_DIR.glob("*.py"), key=lambda x: -x.stat().st_mtime):
            out.append({"slug": f.stem, "name": f.name,
                        "size": f.stat().st_size,
                        "mtime": time.strftime("%m-%d %H:%M", time.localtime(f.stat().st_mtime)),
                        "code": f.read_text(encoding="utf-8")[:20000]})
    return out


def install(slug: str, overwrite: bool = False) -> Dict[str, Any]:
    src = DRAFT_DIR / f"{slug}.py"
    if not src.is_file():
        return {"ok": False, "error": f"草稿不存在: {slug}"}
    code = src.read_text(encoding="utf-8")
    v = validate(code)
    if not v["ok"]:
        return {"ok": False, "error": f"校验未通过: {v['error']}"}
    dst = PLUGIN_DIR / f"{safe_name(v['name'])}.py"
    if dst.exists() and not overwrite:
        return {"ok": False, "error": f"插件已存在: {dst.name}（需要覆盖请加 overwrite）"}
    dst.write_text(code, encoding="utf-8")
    return {"ok": True, "path": str(dst.relative_to(PLUGIN_DIR.parent.parent.parent)),
            "name": v["name"]}

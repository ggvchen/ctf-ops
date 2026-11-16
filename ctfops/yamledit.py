"""就地编辑 targets YAML 的单个字段，尽量不破坏原文件的注释与缩进。

场景：备份源目录（webroot）要按靶机改，但配置是 YAML、里面还有注释和手写格式。
不用 yaml.safe_dump 整体重写（会丢注释、还会把缩进改成 0），而是做"行级手术"。
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .config import Config

_ITEM_RE = re.compile(r'^(?P<indent>\s*)-\s+name:\s*(?P<name>"[^"]*"|\'[^\']*\'|[^#\s]+)')


def targets_path(cfg: Config) -> pathlib.Path:
    """与 load_config 一致的定位：配了 targets_file 用它，否则写主配置。"""
    try:
        raw = yaml.safe_load(cfg.path.read_text(encoding="utf-8")) or {}
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"读取配置失败: {e}") from e
    tf = raw.get("targets_file")
    if not tf:
        return cfg.path
    p = pathlib.Path(tf)
    return p if p.is_absolute() else (cfg.path.parent / p)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def find_block(lines: List[str], name: str) -> Optional[Tuple[int, int, str]]:
    """返回 (起始行, 结束行(不含), 列表项缩进)。"""
    for i, line in enumerate(lines):
        m = _ITEM_RE.match(line)
        if not m or _unquote(m.group("name")) != name:
            continue
        indent = m.group("indent")
        end = len(lines)
        for j in range(i + 1, len(lines)):
            nxt = lines[j]
            if not nxt.strip():
                continue
            ind = len(nxt) - len(nxt.lstrip())
            if ind < len(indent):
                end = j
                break
            if ind == len(indent) and nxt.lstrip().startswith("-"):
                end = j
                break
        return i, end, indent
    return None


def _yaml_str(v: str) -> str:
    s = str(v)
    # 含特殊字符就加引号，普通路径保持可读
    if s == "" or re.search(r"[:#{}\[\],&\*\!\|\>'\"]", s) or s.strip() != s:
        return json.dumps(s, ensure_ascii=False)
    return s


def set_target_field(cfg: Config, name: str, field: str, value: Any) -> Dict[str, Any]:
    path = targets_path(cfg)
    if not path.exists():
        raise ValueError(f"配置文件不存在: {path}")
    original = path.read_text(encoding="utf-8")
    lines = original.splitlines()

    found = find_block(lines, name)
    if not found:
        raise ValueError(f"{path.name} 里找不到靶机 {name}")
    start, end, indent = found
    field_indent = indent + "  "

    if isinstance(value, (list, tuple)):
        rendered = "[" + ", ".join(_yaml_str(x) for x in value) + "]"
    else:
        rendered = _yaml_str(value)

    replaced = False
    for j in range(start + 1, end):
        m = re.match(r"^(\s*)" + re.escape(field) + r"\s*:", lines[j])
        if m:
            lines[j] = f"{m.group(1)}{field}: {rendered}"
            replaced = True
            break
    if not replaced:
        lines.insert(start + 1, f"{field_indent}{field}: {rendered}")

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"path": str(path), "replaced": replaced, "field": field, "value": value}



EDITABLE = ("name", "host", "ssh_port", "user", "password", "key_file", "role",
            "web", "tags", "note", "webroot", "enabled")


# ------------------------------------------------------------- 通用配置段
# 靶机是列表项，ai / submit 这类是顶层映射。上面那套 block 逻辑只认 "- name:"，
# 这里另起一套：按顶层 key 定位段，段内按字段行替换，注释与顺序都不动。
_SECTION_RE = r"^(?P<indent>\s*){key}\s*:\s*(?:#.*)?$"


def _section_span(lines: List[str], name: str) -> Optional[Tuple[int, int, str]]:
    """定位顶层映射段，返回 (段首行, 段末行(不含), 缩进)。"""
    for i, line in enumerate(lines):
        m = re.match(_SECTION_RE.format(key=re.escape(name)), line)
        if not m:
            continue
        indent = m.group("indent")
        end = len(lines)
        for j in range(i + 1, len(lines)):
            s = lines[j]
            if not s.strip():
                continue
            ind = len(s) - len(s.lstrip())
            if ind <= len(indent):
                end = j
                break
        return i, end, indent
    return None


def _split_comment(line: str) -> Tuple[str, str]:
    """拆出行尾注释。引号里的 # 不算注释（比如密码、URL 片段）。"""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"':
                continue
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip(), line[i:]
    return line, ""


def _scalar(value: Any) -> str:
    """渲染标量。只有真会破坏 YAML 的才加引号，URL 这类保持可读。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return repr(value) if isinstance(value, float) else str(value)
    s = str(value)
    risky = (
        s == ""
        or s.strip() != s
        or re.search(r"[\n\r\t]", s)
        or re.match(r"^[\-?:,\[\]{}#&*!|>'\"%@` ]", s)
        or re.search(r":\s|\s#|:$", s)
        or s.lower() in ("null", "true", "false", "yes", "no", "on", "off", "~")
    )
    return json.dumps(s, ensure_ascii=False) if risky else s


def update_section(cfg: Config, section: str, changes: Dict[str, Any],
                   path: Optional[pathlib.Path] = None) -> Dict[str, Any]:
    """修改顶层配置段（如 ai:）里的字段。值为 None 表示删掉该字段。

    写完立刻回读校验：只要有一项对不上，整份文件回滚 —— 配置写坏一次，
    整个作战系统就起不来了，宁可报错也不能留半截。
    """
    target = pathlib.Path(path or cfg.path)
    if not target.exists():
        raise ValueError(f"配置文件不存在: {target}")
    original = target.read_text(encoding="utf-8")
    lines = original.splitlines()
    # 尾部空行会干扰"插到段尾"的下标，先削掉（写回时本来也会 rstrip）
    while lines and not lines[-1].strip():
        lines.pop()

    span = _section_span(lines, section)
    if span is None:
        lines.extend(["", f"{section}:"])
        start, end, indent = len(lines) - 1, len(lines), ""
    else:
        start, end, indent = span

    for field, value in changes.items():
        found = _key_span(lines, start + 1, end, field)
        if value is None:
            if found:
                j, stop, _ = found
                del lines[j:stop]
                end -= (stop - j)
            continue
        rendered = f"{field}: {_scalar(value)}"
        if found:
            j, stop, key_indent = found
            _code, comment = _split_comment(lines[j])
            lines[j] = f"{key_indent}{rendered}" + (f"    {comment}" if comment else "")
            if stop > j + 1:
                del lines[j + 1:stop]
                end -= (stop - j - 1)
        else:
            # 插在段尾（而不是紧跟段首），新字段不会把注释挤到上面去
            lines.insert(end, f"{indent}  {rendered}")
            end += 1

    text = "\n".join(lines).rstrip() + "\n"
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"改动会让 YAML 失效，已放弃写入: {e}") from e
    got = data.get(section)
    if not isinstance(got, dict):
        raise ValueError(f"回读不到 {section} 段，已放弃写入")
    bad = []
    for field, value in changes.items():
        if value is None:
            continue
        if got.get(field) != value and str(got.get(field)) != str(value):
            bad.append(f"{field}: 期望 {value!r} 读到 {got.get(field)!r}")
    if bad:
        raise ValueError("回读不一致，已放弃写入 -> " + "; ".join(bad))

    target.write_text(text, encoding="utf-8")
    return {"path": str(target), "section": section,
            "applied": [k for k in changes], "diff": diff(original, text)}


def _render(field: str, value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        return "[" + ", ".join(_yaml_str(x) for x in value) + "]"
    return _yaml_str(value)


def _key_span(lines: List[str], start: int, end: int, field: str) -> Optional[Tuple[int, int, str]]:
    """找到字段行及其续行范围（块状 list 的 - xx 行）。

    返回 (字段行, 结束行(不含), 缩进)。找不到返回 None。
    """
    for j in range(start, end):
        m = re.match(r"^(\s*)" + re.escape(field) + r"\s*:", lines[j])
        if not m:
            continue
        key_indent = m.group(1)
        stop = j + 1
        while stop < end:
            line = lines[stop]
            if not line.strip():
                break
            ind = len(line) - len(line.lstrip())
            if ind <= len(key_indent):
                break
            stop += 1
        return j, stop, key_indent
    return None


def _apply_changes(lines: List[str], start: int, end: int, indent: str,
                   changes: Dict[str, Any]) -> Tuple[int, List[str]]:
    """把 changes 应用到一个靶机块上，返回 (新的 end, 已应用字段)。"""
    field_indent = indent + "  "
    applied: List[str] = []
    for field, value in changes.items():
        if field not in EDITABLE:
            continue
        if field == "name":
            if value is None:
                raise ValueError("name 不能为空")
            lines[start] = f"{indent}- name: {_render('name', value)}"
            applied.append("name")
            continue
        span = _key_span(lines, start, end, field)
        if value is None:
            if span:
                j, stop, _ = span
                del lines[j:stop]
                end -= (stop - j)
                applied.append(f"-{field}")
            continue
        rendered = f"{field}: {_render(field, value)}"
        if span:
            j, stop, key_indent = span
            lines[j] = f"{key_indent}{rendered}"
            if stop > j + 1:
                del lines[j + 1:stop]
                end -= (stop - j - 1)
        else:
            lines.insert(end, f"{field_indent}{rendered}")
            end += 1
        applied.append(field)
    return end, applied


def update_target(cfg: Config, name: str, changes: Dict[str, Any]) -> Dict[str, Any]:
    """修改一台靶机。字段值为 None 表示删除该字段。支持改名。"""
    path = targets_path(cfg)
    if not path.exists():
        raise ValueError(f"配置文件不存在: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    found = find_block(lines, name)
    if not found:
        raise ValueError(f"{path.name} 里找不到靶机 {name}")
    start, end, indent = found
    _, applied = _apply_changes(lines, start, end, indent, changes)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"path": str(path), "applied": applied}


def update_many(cfg: Config, names: List[str], changes: Dict[str, Any]) -> Dict[str, Any]:
    """批量改字段：读一次、改多块、写一次。"""
    path = targets_path(cfg)
    if not path.exists():
        raise ValueError(f"配置文件不存在: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()

    blocks, missing = [], []
    for name in names:
        found = find_block(lines, name)
        if found:
            blocks.append((name, *found))
        else:
            missing.append(name)
    if not blocks:
        raise ValueError("没有匹配到任何靶机")
    # 从后往前改，前面块的索引才不会被位移影响
    blocks.sort(key=lambda x: -x[1])
    touched = []
    for name, start, end, indent in blocks:
        _, applied = _apply_changes(lines, start, end, indent, changes)
        if applied:
            touched.append(name)

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"path": str(path), "updated": touched, "missing": missing}


def remove_target(cfg: Config, name: str) -> Dict[str, Any]:
    """从配置里整块删除一台靶机（连同其续行和多出的空行）。"""
    path = targets_path(cfg)
    if not path.exists():
        raise ValueError(f"配置文件不存在: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()
    found = find_block(lines, name)
    if not found:
        raise ValueError(f"{path.name} 里找不到靶机 {name}")
    start, end, _ = found
    while end < len(lines) and not lines[end].strip():
        end += 1
    removed = lines[start:end]
    del lines[start:end]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"path": str(path), "removed_lines": len(removed)}


def remove_many(cfg: Config, names: List[str]) -> Dict[str, Any]:
    """批量删除靶机块（从后往前删，避免索引位移）。"""
    path = targets_path(cfg)
    if not path.exists():
        raise ValueError(f"配置文件不存在: {path}")
    lines = path.read_text(encoding="utf-8").splitlines()

    blocks, missing = [], []
    for name in names:
        found = find_block(lines, name)
        if found:
            blocks.append((name, *found))
        else:
            missing.append(name)
    if not blocks:
        raise ValueError("没有匹配到任何靶机")

    blocks.sort(key=lambda x: -x[1])
    removed = []
    for name, start, end, _indent in blocks:
        while end < len(lines) and not lines[end].strip():
            end += 1
        del lines[start:end]
        removed.append(name)

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"path": str(path), "removed": removed, "missing": missing}


def diff(before: str, after: str) -> str:
    import difflib
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                        "before", "after", n=2))


def restore(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")

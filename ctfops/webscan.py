"""WebShell 静态查杀（D盾 那一类的主机侧检测）。

和 nuclei（打网络请求）、exploit 插件（验证可利用性）不同，这里是**看文件内容**：
把 webroot 或备份包里的脚本文件逐个过规则库，命中就打分。用途有三：

1. 自家靶机被上传马之后，快速定位是哪个文件、哪一行、什么类型；
2. 拿到对手的源码包 / 备份后，先静态摸一遍有没有后门和隐藏入口；
3. 比赛前自查自己部署的业务里有没有别人留的钩子。

规则放在 ``config/rules/webshell.yaml``，纯 YAML，可现场加。
"""

from __future__ import annotations

import fnmatch
import os
import pathlib
import re
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import Config, Target
from .util import info, warn

TEXT_EXTS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".pht", ".phar", ".inc",
    ".jsp", ".jspx", ".jspf", ".asp", ".aspx", ".ashx", ".asmx", ".asa", ".cer",
    ".cgi", ".pl", ".py", ".rb", ".sh", ".html", ".htm", ".tpl", ".twig", ".smarty",
    ".eval", ".txt", ".ini", ".htaccess", "",
}
ARCHIVE_EXTS = {".tar", ".gz", ".tgz", ".bz2", ".xz", ".zip", ".7z", ".rar"}
# 图片/媒体也要看：图片马是最常见的绕过上传限制手法
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp", ".mp4"}
IMAGE_PROBE_BYTES = 512 << 10      # 只读前 512KB，足够发现"图片头 + php 尾巴"
MAX_FILE_BYTES = 4 << 20          # 单文件最多读 4MB，够看脚本了
MAX_FILES = 20000                 # 一次最多扫 2 万个文件

SEV_SCORE = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Hit:
    rule_id: str
    name: str
    severity: str
    score: int
    category: str
    line: int = 0
    snippet: str = ""
    count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "name": self.name, "severity": self.severity,
                "score": self.score, "category": self.category,
                "line": self.line, "snippet": self.snippet, "count": self.count}


@dataclass
class FileResult:
    path: str
    size: int = 0
    score: int = 0
    verdict: str = "clean"      # clean / suspicious / malicious
    hits: List[Hit] = field(default_factory=list)
    error: str = ""
    original: bool = False      # 时间戳与安装基线一致：原版框架文件，命中规则大概率是误报

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path, "size": self.size, "score": self.score,
                "verdict": self.verdict, "error": self.error,
                "original": self.original,
                "hits": [h.to_dict() for h in self.hits]}


@dataclass
class ShellReport:
    root: str
    files: int = 0
    suspicious: int = 0
    malicious: int = 0
    skipped: int = 0
    elapsed: float = 0.0
    results: List[FileResult] = field(default_factory=list)
    names: List[str] = field(default_factory=list)   # 可疑文件名
    rules: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"root": self.root, "files": self.files, "suspicious": self.suspicious,
                "malicious": self.malicious, "skipped": self.skipped,
                "elapsed": round(self.elapsed, 2), "rules": self.rules,
                "suspicious_names": self.names, "error": self.error,
                "results": [r.to_dict() for r in self.results]}

    def findings(self, target: str, kind: str = "shell"):
        """转成统一的 Finding，方便入库/报告。"""
        from .exploit import Finding

        out: List[Finding] = []
        for r in self.results:
            if r.verdict == "clean":
                continue
            sev = "critical" if r.verdict == "malicious" else "high"
            detail = "; ".join(f"{h.name}(+{h.score})" for h in r.hits[:6])
            out.append(Finding(target, f"疑似后门文件 {pathlib.PurePosixPath(r.path).name}",
                               sev, kind, detail=detail,
                               evidence=_merge_snippets(r.hits),
                               location=r.path,
                               tags=[h.rule_id for h in r.hits[:6]]))
        return out


def _merge_snippets(hits: List[Hit], limit: int = 900) -> str:
    parts = []
    for h in hits[:5]:
        if h.snippet:
            parts.append(f"L{h.line} [{h.rule_id}] {h.snippet}")
    return "\n".join(parts)[:limit]


# --------------------------------------------------------------------- 规则
_DEFAULT_RULES: List[Dict[str, Any]] = [
    {"id": "ws-one-liner-eval", "name": "一句话木马 · eval 收外部变量",
     "severity": "critical", "score": 95, "category": "一句话", "mode": "any",
     "patterns": [r"@?\beval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\b",
                  r"@?\bassert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\b"]},
    {"id": "ws-cmd-exec", "name": "命令执行函数收外部变量",
     "severity": "critical", "score": 90, "category": "命令执行", "mode": "any",
     "patterns": [r"(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST)"]},
    {"id": "ws-var-function", "name": "变量函数动态调用",
     "severity": "critical", "score": 85, "category": "一句话", "mode": "any",
     "patterns": [r"\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(",
                  r"call_user_func\s*\(\s*\$_"]},
    {"id": "ws-base64-eval", "name": "base64_decode + 执行",
     "severity": "critical", "score": 80, "category": "编码混淆", "mode": "all",
     "patterns": [r"base64_decode\s*\(",
                  r"(eval|assert|create_function|call_user_func)\s*\("]},
    {"id": "ws-gzinflate-eval", "name": "压缩流解码后执行",
     "severity": "critical", "score": 85, "category": "编码混淆", "mode": "all",
     "patterns": [r"(gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin)\s*\(",
                  r"(eval|assert|create_function)\s*\("]},
    {"id": "ws-image-php", "name": "图片马（图片头 + PHP 代码）",
     "severity": "critical", "score": 90, "category": "图片马", "mode": "all",
     "patterns": [r"^(GIF8|\x89PNG|\xff\xd8\xff)", r"<\?php"]},
    {"id": "ws-reverse-shell", "name": "反弹 Shell",
     "severity": "critical", "score": 90, "category": "命令执行", "mode": "any",
     "patterns": [r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+", r"bash\s+-i\s+>&",
                  r"(nc|ncat|socat)\s+(-e|--exec)"]},
]


def rules_path(cfg: Config) -> pathlib.Path:
    """优先用配置目录下的规则库；没有就用项目自带那份。

    这样用 `-c /tmp/xxx/config.yaml` 跑独立环境时，不会因为目录里没有
    rules/ 就退化成内置的 7 条规则（少一半检测能力）。
    """
    local = cfg.path.parent / "rules" / "webshell.yaml"
    if local.exists():
        return local
    packaged = pathlib.Path(__file__).resolve().parent.parent / "config" / "rules" / "webshell.yaml"
    return packaged if packaged.exists() else local


def load_rules(cfg: Config) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """读规则库；文件缺失或写坏就退回内置最小集，绝不因规则问题让扫描失败。"""
    import yaml

    path = rules_path(cfg)
    data: Dict[str, Any] = {}
    if path.exists():
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            warn(f"规则库解析失败，用内置规则: {e}")
            data = {}
    else:
        warn(f"规则库不存在（{path}），用内置规则")

    rules = data.get("rules") or _DEFAULT_RULES
    cleaned = []
    for r in rules:
        if not r.get("patterns"):
            continue
        r = dict(r)
        r.setdefault("mode", "any")
        r.setdefault("severity", "medium")
        r.setdefault("score", 50)
        r.setdefault("category", "其他")
        r["id"] = r.get("id") or f"rule-{len(cleaned)}"
        # 预先编译，坏正则在加载时就暴露
        try:
            r["_re"] = [re.compile(p, re.I | re.S) for p in r["patterns"]]
        except re.error as e:
            warn(f"规则 {r['id']} 正则非法，跳过: {e}")
            continue
        cleaned.append(r)

    heur = {h.get("id"): h for h in (data.get("heuristics") or [])}
    names = data.get("suspicious_names") or []
    return cleaned, {"heuristics": heur, "names": names}


# --------------------------------------------------------------------- 扫描
def _is_text_file(path: pathlib.Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    if path.suffix == "":
        # 无扩展名：只看像脚本的（如 .htaccess 由 suffix 处理，这里看大小）
        return True
    return False


def _extract(archive: pathlib.Path, dest: pathlib.Path) -> bool:
    """把 tar/zip 解到 dest；失败返回 False。"""
    try:
        dest.mkdir(parents=True, exist_ok=True)
        if archive.suffix.lower() == ".zip":
            with zipfile.ZipFile(archive) as z:
                z.extractall(dest)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.isfile() and m.size <= MAX_FILE_BYTES * 8:
                        t.extract(m, dest, filter="data")
        return True
    except Exception:
        return False


def _iter_source(root: pathlib.Path, tmpdir: Optional[pathlib.Path]) -> Iterable[pathlib.Path]:
    """遍历目录；遇到压缩包就在 tmpdir 里解开再遍历。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       ("node_modules", ".git", "__pycache__", ".svn", "vendor_cache")]
        for fn in filenames:
            p = pathlib.Path(dirpath) / fn
            ext = p.suffix.lower()
            if ext in ARCHIVE_EXTS and tmpdir is not None:
                sub = tmpdir / f"x{abs(hash(str(p))) % 100000}"
                try:
                    sub.mkdir(parents=True, exist_ok=True)
                    if ext == ".zip":
                        with zipfile.ZipFile(p) as z:
                            z.extractall(sub)
                    else:
                        with tarfile.open(p) as t:
                            for m in t.getmembers():
                                if m.isfile() and m.size <= MAX_FILE_BYTES * 4:
                                    t.extract(m, sub, filter="data")
                    yield from _iter_source(sub, None)
                except Exception:
                    continue
                continue
            yield p


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet_at(text: str, start: int, end: int, pad: int = 60) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b].replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s{2,}", " ", s).strip()
    return s[:240]


def scan_text(name: str, text: str, rules: List[Dict[str, Any]],
              meta: Optional[Dict[str, Any]] = None) -> FileResult:
    """扫一段文本（也用于内存里的内容，方便测试）。"""
    res = FileResult(path=name, size=len(text))
    meta = meta or {}

    # 1) 内容规则
    for r in rules:
        exts = r.get("exts")
        if exts:
            suffix = pathlib.PurePosixPath(name).suffix.lower()
            if suffix not in exts:
                continue
        hits: List[Tuple[int, int, int]] = []      # (start, end, line)
        if r["mode"] == "all":
            spans = []
            ok = True
            for rx in r["_re"]:
                m = rx.search(text)
                if not m:
                    ok = False
                    break
                spans.append(m)
            if ok:
                first = min(spans, key=lambda m: m.start())
                hits.append((first.start(), first.end(), _line_of(text, first.start())))
        else:
            for rx in r["_re"]:
                for m in rx.finditer(text):
                    hits.append((m.start(), m.end(), _line_of(text, m.start())))
                    if len(hits) >= 3:
                        break
                if len(hits) >= 3:
                    break
        for (a, b, line) in hits:
            res.hits.append(Hit(r["id"], r["name"], r["severity"], int(r["score"]),
                                r["category"], line, _snippet_at(text, a, b)))

    # 2) 文件级启发式
    size = res.size
    if size and size < 200 and re.search(r"(eval|assert)\s*\(", text, re.I):
        res.hits.append(Hit("fh-tiny-eval", "极小文件内含执行函数", "high", 60,
                            "启发", 0, text.strip()[:120]))
    longest = max((len(x) for x in text.splitlines()), default=0)
    if longest > 3000:
        res.hits.append(Hit("fh-long-line", f"超长单行（{longest} 字符）", "medium", 30,
                            "启发", 0, ""))
    mode = meta.get("mode")
    if mode is not None and (int(mode) & 0o777) == 0o777:
        res.hits.append(Hit("fh-world-writable", "文件权限 777", "medium", 25,
                            "启发", 0, oct(int(mode) & 0o777)))
    mtime = meta.get("mtime")
    if mtime and (time.time() - float(mtime)) < 24 * 3600:
        res.hits.append(Hit("fh-recent-write", "24 小时内被修改", "low", 15,
                            "启发", 0, time.strftime("%m-%d %H:%M", time.localtime(float(mtime)))))

    _finalize(res, meta)
    return res


def _finalize(res: FileResult, meta: Optional[Dict[str, Any]] = None) -> None:
    # 同一规则多条命中：只留一条（分数不叠加，否则循环里的马会爆表），
    # 但把命中次数记在 count 上——"只出现 1 次"和"遍布全文"是不同信号
    merged: Dict[str, Hit] = {}
    for h in res.hits:
        cur = merged.get(h.rule_id)
        if cur is None:
            merged[h.rule_id] = h
        else:
            cur.count += h.count
            if h.score > cur.score or (h.score == cur.score and h.line < cur.line):
                prev_count = cur.count
                merged[h.rule_id] = h
                h.count = prev_count
    res.hits = list(merged.values())
    res.score = min(100, sum(h.score for h in res.hits))
    meta = meta or {}

    # 原版文件降级：线上 CMS 的核心代码本来就含 eval/base64_decode 之类，
    # 两条规则一叠就过 70 分 —— 实战里 1830 个文件报 39 个"后门"，全是误报。
    # 判据：mtime 早于/等于安装基线（= 全站最早 mtime）就认为不是后加的。
    base = meta.get("baseline")
    mt = meta.get("mtime")
    # 只在"原版时间 + 大文件 + 没有强特征"三条同时成立时才降级：
    # 真后门要么很小（一句话），要么单条规则就够 90 分，不会被误降。
    strong = any(h.score >= 90 for h in res.hits)
    if (base and mt and float(mt) <= float(base) + 86400
            and res.size > 6000 and not strong):
        res.original = True
        res.score = min(res.score, 39)
    if meta.get("generated"):
        res.original = True          # 编译产物，不是源码
        res.score = min(res.score, 39)

    if res.score >= 70:
        res.verdict = "malicious"
    elif res.score >= 40:
        res.verdict = "suspicious"
    else:
        res.verdict = "clean"
    res.hits.sort(key=lambda h: (SEV_SCORE.get(h.severity, 9), -h.score))


def scan_path(cfg: Config, root: os.PathLike | str, max_files: int = MAX_FILES,
              include_clean: bool = False) -> ShellReport:
    """扫本地目录或压缩包。压缩包会先解到临时目录再扫。"""
    root_p = pathlib.Path(root).expanduser()
    rep = ShellReport(root=str(root_p))
    rules, extra = load_rules(cfg)
    rep.rules = len(rules)
    if not root_p.exists():
        rep.error = f"路径不存在: {root_p}"
        return rep

    t0 = time.time()
    tmpdir: Optional[pathlib.Path] = None
    base_for_rel = root_p
    if root_p.is_dir():
        tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="webscan_"))
        candidates: Iterable[pathlib.Path] = _iter_source(root_p, tmpdir)
    elif root_p.suffix.lower() in ARCHIVE_EXTS:
        # 单个压缩包：先解出来再遍历（之前直接 os.walk 一个文件，结果 0 个文件）
        tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="webscan_"))
        if not _extract(root_p, tmpdir):
            rep.error = f"压缩包解不开（格式不支持或已损坏）: {root_p.name}"
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
            return rep
        base_for_rel = tmpdir
        candidates = _iter_source(tmpdir, None)
    else:
        candidates = [root_p]

    name_patterns = [re.compile(p) for p in extra.get("names") or []]

    # 安装基线：全站最早的 mtime。镜像里原版文件都是同一时间落盘的，
    # 攻击者后加的 webshell 一定比它新 —— 用它把"框架自带的 eval"和"真后门"分开。
    baseline = 0.0
    try:
        if not isinstance(candidates, (list, tuple)):
            candidates = list(candidates)
        mts = []
        for _f in candidates[:max_files]:
            try:
                mts.append(_f.stat().st_mtime)
            except OSError:
                continue
        if len(mts) >= 5:            # 单文件/文件太少时不做基线判定
            baseline = min(mts)
    except Exception:  # noqa: BLE001
        baseline = 0.0

    try:
        for p in candidates:
            if rep.files >= max_files:
                rep.skipped += 1
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            is_image = p.suffix.lower() in IMAGE_EXTS
            if st.st_size > MAX_FILE_BYTES or not (_is_text_file(p) or is_image):
                rep.skipped += 1
                continue
            try:
                raw = p.read_bytes()
            except OSError:
                rep.skipped += 1
                continue
            if is_image:
                # 图片只看"有没有混进 PHP/脚本"，不做全文规则匹配（会大量误报）
                head = raw[:IMAGE_PROBE_BYTES]
                if b"<?php" not in head and b"<?=" not in head:
                    rep.skipped += 1
                    continue
                text = head.decode("latin-1", "replace")
            else:
                if b"\x00" in raw[:2048]:
                    rep.skipped += 1
                    continue
                text = raw.decode("utf-8", "replace")
            try:
                rel = str(p.relative_to(base_for_rel))
            except ValueError:
                rel = p.name
            # 模板缓存产物：编译结果是 "<?php //000.. exit();?> + 序列化数据"，
            # 不是可执行后门，别占"恶意"名额（攻击者真放 shell 不会长这样）
            cache_like = (b"exit();?>" in raw[:120] or b"//000000000000" in raw[:60]) \
                and (b"a:" in raw[:400] or b"\x00" not in raw[:64])
            res = scan_text(rel, text, rules,
                            {"mode": st.st_mode, "mtime": st.st_mtime,
                             "baseline": baseline, "generated": bool(cache_like)})
            rep.files += 1
            if res.verdict == "malicious":
                rep.malicious += 1
            elif res.verdict == "suspicious":
                rep.suspicious += 1
            elif not include_clean:
                continue
            rep.results.append(res)
    finally:
        if tmpdir is not None:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    # 可疑文件名单独列出来（D盾 里也有"可疑文件"清单）
    walk_root = base_for_rel if base_for_rel.is_dir() else None
    for p in (walk_root.rglob("*") if walk_root else []):
        if not p.is_file():
            continue
        base = p.name
        if any(rx.search(base) for rx in name_patterns):
            try:
                rep.names.append(str(p.relative_to(base_for_rel)))
            except ValueError:
                rep.names.append(base)

    rep.results.sort(key=lambda r: -r.score)
    rep.elapsed = time.time() - t0
    return rep


# ------------------------------------------------------------------- 远端
PHP_GLOB = ("-name '*.php' -o -name '*.php[3-8]' -o -name '*.phtml' -o -name '*.inc' "
            "-o -name '*.jsp' -o -name '*.asp' -o -name '*.aspx' -o -name '.htaccess' "
            "-o -name '.user.ini'")


def scan_remote(cfg: Config, target: Target, webroot: Optional[str] = None,
                max_files: int = MAX_FILES) -> ShellReport:
    """把靶机 webroot 里的脚本打包拉回本地再扫（靶机上不需要任何运行时）。"""
    from .backup import _remote_webroot
    from .sshx import SSHSession

    rep = ShellReport(root=f"{target.name}:{webroot or 'auto'}")
    with SSHSession(target, cfg, retries=0) as sess:
        root = webroot or target.webroot or _remote_webroot(sess, target)
        if not root:
            rep.error = "探测不到 webroot，请在靶机配置里指定 webroot"
            return rep
        rep.root = f"{target.name}:{root}"
        chk = sess.exec(f"[ -d {_q(root)} ] && echo DIR", timeout=10)
        if "DIR" not in (chk.out or ""):
            rep.error = f"远端目录不存在: {root}"
            return rep

        remote_tar = f"/tmp/ctfops-shell-{os.getpid()}.tgz"
        cmd = (f"cd {_q(root)} && tar czf {remote_tar} --warning=no-file-changed "
               f"--exclude='*.log' --exclude='*.zip' --exclude='*.tar*' "
               f"$(find . -maxdepth 6 -type f \\( {PHP_GLOB} \\) 2>/dev/null | head -{int(max_files)}) "
               f"2>/dev/null; ls -l {remote_tar} | awk '{{print $5}}'")
        r = sess.exec(cmd, timeout=600, sudo=True)
        size = (r.out or "").strip().splitlines()[-1] if (r.out or "").strip() else ""
        if not size.isdigit():
            r = sess.exec(cmd.replace("--warning=no-file-changed", ""), timeout=600)
            size = (r.out or "").strip().splitlines()[-1] if (r.out or "").strip() else ""
        if not size.isdigit():
            rep.error = f"远端打包失败: {(r.error or r.err or r.out)[:200]}"
            return rep

        local_tar = pathlib.Path(tempfile.mkdtemp(prefix="webscan_remote_")) / "src.tgz"
        try:
            if not sess.download(remote_tar, str(local_tar)):
                rep.error = "拉回打包文件失败"
                return rep
            got = scan_path(cfg, local_tar, max_files=max_files)
            got.root = rep.root
            return got
        finally:
            sess.exec(f"rm -f {remote_tar}", timeout=10)
            import shutil
            shutil.rmtree(local_tar.parent, ignore_errors=True)


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def summarize(rep: ShellReport) -> str:
    if rep.error:
        return f"扫描失败: {rep.error}"
    parts = [f"扫描 {rep.files} 个文件（{rep.elapsed:.1f}s，规则 {rep.rules} 条）"]
    if rep.malicious:
        parts.append(f"恶意 {rep.malicious}")
    if rep.suspicious:
        parts.append(f"可疑 {rep.suspicious}")
    if not rep.malicious and not rep.suspicious:
        parts.append("未发现后门特征")
    if rep.names:
        parts.append(f"可疑文件名 {len(rep.names)}")
    return " · ".join(parts)

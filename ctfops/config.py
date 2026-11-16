"""配置加载：单一 YAML 入口，支持 ${ENV} 展开与环境变量覆盖。"""

from __future__ import annotations

import os
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

DEFAULT_FLAG_PATTERNS = [
    r"flag\{[^}\r\n]{1,200}\}",
    r"FLAG\{[^}\r\n]{1,200}\}",
    r"ctf\{[^}\r\n]{1,200}\}",
    r"ctfhub\{[^}\r\n]{1,200}\}",
    r"dasctf\{[^}\r\n]{1,200}\}",
    r"[A-Za-z0-9_]{2,20}\{[0-9a-f]{16,64}\}",
]

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def sub(m: re.Match) -> str:
            return os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else "")

        out = _ENV_RE.sub(sub, value)
        # 只对纯数字/布尔做收敛，避免端口、超时变成字符串
        if re.fullmatch(r"-?\d+", out):
            return int(out)
        if out in ("true", "True"):
            return True
        if out in ("false", "False"):
            return False
        return out
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


@dataclass
class Target:
    name: str
    host: str
    ssh_port: int = 22
    user: str = "root"
    password: Optional[str] = None
    key_file: Optional[str] = None
    web: List[str] = field(default_factory=list)  # http://ip:port
    tags: List[str] = field(default_factory=list)
    note: str = ""
    webroot: Optional[str] = None
    db: Optional[Dict[str, Any]] = None
    enabled: bool = True
    role: str = "defense"        # defense=我方靶机 / attack=攻击目标

    @property
    def is_attack(self) -> bool:
        return (self.role or "defense").lower() in ("attack", "atk", "offense", "target")

    @property
    def role_label(self) -> str:
        return "攻击" if self.is_attack else "防守"

    @property
    def ssh_label(self) -> str:
        return f"{self.user}@{self.host}:{self.ssh_port}"

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Target":
        raw = dict(raw or {})
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        data = {k: v for k, v in raw.items() if k in known}
        if "host" not in data:
            raise ValueError(f"target 缺少 host 字段: {raw}")
        data.setdefault("name", str(data["host"]))
        # web 允许写成字符串
        web = data.get("web") or []
        if isinstance(web, str):
            web = [web]
        data["web"] = web
        return cls(**data)


@dataclass
class SSHConfig:
    user: str = "root"
    password: Optional[str] = None
    key_file: Optional[str] = None
    port: int = 22
    timeout: int = 12
    banner_timeout: int = 15
    allow_agent: bool = True
    look_for_keys: bool = True


@dataclass
class AIConfig:
    enabled: bool = True
    base_url: str = "http://127.0.0.1:11434/v1"
    model: str = "qwen2.5:7b"
    api_key: str = "not-needed"
    timeout: int = 120
    temperature: float = 0.2
    max_tokens: int = 1600


@dataclass
class ScanConfig:
    nmap: str = "nmap"
    nuclei: str = "nuclei"
    nmap_top_ports: str = "1-10000"
    nuclei_severity: str = "critical,high,medium"
    # 全量 1.1 万模板扫单站要几分钟，按标签收敛到"CTF 常见类型"
    nuclei_tags: str = "cve,rce,sqli,lfi,upload,default-login,exposure,thinkphp,fastjson,shiro,weblogic,struts,spring"
    nuclei_extra_args: List[str] = field(default_factory=list)
    http_timeout: int = 8
    workers: int = 8


@dataclass
class SubmitConfig:
    """FLAG 提交适配器配置。

    mode: generic_http | manual
    generic_http 支持在 url/body/headers 里使用占位符 {flag} {host} {target} {token}
    """

    mode: str = "manual"
    url: str = ""
    method: str = "POST"
    json_body: Optional[Dict[str, Any]] = None
    form_body: Optional[Dict[str, Any]] = None
    raw_body: str = ""                 # 原样发送的 body（从浏览器 cURL 导入时常见）
    headers: Dict[str, str] = field(default_factory=dict)
    token: str = ""
    success_key: str = "success"       # 响应 JSON 中代表成功的字段
    success_value: Any = True
    message_key: str = "message"
    interval: float = 1.0              # 提交间隔，防风控
    retries: int = 3
    timeout: int = 15
    use_proxy: bool = False            # 平台在内网时保持 False，避免系统代理干扰
    strict: bool = False               # True: 响应判定不明确时按失败处理（导入的接口默认开）


@dataclass
class Config:
    path: pathlib.Path
    name: str = "ctf-ops"
    mode: str = "awd"                  # awd | ctf
    workdir: pathlib.Path = PROJECT_ROOT
    targets: List[Target] = field(default_factory=list)
    ssh: SSHConfig = field(default_factory=SSHConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    submit: SubmitConfig = field(default_factory=SubmitConfig)
    flag_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_FLAG_PATTERNS))
    backup: Dict[str, Any] = field(default_factory=dict)
    log_roots: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    # ---------- 派生路径 ----------
    @property
    def db_path(self) -> pathlib.Path:
        return self.workdir / "evidence" / "ops.db"

    @property
    def evidence_dir(self) -> pathlib.Path:
        return self.workdir / "evidence"

    @property
    def backup_dir(self) -> pathlib.Path:
        """默认备份目录；实际使用请走 backup.backup_root()（支持运行时改路径）。"""
        override = str((self.backup or {}).get("path") or "")
        if override:
            p = pathlib.Path(override).expanduser()
            return p if p.is_absolute() else (self.workdir / p)
        return self.workdir / "backups"

    @property
    def report_dir(self) -> pathlib.Path:
        return self.workdir / "report"

    def target(self, name: str) -> Target:
        for t in self.targets:
            if t.name == name or t.host == name:
                return t
        raise KeyError(f"未找到靶机: {name}（可用: {', '.join(t.name for t in self.targets)}）")

    def resolve_role(self, role: str) -> List[Target]:
        """按角色取靶机：attack / defense。"""
        want_attack = role.lower() in ("attack", "atk")
        return [t for t in self.targets if t.enabled and t.is_attack == want_attack]

    def resolve(self, names: Optional[List[str]]) -> List[Target]:
        """支持 all / 名称 / 标签 / 主机名 / @attack / @defense。"""
        active = [t for t in self.targets if t.enabled]
        if not names:
            return active
        names = list(names)
        if "all" in names:
            return active

        picked: List[Target] = []
        # 角色前缀：@attack 只打对手靶机，@defense 只动自家靶机
        if "@attack" in names:
            picked.extend(t for t in active if t.is_attack)
            names = [n for n in names if n != "@attack"]
        if "@defense" in names:
            picked.extend(t for t in active if not t.is_attack)
            names = [n for n in names if n != "@defense"]

        for n in names:
            hit = [t for t in active if n in (t.name, t.host) or n in t.tags]
            if not hit:
                raise KeyError(f"未匹配到靶机: {n}")
            for t in hit:
                if t not in picked:
                    picked.append(t)
        return picked

    def ensure_dirs(self) -> None:
        for d in (self.evidence_dir, self.backup_dir, self.report_dir,
                  self.evidence_dir / "shots", self.workdir / "logs", self.workdir / "outbox"):
            d.mkdir(parents=True, exist_ok=True)


def load_config(path: Optional[str] = None) -> Config:
    cfg_path = pathlib.Path(path).expanduser() if path else PROJECT_ROOT / "config" / "config.yaml"
    if not cfg_path.exists():
        example = PROJECT_ROOT / "config" / "config.example.yaml"
        raise FileNotFoundError(
            f"配置文件不存在: {cfg_path}\n请先复制示例：cp {example} {cfg_path} 然后修改。"
        )
    raw = _expand(yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {})

    cfg = Config(path=cfg_path)
    cfg.name = raw.get("name", cfg.name)
    cfg.mode = raw.get("mode", cfg.mode)
    cfg.workdir = pathlib.Path(raw.get("workdir") or PROJECT_ROOT).expanduser()

    targets_raw = list(raw.get("targets") or [])
    # 支持把靶机拆到单独文件，方便赛后复用
    tf = raw.get("targets_file")
    if tf:
        tf_path = pathlib.Path(tf).expanduser()
        if not tf_path.is_absolute():
            tf_path = cfg_path.parent / tf_path
        if tf_path.exists():
            tdata = _expand(yaml.safe_load(tf_path.read_text(encoding="utf-8")) or {})
            targets_raw.extend(tdata.get("targets") or [])
    cfg.targets = [Target.from_dict(t) for t in targets_raw]

    if raw.get("ssh"):
        cfg.ssh = SSHConfig(**{k: v for k, v in raw["ssh"].items()
                               if k in SSHConfig.__dataclass_fields__})  # type: ignore[attr-defined]
    if raw.get("ai"):
        cfg.ai = AIConfig(**{k: v for k, v in raw["ai"].items()
                             if k in AIConfig.__dataclass_fields__})  # type: ignore[attr-defined]
    if raw.get("scan"):
        cfg.scan = ScanConfig(**{k: v for k, v in raw["scan"].items()
                                 if k in ScanConfig.__dataclass_fields__})  # type: ignore[attr-defined]
    if raw.get("submit"):
        cfg.submit = SubmitConfig(**{k: v for k, v in raw["submit"].items()
                                     if k in SubmitConfig.__dataclass_fields__})  # type: ignore[attr-defined]
    if raw.get("flag_patterns"):
        cfg.flag_patterns = list(raw["flag_patterns"])
    cfg.backup = raw.get("backup") or {}
    cfg.log_roots = raw.get("log_roots") or [
        "/var/log", "/var/www", "/tmp", "/dev/shm", "/home", "/root"
    ]
    known_keys = {"name", "mode", "workdir", "targets", "targets_file", "ssh", "ai",
                  "scan", "submit", "flag_patterns", "backup", "log_roots"}
    cfg.extra = {k: v for k, v in raw.items() if k not in known_keys}

    # 全局默认值下沉到靶机，避免每台重复写账号
    for t in cfg.targets:
        if t.password is None and t.key_file is None:
            t.key_file = cfg.ssh.key_file
        if t.password is None:
            t.password = cfg.ssh.password
        if t.user == "root" and cfg.ssh.user:
            t.user = cfg.ssh.user
        if t.ssh_port == 22 and cfg.ssh.port != 22:
            t.ssh_port = cfg.ssh.port
        if not t.web:
            t.web = [f"http://{t.host}"]
    return cfg


def flag_regexes(cfg: Config) -> List[re.Pattern]:
    return [re.compile(p) for p in cfg.flag_patterns]

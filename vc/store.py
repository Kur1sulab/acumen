"""SQLite 存储层：漏扫发现与资产的去重合并、筛选查询、导出。

设计要点：
  * 只依赖 stdlib sqlite3；连接开 check_same_thread=False，配一把全局写锁（写入都在摄入线程/接口线程里串行）。
  * finding 的去重键 = sha1(资产 | 标题 | 端点 | 参数)，同一漏洞被多家工具/多次扫描命中时
    合并成一行：count 累加、sources 取并集、severity 取最高、first_seen 取最早。
  * asset 以 host 为键，端口信息合并进 ports JSON 数组。
  * files 表记录每个已摄入文件的内容指纹，内容没变就不重复解析。
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .parsers import sev_rank, max_sev

SEV_ORDER = ("critical", "high", "medium", "low", "info")
STATUS_CHOICES = ("待验证", "已确认", "误报", "已修复", "已忽略")


def _key(*parts: str) -> str:
    raw = "|".join((p or "").strip().lower() for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _merge_uniq(old: str, new: Iterable[str], cap: int = 6) -> str:
    """逗号分隔集合合并（保序、去重、限长）。"""
    items: List[str] = []
    for chunk in (old or "").split(","):
        chunk = chunk.strip()
        if chunk and chunk not in items:
            items.append(chunk)
    for item in new:
        item = str(item or "").strip()
        if item and item not in items:
            items.append(item)
    return ",".join(items[:cap])


class Store:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    # ------------------------------------------------------------ schema

    def _init_schema(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS findings(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    asset TEXT, ip TEXT, port INTEGER,
                    endpoint TEXT, param TEXT,
                    title TEXT, sev TEXT, sev_rank INTEGER,
                    sources TEXT, evidence TEXT,
                    count INTEGER DEFAULT 1,
                    status TEXT DEFAULT '待验证',
                    first_seen TEXT, last_seen TEXT, files TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_f_sev   ON findings(sev_rank DESC);
                CREATE INDEX IF NOT EXISTS idx_f_asset ON findings(asset);
                CREATE INDEX IF NOT EXISTS idx_f_stat  ON findings(status);

                CREATE TABLE IF NOT EXISTS assets(
                    host TEXT PRIMARY KEY,
                    ip TEXT, ports TEXT, services TEXT, title TEXT,
                    fingerprint TEXT, sources TEXT, first_seen TEXT, last_seen TEXT
                );

                CREATE TABLE IF NOT EXISTS files(
                    path TEXT PRIMARY KEY,
                    mtime REAL, size INTEGER, digest TEXT,
                    fmt TEXT, findings INTEGER, assets INTEGER,
                    note TEXT, scanned_at TEXT
                );

                CREATE TABLE IF NOT EXISTS log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT, level TEXT, msg TEXT
                );
                """
            )
            self.conn.commit()

    # ------------------------------------------------------------ 日志 / 文件状态

    def log(self, level: str, msg: str) -> None:
        with self.lock:
            self.conn.execute("INSERT INTO log(ts, level, msg) VALUES(?,?,?)", (_now(), level, msg[:800]))
            self.conn.execute("DELETE FROM log WHERE id < (SELECT MAX(id) - 2000 FROM log)")
            self.conn.commit()

    def tail_log(self, limit: int = 200, detail: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT ts, level, msg FROM log"
        if not detail:
            sql += " WHERE level != 'detail'"
        sql += " ORDER BY id DESC LIMIT ?"
        with self.lock:
            rows = self.conn.execute(sql, (limit,)).fetchall()
        return [dict(r) for r in reversed(rows)]

    def file_state(self, path: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.conn.execute("SELECT * FROM files WHERE path=?", (path,)).fetchone()
        return dict(row) if row else None

    def upsert_file(self, path: str, mtime: float, size: int, digest: str, fmt: str,
                    n_findings: int, n_assets: int, note: str) -> None:
        with self.lock:
            self.conn.execute(
                """INSERT INTO files(path,mtime,size,digest,fmt,findings,assets,note,scanned_at)
                   VALUES(?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET
                     mtime=excluded.mtime, size=excluded.size, digest=excluded.digest,
                     fmt=excluded.fmt, findings=excluded.findings, assets=excluded.assets,
                     note=excluded.note, scanned_at=excluded.scanned_at""",
                (path, mtime, size, digest, fmt, n_findings, n_assets, note[:400], _now()),
            )
            self.conn.commit()

    def file_stats(self, limit: int = 100, only_hits: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM files"
        if only_hits:
            sql += " WHERE findings > 0 OR assets > 0"
        sql += " ORDER BY (findings + assets) DESC, scanned_at DESC LIMIT ?"
        with self.lock:
            rows = self.conn.execute(sql, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ 写入

    def add_findings(self, findings: List[Dict[str, Any]], src_file: str) -> Tuple[int, int]:
        """返回 (新增条数, 合并条数)。"""
        added = merged = 0
        with self.lock:
            for f in findings:
                key = _key(f.get("asset", ""), f.get("title", ""), f.get("endpoint", ""), f.get("param", ""))
                row = self.conn.execute("SELECT * FROM findings WHERE key=?", (key,)).fetchone()
                sev = f.get("sev") or "info"
                ts = f.get("last_seen") or _now()
                if row is None:
                    self.conn.execute(
                        """INSERT INTO findings(key,asset,ip,port,endpoint,param,title,sev,sev_rank,
                                                sources,evidence,count,status,first_seen,last_seen,files)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (key, f.get("asset", ""), f.get("ip", ""), f.get("port"),
                         f.get("endpoint", ""), f.get("param", ""), f.get("title", ""),
                         sev, sev_rank(sev), f.get("source", ""), f.get("evidence", ""),
                         int(f.get("count") or 1), "待验证",
                         f.get("first_seen") or ts, ts, src_file[-300:]),
                    )
                    added += 1
                else:
                    best_sev = max_sev(row["sev"], sev)
                    first = min(x for x in [row["first_seen"], f.get("first_seen") or ts, ts] if x)
                    last = max(x for x in [row["last_seen"], ts] if x)
                    self.conn.execute(
                        """UPDATE findings SET count=?, sev=?, sev_rank=?, sources=?, evidence=?,
                               first_seen=?, last_seen=?, files=?, ip=COALESCE(NULLIF(ip,''),?), 
                               port=COALESCE(port,?)
                           WHERE key=?""",
                        (row["count"] + int(f.get("count") or 1), best_sev, sev_rank(best_sev),
                         _merge_uniq(row["sources"], [f.get("source", "")]),
                         (row["evidence"] or f.get("evidence") or "")[:600],
                         first, last, _merge_uniq(row["files"], [src_file[-300:]]),
                         f.get("ip", ""), f.get("port"), key),
                    )
                    merged += 1
            self.conn.commit()
        return added, merged

    def add_assets(self, assets: List[Dict[str, Any]], src_file: str) -> int:
        touched = 0
        with self.lock:
            for a in assets:
                host = (a.get("host") or a.get("ip") or "").strip()
                if not host:
                    continue
                row = self.conn.execute("SELECT * FROM assets WHERE host=?", (host,)).fetchone()
                port_entry = {"port": a.get("port"), "proto": a.get("proto", ""),
                              "service": a.get("service", ""), "title": a.get("title", "")}
                if row is None:
                    self.conn.execute(
                        """INSERT INTO assets(host,ip,ports,services,title,fingerprint,sources,first_seen,last_seen)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (host, a.get("ip", ""), json.dumps([port_entry], ensure_ascii=False),
                         a.get("service", ""), a.get("title", ""), a.get("fingerprint", ""),
                         a.get("source", ""), _now(), _now()),
                    )
                    touched += 1
                else:
                    try:
                        ports = json.loads(row["ports"] or "[]")
                    except json.JSONDecodeError:
                        ports = []
                    if a.get("port") not in (None, ""):
                        if not any(p.get("port") == a.get("port") and p.get("proto") == a.get("proto") for p in ports):
                            ports.append(port_entry)
                    self.conn.execute(
                        """UPDATE assets SET ip=COALESCE(NULLIF(?,''),ip), ports=?, services=?,
                               title=COALESCE(NULLIF(?,''),title), fingerprint=COALESCE(NULLIF(?,''),fingerprint),
                               sources=?, last_seen=?
                           WHERE host=?""",
                        (a.get("ip", ""), json.dumps(ports, ensure_ascii=False),
                         _merge_uniq(row["services"], [a.get("service", "")]),
                         a.get("title", ""), a.get("fingerprint", ""),
                         _merge_uniq(row["sources"], [a.get("source", "")]), _now(), host),
                    )
            self.conn.commit()
        return touched

    # ------------------------------------------------------------ 查询

    def summary(self) -> Dict[str, Any]:
        with self.lock:
            sev_rows = self.conn.execute("SELECT sev, COUNT(*) n, SUM(count) hits FROM findings GROUP BY sev").fetchall()
            total_findings = self.conn.execute("SELECT COUNT(*) c, SUM(count) h FROM findings").fetchone()
            total_assets = self.conn.execute("SELECT COUNT(*) c FROM assets").fetchone()["c"]
            total_files = self.conn.execute("SELECT COUNT(*) c, SUM(findings) f, SUM(assets) a FROM files").fetchone()
            by_source = [dict(r) for r in self.conn.execute(
                """SELECT sources, COUNT(*) n FROM findings GROUP BY sources ORDER BY n DESC LIMIT 8""").fetchall()]
            by_status = [dict(r) for r in self.conn.execute(
                "SELECT status, COUNT(*) n FROM findings GROUP BY status").fetchall()]
            top_assets = [dict(r) for r in self.conn.execute(
                """SELECT asset, COUNT(*) n, MAX(sev_rank) r FROM findings WHERE asset<>''
                   GROUP BY asset ORDER BY r DESC, n DESC LIMIT 12""").fetchall()]
            by_type = [dict(r) for r in self.conn.execute(
                """SELECT title, COUNT(*) n, MAX(sev_rank) r FROM findings
                   GROUP BY title ORDER BY r DESC, n DESC LIMIT 12""").fetchall()]
            last = self.conn.execute("SELECT MAX(scanned_at) t FROM files").fetchone()["t"]
        sev_counts = {s: 0 for s in SEV_ORDER}
        hits = {s: 0 for s in SEV_ORDER}
        for r in sev_rows:
            if r["sev"] in sev_counts:
                sev_counts[r["sev"]] = r["n"]
                hits[r["sev"]] = r["hits"] or 0
        return {
            "findings": total_findings["c"] or 0,
            "hits": total_findings["h"] or 0,
            "assets": total_assets,
            "files": total_files["c"] or 0,
            "severity": sev_counts,
            "severity_hits": hits,
            "by_source": by_source,
            "by_status": by_status,
            "top_assets": top_assets,
            "by_type": by_type,
            "last_scan": last,
            "generated_at": _now(),
        }

    def findings(self, sev: str = "", asset: str = "", status: str = "", q: str = "",
                 limit: int = 200, offset: int = 0) -> Dict[str, Any]:
        where: List[str] = []
        args: List[Any] = []
        if sev:
            where.append("sev=?")
            args.append(sev)
        if status:
            where.append("status=?")
            args.append(status)
        if asset:
            where.append("asset LIKE ?")
            args.append(f"%{asset}%")
        if q:
            where.append("(title LIKE ? OR endpoint LIKE ? OR evidence LIKE ? OR asset LIKE ?)")
            args.extend([f"%{q}%"] * 4)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.lock:
            total = self.conn.execute(f"SELECT COUNT(*) c FROM findings {clause}", args).fetchone()["c"]
            rows = self.conn.execute(
                f"""SELECT * FROM findings {clause}
                    ORDER BY sev_rank DESC, count DESC, last_seen DESC LIMIT ? OFFSET ?""",
                args + [limit, offset],
            ).fetchall()
        return {"total": total, "rows": [dict(r) for r in rows]}

    def assets(self, q: str = "", limit: int = 300, offset: int = 0) -> Dict[str, Any]:
        where, args = [], []
        if q:
            where.append("(host LIKE ? OR ip LIKE ? OR services LIKE ? OR title LIKE ?)")
            args.extend([f"%{q}%"] * 4)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.lock:
            total = self.conn.execute(f"SELECT COUNT(*) c FROM assets {clause}", args).fetchone()["c"]
            rows = self.conn.execute(
                f"SELECT * FROM assets {clause} ORDER BY host LIMIT ? OFFSET ?", args + [limit, offset]
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["ports"] = json.loads(d.get("ports") or "[]")
            except json.JSONDecodeError:
                d["ports"] = []
            out.append(d)
        return {"total": total, "rows": out}

    def set_status(self, ids: List[int], status: str) -> int:
        if status not in STATUS_CHOICES:
            raise ValueError(f"非法状态：{status}")
        if not ids:
            return 0
        q = ",".join("?" * len(ids))
        with self.lock:
            cur = self.conn.execute(f"UPDATE findings SET status=? WHERE id IN ({q})", [status] + ids)
            self.conn.commit()
            return cur.rowcount

    # ------------------------------------------------------------ 导出

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["严重度", "漏洞名称", "资产", "IP", "端口", "端点", "参数", "命中次数", "来源", "状态", "首次发现", "最近发现", "证据"])
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY sev_rank DESC, count DESC, asset").fetchall()
        for r in rows:
            w.writerow([r["sev"], r["title"], r["asset"], r["ip"], r["port"], r["endpoint"], r["param"],
                        r["count"], r["sources"], r["status"], r["first_seen"], r["last_seen"], r["evidence"]])
        return buf.getvalue()

    def export_md(self) -> str:
        s = self.summary()
        lines = [f"# 漏扫结果整理（{s['generated_at']}）", ""]
        lines.append(f"- 发现条目：**{s['findings']}**（累计命中 {s['hits']} 次）")
        lines.append(f"- 资产：**{s['assets']}**　来源文件：**{s['files']}**")
        sev_txt = " / ".join(f"{k} {v}" for k, v in s["severity"].items() if v)
        lines.append(f"- 分级：{sev_txt or '（空）'}")
        lines += ["", "## 漏洞清单", "",
                  "| 严重度 | 漏洞 | 资产 | 端点 | 命中 | 来源 | 状态 |",
                  "|---|---|---|---|---|---|---|"]
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY sev_rank DESC, count DESC LIMIT 500").fetchall()
        for r in rows:
            ep = (r["endpoint"] or "").replace("|", "\\|")
            lines.append(f"| {r['sev']} | {r['title']} | {r['asset']} | {ep} | {r['count']} | {r['sources']} | {r['status']} |")
        if s["top_assets"]:
            lines += ["", "## 按资产分布", "", "| 资产 | 条目 | 最高级别 |", "|---|---|---|"]
            rank_name = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
            for a in s["top_assets"]:
                lines.append(f"| {a['asset']} | {a['n']} | {rank_name.get(a['r'], 'info')} |")
        return "\n".join(lines) + "\n"

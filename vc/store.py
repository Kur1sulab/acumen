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
import re
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .parsers import sev_rank, max_sev
from .verify import (LIVENESS_LABELS, LIVENESS_STATES, LIVENESS_TOKENS,
                     liveness_of, liveness_summary)
from . import waf as wafmod

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
        self._migrate()

    def _migrate(self) -> None:
        """老库补列，幂等。"""
        with self.lock:
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(findings)")}
            if "cve" not in cols:
                self.conn.execute("ALTER TABLE findings ADD COLUMN cve TEXT DEFAULT ''")
            # v1.3.0：复证三件套 —— 复现命令 + 复验结论/时间/次数
            for col, ddl in (("repro", "TEXT DEFAULT ''"),
                             ("verify_state", "TEXT DEFAULT ''"),
                             ("verify_at", "TEXT DEFAULT ''"),
                             ("verify_times", "INTEGER DEFAULT 0"),
                             ("verify_note", "TEXT DEFAULT ''"),
                             ("base", "TEXT DEFAULT ''"),
                             # WAF 三态：blocked/absent/unknown/present。
                             # 「被拦」不许计成「已确认不存在」，所以状态要和 404 分开存。
                             ("waf_state", "TEXT DEFAULT ''"),
                             ("waf", "TEXT DEFAULT ''")):
                if col not in cols:
                    self.conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {ddl}")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_f_cve ON findings(cve)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_f_vfy ON findings(verify_state)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_f_waf ON findings(waf_state)")
            self.conn.commit()

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
                    title TEXT, cve TEXT DEFAULT '', sev TEXT, sev_rank INTEGER,
                    sources TEXT, evidence TEXT,
                    count INTEGER DEFAULT 1,
                    status TEXT DEFAULT '待验证',
                    first_seen TEXT, last_seen TEXT, files TEXT,
                    repro TEXT DEFAULT '',
                    verify_state TEXT DEFAULT '', verify_at TEXT DEFAULT '',
                    verify_times INTEGER DEFAULT 0, verify_note TEXT DEFAULT '',
                    base TEXT DEFAULT '',
                    waf_state TEXT DEFAULT '', waf TEXT DEFAULT ''
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
                        """INSERT INTO findings(key,asset,ip,port,endpoint,param,title,cve,sev,sev_rank,
                                                sources,evidence,count,status,first_seen,last_seen,files,repro,base,
                                                waf_state,waf)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (key, f.get("asset", ""), f.get("ip", ""), f.get("port"),
                         f.get("endpoint", ""), f.get("param", ""), f.get("title", ""),
                         f.get("cve", ""), sev, sev_rank(sev), f.get("source", ""), f.get("evidence", ""),
                         int(f.get("count") or 1), "待验证",
                         f.get("first_seen") or ts, ts, src_file[-300:],
                         str(f.get("repro") or "")[:1200], str(f.get("base") or "")[:200],
                         wafmod.norm_state(f.get("waf_state"), strict=False),
                         str(f.get("waf") or "")[:120]),
                    )
                    added += 1
                else:
                    best_sev = max_sev(row["sev"], sev)
                    first = min(x for x in [row["first_seen"], f.get("first_seen") or ts, ts] if x)
                    last = max(x for x in [row["last_seen"], ts] if x)
                    self.conn.execute(
                        """UPDATE findings SET count=?, sev=?, sev_rank=?, sources=?, evidence=?,
                               first_seen=?, last_seen=?, files=?, ip=COALESCE(NULLIF(ip,''),?), 
                               port=COALESCE(port,?),
                               cve=?, repro=COALESCE(NULLIF(repro,''),?),
                               base=COALESCE(NULLIF(base,''),?),
                               waf_state=?, waf=?
                           WHERE key=?""",
                        (row["count"] + int(f.get("count") or 1), best_sev, sev_rank(best_sev),
                         _merge_uniq(row["sources"], [f.get("source", "")]),
                         (row["evidence"] or f.get("evidence") or "")[:600],
                         first, last, _merge_uniq(row["files"], [src_file[-300:]]),
                         f.get("ip", ""), f.get("port"),
                         _merge_uniq(row["cve"], [f.get("cve", "")], cap=8),
                         str(f.get("repro") or "")[:1200],
                         str(f.get("base") or "")[:200],
                         # 同一命中被多份产物看到时取「最坏」的那格：被拦的证据不许被后来的
                         # 404 覆盖掉，否则合并一次就把「拦」洗成「不存在」。
                         wafmod.merge_state(row["waf_state"] or "", str(f.get("waf_state") or "")),
                         _merge_uniq(row["waf"], str(f.get("waf") or "").split(","), cap=4), key),
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
                        # 端口去重时把「空 proto」当通配：同一个 8899 先由敏感路径记过
                        # （只知道能访问），再由端口扫描补上 tcp 协议，否则会重复两行。
                        same = next((p for p in ports
                                     if p.get("port") == a.get("port")
                                     and (not p.get("proto") or not a.get("proto")
                                          or p.get("proto") == a.get("proto"))), None)
                        if same is None:
                            ports.append(port_entry)
                        else:
                            for k in ("proto", "service", "title"):
                                if not same.get(k) and port_entry.get(k):
                                    same[k] = port_entry[k]
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
            repro_n = self.conn.execute("SELECT COUNT(*) c FROM findings WHERE repro<>''").fetchone()["c"]
            # WAF 三态分布：抬头要能一眼看出「这库里有多少条是被拦，不是不存在」
            by_waf = [dict(r) for r in self.conn.execute(
                "SELECT waf_state, COUNT(*) n FROM findings WHERE waf_state<>'' "
                "GROUP BY waf_state").fetchall()]
        by_verify = self.verify_stats()   # 锁是 RLock，放在 with 外面只为读着清楚
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
            "by_verify": by_verify,
            "by_waf": by_waf,
            "repro": repro_n or 0,
            "top_assets": top_assets,
            "by_type": by_type,
            "last_scan": last,
            "generated_at": _now(),
        }

    @staticmethod
    def _filter(sev: str = "", status: str = "", q: str = "", asset: str = "",
                liveness: str = "", waf: str = "") -> Tuple[str, List[Any]]:
        """筛选子句：列表页与导出共用同一套条件，保证「导出的就是你看到的」。"""
        where: List[str] = []
        args: List[Any] = []
        if sev:
            where.append("sev=?")
            args.append(sev)
        if status:
            where.append("status=?")
            args.append(status)
        if liveness:
            # 存活状态从 verify_state 翻译而来（唯一真相源，见 verify.liveness_of）。
            # UNVERIFIED = 从没写过复验结论；老库迁移行可能是 NULL，一并算上。
            token = str(liveness).strip().upper()
            if token not in LIVENESS_STATES:
                raise ValueError(f"未知存活状态：{liveness}")
            if token == "UNVERIFIED":
                where.append("(verify_state IS NULL OR verify_state='')")
            else:
                where.append("verify_state=?")
                args.append(LIVENESS_STATES[token])
        if asset:
            where.append("asset LIKE ?")
            args.append(f"%{asset}%")
        if waf:
            # WAF 三态过滤（blocked/absent/unknown/present）。认不出的取值直接抛，
            # 静默忽略会让人把「筛出来是空的」读成「库里没有」——又一个假结论。
            where.append("waf_state=?")
            args.append(wafmod.norm_state(waf))
        if q:
            where.append("(title LIKE ? OR endpoint LIKE ? OR evidence LIKE ? OR asset LIKE ?)")
            args.extend([f"%{q}%"] * 4)
        return (("WHERE " + " AND ".join(where)) if where else ""), args

    def findings(self, sev: str = "", asset: str = "", status: str = "", q: str = "",
                 limit: int = 200, offset: int = 0, liveness: str = "",
                 waf: str = "") -> Dict[str, Any]:
        clause, args = self._filter(sev, status, q, asset, liveness=liveness, waf=waf)
        with self.lock:
            total = self.conn.execute(f"SELECT COUNT(*) c FROM findings {clause}", args).fetchone()["c"]
            rows = self.conn.execute(
                f"""SELECT * FROM findings {clause}
                    ORDER BY sev_rank DESC, count DESC, last_seen DESC LIMIT ? OFFSET ?""",
                args + [limit, offset],
            ).fetchall()
        return {"total": total, "rows": [dict(r) for r in rows]}

    SEV_ORDER = ("critical", "high", "medium", "low", "info")

    def assets(self, q: str = "", limit: int = 300, offset: int = 0) -> Dict[str, Any]:
        """资产清单 = 资产表 ∪ 漏洞里出现过的资产。

        两边的"主机名"经常不是同一套命名（端口扫描给 public-ip-xxx，报告里是 10.71.x.x），
        只查资产表会得到一堆"暂无漏洞"的空卡 —— 所以漏洞侧出现的资产也补成一行，
        ports / 来源 / 风险全从既有记录里推出来。
        """
        where, args = [], []
        if q:
            where.append("(host LIKE ? OR ip LIKE ? OR services LIKE ? OR title LIKE ?)")
            args.extend([f"%{q}%"] * 4)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self.lock:
            rows = self.conn.execute(f"SELECT * FROM assets {clause} ORDER BY host", args).fetchall()
            fagg = self.conn.execute(
                "SELECT asset, sev, port, COUNT(*) n, MAX(last_seen) ls, GROUP_CONCAT(DISTINCT sources) src "
                "FROM findings WHERE asset <> '' GROUP BY asset, sev, port").fetchall()
        out: List[Dict[str, Any]] = []
        by_host: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            d = dict(r)
            try:
                d["ports"] = json.loads(d.get("ports") or "[]")
            except json.JSONDecodeError:
                d["ports"] = []
            out.append(d)
            by_host[d["host"]] = d

        with self.lock:
            # 每个资产"最高等级那条漏洞"的标题 —— 资产卡标题空的时候拿它填，比留白有用
            tops = self.conn.execute(
                "SELECT asset, title FROM findings WHERE asset <> '' AND title <> '' "
                "ORDER BY asset, sev_rank DESC, count DESC").fetchall()
        hint: Dict[str, str] = {}
        for t in tops:
            hint.setdefault(t["asset"], t["title"])

        risk: Dict[str, Dict[str, Any]] = {}
        for a in fagg:
            host = a["asset"]
            item = risk.setdefault(host, {"mix": {}, "ports": set(), "sources": set(), "last": ""})
            item["mix"][a["sev"] or "info"] = item["mix"].get(a["sev"] or "info", 0) + a["n"]
            if a["port"]:
                item["ports"].add(int(a["port"]))
            for s in str(a["src"] or "").split(","):
                if s.strip():
                    item["sources"].add(s.strip())
            if (a["ls"] or "") > item["last"]:
                item["last"] = a["ls"] or ""

        mix_by_host: Dict[str, Dict[str, int]] = {}
        for host, item in risk.items():
            d = by_host.get(host)
            # 漏洞侧的资产名可能带端口（1.2.3.4:8899），资产表按主机名存。
            # 同一台机器的两种写法必须合并成一张卡：否则页面上会出现两张卡，
            # 一张有端口没漏洞、一张有漏洞没端口，看着像两台机器。
            if d is None and ":" in str(host):
                bare = str(host).rsplit(":", 1)[0]
                if bare in by_host:
                    d = by_host[bare]
            if d is None:
                if q and q.lower() not in str(host).lower():
                    continue
                covered = set()
                d = {
                    "host": host, "ip": host if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else "",
                    "ports": [{"port": p, "proto": "tcp", "service": ""}
                              for p in sorted(item["ports"] - covered)],
                    "services": "", "title": "", "fingerprint": "",
                    "sources": ",".join(sorted(item["sources"])) or "report",
                    "first_seen": "", "last_seen": item["last"],
                }
                out.append(d)
                by_host[host] = d
            else:
                covered = {int(p.get("port") or 0) for p in d["ports"]}
                for p in sorted(item["ports"] - covered):
                    d["ports"].append({"port": p, "proto": "tcp", "service": ""})
                if not d.get("last_seen") or (item["last"] or "") > d["last_seen"]:
                    d["last_seen"] = item["last"]
                if not d.get("sources"):
                    d["sources"] = ",".join(sorted(item["sources"]))
            # 严重度分布按「合并后」的主机名累计，否则合并过的卡会显示 0 条漏洞
            bucket = mix_by_host.setdefault(d["host"], {})
            for k, v in (item["mix"] or {}).items():
                bucket[k] = bucket.get(k, 0) + v

        for d in out:
            m = mix_by_host.get(d.get("host") or "") or {}
            d["sev_mix"] = {k: m.get(k, 0) for k in self.SEV_ORDER}
            d["n_find"] = sum(d["sev_mix"].values())
            d["top_sev"] = next((k for k in self.SEV_ORDER if d["sev_mix"][k]), "")
            d["hint"] = hint.get(d.get("host") or "", "")

        out.sort(key=lambda d: str(d.get("host") or ""))
        total = len(out)
        return {"total": total, "rows": out[offset:offset + limit]}

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

    # ------------------------------------------------------------ 复证（v1.3.0）

    def findings_by_ids(self, ids: List[int]) -> List[Dict[str, Any]]:
        """按 id 取原始行——复验要的是每条命中的来源、目标、标题。"""
        ids = [int(x) for x in (ids or [])]
        if not ids:
            return []
        q = ",".join("?" * len(ids))
        with self.lock:
            rows = self.conn.execute(f"SELECT * FROM findings WHERE id IN ({q})", ids).fetchall()
        return [dict(r) for r in rows]

    def set_verify(self, updates: List[Tuple[int, str, str]]) -> int:
        """写复验结论：状态 + 依据 + 时间，次数自增。

        单独一个方法（而不是塞进 set_status）是因为两者的语义完全不同：
        状态是人判断的，复验是机器重跑出来的，混在一个字段里就再也分不清
        哪条是「我确认过」，哪条是「工具刚又打了一枪」。
        """
        if not updates:
            return 0
        ts = _now()
        n = 0
        with self.lock:
            for fid, state, note in updates:
                cur = self.conn.execute(
                    "UPDATE findings SET verify_state=?, verify_at=?, verify_times=verify_times+1, "
                    "verify_note=? WHERE id=?",
                    (str(state)[:20], ts, str(note or "")[:300], int(fid)))
                n += cur.rowcount
            self.conn.commit()
        return n

    def verify_stats(self) -> List[Dict[str, Any]]:
        """按复验结论分组计数（summary() 用它填 by_verify）。"""
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT verify_state, COUNT(*) n FROM findings GROUP BY verify_state").fetchall()]

    def set_waf(self, ids: List[int], state: str, names: str = "") -> int:
        """把一批命中的 WAF 三态刷掉（复验发现被拦时用）。

        为什么单独一个方法：复验的结论（verify_state）和这次到底有没有被拦是两件事。
        被拦只说明「这次没测到」，不许顺手把命中写成「已消失」——状态得留在 waf_state 里，
        让 list/报告能当着人面说清「是拦，不是没了」。
        """
        token = wafmod.norm_state(state)
        if not ids:
            return 0
        rows = ",".join("?" * len(ids))
        with self.lock:
            cur = self.conn.execute(
                f"UPDATE findings SET waf_state=?, waf=CASE WHEN ?='' THEN waf ELSE ? END "
                f"WHERE id IN ({rows})",
                [token, names, str(names)[:120]] + [int(i) for i in ids],
            )
            self.conn.commit()
            return cur.rowcount or 0

    # ------------------------------------------------------------ 导出

    def export_csv(self, sev: str = "", status: str = "", q: str = "",
                   liveness: str = "", waf: str = "") -> str:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["严重度", "漏洞名称", "资产", "IP", "端口", "端点", "参数", "命中次数", "来源", "状态",
                    "存活", "复验", "复验时间", "首次发现", "最近发现", "证据", "复现命令", "WAF 三态"])
        clause, args = self._filter(sev, status, q, liveness=liveness, waf=waf)
        with self.lock:
            rows = self.conn.execute(
                f"SELECT * FROM findings {clause} ORDER BY sev_rank DESC, count DESC, asset", args).fetchall()
        for r in rows:
            # 导出也要带三态：别人拿 csv 去写报告时，「被拦」和「不存在」得能分开
            w.writerow([r["sev"], r["title"], r["asset"], r["ip"], r["port"], r["endpoint"], r["param"],
                        r["count"], r["sources"], r["status"], liveness_of(r), r["verify_state"], r["verify_at"],
                        r["first_seen"], r["last_seen"], r["evidence"], r["repro"],
                        wafmod.label(r["waf_state"] or "") or "未判定"])
        return buf.getvalue()

    def export_md(self, sev: str = "", status: str = "", q: str = "",
                  liveness: str = "", waf: str = "") -> str:
        s = self.summary()
        lines = [f"# 漏扫结果整理（{s['generated_at']}）", ""]
        lines.append(f"- 发现条目：**{s['findings']}**（累计命中 {s['hits']} 次）")
        lines.append(f"- 资产：**{s['assets']}**　来源文件：**{s['files']}**")
        sev_txt = " / ".join(f"{k} {v}" for k, v in s["severity"].items() if v)
        lines.append(f"- 分级：{sev_txt or '（空）'}")
        vfy = {r["verify_state"] or "（未复验）": r["n"] for r in s.get("by_verify") or []}
        if vfy:
            lines.append("- 复验：" + " / ".join(f"{k} {v}" for k, v in vfy.items()))
        live = liveness_summary(s.get("by_verify") or [])
        lines.append("- 存活：" + " / ".join(f"{LIVENESS_LABELS[t]} {live[t]}" for t in LIVENESS_TOKENS))
        wf = {wafmod.label(r["waf_state"]): r["n"] for r in (s.get("by_waf") or []) if r.get("waf_state")}
        if wf:
            # 三态要出现在报告抬头：被拦的那批不计入「确认不存在」，读者得先知道有多少条
            lines.append("- WAF 三态：" + " / ".join(f"{k} {v}" for k, v in wf.items()))
        lines += ["", "## 漏洞清单", "",
                  "| 严重度 | 漏洞 | 资产 | 端点 | 命中 | 来源 | 状态 | 复验 | WAF |",
                  "|---|---|---|---|---|---|---|---|---|"]
        clause, args = self._filter(sev, status, q, liveness=liveness, waf=waf)
        with self.lock:
            rows = self.conn.execute(
                f"SELECT * FROM findings {clause} ORDER BY sev_rank DESC, count DESC LIMIT 500",
                args).fetchall()
        for r in rows:
            ep = (r["endpoint"] or "").replace("|", "\\|")
            lines.append(f"| {r['sev']} | {r['title']} | {r['asset']} | {ep} | {r['count']} | "
                         f"{r['sources']} | {r['status']} | {r['verify_state'] or '未复验'} | "
                         f"{wafmod.label(r['waf_state'] or '') or '未判定'} |")
        repro = [r for r in rows if (r["repro"] or "").strip()]
        if repro:
            # 复现材料单独列出来：报告里能直接粘的那一段，比表格有用
            lines += ["", "## 复现材料", ""]
            for r in repro[:100]:
                lines.append(f"### {r['title']}")
                if r["endpoint"]:
                    lines.append(f"- 端点：`{r['endpoint']}`")
                lines.append(f"- 来源：`{r['sources']}`　复验：{r['verify_state'] or '未复验'}")
                if (r["evidence"] or "").strip():
                    lines.append(f"- 判据：{r['evidence']}")
                lines += ["", "```bash", r["repro"].strip(), "```", ""]
        if s["top_assets"]:
            lines += ["", "## 按资产分布", "", "| 资产 | 条目 | 最高级别 |", "|---|---|---|"]
            rank_name = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}
            for a in s["top_assets"]:
                lines.append(f"| {a['asset']} | {a['n']} | {rank_name.get(a['r'], 'info')} |")
        return "\n".join(lines) + "\n"

"""空境 Kara —— 单入口命令行（唯一界面）。

三个动词，别的一律不进命令表：

    kara                              # 状态：引擎、库、存量
    kara scan -t <目标> [-m 模式]      # 扫（-m strike 就是深度验证）
    kara list [-i 序号] [--assets]    # 看（列表 / 详情 / 资产 / 导出）
    kara verify [--ids …] [--deep]    # 复验（--deep 用验证内核真打）

约束：
  * 一条命令做一件事：没有子子命令、没有交互向导、没有配置文件。
  * 扫描与复验共用 ScanManager / Verifier，写同一个库（默认 ~/.kara/vuln.db）。
  * 引擎（Go 单文件）只负责跑，产物落收件箱，由 parsers_sweep 归一化入账。
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import time
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional

from . import __version__
from . import paths as kpaths
from . import scans as sc
from . import verify as vfy
from .ingest import Ingestor
from .store import Store

TERMINAL_STATUS = ("ok", "partial", "failed", "stopped", "interrupted", "timeout")
SEV_COLOR = {"critical": "35", "high": "31", "medium": "33", "low": "36", "info": "90"}
SEV_ORDER = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------- 输出小工具

def _tty() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty() and code else text


def _sev(sev: str) -> str:
    return _c(f"{sev:<8}", SEV_COLOR.get(sev, "0"))


def _w(s: Any) -> int:
    """显示宽度：东亚宽字符算 2 列（表格别错位）。"""
    s = "" if s is None else str(s)
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in s)


def _pad(s: Any, width: int) -> str:
    s = "" if s is None else str(s)
    return s + " " * max(0, width - _w(s))


def _cut(s: Any, width: int) -> str:
    s = "" if s is None else str(s)
    if _w(s) <= width:
        return s
    out, used = "", 0
    for ch in s:
        step = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + step > width - 1:
            break
        out, used = out + ch, used + step
    return out + "…"


def _hms(sec: float) -> str:
    sec = max(0, int(sec or 0))
    return f"{sec // 60:02d}:{sec % 60:02d}"


def _table(headers: List[str], rows: List[List[Any]], widths: List[int]) -> str:
    lines = ["  ".join(_pad(_c(h, "1"), widths[i]) for i, h in enumerate(headers))]
    lines.append("  ".join("─" * widths[i] for i in range(len(headers))))
    for r in rows:
        lines.append("  ".join(_pad(v, widths[i]) for i, v in enumerate(r)))
    return "\n".join(lines)


def probe_scheme(hostport: str) -> str:
    """裸主机（可带端口）→ https / http。

    引擎对 url 类目标默认补 https://，碰上 http 站会直接扫空：连接失败 → 0 命中，
    看着像「目标干净」。这里先握手一次再决定，省掉一次白跑。
    """
    head = hostport.split("/")[0]
    host, _, port = head.rpartition(":")
    if not host:
        host, port = head, ""
    host = host.strip("[]")
    if not host:
        return "https"

    def _port(default: int) -> int:
        return int(port) if port.isdigit() else default

    try:
        sock = socket.create_connection((host, _port(443)), timeout=3)
        ctx = ssl._create_unverified_context()
        ctx.wrap_socket(sock, server_hostname=host).close()
        return "https"
    except Exception:
        pass
    try:
        socket.create_connection((host, _port(80)), timeout=3).close()
        return "http"
    except Exception:
        return "https"


# ---------------------------------------------------------------- 装配

class Ctx:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.db = os.path.abspath(os.path.expanduser(args.db or kpaths.default_db_path()))
        self.inboxes = [os.path.abspath(os.path.expanduser(p))
                        for p in (getattr(args, "inbox", None) or kpaths.DEFAULT_INBOXES)]
        for box in self.inboxes:
            try:
                os.makedirs(box, exist_ok=True)
            except OSError:
                pass
        self.store = Store(self.db)
        self.ingestor = Ingestor(self.store, self.inboxes)

    def manager(self, mode_args: Optional[list] = None) -> sc.ScanManager:
        # ingest_cb=None：入账由本进程在确定时机跑一次，避免同一批产物入两遍
        return sc.ScanManager(
            db_path=self.db,
            inbox_root=self.inboxes[0],
            engine=getattr(self.args, "engine", ""),
            timeout=getattr(self.args, "timeout", 900),
            max_parallel=getattr(self.args, "parallel", 2),
            mode_args=mode_args,
            ingest_cb=None,
        )


# ---------------------------------------------------------------- 任务轮询

def _print_job_status(runs: List[Dict[str, Any]], elapsed: float, job_status: str) -> None:
    if not _tty():
        return
    parts = []
    for r in runs[:4]:
        parts.append(f"{_cut(r['target'], 26)} {_pad(r['pct'], 3)}% {_cut(r['step'] or r['status'], 14)}")
    more = "" if len(runs) <= 4 else f" +{len(runs) - 4}"
    line = f"{_c('[kara]', '36')} {_hms(elapsed)}  {job_status:<9} " + " │ ".join(parts) + more
    sys.stdout.write("\r\033[K" + line[:200])
    sys.stdout.flush()


def _run_job_loop(mgr, job_id: int) -> str:
    t0 = time.time()
    cursor = 0
    status = "queued"
    try:
        while True:
            j = mgr.job(job_id, log_from=cursor)
            if not j:
                print(_c("[!] 任务查不到，可能被清库了", "31"), file=sys.stderr)
                return "failed"
            log = j.get("log") or {}
            for line in log.get("lines") or []:
                if _tty():
                    sys.stdout.write("\r\033[K")
                print(f"  {_cut(line, 160)}")
            cursor = log.get("next", cursor)
            status = j.get("status", status)
            _print_job_status(j.get("runs") or [], time.time() - t0, status)
            if status in TERMINAL_STATUS:
                break
            time.sleep(0.4)
    except KeyboardInterrupt:
        print()
        print(_c("[kara] 收到中断，正在让引擎收工（进程组 TERM → KILL）…", "33"))
        mgr.stop(job_id)
        while True:
            j = mgr.job(job_id)
            if (j or {}).get("status") in TERMINAL_STATUS:
                status = j["status"]
                break
            time.sleep(0.3)
    if _tty():
        sys.stdout.write("\r\033[K")
    print()
    print(f"{_c('[kara]', '36')} 任务 #{job_id} {status} · 用时 {_hms(time.time() - t0)}")
    return status


def _ingest(ctx: Ctx) -> Dict[str, Any]:
    stats = ctx.ingestor.scan() or {}
    print(f"{_c('[kara]', '36')} 入账：新解析 {stats.get('parsed', 0)} 个产物 · "
          f"漏洞 +{stats.get('findings_added', 0)} · 合并 {stats.get('findings_merged', 0)} · "
          f"资产 +{stats.get('assets', 0)} · 解析失败 {stats.get('errors', 0)}")
    return stats


def _mode_args(args: argparse.Namespace) -> List[str]:
    """验证内核的透传参数（其它模式用不到）。"""
    out: List[str] = []
    if getattr(args, "ports", ""):
        out += ["--ports", args.ports]
    if getattr(args, "intensity", ""):
        out += ["--intensity", args.intensity]
    if getattr(args, "allow_public", False):
        out += ["--allow-public"]
    return out


def _level_of(row: Dict[str, Any]) -> str:
    """从证据串里摘出验证内核给的级别标记，如 [L2/confirmed]。"""
    ev = row.get("evidence") or ""
    if "[" in ev and "]" in ev:
        seg = ev[ev.rfind("[") + 1:ev.rfind("]")]
        if "/" in seg or seg.startswith("L"):
            return seg
    return "-"


def _show_new(ctx: Ctx, before: int) -> int:
    rows = [dict(r) for r in ctx.store.conn.execute(
        "SELECT id,sev,title,asset,endpoint,count,evidence FROM findings WHERE id > ? "
        "ORDER BY sev_rank DESC, id", (before,)).fetchall()]
    if not rows:
        print(f"{_c('[kara]', '36')} 本轮没有新增命中（老命中被重复报到的会并进原条目）")
        return 0
    print()
    print(_table(["ID", "严重度", "标题", "资产", "级别", "次数"],
                 [[r["id"], _sev(r["sev"]), _cut(r["title"], 40), _cut(r["asset"], 26),
                   _cut(_level_of(r), 12), r["count"]] for r in rows],
                 [5, 8, 40, 26, 12, 4]))
    print(f"\n看详情：{_c('kara list -i ' + str(rows[0]['id']), '36')}　"
          f"复验：{_c('kara verify --ids ' + ','.join(str(r['id']) for r in rows[:8]), '36')}")
    return 0


# ---------------------------------------------------------------- 状态（裸命令）

def cmd_status(ctx: Ctx, args: argparse.Namespace) -> int:
    mgr = ctx.manager()
    meta = mgr.meta().get("engine") or {}
    s = ctx.store.summary()
    print(f"{_c('空境 · Kara', '1')} v{__version__}　本地漏扫（单一 CLI）")
    print(f"  引擎　{meta.get('path') or '(未找到)'}"
          + (f"　{meta.get('version') or ''}" if meta.get("ok") else ""))
    if not meta.get("ok"):
        print(_c("  " + (meta.get("hint") or sc.ENGINE_HINT).replace("\n", "\n  "), "33"))
    print(f"  库　　{ctx.db}")
    sev = s["severity"]
    print(f"  存量　漏洞 {s['findings']} 条 / 命中 {s['hits']} 次　资产 {s['assets']}　文件 {s['files']}")
    print("  分级　" + "　".join(f"{k} {sev.get(k, 0)}" for k in SEV_ORDER))
    if s.get("last_scan"):
        print(f"  最近　{s['last_scan']}")
    print()
    print("  kara scan -t <目标> [-m 模式]　扫（-m strike = 深度验证，会真发请求）")
    print("  kara list [-i 序号] [--assets]　看（--csv/--md 导出）")
    print("  kara verify [--ids …] [--deep]　复验")
    return 0


# ---------------------------------------------------------------- scan

def cmd_scan(ctx: Ctx, args: argparse.Namespace) -> int:
    mode = args.mode
    mgr = ctx.manager(mode_args=_mode_args(args) if mode == "strike" else None)
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2

    raw = list(args.targets)
    if sc.MODES[mode]["kind"] == "url" and args.scheme != "raw":
        fixed = []
        for t in raw:
            if "://" in t:
                fixed.append(t)
                continue
            picked = args.scheme if args.scheme in ("http", "https") else probe_scheme(t)
            fixed.append(f"{picked}://{t}")
            print(f"  {_c('[scheme]', '36')} {t} → {picked}://{t}")
        raw = fixed
    try:
        targets = sc.normalize_targets(mode, raw)
    except sc.ScanError as exc:
        print(_c(f"[!] {exc}", "31"), file=sys.stderr)
        return 2

    before = ctx.store.conn.execute("SELECT COALESCE(MAX(id),0) c FROM findings").fetchone()["c"]
    print(f"{_c('空境 · Kara', '1')} v{__version__}　{sc.MODES[mode]['label']}")
    print(f"  模式　{sc.MODES[mode]['hint']}")
    print(f"  目标　{', '.join(targets)}")
    print(f"  引擎　{mgr.engine}")
    print()

    res = mgr.start(mode, targets, parallel=args.parallel, timeout=args.timeout)
    _run_job_loop(mgr, res["job_id"])
    _ingest(ctx)
    _show_new(ctx, before)
    return 0


# ---------------------------------------------------------------- list

def _ports_text(ports: Any, cap: int = 8) -> str:
    items = []
    for p in ports or []:
        if isinstance(p, dict):
            num, svc = p.get("port"), p.get("service") or ""
            items.append(f"{num}" + (f"({svc})" if svc else ""))
        else:
            items.append(str(p))
    if not items:
        return "-"
    head = ",".join(items[:cap])
    return head + (f" …+{len(items) - cap}" if len(items) > cap else "")


def cmd_list(ctx: Ctx, args: argparse.Namespace) -> int:
    if args.csv or args.md:
        out = os.path.abspath(os.path.expanduser(args.csv or args.md))
        if args.csv:
            # 带 BOM：Windows Excel 双击不乱码
            data = ctx.store.export_csv(sev=args.sev, status=args.status, q=args.q).encode("utf-8-sig")
        else:
            data = ctx.store.export_md(sev=args.sev, status=args.status, q=args.q).encode("utf-8")
        with open(out, "wb") as fh:
            fh.write(data)
        print(f"已写 {out}（{len(data)} 字节）")
        return 0

    if args.id is not None:
        return _show_one(ctx, args.id)

    if args.assets:
        data = ctx.store.assets(q=args.q, limit=args.limit)
        rows = data["rows"]
        if not rows:
            print("库里还没有资产。先 kara scan。")
            return 0
        print(_table(["资产", "IP", "端口", "标题 / 最高命中", "指纹", "漏洞"],
                     [[_cut(r.get("host") or "-", 30), _cut(r.get("ip") or "-", 16),
                       _cut(_ports_text(r.get("ports")), 30),
                       _cut(r.get("title") or r.get("hint") or "-", 30),
                       _cut(r.get("fingerprint") or r.get("services") or "-", 22),
                       f"{r.get('n_find') or 0}" + (f" ({r['top_sev']})" if r.get("top_sev") else "")]
                      for r in rows],
                     [30, 16, 30, 30, 22, 12]))
        print(f"\n共 {data['total']} 个资产（显示 {len(rows)}）")
        return 0

    data = ctx.store.findings(sev=args.sev, status=args.status, q=args.q, limit=args.limit)
    rows = data["rows"]
    if not rows:
        print("库里没有符合条件的条目。先 kara scan。")
        return 0
    print(_table(["ID", "严重度", "标题", "资产", "端点", "级别", "次数", "状态"],
                 [[r["id"], _sev(r["sev"]), _cut(r["title"], 36), _cut(r["asset"], 24),
                   _cut(r["endpoint"] or "-", 28), _cut(_level_of(dict(r)), 12), r["count"],
                   _cut(r["status"], 8)] for r in rows],
                 [5, 8, 36, 24, 28, 12, 4, 8]))
    print(f"\n共 {data['total']} 条（显示 {len(rows)}）　详情 {_c('kara list -i <ID>', '36')}"
          f"　导出 {_c('kara list --csv out.csv', '36')}")
    return 0


def _show_one(ctx: Ctx, row_id: int) -> int:
    rows = ctx.store.findings_by_ids([row_id])
    if not rows:
        print(f"[!] 序号 {row_id} 不存在", file=sys.stderr)
        return 2
    r = dict(rows[0])
    print(f"{_c(str(r.get('title') or ''), '1')}")
    print(f"  严重度　{_sev(r.get('sev') or 'info')}　级别 {_level_of(r)}")
    print(f"  资产　　{r.get('asset') or '-'}　端口 {r.get('port') or '-'}　IP {r.get('ip') or '-'}")
    print(f"  端点　　{r.get('endpoint') or '-'}")
    print(f"  来源　　{r.get('sources') or '-'}　次数 {r.get('count')}　状态 {r.get('status')}")
    print(f"  复验　　{r.get('verify_state') or '未复验'} {r.get('verify_note') or ''}")
    print(f"  时间　　{r.get('first_seen')} → {r.get('last_seen')}")
    if r.get("evidence"):
        print(f"  判据　　{_cut(r['evidence'], 400)}")
    if r.get("repro"):
        print(f"  复现　　{_c(str(r['repro']), '36')}")
    print(f"  产物　　{r.get('files') or '-'}")
    return 0


# ---------------------------------------------------------------- verify

def _target_of(row: Dict[str, Any]) -> str:
    """一条命中 → 可回访的目标（端点裁到 scheme://host:port，退回「资产:端口」）。"""
    ep = (row.get("endpoint") or "").strip()
    if ep.startswith(("http://", "https://")):
        u = urllib.parse.urlsplit(ep)
        if u.hostname:
            return f"{u.scheme}://{u.hostname}" + (f":{u.port}" if u.port else "")
    asset = str(row.get("asset") or "").strip()
    if asset and asset not in ("-", "unknown"):
        port = row.get("port")
        return f"{asset}:{port}" if port and ":" not in asset else asset
    return ""


def cmd_verify(ctx: Ctx, args: argparse.Namespace) -> int:
    if args.ids:
        ids = [int(x) for x in args.ids.replace(",", " ").split() if x.strip().isdigit()]
        rows = [dict(r) for r in ctx.store.findings_by_ids(ids)]
    else:
        rows = [dict(r) for r in ctx.store.findings(sev=args.sev, status=args.status,
                                                   limit=args.limit)["rows"]]
    if not rows:
        print("没有要复验的条目。")
        return 0
    if args.deep:
        return _verify_deep(ctx, rows, args)

    mgr = ctx.manager()
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2
    v = vfy.Verifier(ctx.store, engine=mgr.engine, timeout=args.timeout,
                     log=lambda lvl, msg: print(f"  [{lvl}] {msg}"))
    ids = [r["id"] for r in rows]
    print(f"复验 {len(ids)} 条：按当初发现它的同一个模式、同一个入口重跑…")
    v.start(ids)
    try:
        while True:
            st = v.status()
            if not st.get("running"):
                break
            if _tty():
                sys.stdout.write("\r\033[K" + f"{_c('[kara]', '36')} {st['done']}/{st['total']} "
                                                f"{_hms(st.get('elapsed') or 0)} "
                                                f"{_cut(st.get('current') or '', 60)}")
                sys.stdout.flush()
            time.sleep(0.4)
    except KeyboardInterrupt:
        print("\n[kara] 中断（跑完的那部分已写回库）")
        return 130
    if _tty():
        sys.stdout.write("\r\033[K")
    st = v.status()
    summary = st.get("summary") or {}
    print(f"{_c('[kara]', '36')} 复验完成　" + "　".join(f"{k} {n}" for k, n in summary.items() if n))
    for item in (st.get("last") or [])[:20]:
        print(f"  #{item.get('id')} {item.get('state')} {_cut(item.get('title') or '', 40)} "
              f"{_cut(item.get('note') or '', 40)}")
    return 0


def _verify_deep(ctx: Ctx, rows: List[Dict[str, Any]], args: argparse.Namespace) -> int:
    """--deep：用验证内核真打一遍（L1 → L2 的那一步），而不是重放只读探测。"""
    targets: List[str] = []
    for t in getattr(args, "target", None) or []:
        t = t.strip()
        if t and t.lower() not in {x.lower() for x in targets}:
            targets.append(t)
    for r in rows:
        t = _target_of(r)
        if t and t.lower() not in {x.lower() for x in targets}:
            targets.append(t)
    if not targets:
        print("这些条目没有可回访的目标（白盒报告、离线产物都这样），深度验证需要端点或资产。")
        return 0
    try:
        targets = sc.normalize_targets("strike", targets)
    except sc.ScanError as exc:
        print(_c(f"[!] {exc}", "31"), file=sys.stderr)
        return 2

    mgr = ctx.manager(mode_args=_mode_args(args))
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2
    if args.dry_run:
        print(f"{_c('空境 · Kara', '1')} v{__version__}　深度验证（dry-run）")
        print(f"  目标 {len(targets)} 个")
        for i, t in enumerate(targets, 1):
            print(f"  {i:>2}. {t}")
        print("\n--dry-run：没有发起任何请求。去掉它就跑。")
        return 0

    before = ctx.store.conn.execute("SELECT COALESCE(MAX(id),0) c FROM findings").fetchone()["c"]
    print(f"{_c('空境 · Kara', '1')} v{__version__}　深度验证")
    print(f"  来源　{len(rows)} 条命中 → 目标 {len(targets)} 个：{', '.join(targets)}")
    print(_c("  这一档会真的发请求（真登/未授权/注入探测），确认目标在授权范围内。", "33"))
    print()
    res = mgr.start("strike", targets, parallel=args.parallel, timeout=args.timeout)
    _run_job_loop(mgr, res["job_id"])
    _ingest(ctx)
    _show_new(ctx, before)
    return 0


# ---------------------------------------------------------------- 入口

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="kara",
        description="空境 Kara —— 本地漏扫（单一 CLI：scan / list / verify）",
        epilog="不给子命令就打印状态。")
    ap.add_argument("--db", default="", help=f"库路径（默认 {kpaths.default_db_path()}）")
    ap.add_argument("--inbox", action="append", default=None, help="收件箱目录，可重复")
    ap.add_argument("--engine", default="", help="引擎路径（默认自动查找）")
    ap.add_argument("--timeout", type=int, default=900, help="单目标超时秒数（默认 900）")
    ap.add_argument("--parallel", type=int, default=2, help="并发目标数（上限 4）")
    ap.add_argument("-v", "--version", action="version", version=f"kara {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="扫描（-m strike 为深度验证）")
    p.add_argument("-t", "--targets", nargs="+", required=True, help="目标（域名 / IP / URL）")
    p.add_argument("-m", "--mode", default="all", choices=list(sc.MODES), help="扫描模式")
    p.add_argument("--scheme", default="auto", choices=["auto", "http", "https", "raw"],
                   help="url 类模式的协议：auto 先握手判定（默认）")
    p.add_argument("--ports", default="", help="仅 strike：top100 / top1000 / full / 80,443")
    p.add_argument("--intensity", default="", choices=["", "low", "normal", "high"],
                   help="仅 strike：强度档位")
    p.add_argument("--allow-public", action="store_true", help="仅 strike：允许公网目标")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("list", help="看：列表 / 详情 / 资产 / 导出")
    p.add_argument("-i", "--id", type=int, default=None, help="看某一条的详情")
    p.add_argument("--assets", action="store_true", help="看资产（主机/端口/指纹）")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--status", default="", help="待验证 / 已确认 / 误报 / 已修复 / 已忽略")
    p.add_argument("--q", default="", help="关键词")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--csv", default="", help="导出 CSV 到该文件")
    p.add_argument("--md", default="", help="导出 Markdown 到该文件")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("verify", help="复验（--deep 用验证内核真打）")
    p.add_argument("--ids", default="", help="如 12,15,19；不给就按筛选批量")
    p.add_argument("--target", action="append", default=[], help="仅 --deep：直接指定目标")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--status", default="")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--deep", action="store_true", help="深度验证（会真发请求）")
    p.add_argument("--dry-run", action="store_true", help="仅 --deep：只列目标，不发请求")
    p.add_argument("--ports", default="", help="仅 --deep：top100 / full / 80,443")
    p.add_argument("--intensity", default="", choices=["", "low", "normal", "high"])
    p.add_argument("--allow-public", action="store_true")
    p.set_defaults(func=cmd_verify)

    ap.set_defaults(func=cmd_status)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    ctx = Ctx(args)
    try:
        return args.func(ctx, args) or 0
    except sc.ScanError as exc:
        print(_c(f"[!] {exc}", "31"), file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

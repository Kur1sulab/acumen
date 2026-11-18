"""空境 · Kara —— 终端模式（无 Web、无浏览器、不占端口）。

Web 控制台能做的事这里都能做：扫 → 入账 → 看 → 复验 → 导出。
区别只是不走 HTTP：全部在本进程里直连 Store / ScanManager / Verifier。

    python3 -m vc.cli scan -t 127.0.0.1:18080 --mode all
    python3 -m vc.cli list --sev high
    python3 -m vc.cli show 12
    python3 -m vc.cli verify --all --sev high
    python3 -m vc.cli export --format md -o report.md
    python3 -m vc.cli engine

设计约束（跟 Web 版共用同一套逻辑，不复制粘贴）：
  * 扫描走 scans.ScanManager（目标校验、引擎发现、进度解析、并发上限全在它手里）
  * 入库走 store.Store + ingest.Ingestor（去重合并键一致）
  * 复验走 verify.Verifier（同一模式同一入口重跑，连不上 ≠ 已消失）
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import time
import unicodedata
from typing import Any, Dict, List, Optional

from . import __version__
from . import scans as sc
from . import verify as vfy
from .ingest import Ingestor
from .store import Store
from .server import DEFAULT_INBOXES, default_db_path

TERMINAL_STATUS = ("ok", "partial", "failed", "stopped", "interrupted", "timeout")


def probe_scheme(hostport: str) -> str:
    """裸主机（可带端口）→ https / http。

    引擎对 url 类目标默认补 https://，这在 http 站（本机靶场、内网业务系统）上会直接扫空：
    连接失败 → 0 命中，看起来像「目标干净」。这里先握手一次再决定，省掉一次白跑。
    """
    head = hostport.split("/")[0]
    host, _, port = head.rpartition(":")
    if not host:                       # 没有端口
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
SEV_COLOR = {"critical": "35", "high": "31", "medium": "33", "low": "36", "info": "90"}


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


# ---------------------------------------------------------------- 装配

class Ctx:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.db = os.path.abspath(os.path.expanduser(args.db or default_db_path()))
        self.inboxes = [os.path.abspath(os.path.expanduser(p))
                        for p in (args.inbox or DEFAULT_INBOXES)]
        for box in self.inboxes:
            try:
                os.makedirs(box, exist_ok=True)
            except OSError:
                pass
        self.store = Store(self.db)
        self.ingestor = Ingestor(self.store, self.inboxes)

    def manager(self) -> sc.ScanManager:
        # ingest_cb=None：Web 版靠回调把产物推进库，终端版自己算准时机跑一次就够了。
        # 两边都跑会让同一批产物入账两遍——第一遍新增、第二遍全算「合并」，统计会骗人。
        return sc.ScanManager(
            db_path=self.db,
            inbox_root=self.inboxes[0],
            engine=self.args.engine,
            timeout=getattr(self.args, "timeout", 900),
            max_parallel=getattr(self.args, "parallel", 2),
            ingest_cb=None,
        )


# ---------------------------------------------------------------- scan

def _print_job_status(runs: List[Dict[str, Any]], elapsed: float, job_status: str) -> None:
    """一行实时状态（只在 TTY 里刷，重定向到文件时不铺垃圾）。"""
    if not _tty():
        return
    parts = []
    for r in runs[:4]:
        parts.append(f"{_cut(r['target'], 26)} {_pad(r['pct'], 3)}% {_cut(r['step'] or r['status'], 14)}")
    more = "" if len(runs) <= 4 else f" +{len(runs) - 4}"
    line = f"{_c('[kara]', '36')} {_hms(elapsed)}  {job_status:<9} " + " │ ".join(parts) + more
    sys.stdout.write("\r\033[K" + line[:200])
    sys.stdout.flush()


def cmd_scan(ctx: Ctx, args: argparse.Namespace) -> int:
    mgr = ctx.manager()
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2
    mode = args.mode
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

    print(f"{_c('空境 · Kara', '1')} v{__version__}　终端模式")
    print(f"  引擎　{_c(mgr.engine, '36')}")
    print(f"  模式　{sc.MODES[mode]['label']}（{sc.MODES[mode]['hint']}）")
    print(f"  目标　{', '.join(targets)}")
    print(f"  库　　{ctx.db}")
    print(f"  产物　{ctx.inboxes[0]}")
    print()

    res = mgr.start(mode, targets, parallel=args.parallel, timeout=args.timeout)
    job_id = res["job_id"]
    t0 = time.time()
    cursor = 0
    status = "queued"
    try:
        while True:
            j = mgr.job(job_id, log_from=cursor)
            if not j:
                print(_c("[!] 任务查不到，可能被清库了", "31"), file=sys.stderr)
                return 2
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
    elapsed = time.time() - t0
    print()
    print(f"{_c('[kara]', '36')} 任务 #{job_id} {status} · 用时 {_hms(elapsed)}")

    # 引擎产物 → 库（job 线程末尾也会触发一次，这里显式跑一遍拿确定的统计）
    stats = ctx.ingestor.scan() or {}
    print(f"{_c('[kara]', '36')} 入账：新解析 {stats.get('parsed', 0)} 个产物 · "
          f"漏洞 +{stats.get('findings_added', 0)} · 合并 {stats.get('findings_merged', 0)} · "
          f"资产 +{stats.get('assets', 0)} · 解析失败 {stats.get('errors', 0)}")

    rows = [dict(r) for r in ctx.store.conn.execute(
        "SELECT id,sev,title,asset,endpoint,count FROM findings WHERE id > ? "
        "ORDER BY sev_rank DESC, id", (before,)).fetchall()]
    if not rows:
        print(f"{_c('[kara]', '36')} 本轮没有新增命中（老命中被重复报到的会并进原条目）")
        return 0
    print()
    print(_table(["ID", "严重度", "标题", "资产", "端点", "次数"],
                 [[r["id"], _sev(r["sev"]), _cut(r["title"], 40), _cut(r["asset"], 28),
                   _cut(r["endpoint"] or "-", 34), r["count"]] for r in rows],
                 [5, 8, 40, 28, 34, 4]))
    print()
    first_id = rows[0]["id"]
    verify_ids = ",".join(str(r["id"]) for r in rows[:8])
    print(f"常用：{_c('python3 -m vc.cli show ' + str(first_id), '36')}　看详情与复现命令　"
          f"{_c('python3 -m vc.cli verify --ids ' + verify_ids, '36')}　复验")
    return 0


# ---------------------------------------------------------------- list / show

def cmd_list(ctx: Ctx, args: argparse.Namespace) -> int:
    data = ctx.store.findings(sev=args.sev, status=args.status, q=args.q, limit=args.limit)
    rows = data["rows"]
    if not rows:
        print("库里没有符合条件的条目。先 'scan' 或 'ingest'。")
        return 0
    print(_table(["ID", "严重度", "标题", "资产", "端点", "次数", "状态", "复验"],
                 [[r["id"], _sev(r["sev"]), _cut(r["title"], 38), _cut(r["asset"], 26),
                   _cut(r["endpoint"] or "-", 30), r["count"], _cut(r["status"], 8),
                   _cut(r.get("verify") or "-", 8)] for r in rows],
                 [5, 8, 38, 26, 30, 4, 8, 8]))
    print(f"\n共 {data['total']} 条（显示 {len(rows)}）")
    return 0


def _ports_text(ports: Any, cap: int = 8) -> str:
    """store 里的 ports 是 [{"port":80,"service":"http"}, …]，这里摊成一行。"""
    items = []
    for p in ports or []:
        if isinstance(p, dict):
            num = p.get("port")
            svc = p.get("service") or ""
            items.append(f"{num}" + (f"({svc})" if svc else ""))
        else:
            items.append(str(p))
    if not items:
        return "-"
    head = ",".join(items[:cap])
    return head + (f" …+{len(items) - cap}" if len(items) > cap else "")


def cmd_assets(ctx: Ctx, args: argparse.Namespace) -> int:
    data = ctx.store.assets(q=args.q, limit=args.limit)
    rows = data["rows"]
    if not rows:
        print("库里还没有资产。先 'scan' 或 'ingest'。")
        return 0
    print(_table(["资产", "IP", "端口", "标题 / 最高命中", "指纹", "漏洞"],
                 [[_cut(r.get("host") or "-", 30),
                   _cut(r.get("ip") or "-", 16),
                   _cut(_ports_text(r.get("ports")), 30),
                   _cut(r.get("title") or r.get("hint") or "-", 30),
                   _cut(r.get("fingerprint") or r.get("services") or "-", 22),
                   f"{r.get('n_find') or 0}" + (f" ({r['top_sev']})" if r.get("top_sev") else "")] for r in rows],
                 [30, 16, 30, 30, 22, 12]))
    print(f"\n共 {data['total']} 个资产（显示 {len(rows)}）")
    return 0


def cmd_show(ctx: Ctx, args: argparse.Namespace) -> int:
    rows = ctx.store.findings_by_ids([args.id])
    if not rows:
        print(f"[!] id={args.id} 不存在", file=sys.stderr)
        return 2
    r = rows[0]
    print(f"{_c(str(r.get('title') or ''), '1')}")
    print(f"  严重度　{_sev(r.get('sev') or 'info')}  {r.get('cve') or ''}")
    print(f"  资产　　{r.get('asset') or '-'}　端口 {r.get('port') or '-'}　IP {r.get('ip') or '-'}")
    print(f"  端点　　{r.get('endpoint') or '-'}")
    print(f"  参数　　{r.get('param') or '-'}")
    print(f"  来源　　{r.get('sources') or '-'}")
    print(f"  次数　　{r.get('count')}　状态 {r.get('status')}　复验 {r.get('verify') or '-'} {r.get('verify_note') or ''}")
    print(f"  时间　　{r.get('first_seen')} → {r.get('last_seen')}")
    if r.get("evidence"):
        print(f"  判据　　{_cut(r['evidence'], 400)}")
    if r.get("repro"):
        print(f"  复现　　{_c(str(r['repro']), '36')}")
    print(f"  产物　　{r.get('files') or '-'}")
    return 0


# ---------------------------------------------------------------- ingest / export

def cmd_ingest(ctx: Ctx, args: argparse.Namespace) -> int:
    stats = ctx.ingestor.scan(force=args.force) or {}
    print(f"收件箱：{', '.join(ctx.inboxes)}")
    print(f"扫描 {stats.get('seen', 0)} 个文件 · 新解析 {stats.get('parsed', 0)} · "
          f"漏洞 +{stats.get('findings_added', 0)} · 合并 {stats.get('findings_merged', 0)} · "
          f"资产 +{stats.get('assets', 0)} · 跳过 {stats.get('skipped', 0)} · "
          f"失败 {stats.get('errors', 0)}　用时 {stats.get('elapsed', 0)}s")
    if stats.get("truncated"):
        print("  [!] 达到单次扫描文件上限，剩下的留到下次")
    return 0


def cmd_export(ctx: Ctx, args: argparse.Namespace) -> int:
    if args.format == "csv":
        # 跟网页导出一致：utf-8-sig（带 BOM），否则 Windows Excel 双击就是乱码
        text = ctx.store.export_csv(sev=args.sev, status=args.status, q=args.q)
        data = text.encode("utf-8-sig")
    else:
        text = ctx.store.export_md(sev=args.sev, status=args.status, q=args.q)
        data = text.encode("utf-8")
    if args.out:
        path = os.path.abspath(os.path.expanduser(args.out))
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"已写 {path}（{len(data)} 字节）")
    else:
        sys.stdout.write(text)
    return 0


# ---------------------------------------------------------------- verify

def cmd_verify(ctx: Ctx, args: argparse.Namespace) -> int:
    mgr = ctx.manager()
    if not mgr.engine:
        print(_c(sc.ENGINE_HINT, "31"), file=sys.stderr)
        return 2
    if args.ids:
        ids = [int(x) for x in args.ids.replace(",", " ").split() if x.strip().isdigit()]
    else:
        ids = [r["id"] for r in ctx.store.findings(sev=args.sev, status=args.status,
                                                   limit=args.limit)["rows"]]
    if not ids:
        print("没有要复验的条目。")
        return 0

    v = vfy.Verifier(ctx.store, engine=mgr.engine, timeout=args.timeout,
                     log=lambda lvl, msg: print(f"  [{lvl}] {msg}"))
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
        print("\n[kara] 中断（当前批次跑完的那部分已写回库）")
        return 130
    if _tty():
        sys.stdout.write("\r\033[K")
    st = v.status()
    summary = st.get("summary") or {}
    print(f"{_c('[kara]', '36')} 复验完成　" + "　".join(f"{k} {n}" for k, n in summary.items() if n))
    for item in (st.get("last") or [])[:20]:
        print(f"  #{item.get('id')} {item.get('state')} {_cut(item.get('title') or '', 40)} {_cut(item.get('note') or '', 40)}")
    return 0


# ---------------------------------------------------------------- summary / engine

def cmd_summary(ctx: Ctx, args: argparse.Namespace) -> int:
    s = ctx.store.summary()
    sev = s["severity"]
    print(f"{_c('空境 · Kara', '1')} v{__version__}　库 {ctx.db}")
    print(f"  漏洞 {s['findings']} 条 / 命中 {s['hits']} 次　资产 {s['assets']}　已摄入文件 {s['files']}")
    print("  严重度　" + "　".join(f"{k} {sev.get(k, 0)}" for k in ("critical", "high", "medium", "low", "info")))
    if s.get("by_verify"):
        print("  复验　　" + "　".join(f"{r.get('verify')} {r.get('n')}" for r in s["by_verify"]))
    if s.get("by_status"):
        print("  状态　　" + "　".join(f"{r.get('status')} {r.get('n')}" for r in s["by_status"]))
    if s.get("top_assets"):
        print("  头号资产")
        for a in s["top_assets"][:6]:
            print(f"    {_cut(a.get('asset') or '-', 40):<42}{a.get('n')} 条")
    if s.get("last_scan"):
        print(f"  最近扫描 {s['last_scan']}")
    return 0


def cmd_engine(ctx: Ctx, args: argparse.Namespace) -> int:
    mgr = ctx.manager()
    meta = mgr.meta()
    eng = meta.get("engine") or {}
    print(f"引擎　{eng.get('path') or '(未找到)'}")
    print(f"  可用　{'是' if eng.get('ok') else '否'}　版本 {eng.get('version') or '-'}")
    if not eng.get("ok"):
        print(_c(eng.get("hint") or sc.ENGINE_HINT, "33"))
        return 2
    print(f"  库　　{ctx.db}")
    print(f"  收件箱 {', '.join(ctx.inboxes)}")
    for m, spec in sc.MODES.items():
        print(f"  · {m:<12}{spec['label']}  ({spec['flag']} <{spec['kind']}>)")
    return 0


# ---------------------------------------------------------------- 入口

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python3 -m vc.cli",
        description="空境 · Kara —— 终端模式（扫 / 入账 / 复验 / 导出，无 Web 界面）")
    ap.add_argument("--db", default="", help=f"SQLite 库路径（默认 {default_db_path()}）")
    ap.add_argument("--inbox", action="append", default=None, help="收件箱目录，可重复")
    ap.add_argument("--engine", default="", help="sweep 可执行文件路径（默认自动查找）")
    ap.add_argument("--timeout", type=int, default=900, help="单目标超时秒数（默认 900）")
    ap.add_argument("--parallel", type=int, default=2, help="并发目标数（上限 4，默认 2）")
    ap.add_argument("-v", "--version", action="version", version=f"kara {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="起一次扫描并在终端看进度")
    p.add_argument("-t", "--targets", nargs="+", required=True, help="目标（域名 / IP / URL）")
    p.add_argument("-m", "--mode", default="all", choices=list(sc.MODES), help="扫描模式")
    p.add_argument("--scheme", default="auto", choices=["auto", "http", "https", "raw"],
                   help="url 类模式的目标协议：auto=先握手判定（默认）/ raw=原样交给引擎（默认补 https）")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("ingest", help="把收件箱里的产物解析入库（增量；--force 全量重解析）")
    p.add_argument("--force", action="store_true", help="忽略内容指纹，已摄入的文件也重新解析")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("list", help="列命中")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--status", default="", help="待验证 / 已确认 / 误报 / 已修复 / 已忽略")
    p.add_argument("--q", default="", help="关键词")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("assets", help="列资产（主机/端口/指纹）")
    p.add_argument("--q", default="", help="关键词")
    p.add_argument("--limit", type=int, default=60)
    p.set_defaults(func=cmd_assets)

    p = sub.add_parser("show", help="看单条详情（含判据与复现命令）")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("export", help="导出 CSV / MD")
    p.add_argument("--format", dest="format", default="md", choices=["csv", "md"])
    p.add_argument("-o", "--out", default="", help="输出文件；不给就打到 stdout")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--status", default="")
    p.add_argument("--q", default="")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("verify", help="复验（同一模式同一入口重跑）")
    p.add_argument("--ids", default="", help="如 12,15,19；不给就按筛选批量")
    p.add_argument("--sev", default="", choices=["", "critical", "high", "medium", "low", "info"])
    p.add_argument("--status", default="")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("summary", help="库总览")
    p.set_defaults(func=cmd_summary)

    p = sub.add_parser("engine", help="引擎与模式自检")
    p.set_defaults(func=cmd_engine)
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

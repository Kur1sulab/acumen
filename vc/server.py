"""漏扫控制台 · 本地 Web 服务（stdlib 零依赖）

用法：
    python3 -m vc.server --inbox ~/pentest --inbox ~/pentest-inbox --port 7788 --open

设计：
  * 只绑 127.0.0.1（除非显式 --host），无鉴权，仅供本机单人使用。
  * 页面打开 → 前端立刻 POST /api/rescan（增量，mtime 门控）→ 再取 summary/列表。
  * 后台 watcher 每 5s 看收件箱有没有新文件；前端每 4s 轮询 summary，发现变化自动刷新。
  * 所有接口返回 JSON；导出走 text/csv 与 text/markdown 附件。
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import sys
import threading
import time
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

if __package__ in (None, ""):  # 允许 `python3 vc/server.py` 直接跑
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from vc.ingest import Ingestor
    from vc.store import Store, STATUS_CHOICES
else:
    from .ingest import Ingestor
    from .store import Store, STATUS_CHOICES

UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
DEFAULT_INBOXES = ["~/pentest-inbox", "~/pentest", "~/pentest-assets"]
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
        ".ico": "image/x-icon", ".json": "application/json; charset=utf-8"}


class State:
    store: Store
    ingestor: Ingestor
    watcher: Optional[threading.Thread] = None
    stop = threading.Event()


STATE = State()


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnConsole/1.0"
    protocol_version = "HTTP/1.1"

    # -------------------------------------------------------- 基础工具

    def log_message(self, fmt: str, *args: Any) -> None:  # 静音：只留自己的 log 表
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _err(self, code: int, msg: str) -> None:
        self._json({"ok": False, "error": msg}, code=code)

    def _body(self) -> Dict[str, Any]:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            obj = json.loads(raw.decode("utf-8"))
            return obj if isinstance(obj, dict) else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _query(self) -> Dict[str, str]:
        parsed = urllib.parse.urlsplit(self.path)
        return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    # -------------------------------------------------------- 路由

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        q = self._query()
        try:
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path == "/api/summary":
                return self._json(STATE.store.summary())
            if path == "/api/findings":
                return self._json(STATE.store.findings(
                    sev=q.get("sev", ""), asset=q.get("asset", ""), status=q.get("status", ""),
                    q=q.get("q", ""), limit=min(int(q.get("limit", 200) or 200), 1000),
                    offset=max(int(q.get("offset", 0) or 0), 0),
                ))
            if path == "/api/assets":
                return self._json(STATE.store.assets(
                    q=q.get("q", ""), limit=min(int(q.get("limit", 300) or 300), 1000),
                    offset=max(int(q.get("offset", 0) or 0), 0),
                ))
            if path == "/api/log":
                detail = (q.get("detail") or "") in ("1", "true")
                return self._json({"rows": STATE.store.tail_log(int(q.get("limit", 200) or 200), detail=detail),
                                   "detail": detail})
            if path == "/api/files":
                only = (q.get("only") or "") in ("1", "hits", "true")
                return self._json({"rows": STATE.store.file_stats(500, only_hits=only),
                                   "inboxes": STATE.ingestor.inboxes,
                                   "last_run": STATE.ingestor.last_run})
            if path == "/api/export":
                fmt = (q.get("fmt") or "csv").lower()
                stamp = time.strftime("%Y%m%d-%H%M%S")
                if fmt == "md":
                    body = STATE.store.export_md().encode("utf-8")
                    return self._send(200, body, "text/markdown; charset=utf-8",
                                      {"Content-Disposition": f'attachment; filename="vulns-{stamp}.md"'})
                body = STATE.store.export_csv().encode("utf-8-sig")
                return self._send(200, body, "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="vulns-{stamp}.csv"'})
            if path == "/api/health":
                return self._json({"ok": True, "ts": time.time()})
            if path.startswith("/ui/"):
                return self._static(path[len("/ui/"):])
        except ValueError as exc:
            return self._err(400, f"参数非法：{exc}")
        except Exception as exc:  # 兜底，免得前端拿到空响应
            STATE.store.log("error", f"GET {path} 失败：{type(exc).__name__}: {exc}")
            return self._err(500, f"{type(exc).__name__}: {exc}")
        return self._err(404, "not found")

    def do_HEAD(self) -> None:  # noqa: N802
        return self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        body = self._body()
        try:
            if path == "/api/rescan":
                force = bool(body.get("force"))
                stats = STATE.ingestor.scan(force=force)
                return self._json({"ok": True, "stats": stats, "summary": STATE.store.summary()})
            if path == "/api/status":
                ids = body.get("ids") or []
                if not isinstance(ids, list):
                    return self._err(400, "ids 必须是数组")
                ids = [int(x) for x in ids]
                n = STATE.store.set_status(ids, str(body.get("status") or ""))
                STATE.store.log("info", f"状态更新：{n} 条 → {body.get('status')}")
                return self._json({"ok": True, "updated": n})
        except ValueError as exc:
            return self._err(400, str(exc))
        except Exception as exc:
            STATE.store.log("error", f"POST {path} 失败：{type(exc).__name__}: {exc}")
            return self._err(500, f"{type(exc).__name__}: {exc}")
        return self._err(404, "not found")

    # -------------------------------------------------------- 静态资源

    def _static(self, rel: str) -> None:
        rel = posixpath.normpath(rel).lstrip("/")
        if rel.startswith("..") or os.path.isabs(rel):
            return self._err(403, "forbidden")
        full = os.path.join(UI_DIR, rel)
        if not os.path.isfile(full):
            return self._err(404, f"静态文件缺失：{rel}")
        ctype = MIME.get(os.path.splitext(full)[1].lower(), "application/octet-stream")
        with open(full, "rb") as fh:
            data = fh.read()
        return self._send(200, data, ctype)


def _watcher_loop(interval: float = 5.0) -> None:
    """后台轮询：收件箱有新文件就自动摄入（页面不用手动点）。"""
    while not STATE.stop.is_set():
        try:
            if STATE.ingestor and STATE.ingestor.dirty():
                STATE.ingestor.scan()
        except Exception as exc:
            STATE.store.log("error", f"watcher 异常：{type(exc).__name__}: {exc}")
        STATE.stop.wait(interval)


def build(inboxes: List[str], db_path: str, watch: bool = True) -> ThreadingHTTPServer:
    STATE.store = Store(db_path)
    STATE.ingestor = Ingestor(STATE.store, inboxes)
    for box in STATE.ingestor.inboxes:
        if not os.path.isdir(box):
            try:
                os.makedirs(box, exist_ok=True)
                STATE.store.log("info", f"已创建收件箱：{box}")
            except OSError as exc:
                STATE.store.log("warn", f"收件箱无法创建 {box}：{exc}")
    if watch:
        STATE.watcher = threading.Thread(target=_watcher_loop, daemon=True)
        STATE.watcher.start()
    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)  # 占位，真端口在 main 里定


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="漏扫控制台 · 本地 Web（零依赖）")
    ap.add_argument("--inbox", action="append", default=None,
                    help=f"收件箱目录，可重复；默认 {DEFAULT_INBOXES}")
    ap.add_argument("--port", type=int, default=7788)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--db", default=os.path.expanduser("~/.vuln-console/vuln.db"))
    ap.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    ap.add_argument("--no-watch", action="store_true", help="关闭后台自动摄入")
    ap.add_argument("--scan", action="store_true", help="只在命令行跑一次摄入然后退出")
    args = ap.parse_args(argv)

    inboxes = [os.path.expanduser(p) for p in (args.inbox or DEFAULT_INBOXES)]
    STATE.store = Store(args.db)
    STATE.ingestor = Ingestor(STATE.store, inboxes)

    if args.scan:
        for box in STATE.ingestor.inboxes:
            os.makedirs(box, exist_ok=True)
        stats = STATE.ingestor.scan(force=True)
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        print(json.dumps(STATE.store.summary(), ensure_ascii=False, indent=2))
        return 0

    for box in STATE.ingestor.inboxes:
        os.makedirs(box, exist_ok=True)
    if not args.no_watch:
        STATE.watcher = threading.Thread(target=_watcher_loop, daemon=True)
        STATE.watcher.start()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    STATE.store.log("info", f"服务启动：{url}　收件箱：{', '.join(STATE.ingestor.inboxes)}")
    print(f"[vuln-console] {url}")
    print(f"[vuln-console] 收件箱: {', '.join(STATE.ingestor.inboxes)}")
    print(f"[vuln-console] 数据库: {args.db}")
    if args.open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[vuln-console] 收工")
    finally:
        STATE.stop.set()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

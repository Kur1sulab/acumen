"""终端模式的单测：目标归一化补丁、显示宽度、协议判定、一次完整 scan 流程。

不联网：HTTP 判定用 stdlib 起一个回环 server 当靶子；扫描链路用 tests.test_scans
里那段假引擎（会写 nuclei 形状产物），验证「跑引擎 → 入账 → 报告」真的走通。
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import cli                     # noqa: E402
from vc.scans import normalize_targets  # noqa: E402
from vc.store import Store            # noqa: E402

from tests.test_scans import make_engine  # noqa: E402


class TestTargetPatch(unittest.TestCase):
    """浏览器复制的 URL 带尾斜杠 —— 以前直接被拒收，现在按合法目标处理。"""

    def test_trailing_slash_accepted(self):
        self.assertEqual(normalize_targets("fingerprint", ["http://a.com/x/"]), ["http://a.com/x"])
        self.assertEqual(normalize_targets("fingerprint", ["a.com/"]), ["https://a.com"])

    def test_bare_host_unchanged(self):
        self.assertEqual(normalize_targets("fingerprint", ["a.com"]), ["https://a.com"])

    def test_root_slash_kept_sane(self):
        self.assertEqual(normalize_targets("api", ["http://a.com/"]), ["http://a.com"])

    def test_still_rejects_dangerous(self):
        for bad in ["a.com; id", "http://a.com/../x", "-rf"]:
            with self.assertRaises(Exception):
                normalize_targets("fingerprint", [bad])


class TestDisplay(unittest.TestCase):
    def test_cjk_width(self):
        self.assertEqual(cli._w("中文"), 4)
        self.assertEqual(cli._w("ab"), 2)
        # 东亚宽字符按 2 列算，裁切后不得超过预算
        for budget in (3, 5, 7, 9):
            self.assertLessEqual(cli._w(cli._cut("敏感路径可访问：/.git/config", budget)), budget)
        self.assertTrue(cli._cut("abcdef", 4).endswith("…"))

    def test_pad(self):
        self.assertEqual(cli._w(cli._pad("中文", 10)), 10)
        self.assertEqual(cli._w(cli._pad("ab", 6)), 6)

    def test_ports_text(self):
        ports = [{"port": 80, "service": "http"}, {"port": 443, "service": ""}, 8080]
        self.assertEqual(cli._ports_text(ports), "80(http),443,8080")
        self.assertEqual(cli._ports_text([]), "-")
        many = [{"port": i} for i in range(1, 13)]
        self.assertTrue(cli._ports_text(many, cap=3).endswith("…+9"))


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self):                      # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):             # 静音
        pass


class TestProbeScheme(unittest.TestCase):
    def test_http_server_detected(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Ok)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            port = srv.server_address[1]
            self.assertEqual(cli.probe_scheme(f"127.0.0.1:{port}"), "http")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_dead_port_falls_back_to_https(self):
        # 没人监听的端口：两种握手都失败 → 交回引擎默认的 https
        self.assertEqual(cli.probe_scheme("127.0.0.1:9"), "https")


class TestScanEndToEnd(unittest.TestCase):
    """假引擎跑一次完整 scan：退出码 0，产物入账，库里有条目。"""

    def test_scan_ingests(self):
        with tempfile.TemporaryDirectory() as d:
            engine = make_engine(d)
            db = os.path.join(d, "v.db")
            inbox = os.path.join(d, "inbox")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli.main(["--db", db, "--inbox", inbox, "--engine", engine,
                                 "--timeout", "60", "scan", "-t", "example.com",
                                 "-m", "api", "--scheme", "https"])
            self.assertEqual(code, 0, buf.getvalue())
            store = Store(db)
            rows = store.findings(limit=50)["rows"]
            self.assertEqual(len(rows), 1, buf.getvalue())
            self.assertEqual(rows[0]["sev"], "high")
            self.assertIn("XSS", rows[0]["title"])
            self.assertTrue(rows[0]["repro"] is not None)

    def test_bad_target_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            engine = make_engine(d)
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(["--db", os.path.join(d, "v.db"),
                                 "--inbox", os.path.join(d, "inbox"), "--engine", engine,
                                 "scan", "-t", "a.com; id", "-m", "api"])
            self.assertEqual(code, 2)
            self.assertIn("不合法", err.getvalue())

    def test_export_writes_file(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "v.db")
            store = Store(db)
            store.add_findings([{
                "asset": "a.com", "title": "测试命中", "sev": "high", "endpoint": "http://a.com/x",
                "param": "q", "port": "", "ip": "", "cve": "", "evidence": "200 · 12B",
                "repro": "curl -i http://a.com/x", "sources": "sweep-paths",
            }], "t.json")
            out = os.path.join(d, "r.csv")
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(["--db", db, "export", "--format", "csv", "-o", out])
            self.assertEqual(code, 0)
            raw = open(out, "rb").read()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), "CSV 必须带 BOM，Excel 才不乱码")
            self.assertIn("测试命中", raw.decode("utf-8-sig"))


if __name__ == "__main__":
    unittest.main()

"""扫描路由的 HTTP 层测试：回环校验放行、无引擎 503、坏目标 400、任务不存在 404。

真起一个 ThreadingHTTPServer（绑随机端口）打真接口，不用 mock 请求对象。
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import server                      # noqa: E402
from vc.scans import ScanManager           # noqa: E402
from tests.test_scans import make_engine   # noqa: E402


def call(port: int, path: str, body=None):
    url = f"http://127.0.0.1:{port}{path}"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode() or "{}"
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}


class ScanRoutes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vc-routes-")
        self.inbox = os.path.join(self.tmp, "inbox")
        os.makedirs(self.inbox)
        self.db = os.path.join(self.tmp, "vuln.db")
        self.engine = make_engine(self.tmp)
        self.httpd = server.build([self.inbox], self.db, watch=False)
        self.port = self.httpd.server_address[1]
        self.mgr = ScanManager(self.db, self.inbox, engine=self.engine,
                               timeout=60, max_parallel=2)
        server.STATE.scans = self.mgr
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        server.STATE.scans = None
        self.httpd.shutdown()
        self.httpd.server_close()
        self.mgr.shutdown()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_meta(self):
        code, data = call(self.port, "/api/scan/meta")
        self.assertEqual(code, 200)
        self.assertTrue(data["engine"]["ok"])
        self.assertTrue(any(m["id"] == "all" for m in data["modes"]))

    def test_start_bad_target_is_400(self):
        code, data = call(self.port, "/api/scan/start",
                          {"mode": "portscan", "targets": ["a.com; id"]})
        self.assertEqual(code, 400)
        self.assertFalse(data["ok"])
        self.assertIn("目标", data["error"])

    def test_start_then_read_job(self):
        code, data = call(self.port, "/api/scan/start",
                          {"mode": "portscan", "targets": ["10.9.9.9"], "parallel": 1})
        self.assertEqual(code, 200)
        jid = data["job_id"]
        end = time.time() + 15
        job = None
        while time.time() < end:
            c2, job = call(self.port, f"/api/scan/job?id={jid}")
            self.assertEqual(c2, 200)
            if job["status"] in ("ok", "failed", "partial", "stopped"):
                break
            time.sleep(0.2)
        self.assertIn(job["status"], ("ok", "partial"))
        self.assertEqual(job["runs"][0]["target"], "10.9.9.9")
        self.assertTrue(job["log"]["lines"])

    def test_unknown_job_is_404(self):
        code, data = call(self.port, "/api/scan/job?id=999999")
        self.assertEqual(code, 404)
        self.assertFalse(data["ok"])
        self.assertIn("不存在", data["error"])

    def test_jobs_list(self):
        code, data = call(self.port, "/api/scan/jobs?limit=5")
        self.assertEqual(code, 200)
        self.assertIn("rows", data)
        self.assertIn("active", data)

    def test_disabled_returns_503(self):
        server.STATE.scans = None
        code, data = call(self.port, "/api/scan/meta")
        self.assertEqual(code, 503)
        self.assertFalse(data["ok"])
        self.assertIn("未启用", data["error"])


if __name__ == "__main__":
    unittest.main()

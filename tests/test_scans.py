"""扫描控制的单测：目标校验、引擎发现、任务生命周期、停止、结果回流。

不联网：用一段假引擎（sh 脚本）走完整链路——提交任务 → 解析 --progress-file 进度
→ 写产物到 out/<target>/ → 摄入器入账 → 界面读到的 findings 涨上去。
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc.ingest import Ingestor            # noqa: E402
from vc.scans import (MODES, ScanError, ScanManager, find_engine,  # noqa: E402
                      normalize_targets, safe_name)
from vc.store import Store                # noqa: E402

FAKE_ENGINE = r"""#!/bin/sh
# 假 sweep：解析 --progress-file，按模块发事件，写一条 nuclei 形状的产物。
# 无参数时只报版本（真引擎的 meta() 探测会这么调，别在这里落文件）。
if [ $# -eq 0 ]; then echo "sweep — fake engine for tests (0.0.1)"; exit 0; fi
PROG=""; TARGET=""; prev=""
for a in "$@"; do
  if [ "$prev" = "--progress-file" ]; then PROG="$a"; fi
  if [ "$prev" = "-t" ] || [ "$prev" = "-u" ] || [ "$prev" = "-d" ]; then TARGET="$a"; fi
  prev="$a"
done
ev() { printf '{"ts": 1.5, "event": "%s", "module": "%s", "detail": "%s"}\n' "$1" "$2" "$3" >> "$PROG"; }
SLOW="${VC_FAKE_SLOW:-}"
case "$SLOW" in 1) SLOW=1;; *) SLOW="";; esac
ev pipeline_start pipeline "$TARGET"
for step in reverse fingerprint api; do
  ev start "$step" ""
  if [ -n "$SLOW" ]; then sleep 30; fi
  ev done "$step" ""
done
mkdir -p "out/$TARGET"
printf '{"template-id":"fake-xss","info":{"name":"测试反射型XSS","severity":"high"},"host":"http://%s","matched-at":"http://%s/x?q=1"}\n' \
  "$TARGET" "$TARGET" > "out/$TARGET/nuclei.jsonl"
ev pipeline_end pipeline done
exit 0
"""


def make_engine(dirpath: str) -> str:
    p = os.path.join(dirpath, "sweep")
    with open(p, "w", encoding="utf-8") as f:
        f.write(FAKE_ENGINE)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    return p


def wait_for(fn, timeout: float = 10.0, step: float = 0.1):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return fn()


class TestTargets(unittest.TestCase):
    def test_normalize_dedupe(self):
        got = normalize_targets("portscan", ["10.0.0.1", "10.0.0.1 ", "a.example.com"])
        self.assertEqual(got, ["10.0.0.1", "a.example.com"])

    def test_newline_input(self):
        got = normalize_targets("all", "a.com\nb.com\n\nc.com")
        self.assertEqual(got, ["a.com", "b.com", "c.com"])

    def test_url_kind_prefixes_scheme(self):
        self.assertEqual(normalize_targets("fingerprint", ["a.com"]), ["https://a.com"])
        self.assertEqual(normalize_targets("fingerprint", ["http://a.com/x"]), ["http://a.com/x"])

    def test_domain_kind_rejects_port_and_scheme(self):
        with self.assertRaises(ScanError):
            normalize_targets("subdomain", ["a.com:8080"])
        with self.assertRaises(ScanError):
            normalize_targets("subdomain", ["https://a.com"])

    def test_reject_injection_shapes(self):
        for bad in ["a.com; id", "a.com && id", "$(id).com", "a.com`id`", "a.com'x",
                    "a.com\"x", "a.com|x", "a.com\nb.com", "a.com b.com", "-rf"]:
            with self.assertRaises(ScanError, msg=bad):
                normalize_targets("portscan", [bad])

    def test_reject_traversal_and_empty(self):
        with self.assertRaises(ScanError):
            normalize_targets("portscan", ["../../etc/passwd"])
        with self.assertRaises(ScanError):
            normalize_targets("portscan", [])
        with self.assertRaises(ScanError):
            normalize_targets("portscan", ["   "])

    def test_unknown_mode(self):
        with self.assertRaises(ScanError):
            normalize_targets("bogus", ["a.com"])

    def test_safe_name(self):
        self.assertEqual(safe_name("https://a.com/x?y=1"), "https_www_a.com_x_y_1".replace("www_", ""))
        self.assertTrue(safe_name("a.com:8080").startswith("a.com_8080"))


class TestEngineDiscovery(unittest.TestCase):
    def test_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            p = make_engine(d)
            self.assertEqual(find_engine(p), os.path.abspath(p))

    def test_missing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(find_engine(os.path.join(d, "nope")), "")

    def test_bundled_engine_wins_over_path(self):
        """绿色版自带的引擎必须优先于机器上那个同名二进制。

        回归背景：v1.1.0 的绿色版根本没打包引擎，扫描页在 Windows 上
        永远是「没找到扫描引擎」；补包之后又出现另一个坑——机器上恰好装过
        旧版 sweep 时会被先挑中，界面新引擎旧，跑出来的模块跟界面对不上。
        """
        import vc.scans as sc

        with tempfile.TemporaryDirectory() as d:
            eng_dir = os.path.join(d, "engine")
            os.makedirs(eng_dir)
            eng = make_engine(eng_dir)          # <root>/engine/sweep
            other = make_engine(d)              # 干扰项：<root>/sweep

            env = {k: v for k, v in os.environ.items() if k != "VC_RECON_BIN"}
            with mock.patch.object(sc, "PKG_ROOT", d), \
                    mock.patch.object(sc, "_EXE", ""), \
                    mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch("shutil.which", return_value=other):
                self.assertEqual(sc.find_engine(""), eng)


class ScanCase(unittest.TestCase):
    """起一个真 Store + Ingestor + ScanManager，用假引擎跑真任务。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vc-scan-")
        self.inbox = os.path.join(self.tmp, "inbox")
        os.makedirs(self.inbox)
        self.db = os.path.join(self.tmp, "vuln.db")
        self.engine = make_engine(self.tmp)
        self.store = Store(self.db)
        self.ingestor = Ingestor(self.store, [self.inbox])
        self.mgr = ScanManager(self.db, self.inbox, engine=self.engine,
                               timeout=60, max_parallel=2,
                               ingest_cb=self.ingestor.scan)

    def tearDown(self):
        self.mgr.shutdown()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _finish(self, job_id, timeout=15):
        def done():
            j = self.mgr.job(job_id)
            return j if j and j["status"] in ("ok", "failed", "partial", "stopped") else None
        return wait_for(done, timeout)

    def test_meta(self):
        m = self.mgr.meta()
        self.assertTrue(m["engine"]["ok"])
        self.assertEqual(m["engine"]["path"], self.engine)
        self.assertEqual(len(m["modes"]), len(MODES))
        self.assertIn("all", [x["id"] for x in m["modes"]])

    def test_start_without_engine(self):
        mgr = ScanManager(self.db, self.inbox, engine="/nonexistent/sweep")
        with self.assertRaises(ScanError):
            mgr.start("all", ["a.com"])

    def test_bad_target_rejected(self):
        with self.assertRaises(ScanError):
            self.mgr.start("portscan", ["a.com; rm -rf /"])

    def test_job_lifecycle(self):
        res = self.mgr.start("all", ["example.com"], parallel=1)
        self.assertTrue(res["ok"])
        job = self._finish(res["job_id"])
        self.assertIsNotNone(job, "任务没在超时内结束")
        self.assertEqual(job["status"], "ok")
        run = job["runs"][0]
        self.assertEqual(run["status"], "ok")
        self.assertEqual(run["exit_code"], 0)
        self.assertEqual([s["name"] for s in run["steps"]], ["reverse", "fingerprint", "api"])
        self.assertTrue(all(s["status"] == "done" for s in run["steps"]))
        self.assertEqual(run["expect"], 7)          # 首步 reverse → IP 分支
        self.assertEqual(run["pct"], 100)
        self.assertTrue(job["log"]["lines"], "日志是空的")
        self.assertTrue(any("pipeline_start" not in ln for ln in job["log"]["lines"]))
        # 产物落在收件箱里的任务目录，摄入器能把命中数回来
        self.assertIn(self.inbox, job["dir"])
        self.assertTrue(os.path.isdir(os.path.join(job["dir"], "out", "example.com")))

        def got_findings():
            j = self.mgr.job(res["job_id"])
            return j["runs"][0]["findings"] >= 1 and j
        job2 = wait_for(got_findings, 6)
        self.assertGreaterEqual(job2["runs"][0]["findings"], 1, "产物没被摄入")
        self.assertGreaterEqual(job2["findings"], 1)

    def test_incremental_log(self):
        res = self.mgr.start("portscan", ["10.1.1.1"])
        self._finish(res["job_id"])
        full = self.mgr.job(res["job_id"])
        nxt = full["log"]["next"]
        self.assertGreater(nxt, 0)
        tail = self.mgr.job(res["job_id"], log_from=nxt)
        self.assertEqual(tail["log"]["lines"], [])   # 从末尾读 → 没有新行

    def test_stop(self):
        os.environ["VC_FAKE_SLOW"] = "1"
        try:
            res = self.mgr.start("portscan", ["10.2.2.2"])
            # 等它真的跑起来
            wait_for(lambda: [r for r in self.mgr.job(res["job_id"])["runs"]
                              if r["status"] == "running"], 6)
            self.mgr.stop(res["job_id"])
            job = self._finish(res["job_id"], timeout=15)
            self.assertIsNotNone(job)
            self.assertIn(job["status"], ("stopped", "partial", "failed"))
            self.assertIn(job["runs"][0]["status"], ("stopped", "failed"))
        finally:
            os.environ.pop("VC_FAKE_SLOW", None)

    def test_expect_by_branch(self):
        self.assertEqual(ScanManager._expect("all", []), 10)
        self.assertEqual(ScanManager._expect("all", [{"name": "subdomain"}]), 10)
        self.assertEqual(ScanManager._expect("all", [{"name": "reverse"}]), 7)
        self.assertEqual(ScanManager._expect("portscan", []), 1)

    def test_jobs_list(self):
        res = self.mgr.start("portscan", ["10.3.3.3"])
        self._finish(res["job_id"])
        rows = self.mgr.jobs(5)
        self.assertTrue(rows and rows[0]["id"] == res["job_id"])
        self.assertEqual(rows[0]["mode_label"], "端口扫描")
        self.assertEqual(rows[0]["counts"]["total"], 1)

    def test_orphan_marked_interrupted(self):
        with self.mgr._lock:
            cur = self.mgr._conn.execute(
                "INSERT INTO scan_jobs(mode,targets,status,parallel,timeout,created) "
                "VALUES('all','[\"x\"]','running',1,60,?)", (time.time(),))
            self.mgr._conn.commit()
            jid = cur.lastrowid
        mgr2 = ScanManager(self.db, self.inbox, engine=self.engine)
        rows = mgr2._rows("SELECT status FROM scan_jobs WHERE id=?", (jid,))
        self.assertEqual(rows[0]["status"], "interrupted")


if __name__ == "__main__":
    unittest.main()

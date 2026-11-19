"""回归：scan 的 --timeout 不许依赖引擎吐输出。

修复前 vc/scans.py 的 _run_target 把 deadline 检查挂在 `for line in proc.stdout`
循环体里：引擎卡死时往往一行日志都不吐（内网黑洞主机上 TCP connect / DNS 挂起
是常态），读循环永远等不到下一行，超时永不触发，任务无限挂起——
`kara scan --timeout 60` 的承诺形同虚设，只能 Ctrl+C。

这里用「静默假引擎」复现该形状：sleep 远超 tmo、不写任何 stdout。
修复前：睡满全程、状态 ok（超时被无视）；修复后：~tmo 被杀、状态 timeout。
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc.scans import ScanManager  # noqa: E402


def make_engine(dirpath: str, body: str) -> str:
    p = os.path.join(dirpath, "sweep")
    with open(p, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    return p


class TimeoutCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kara-tmo-")
        self.inbox = os.path.join(self.tmp, "inbox")
        os.makedirs(self.inbox)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mgr(self, body: str) -> ScanManager:
        eng = make_engine(self.tmp, body)
        return ScanManager(os.path.join(self.tmp, "v.db"), self.inbox, engine=eng)

    def _mk_job(self, mgr: ScanManager, target: str = "10.255.255.1") -> int:
        """照 start() 的形状落任务行，但不进工作线程——直接同步调 _run_target。"""
        with mgr._lock:
            cur = mgr._conn.execute(
                "INSERT INTO scan_jobs(mode,targets,status,parallel,timeout,created) "
                "VALUES('portscan',?,'running',1,60,?)", (json.dumps([target]), time.time()))
            mgr._conn.commit()
            jid = cur.lastrowid
            assert jid is not None
            job_dir = os.path.join(mgr.inbox_root, f"scan-tmo-{jid}")
            for sub in ("out", "progress", "logs"):
                os.makedirs(os.path.join(job_dir, sub), exist_ok=True)
            mgr._conn.execute("UPDATE scan_jobs SET dir=? WHERE id=?", (job_dir, jid))
            mgr._conn.execute("INSERT INTO scan_runs(job_id,target,status,steps) "
                              "VALUES(?,?,'queued','[]')", (jid, target))
            mgr._conn.commit()
        return jid

    def _run_status(self, mgr: ScanManager, jid: int):
        return mgr._rows("SELECT status, error FROM scan_runs WHERE job_id=?", (jid,))[0]

    def test_silent_engine_is_killed_at_deadline(self):
        """完全静默的引擎：到点必须被杀，而不是等它自己睡醒。"""
        mgr = self._mgr("sleep 6\nexit 0")
        try:
            jid = self._mk_job(mgr)
            t0 = time.time()
            mgr._run_target(jid, "portscan", "10.255.255.1", 2)
            elapsed = time.time() - t0
            row = self._run_status(mgr, jid)
            self.assertEqual(row["status"], "timeout",
                             f"静默引擎没被超时终止（修复前形状：{row}）")
            self.assertIn("超时", row["error"])
            self.assertLess(elapsed, 5.0, f"超时 2s 却跑了 {elapsed:.1f}s")
        finally:
            mgr.shutdown()

    def test_one_line_then_silent_still_times_out(self):
        """吐一行后卡死：读循环同样等不到下一行，超时必须照样触发。"""
        mgr = self._mgr("echo 'portscan start'\nsleep 6\nexit 0")
        try:
            jid = self._mk_job(mgr)
            t0 = time.time()
            mgr._run_target(jid, "portscan", "10.255.255.1", 2)
            elapsed = time.time() - t0
            row = self._run_status(mgr, jid)
            self.assertEqual(row["status"], "timeout")
            self.assertLess(elapsed, 5.0, f"超时 2s 却跑了 {elapsed:.1f}s")
        finally:
            mgr.shutdown()

    def test_silent_engine_finishing_in_time_stays_ok(self):
        """没超时的静默引擎不许被误杀、不许被误标 timeout。"""
        mgr = self._mgr("sleep 0.3\nexit 0")
        try:
            jid = self._mk_job(mgr)
            mgr._run_target(jid, "portscan", "10.255.255.1", 5)
            row = self._run_status(mgr, jid)
            self.assertEqual(row["status"], "ok", f"正常跑完被误判：{row}")
            self.assertEqual(row["error"], "")
        finally:
            mgr.shutdown()

    def test_stop_before_deadline_is_stopped_not_timeout(self):
        """看门狗不许抢 stop 的活：deadline 前手动停止 → stopped。"""
        mgr = self._mgr("sleep 6\nexit 0")
        try:
            jid = self._mk_job(mgr)
            t = threading.Thread(target=mgr._run_target,
                                 args=(jid, "portscan", "10.255.255.1", 30), daemon=True)
            t.start()
            end = time.time() + 6
            while time.time() < end:
                if self._run_status(mgr, jid)["status"] == "running":
                    break
                time.sleep(0.05)
            self.assertEqual(self._run_status(mgr, jid)["status"], "running")
            mgr.stop(jid)
            t.join(timeout=10)
            self.assertFalse(t.is_alive(), "stop 之后执行线程没退出")
            row = self._run_status(mgr, jid)
            self.assertEqual(row["status"], "stopped", f"手动停止被误标：{row}")
        finally:
            mgr.shutdown()


if __name__ == "__main__":
    unittest.main()

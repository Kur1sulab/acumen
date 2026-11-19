"""brute 模式的透传参数必须真的到引擎手里（回归测试）。

背景：`vc/scans.py` 的 `_run_target` 曾经只在 `spec["sub"] == "strike"` 时追加
`mode_args`，于是 `kara scan -m brute -p 6379 --service redis` 的 `-p/--service`
被静默丢掉——命令照跑、日志照打，实际却在按默认端口表自动识别服务。
这种「参数丢了但不报错」的坑最贵：跑完没命中，人会当成「目标没问题」。

不联网、不真握手：假引擎只把 argv 落盘然后退出 0。
"""

import os
import stat
import sys
import tempfile
import time
import unittest
from argparse import Namespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc.cli import _mode_args                       # noqa: E402
from vc.scans import MODES, ScanManager             # noqa: E402

FAKE_BRUTE = """#!/bin/sh
if [ $# -eq 0 ]; then echo "sweep v0.0.1 · kara-engine (fake)"; exit 0; fi
echo "$@" > args.txt
exit 0
"""


def make_engine(d):
    p = os.path.join(d, "sweep")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(FAKE_BRUTE)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    return p


def wait(fn, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.05)
    return fn()


class TestBruteArgs(unittest.TestCase):
    def test_cli_builds_brute_flags(self):
        """_mode_args 在 brute 下给的是 -p/--service（不是 strike 的 --ports）。"""
        ns = Namespace(ports="6379", service="redis", intensity="", allow_public=False)
        self.assertEqual(_mode_args(ns, "brute"), ["-p", "6379", "--service", "redis"])
        # strike 用长参数，别串味
        self.assertEqual(_mode_args(ns, "strike"), ["--ports", "6379"])

    def test_mode_args_reach_engine(self):
        with tempfile.TemporaryDirectory() as d:
            engine = make_engine(d)
            db = os.path.join(d, "v.db")
            mgr = ScanManager(db_path=db, inbox_root=os.path.join(d, "inbox"),
                              engine=engine,
                              mode_args=["-p", "6379", "--service", "redis"],
                              timeout=60, max_parallel=1)
            self.assertTrue(mgr.engine, "假引擎没被认出来")
            res = mgr.start("brute", ["10.0.0.5"], parallel=1, timeout=60)
            job_id = res["job_id"]
            st = wait(lambda: (mgr.job(job_id) or {}).get("status")
                      if (mgr.job(job_id) or {}).get("status") in
                      ("ok", "partial", "failed", "stopped", "timeout") else None)
            self.assertEqual(st, "ok")

            argv = open(os.path.join(mgr._job_dir(job_id), "args.txt"),
                        encoding="utf-8").read()
            self.assertIn("brute", argv)
            self.assertIn("-p 6379", argv)
            self.assertIn("--service redis", argv)
            # 目标仍在 -t 后面，参数没把目标挤掉
            self.assertIn("-t 10.0.0.5", argv)
            mgr.shutdown()

    def test_modes_other_than_brute_untouched(self):
        """paths 这类模式不该收到任何 mode_args（空列表不追加）。"""
        self.assertEqual(MODES["paths"]["sub"], "paths")
        with tempfile.TemporaryDirectory() as d:
            engine = make_engine(d)
            mgr = ScanManager(db_path=os.path.join(d, "v.db"),
                              inbox_root=os.path.join(d, "inbox"), engine=engine,
                              mode_args=[], timeout=60, max_parallel=1)
            res = mgr.start("paths", ["https://a.com"], parallel=1, timeout=60)
            job_id = res["job_id"]
            wait(lambda: (mgr.job(job_id) or {}).get("status")
                 if (mgr.job(job_id) or {}).get("status") in
                 ("ok", "partial", "failed", "stopped", "timeout") else None)
            argv = open(os.path.join(mgr._job_dir(job_id), "args.txt"),
                        encoding="utf-8").read()
            # 全局参数在前，业务参数从子命令名开始；paths 不该带任何 mode_args
            self.assertEqual(argv.split()[-3:], ["paths", "-u", "https://a.com"])
            mgr.shutdown()


if __name__ == "__main__":
    unittest.main()

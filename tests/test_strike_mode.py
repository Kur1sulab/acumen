"""深度验证（内建 litmus 内核）作为第 9 模式的单测。

不联网、不真跑内核：假引擎把 argv 落盘并造一份 litmus 形状的 findings.json，
验证「模式注册 → mode_args 透传 → 产物解析 → 入账」四段真的接上了。
"""

import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import parsers_sweep            # noqa: E402
from vc.scans import MODES, ScanManager, normalize_targets  # noqa: E402
from vc.store import Store             # noqa: E402
from vc.ingest import Ingestor         # noqa: E402

# 假引擎：记录 argv → 发进度事件 → 造 litmus 形状产物
FAKE_STRIKE = r"""#!/bin/sh
if [ $# -eq 0 ]; then echo "sweep v0.0.1 · kara-engine (fake)"; exit 0; fi
echo "$@" > args.txt
PROG=""; TARGET=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--progress-file" ]; then PROG="$a"; fi
  if [ "$prev" = "-t" ]; then TARGET="$a"; fi
  prev="$a"
done
printf '{"ts":1.0,"event":"start","module":"strike","detail":"%s"}\n' "$TARGET" >> "$PROG"
mkdir -p "out/$TARGET/strike"
cat > "out/$TARGET/strike/findings.json" <<EOF
{"run_id":"fake-1","opts":{},"elapsed":0.2,
 "findings":[{"id":"LS-001","check":"env-leak","name":".env 配置文件可下载",
   "severity":"critical","target":"http://$TARGET/.env","host":"$TARGET","port":18099,
   "scheme":"http","level":"L2","confidence":"confirmed",
   "evidence":"HTTP 200 · DB_PASSWORD=****","repro":"curl -i http://$TARGET/.env"}],
 "coverage":[{"item":"authprobe","state":"ok","reason":""},
             {"item":"smb","state":"skip","reason":"非 Windows 目标"}]}
EOF
printf '{"ts":1.2,"event":"done","module":"strike","detail":"1 条命中"}\n' >> "$PROG"
exit 0
"""


def make_engine(d: str) -> str:
    p = os.path.join(d, "sweep")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(FAKE_STRIKE)
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    return p


def wait(fn, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.05)
    return fn()


LITMUS_PAYLOAD = {
    "run_id": "r1",
    "findings": [{
        "id": "LS-003", "check": "backup-leak", "name": "备份文件可下载 /www.zip",
        "severity": "critical", "target": "http://127.0.0.1:18099/www.zip",
        "host": "127.0.0.1", "port": 18099, "scheme": "http",
        "level": "L2", "confidence": "confirmed",
        "evidence": "HTTP 200 · 32B", "repro": "curl -i http://127.0.0.1:18099/www.zip",
    }],
    "coverage": [{"item": "authprobe", "state": "skip", "reason": "无凭据"}],
}


class TestParser(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(parsers_sweep.detect(LITMUS_PAYLOAD), "sweep_strike")

    def test_parse(self):
        res = parsers_sweep.parse(json.dumps(LITMUS_PAYLOAD), "out/http_127.0.0.1_18099/strike/findings.json")
        self.assertIsNotNone(res)
        self.assertEqual(res.fmt, "sweep_strike")
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertEqual(f["sev"], "critical")
        self.assertIn("备份文件可下载", f["title"])
        self.assertIn("[L2/confirmed]", f["evidence"])
        self.assertIn("curl", f["repro"])
        self.assertTrue(f["source"].startswith("sweep-strike"))
        self.assertEqual(f["asset"], "127.0.0.1")
        self.assertIn("1 项跳过", res.note)

    def test_empty_findings_still_parsed(self):
        """0 命中也要认得：不然「测了但没漏洞」会变成「没测」。"""
        res = parsers_sweep.parse(json.dumps({"findings": [], "coverage": [{"item": "x", "state": "ok"}]}))
        self.assertIsNotNone(res)
        self.assertEqual(res.findings, [])


class TestMode(unittest.TestCase):
    def test_registered(self):
        self.assertIn("strike", MODES)
        self.assertEqual(MODES["strike"]["sub"], "strike")
        self.assertEqual(MODES["strike"]["flag"], "-t")

    def test_target_normalized(self):
        self.assertEqual(normalize_targets("strike", ["http://a.com:8080/x/"]), ["http://a.com:8080/x"])


class TestEndToEnd(unittest.TestCase):
    def test_mode_args_and_ingest(self):
        """--ports 这类参数必须原样透传给引擎，产物由解析器入账。"""
        with tempfile.TemporaryDirectory() as d:
            engine = make_engine(d)
            db = os.path.join(d, "v.db")
            inbox = os.path.join(d, "inbox")
            store = Store(db)
            mgr = ScanManager(db_path=db, inbox_root=inbox, engine=engine,
                              mode_args=["--ports", "18099", "--intensity", "high"],
                              timeout=60, max_parallel=1)
            self.assertTrue(mgr.engine, "假引擎没被认出来")
            res = mgr.start("strike", ["127.0.0.1:18099"], parallel=1, timeout=60)
            job_id = res["job_id"]
            st = wait(lambda: (mgr.job(job_id) or {}).get("status") if (mgr.job(job_id) or {}).get("status") in
                              ("ok", "partial", "failed", "stopped", "timeout") else None, timeout=15)
            self.assertEqual(st, "ok")

            argv = open(os.path.join(mgr._job_dir(job_id), "args.txt"), encoding="utf-8").read()
            self.assertIn("--ports 18099", argv)
            self.assertIn("--intensity high", argv)
            self.assertIn("strike", argv)

            Ingestor(store, [inbox]).scan()
            rows = store.findings(limit=10)["rows"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["sev"], "critical")
            self.assertIn("L2", rows[0]["evidence"])
            mgr.shutdown()


if __name__ == "__main__":
    unittest.main()

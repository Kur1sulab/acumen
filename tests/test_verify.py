"""复验的单测：入口还原、可达性判读、三态 + 不可复验。

不联网：用一段假引擎（sh 脚本）写产物——可控地造出「命中还在」「命中没了」
「目标根本没连上」三种产物，验证结论不会被伪造出来。最后那种是重点：
http 目标被当成 https 重跑时引擎空手而归，绝不能报「已消失」。
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

from vc import verify as vfy           # noqa: E402
from vc.store import Store            # noqa: E402

# 假引擎：按 FAKE_SCENARIO 决定写出哪种产物。
#   alive  目标连上了，/.env 还在        → 命中的条目应当「仍存在」
#   gone   目标连上了，但 /.env 没了     → 命中的条目应当「已消失」
#   dead   目标连不上（baseline=unknown）→ 一律「无法判定」，不许说已消失
FAKE_ENGINE = r"""#!/bin/sh
SC="${FAKE_SCENARIO:-alive}"
OUT=""
for a in "$@"; do OUT="$a"; done
HOST=$(echo "$*" | sed -n 's/.*-u \(http[s]*:\/\/[^ ]*\).*/\1/p' | sed 's#.*//##')
DIR="out/$(echo "$HOST" | sed 's/[:.]/_/g')"
mkdir -p "$DIR"
case "$SC" in
  alive)
    cat > "$DIR/paths.json" <<EOF
{"base":"http://$HOST","baseline":{"kind":"normal","status":404,"digest":"aa","size":12,"samples":2},
 "alive":[{"path":"/.env","status":200,"size":63,"ctype":"text/plain","final_url":"http://$HOST/.env","verified":true}]}
EOF
    ;;
  gone)
    cat > "$DIR/paths.json" <<EOF
{"base":"http://$HOST","baseline":{"kind":"normal","status":404,"digest":"aa","size":12,"samples":2},
 "alive":[]}
EOF
    ;;
  dead)
    cat > "$DIR/paths.json" <<EOF
{"base":"https://$HOST","baseline":{"kind":"unknown","samples":0},"alive":[]}
EOF
    ;;
esac
exit 0
"""


def make_engine(root: str) -> str:
    p = os.path.join(root, "sweep")
    with open(p, "w") as fh:
        fh.write(FAKE_ENGINE)
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return p


def row(**kw):
    base = {"id": 1, "sources": "sweep-paths", "asset": "127.0.0.1", "port": 8080,
            "endpoint": "/.env", "title": "敏感路径可访问：/.env", "base": ""}
    base.update(kw)
    return base


class TestBaseUrl(unittest.TestCase):
    def test_prefers_saved_base(self):
        # 引擎记下的 base 说什么就是什么：扫描时是 http，重跑也必须是 http
        self.assertEqual(vfy.base_url(row(base="http://127.0.0.1:18080")), "http://127.0.0.1:18080")
        self.assertEqual(vfy.base_url(row(base="https://a.example:8443/x")), "https://a.example:8443")

    def test_endpoint_scheme_when_no_base(self):
        self.assertEqual(vfy.base_url(row(endpoint="https://b.example/a/b")), "https://b.example")

    def test_guess_does_not_default_to_https(self):
        # 没有 base 也没有带 scheme 的端点时才猜：443 猜 https，其余猜 http
        self.assertEqual(vfy.base_url(row(port=8443)), "http://127.0.0.1:8443")
        self.assertEqual(vfy.base_url(row(port=443, asset="c.example")), "https://c.example")

    def test_empty_when_nothing_to_go_on(self):
        self.assertEqual(vfy.base_url({"title": "x"}), "")


class TestPlan(unittest.TestCase):
    def test_engine_sources_are_verifiable(self):
        for src in ("sweep-paths", "sweep-api", "sweep-evidence", "sweep-jsintel"):
            self.assertIsNotNone(vfy.plan_of(row(sources=src)), src)

    def test_baseline_passes_check_name(self):
        p = vfy.plan_of(row(sources="sweep-secheaders"))
        assert p is not None
        self.assertEqual(p["mode"], "baseline")
        self.assertEqual(p["check"], "secheaders")
        self.assertIn("--checks", p["argv"])

    def test_foreign_sources_are_not_verifiable(self):
        for src in ("nuclei", "nessus", "audit-md", ""):
            self.assertIsNone(vfy.plan_of(row(sources=src)), src)

    def test_enrich_marks_fields(self):
        rows = [row(), row(sources="nuclei", title="离线条目")]
        vfy.enrich(rows)
        self.assertTrue(rows[0]["verifiable"])
        self.assertIn("curl", rows[0]["repro"])
        self.assertFalse(rows[1]["verifiable"])
        self.assertTrue(rows[1]["verify_hint"])


class TestReach(unittest.TestCase):
    def test_baseline_unknown_means_unreachable(self):
        self.assertFalse(vfy._reach({"baseline": {"kind": "unknown", "samples": 0}}))
        self.assertTrue(vfy._reach({"baseline": {"kind": "normal", "status": 404}}))

    def test_all_entries_failed_means_unreachable(self):
        dead = {"all": [{"status": None, "error": "connection refused"},
                        {"status": None, "error": "connection refused"}]}
        live = {"all": [{"status": None, "error": "x"}, {"status": 200, "hit": True}]}
        self.assertFalse(vfy._reach(dead))
        self.assertTrue(vfy._reach(live))

    def test_jsintel_page_status(self):
        self.assertTrue(vfy._reach({"page_status": 200, "error": ""}))
        self.assertFalse(vfy._reach({"page_status": 0, "error": "dial tcp: refused"}))

    def test_no_opinion(self):
        self.assertIsNone(vfy._reach({"alive": []}))


class TestVerifyRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vc-vfy-")
        self.engine = make_engine(self.tmp)
        self.db = os.path.join(self.tmp, "t.db")
        self.store = Store(self.db)
        self.store.add_findings([{
            "title": "敏感路径可访问：/.env", "sev": "high", "asset": "127.0.0.1",
            "port": 8080, "endpoint": "/.env", "source": "sweep-paths", "evidence": "HTTP 200",
            "base": "http://127.0.0.1:8080",
        }, {
            "title": "离线报告条目", "sev": "medium", "source": "nuclei", "evidence": "摘自 md",
        }], "t.json")
        self.rows = self.store.findings(limit=50)["rows"]
        self.ids = [int(r["id"]) for r in self.rows]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, scenario: str, ids=None):
        os.environ["FAKE_SCENARIO"] = scenario
        try:
            v = vfy.Verifier(self.store, engine=self.engine, timeout=60)
            r = v.start(ids if ids is not None else self.ids)
            self.assertTrue(r["ok"], r)
            for _ in range(600):
                if not v.status()["running"]:
                    break
                time.sleep(0.05)
            return v.status(), {r["id"]: r for r in self.store.findings(limit=50)["rows"]}
        finally:
            os.environ.pop("FAKE_SCENARIO", None)

    def test_alive_says_still(self):
        st, rows = self._run("alive")
        self.assertEqual(st["summary"].get("仍存在"), 1)
        self.assertEqual(st["summary"].get("不可复验"), 1)
        hit = [r for r in rows.values() if r["sources"] == "sweep-paths"][0]
        self.assertEqual(hit["verify_state"], "仍存在")
        self.assertEqual(hit["verify_times"], 1)
        self.assertTrue(hit["verify_note"])

    def test_gone_says_gone(self):
        st, rows = self._run("gone")
        self.assertEqual(st["summary"].get("已消失"), 1)
        hit = [r for r in rows.values() if r["sources"] == "sweep-paths"][0]
        self.assertEqual(hit["verify_state"], "已消失")

    def test_unreachable_target_is_never_gone(self):
        # 这条是复验的底线：引擎连不上目标 ≠ 漏洞修好了
        st, rows = self._run("dead")
        self.assertEqual(st["summary"].get("已消失"), 0)
        self.assertEqual(st["summary"].get("无法判定"), 1)
        hit = [r for r in rows.values() if r["sources"] == "sweep-paths"][0]
        self.assertEqual(hit["verify_state"], "无法判定")

    def test_foreign_source_marks_na(self):
        st, rows = self._run("alive", ids=[i for i in self.ids
                                          if "离线" in str([r for r in self.rows if r["id"] == i][0]["title"])])
        self.assertEqual(st["summary"].get("不可复验"), 1)

    def test_times_increase(self):
        self._run("alive")
        self._run("alive")
        hit = [r for r in self.store.findings(limit=50)["rows"] if r["sources"] == "sweep-paths"][0]
        self.assertEqual(hit["verify_times"], 2)

    def test_empty_ids_is_refused(self):
        v = vfy.Verifier(self.store, engine=self.engine, timeout=30)
        with self.assertRaises(ValueError):
            v.start([])

    def test_missing_engine_marks_unknown(self):
        v = vfy.Verifier(self.store, engine=os.path.join(self.tmp, "nope"), timeout=30)
        r = v.start(self.ids)
        self.assertTrue(r["ok"], r)   # 派发照常，结论在后面
        for _ in range(600):
            if not v.status()["running"]:
                break
            time.sleep(0.05)
        st = v.status()
        self.assertGreaterEqual(st["summary"].get("无法判定", 0), 1)


class TestExport(unittest.TestCase):
    def test_csv_and_md_carry_repro_and_verify(self):
        tmp = tempfile.mkdtemp(prefix="vc-vfy-exp-")
        try:
            s = Store(os.path.join(tmp, "t.db"))
            s.add_findings([{"title": "敏感路径可访问：/.env", "sev": "high", "asset": "h",
                             "endpoint": "/.env", "source": "sweep-paths",
                             "repro": "curl -sk -i 'http://h/.env'"}], "t.json")
            fid = int(s.findings(limit=10)["rows"][0]["id"])
            s.set_verify([(fid, "仍存在", "重跑命中")])
            csv = s.export_csv().splitlines()
            self.assertIn("复验", csv[0])
            self.assertIn("复现命令", csv[0])
            self.assertTrue(any("仍存在" in ln and "curl" in ln for ln in csv[1:]), csv)
            md = s.export_md()
            self.assertIn("复现", md)
            self.assertIn("仍存在", md)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

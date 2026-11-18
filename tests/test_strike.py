"""strike 移交链路的单测：目标推导、线索雏形、litmus 结论回写形状。

不联网、不调 litmus：执行层用临时文件模拟它的 findings.json，
验证「挑命中 → 生成清单 → 读回结论 → 归一化成 Kara 条目」这一段是准的。
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import strike                    # noqa: E402
from vc import cli                       # noqa: E402
from vc.store import Store               # noqa: E402


def row(**kw):
    base = {"id": 1, "asset": "127.0.0.1", "port": 18099, "endpoint": "",
            "title": "敏感路径可访问：/.env", "sev": "high", "evidence": "200 · 63B",
            "repro": "curl -i http://127.0.0.1:18099/.env", "files": "paths.json"}
    base.update(kw)
    return base


class TestTargets(unittest.TestCase):
    def test_endpoint_trimmed_to_origin(self):
        """端点要裁到 scheme://host:port —— 把具体路径递给执行层等于替它预设结论。"""
        self.assertEqual(strike.target_of(row(endpoint="http://127.0.0.1:18099/.env")),
                         "http://127.0.0.1:18099")
        self.assertEqual(strike.target_of(row(endpoint="https://a.com/x/y?z=1")), "https://a.com")

    def test_asset_with_port(self):
        self.assertEqual(strike.target_of(row(endpoint="", asset="10.0.0.5", port=8080)), "10.0.0.5:8080")

    def test_asset_only(self):
        self.assertEqual(strike.target_of(row(endpoint="", asset="a.com", port=None)), "a.com")

    def test_nothing_usable(self):
        self.assertEqual(strike.target_of(row(endpoint="", asset="", port=None)), "")

    def test_collect_dedupes(self):
        rows = [row(endpoint="http://127.0.0.1:18099/.env"),
                row(endpoint="http://127.0.0.1:18099/actuator/env"),
                row(endpoint="https://127.0.0.1:18443/x", port=18443)]
        self.assertEqual(strike.collect(rows),
                         ["http://127.0.0.1:18099", "https://127.0.0.1:18443"])

    def test_public_flag(self):
        self.assertTrue(strike.needs_public_flag(["https://example.com"]))
        self.assertTrue(strike.needs_public_flag(["8.8.8.8:443"]))
        self.assertFalse(strike.needs_public_flag(["127.0.0.1:8080", "10.1.2.3:80", "192.168.1.1"]))
        self.assertFalse(strike.needs_public_flag(["localhost:8080"]))


class TestSeed(unittest.TestCase):
    def test_seed_is_l1_suspected(self):
        """Kara 只给线索：level 必须写 L1、confidence 写 suspected，不许冒充 L2。"""
        seeds = strike.build_seed([row(endpoint="http://127.0.0.1:18099/.env")])
        self.assertEqual(len(seeds), 1)
        s = seeds[0]
        self.assertEqual(s["level"], "L1")
        self.assertEqual(s["confidence"], "suspected")
        self.assertEqual(s["target"], "http://127.0.0.1:18099")
        self.assertEqual(s["host"], "127.0.0.1")
        self.assertEqual(s["port"], 18099)
        self.assertEqual(s["severity"], "high")
        self.assertIn("kara-", s["id"])

    def test_seed_skips_unusable(self):
        self.assertEqual(strike.build_seed([row(endpoint="", asset="", port=None)]), [])


class TestReadAndMap(unittest.TestCase):
    def _write(self, d, payload):
        with open(os.path.join(d, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)

    def test_read_nested_dir(self):
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "out", "run1")
            os.makedirs(sub)
            self._write(sub, {"findings": [{"id": "LS-001", "severity": "critical"}]})
            items = strike.read_litmus_findings(d)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["id"], "LS-001")

    def test_read_missing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(strike.read_litmus_findings(d), [])
            self.assertEqual(strike.read_litmus_findings(""), [])

    def test_to_kara_keeps_level(self):
        """级别/置信要进证据串：L1 的条目交付时一眼能看出还没落地。"""
        items = [{
            "id": "LS-001", "check": "exposure", "name": ".env 配置文件可下载",
            "severity": "critical", "target": "http://127.0.0.1:18099/.env",
            "host": "127.0.0.1", "port": 18099, "level": "L2", "confidence": "confirmed",
            "evidence": "HTTP 200 · DB_PASSWORD=****", "repro": "curl -i http://x/.env",
        }]
        out = strike.to_kara(items, "findings.json")
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f["sev"], "critical")
        self.assertEqual(f["asset"], "127.0.0.1")
        self.assertEqual(f["source"], "litmus2:exposure")
        self.assertIn("[L2/confirmed]", f["evidence"])
        self.assertIn("DB_PASSWORD", f["evidence"])
        self.assertEqual(f["endpoint"], "http://127.0.0.1:18099/.env")

    def test_to_kara_bad_severity(self):
        out = strike.to_kara([{"severity": "SEVERE", "name": "x", "target": "http://a.com"}], "f.json")
        self.assertEqual(out[0]["sev"], "info")

    def test_summarize(self):
        mix = strike.summarize([{"severity": "critical"}, {"severity": "critical"}, {"severity": "low"}])
        self.assertEqual(mix, {"critical": 2, "low": 1})


class TestFindLitmus(unittest.TestCase):
    def test_explicit_missing(self):
        self.assertEqual(strike.find_litmus("/nope/litmus"), "")

    def test_explicit_ok(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "litmus")
            open(p, "w").close()
            os.chmod(p, 0o755)
            self.assertEqual(strike.find_litmus(p), os.path.abspath(p))


class TestStrikeCli(unittest.TestCase):
    def test_dry_run_no_requests(self):
        """--dry-run 必须只落清单、不调执行层（执行层不存在也照样成功）。"""
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "v.db"))
            store.add_findings([{
                "asset": "127.0.0.1", "title": ".env 暴露", "sev": "high",
                "endpoint": "http://127.0.0.1:18099/.env", "port": 18099,
                "ip": "127.0.0.1", "source": "sweep-paths", "evidence": "200", "repro": "curl -i x",
            }], "t.json")
            import contextlib, io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli.main(["--db", os.path.join(d, "v.db"), "strike",
                                 "--sev", "high", "--dry-run", "--litmus-bin", "/nope/litmus"])
            self.assertEqual(code, 0, buf.getvalue())
            self.assertIn("dry-run", buf.getvalue().lower())

    def test_missing_litmus_errors_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "v.db"))
            store.add_findings([{
                "asset": "10.0.0.5", "title": "端口暴露", "sev": "medium",
                "endpoint": "", "port": 8080, "ip": "10.0.0.5", "source": "sweep-ports",
                "evidence": "open", "repro": "",
            }], "t.json")
            import contextlib, io
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(["--db", os.path.join(d, "v.db"), "strike",
                                 "--litmus-bin", "/nope/litmus"])
            self.assertEqual(code, 2)
            self.assertIn("litmus", err.getvalue())


if __name__ == "__main__":
    unittest.main()

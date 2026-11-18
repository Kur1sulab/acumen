"""离线能力与报告的单测：brute / cve 两种产物解析 + 报告必须带证据与复现。

断网定位是硬约束：这些用例不联网，全部用固定产物验证「
解析得对、报告里写清了发现方式 / 判据 / 证据 / 复现」。
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import parsers_sweep, report   # noqa: E402

BRUTE = [{
    "host": "10.0.0.5", "port": 6379, "service": "redis", "tried": 3,
    "found": [{"service": "redis", "host": "10.0.0.5", "port": 6379,
               "user": "", "pass": "root", "note": "Redis AUTH 通过: +OK"}],
    "elapsed": 0.4,
}, {
    "host": "10.0.0.5", "port": 22, "service": "ssh", "tried": 0,
    "found": [], "skipped": "不支持的服务类型 \"ssh\"", "elapsed": 0.0,
}]

CVE = {
    "target": "http://10.0.0.5",
    "products": [{"product": "apache_httpd", "version": "2.4.49", "evidence": "Server: Apache/2.4.49"}],
    "matches": [{
        "id": "CVE-2021-41773", "title": "Apache HTTP Server 2.4.49 路径穿越 / 任意文件读取",
        "severity": "high", "product": "apache_httpd", "version": "2.4.49",
        "evidence": "Server: Apache/2.4.49", "verify": "GET /cgi-bin/.%2e/.../etc/passwd",
        "confidence": "version-range", "level": "L1",
    }],
}


class TestBruteParser(unittest.TestCase):
    def test_detect_and_parse(self):
        self.assertEqual(parsers_sweep.detect(BRUTE), "sweep_brute")
        res = parsers_sweep.parse(json.dumps(BRUTE), "out/10.0.0.5/brute.json")
        self.assertEqual(res.fmt, "sweep_brute")
        # 一条命中 + 一条「未验证」——没测成的必须留痕，不能装成「没弱口令」
        self.assertEqual(len(res.findings), 2)
        hit = [f for f in res.findings if f["sev"] != "info"][0]
        self.assertIn("redis", hit["title"])
        self.assertIn("root", hit["title"])
        self.assertIn("redis-cli", hit["repro"])
        skipped = [f for f in res.findings if f["sev"] == "info"][0]
        self.assertIn("未能验证", skipped["title"])
        self.assertIn("ssh", skipped["title"])


class TestCveParser(unittest.TestCase):
    def test_detect_and_parse(self):
        self.assertEqual(parsers_sweep.detect(CVE), "sweep_cve")
        res = parsers_sweep.parse(json.dumps(CVE), "out/10.0.0.5/cve.json")
        self.assertEqual(res.fmt, "sweep_cve")
        self.assertEqual(len(res.findings), 1)
        f = res.findings[0]
        self.assertIn("CVE-2021-41773", f["title"])
        self.assertIn("可能受影响", f["title"])   # L1 不许写成已确认
        self.assertEqual(f["cve"], "CVE-2021-41773")
        self.assertIn("2.4.49", f["evidence"])
        self.assertIn("cgi-bin", f["repro"])


class TestReport(unittest.TestCase):
    def _rows(self):
        return [
            {"id": 1, "sev": "critical", "title": "弱口令：redis/root",
             "asset": "10.0.0.5", "port": 6379, "endpoint": "redis://10.0.0.5:6379",
             "sources": "sweep-brute:redis", "evidence": "redis 登录成功 · +OK",
             "repro": "redis-cli -h 10.0.0.5 -p 6379 -a 'root' ping",
             "status": "待验证", "files": "/tmp/out/10.0.0.5/brute.json"},
            {"id": 2, "sev": "high", "title": "CVE-2021-41773 可能受影响：Apache 路径穿越",
             "asset": "10.0.0.5", "port": 80, "endpoint": "http://10.0.0.5/",
             "sources": "sweep-cve:CVE-2021-41773",
             "evidence": "apache_httpd 2.4.49 · [L1]", "repro": "GET /cgi-bin/...",
             "status": "待验证", "files": ""},
        ]

    def test_sections(self):
        text = report.render(self._rows(), target="10.0.0.5", mode="brute",
                             engine="/x/sweep", db="/tmp/v.db",
                             notes=["模式 `brute`：协议握手验证"])
        for must in ("# 空境 Kara", "本次做了什么", "漏洞明细",
                     "发现方式", "判据/证据", "复现", "未验证", "L2"):
            self.assertIn(must, text)
        # 复现命令必须原样出现，能直接粘
        self.assertIn("redis-cli -h 10.0.0.5", text)
        self.assertIn("弱口令验证", text)          # 来源翻译成人话
        self.assertIn("离线 CVE 匹配", text)

    def test_evidence_inlined(self):
        """有 evidence/ 目录就摘响应片段进报告，而不是只丢个路径。"""
        with tempfile.TemporaryDirectory() as d:
            art = os.path.join(d, "out", "10.0.0.5")
            ev = os.path.join(art, "evidence", "10.0.0.5", "actuator_env")
            os.makedirs(ev)
            with open(os.path.join(art, "api_unauth.json"), "w", encoding="utf-8") as fh:
                fh.write("{}")
            with open(os.path.join(ev, "response.snippet.txt"), "w", encoding="utf-8") as fh:
                fh.write('{"propertySources":[{"name":"app"}]}\n')
            rows = [{"id": 3, "sev": "high", "title": "API 未授权访问：Actuator env",
                     "asset": "10.0.0.5", "port": 8080,
                     "endpoint": "http://10.0.0.5:8080/actuator/env",
                     "sources": "sweep-api", "evidence": "HTTP 200", "repro": "",
                     "status": "待验证",
                     "files": os.path.join(art, "api_unauth.json")}]
            text = report.render(rows, target="10.0.0.5", mode="api")
            self.assertIn("证据（响应片段）", text)
            self.assertIn("propertySources", text)
            self.assertIn("response.snippet.txt", text)

    def test_write(self):
        with tempfile.TemporaryDirectory() as d:
            p = report.write("# x\n", d, "r.md")
            self.assertTrue(os.path.isfile(p))
            self.assertEqual(open(p, encoding="utf-8").read(), "# x\n")


if __name__ == "__main__":
    unittest.main()

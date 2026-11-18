"""引擎原生产物解析的回归测试。

fixtures 全部是 2026-11-18 从真引擎跑真目标（本机 127.0.0.1 + 一个故意放 .env/.git 的
本地 http.server）拿到的原始输出，不是手捏的样板——手捏的样板永远比现实干净，
测不出「压缩 JS 变量名被当成密钥」这种真实误报。
"""

import json
import os
import unittest

from vc import parsers_sweep as ps
from vc.parsers import parse_file

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "sweep")


def fixture(name):
    return os.path.join(FIX, name)


def load(name):
    with open(fixture(name), encoding="utf-8") as fh:
        return json.load(fh)


class TestHostFromPath(unittest.TestCase):
    def test_recovers_host_and_port(self):
        p = "/x/inbox/scan-1/out/http_10.71.32.204_8443/paths.json"
        self.assertEqual(ps.host_from_path(p), "10.71.32.204:8443")

    def test_plain_host(self):
        self.assertEqual(ps.host_from_path("/x/out/10.71.32.204/ports.json"), "10.71.32.204")

    def test_no_host_in_path(self):
        self.assertEqual(ps.host_from_path("/tmp/a/b/c.json"), "")

    def test_windows_separators(self):
        p = r"C:\kara\inbox\scan-2\out\http_example.com\ports.json"
        self.assertEqual(ps.host_from_path(p), "example.com")


class TestPaths(unittest.TestCase):
    def test_alive_paths_become_findings(self):
        obj = load("paths.json")
        host = ps.host_from_path(fixture("paths.json"))
        r = ps.parse_paths(obj, host)
        titles = [f["title"] for f in r.findings]
        self.assertEqual(len(r.findings), 3, titles)
        # 配置/凭据类才是高危；actuator 只是「暴露了信息」，给中危
        sev = {f["title"].rsplit("：", 1)[-1]: f["sev"] for f in r.findings}
        self.assertEqual(sev["/.env"], "high")
        self.assertEqual(sev["/.git/config"], "high")
        self.assertEqual(sev["/actuator"], "medium")

    def test_asset_gets_port_from_directory(self):
        """产物目录名带主机和端口，解析时必须把端口一起记进资产。"""
        obj = load("paths.json")
        r = ps.parse_paths(obj, "127.0.0.1:8899")
        self.assertEqual(r.assets[0]["host"], "127.0.0.1")
        self.assertEqual(r.assets[0]["port"], 8899)
        # 漏洞挂在主机名上（与资产表同一口径），端口信息留在 endpoint 里
        self.assertEqual(r.findings[0]["asset"], "127.0.0.1")
        self.assertIn(":8899/", r.findings[0]["endpoint"])


class TestPorts(unittest.TestCase):
    def test_open_ports_become_assets(self):
        r = ps.parse_ports(load("ports.json"), "127.0.0.1")
        self.assertGreaterEqual(len(r.assets), 5)
        ports = {a["port"] for a in r.assets}
        self.assertIn(22, ports)
        self.assertTrue(all(a["proto"] == "tcp" for a in r.assets))

    def test_binary_banner_is_sanitised(self):
        """MySQL 握手包里是原始字节，塞进界面就是乱码。"""
        r = ps.parse_ports(load("ports.json"), "127.0.0.1")
        mysql = next(a for a in r.assets if a["port"] == 3306)
        self.assertNotRegex(mysql["service"], r"[\x00-\x1f\x7f-\x9f]")
        self.assertIn("mysql", mysql["service"].lower())

    def test_banner_helper(self):
        self.assertEqual(ps.clean_banner("SSH-2.0-OpenSSH_10.5\r\n"), "SSH-2.0-OpenSSH_10.5")
        self.assertEqual(ps.clean_banner("\x00\x01\x02\x03"), "")
        self.assertEqual(ps.clean_banner(""), "")


class TestApiUnauth(unittest.TestCase):
    def test_only_hits_count(self):
        obj = load("api_unauth.json")
        hits = [x for x in obj["all"] if x.get("hit")]
        r = ps.parse_api(obj, "127.0.0.1")
        self.assertEqual(len(r.findings), len(hits))
        for f in r.findings:
            self.assertIn("未授权", f["title"])
            self.assertIn(f["sev"], ("critical", "high", "medium", "low", "info"))

    def test_no_hit_no_finding(self):
        obj = {"all": [{"name": "Swagger UI", "path": "/swagger-ui.html", "risk": "中",
                        "hit": False, "status": 404, "size": 335}]}
        r = ps.parse_api(obj, "1.2.3.4")
        self.assertEqual(r.findings, [])
        self.assertIn("无未授权命中", r.note)


class TestJsIntel(unittest.TestCase):
    def test_compressed_js_variables_are_not_secrets(self):
        """真样本回归：一轮跑出 8 条「敏感串」，全是压缩 JS 的变量名（sk/ak）。

        这类误报会直接把漏扫变成谣言机，所以必须在解析层拦掉并留痕（note 里报丢弃数）。
        """
        obj = load("jsintel.json")
        r = ps.parse_jsintel(obj, "127.0.0.1")
        self.assertEqual(r.findings, [], [f["title"] for f in r.findings])
        self.assertIn("丢弃", r.note)

    def test_real_looking_secret_kept(self):
        obj = {"base": "https://t.example.com", "scripts": {}, "endpoints": [],
               "sensitive": [{"key": "api_key", "value": "a8f3kd92mfk20dk3m4ldk39fk", 
                              "snippet": 'api_key:"a8f3kd92mfk20dk3m4ldk39fk"'}]}
        r = ps.parse_jsintel(obj, "t.example.com")
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0]["sev"], "high")

    def test_word_like_value_rejected(self):
        obj = {"base": "https://t.example.com", "scripts": {}, "endpoints": [],
               "sensitive": [{"key": "api_key", "value": "consent_management_mode",
                              "snippet": "api_key:consent_management_mode"}]}
        r = ps.parse_jsintel(obj, "t.example.com")
        self.assertEqual(r.findings, [])

    def test_secret_helper(self):
        self.assertTrue(ps.looks_like_secret("AKIAIOSFODNN7EXAMPLE"))
        self.assertTrue(ps.looks_like_secret("ghp_" + "a1b2c3d4" * 5))
        self.assertFalse(ps.looks_like_secret("enhanced_mode"))      # 8 字符标识符
        self.assertFalse(ps.looks_like_secret("authentication"))     # 纯单词
        self.assertFalse(ps.looks_like_secret("")) 

    def test_secret_value_is_masked_in_evidence(self):
        obj = {"base": "https://t.example.com", "scripts": {}, "endpoints": [],
               "sensitive": [{"key": "secret", "value": "Zx9Qw8Er7Ty6Ui5Op4As3Df2",
                              "snippet": 'secret="Zx9Qw8Er7Ty6Ui5Op4As3Df2"'}]}
        r = ps.parse_jsintel(obj, "t.example.com")
        self.assertEqual(len(r.findings), 1)
        masks = [e for e in r.findings[0]["evidence"].split(" · ") if "*" in e]
        self.assertTrue(masks, r.findings[0]["evidence"])
        self.assertNotIn("Zx9Qw8Er7Ty6Ui5Op4As3Df2", r.findings[0]["evidence"])


class TestBaseline(unittest.TestCase):
    def test_risks_become_low_findings(self):
        obj = load("secheaders.json")
        r = ps.parse_baseline(obj, "127.0.0.1")
        self.assertEqual(len(r.findings), len(obj["risks"]))
        self.assertTrue(all(f["sev"] == "low" for f in r.findings))
        self.assertTrue(all(f["title"].startswith("secheaders：") for f in r.findings))

    def test_clean_check_has_no_findings(self):
        obj = load("webfiles.json")
        r = ps.parse_baseline(obj, "127.0.0.1")
        self.assertEqual(r.findings, [])
        self.assertIn("无风险项", r.note)


class TestEvidenceMeta(unittest.TestCase):
    def test_meta_json_is_a_finding(self):
        obj = load("evidence-meta.json")
        r = ps.parse_evidence(obj, "127.0.0.1:8899")
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0]["asset"], "127.0.0.1")
        self.assertEqual(r.findings[0]["severity"] if False else r.findings[0]["sev"], "low")

    def test_generic_risk_word_rejected(self):
        """乱七八糟的 JSON（有 url+name 但没有风险语义）不该被认成取证记录。"""
        self.assertFalse(ps._is_evidence({"url": "https://a", "name": "x"}))


class TestDispatch(unittest.TestCase):
    def test_parse_file_paths(self):
        r = parse_file(fixture("paths.json"))
        self.assertEqual(r.fmt, "sweep_paths")
        self.assertEqual(len(r.findings), 3)

    def test_parse_file_empty_fingerprint(self):
        """引擎 0 命中写的是 []，不该显示成「格式无法识别」。"""
        r = parse_file(fixture("fingerprint.json"))
        self.assertIn(r.fmt, ("sweep_fingerprint", "skipped"))
        if r.fmt == "skipped":
            self.assertIn("0", r.note)

    def test_parse_file_evidence_copy_dir_skipped(self):
        r = parse_file("/tmp/x/scan-1/out/1.2.3.4/evidence/baseline/secheaders.json")
        self.assertTrue(r.fmt == "skipped" or "基线产物副本" in r.note)

    def test_unknown_json_still_falls_through(self):
        r = ps.parse('{"hello": "world"}', "/tmp/x.json")
        self.assertIsNone(r)

    def test_non_json_ignored(self):
        self.assertIsNone(ps.parse("just text", "/tmp/x.txt"))


if __name__ == "__main__":
    unittest.main()

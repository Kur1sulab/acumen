"""CVE 识别链路 + 资产补全 + 繁体报告的表头识别。

写这组测试的起因很具体：库里 129 条 finding 一条 CVE 都没有，而调研结论说
「没有 CVE 就没有 EPSS/KEV」。查下来发现不是数据没有编号，是解析器从来没取过——
nuclei 把 CVE 写在 template-id 里、nessus 写在 <cve> 子元素里，两处都被丢了。
"""

from __future__ import annotations

import os
import unittest

from vc.parsers import cve_of, parse_file, _mk_finding

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class TestCveOf(unittest.TestCase):
    """编号抽取：容错但不误报。"""

    def test_standard(self):
        self.assertEqual(cve_of("CVE-2021-44228"), "CVE-2021-44228")

    def test_separator_variants(self):
        # 报告里这几种写法都见过：下划线、空格、全角横线、短破折、长破折、减号
        for raw in ("cve_2021_44228", "CVE 2021 44228", "CVE\uFF0D2021\uFF0D44228",
                    "CVE\u20132021\u201344228", "CVE\u20142021\u201444228", "CVE\u22122021\u221244228"):
            with self.subTest(raw=raw):
                self.assertEqual(cve_of(raw), "CVE-2021-44228")

    def test_multiple_sorted_and_deduped(self):
        got = cve_of("CVE-2022-1234 与 CVE-2021-44228，重复 CVE-2021-44228")
        self.assertEqual(got, "CVE-2021-44228,CVE-2022-1234")

    def test_short_number(self):
        self.assertEqual(cve_of("CVE-2021-4422"), "CVE-2021-4422")

    def test_no_false_positive(self):
        # 拼在别的词后面、或者根本不是编号的，一律不许当 CVE
        for raw in ("XVENOM2021-44228", "CVE-ABCD-1234", "exposed-panel", "apache-log4j", ""):
            with self.subTest(raw=raw):
                self.assertEqual(cve_of(raw), "")

    def test_chinese_text_without_id(self):
        self.assertEqual(cve_of("Apache Shiro 反序列化（无编号）"), "")


class TestFindingCarriesCve(unittest.TestCase):

    def test_from_title(self):
        f = _mk_finding(title="Apache Log4j2 RCE (CVE-2021-44228)", sev="critical")
        self.assertEqual(f["cve"], "CVE-2021-44228")

    def test_from_evidence(self):
        f = _mk_finding(title="某漏洞", evidence="详见 CVE-2020-2222")
        self.assertEqual(f["cve"], "CVE-2020-2222")

    def test_explicit_wins(self):
        f = _mk_finding(title="x", cve="CVE-2020-1111", evidence="CVE-2020-2222")
        self.assertEqual(f["cve"], "CVE-2020-1111")

    def test_non_cve_template_id_does_not_pollute(self):
        """template-id 可能是 exposed-panel 这种名字，不能塞进 cve 字段。"""
        f = _mk_finding(title="Admin panel exposed", cve="exposed-panel")
        self.assertEqual(f["cve"], "")

    def test_port_from_endpoint(self):
        f = _mk_finding(title="x", endpoint="https://a.example.test:8443/x")
        self.assertEqual(f["port"], 8443)


class TestParsersCarryCve(unittest.TestCase):

    def test_nuclei_template_id_is_cve(self):
        res = parse_file(os.path.join(FIX, "nuclei-cve.jsonl"))
        got = {f["title"]: f["cve"] for f in res.findings}
        self.assertEqual(got.get("Apache Log4j2 Remote Code Execution"), "CVE-2021-44228")
        # 这一条模板 ID 不是 CVE，字段必须留空
        self.assertEqual(got.get("Admin panel exposed (no vuln id)"), "")

    def test_nessus_cve_elements(self):
        res = parse_file(os.path.join(FIX, "nessus-cve.nessus"))
        self.assertTrue(res.findings, "nessus 应当解析出 finding")
        joined = ",".join(f["cve"] for f in res.findings)
        self.assertIn("CVE-2021-44228", joined)
        self.assertIn("CVE-2021-45046", joined)

    def test_traditional_chinese_header(self):
        """繁体表头（編號/發現/嚴重度）以前整份丢弃，88 行一条不剩。"""
        res = parse_file(os.path.join(FIX, "zh-hant-report.md"))
        self.assertEqual(len(res.findings), 3)
        sev = sorted(f["sev"] for f in res.findings)
        self.assertEqual(sev, ["critical", "high", "medium"])


if __name__ == "__main__":
    unittest.main()

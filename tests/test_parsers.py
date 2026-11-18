"""漏扫控制台单测：解析器逐格式 + 存储层去重合并 + 端到端摄入。

跑法：python3 -m pytest tests/ -q   或   python3 -m unittest discover -s tests -v
（零依赖：pytest 不在时用 unittest 也能跑）
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import parsers  # noqa: E402
from vc.ingest import Ingestor  # noqa: E402
from vc.store import Store  # noqa: E402

# ------------------------------------------------------------------ 样本

NUCLEI_JSONL = "\n".join([
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j RCE","severity":"critical"},'
    '"host":"https://a.example.com","matched-at":"https://a.example.com/api?x=1","ip":"10.0.0.5",'
    '"matcher-name":"word","timestamp":"2026-11-17T10:00:00+08:00"}',
    '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium"},'
    '"host":"https://b.example.com","matched-at":"https://b.example.com/admin"}',
])

NUCLEI_TEXT = "\n".join([
    "[CVE-2021-44228] [http] [critical] https://a.example.com/api?x=1",
    "[exposed-panel] [http] [medium] https://b.example.com/admin",
    "[info] [4/28] https://a.example.com/x -> status=302, body=0 bytes",  # yakit 进度行，不该当漏洞
])

XRAY_JSONL = "\n".join([
    '{"type":"web_vuln","plugin":"sql_injection","target":{"url":"https://c.example.com/item?id=1"},'
    '"detail":{"payload":"1 AND 1=1"},"create_time":"2026-11-17"}',
    '{"type":"web_vuln","plugin":"xss","target":{"url":"https://c.example.com/search?q=1"},'
    '"detail":{"payload":"<script>"}}',
])

XRAY_WRAPPED = """{"data":{"detail":[
  {"plugin":"ssrf","target":{"url":"https://d.example.com/fetch?u=1"},"detail":{"payload":"http://169.254.169.254"}}
]}}"""

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
 <host><address addr="10.0.0.9" addrtype="ipv4"/>
  <hostnames><hostname name="web.example.com"/></hostnames>
  <ports>
   <port protocol="tcp" portid="443">
     <state state="open"/>
     <service name="https" product="nginx" version="1.24"/>
     <script id="ssl-weak" output="CVSS: 7.4 - weak ciphers"/>
   </port>
   <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
   <port protocol="tcp" portid="8080"><state state="closed"/></port>
  </ports>
 </host>
</nmaprun>"""

NESSUS = """<?xml version="1.0"?>
<NessusClientData_v2>
 <Report name="test">
  <ReportHost name="10.0.0.20">
   <HostProperties><tag name="host-ip">10.0.0.20</tag></HostProperties>
   <ReportItem port="443" svc_name="www" pluginID="51192" pluginName="SSL Certificate Cannot Be Trusted" severity="2">
     <description>证书不受信任</description>
   </ReportItem>
   <ReportItem port="445" svc_name="smb" pluginID="97833" pluginName="SMB Signing Disabled" severity="3"/>
  </ReportHost>
 </Report>
</NessusClientData_v2>"""

YAKIT_PORT = "\n".join([
    '禁用基础爬虫',
    '[Result] {"fingerprint":"conn_keepalive/https/nginx","host":"10.0.0.30","htmlTitle":"登录","isOpen":true,"port":443}',
    '[Result] {"fingerprint":"http/php","host":"10.0.0.31","htmlTitle":"","isOpen":true,"port":80}',
    '[Result] {"fingerprint":"http","host":"10.0.0.32","htmlTitle":"","isOpen":false,"port":80}',
])

# 真实世界形状：存活/指纹清单（绝不能被当成漏洞）
INVENTORY_JSON = """[
 {"host":"dmcx.example.gov.cn","status":-1,"server":"","powered":"","title":"","ct":"","len":0,"fw":""},
 {"host":"dtgl.example.gov.cn","status":200,"server":"nginx","powered":"jQuery","title":"电梯平台","ct":"text/html","len":8996,"fw":"JHi"}
]"""

CSV_CN = """漏洞名称,风险等级,URL,描述
SQL 注入,高危,https://e.example.com/item?id=1,参数 id 可注入
反射型 XSS,中危,https://e.example.com/search?q=1,未过滤
"""

CSV_INVENTORY = """主机,标题,状态码
a.example.com,首页,200
"""

MD_TABLE = """
## 漏洞清单

| 漏洞 | 等级 | URL | 证据 |
|---|---|---|---|
| Shiro 反序列化 | 严重 | https://f.example.com/login | rememberMe cookie 回显 |
| 目录遍历 | 低危 | https://f.example.com/download?f=1 | 读到 passwd |
"""

MD_EVIDENCE_TABLE = """
| 项 | 值 | 证据 |
|---|---|---|
| 中间件 | Tomcat 8.5 | 405 页 |
"""


class TestNuclei(unittest.TestCase):
    def test_jsonl(self):
        r = parsers.parse_nuclei_jsonl(NUCLEI_JSONL)
        self.assertEqual(len(r.findings), 2)
        self.assertEqual(r.findings[0]["sev"], "critical")
        self.assertEqual(r.findings[0]["asset"], "a.example.com")
        self.assertEqual(r.findings[0]["param"], "x")

    def test_text_and_progress_line(self):
        r = parsers.parse_nuclei_text(NUCLEI_TEXT)
        self.assertEqual(len(r.findings), 2, [f["title"] for f in r.findings])
        self.assertEqual({f["sev"] for f in r.findings}, {"critical", "medium"})


class TestXray(unittest.TestCase):
    def test_jsonl(self):
        agg = parsers.ParseResult("xray", [], [])
        for obj in parsers.iter_json_objects(XRAY_JSONL):
            r = parsers.parse_xray(obj)
            agg.findings.extend(r.findings)
        self.assertEqual(len(agg.findings), 2)
        self.assertEqual(agg.findings[0]["title"], "sql_injection")
        self.assertEqual(agg.findings[0]["asset"], "c.example.com")

    def test_wrapped(self):
        r = parsers.parse_xray(parsers.iter_json_objects(XRAY_WRAPPED)[0])
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0]["title"], "ssrf")


class TestNmapNessus(unittest.TestCase):
    def test_nmap(self):
        r = parsers.parse_nmap_xml(NMAP_XML)
        self.assertEqual(len(r.assets), 2, "只有 open 端口进资产")
        self.assertEqual({a["port"] for a in r.assets}, {443, 22})
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0]["sev"], "high", "CVSS 7.4 → high")
        self.assertEqual(r.findings[0]["asset"], "web.example.com")

    def test_nessus(self):
        r = parsers.parse_nessus(NESSUS)
        self.assertEqual(len(r.findings), 2)
        self.assertEqual({f["sev"] for f in r.findings}, {"medium", "high"})


class TestYakitAndInventory(unittest.TestCase):
    def test_yakit_open_only(self):
        r = parsers.parse_yakit_port(YAKIT_PORT)
        self.assertEqual(len(r.assets), 2)
        self.assertIn(443, [a["port"] for a in r.assets])

    def test_inventory_is_not_findings(self):
        """回归：指纹清单曾被误判成 14 条 info 漏洞。"""
        objs = parsers.iter_json_objects(INVENTORY_JSON)
        r = parsers.parse_json_generic(objs[0])
        self.assertEqual(len(r.findings), 0, "资产清单不该产出漏洞")
        self.assertEqual(len(r.assets), 2)
        self.assertEqual(r.assets[1]["title"], "电梯平台")
        self.assertEqual(r.assets[1]["service"], "nginx")


class TestTables(unittest.TestCase):
    def test_csv_cn(self):
        r = parsers.parse_csv_table(CSV_CN)
        self.assertEqual(len(r.findings), 2)
        self.assertEqual({f["sev"] for f in r.findings}, {"high", "medium"})

    def test_csv_inventory_rejected(self):
        r = parsers.parse_csv_table(CSV_INVENTORY)
        self.assertEqual(len(r.findings), 0)
        self.assertIn("无漏洞列", r.note)

    def test_md_table(self):
        r = parsers.parse_md_table(MD_TABLE)
        self.assertEqual(len(r.findings), 2)
        self.assertEqual(r.findings[0]["sev"], "critical")

    def test_md_evidence_table_rejected(self):
        r = parsers.parse_md_table(MD_EVIDENCE_TABLE)
        self.assertEqual(len(r.findings), 0)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))

    def tearDown(self):
        self.store.conn.close()
        self.tmp.cleanup()

    def test_dedupe_merge(self):
        f1 = parsers.parse_nuclei_jsonl(NUCLEI_JSONL).findings[0]
        a, m = self.store.add_findings([f1], "/tmp/a.jsonl")
        self.assertEqual((a, m), (1, 0))
        f2 = dict(f1, source="xray", sev="info")  # 同一漏洞，另一来源、更低分级
        a, m = self.store.add_findings([f2], "/tmp/b.json")
        self.assertEqual((a, m), (0, 1))
        s = self.store.summary()
        self.assertEqual(s["findings"], 1)
        self.assertEqual(s["severity"]["critical"], 1, "取最高分级")
        row = self.store.findings()["rows"][0]
        self.assertEqual(row["count"], 2)
        self.assertEqual(set(row["sources"].split(",")), {"nuclei", "xray"})

    def test_status_and_export(self):
        self.store.add_findings(parsers.parse_nuclei_jsonl(NUCLEI_JSONL).findings, "/tmp/a.jsonl")
        ids = [r["id"] for r in self.store.findings()["rows"]]
        self.assertEqual(self.store.set_status(ids, "已确认"), len(ids))
        with self.assertRaises(ValueError):
            self.store.set_status(ids, "瞎写")
        csv_text = self.store.export_csv()
        self.assertIn("已确认", csv_text)
        self.assertIn("Apache Log4j RCE", csv_text)
        md = self.store.export_md()
        self.assertIn("## 漏洞清单", md)
        self.assertIn("Apache Log4j RCE", md)

    def test_assets_merge_ports(self):
        r = parsers.parse_nmap_xml(NMAP_XML)
        self.store.add_assets(r.assets, "/tmp/n.xml")
        self.store.add_assets([{"host": "web.example.com", "ip": "", "port": 8080, "proto": "tcp",
                                "service": "", "title": "", "fingerprint": "", "source": "yakit"}], "/tmp/y.txt")
        rows = self.store.assets()["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(sorted(p["port"] for p in rows[0]["ports"]), [22, 443, 8080])


class TestIngestEndToEnd(unittest.TestCase):
    def test_incremental(self):
        with tempfile.TemporaryDirectory() as tmp:
            inbox = os.path.join(tmp, "inbox")
            os.makedirs(inbox)
            with open(os.path.join(inbox, "nuclei.jsonl"), "w", encoding="utf-8") as fh:
                fh.write(NUCLEI_JSONL)
            with open(os.path.join(inbox, "ports.txt"), "w", encoding="utf-8") as fh:
                fh.write(YAKIT_PORT)
            with open(os.path.join(inbox, "inventory.json"), "w", encoding="utf-8") as fh:
                fh.write(INVENTORY_JSON)
            with open(os.path.join(inbox, "notes.log"), "w", encoding="utf-8") as fh:
                fh.write("not whitelisted")

            store = Store(os.path.join(tmp, "t.db"))
            ing = Ingestor(store, [inbox])
            stats = ing.scan()
            self.assertEqual(stats["parsed"], 3, stats)
            self.assertEqual(stats["findings_added"], 2)
            self.assertEqual(stats["assets"], 4)  # yakit 2 + inventory 2

            stats2 = ing.scan()  # 第二轮：全部未变
            self.assertEqual(stats2["parsed"], 0)
            self.assertEqual(stats2["unchanged"], 3)

            # 改动一个文件 → 只重解析它
            with open(os.path.join(inbox, "nuclei.jsonl"), "a", encoding="utf-8") as fh:
                fh.write("\n" + '{"template-id":"new-one","info":{"name":"New Hit","severity":"high"},'
                                '"host":"https://g.example.com","matched-at":"https://g.example.com/x"}')
            stats3 = ing.scan()
            self.assertEqual(stats3["parsed"], 1)
            self.assertEqual(stats3["findings_added"], 1)
            self.assertEqual(store.summary()["findings"], 3)
            store.conn.close()


class TestRealFilesIfPresent(unittest.TestCase):
    """拿本机真实产物做冒烟（没有就跳过，不伪造）。"""

    REAL_DIR = os.path.expanduser("~/pentest/lzxf-1111/live-1116")

    @unittest.skipUnless(os.path.isdir(REAL_DIR), "本机没有真实样本目录")
    def test_real_portscan(self):
        path = os.path.join(self.REAL_DIR, "portscan.txt")
        if not os.path.isfile(path):
            self.skipTest("portscan.txt 不存在")
        r = parsers.parse_file(path)
        self.assertEqual(r.fmt, "yakit_port")
        self.assertGreater(len(r.assets), 0)
        for a in r.assets:
            self.assertTrue(a["host"])
            self.assertIsInstance(a["port"], int)

    @unittest.skipUnless(os.path.isdir(REAL_DIR), "本机没有真实样本目录")
    def test_real_fingerprint_is_inventory(self):
        path = os.path.join(self.REAL_DIR, "r3b2-fingerprint.json")
        if not os.path.isfile(path):
            self.skipTest("r3b2-fingerprint.json 不存在")
        r = parsers.parse_file(path)
        self.assertEqual(r.fmt, "host_inventory")
        self.assertEqual(len(r.findings), 0)
        self.assertGreater(len(r.assets), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)

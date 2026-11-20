"""三层流水线的落库、反馈闭环与 CLI 接线。

和 tests/test_pipeline.py 的分工：
    那个文件钉「判定语义」（真 HTTP 靶子 + 真 prober：全站 500、WAF 页、布尔对照……）；
    这个文件钉「判定之后」——结论怎么落库、人工判定怎么回写、历史怎么参与下一轮、
    list/verify 两条命令怎么把它显示出来。用注入的假 prober，不发任何请求。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vc import cli                 # noqa: E402
from vc import pipeline as pipemod  # noqa: E402
from vc import verify as vfy      # noqa: E402
from vc.store import Store        # noqa: E402


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:      # --help / 用法错误走的是 argparse 的退出
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


def row(**kw):
    base = {"id": 1, "title": "参数触发服务端错误：tpl", "asset": "127.0.0.1", "port": "8080",
            "endpoint": "http://127.0.0.1:8080/render?tpl={{7*7}}&lang=zh", "param": "tpl",
            "sources": "sweep-paths", "sev": "high", "base": "http://127.0.0.1:8080",
            "status": "待验证", "evidence": ""}
    base.update(kw)
    return base


class FakeProber:
    """按 URL 特征回假响应：payload 在 → 500；无害值 → 200；别的 → 200 静态页。"""

    def __init__(self):
        self.calls = []

    def __call__(self, req):
        url = req.get("url") or ""
        self.calls.append(url)
        if "%7B%7B7%2A7%7D%7D" in url or "{{7*7}}" in url:
            return {"status": 500, "headers": {"content-type": "text/plain"},
                    "body": "Template render failed", "url": url, "error": ""}
        if "/render" in url:
            return {"status": 200, "headers": {"content-type": "text/html"},
                    "body": "<html>渲染成功</html>", "url": url, "error": ""}
        return {"status": 404, "headers": {}, "body": "nope", "url": url, "error": ""}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kara-pipe-")
        self.db = os.path.join(self.tmp, "v.db")
        self.store = Store(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed(self, n: int = 1, **kw) -> int:
        title = f"参数触发服务端错误：tpl{n}"
        self.store.add_findings([row(title=title, endpoint=row()["endpoint"] + f"&i={n}", **kw)],
                                "t.json")
        got = [r for r in self.store.findings(q=title, limit=50)["rows"] if r["title"] == title]
        self.assertTrue(got, f"没入账：{title}")
        return int(got[0]["id"])


class TestStorePipeline(Base):
    def test_set_pipeline_and_stats(self):
        fid = self.seed()
        layers = {"L1": {"state": "pass", "reason": "a"}, "L2": {"state": "skip", "reason": "b"},
                  "L3": {"state": "pass", "reason": "c"}}
        n = self.store.set_pipeline([{"id": fid, "state": "verified", "pass": 2,
                                      "layers": layers, "reason": "三层全过", "poc": "curl x"}])
        self.assertEqual(n, 1)
        got = self.store.findings(limit=5)["rows"][0]
        self.assertEqual(got["pipe_state"], "verified")
        self.assertEqual(got["pipe_pass"], 2)
        self.assertEqual(got["pipe_poc"], "curl x")
        self.assertEqual(json.loads(got["pipe_layers"])["L2"]["state"], "skip")
        self.assertEqual(self.store.pipeline_stats()[0]["n"], 1)

    def test_pipeline_of_roundtrip(self):
        fid = self.seed()
        layers = {"L1": {"state": "pass", "reason": "a"}, "L2": {"state": "fail", "reason": "b"},
                  "L3": {"state": "skip", "reason": "c"}}
        self.store.set_pipeline([{"id": fid, "state": "refuted", "pass": 1,
                                  "layers": layers, "reason": "L2 不通过", "poc": ""}])
        r = self.store.findings(limit=5)["rows"][0]
        res = vfy.pipeline_of(r)
        self.assertEqual(res["verdict"], "refuted")
        self.assertEqual(res["layers"]["L2"]["state"], "fail")
        self.assertEqual(res["ran_count"], 2)          # skip 不算跑过
        self.assertEqual(pipemod.badge(res), "✗1/2")

    def test_badge_uses_applicable_layers(self):
        ok = {"verdict": "verified",
              "layers": {"L1": {"state": "pass"}, "L2": {"state": "skip"}, "L3": {"state": "skip"}}}
        self.assertEqual(pipemod.badge(ok), "✓1/1")     # 1/3 会被读成「只过一层」
        self.assertEqual(pipemod.badge({"verdict": "", "layers": {}}), "—")
        self.assertEqual(pipemod.badge("downgraded"), "⚠降级")


class TestFeedbackLoop(Base):
    def test_add_feedback_accumulates(self):
        self.assertEqual(self.store.add_feedback("h", "rule", "p", "refuted", "note", "cli"), 1)
        self.assertEqual(self.store.add_feedback("h", "rule", "p", "refuted", "", "cli"), 2)
        got = self.store.feedback_for("h", "rule", "p")
        self.assertEqual(got["times"], 2)
        self.assertEqual(pipemod.norm_human(got["verdict"]), pipemod.REFUTED)

    def test_feedback_for_missing_is_empty(self):
        self.assertEqual(self.store.feedback_for("h", "x", "y"), {})

    def test_apply_history_marks_downgraded(self):
        fid = self.seed()
        r = self.store.findings(limit=5)["rows"][0]
        self.store.add_feedback(r["asset"], pipemod.rule_of(r), r["param"], "refuted", "人工判过")
        stats = self.store.apply_history()
        self.assertEqual(stats["marked"], 1)
        got = self.store.findings(limit=5)["rows"][0]
        self.assertEqual(got["pipe_state"], pipemod.DOWNGRADED)
        self.assertIn("历史人工判误报", got["pipe_reason"])
        self.assertEqual(int(got["id"]), fid)

    def test_apply_history_does_not_touch_verified_rows(self):
        fid = self.seed()
        r = self.store.findings(limit=5)["rows"][0]
        self.store.set_pipeline([{"id": fid, "state": "verified", "pass": 3,
                                  "layers": {}, "reason": "三层全过", "poc": ""}])
        self.store.add_feedback(r["asset"], pipemod.rule_of(r), r["param"], "refuted")
        self.assertEqual(self.store.apply_history()["marked"], 0)
        self.assertEqual(self.store.findings(limit=5)["rows"][0]["pipe_state"], "verified")

    def test_apply_history_no_feedback_is_noop(self):
        self.seed()
        self.assertEqual(self.store.apply_history(), {"marked": 0, "scanned": 0})

    def test_apply_history_since_limits_scope(self):
        """只处理这一轮扫描碰过的行：老行不该被顺手改写（大库也不该每轮全表扫）。"""
        fid = self.seed()
        r = self.store.findings(limit=5)["rows"][0]
        self.store.add_feedback(r["asset"], pipemod.rule_of(r), r["param"], "refuted")
        with self.store.lock:                      # 把这一行按到「很久以前」
            self.store.conn.execute("UPDATE findings SET last_seen='2000-01-01 00:00:00' WHERE id=?",
                                    (fid,))
            self.store.conn.commit()
        self.assertEqual(self.store.apply_history(since="2020-01-01 00:00:00")["marked"], 0)
        self.assertEqual(self.store.apply_history()["marked"], 1)      # 全库回填仍能命中


class TestRunLayers(Base):
    def test_run_layers_writes_both_projections(self):
        fid = self.seed()
        r = self.store.findings(limit=5)["rows"][0]
        out = vfy.run_layers(self.store, [dict(r)], prober=FakeProber())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["result"]["verdict"], pipemod.VERIFIED)
        got = self.store.findings(limit=5)["rows"][0]
        self.assertEqual(got["pipe_state"], "verified")
        # 存活是同一件事的另一个投影：确认过 = 仍存在
        self.assertEqual(got["verify_state"], vfy.STILL)
        self.assertIn("curl", got["pipe_poc"])

    def test_run_layers_history_downgrade(self):
        fid = self.seed()
        r = dict(self.store.findings(limit=5)["rows"][0])
        self.store.add_feedback(r["asset"], pipemod.rule_of(r), r["param"], "refuted")

        class UniformProber:                     # 全站同一张 200 —— L1 判「没差异」
            def __call__(self, req):
                return {"status": 200, "headers": {}, "body": "same", "url": req["url"], "error": ""}

        out = vfy.run_layers(self.store, [r], prober=UniformProber())
        # 三层判 refuted（与人工结论一致），落库仍是 refuted，不标降级
        self.assertEqual(out[0]["result"]["verdict"], pipemod.REFUTED)
        self.assertEqual(self.store.findings(limit=5)["rows"][0]["pipe_state"], "refuted")

    def test_run_layers_failure_is_uncertain_not_refuted(self):
        fid = self.seed()

        class Dead:
            def __call__(self, req):
                raise OSError("connection refused")

        out = vfy.run_layers(self.store, [dict(self.store.findings(limit=5)["rows"][0])], prober=Dead())
        self.assertEqual(out[0]["result"]["verdict"], pipemod.UNCERTAIN)
        got = self.store.findings(limit=5)["rows"][0]
        self.assertEqual(got["pipe_state"], "uncertain")
        self.assertEqual(got["verify_state"], vfy.UNKNOWN)


class TestCliSurface(Base):
    def test_list_shows_pipeline_column(self):
        fid = self.seed()
        self.store.set_pipeline([{"id": fid, "state": "verified", "pass": 3,
                                  "layers": {"L1": {"state": "pass"}, "L2": {"state": "pass"},
                                             "L3": {"state": "pass"}},
                                  "reason": "三层全过", "poc": ""}])
        code, out, _ = run("--db", self.db, "list")
        self.assertEqual(code, 0)
        self.assertIn("三层", out)
        self.assertIn("✓3/3", out)
        self.assertIn("全过 1", out)

    def test_list_pipeline_filter(self):
        a = self.seed()
        b = self.seed(2)
        self.store.set_pipeline([{"id": a, "state": "verified", "pass": 3, "layers": {},
                                  "reason": "x", "poc": ""},
                                 {"id": b, "state": "uncertain", "pass": 1, "layers": {},
                                  "reason": "y", "poc": ""}])
        _, out, _ = run("--db", self.db, "list", "--pipeline", "verified")
        self.assertIn("参数触发服务端错误：tpl1", out)
        self.assertNotIn("参数触发服务端错误：tpl2", out)
        _, out2, _ = run("--db", self.db, "list", "--pipeline", "unrun")
        self.assertIn("没有符合条件", out2)

    def test_list_pipeline_filter_rejects_unknown(self):
        code, _, err = run("--db", self.db, "list", "--pipeline", "半过")
        self.assertEqual(code, 2)
        self.assertIn("未知三层状态", err)

    def test_feedback_command_writes_ledger(self):
        fid = self.seed()
        code, out, _ = run("--db", self.db, "verify", str(fid), "--feedback",
                           "--verdict", "误报", "--note", "自研 WAF 拦截页")
        self.assertEqual(code, 0)
        self.assertIn("已记下人工判定", out)
        r = self.store.findings(limit=5)["rows"][0]
        self.assertEqual(r["fb_state"], pipemod.REFUTED)
        led = self.store.feedback_rows()
        self.assertEqual(len(led), 1)
        self.assertEqual(led[0]["note"], "自研 WAF 拦截页")
        _, out2, _ = run("--db", self.db, "verify", "--feedback-list")
        self.assertIn("自研 WAF 拦截页", out2)

    def test_feedback_requires_id_and_verdict(self):
        code, _, err = run("--db", self.db, "verify", "--feedback", "--verdict", "误报")
        self.assertEqual(code, 2)
        self.assertIn("--feedback", err)
        fid = self.seed()
        code, _, err = run("--db", self.db, "verify", str(fid), "--feedback", "--verdict", "也许")
        self.assertEqual(code, 2)
        self.assertIn("认不出的判定", err)

    def test_verify_help_mentions_layers(self):
        _, out, _ = run("verify", "--help")
        for word in ("L1", "L2", "L3", "--feedback", "--legacy", "--pipeline"):
            self.assertIn(word, out)

    def test_csv_export_has_pipeline_columns(self):
        fid = self.seed()
        self.store.set_pipeline([{"id": fid, "state": "verified", "pass": 3,
                                  "layers": {"L1": {"state": "pass"}, "L2": {"state": "pass"},
                                             "L3": {"state": "pass"}},
                                  "reason": "三层全过", "poc": "curl -sk 'x'"}])
        path = os.path.join(self.tmp, "o.csv")
        code, _, _ = run("--db", self.db, "list", "--csv", path)
        self.assertEqual(code, 0)
        with open(path, encoding="utf-8-sig") as fh:
            text = fh.read()
        self.assertIn("三层", text.splitlines()[0])
        self.assertIn("✓3/3", text)
        self.assertIn("curl -sk 'x'", text)


class TestFieldPayload(Base):
    def test_stored_request_without_payload_is_not_reproducible(self):
        """payload 只在字段里、端点没带：原请求打不出差异，L1 就该判不通过。

        这是「别把标题里的 payload 当成已经复现过」：复验只重放**存下来的请求**，
        存下来的请求里没有 payload，那它证明不了任何事。
        """
        class Echo:
            def __call__(self, req):
                return {"status": 200, "headers": {}, "body": "ok", "url": req["url"]}

        r = row(endpoint="http://127.0.0.1:8080/render", param="tpl", payload="{{7*7}}")
        res = pipemod.verify(r, Echo())
        self.assertEqual(res["verdict"], pipemod.REFUTED)
        self.assertEqual(res["layers"]["L1"]["state"], pipemod.FAIL)
        self.assertIn("没产生任何差异", res["layers"]["L1"]["reason"])

    def test_minimal_url_for_field_only_payload(self):
        """防御路径：真要最小化时，得把 payload 现造进 URL，而不是退化成裸地址。"""
        ctx = pipemod._Ctx(row(endpoint="http://127.0.0.1:8080/render", param="tpl",
                               payload="{{7*7}}"))
        url, body = ctx.minimal()
        self.assertIn("tpl=", url)
        self.assertIn("7%2A7", url)
        self.assertEqual(body, "")


class TestKeywordCompare(Base):
    def test_evidence_mentioned_in_l1_reason(self):
        """判据词出现在重放正文、对照里没有 —— L1 理由要把这句话说出来。"""
        class EvProber:
            def __call__(self, req):
                if "etc/passwd" in (req.get("url") or ""):
                    return {"status": 200, "headers": {}, "body": "root:x:0:0:root:/root\n", "url": req["url"]}
                return {"status": 200, "headers": {}, "body": "<html>下载中心</html>", "url": req["url"]}

        r = row(endpoint="http://127.0.0.1:8080/download?file=../../etc/passwd", param="file",
                evidence="root:x:0:0")
        res = pipemod.verify(r, EvProber())
        self.assertEqual(res["layers"]["L1"]["state"], pipemod.PASS)
        self.assertIn("root:x:0:0", res["layers"]["L1"]["reason"])
        self.assertIn("对照里没有", res["layers"]["L1"]["reason"])


class TestMigration(Base):
    def test_opens_old_db_without_pipeline_columns(self):
        """老库（v1.9.x 之前）没有 pipe_*/fb_* 列，升级后打开必须能开、能读、能写。

        最容易踩的坑：把 CREATE INDEX ... findings(pipe_state) 写进建表脚本里，
        老表上那一句会直接 no such column —— 用户升级后第一件事就是打不开库。
        """
        old = os.path.join(self.tmp, "old.db")
        import sqlite3
        con = sqlite3.connect(old)
        con.executescript("""
            CREATE TABLE findings(
                id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL,
                asset TEXT, ip TEXT, port INTEGER, endpoint TEXT, param TEXT,
                title TEXT, sev TEXT, sev_rank INTEGER, sources TEXT, evidence TEXT,
                count INTEGER DEFAULT 1, status TEXT DEFAULT '待验证',
                first_seen TEXT, last_seen TEXT, files TEXT, repro TEXT DEFAULT '',
                verify_state TEXT DEFAULT '', verify_at TEXT DEFAULT '',
                verify_times INTEGER DEFAULT 0, verify_note TEXT DEFAULT '',
                base TEXT DEFAULT '', waf_state TEXT DEFAULT '', waf TEXT DEFAULT '');
            INSERT INTO findings(key, asset, endpoint, title, sev, sev_rank, sources, count)
            VALUES('k1', '10.0.0.9', 'http://10.0.0.9/.env', '敏感路径可访问：/.env', 'high', 4, 'sweep-paths', 1);
        """)
        con.commit()
        con.close()

        st = Store(old)
        cols = {r[1] for r in st.conn.execute("PRAGMA table_info(findings)")}
        for c in ("pipe_state", "pipe_pass", "pipe_layers", "pipe_reason", "pipe_poc",
                  "pipe_at", "fb_state", "fb_at"):
            self.assertIn(c, cols)
        rows = st.findings(limit=5)["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pipe_state"], "")
        self.assertEqual(st.summary()["by_pipeline"], [])
        st.set_pipeline([{"id": rows[0]["id"], "state": "verified", "pass": 3,
                          "layers": {}, "reason": "x", "poc": ""}])
        self.assertEqual(st.findings(limit=5)["rows"][0]["pipe_state"], "verified")


class TestBodyPayload(Base):
    """payload 在表单体里（POST）也要能换位置、能量化最小化。"""

    def test_post_form_payload_round_trip(self):
        seen = []

        class FormProber:
            def __call__(self, req):
                blob = (req.get("url") or "") + "|" + (req.get("body") or "")
                seen.append((req.get("method"), req.get("url"), req.get("body")))
                if "1'" in blob or "1%27" in blob:
                    return {"status": 500, "headers": {}, "body": "SQL syntax error", "url": req["url"]}
                return {"status": 200, "headers": {}, "body": "<html>登录页</html>", "url": req["url"]}

        r = row(method="POST", endpoint="http://127.0.0.1:8080/login",
                body="csrf=t&user=1'&pass=x", param="user", payload="1'")
        res = pipemod.verify(r, FormProber())
        self.assertEqual(res["verdict"], pipemod.VERIFIED, res["reason"])
        self.assertEqual(res["layers"]["L2"]["state"], pipemod.PASS)
        # 换位置：payload 从 body 搬到查询串，原 body 里那一段必须去掉
        moved = [c for c in seen if "kara_" in (c[1] or "")]
        self.assertTrue(moved)
        self.assertNotIn("user=1", moved[0][2] or "")
        # 最小化：只留 user=1' 这一段
        self.assertEqual(res["layers"]["L3"]["state"], pipemod.PASS)
        self.assertIn("--data", res["minimal_curl"])
        self.assertIn("user=1", res["minimal_curl"])


if __name__ == "__main__":
    unittest.main()

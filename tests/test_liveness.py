# -*- coding: utf-8 -*-
"""存活维度单元测试：把「每一条命中都回答：现在还活着吗」钉在 CLI 上。

守六件事：
    1. 存活只从 verify_state 推导（唯一真相源），空结论 = 从没复验过；
    2. 「无法判定 / 不可复验」不得并进 UNVERIFIED——否则「从没复验过」变成谎话；
    3. --liveness 筛选、顶部汇总、CSV 导出同一套口径，五桶之和恒等于总数；
    4. 黑白灰为主：符号 + 文字承载状态，颜色只点单个字符；汇总用加粗/淡化，不靠红黄绿；
    5. NO_COLOR / 非 TTY 自动关色；
    6. 中文宽字符 + ANSI 不破坏对齐（逐行显示宽度一致）。

不触网：CLI 用 --db 隔离库；复验链路用 tests.test_verify 的假引擎。
"""

import contextlib
import csv as csvmod
import io
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

from vc import cli
from vc import verify as vfy
from vc.store import Store
from tests.test_verify import make_engine

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# 一条一态的混合存量：标题即身份，方便断言谁在谁不在
MIXED = [
    ("存活漏洞", "high", "仍存在"),
    ("已死漏洞", "medium", "已消失"),
    ("未复验漏洞", "high", None),
    ("没结论漏洞", "low", "无法判定"),
    ("离线漏洞", "info", "不可复验"),
]


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def seed(db, specs):
    """specs: [(title, sev, verify_state 或 None)]；None = 从没复验过。返回 title→id。"""
    s = Store(db)
    s.add_findings([{
        "title": t, "sev": sev, "asset": "127.0.0.1", "port": 8080,
        "endpoint": "/.env", "source": "sweep-paths", "evidence": "HTTP 200",
        "base": "http://127.0.0.1:8080",
    } for t, sev, _ in specs], "seed.json")
    ids = {r["title"]: int(r["id"]) for r in s.findings(limit=100)["rows"]}
    for t, _, st in specs:
        if st is not None:
            s.set_verify([(ids[t], st, "测试写回")])
    return ids


class TestLivenessDerivation(unittest.TestCase):
    def test_mapping_all_states(self):
        for token, state in vfy.LIVENESS_STATES.items():
            self.assertEqual(vfy.liveness_of({"verify_state": state}), token)

    def test_empty_missing_unknown_are_unverified(self):
        for row in ({}, {"verify_state": None}, {"verify_state": "  "},
                    {"verify_state": "外星结论"}):
            self.assertEqual(vfy.liveness_of(row), "UNVERIFIED")

    def test_sqlite_row_supported(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE t(verify_state TEXT)")
        conn.execute("INSERT INTO t VALUES ('仍存在')")
        row = conn.execute("SELECT * FROM t").fetchone()
        self.assertEqual(vfy.liveness_of(row), "ALIVE")
        # 连列都没有（老库迁移前的行）也不能炸
        row2 = conn.execute("SELECT 1 AS x").fetchone()
        self.assertEqual(vfy.liveness_of(row2), "UNVERIFIED")
        conn.close()

    def test_summary_sums_to_total(self):
        counts = vfy.liveness_summary([
            {"verify_state": "仍存在", "n": 3},
            {"verify_state": "", "n": 5},
            {"verify_state": "已消失", "n": 2},
        ])
        self.assertEqual(counts, {"ALIVE": 3, "DEAD": 2, "UNVERIFIED": 5,
                                  "UNKNOWN": 0, "NA": 0})
        self.assertEqual(sum(counts.values()), 10)
        self.assertEqual(sum(vfy.liveness_summary([]).values()), 0)

    def test_symbols_cover_tokens_and_are_single_char(self):
        self.assertEqual(set(vfy.LIVENESS_SYMBOLS), set(vfy.LIVENESS_TOKENS))
        for sym in vfy.LIVENESS_SYMBOLS.values():
            self.assertEqual(len(sym), 1)


class TestStoreFilter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kara-live-")
        self.db = os.path.join(self.tmp, "t.db")
        self.ids = seed(self.db, MIXED)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_each_token_filters_exactly(self):
        want = {"alive": "存活漏洞", "dead": "已死漏洞", "unverified": "未复验漏洞",
                "unknown": "没结论漏洞", "na": "离线漏洞"}
        for token, title in want.items():
            data = Store(self.db).findings(liveness=token)
            self.assertEqual(data["total"], 1, token)
            self.assertEqual([r["title"] for r in data["rows"]], [title])

    def test_unverified_excludes_inconclusive_and_na(self):
        # 诚实性底线：复验过但没结论 / 没有目标，都不是「从没复验过」
        rows = Store(self.db).findings(liveness="unverified")["rows"]
        titles = [r["title"] for r in rows]
        self.assertEqual(titles, ["未复验漏洞"])

    def test_null_state_counts_as_unverified(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("UPDATE findings SET verify_state=NULL WHERE id=?",
                         (self.ids["已死漏洞"],))
        rows = Store(self.db).findings(liveness="unverified")["rows"]
        self.assertEqual({r["title"] for r in rows}, {"未复验漏洞", "已死漏洞"})

    def test_combines_with_sev(self):
        s = Store(self.db)
        self.assertEqual([r["title"] for r in s.findings(sev="high", liveness="unverified")["rows"]],
                         ["未复验漏洞"])
        self.assertEqual([r["title"] for r in s.findings(sev="high", liveness="alive")["rows"]],
                         ["存活漏洞"])

    def test_invalid_token_raises(self):
        with self.assertRaises(ValueError):
            Store(self.db).findings(liveness="zombie")


class TestListCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kara-live-")
        self.db = os.path.join(self.tmp, "t.db")
        self.ids = seed(self.db, MIXED)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_column_and_symbols(self):
        code, out, _ = run("--db", self.db, "list")
        self.assertEqual(code, 0)
        self.assertIn("存活", out)
        for token in vfy.LIVENESS_TOKENS:
            self.assertIn(f"{vfy.LIVENESS_SYMBOLS[token]} {token}", out)

    def test_summary_is_global_inventory(self):
        code, out, _ = run("--db", self.db, "list", "--sev", "high")
        self.assertEqual(code, 0)
        self.assertIn("存量", out)
        self.assertIn("未复验 1", out)      # 全库口径，不随 --sev 变
        self.assertIn("共 2 条", out)       # 筛选后的条数看底部

    def test_filter_unverified(self):
        code, out, _ = run("--db", self.db, "list", "--liveness", "unverified")
        self.assertEqual(code, 0)
        self.assertIn("未复验漏洞", out)
        for gone in ("存活漏洞", "已死漏洞", "没结论漏洞", "离线漏洞"):
            self.assertNotIn(gone, out)
        self.assertIn("共 1 条", out)
        self.assertIn("kara verify --liveness unverified", out)

    def test_filter_case_insensitive(self):
        code, out, _ = run("--db", self.db, "list", "--liveness", "ALIVE")
        self.assertEqual(code, 0)
        self.assertIn("存活漏洞", out)
        self.assertIn("共 1 条", out)

    def test_invalid_exits_2(self):
        code, _, err = run("--db", self.db, "list", "--liveness", "zombie")
        self.assertEqual(code, 2)
        self.assertIn("未知存活状态", err)
        self.assertIn("unverified", err)

    def test_empty_match_keeps_summary(self):
        code, out, _ = run("--db", self.db, "list", "--sev", "info", "--liveness", "alive")
        self.assertEqual(code, 0)
        self.assertIn("没有符合条件", out)
        self.assertIn("存量", out)

    def test_detail_shows_symbol_and_token(self):
        code, out, _ = run("--db", self.db, "list", "-i", str(self.ids["存活漏洞"]))
        self.assertEqual(code, 0)
        self.assertIn("● ALIVE", out)
        self.assertIn("仍存在", out)

    def test_status_page_liveness(self):
        code, out, _ = run("--db", self.db)
        self.assertEqual(code, 0)
        self.assertIn("存活", out)
        self.assertIn("未复验 1", out)


class TestOutputHygiene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kara-live-")
        self.db = os.path.join(self.tmp, "t.db")
        seed(self.db, MIXED)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _table_lines(self, out):
        lines = out.splitlines()
        plain = [ANSI.sub("", l) for l in lines]
        idx = next(i for i, l in enumerate(plain) if l.startswith("ID "))
        return lines[idx:idx + 2 + len(MIXED)]   # 表头 + 分隔线 + 5 行

    def test_no_ansi_when_not_tty(self):
        _, out, _ = run("--db", self.db, "list")
        self.assertNotIn("\x1b", out)

    def test_no_color_env_disables_tty_color(self):
        with mock.patch.object(sys.stdout, "isatty", return_value=True):
            with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
                self.assertFalse(cli._tty())

    def test_tty_without_no_color_enables(self):
        had = os.environ.pop("NO_COLOR", None)
        try:
            with mock.patch.object(sys.stdout, "isatty", return_value=True):
                self.assertTrue(cli._tty())
        finally:
            if had is not None:
                os.environ["NO_COLOR"] = had

    def test_color_only_on_symbols_when_tty(self):
        with mock.patch.object(cli, "_tty", return_value=True):
            _, out, _ = run("--db", self.db, "list")
        # 色只点单个字符的符号，状态词本身不着色
        self.assertIn("\x1b[31m●\x1b[0m ALIVE", out)
        self.assertIn("\x1b[33m—\x1b[0m UNVERIFIED", out)
        self.assertNotIn("\x1b[31mALIVE", out)     # 旧式整词染色必须消失
        # 汇总：非零数字加粗、零桶淡化，没有红黄绿
        self.assertIn("\x1b[1m1\x1b[0m", out)
        self.assertIn("\x1b[90m", out)
        self.assertIsNone(re.search(r"\x1b\[(3[123]|90)m(存活|已死|未复验)", out))
        # 任何背景色块都不允许
        self.assertIsNone(re.search(r"\x1b\[(4[0-7]|10[0-7])m", out))

    def test_alignment_non_tty(self):
        _, out, _ = run("--db", self.db, "list")
        widths = {cli._w(l) for l in self._table_lines(out)}
        self.assertEqual(widths, {153})   # 5+8+12+36+24+28+12+4+8 + 8×2 间隔

    def test_alignment_tty(self):
        with mock.patch.object(cli, "_tty", return_value=True):
            _, out, _ = run("--db", self.db, "list")
        widths = {cli._w(l) for l in self._table_lines(out)}
        self.assertEqual(widths, {153})

    def test_cjk_titles_align(self):
        db = os.path.join(self.tmp, "cjk.db")
        seed(db, [("短", "high", None),
                  ("中等长度中文标题", "medium", None),
                  ("这是一个超过三十六列宽度的很长很长的中文漏洞标题需要被截断", "low", None),
                  ("mix混合English标题", "info", None)])
        _, out, _ = run("--db", db, "list")
        lines = out.splitlines()
        idx = next(i for i, l in enumerate(lines) if l.startswith("ID "))
        widths = {cli._w(l) for l in lines[idx:idx + 2 + 4]}
        self.assertEqual(len(widths), 1)


class TestVerifyAndExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kara-live-")
        self.db = os.path.join(self.tmp, "t.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_verify_liveness_picks_only_unverified(self):
        # 标题与假引擎产物一致才能对上命中（去重键含标题）；甲已是 ALIVE，应被排除
        ids = seed(self.db, [("甲漏洞", "high", "仍存在"),
                             ("敏感路径可访问：/.env", "high", None)])
        engine = make_engine(self.tmp)
        os.environ["FAKE_SCENARIO"] = "alive"
        try:
            code, out, err = run("--db", self.db, "--engine", engine,
                                 "verify", "--liveness", "unverified")
        finally:
            os.environ.pop("FAKE_SCENARIO", None)
        self.assertEqual(code, 0, err)
        self.assertIn("复验 1 条", out)
        rows = {r["title"]: r for r in Store(self.db).findings(limit=10)["rows"]}
        self.assertEqual(rows["敏感路径可访问：/.env"]["verify_state"], "仍存在")
        self.assertEqual(rows["敏感路径可访问：/.env"]["verify_times"], 1)
        # 甲已是 ALIVE，不该被这批碰到（次数不涨）
        self.assertEqual(rows["甲漏洞"]["verify_times"], 1)

    def test_verify_liveness_no_match(self):
        seed(self.db, [("甲漏洞", "high", "仍存在")])
        code, out, _ = run("--db", self.db, "verify", "--liveness", "dead")
        self.assertEqual(code, 0)
        self.assertIn("没有要复验的条目", out)

    def test_verify_invalid_liveness(self):
        code, _, err = run("--db", self.db, "verify", "--liveness", "zombie")
        self.assertEqual(code, 2)
        self.assertIn("未知存活状态", err)

    def test_csv_column_and_filter(self):
        seed(self.db, MIXED)
        out_csv = os.path.join(self.tmp, "o.csv")
        code, _, _ = run("--db", self.db, "list", "--liveness", "alive", "--csv", out_csv)
        self.assertEqual(code, 0)
        with open(out_csv, "rb") as fh:
            raw = fh.read()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))   # BOM 还在
        rows = list(csvmod.reader(io.StringIO(raw.decode("utf-8-sig"))))
        header = rows[0]
        self.assertIn("存活", header)
        col = header.index("存活")
        self.assertEqual(len(rows), 2)                     # 表头 + 1 条
        self.assertEqual(rows[1][col], "ALIVE")
        self.assertIn("存活漏洞", rows[1])
        self.assertNotIn("已死漏洞", raw.decode("utf-8-sig"))

    def test_md_summary_line(self):
        seed(self.db, MIXED)
        md = Store(self.db).export_md()
        self.assertIn("存活：", md)
        self.assertIn("未复验 1", md)

    def test_cli_md_filter(self):
        seed(self.db, MIXED)
        out_md = os.path.join(self.tmp, "o.md")
        code, _, _ = run("--db", self.db, "list", "--liveness", "alive", "--md", out_md)
        self.assertEqual(code, 0)
        with open(out_md, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("存活漏洞", text)
        self.assertNotIn("已死漏洞", text)


if __name__ == "__main__":
    unittest.main()

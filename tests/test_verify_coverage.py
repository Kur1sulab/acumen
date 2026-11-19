"""复验覆盖扩展的单测：strike / brute / cve / sslchain 四类原生判定也能复验。

缺口背景：1.9.0 的 SOURCE_MODE 只认 6 个来源标签，strike（深度验证）、brute（弱口令）、
cve（离线 CVE）、sslchain（TLS 证书链）跑出来的命中全被标成「不可复验」——
理由还写错了（「不是本机引擎产物」）。这些恰恰是产出漏洞判定的模式。

这里沿用 test_verify.py 的假引擎路子，重点盯两条底线：
  ① 同模式重跑、同判据比对：还在 = 仍存在，真测完了且没了 = 已消失；
  ② 连不上 / 没测成 ≠ 已消失：strike 0 开放端口或全 skip、brute 全 skipped、
     cve 指纹为空或引擎退出码非 0 —— 一律「无法判定」。
"""

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

# 假引擎：第一个参数是模式，FAKE_SCENARIO 决定写哪种产物。
# 产物形状与真引擎一致（strike=findings+coverage，brute=握手记录数组，
# cve=target+products+matches，baseline=单检查 dict）。
FAKE_ENGINE = r"""#!/bin/sh
MODE="$1"
SC="${FAKE_SCENARIO:-still}"
DIR="out/fake_$MODE"
mkdir -p "$DIR"
case "$MODE:$SC" in
  strike:still)
    cat > "$DIR/findings.json" <<'EOF'
{"findings":[{"check":"redis-unauth","name":"Redis 未授权访问","severity":"critical",
  "level":"L2","confidence":"confirmed","target":"127.0.0.1:16379","host":"127.0.0.1",
  "port":16379,"evidence":"+PONG","repro":"redis-cli -h 127.0.0.1 -p 16379 ping"}],
 "coverage":[{"item":"port-scan","state":"ok","count":1},
             {"item":"authprobe:redis@16379","state":"ok","count":1}]}
EOF
    ;;
  strike:gone)
    cat > "$DIR/findings.json" <<'EOF'
{"findings":[],
 "coverage":[{"item":"port-scan","state":"ok","count":1},
             {"item":"webcheck:env@18080","state":"ok","count":0}]}
EOF
    ;;
  strike:dead)
    cat > "$DIR/findings.json" <<'EOF'
{"findings":[],"coverage":[{"item":"port-scan","state":"ok","count":0}]}
EOF
    ;;
  strike:allskip)
    cat > "$DIR/findings.json" <<'EOF'
{"findings":[],"coverage":[{"item":"scope","state":"skip","reason":"公网目标未放行"}]}
EOF
    ;;
  brute:still)
    cat > "$DIR/brute.json" <<'EOF'
[{"host":"127.0.0.1","port":16379,"service":"redis","tried":1,
  "found":[{"user":"root","pass":"123456","note":"AUTH ok"}]}]
EOF
    ;;
  brute:gone)
    cat > "$DIR/brute.json" <<'EOF'
[{"host":"127.0.0.1","port":16379,"service":"redis","tried":20,"found":[]}]
EOF
    ;;
  brute:dead)
    cat > "$DIR/brute.json" <<'EOF'
[{"host":"127.0.0.1","port":16379,"service":"redis","tried":1,"found":[],
  "skipped":"协议错误：dial tcp 127.0.0.1:16379: connect: connection refused"}]
EOF
    ;;
  brute:locked)
    cat > "$DIR/brute.json" <<'EOF'
[{"host":"127.0.0.1","port":16379,"service":"redis","tried":3,"found":[],
  "skipped":"服务提示尝试过多/账号锁定，已停止"}]
EOF
    ;;
  cve:still)
    cat > "$DIR/cve.json" <<'EOF'
{"target":"http://127.0.0.1:18080/",
 "products":[{"product":"apache","version":"2.4.49","evidence":"Server: Apache/2.4.49"}],
 "matches":[{"id":"CVE-2021-41773","title":"Apache 路径穿越","product":"apache",
   "version":"2.4.49","severity":"high","verify":"curl --path-as-is http://TARGET/cgi-bin/.%2e/%2e%2e/etc/passwd"}]}
EOF
    ;;
  cve:gone)
    cat > "$DIR/cve.json" <<'EOF'
{"target":"http://127.0.0.1:18080/",
 "products":[{"product":"apache","version":"2.4.52","evidence":"Server: Apache/2.4.52"}],
 "matches":[]}
EOF
    ;;
  cve:empty)
    cat > "$DIR/cve.json" <<'EOF'
{"target":"http://127.0.0.1:18080/","products":[],"matches":[]}
EOF
    ;;
  cve:exit1)
    echo "[!] cve: 目标不可达: dial tcp: connection refused" >&2
    exit 1
    ;;
  baseline:still)
    cat > "$DIR/sslchain.json" <<'EOF'
{"check":"sslchain","target":"127.0.0.1",
 "conclusion":{"level":"fail","text":"1 个端口，风险 1 条"},
 "risks":[{"level":"fail","title":"证书已过期 5 天（端口 443）","detail":"NotAfter 2026-11-14"}]}
EOF
    ;;
  baseline:gone)
    cat > "$DIR/sslchain.json" <<'EOF'
{"check":"sslchain","target":"127.0.0.1",
 "conclusion":{"level":"ok","text":"1 个端口，风险 0 条"},"risks":[]}
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


def strike_row(**kw):
    base = {"id": 1, "sources": "sweep-strike:redis-unauth", "asset": "127.0.0.1",
            "endpoint": "127.0.0.1:16379", "title": "Redis 未授权访问", "base": ""}
    base.update(kw)
    return base


def brute_row(**kw):
    base = {"id": 2, "sources": "sweep-brute:redis", "asset": "127.0.0.1", "port": 16379,
            "endpoint": "redis://127.0.0.1:16379", "title": "弱口令：redis root/123456", "base": ""}
    base.update(kw)
    return base


def cve_row(**kw):
    base = {"id": 3, "sources": "sweep-cve:CVE-2021-41773", "asset": "127.0.0.1", "port": 18080,
            "endpoint": "http://127.0.0.1:18080/", "base": "",
            "title": "CVE-2021-41773 可能受影响：Apache 路径穿越"}
    base.update(kw)
    return base


def ssl_row(**kw):
    base = {"id": 4, "sources": "sweep-sslchain", "asset": "127.0.0.1",
            "endpoint": "127.0.0.1", "base": "",
            "title": "sslchain：证书已过期 5 天（端口 443）"}
    base.update(kw)
    return base


class TestBareHostport(unittest.TestCase):
    def test_valid_shapes(self):
        self.assertEqual(vfy.bare_hostport("127.0.0.1:6379"), "127.0.0.1:6379")
        self.assertEqual(vfy.bare_hostport("[::1]:6379"), "[::1]:6379")
        self.assertEqual(vfy.bare_hostport(" 10.0.0.5:8080 "), "10.0.0.5:8080")

    def test_invalid_shapes(self):
        for ep in ("", "/.env", "http://h:80/x", "redis://h:6379", "h", "h:0", "h:99999", "h:abc"):
            self.assertEqual(vfy.bare_hostport(ep), "", ep)

    def test_base_url_keeps_service_port(self):
        # strike 服务级命中：端口是判据的一部分，不许裁掉再猜
        self.assertEqual(vfy.base_url(strike_row()), "127.0.0.1:16379")
        self.assertEqual(vfy.base_url(strike_row(endpoint="http://127.0.0.1:18080/x")),
                         "http://127.0.0.1:18080")


class TestPlanCoverage(unittest.TestCase):
    def test_strike_service_and_web(self):
        p = vfy.plan_of(strike_row())
        assert p is not None
        self.assertEqual(p["mode"], "strike")
        self.assertEqual(p["argv"], ["strike", "-t", "127.0.0.1:16379"])
        p = vfy.plan_of(strike_row(endpoint="http://127.0.0.1:18080/actuator/env"))
        assert p is not None
        self.assertEqual(p["argv"], ["strike", "-t", "http://127.0.0.1:18080"])

    def test_brute_carries_port_and_service(self):
        p = vfy.plan_of(brute_row())
        assert p is not None
        self.assertEqual(p["mode"], "brute")
        self.assertEqual(p["argv"], ["brute", "-t", "127.0.0.1", "-p", "16379", "--service", "redis"])

    def test_cve_keeps_original_url_path(self):
        p = vfy.plan_of(cve_row(endpoint="http://127.0.0.1:18080/app/"))
        assert p is not None
        self.assertEqual(p["argv"], ["cve", "-u", "http://127.0.0.1:18080/app/"])

    def test_sslchain_is_baseline_check(self):
        p = vfy.plan_of(ssl_row())
        assert p is not None
        self.assertEqual(p["mode"], "baseline")
        self.assertEqual(p["check"], "sslchain")
        self.assertIn("--checks", p["argv"])
        self.assertIn("sslchain", p["argv"])

    def test_foreign_sources_still_na(self):
        for src in ("nuclei", "nessus", "audit-md", "xray", ""):
            self.assertIsNone(vfy.plan_of(strike_row(sources=src)), src)

    def test_enrich_marks_native_rows_verifiable(self):
        rows = [strike_row(), brute_row(), cve_row(), ssl_row()]
        vfy.enrich(rows)
        for r in rows:
            self.assertTrue(r["verifiable"], r["sources"])
        # sslchain 没有可 GET 的端点，复现命令给建链命令
        self.assertIn("openssl s_client", rows[3]["repro"])


class TestReachCoverage(unittest.TestCase):
    def test_strike_needs_open_port_and_finished_check(self):
        ok = {"findings": [], "coverage": [
            {"item": "port-scan", "state": "ok", "count": 2},
            {"item": "webcheck:env@18080", "state": "ok", "count": 0}]}
        self.assertTrue(vfy._reach(ok))
        dead = {"findings": [], "coverage": [{"item": "port-scan", "state": "ok", "count": 0}]}
        self.assertFalse(vfy._reach(dead))          # 主机挂了还是服务全停？分不清 → 不作数
        skip = {"findings": [], "coverage": [{"item": "scope", "state": "skip", "reason": "x"}]}
        self.assertFalse(vfy._reach(skip))
        hung = {"findings": [], "coverage": [
            {"item": "port-scan", "state": "ok", "count": 1},
            {"item": "authprobe:redis@16379", "state": "skip", "reason": "超时"}]}
        self.assertFalse(vfy._reach(hung))          # 端口开着但检查没跑完 → 也不作数
        self.assertFalse(vfy._reach({"findings": [], "coverage": []}))

    def test_cve_needs_fingerprinted_product(self):
        self.assertTrue(vfy._reach({"products": [{"product": "apache"}], "matches": []}))
        self.assertFalse(vfy._reach({"products": [], "matches": []}))

    def test_brute_skipped_is_not_gone(self):
        self.assertTrue(vfy._reach_brute([{"found": [{"user": "a"}], "tried": 1}]))
        self.assertTrue(vfy._reach_brute([{"found": [], "tried": 20}]))      # 真试完了
        self.assertFalse(vfy._reach_brute([{"found": [], "tried": 1, "skipped": "协议错误：x"}]))
        self.assertFalse(vfy._reach_brute([{"found": [], "tried": 3, "skipped": "账号锁定"}]))
        self.assertIsNone(vfy._reach_brute([]))


class TestVerifyRunCoverage(unittest.TestCase):
    """假引擎端到端：四类命中 × 还在/没了/连不上。"""

    ROWS = [strike_row(), brute_row(), cve_row(), ssl_row()]

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vc-vfy-cov-")
        self.engine = make_engine(self.tmp)
        self.store = Store(os.path.join(self.tmp, "t.db"))
        docs = []
        for r in self.ROWS:
            d = dict(r)
            d["sev"] = "high"
            d["source"] = d.pop("sources")
            d["evidence"] = "单测夹具"
            docs.append(d)
        self.store.add_findings(docs, "fixture.json")
        self.rows = self.store.findings(limit=50)["rows"]
        self.by_src = {r["sources"]: int(r["id"]) for r in self.rows}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, scenario: str, src: str):
        os.environ["FAKE_SCENARIO"] = scenario
        try:
            v = vfy.Verifier(self.store, engine=self.engine, timeout=60)
            r = v.start([self.by_src[src]])
            self.assertTrue(r["ok"], r)
            for _ in range(600):
                if not v.status()["running"]:
                    break
                time.sleep(0.05)
            st = v.status()
            row = [x for x in self.store.findings(limit=50)["rows"]
                   if x["sources"] == src][0]
            return st, row
        finally:
            os.environ.pop("FAKE_SCENARIO", None)

    def _state(self, scenario, src):
        st, row = self._run(scenario, src)
        self.assertEqual(st["summary"].get(row["verify_state"]), 1, st["summary"])
        return row["verify_state"], row["verify_note"]

    # ---------------- strike ----------------
    def test_strike_still(self):
        state, note = self._state("still", "sweep-strike:redis-unauth")
        self.assertEqual(state, "仍存在")
        self.assertIn("重跑命中", note)

    def test_strike_gone(self):
        state, _ = self._state("gone", "sweep-strike:redis-unauth")
        self.assertEqual(state, "已消失")

    def test_strike_dead_host_is_never_gone(self):
        state, note = self._state("dead", "sweep-strike:redis-unauth")
        self.assertEqual(state, "无法判定")
        self.assertIn("不作数", note)

    def test_strike_all_skip_is_never_gone(self):
        state, _ = self._state("allskip", "sweep-strike:redis-unauth")
        self.assertEqual(state, "无法判定")

    # ---------------- brute ----------------
    def test_brute_still(self):
        state, _ = self._state("still", "sweep-brute:redis")
        self.assertEqual(state, "仍存在")

    def test_brute_gone_after_full_attempts(self):
        state, _ = self._state("gone", "sweep-brute:redis")
        self.assertEqual(state, "已消失")

    def test_brute_dial_failure_is_never_gone(self):
        state, note = self._state("dead", "sweep-brute:redis")
        self.assertEqual(state, "无法判定")
        self.assertIn("不作数", note)

    def test_brute_lockout_is_never_gone(self):
        state, _ = self._state("locked", "sweep-brute:redis")
        self.assertEqual(state, "无法判定")

    # ---------------- cve ----------------
    def test_cve_still(self):
        state, _ = self._state("still", "sweep-cve:CVE-2021-41773")
        self.assertEqual(state, "仍存在")

    def test_cve_gone_after_version_upgrade(self):
        state, _ = self._state("gone", "sweep-cve:CVE-2021-41773")
        self.assertEqual(state, "已消失")

    def test_cve_empty_fingerprint_is_never_gone(self):
        state, _ = self._state("empty", "sweep-cve:CVE-2021-41773")
        self.assertEqual(state, "无法判定")

    def test_cve_unreachable_exit1_is_never_gone(self):
        state, note = self._state("exit1", "sweep-cve:CVE-2021-41773")
        self.assertEqual(state, "无法判定")
        self.assertIn("退出码", note)

    # ---------------- sslchain ----------------
    def test_sslchain_still(self):
        state, _ = self._state("still", "sweep-sslchain")
        self.assertEqual(state, "仍存在")

    def test_sslchain_gone(self):
        state, _ = self._state("gone", "sweep-sslchain")
        self.assertEqual(state, "已消失")


class TestDeepTargetOf(unittest.TestCase):
    def test_service_endpoint_keeps_port(self):
        from vc.cli import _target_of
        self.assertEqual(_target_of(strike_row()), "127.0.0.1:16379")
        self.assertEqual(_target_of(strike_row(endpoint="http://127.0.0.1:18080/x")),
                         "http://127.0.0.1:18080")


if __name__ == "__main__":
    unittest.main()
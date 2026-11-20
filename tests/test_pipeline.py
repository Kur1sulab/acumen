"""三层复验流水线的端到端测试：真 HTTP 靶子 + 真 prober。

为什么不用 mock
    vc/verify.py 那一层只会「重跑引擎看同标题还在不在」，它读不到响应体，
    所以「真命中」「全站 500」「WAF 拦截页」「布尔差异不成立」在它眼里长得
    一模一样。三层流水线的全部价值就是「看得见响应」——把 HTTP 层 mock 掉，
    测的就不是这件事了。所以这里用 stdlib 起真服务，prober 用 http.client
    真建连（tests/ 不在 tools/check_offline.py 的检查范围，vc/ 里仍然不许出站）。

契约（vc/pipeline.py 按这个写，测试按这个断言）
    入口      verify(row, prober) -> dict
    row       命中行（store.findings 的字典），用到这些键：
                id / title / sources / status（人工状态：待验证/已确认/误报/…）
                base（http://host:port）/ method / endpoint（带 payload 的原始路径）
                param（承载 payload 的参数名）/ payload（注入串）
                evidence（证明命中的正文子串，可空）
              payload 一律同时是 endpoint 的字面子串——实现是从 endpoint 里
              抠 payload 还是直接读 row["payload"]，两条路都走得通。
    prober    prober(req) -> resp
                req  = {"method", "url", "headers", "body"}
                resp = {"status", "headers", "body", "url", "error"}
                status=0 表示没拿到响应（连不上/超时）
    返回      {"verdict": "verified" | "refuted" | "uncertain",
               "reason": 人话，必须带层标签（L1/L2/L3）,
               "layers": {"L1": {"state": ..., "reason": ...}, "L2": ..., "L3": ...},
               "minimal_curl": L3 通过时的最小复现串}
    层状态    pass | fail | unstable | blocked | skip | error

判定口径（测试逐条钉死）
    任一层 fail → refuted；适用层全 pass → verified；其余 → uncertain。
    blocked 不是 fail：被 WAF 拦住时拿到的响应证明不了任何事，只能 uncertain。
    历史人工判「误报」压过三层结论：三层全过也只给 uncertain。

端口一律用 0 让内核分配，测试之间不抢端口，也不会撞上本机在跑的服务。
"""

from __future__ import annotations

import copy
import http.client
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from vc import pipeline
except Exception as exc:                      # 实现没落地时，夹具自检仍要能跑
    pipeline = None
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
else:
    _IMPORT_ERROR = ""

STATES = {"pass", "fail", "unstable", "blocked", "skip", "error"}

# —— 固定 payload：都是 URL 里不用转义就能原样出现的字符，省掉「编码方式
#    不同导致实现找不到子串」这类与语义无关的翻车。
TPL = "{{7*7}}"                               # 模板表达式：非 SQLi，走不到布尔对照
TRAV = "../../../../etc/passwd"
XSS = "alert(1)//"
BOOL = "1'AND(1=1)--"

PASSWD = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
TPL_ERROR = "Template render failed: ZeroDivisionError at line 42"
CF_PAGE = ("<html><head><title>Attention Required! | Cloudflare</title></head>"
           "<body><h1>Sorry, you have been blocked</h1>"
           "<p>Cloudflare Ray ID: 8a1b2c3d4e5f-SJC</p></body></html>")


# ────────────────────────────────────────────────────────────── 靶子

def _resp(status: int, body: str = "", headers=None):
    return status, dict(headers or {}), body


def _values(qs, form):
    """query 与 form 里的所有值摊平——payload 放 URL 还是放 body 都认。"""
    out = []
    for src in (qs, form):
        for vs in (src or {}).values():
            out.extend(vs)
    return out


def _norm(v: str) -> str:
    """去引号、去空白、转小写：布尔探针的写法五花八门，归一后再认。"""
    return v.replace("'", "").replace('"', "").replace(" ", "").lower()


def route_tpl_500(qs, form, headers):
    """payload 触发 500，无害值 200 —— 「payload 打出了服务端错误」的形状。"""
    if any(TPL in v for v in _values(qs, form)):
        return _resp(500, TPL_ERROR)
    return _resp(200, "<html>渲染成功</html>")


def route_passwd(qs, form, headers):
    """payload 读到敏感文件 —— 「返回敏感内容」的形状。"""
    if any("etc/passwd" in v for v in _values(qs, form)):
        return _resp(200, PASSWD, {"Content-Type": "text/plain"})
    return _resp(200, "<html>下载中心</html>")


def route_sitewide_500(qs, form, headers):
    """全站 500：不管打哪个参数、哪条路径，都是同一张错误页。"""
    return _resp(500, "<html><body><h1>Internal Server Error</h1></body></html>")


def route_static(qs, form, headers):
    """全站同形 200：payload 打进去跟没打一样。"""
    return _resp(200, "<html><body>静态页</body></html>")


def route_waf(qs, form, headers):
    """payload 被 WAF 拦（403 + Cloudflare 拦截页），无害值正常放行。"""
    if any(XSS in v for v in _values(qs, form)):
        return _resp(403, CF_PAGE, {"cf-ray": "8a1b2c3d4e5f-SJC"})
    return _resp(200, "<html>搜索结果</html>")


def route_waf_all(qs, form, headers):
    """连对照都拦：全站 403 拦截页。这时 orig 与 ctl 完全一致，但那是「被拦」。"""
    return _resp(403, CF_PAGE, {"cf-ray": "8a1b2c3d4e5f-SJC"})


BOOL_PAGE = "<html><body>结果页：共 3 条记录</body></html>"


def route_bool_same(qs, form, headers):
    """1=1 与 1=2 返回同一张页面 —— 布尔差异不成立，注入是假的。"""
    for v in _values(qs, form):
        n = _norm(v)
        if "1=1" in n or "1=2" in n:
            return _resp(200, BOOL_PAGE)
    return _resp(200, "<html><body>列表页</body></html>")


def route_needs_debug(qs, form, headers):
    """现象要两个参数同时在场：payload + debug=1。最小化剥掉 debug 就没了。"""
    vals = _values(qs, form)
    has_payload = any(TPL in v for v in vals)
    has_debug = any(v.strip() == "1" for v in (qs.get("debug") or []) + (form.get("debug") or []))
    if has_payload and has_debug:
        return _resp(500, TPL_ERROR)
    return _resp(200, "<html>渲染成功</html>")


class _Handler(BaseHTTPRequestHandler):
    """真 HTTP 服务：按路由表回包，顺手记下每一次请求。"""

    server_version = "kara-target/1.0"

    def do_GET(self):
        self._serve("GET")

    def do_POST(self):
        self._serve("POST")

    def log_message(self, fmt, *args):        # 测试输出里不要一堆 access log
        pass

    def _serve(self, method):
        parts = urlsplit(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        form = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
        qs = parse_qs(parts.query, keep_blank_values=True)
        tgt = self.server.target
        tgt.hits.append({"method": method, "path": parts.path, "query": parts.query,
                         "qs": qs, "form": form})
        fn = tgt.routes.get(parts.path) or tgt.fallback
        status, headers, body = fn(qs, form, self.headers)
        data = body.encode("utf-8")
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Target:
    """回环靶子：127.0.0.1 + 内核分配端口，一条路由一个行为。"""

    def __init__(self):
        self.routes = {}
        self.hits = []
        self.fallback = route_static
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.target = self
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        kwargs={"poll_interval": 0.02},
                                        name="kara-target", daemon=True)
        self._thread.start()

    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def route(self, path: str, fn):
        self.routes[path] = fn
        return fn

    def paths_hit(self):
        return [h["path"] for h in self.hits]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=2)


# ────────────────────────────────────────────────────────── prober

class HttpProber:
    """测试侧的真 prober：http.client 直连回环靶子，不 mock 任何一层。"""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.calls = []

    def __call__(self, req):
        method = str(req.get("method") or "GET").upper()
        url = str(req.get("url") or "")
        parts = urlsplit(url)
        path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        body = req.get("body")
        headers = dict(req.get("headers") or {})
        data = None
        if body not in (None, ""):
            data = body.encode("utf-8") if isinstance(body, str) else body
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        self.calls.append({"method": method, "url": url, "body": body})
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=self.timeout)
        try:
            conn.request(method, path, body=data, headers=headers)
            r = conn.getresponse()
            text = r.read().decode("utf-8", "replace")
            return {"status": r.status,
                    "headers": {k.lower(): v for k, v in r.getheaders()},
                    "body": text, "url": url, "error": ""}
        except OSError as exc:
            return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(exc)}
        finally:
            conn.close()


class FakeProber:
    """纯逻辑用例的假 prober：不建连接，按请求内容回包。"""

    def __init__(self, fn):
        self.fn = fn
        self.calls = []

    def __call__(self, req):
        self.calls.append(req)
        return self.fn(req, len(self.calls))


def carries(req, needle: str) -> bool:
    """payload 在 URL 还是 body 里都算——顺便解一层百分号编码。"""
    blob = unquote(str(req.get("url") or "")) + " " + unquote(str(req.get("body") or ""))
    return needle in blob


# ───────────────────────────────────────────────────── 结果读取

def verdict_of(res) -> str:
    return str(res.get("verdict") or "").strip().lower()


def layer_of(res, name: str):
    layers = res.get("layers") or {}
    if isinstance(layers, dict):
        item = layers.get(name) or layers.get(name.lower()) or {}
    else:
        item = next((x for x in layers
                     if str(x.get("name") or x.get("layer") or "").upper() == name), {})
    return item or {}


def layer_state(res, name: str) -> str:
    return str(layer_of(res, name).get("state") or "").strip().lower()


def reason_text(res, name: str = "") -> str:
    """顶层理由 + 该层理由，一起看——判词写在哪一头都算数。"""
    text = str(res.get("reason") or "")
    if name:
        text += " " + str(layer_of(res, name).get("reason") or "")
    return text


# ─────────────────────────────────────────────────────── 用例基类

class TargetCase(unittest.TestCase):
    def setUp(self):
        self.target = Target()
        self.addCleanup(self.target.close)
        self.prober = HttpProber()

    def route(self, path: str, fn):
        return self.target.route(path, fn)

    def finding(self, endpoint: str, **kw):
        row = {
            "id": 1,
            "sources": "sweep-strike:xss",
            "asset": "127.0.0.1",
            "port": self.target.port,
            "endpoint": endpoint,
            "title": "参数触发服务端错误",
            "base": self.target.base(),
            "method": "GET",
            "param": "",
            "payload": "",
            "evidence": "",
            "status": "待验证",
        }
        row.update(kw)
        return row

    def run_pipeline(self, row, prober=None):
        return pipeline.verify(row, prober if prober is not None else self.prober)


needs_pipeline = unittest.skipIf(
    pipeline is None, f"vc/pipeline.py 尚未落地（{_IMPORT_ERROR}）——本套用例按文件头契约编写")


class TestPipelinePresent(unittest.TestCase):
    """实现没落地时这里必须红。

    其余用例在模块缺失时只能 skip（否则每条都抛 AttributeError，噪音盖住真问题），
    但「整套 skip」会伪装成绿——所以留一条硬失败当信号灯。
    """

    def test_module_importable(self):
        if pipeline is None:
            self.fail(f"vc/pipeline.py 不存在或导入失败：{_IMPORT_ERROR}")
        self.assertTrue(callable(getattr(pipeline, "verify", None)))


# ═════════════════════════════════════════════════════ 1. 夹具自检

class TestHarness(unittest.TestCase):
    """先证明靶子和 prober 是真的：这几条不依赖流水线，现在就该绿。

    如果这里红了，后面所有「流水线判错」的结论都不作数——那只是夹具坏了。
    """

    def setUp(self):
        self.target = Target()
        self.addCleanup(self.target.close)
        self.prober = HttpProber()

    def get(self, path: str):
        return self.prober({"method": "GET", "url": self.target.base() + path})

    def test_port_is_kernel_assigned(self):
        self.assertGreater(self.target.port, 0)
        self.assertEqual(self.prober({"method": "GET", "url": self.target.base() + "/x"})["status"],
                         200)      # 默认路由是静态 200

    def test_payload_route_returns_500_and_control_returns_200(self):
        self.target.route("/render", route_tpl_500)
        hit = self.get("/render?tpl=" + TPL + "&lang=zh")
        ctl = self.get("/render?tpl=1&lang=zh")
        self.assertEqual(hit["status"], 500)
        self.assertIn("ZeroDivisionError", hit["body"])
        self.assertEqual(ctl["status"], 200)

    def test_sensitive_route_leaks_passwd(self):
        self.target.route("/download", route_passwd)
        self.assertIn("root:x:0:0", self.get("/download?file=" + TRAV)["body"])
        self.assertNotIn("root:x:0:0", self.get("/download?file=readme")["body"])

    def test_sitewide_500_route_is_uniform(self):
        self.target.fallback = route_sitewide_500
        a, b = self.get("/a?q=1"), self.get("/b?q=" + TPL)
        self.assertEqual((a["status"], a["body"]), (b["status"], b["body"]))

    def test_waf_route_has_block_page_fingerprint(self):
        self.target.route("/search", route_waf)
        r = self.get("/search?q=" + XSS)
        self.assertEqual(r["status"], 403)
        self.assertIn("Attention Required! | Cloudflare", r["body"])
        self.assertIn("cf-ray", r["headers"])
        self.assertEqual(self.get("/search?q=hi")["status"], 200)

    def test_boolean_route_returns_identical_page_for_1_and_2(self):
        self.target.route("/list", route_bool_same)
        one = self.get("/list?id=1'AND(1=1)--")
        two = self.get("/list?id=1'AND(1=2)--")
        self.assertEqual((one["status"], one["body"]), (two["status"], two["body"]))
        self.assertNotEqual(one["body"], self.get("/list?id=1")["body"])

    def test_minimal_route_needs_debug_param(self):
        self.target.route("/render", route_needs_debug)
        self.assertEqual(self.get("/render?debug=1&tpl=" + TPL)["status"], 500)
        self.assertEqual(self.get("/render?tpl=" + TPL)["status"], 200)

    def test_prober_records_every_call(self):
        self.get("/a?x=1")
        self.get("/b?y=2")
        self.assertEqual([c["url"].split(str(self.target.port))[-1] for c in self.prober.calls],
                         ["/a?x=1", "/b?y=2"])

    def test_prober_reports_no_response_instead_of_raising(self):
        # 关掉服务再打：必须回 status=0，而不是把异常抛给流水线
        port = self.target.port
        self.target.close()
        r = self.prober({"method": "GET", "url": f"http://127.0.0.1:{port}/x"})
        self.assertEqual(r["status"], 0)
        self.assertTrue(r["error"])


# ═════════════════════════════════════════════════════ 2. 契约面

@needs_pipeline
class TestContract(unittest.TestCase):
    """返回结构本身也是契约：调用方要按它写库、出报告。"""

    def test_module_exposes_verify(self):
        self.assertTrue(callable(getattr(pipeline, "verify", None)),
                        "vc/pipeline.py 必须提供 verify(row, prober)")

    def test_result_shape(self):
        row = {"id": 1, "sources": "sweep-strike:xss", "asset": "127.0.0.1", "port": 80,
               "endpoint": "/render?tpl=" + TPL, "title": "参数触发服务端错误",
               "base": "http://127.0.0.1:80", "method": "GET",
               "param": "tpl", "payload": TPL, "evidence": "", "status": "待验证"}

        def fn(req, n):
            if carries(req, TPL):
                return {"status": 500, "headers": {}, "body": TPL_ERROR, "url": "", "error": ""}
            return {"status": 200, "headers": {}, "body": "<html>ok</html>", "url": "", "error": ""}

        res = pipeline.verify(row, FakeProber(fn))
        self.assertIsInstance(res, dict)
        self.assertIn(verdict_of(res), {"verified", "refuted", "uncertain"})
        self.assertTrue(str(res.get("reason") or "").strip(), "结论必须带人话理由")
        self.assertIsInstance(res.get("layers"), dict)
        self.assertEqual(set(res["layers"]), {"L1", "L2", "L3"})


# ═════════════════════════════════════════════════════ 3. 真命中

@needs_pipeline
class TestTrueHit(TargetCase):
    def test_payload_triggered_500_is_verified(self):
        self.route("/render", route_tpl_500)
        row = self.finding("/render?tpl=" + TPL + "&lang=zh&page=2",
                           payload=TPL, param="tpl", evidence="ZeroDivisionError")
        res = self.run_pipeline(row)
        self.assertEqual(verdict_of(res), "verified", reason_text(res))
        for name in ("L1", "L2", "L3"):
            self.assertEqual(layer_state(res, name), "pass", f"{name}: {reason_text(res, name)}")
        self.assertIn("curl", str(res.get("minimal_curl") or ""))
        self.assertIn(str(self.target.port), str(res.get("minimal_curl") or ""))
        # 真打了：orig / orig2 / ctl 至少三次落在同一个端点上
        self.assertGreaterEqual(self.target.paths_hit().count("/render"), 3)

    def test_sensitive_content_is_verified(self):
        self.route("/download", route_passwd)
        row = self.finding("/download?file=" + TRAV + "&dir=pub",
                           payload=TRAV, param="file", title="任意文件读取",
                           evidence="root:x:0:0")
        res = self.run_pipeline(row)
        self.assertEqual(verdict_of(res), "verified", reason_text(res))
        self.assertEqual(layer_state(res, "L1"), "pass", reason_text(res, "L1"))
        self.assertEqual(layer_state(res, "L3"), "pass", reason_text(res, "L3"))

    def test_non_injectable_finding_skips_context_layers(self):
        """没有 payload 的条目（敏感路径）没有 L2/L3 可做：适用层全过就算 verified。"""
        self.route("/.env", lambda qs, form, h: _resp(200, "DB_PASSWORD=kara", {"Content-Type": "text/plain"}))
        row = self.finding("/.env", title="敏感路径可访问：/.env", evidence="DB_PASSWORD")
        res = self.run_pipeline(row)
        self.assertEqual(verdict_of(res), "verified", reason_text(res))
        self.assertEqual(layer_state(res, "L1"), "pass", reason_text(res, "L1"))
        self.assertEqual(layer_state(res, "L2"), "skip", reason_text(res, "L2"))
        self.assertIn(layer_state(res, "L3"), {"skip", "pass"}, reason_text(res, "L3"))

    def test_row_is_not_mutated(self):
        self.route("/render", route_tpl_500)
        row = self.finding("/render?tpl=" + TPL, payload=TPL, param="tpl")
        before = copy.deepcopy(row)
        self.run_pipeline(row)
        self.assertEqual(row, before, "流水线不该改命中行——写库由调用方决定")


# ═══════════════════════════════════════ 4. 全站 500 假命中

@needs_pipeline
class TestSitewide5xx(TargetCase):
    def test_sitewide_500_is_refuted_by_l1(self):
        self.target.fallback = route_sitewide_500
        row = self.finding("/search?q=" + XSS, payload=XSS, param="q", title="反射型 XSS")
        res = self.run_pipeline(row)
        self.assertEqual(verdict_of(res), "refuted", reason_text(res))
        self.assertEqual(layer_state(res, "L1"), "fail", reason_text(res, "L1"))
        self.assertIn("全站", reason_text(res, "L1"))
        self.assertIn("L1", str(res.get("reason") or ""), "理由是 L1，顶层就得写 L1")

    def test_payload_made_no_difference_is_refuted_by_l1(self):
        self.target.fallback = route_static
        row = self.finding("/search?q=" + XSS, payload=XSS, param="q", title="反射型 XSS")
        res = self.run_pipeline(row)
        self.assertEqual(verdict_of(res), "refuted", reason_text(res))
        self.assertEqual(layer_state(res, "L1"), "fail", reason_text(res, "L1"))
        self.assertIn("没产生任何差异", reason_text(res, "L1"))


# ═══════════════════════════════════════════════ 5. WAF 拦截页

@needs_pipeline
class TestWafBlocked(TargetCase):
    def test_block_page_is_uncertain_with_l1_blocked(self):
        self.route("/search", route_waf)
        row = self.finding("/search?q=" + XSS, payload=XSS, param="q", title="反射型 XSS")
        res = self.run_pipeline(row)
        self.assertEqual(layer_state(res, "L1"), "blocked", reason_text(res, "L1"))
        self.assertEqual(verdict_of(res), "uncertain",
                         "被 WAF 拦住 = 没拿到证据，不许判 refuted：" + reason_text(res))
        self.assertIn("拦", reason_text(res, "L1"))
        self.assertIn("403", reason_text(res, "L1"))

    def test_blocked_control_too_is_still_blocked_not_refuted(self):
        """orig 与 ctl 完全一致，但那是同一张拦截页——不能算「payload 没差异」。"""
        self.target.fallback = route_waf_all
        row = self.finding("/search?q=" + XSS, payload=XSS, param="q", title="反射型 XSS")
        res = self.run_pipeline(row)
        self.assertEqual(layer_state(res, "L1"), "blocked", reason_text(res, "L1"))
        self.assertEqual(verdict_of(res), "uncertain", reason_text(res))


# ═══════════════════════════════════════════ 6. 布尔对照不成立

@needs_pipeline
class TestBooleanControl(TargetCase):
    def test_identical_1_and_2_pages_refute_at_l2(self):
        self.route("/list", route_bool_same)
        row = self.finding("/list?id=" + BOOL + "&p=2",
                           payload=BOOL, param="id", title="SQL 注入（布尔盲注）")
        res = self.run_pipeline(row)
        self.assertEqual(verdict_of(res), "refuted", reason_text(res))
        self.assertEqual(layer_state(res, "L1"), "pass", "L1 得先过，否则测不到 L2：" + reason_text(res, "L1"))
        self.assertEqual(layer_state(res, "L2"), "fail", reason_text(res, "L2"))
        self.assertIn("布尔对照不成立", reason_text(res, "L2"))
        self.assertIn("L2", str(res.get("reason") or ""), "理由是 L2，顶层就得写 L2")


# ═══════════════════════════════════════════ 7. 最小化后现象消失

@needs_pipeline
class TestMinimisation(TargetCase):
    def test_phenomenon_gone_after_stripping_params_is_unstable(self):
        self.route("/render", route_needs_debug)
        row = self.finding("/render?debug=1&tpl=" + TPL + "&lang=zh",
                           payload=TPL, param="tpl")
        res = self.run_pipeline(row)
        self.assertEqual(layer_state(res, "L1"), "pass", reason_text(res, "L1"))
        self.assertEqual(layer_state(res, "L2"), "pass", reason_text(res, "L2"))
        self.assertEqual(layer_state(res, "L3"), "unstable", reason_text(res, "L3"))
        self.assertEqual(verdict_of(res), "uncertain", reason_text(res))
        self.assertTrue("最小化" in reason_text(res, "L3") or "现象消失" in reason_text(res, "L3"),
                        "L3 得说清是「最小化后现象消失」：" + reason_text(res, "L3"))


# ═══════════════════════════════════════ 8. 历史人工判误报降级

@needs_pipeline
class TestHistoryDowngrade(TargetCase):
    def test_manual_false_positive_downgrades_verified(self):
        self.route("/render", route_tpl_500)
        row = self.finding("/render?tpl=" + TPL + "&lang=zh",
                           payload=TPL, param="tpl", status="误报")
        res = self.run_pipeline(row)
        # 三层真全过了……
        for name in ("L1", "L2", "L3"):
            self.assertEqual(layer_state(res, name), "pass", f"{name}: {reason_text(res, name)}")
        # ……但人工判过误报，结论必须降级，且理由说得出为什么
        self.assertEqual(verdict_of(res), "uncertain", reason_text(res))
        self.assertIn("历史人工判误报", reason_text(res))


# ═════════════════════════════════════ 9. 纯逻辑（假 prober，不建连）

@needs_pipeline
class TestPureLogic(unittest.TestCase):
    """HTTP 层已经在上面用真服务测过了，这里只钉「层与层之间」的判定规则。"""

    def row(self, **kw):
        row = {"id": 1, "sources": "sweep-strike:sqli", "asset": "127.0.0.1", "port": 80,
               "endpoint": "/list?id=" + BOOL, "title": "SQL 注入（布尔盲注）",
               "base": "http://127.0.0.1:80", "method": "GET",
               "param": "id", "payload": BOOL, "evidence": "", "status": "待验证"}
        row.update(kw)
        return row

    @staticmethod
    def ok(body="ok"):
        return {"status": 200, "headers": {}, "body": body, "url": "", "error": ""}

    @staticmethod
    def err(body="boom"):
        return {"status": 500, "headers": {}, "body": body, "url": "", "error": ""}

    def test_any_layer_fail_refutes(self):
        # L1 过（payload 500 / 对照 200），L2 布尔对照不成立
        def fn(req, n):
            if carries(req, "1=1") or carries(req, "1=2"):
                return self.ok(BOOL_PAGE)
            return self.err(TPL_ERROR) if carries(req, BOOL) else self.ok("<html>列表页</html>")
        res = pipeline.verify(self.row(), FakeProber(fn))
        self.assertEqual(verdict_of(res), "refuted", reason_text(res))
        self.assertEqual(layer_state(res, "L1"), "pass", reason_text(res, "L1"))
        self.assertEqual(layer_state(res, "L2"), "fail", reason_text(res, "L2"))

    def test_no_response_is_error_not_refuted(self):
        res = pipeline.verify(self.row(), FakeProber(
            lambda req, n: {"status": 0, "headers": {}, "body": "", "url": "", "error": "connection refused"}))
        self.assertEqual(layer_state(res, "L1"), "error", reason_text(res, "L1"))
        self.assertEqual(verdict_of(res), "uncertain",
                         "连不上 = 没测到，不许说命中没了：" + reason_text(res))

    def test_intermittent_5xx_fails_l1(self):
        seen = {"n": 0}

        def fn(req, n):
            if carries(req, BOOL):
                seen["n"] += 1
                return self.err() if seen["n"] == 1 else (self.ok("ok") if seen["n"] == 2 else self.err())
            return self.ok("<html>列表页</html>")
        res = pipeline.verify(self.row(title="参数触发服务端错误"), FakeProber(fn))
        self.assertEqual(layer_state(res, "L1"), "fail", reason_text(res, "L1"))
        self.assertIn("偶发", reason_text(res, "L1"))
        self.assertEqual(verdict_of(res), "refuted", reason_text(res))

    def test_identical_orig_and_control_fails_l1(self):
        res = pipeline.verify(self.row(title="反射型 XSS", payload=XSS, param="q",
                                       endpoint="/search?q=" + XSS),
                              FakeProber(lambda req, n: self.ok("<html>同形页</html>")))
        self.assertEqual(layer_state(res, "L1"), "fail", reason_text(res, "L1"))
        self.assertIn("没产生任何差异", reason_text(res, "L1"))
        self.assertEqual(verdict_of(res), "refuted", reason_text(res))

    def test_5xx_with_clean_control_passes_l1(self):
        # payload 与标题都不能带引号/SQL 字样：这里只想验 L1
        # 「两次 5xx 但对照正常 = payload 打出来的」，否则 L2 的布尔对照会先接管
        # （那正是汇报里要单独讨论的坑）。
        res = pipeline.verify(self.row(title="参数触发服务端错误", payload=TPL,
                                       param="tpl", endpoint="/render?tpl=" + TPL),
                              FakeProber(lambda req, n: self.err() if carries(req, TPL)
                                         else self.ok("<html>列表页</html>")))
        self.assertEqual(layer_state(res, "L1"), "pass", reason_text(res, "L1"))
        self.assertEqual(verdict_of(res), "verified", reason_text(res))

    def test_layer_states_stay_in_vocabulary(self):
        res = pipeline.verify(self.row(), FakeProber(lambda req, n: self.err()))
        self.assertEqual(set(res.get("layers") or {}), {"L1", "L2", "L3"})
        for name in ("L1", "L2", "L3"):
            self.assertIn(layer_state(res, name), STATES, f"{name} 状态不在词表里")
        self.assertIn(verdict_of(res), {"verified", "refuted", "uncertain"})


if __name__ == "__main__":
    unittest.main()

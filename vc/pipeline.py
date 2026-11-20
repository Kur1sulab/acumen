"""三层复验流水线：命中 → 上下文复核 → 最小化 PoC。

为什么单层判定不够（总纲 4.2 P0）
    `vc/verify.py` 原来的判定只有一层：重跑同一个扫描模式，看同标题的命中还在不在。
    它拿不到响应体，所以下面四种形状在它眼里一模一样：
        真命中（payload 打出了 500 / 读到了文件）
        全站 500（打什么都是同一张错误页）
        WAF 拦截页（403 + Cloudflare 那种拦截页，打什么都是它）
        payload 根本没进业务（静态页，打什么都一样）
    四种都记成「仍存在」，报告里就是四条假漏洞；反过来，被 WAF 拦住的那批又会被
    记成「已消失」，变成漏报。两层错误来自同一个根：**没有上下文对照**。

三层各自回答一个问题，任一层的 fail 都能单独把结论推翻
    L1 命中复核     原请求重放两次 + 打一个无害对照。响应与对照完全一致 → 不是命中；
                   首次 5xx、重放变 2xx → 偶发错误，不是命中；被 WAF 拦 → 不下结论。
    L2 上下文复核   同位置换无害值、把 payload 换到另一个参数名/位置。换无害值后现象
                   照旧 → 现象不是 payload 造成的；SQLi 还要跑布尔对照（1=1 vs 1=2），
                   两边响应一致 → 布尔差异不成立，注入是假的。
    L3 最小化 PoC   剥掉无关参数只留 payload 再打一次，产出能直接粘进报告的最小复现串；
                   剥完现象就没了 → 结论依赖被剥掉的部分，给不出最小 PoC（存疑）。

状态词表（每个层独立结论，不合并成一句话）
    pass      通过
    fail      不通过 —— 这一层就足以判定为误报
    unstable  现象不稳（两次重放不一致 / 最小化后现象消失）—— 不下结论
    blocked   被 WAF 拦 —— 拿到的响应证明不了任何事，既不能确认也不能否定
    skip      不适用（该层对这个类别的命中没有对象，例如路径类命中没有可换的参数）
    error     没跑成（连不上、超时、引擎不支持）—— 不下结论

判定规则
    任一层 fail                          → refuted
    适用层（非 skip）全部 pass            → verified
    其余（含 blocked / unstable / error） → uncertain
    「任一层不通过就不算确认」是硬口径：不要为了凑 verified 把 blocked 当 pass。

为什么这里不自己发请求
    Python 侧出站被 tools/check_offline.py 拦着（产品纪律：空境自身不联网）。
    所以本模块只做「判定」，请求由调用方注入的 prober 发：
        prober(req) -> {"status", "headers", "body", "url", "error"}
        req = {"method", "url", "headers", "body"}
    生产实现是 vc/probe.py 的 EngineProber（起引擎子进程发一次精确请求），
    测试实现是 tests/test_pipeline.py 里的 http.client 直连回环靶子。
    判定逻辑因此可以脱网单测，也不会在 vc/ 里留下任何出站能力。

历史人工结论参与判定
    人标过「误报」的 (host, rule, param)，再次命中时不能直接丢掉（那是隐瞒），
    也不能照旧报 verified（那是无视人的判断）：降级成 uncertain 并把理由写在明面上。
"""

from __future__ import annotations

import hashlib
import random
import re
import string
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote, unquote, urlsplit

from . import waf as wafmod

# ---------------------------------------------------------------- 层与状态

L1, L2, L3 = "L1", "L2", "L3"
LAYERS = (L1, L2, L3)
LAYER_TITLES = {L1: "命中复核", L2: "上下文复核", L3: "最小化 PoC"}

PASS, FAIL, UNSTABLE, BLOCKED, SKIP, ERROR = (
    "pass", "fail", "unstable", "blocked", "skip", "error")
LAYER_STATES = (PASS, FAIL, UNSTABLE, BLOCKED, SKIP, ERROR)
STATE_LABELS = {
    PASS: "通过", FAIL: "不通过", UNSTABLE: "现象不稳",
    BLOCKED: "被拦", SKIP: "不适用", ERROR: "没跑成",
}
# 符号 + 文字是第一载体，颜色只是辅助（与 list 的存活列同一套纪律）
STATE_SYMBOLS = {PASS: "✓", FAIL: "✗", UNSTABLE: "~", BLOCKED: "⊘", SKIP: "—", ERROR: "!"}

VERIFIED, REFUTED, UNCERTAIN = "verified", "refuted", "uncertain"
VERDICTS = (VERIFIED, REFUTED, UNCERTAIN)
VERDICT_LABELS = {
    VERIFIED: "确认（三层全过）",
    REFUTED: "误报（有不通过的层）",
    UNCERTAIN: "存疑（证据不足，不下结论）",
}
VERDICT_SYMBOLS = {VERIFIED: "✓", REFUTED: "✗", UNCERTAIN: "?"}

# 扫描时给「历史人工判过误报」的命中打的降级标（不是流水线结论，别混进 VERDICTS）
DOWNGRADED = "downgraded"

BENIGN = "kara"          # 无害对照值：短、无特殊字符，任何正常业务都不该因它改变
PROBE_PREFIX = "kara_"   # 换位置时用的参数名前缀，方便在目标日志里认出是我们在复核

MAX_BODY = 4096          # 只在内存里留这么多：判定看状态码/长度/摘要，不留全量正文


# ---------------------------------------------------------------- 行 → 请求

_PAYLOAD_HINT = re.compile(r"""['"<>(){}\[\];|`$\\]|\.\.|1=1|%00|\{\{|<script""", re.I)


def _rand(n: int = 6) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def base_of(row: Any) -> str:
    """命中行的基地址：优先用引擎记下的 base，其次端点里带的 scheme，最后按端口猜。

    和 vc/verify.py 的 base_url 同口径，但这里独立实现：pipeline 不该反向依赖 verdict 层
    （verify.py 会 import 本模块，反过来 import 会成环）。
    """
    def get(k: str, default: str = "") -> str:
        try:
            v = row[k]
        except (KeyError, IndexError, TypeError):
            return default
        return str(v or default)

    base = get("base").strip()
    if base:
        m = re.match(r"^(https?)://([^/\s]+)", base, re.I)
        if m:
            return f"{m.group(1).lower()}://{m.group(2)}"
        base = base.rstrip("/")
        return base if re.match(r"^https?://", base, re.I) else ""
    ep = get("endpoint").strip()
    m = re.match(r"^(https?)://([^/\s]+)", ep, re.I)
    if m:
        return f"{m.group(1).lower()}://{m.group(2)}"
    host = get("asset").strip()
    if not host:
        return ""
    port = get("port").strip()
    scheme = "https" if port in ("443", "8443") else "http"
    return f"{scheme}://{host}{(':' + port) if port else ''}"


class _Params:
    """查询串 / 表单体的分段编辑。

    刻意不做 parse + 重新编码：重放要尽量保持原请求的字节形状，只有被改动的那一段
    才重新编码；否则「重放结果不同」可能只是我们自己把编码改了。
    """

    def __init__(self, raw: str):
        self.raw = raw or ""
        self.segs: List[str] = [s for s in self.raw.split("&") if s]

    def __len__(self) -> int:
        return len(self.segs)

    def key(self, i: int) -> str:
        return unquote(self.segs[i].split("=", 1)[0])

    def value(self, i: int) -> str:
        return unquote(self.segs[i].split("=", 1)[1]) if "=" in self.segs[i] else ""

    def find(self, key: str) -> int:
        if not key:
            return -1
        for i in range(len(self.segs)):
            if self.key(i) == key:
                return i
        return -1

    def find_value(self, value: str) -> int:
        if not value:
            return -1
        for i in range(len(self.segs)):
            if self.value(i) == value:
                return i
        return -1

    def _enc(self, v: str) -> str:
        return quote(v, safe="")

    def render(self, segs: Sequence[str]) -> str:
        return "&".join(segs)

    def with_value(self, i: int, value: str) -> str:
        out = list(self.segs)
        k = self.segs[i].split("=", 1)[0]        # 键保持原样：只改值，别顺手改动编码
        out[i] = f"{k}={self._enc(value)}"
        return self.render(out)

    def with_key(self, i: int, key: str) -> str:
        out = list(self.segs)
        out[i] = f"{self._enc(key)}={self.segs[i].split('=', 1)[1] if '=' in self.segs[i] else ''}"
        return self.render(out)

    def only(self, i: int) -> str:
        return self.segs[i]


class _Ctx:
    """一条命中 → 可重放的请求。payload 在 query 还是 body 都认。"""

    def __init__(self, row: Any):
        def get(k: str, default: str = "") -> str:
            try:
                v = row[k]
            except (KeyError, IndexError, TypeError):
                return default
            return str(v or default)

        self.row = row
        self.base = base_of(row)
        self.method = (get("method") or _method_of(get("repro")) or "GET").upper()
        self.evidence = get("evidence")
        self.param = get("param")
        self.path = ""
        self.query = ""
        self.body = get("body")

        ep = get("endpoint")
        if ep:
            parts = urlsplit(ep)
            self.path = parts.path or "/"
            self.query = parts.query
        else:
            self.path = "/"
        if not self.base:
            self.base = base_of({"endpoint": ep})

        # payload 位置：显式字段 > 端点里的参数值 > 正文
        payload = get("payload")
        place, index = "", -1
        qp = _Params(self.query)
        bp = _Params(self.body)
        if payload and self.param and qp.find(self.param) >= 0:
            place, index = "query", qp.find(self.param)
        elif payload and bp.find_value(payload) >= 0:
            place, index = "body", bp.find_value(payload)
        elif payload and qp.find_value(payload) >= 0:
            place, index = "query", qp.find_value(payload)
        elif payload and bp.find_value(payload) < 0 and qp.find_value(payload) < 0:
            # payload 不在请求里（有些解析只留了标题）：挂到同名参数上，照样能重放
            if self.param:
                place, index = "query", -2
        if not payload:
            # 没有显式 payload：从参数值里挑一个像注入串的（strike 类命中只有端点）
            for i in range(len(qp)):
                v = qp.value(i)
                if _PAYLOAD_HINT.search(v):
                    place, index, payload = "query", i, v
                    if not self.param:
                        self.param = qp.key(i)
                    break
            else:
                for i in range(len(bp)):
                    v = bp.value(i)
                    if _PAYLOAD_HINT.search(v):
                        place, index, payload = "body", i, v
                        if not self.param:
                            self.param = bp.key(i)
                        break

        self.place = place
        self.index = index
        self.payload = payload
        self.params = qp if place != "body" else bp

    # —— 请求组装 ——

    def url(self, query: Optional[str] = None) -> str:
        q = self.query if query is None else query
        return f"{self.base}{self.path}" + (f"?{q}" if q else "")

    def req(self, url: str, body: Optional[str] = None, method: Optional[str] = None) -> Dict[str, Any]:
        m = (method or self.method).upper()
        b = self.body if body is None else body
        return {"method": m, "url": url, "headers": {}, "body": b}

    def has_payload(self) -> bool:
        return bool(self.payload) and self.place != ""

    def ctl_url(self) -> str:
        """无害对照：payload 换成本地无害值；没有 payload 就换一个同目录随机路径。"""
        if self.has_payload() and self.index >= 0 and self.place == "query":
            return self.url(self.params.with_value(self.index, BENIGN))
        # 路径类命中：同目录随机兄弟路径。软 404 / catch-all 全站 200 会在这里露馅
        d = self.path.rsplit("/", 1)[0] if "/" in self.path.rstrip("/") else ""
        return f"{self.base}{d}/kara-ctl-{_rand()}"

    def ctl_body(self) -> Optional[str]:
        """body 承载 payload 时的无害对照：同位置换无害值。"""
        if self.has_payload() and self.index >= 0 and self.place == "body":
            return self.params.with_value(self.index, BENIGN)
        return None

    def moved(self) -> Tuple[str, Optional[str]]:
        """同 payload 换一个位置/参数名重放，返回 (url, body)。

        query → 换个参数名；body → 搬进查询串（真换位置，不是换个键名），
        原 body 里那一段同时去掉，否则 payload 还在原处，等于没换。
        """
        if self.place == "body" and self.index >= 0:
            key = f"{PROBE_PREFIX}{_rand()}"
            q = self.query + ("&" if self.query else "") + f"{key}={quote(self.payload, safe='')}"
            rest = [s for i, s in enumerate(self.params.segs) if i != self.index]
            return self.url(q), "&".join(rest)
        if self.index >= 0:
            return self.url(self.params.with_key(self.index, f"{PROBE_PREFIX}{_rand()}")), None
        q = self.query + ("&" if self.query else "") + f"{PROBE_PREFIX}probe={quote(self.payload, safe='')}"
        return self.url(q), None

    def minimal(self) -> Tuple[str, Optional[str]]:
        """只留承载 payload 的那一段——报告里能贴的最小复现。"""
        if self.place == "body" and self.index >= 0:
            return self.url(""), self.params.only(self.index)
        if self.index == -2:      # payload 只在标题/证据里：按参数名现造一段
            key = self.param or f"{PROBE_PREFIX}probe"
            return self.url(f"{key}={quote(self.payload, safe='')}"), ""
        if self.index >= 0:
            return self.url(self.params.only(self.index)), ""
        return self.url(""), ""


def _method_of(repro: str) -> str:
    m = re.search(r"curl\b[^\n]*?(?:-X|--request)\s+([A-Za-z]+)", repro or "")
    return m.group(1).upper() if m else ""


# ---------------------------------------------------------------- 观测

def _obs(resp: Any) -> Dict[str, Any]:
    resp = resp if isinstance(resp, dict) else {}
    body = resp.get("body")
    body = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body or "")
    headers = resp.get("headers") or {}
    try:
        status = int(resp.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    return {
        "status": status,
        "headers": {str(k).lower(): str(v) for k, v in dict(headers).items()},
        "body": body[:MAX_BODY],
        "size": len(body.encode("utf-8", "replace")),
        "digest": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16],
        "url": str(resp.get("url") or ""),
        "error": str(resp.get("error") or ""),
        "ms": 0,
    }


def _probe(prober, ctx: _Ctx, url: str, body: Optional[str] = None) -> Dict[str, Any]:
    """发一次探测。prober 抛异常也要变成「没拿到响应」，不许把异常冒到判定里。"""
    req = ctx.req(url, body=body)
    t0 = time.monotonic()
    try:
        resp = prober(req)
    except Exception as exc:                       # noqa: BLE001 —— 兜住任何一种 prober 的失败
        resp = {"status": 0, "error": f"{type(exc).__name__}: {exc}"}
    obs = _obs(resp)
    obs["ms"] = int((time.monotonic() - t0) * 1000)
    return obs


def _sig(obs: Dict[str, Any]) -> Tuple[int, str]:
    return int(obs["status"]), str(obs["digest"])


def same(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """同一张响应：状态码 + 正文摘要。长度不参与——压缩/时间戳会晃，摘要不会。"""
    return _sig(a) == _sig(b)


def _desc(obs: Dict[str, Any]) -> str:
    if not obs["status"]:
        return f"无响应（{obs['error'] or '超时'}）"
    return f"HTTP {obs['status']} / {obs['size']}B / 摘要 {obs['digest']} / {obs['ms']}ms"


def _layer(name: str, state: str, reason: str, **extra: Any) -> Dict[str, Any]:
    out = {"name": name, "state": state, "reason": reason}
    out.update(extra)
    return out


def _blocked(obs: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    v = wafmod.classify(obs["status"], obs["headers"], obs["body"])
    return v if v.get("state") == wafmod.BLOCKED else None


# ---------------------------------------------------------------- L1 命中复核

def layer1(ctx: _Ctx, prober) -> Dict[str, Any]:
    orig = _probe(prober, ctx, ctx.url())
    if not orig["status"]:
        return _layer(L1, ERROR, f"原请求没拿到响应：{orig['error'] or '超时'}，无从判定", _obs=orig)
    wv = _blocked(orig)
    if wv:
        # 顺序要紧：拦截页本身往往「每次都一样」，先判 blocked 才不会被 L1 的
        # 「与对照一致 = 没差异」误判成误报——被拦不是证据，不能用来否定命中。
        return _layer(L1, BLOCKED,
                      f"被 WAF 拦（HTTP {orig['status']}）：{wv.get('reason')}"
                      f"——拿到的不是业务响应，命中既不能确认也不能否定", _obs=orig)

    again = _probe(prober, ctx, ctx.url())
    if not again["status"]:
        return _layer(L1, ERROR, f"原样重放没拿到响应：{again['error'] or '超时'}", _obs=orig)

    if orig["status"] >= 500 and again["status"] < 500:
        return _layer(L1, FAIL,
                      f"偶发 5xx：首次 {orig['status']}，原样重放第二次 {again['status']}"
                      f"（{_desc(again)}）——一次性错误不是命中", _obs=orig)

    ctl = _probe(prober, ctx, ctx.ctl_url(), body=ctx.ctl_body())
    if not ctl["status"]:
        return _layer(L1, ERROR, f"无害对照没拿到响应：{ctl['error'] or '超时'}", _obs=orig)

    if orig["status"] >= 500 and ctl["status"] >= 500 and same(orig, ctl):
        return _layer(L1, FAIL,
                      f"全站 5xx：payload 与无害对照都拿到 {orig['status']}、正文摘要相同"
                      f"（{orig['digest']}）——这是站点的错误页，不是命中", _obs=orig)

    if same(orig, ctl):
        return _layer(L1, FAIL,
                      f"payload 没产生任何差异：原请求与无害对照的响应完全一致"
                      f"（{_desc(orig)}）——命中不是 payload 造成的", _obs=orig)

    if not same(orig, again) and orig["status"] < 500 and again["status"] < 500:
        return _layer(L1, UNSTABLE,
                      f"两次重放不一致（{orig['size']}B vs {again['size']}B，摘要不同）"
                      f"——响应本身在晃，据此确认会写出假漏洞", _obs=orig)

    # 关键字比对（有判据词时才做）：判据出现在重放响应里、却不在对照里，
    # 比「摘要不同」更贴报告——报告要写的是「看到了什么」，不是「哈希是多少」。
    kw = ""
    ev = (ctx.evidence or "").strip()
    if ev and ev in orig["body"] and ev not in ctl["body"]:
        kw = f"；判据「{ev[:40]}」出现在重放正文、对照里没有"

    return _layer(L1, PASS,
                  f"重放 {_desc(orig)}，与无害对照（{_desc(ctl)}）不同；两次重放一致{kw}",
                  _obs=orig)


# ---------------------------------------------------------------- L2 上下文复核

def _boolean_pair(payload: str) -> Optional[Tuple[str, str]]:
    """从 payload 造 (真, 假) 一对布尔表达式。造不出来就返回 None。

    只在本模块能确定「换掉哪一段」时才做：硬猜一个 1=2 出来，得到的一致是
    「两个都不成立」，反而会把真注入判成误报。
    """
    if "1=1" in payload:
        return payload, payload.replace("1=1", "1=2", 1)
    if "1%3D1" in payload:
        return payload, payload.replace("1%3D1", "1%3D2", 1)
    if "'1'='1" in payload:
        return payload, payload.replace("'1'='1", "'1'='2", 1)
    return None


def _sqlish(ctx: _Ctx) -> bool:
    try:
        title = str(ctx.row["title"] or "")
    except (KeyError, IndexError, TypeError):
        title = ""
    blob = f"{title} {ctx.payload} {ctx.param}".lower()
    return bool(re.search(r"sql|注入|inject|union|select|'|\b1=1\b", blob))


def layer2(ctx: _Ctx, prober, orig: Dict[str, Any]) -> Dict[str, Any]:
    if not ctx.has_payload():
        return _layer(L2, SKIP, "没有可换位置的 payload（路径/配置类命中），上下文复核没有对象")

    # ① 同位置换无害值：现象照旧 = 现象不是 payload 造成的
    if ctx.index >= 0:
        harm_body = ctx.ctl_body() if ctx.place == "body" else None
        harm_url = (ctx.url(ctx.params.with_value(ctx.index, BENIGN))
                    if ctx.place == "query" else ctx.url(""))
        harm = _probe(prober, ctx, harm_url, body=harm_body)
        if not harm["status"]:
            return _layer(L2, ERROR, f"无害值对照没拿到响应：{harm['error'] or '超时'}")
        if same(harm, orig):
            return _layer(L2, FAIL,
                          f"payload 与无害值响应完全一致（{_desc(harm)}）"
                          f"——这个位置对输入不敏感，命中不成立")

    # ② 换参数名/位置：结论如果只对某个参数名成立，说明拿到的可能是该参数的特有分支；
    #    换位置后现象还在，说明是通用 sink（照样算命中，但要在理由里说清楚）。
    moved_url, moved_body = ctx.moved()
    moved = _probe(prober, ctx, moved_url, body=moved_body)
    notes: List[str] = []
    if not moved["status"]:
        notes.append(f"换位置重放没拿到响应（{moved['error'] or '超时'}），该项未验")
    elif same(moved, orig):
        notes.append("换参数名后现象不变（通用 sink，不是该参数特有）")
    else:
        notes.append(f"换参数名后响应改变（{moved['status']}/{moved['size']}B），现象与该参数相关")

    # ③ 布尔对照：SQLi 不能只看「有没有报错」
    pair = _boolean_pair(ctx.payload) if _sqlish(ctx) else None
    if pair and orig["status"] < 500:
        one = _probe(prober, ctx, ctx.url(ctx.params.with_value(ctx.index, pair[0])))
        two = _probe(prober, ctx, ctx.url(ctx.params.with_value(ctx.index, pair[1])))
        if not one["status"] or not two["status"]:
            notes.append("布尔对照没跑完（一侧无响应），该项未验")
        elif same(one, two):
            return _layer(L2, FAIL,
                          f"布尔对照不成立：1=1 与 1=2 的响应一致（{_desc(one)}）"
                          f"——布尔差异不存在，注入是假的")
        else:
            notes.append(f"布尔对照成立（1=1 与 1=2 响应不同：{one['size']}B vs {two['size']}B）")
    elif pair:
        # 报错型注入：两边都会 500，布尔对照没有判别力，硬比会把真注入判成误报
        notes.append("报错型响应，跳过布尔对照（两侧都会 5xx，比值没有判别力）")

    return _layer(L2, PASS, "；".join(notes))


# ---------------------------------------------------------------- L3 最小化 PoC

def curl_of(req: Dict[str, Any], insecure: bool = True) -> str:
    """把请求渲染成能直接粘进报告的 curl 串（单引号包参数，内部单引号转义）。"""
    def q(s: str) -> str:
        return "'" + str(s).replace("'", "'\\''") + "'"

    parts = ["curl", "-s" + ("k" if insecure else ""), "-i"]
    m = str(req.get("method") or "GET").upper()
    if m != "GET":
        parts += ["-X", m]
    body = req.get("body") or ""
    if body:
        parts += ["--data", q(body)]
    parts.append(q(req.get("url") or ""))
    return " ".join(parts)


def _effect_holds(orig: Dict[str, Any], obs: Dict[str, Any], evidence: str) -> bool:
    """最小化后的响应是否「还是同一个现象」。

    比 same() 宽一档：页面里少了个 lang 参数导致长度变化不算现象消失；
    但状态码变了、正文摘要变了又没有 evidence 兜底，就不能说现象还在。
    """
    if not obs["status"]:
        return False
    if same(orig, obs):
        return True
    if orig["status"] >= 500 and obs["status"] >= 500:
        return True
    if evidence and evidence in obs["body"]:
        return True
    return obs["status"] == orig["status"] and obs["status"] >= 400 and orig["status"] >= 400


def layer3(ctx: _Ctx, prober, orig: Dict[str, Any]) -> Dict[str, Any]:
    if not ctx.has_payload():
        return _layer(L3, SKIP, "没有 payload 可最小化（路径/配置类命中的最小复现就是原请求）")
    if ctx.index < 0:
        return _layer(L3, SKIP, "payload 不在请求参数里（只在标题/证据里），无法自动最小化")

    minimal, min_body = ctx.minimal()
    obs = _probe(prober, ctx, minimal, body=min_body)
    if not obs["status"]:
        return _layer(L3, ERROR, f"最小化请求没拿到响应：{obs['error'] or '超时'}")
    if not _effect_holds(orig, obs, ctx.evidence):
        return _layer(L3, UNSTABLE,
                      f"最小化后现象消失（{_desc(obs)} vs 原始 {_desc(orig)}）"
                      f"——结论依赖被剥掉的参数，给不出最小复现串")
    poc = curl_of(ctx.req(minimal, body=min_body))
    return _layer(L3, PASS, f"剥到只剩 {ctx.param or 'payload'} 参数后现象仍在（{_desc(obs)}）",
                  poc=poc)


# ---------------------------------------------------------------- 历史人工结论

HUMAN_REFUTED = {"refuted", "false-positive", "fp", "误报", "已误报", "false_positive"}
HUMAN_VERIFIED = {"verified", "true-positive", "tp", "真报", "已确认", "true_positive"}


def norm_human(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in HUMAN_REFUTED:
        return REFUTED
    if s in HUMAN_VERIFIED:
        return VERIFIED
    return ""


def rule_of(row: Any) -> str:
    """同一条规则的稳定标识：标题归一（去空白、去大小写）。

    为什么用标题而不是 CVE 号：绝大多数命中没有 CVE，标题才是「同一个检查项」的名字。
    """
    try:
        title = str(row["title"] or "")
    except (KeyError, IndexError, TypeError):
        title = ""
    return re.sub(r"\s+", "", title).lower()


def history_of(row: Any, history: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """人工结论：显式传入的历史优先，其次看行上的 fb_state / status=误报。"""
    if isinstance(history, dict) and norm_human(history.get("verdict")):
        return {"verdict": norm_human(history.get("verdict")),
                "times": int(history.get("times") or 1),
                "note": str(history.get("note") or "")}
    def get(k: str) -> str:
        try:
            return str(row[k] or "")
        except (KeyError, IndexError, TypeError):
            return ""
    v = norm_human(get("fb_state"))
    if v:
        return {"verdict": v, "times": int(get("fb_times") or 1) or 1, "note": ""}
    if get("status").strip() == "误报":
        return {"verdict": REFUTED, "times": 1, "note": "人工状态=误报"}
    return {}


# ---------------------------------------------------------------- 入口

def verify(row: Any, prober, history: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """跑完三层，返回 {verdict, reason, layers:{L1,L2,L3}, minimal_curl}。

    不改 row（写库由调用方决定）；不抛异常（prober 的锅变成 L1 error）。
    """
    ctx = _Ctx(row)
    if not ctx.base:
        layers = {
            L1: _layer(L1, ERROR, "这条命中没有可回访的地址（base/endpoint 都为空），无法复验"),
            L2: _layer(L2, SKIP, "L1 没跑成，后续层不执行"),
            L3: _layer(L3, SKIP, "L1 没跑成，后续层不执行"),
        }
        return _finish(layers, ctx, history)

    l1 = layer1(ctx, prober)
    orig = l1.pop("_obs", None) or _obs({})
    if l1["state"] == PASS:
        l2 = layer2(ctx, prober, orig)
        l3 = layer3(ctx, prober, orig) if l2["state"] in (PASS, SKIP) else _layer(
            L3, SKIP, "L2 未通过/未跑成，最小化没有意义")
    else:
        l2 = _layer(L2, SKIP, f"{l1['state']}：{LAYER_TITLES[L1]}没通过，后续层不执行")
        l3 = _layer(L3, SKIP, f"{l1['state']}：{LAYER_TITLES[L1]}没通过，后续层不执行")
    return _finish({L1: l1, L2: l2, L3: l3}, ctx, history)


def _finish(layers: Dict[str, Dict[str, Any]], ctx: _Ctx, history: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    fails = [n for n in LAYERS if layers[n]["state"] == FAIL]
    ran = [n for n in LAYERS if layers[n]["state"] in (PASS, FAIL, UNSTABLE, BLOCKED, ERROR)]
    passes = [n for n in LAYERS if layers[n]["state"] == PASS]

    if fails:
        n = fails[0]
        verdict = REFUTED
        reason = f"{n} {LAYER_TITLES[n]}不通过：{layers[n]['reason']}"
    elif passes and all(layers[n]["state"] in (PASS, SKIP) for n in LAYERS):
        verdict = VERIFIED
        done = "、".join(f"{n} {LAYER_TITLES[n]}" for n in passes)
        reason = f"三层全过（{done}）"
    else:
        bad = next((n for n in LAYERS if layers[n]["state"] not in (PASS, SKIP)), "")
        verdict = UNCERTAIN
        reason = (f"{bad} {LAYER_TITLES[bad]}没给出结论：{layers[bad]['reason']}"
                  if bad else "没有任何一层完成，不能下结论")

    hist = history_of(ctx.row, history)
    hv = hist.get("verdict")
    if hv == REFUTED:
        times = max(1, int(hist.get("times") or 1))
        tail = f"；人工备注：{hist['note']}" if hist.get("note") else ""
        if verdict == VERIFIED:
            verdict = UNCERTAIN
            reason = (f"历史人工判误报（{times} 次）：本次三层全过，但按人工结论降级为存疑，"
                      f"需人工复核后才算确认{tail}")
        elif verdict == REFUTED:
            reason += f"（与历史人工判误报一致，共 {times} 次）{tail}"
        else:
            reason += f"；历史人工判误报（{times} 次）：本层没有定论，按人工结论一并降级{tail}"
    elif hv == VERIFIED and verdict != VERIFIED:
        reason += "（历史人工已确认过，但这三层没全过——建议人工复看）"

    poc = ""
    for n in LAYERS:
        poc = poc or str(layers[n].get("poc") or "")
    return {
        "verdict": verdict,
        "reason": reason,
        "layers": layers,
        "minimal_curl": poc,
        "pass_count": len(passes),
        "ran_count": len(ran),
        # 被历史人工结论压下去的标记：结论是 uncertain，但落库会标成 downgraded
        "history_downgraded": bool(hv == REFUTED and verdict != REFUTED),
    }


def applicable(row: Any) -> bool:
    """这条命中能不能走三层流水线：得有一个可回访的 HTTP 地址。

    弱口令（协议握手）、配置检查（secheaders/sslchain）没有请求上下文可换，
    它们是「重跑一遍看还在不在」的形态，由 verify.py 的老路径继续管。
    """
    if not base_of(row):
        return False
    try:
        sources = str(row["sources"] or "")
    except (KeyError, IndexError, TypeError):
        sources = ""
    head = sources.split(":", 1)[0].strip()
    return head in {"sweep-paths", "sweep-api", "sweep-evidence", "sweep-jsintel",
                    "sweep-strike", "sweep-cve"}


def badge(res_or_state: Any) -> str:
    """三层通过度：✓3/3、✗1/2、⚠降级、—（没跑）。

    分母是**适用层数**，不是恒定的 3：路径类命中没有可换的参数，L2/L3 是 skip，
    写成 1/3 会让人以为是「三层只过了一层」，那是把「不适用」读成了「没通过」。
    """
    if isinstance(res_or_state, str):
        state = res_or_state.strip()
        if state == DOWNGRADED:
            return "⚠降级"
        if not state:
            return "—"
        return {"verified": "✓3/3", "refuted": "✗3/3", "uncertain": "?3/3"}.get(state, "—")
    res = res_or_state or {}
    state = str(res.get("verdict") or "")
    if state == DOWNGRADED:
        return "⚠降级"
    layers = res.get("layers") or {}
    app = [n for n in LAYERS
           if str((layers.get(n) or {}).get("state") or "") not in ("", SKIP)]
    if not app:
        return "—" if not state else "?"
    ok = [n for n in app if (layers[n] or {}).get("state") == PASS]
    sym = {VERIFIED: "✓", REFUTED: "✗", UNCERTAIN: "?"}.get(state, "?")
    return f"{sym}{len(ok)}/{len(app)}"


def format_layers(res: Dict[str, Any], indent: str = "  ") -> str:
    """三层 + 结论的终端排版（CLI 与 -i 详情共用）。"""
    lines = []
    for n in LAYERS:
        item = (res.get("layers") or {}).get(n) or {}
        st = str(item.get("state") or "")
        lines.append(f"{indent}{n} {LAYER_TITLES[n]}\u3000{STATE_SYMBOLS.get(st, '?')} "
                     f"{STATE_LABELS.get(st, st)}\u3000{item.get('reason') or ''}")
    v = str(res.get("verdict") or "")
    extra = "（历史人工判误报，已降级）" if res.get("history_downgraded") else ""
    lines.append(f"{indent}结论\u3000{VERDICT_SYMBOLS.get(v, '?')} {VERDICT_LABELS.get(v, v)}"
                 f"{extra}\u3000{res.get('reason') or ''}")
    if res.get("minimal_curl"):
        lines.append(f"{indent}最小复现\u3000{res['minimal_curl']}")
    return "\n".join(lines)

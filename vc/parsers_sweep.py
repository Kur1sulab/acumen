"""sweep 引擎原生产物的解析片段（由 parsers.py 调用）。

为什么单独拿出来：这些 JSON 是**自家引擎**直接写出来的，字段比第三方产物规整得多，
但形状按模式分裂成十几种（paths/ports/api/jsintel/fingerprint/baseline/evidence…），
塞进 parsers.py 会把那一坨通用嗅探逻辑淹掉。这里只做一件事：认得就转成
统一 finding / asset，不认得就返回 None 让上层继续按通用格式试。

设计红线（和 parsers.py 一致）：
  - 不联网、只读、不猜：形状对不上就交给别人，别硬解出一堆假漏洞。
  - 分级如实：路径可达 ≠ 高危；只有凭据/源码/配置这类真的能往下走的才给 high。
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from .parsers import ParseResult, _mk_asset, _mk_finding, norm_sev
from . import waf as wafmod

# ---------------------------------------------------------------- 形状识别


def _is_paths(obj: Any) -> bool:
    if not isinstance(obj, dict) or "alive" not in obj or isinstance(obj.get("open"), list):
        return False
    items = obj.get("alive") or []
    if not isinstance(items, list):
        return False
    if any(isinstance(x, dict) and ("final_url" in x or "verdict" in x) for x in items[:5]):
        return True
    # 0 命中时 alive 是 null/[]，靠包络字段认（base + baseline + notes 是全流程/敏感路径的壳）
    return isinstance(obj.get("baseline"), dict) and "base" in obj


def _is_ports(obj: Any) -> bool:
    return (isinstance(obj, dict) and isinstance(obj.get("open"), list)
            and "scanned" in obj and "target" in obj)


def _is_api(obj: Any) -> bool:
    return (isinstance(obj, dict) and isinstance(obj.get("all"), list)
            and any(isinstance(x, dict) and "hit" in x and "risk" in x
                    for x in obj["all"][:5]))


def _is_jsintel(obj: Any) -> bool:
    return (isinstance(obj, dict) and isinstance(obj.get("scripts"), dict)
            and "endpoints" in obj and ("sensitive" in obj or "domains" in obj))


def _is_fingerprint(obj: Any) -> bool:
    return (isinstance(obj, list) and bool(obj)
            and all(isinstance(x, dict) and "name" in x for x in obj[:5])
            and any("type" in x for x in obj[:5]))


def _is_baseline(obj: Any) -> bool:
    return (isinstance(obj, dict) and "check" in obj and "conclusion" in obj
            and isinstance(obj.get("risks"), list))


def _is_strike(obj: Any) -> bool:
    """深度验证（内建 litmus 内核）的 findings.json：findings + coverage 双键。"""
    return (isinstance(obj, dict) and isinstance(obj.get("findings"), list)
            and isinstance(obj.get("coverage"), list))


def _is_evidence(obj: Any) -> bool:
    """引擎取证目录里的 meta.json：命中点的复现材料。"""
    return (isinstance(obj, dict) and "url" in obj and "name" in obj
            and ("evidence" in obj or "recheck" in obj) and "risk" in obj)



# 空结果文件的文件名 → 它代表哪个动作跑完了（引擎 0 命中时写空数组）
_EMPTY_KIND = {
    "fingerprint": "sweep_fingerprint",
    "paths": "sweep_paths",
    "api_unauth": "sweep_api",
    "jsintel": "sweep_jsintel",
    "ports": "sweep_ports",
}


def detect(obj: Any) -> str:
    for name, fn in _SNIFFERS:
        try:
            if fn(obj):
                return name
        except Exception:
            continue
    return ""


# ---------------------------------------------------------------- 通用小工具

# 顶级目录名 → 主机。引擎的产物按 out/<host_port>/… 落盘，文件名本身不带主机，
# 不从这里捞就只能记成 "unknown"，一条漏洞挂不上资产等于白挖。
_HOST_DIR = re.compile(r"^(?:https?_)?(\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9.-]+\.[a-z]{2,})(?:_(\d{2,5}))?$", re.I)


def host_from_path(path: str) -> str:
    """从产物路径里反推主机（out/http_1.2.3.4_8443/x.json → 1.2.3.4:8443）。"""
    # 反斜杠也当分隔符：Windows 上跑出来的产物路径回到别的系统上看时照样要认
    norm = os.path.normpath(os.path.abspath(path)).replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    for seg in reversed(parts[:-1]):
        m = _HOST_DIR.match(seg)
        if not m:
            continue
        host, port = m.group(1), m.group(2)
        return f"{host}:{port}" if port else host
    return ""


_MASK = re.compile(r"(?i)((?:pass(?:wd|word)?|secret|token|key|sk|ak)[\"']?\s*[:=]\s*[\"']?)([^\s\"',;&]{4,})")


def mask_secret(text: str) -> str:
    """把凭据值中间打码：留前 4 位够定位，不留全量——产物会被导出成报告发给别人。"""
    def _sub(m: re.Match) -> str:
        val = m.group(2)
        head = val[:4]
        return f"{m.group(1)}{head}{'*' * max(4, len(val) - 4)}"
    return _MASK.sub(_sub, str(text))


_PRINTABLE = re.compile(r"[^\x20-\x7e]+")


def clean_banner(text: str, limit: int = 80) -> str:
    """端口 banner 净化。

    二进制协议的 banner 是原始字节（memcached 的 VERSION 后面跟控制字符、
    MySQL 握手包里有版本+随机盐），直接塞进资产表会把界面弄成乱码。
    只留可打印 ASCII 里第一段像话的内容；实在抠不出字母就返回空，只显示服务名。
    """
    flat = " ".join(_PRINTABLE.sub(" ", str(text or "")).split())
    if len(re.findall(r"[A-Za-z]", flat)) < 4:
        return ""
    return flat[:limit]


_DOMAIN_PORT = re.compile(r"^(?:(https?)://)?([^/:]+)(?::(\d+))?/?$", re.I)


def split_host_port(host: str) -> tuple:
    """'1.2.3.4:8899' → ('1.2.3.4', 8899)；认不出端口就 (原名, None)。"""
    m = _DOMAIN_PORT.match((host or "").strip())
    if not m:
        return host, None
    port = int(m.group(3)) if m.group(3) else None
    return m.group(2), port


def _ev(*parts: Any) -> str:
    return " · ".join(str(p) for p in parts if p not in (None, "", [], {}))


# 敏感路径 → 分级。判据是「拿到它能不能继续往下走」，不是「名字听起来吓人」。
_PATH_SEV: List[tuple] = [
    (re.compile(r"(^|/)(\.env|\.env\.\w+|\.git/(config|HEAD)|\.svn/|\.hg/|web\.config|"
                r"WEB-INF/web\.xml|id_rsa|\.aws/credentials|\.npmrc|\.docker/config\.json)", re.I), "high"),
    (re.compile(r"(\.sql|\.bak|\.old|\.swp|\.zip|\.tar\.gz|\.7z|\.rar|backup|dump|"
                r"actuator/(env|heapdump|trace|threaddump)|druid/(index|sql)|"
                r"phpinfo|debug|console|jolokia|nacos|swagger|api-docs|v2/api-docs)", re.I), "high"),
    (re.compile(r"(actuator|metrics|health|info|env|logfile|trace|mappings|"
                r"admin|login|manage|manage\.html)", re.I), "medium"),
]


def _path_sev(path: str) -> str:
    for rx, sev in _PATH_SEV:
        if rx.search(path or ""):
            return sev
    return "low"


# ---------------------------------------------------------------- 各模式


_SEV_OK = ("critical", "high", "medium", "low", "info")


def parse_strike(obj: Dict[str, Any], host: str) -> ParseResult:
    """深度验证结论入账。

    与只读模式的差别就在 evidence 里那截 `[L2/confirmed]`：L1 只到「看得见」，
    L2 才是「拿到了真实数据」，交付线看的是这个，不是标题吓不吓人。
    """
    findings, assets = [], []
    items = [x for x in obj.get("findings") or [] if isinstance(x, dict)]
    seen_hosts = set()
    for it in items:
        target = str(it.get("target") or "")
        h = str(it.get("host") or "") or split_host_port(host)[0]
        sev = str(it.get("severity") or "").lower()
        level = str(it.get("level") or "")
        conf = str(it.get("confidence") or "")
        name = str(it.get("name") or it.get("check") or "深度验证发现")
        findings.append(_mk_finding(
            asset=h or host,
            endpoint=target,
            title=name,
            sev=sev if sev in _SEV_OK else "info",
            source=f"sweep-strike:{it.get('check') or ''}".rstrip(":"),
            evidence=_ev(it.get("evidence"), f"[{level}/{conf}]" if (level or conf) else "",
                         it.get("impact")),
            repro=str(it.get("repro") or ""),
            raw=json.dumps(it, ensure_ascii=False)[:1200],
        ))
        if h and h not in seen_hosts:
            seen_hosts.add(h)
            assets.append(_mk_asset(host=h, port=it.get("port") or "", source="sweep-strike"))

    cov = [x for x in obj.get("coverage") or [] if isinstance(x, dict)]
    skipped = [x for x in cov if str(x.get("state")) == "skip"]
    if cov:
        note = f"{len(items)} 条命中 · 覆盖 {len(cov) - len(skipped)} 项完成 / {len(skipped)} 项跳过"
    else:
        note = f"{len(items)} 条命中"
    return ParseResult("sweep_strike", findings, assets, note=note)


def _is_brute(obj: Any) -> bool:
    """brute.json：数组，元素带 host/service/tried/found。"""
    if not isinstance(obj, list) or not obj:
        return False
    first = obj[0]
    return isinstance(first, dict) and "service" in first and "found" in first and "tried" in first


def _brute_repro(h: Dict[str, Any]) -> str:
    """按协议给出可直接粘贴的复现命令（含凭据，报告内部用）。"""
    svc = str(h.get("service") or "")
    host, port = h.get("host") or "", h.get("port") or ""
    u, pw = h.get("user") or "", h.get("pass") or ""
    if svc == "redis":
        return f"redis-cli -h {host} -p {port} -a '{pw}' ping" if pw else \
               f"redis-cli -h {host} -p {port} ping"
    if svc == "mysql":
        return f"mysql -h {host} -P {port} -u{u} -p'{pw}' -e 'select version()'"
    if svc == "postgres":
        return f"PGPASSWORD='{pw}' psql -h {host} -p {port} -U {u} -c 'select version()'"
    if svc == "ftp":
        return f"curl -s ftp://{u}:'{pw}'@{host}:{port}/"
    if svc == "http-basic":
        return f"curl -i -k -u '{u}:{pw}' 'http://{host}:{port}/'"
    if svc == "telnet":
        return f"telnet {host} {port}   # 用户 {u} / 口令 {pw}"
    return f"# {svc} {host}:{port} {u}/{pw}"


def parse_brute(obj: List[Any], host: str) -> ParseResult:
    """弱口令命中入账：凭据本身就是证据，报告里连协议回包摘要一起给。"""
    findings, assets = [], []
    for r in obj:
        if not isinstance(r, dict):
            continue
        svc = str(r.get("service") or "")
        h = str(r.get("host") or host)
        port = r.get("port")
        found = [x for x in r.get("found") or [] if isinstance(x, dict)]
        if found:
            for hit in found:
                user = str(hit.get("user") or "")
                pw = str(hit.get("pass") or "")
                findings.append(_mk_finding(
                    asset=h, ip=h, port=port, endpoint=f"{svc}://{h}:{port}",
                    title=f"弱口令：{svc} {user}/{'（空口令）' if pw == '' else pw}",
                    sev="critical" if svc in ("redis", "mysql", "postgres") else "high",
                    source=f"sweep-brute:{svc}",
                    evidence=_ev(f"{svc} 登录成功", hit.get("note"),
                                 f"尝试 {r.get('tried')} 次"),
                    repro=_brute_repro(hit),
                    raw=json.dumps(hit, ensure_ascii=False)[:800],
                ))
        elif r.get("skipped"):
            # 没测成也要留痕：不写的话会变成「没弱口令」的假结论
            findings.append(_mk_finding(
                asset=h, ip=h, port=port, endpoint=f"{svc}://{h}:{port}",
                title=f"未能验证：{svc}（{r.get('skipped')}）",
                sev="info", source=f"sweep-brute:{svc}",
                evidence=_ev(r.get("skipped"), f"尝试 {r.get('tried')} 次"),
                repro="", raw=json.dumps(r, ensure_ascii=False)[:800],
            ))
    note = f"{len(findings)} 条（含未验证项，见 evidence）" if findings else "无弱口令命中"
    return ParseResult("sweep_brute", findings, assets, note=note)


def _is_cve(obj: Any) -> bool:
    """cve.json：target + products + matches。"""
    return (isinstance(obj, dict) and "matches" in obj and "products" in obj
            and isinstance(obj.get("matches"), list))


def parse_cve(obj: Dict[str, Any], host: str) -> ParseResult:
    """版本区间命中：L1，标题里就写清楚「可能受影响」，并给出验证动作。"""
    findings = []
    for m in [x for x in obj.get("matches") or [] if isinstance(x, dict)]:
        target = str(obj.get("target") or "")
        findings.append(_mk_finding(
            asset=split_host_port(host)[0] or host,
            endpoint=target,
            title=f"{m.get('id')} 可能受影响：{m.get('title')}",
            sev=str(m.get("severity") or "medium"),
            source=f"sweep-cve:{m.get('id')}",
            evidence=_ev(f"{m.get('product')} {m.get('version')}", m.get("evidence"),
                         "版本区间命中（L1，未验证可利用）"),
            repro=str(m.get("verify") or ""),
            cve=str(m.get("id") if str(m.get("id", "")).startswith("CVE-") else ""),
            raw=json.dumps(m, ensure_ascii=False)[:800],
        ))
    prods = [f"{p.get('product')} {p.get('version')}".strip()
             for p in obj.get("products") or [] if isinstance(p, dict)]
    note = f"{len(findings)} 条版本命中；识别产品：{', '.join(prods) or '无'}"
    return ParseResult("sweep_cve", findings, [], note=note)


def parse_paths(obj: Dict[str, Any], host: str) -> ParseResult:
    findings, assets = [], []
    alive = [x for x in obj.get("alive") or [] if isinstance(x, dict)]
    for it in alive:
        p = str(it.get("path") or "")
        url = str(it.get("final_url") or "")
        endpoint = url or (f"http://{host}{p}" if host and p.startswith("/") else p)
        status = it.get("status")
        size = it.get("size")
        findings.append(_mk_finding(
            asset=split_host_port(host)[0] or endpoint,
            endpoint=endpoint,
            title=f"敏感路径可访问：{p or endpoint}",
            sev=_path_sev(p or endpoint),
            source="sweep-paths",
            evidence=_ev(f"HTTP {status}" if status else "", f"{size}B" if size else "",
                         it.get("ctype"), "复验通过" if it.get("verified") else ""),
            repro=(f"curl -i -k '{endpoint}'" if endpoint.startswith("http") else
                   f"curl -i -k 'http://{host}{p}'"),
            raw=json.dumps(it, ensure_ascii=False)[:1200],
        ))
    if host:
        h, port = split_host_port(host)
        assets.append(_mk_asset(host=h, port=port, source="sweep-paths"))
    note = f"存活 {len(alive)} 条" if alive else "没有存活路径（基线过滤后为 0）"
    v = wafmod.classify_doc(obj)
    if not alive and v["state"] in (wafmod.BLOCKED, wafmod.UNKNOWN):
        # 「0 命中」不等于「都不存在」——这一句必须写进产物说明里。
        # 不写的话，报告上的「没有存活路径」就会被人当成「这些路径都没东西」。
        note = f"{note}；{wafmod.note(v)}，0 命中不代表这些路径不存在"
    return ParseResult("sweep_paths", findings, assets, note=note)


def parse_ports(obj: Dict[str, Any], host: str) -> ParseResult:
    assets = []
    rows = [x for x in obj.get("open") or [] if isinstance(x, dict) and x.get("open")]
    target = str(obj.get("ip") or obj.get("target") or host or "")
    for it in rows:
        port = it.get("port")
        banner = clean_banner(it.get("banner") or "")
        assets.append(_mk_asset(
            host=target or host, ip=str(obj.get("ip") or ""), port=port, proto="tcp",
            service=_ev(it.get("service"), banner),
            source="sweep-portscan",
        ))
    note = f"{len(rows)} 个开放端口（扫了 {obj.get('scanned', '?')} 个）"
    return ParseResult("sweep_ports", [], assets, note=note)


def parse_api(obj: Dict[str, Any], host: str) -> ParseResult:
    findings = []
    for it in [x for x in obj.get("all") or [] if isinstance(x, dict)]:
        if not it.get("hit"):
            continue
        url = str(it.get("final_url") or "")
        findings.append(_mk_finding(
            asset=split_host_port(host)[0] or url,
            endpoint=url or (f"http://{host}{it.get('path')}" if host else str(it.get("path") or "")),
            title=f"API 未授权访问：{it.get('name') or it.get('path')}",
            sev=norm_sev(it.get("risk") or "high"),
            source="sweep-api",
            evidence=_ev(it.get("evidence") or it.get("marker"),
                         f"HTTP {it.get('status')}" if it.get("status") else "",
                         f"{it.get('size')}B" if it.get("size") else ""),
            repro=(f"curl -i -k '{url}'" if url else
                   f"curl -i -k 'http://{host}{it.get('path')}'"),
            raw=json.dumps(it, ensure_ascii=False)[:1200],
        ))
    hits = len(findings)
    note = f"{hits} 个未授权命中（共试 {len(obj.get('all') or [])} 条端点）" if hits else "无未授权命中"
    return ParseResult("sweep_api", findings, [], note=note)


_KEYISH = re.compile(r"(?i)(pass|secret|token|key|credential|auth|apikey|sk-)")
# 长得就像凭据名的键：这些键名本身就说明问题，值只要不是空的就值得看一眼
_STRONG_KEY = re.compile(
    r"(?i)(api[_-]?key|secret|passw|pwd|token|credential|authorization|bearer|"
    r"private[_-]?key|access[_-]?key|akia[0-9a-z]{12,}|-----BEGIN|sk-[A-Za-z0-9])")
# 压缩 JS 里出现的键名/变量名是三四个字母的随机串（sk、ak、password），
# 这类弱键名必须自带一个像凭据的值才能留下
_VALUE_LITERAL = re.compile(r"""["']([A-Za-z0-9_\-+/=.]{10,})["']""")
_CODE_NOISE = re.compile(r"(function\s*\(|\)\s*\{|\}\s*\)|=>|;|\bvar\b|\breturn\b|[\u4e00-\u9fff])")
# 各家凭据都有自己的前缀，认前缀最靠谱（长度和字符集都可能撞车）
_SECRET_PREFIX = re.compile(
    r"^(AKIA|ASIA|sk-|sk_|ghp_|gho_|ghs_|github_pat_|xox[baprs]-|AIza|glpat-|npm_|"
    r"-----BEGIN|eyJ)")
_WORD_RUN = re.compile(r"[A-Za-z]{10,}")


def looks_like_secret(value: str) -> bool:
    """判断一个字符串「像不像真的凭据」。

    实测教训：引擎在压缩 JS 上按 key 名粗匹配，抓回来的「值」全是 8 个字符的
    标识符碎片（`enhanced_`、`consent_m`、`function` 截断），长度一致、无数字、
    像驼峰单词。凭据不长这样：要么带厂商前缀，要么够长且字母数字混排。
    """
    v = (value or "").strip()
    if not v:
        return False
    if _SECRET_PREFIX.match(v):
        return True
    if len(v) < 16:
        return False
    if not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)):
        return False
    # 连续 10 个以上纯字母 = 英文单词 / 标识符，不是随机密钥
    return not _WORD_RUN.search(v)


def js_secret_sev(key: str, value: str, snippet: str) -> str:
    """JS「敏感串」二次判定。返回分级，空串表示丢弃。

    为什么必须二次判定：引擎按 key 名做的粗匹配，在压缩过的第三方 JS 上会疯狂误报——
    `var sk={...}`、`ak:"endpoint_for_debug"` 这种压缩变量名会被当成「密钥」。
    实测一轮下来 8 条命中里 8 条是压缩 JS 变量名，全量入库等于把漏扫变成谣言机。
    判据只有两条：键名够不够像凭据、有没有真的取到一个像凭据的字面量。
    """
    k = (key or "").strip()
    strong = bool(_STRONG_KEY.search(k))
    if not strong and len(k) < 4:
        return ""
    cand = (value or "").strip()
    if not cand:
        m = _VALUE_LITERAL.search(snippet or "")
        cand = m.group(1) if m else ""
    if not cand or _CODE_NOISE.search(cand):
        return ""
    if not looks_like_secret(cand):
        return ""
    return "high"


def parse_jsintel(obj: Dict[str, Any], host: str) -> ParseResult:
    findings = []
    dropped = 0
    base = str(obj.get("base") or host or "")
    for it in [x for x in obj.get("sensitive") or [] if isinstance(x, dict)]:
        key = str(it.get("key") or "")
        sev = js_secret_sev(key, str(it.get("value") or ""), str(it.get("snippet") or ""))
        if not sev:
            dropped += 1
            continue
        findings.append(_mk_finding(
            asset=split_host_port(host)[0] or base,
            endpoint=base,
            title=f"JS 硬编码敏感信息：{key or '敏感串'}",
            sev=sev,
            source="sweep-jsintel",
            evidence=_ev(f"{it.get('file')}:{it.get('line')}" if it.get("file") else "",
                         mask_secret(it.get("snippet") or it.get("value") or "")),
            raw=json.dumps(it, ensure_ascii=False)[:1200],
        ))
    eps = obj.get("endpoints") or []
    note = (f"接口 {len(eps)} 条 · 敏感串 {len(findings)} 条"
            + (f"（丢弃 {dropped} 条压缩变量名误报）" if dropped else "")
            + f" · JS {obj.get('scripts', {}).get('downloaded', 0)}/{obj.get('scripts', {}).get('external', 0)}")
    return ParseResult("sweep_jsintel", findings, [], note=note)


def parse_fingerprint(obj: List[Any], host: str) -> ParseResult:
    names = [str(x.get("name")) for x in obj if isinstance(x, dict) and x.get("name")]
    h, p = split_host_port(host)
    assets = [_mk_asset(host=h or "unknown", port=p, fingerprint=", ".join(names),
                        source="sweep-fingerprint")] if names else []
    return ParseResult("sweep_fingerprint", [], assets,
                       note=("指纹 " + ", ".join(names)) if names else "无指纹命中")


_BASE_SEV = {"bad": "high", "critical": "high", "error": "medium", "high": "high",
             "warn": "low", "warning": "low", "info": "info", "ok": "info"}


def parse_baseline(obj: Dict[str, Any], host: str) -> ParseResult:
    check = str(obj.get("check") or "baseline")
    target = str(obj.get("target") or host or "")
    url = str(obj.get("url") or "")
    conclusion = (obj.get("conclusion") or {}).get("text") or ""
    findings = []
    for it in [x for x in obj.get("risks") or [] if isinstance(x, dict)]:
        findings.append(_mk_finding(
            asset=host or target,
            endpoint=url or target,
            title=f"{check}：{it.get('title')}",
            sev=_BASE_SEV.get(str(it.get("level") or "").lower(), "low"),
            source=f"sweep-{check}",
            evidence=_ev(it.get("detail") or conclusion),
            raw=json.dumps(it, ensure_ascii=False)[:1200],
        ))
    return ParseResult("sweep_baseline", findings, [],
                       note=(f"{check} · {len(findings)} 项风险" if findings else f"{check} · 无风险项"))


def parse_evidence(obj: Dict[str, Any], host: str) -> ParseResult:
    url = str(obj.get("url") or "")
    finding = _mk_finding(
        asset=split_host_port(host)[0] or url,
        endpoint=url,
        title=str(obj.get("name") or url),
        sev=norm_sev(obj.get("risk") or "medium"),
        source="sweep-evidence",
        evidence=_ev(obj.get("evidence"), f"HTTP {obj.get('status')}" if obj.get("status") else "",
                     f"{obj.get('size')}B" if obj.get("size") else "",
                     "存活" if obj.get("live") else "已失活"),
        raw=json.dumps(obj, ensure_ascii=False)[:1200],
    )
    return ParseResult("sweep_evidence", [finding], [], note=str(obj.get("name") or ""))




def parse(text: str, path: str = "") -> Optional[ParseResult]:
    """认得就返回聚合结果，认不得返回 None（让上层继续按通用 JSON 试）。

    一个文件里可能有多个对象（JSONL），也可能一个都没有；全都不认得才算不认得。
    """
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    objs: List[Any] = []
    try:
        objs = [json.loads(stripped)]
    except json.JSONDecodeError:
        for line in stripped.splitlines():
            line = line.strip()
            if not line.startswith(("{", "[")):
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if not objs:
        return None

    # 引擎「没有命中」时写的是空数组/空对象，而不是不写文件。
    # 这类文件不算垃圾：页面要能让用户看出「这一项跑过、结果是 0」，而不是「格式不认识」。
    if all(o == [] or o == {} for o in objs):
        stem = os.path.basename(path).split(".")[0].lower()
        kind = _EMPTY_KIND.get(stem)
        if kind:
            return ParseResult(kind, [], [], note=f"{stem}：引擎跑完，0 命中")
        return None

    host = host_from_path(path) if path else ""
    agg = ParseResult("sweep", [], [])
    hit = 0
    notes: List[str] = []
    for obj in objs:
        kind = detect(obj)
        fn = _PARSERS.get(kind)
        if not fn:
            continue
        hit += 1
        r = fn(obj, host)
        # WAF 三态跟着产物走：每份产物先判一次「这轮到底拿到内容没有」，再贴到它产出的
        # 每条命中上。贴在这个汇合点而不是各 parse_* 里，是因为十几种产物形状只在这里
        # 归一——漏一个模式，就漏掉一整类「被拦当不存在」。
        if isinstance(obj, dict):
            v = wafmod.classify_doc(obj)
            for f in r.findings:
                f.setdefault("waf_state", v["state"])
                f.setdefault("waf", v["waf"])
        # 把引擎自己记下的 base 挂到每条命中上：复验要按原样的 scheme/host/port 重跑，
        # 光靠 asset+port 反推会把 http 目标猜成 https，重跑必然空手而归（假「已消失」）。
        base = str(obj.get("base") or "").strip() if isinstance(obj, dict) else ""
        if base:
            for f in r.findings:
                f.setdefault("base", base)
        agg.findings.extend(r.findings)
        agg.assets.extend(r.assets)
        if r.note:
            notes.append(f"{kind.replace('sweep_', '')}: {r.note}")
        agg.fmt = kind if len(objs) == 1 else "sweep"
    if not hit:
        return None
    agg.note = "；".join(dict.fromkeys(notes))[:400]
    return agg


# ---------------------------------------------------------------- 注册表
#
# 放在文件末尾：嗅探器引用的是下面这些解析函数，定义顺序反了会在 import 阶段就 NameError。
_SNIFFERS = (
    ("sweep_strike", _is_strike),
    ("sweep_cve", _is_cve),
    ("sweep_brute", _is_brute),
    ("sweep_paths", _is_paths),
    ("sweep_ports", _is_ports),
    ("sweep_api", _is_api),
    ("sweep_jsintel", _is_jsintel),
    ("sweep_baseline", _is_baseline),
    ("sweep_evidence", _is_evidence),
    ("sweep_fingerprint", _is_fingerprint),
)

_PARSERS = {
    "sweep_strike": parse_strike,
    "sweep_cve": parse_cve,
    "sweep_brute": parse_brute,
    "sweep_paths": parse_paths,
    "sweep_ports": parse_ports,
    "sweep_api": parse_api,
    "sweep_jsintel": parse_jsintel,
    "sweep_baseline": parse_baseline,
    "sweep_evidence": parse_evidence,
    "sweep_fingerprint": parse_fingerprint,
}

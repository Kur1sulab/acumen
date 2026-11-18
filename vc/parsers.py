"""漏扫产物解析器：把各家工具的原始输出归一化成统一的 finding / asset 记录。

支持格式（按 sniff 结果分派）：
  nuclei_jsonl   nuclei -jsonl 输出（每行一个 JSON）
  nuclei_text    nuclei 文本输出  [template-id] [protocol] [severity] url
  xray           xray --json-output（JSONL 或 {"data":{"detail":[...]}}）
  nmap_xml       nmap -oX 输出（开放端口 → asset；脚本命中 → finding）
  nessus         Nessus .nessus XML（ReportHost/ReportItem）
  yakit_port     yakit 端口扫描行  [Result] {"fingerprint":..,"host":..,"port":..}
  json_generic   通用 JSON 数组/对象（字段名模糊匹配，中英文皆可）
  csv_table      通用 CSV / TSV（表头映射，中英文皆可）
  md_table       Markdown 表格（报告里的漏洞清单）

统一记录：
  finding: {asset, ip, port, endpoint, param, title, cve, sev, source, evidence,
            first_seen, last_seen, count}
  asset:   {host, ip, port, proto, service, title, fingerprint, source}

设计约束：只读、不联网、单文件超过 MAX_BYTES 直接跳过并记原因。
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl

MAX_BYTES = 20 * 1024 * 1024  # 单文件上限 20MB，超过只记日志不解析

# 解析器代次。改了解析逻辑（新增格式、修判定）就把这个数字 +1：
# 摄入缓存以 "g<代次>:<内容哈希>" 作为指纹，代次一变全部文件自动重解析一次。
# 不加这个的话，升级解析器之后旧产物永远停在「格式无法识别」，用户得手动 --force。
PARSER_GEN = 5


def gen_digest(path: str) -> str:
    """带代次的文件指纹（缓存键）。"""
    return f"g{PARSER_GEN}:" + file_fingerprint(path)


# ---------------------------------------------------------------- 严重度归一

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_SEV_ALIAS = {
    # 英文
    "critical": "critical", "crit": "critical", "urgent": "critical",
    "high": "high", "important": "high",
    "medium": "medium", "moderate": "medium", "mid": "medium",
    "low": "low", "minor": "low",
    "info": "info", "informational": "info", "none": "info", "unknown": "info",
    "notice": "low",
    # 中文（绿盟/天镜/360/自定义报告常见）
    "严重": "critical", "紧急": "critical", "超危": "critical", "致命": "critical",
    "高危": "high", "高": "high", "高风险": "high",
    "中危": "medium", "中": "medium", "中风险": "medium",
    "低危": "low", "低": "low", "低风险": "low",
    "信息": "info", "提示": "info", "无": "info",
    # 繁体（港台报告）
    "嚴重": "critical", "極危": "critical", "高危": "high", "高風險": "high",
    "中危": "medium", "中風險": "medium", "低危": "low", "低風險": "low",
    "資訊": "info", "訊息": "info", "提示訊息": "info",
    # nessus 数字
    "4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info",
}


def norm_sev(value: Any) -> str:
    """任意严重度写法 → critical/high/medium/low/info。"""
    if value is None:
        return "info"
    s = str(value).strip().lower()
    if not s:
        return "info"
    if s in _SEV_ALIAS:
        return _SEV_ALIAS[s]
    # 去掉常见修饰："高危漏洞" / "High Risk" / "cvss:7.5"
    for k, v in _SEV_ALIAS.items():
        if k.isascii() and len(k) > 2 and k in s:
            return v
        if not k.isascii() and k in s:
            return v
    m = re.search(r"(\d+(?:\.\d+)?)", s)
    if m:
        try:
            score = float(m.group(1))
        except ValueError:
            return "info"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
    return "info"


def sev_rank(sev: str) -> int:
    return SEV_RANK.get(sev, 0)


def max_sev(*sevs: str) -> str:
    best = "info"
    for s in sevs:
        if sev_rank(s) > sev_rank(best):
            best = s
    return best


# ---------------------------------------------------------------- 小工具

def _asset_of(url: str) -> str:
    """URL/host 串 → 资产标识（host[:port]），解析不出就原样返回。"""
    if not url:
        return ""
    s = str(url).strip()
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlsplit(s)
    except ValueError:
        return str(url).strip()
    host = p.hostname or ""
    if not host:
        return str(url).strip()
    port = p.port
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        return f"{host}:{port}"
    return host


def _port_of(url: str) -> Optional[int]:
    s = str(url or "").strip()
    if "://" not in s:
        s = "http://" + s
    try:
        return urlsplit(s).port
    except ValueError:
        return None


def _param_of(url: str) -> str:
    """从 URL 里取参数名（xray/nuclei 常用于区分同端点不同参数）。"""
    try:
        q = urlsplit(str(url)).query
    except ValueError:
        return ""
    if not q:
        return ""
    return ",".join(sorted({k for k, _ in parse_qsl(q, keep_blank_values=True)}))[:200]


# ---------------------------------------------------------------- CVE 识别

# 分隔符要兼收：半角横线/下划线/空白 + 全角－(U+FF0D) + 短破折–、长破折—、减号−
_CVE_SEP = r"[-_\s\uFF0D\u2013\u2014\u2212]{0,2}"
_CVE_RE = re.compile(r"\bCVE" + _CVE_SEP + r"(\d{4})" + _CVE_SEP + r"(\d{4,7})\b", re.I)


def cve_of(*texts: Any) -> str:
    """从任意文本里抽 CVE 编号，兼容 CVE-2021-44228 / cve_2021_44228 / CVE 2021 44228。"""
    seen: List[str] = []
    for t in texts:
        if t is None:
            continue
        for m in _CVE_RE.finditer(str(t)):
            cid = "CVE-%s-%s" % (m.group(1), m.group(2))
            if cid not in seen:
                seen.append(cid)
    return ",".join(sorted(seen))


def _trim(text: Any, limit: int = 600) -> str:
    s = "" if text is None else str(text)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def _pick(d: Dict[str, Any], *names: str) -> Any:
    """按候选键名（大小写/下划线不敏感）取值。"""
    if not isinstance(d, dict):
        return None
    lower = {str(k).strip().lower().replace("_", "").replace("-", ""): v for k, v in d.items()}
    for name in names:
        key = name.lower().replace("_", "").replace("-", "")
        if key in lower and lower[key] not in (None, ""):
            return lower[key]
    return None


def _mk_finding(**kw) -> Dict[str, Any]:
    f = {
        "asset": "", "ip": "", "port": None, "endpoint": "", "param": "",
        "title": "", "cve": "", "sev": "info", "source": "", "evidence": "",
        "first_seen": "", "last_seen": "", "count": 1,
    }
    f.update({k: v for k, v in kw.items() if v is not None})
    f["sev"] = norm_sev(f.get("sev"))
    f["title"] = _trim(f.get("title"), 200)
    f["asset"] = _trim(f.get("asset") or _asset_of(f.get("endpoint", "")), 200)
    if f.get("port") in (None, ""):
        f["port"] = _port_of(f.get("endpoint", ""))
    f["endpoint"] = _trim(f.get("endpoint"), 600)
    f["evidence"] = _trim(f.get("evidence"), 600)
    # CVE：显式值也要过一遍提取（template-id 可能是 CVE-xxx 也可能是 exposed-panel，只留真编号）
    # 显式值抽得出就用它，抽不出再退回标题 / 证据 / 原始文本
    f["cve"] = _trim(cve_of(f.get("cve")) or cve_of(f["title"], f["evidence"], kw.get("raw")), 200)
    if f["param"] in ("", None) and f["endpoint"]:
        f["param"] = _param_of(f["endpoint"])
    return f


def _mk_asset(**kw) -> Dict[str, Any]:
    a = {"host": "", "ip": "", "port": None, "proto": "", "service": "",
         "title": "", "fingerprint": "", "source": ""}
    a.update({k: v for k, v in kw.items() if v is not None})
    a["host"] = _trim(a.get("host"), 200)
    for k in ("service", "title", "fingerprint"):
        a[k] = _trim(a.get(k), 300)
    a["proto"] = _trim(a.get("proto"), 20)
    return a


class ParseResult:
    __slots__ = ("fmt", "findings", "assets", "note")

    def __init__(self, fmt: str, findings: List[Dict[str, Any]], assets: List[Dict[str, Any]], note: str = ""):
        self.fmt = fmt
        self.findings = findings
        self.assets = assets
        self.note = note

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ParseResult {self.fmt} findings={len(self.findings)} assets={len(self.assets)} {self.note}>"


# ---------------------------------------------------------------- nuclei

_NUCLEI_TEXT = re.compile(r"^\[([^\]\s]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)")


def parse_nuclei_jsonl(text: str) -> ParseResult:
    findings: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        url = obj.get("matched-at") or obj.get("host") or obj.get("url") or ""
        findings.append(_mk_finding(
            title=info.get("name") or obj.get("template-id") or obj.get("templateID") or "nuclei hit",
            sev=info.get("severity") or obj.get("severity"),
            endpoint=url,
            ip=obj.get("ip") or "",
            port=obj.get("port") or _port_of(url),
            source="nuclei",
            # nuclei 的 CVE 编号绝大多数写在模板 ID 里（CVE-2021-44228.yaml → template-id 同名）
            cve=obj.get("template-id") or obj.get("templateID") or obj.get("id") or "",
            evidence=obj.get("matcher-name") or "; ".join(map(str, obj.get("extracted-results") or [])),
            first_seen=obj.get("timestamp") or "",
            last_seen=obj.get("timestamp") or "",
        ))
    return ParseResult("nuclei_jsonl", findings, [])


def parse_nuclei_text(text: str) -> ParseResult:
    findings: List[Dict[str, Any]] = []
    for line in text.splitlines():
        m = _NUCLEI_TEXT.match(line.strip())
        if not m:
            continue
        tid, proto, sev, url = m.groups()
        if norm_sev(sev) == "info" and sev.lower() not in ("info", "unknown", "信息", "提示"):
            # 三个方括号但严重度不认识 → 大概是 yakit 之类的进度行，跳过
            if "[" not in line[1:]:
                continue
        findings.append(_mk_finding(
            title=tid, sev=sev, endpoint=url, source="nuclei",
            evidence=line.strip()[:400], port=_port_of(url),
        ))
    return ParseResult("nuclei_text", findings, [])


# ---------------------------------------------------------------- xray

def parse_xray(obj: Any) -> ParseResult:
    findings: List[Dict[str, Any]] = []

    def take(item: Dict[str, Any]) -> None:
        if not isinstance(item, dict):
            return
        target = item.get("target") if isinstance(item.get("target"), dict) else {}
        detail = item.get("detail") if isinstance(item.get("detail"), dict) else {}
        url = (target or {}).get("url") or item.get("url") or detail.get("url") or ""
        title = (item.get("plugin") or item.get("vuln_class") or detail.get("plugin")
                 or detail.get("vuln_class") or item.get("title") or "xray hit")
        findings.append(_mk_finding(
            title=title,
            sev=item.get("severity") or detail.get("severity") or item.get("level"),
            endpoint=url,
            source="xray",
            evidence=detail.get("payload") or detail.get("snapshot") or detail.get("extra") or "",
            first_seen=str(item.get("create_time") or ""),
            last_seen=str(item.get("create_time") or ""),
        ))

    if isinstance(obj, list):
        for it in obj:
            take(it)
    elif isinstance(obj, dict):
        if isinstance(obj.get("data"), dict) and isinstance(obj["data"].get("detail"), list):
            for it in obj["data"]["detail"]:
                # detail 里通常是单个漏洞的明细， título 在内层
                if isinstance(it, dict) and ("target" in it or "plugin" in it):
                    take(it)
                elif isinstance(it, dict):
                    take({"detail": it})
        elif isinstance(obj.get("detail"), list):
            for it in obj["detail"]:
                take(it if isinstance(it, dict) else {})
        elif "target" in obj or "plugin" in obj or "vuln_class" in obj:
            take(obj)
    return ParseResult("xray", findings, [])


# ---------------------------------------------------------------- nmap

def parse_nmap_xml(text: str) -> ParseResult:
    findings: List[Dict[str, Any]] = []
    assets: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return ParseResult("nmap_xml", [], [], note="XML 解析失败")

    for host in root.iter("host"):
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr") or ""
        hostnames = [h.get("name") for h in host.findall("./hostnames/hostname") if h.get("name")]
        name = hostnames[0] if hostnames else ip
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                pnum = int(port.get("portid") or 0)
            except ValueError:
                pnum = 0
            svc = port.find("service")
            service = ""
            if svc is not None:
                service = " ".join(x for x in [svc.get("name"), svc.get("product"), svc.get("version")] if x)
            assets.append(_mk_asset(host=name, ip=ip, port=pnum, proto=port.get("protocol") or "",
                                   service=service, source="nmap"))
            for script in port.findall("script"):
                sid = script.get("id") or ""
                out = script.get("output") or ""
                if not out:
                    continue
                sev = "info"
                m = re.search(r"CVSS(?:\s*[:=])\s*(\d+(?:\.\d+)?)", out, re.I)
                if m:
                    sev = norm_sev(m.group(1))
                elif re.search(r"CVE-\d{4}-\d+", out):
                    sev = "medium"
                findings.append(_mk_finding(
                    title=f"nmap:{sid}", sev=sev, endpoint=f"{ip}:{pnum}", asset=name or ip,
                    ip=ip, port=pnum, source="nmap", evidence=out[:400],
                ))
    return ParseResult("nmap_xml", findings, assets)


# ---------------------------------------------------------------- nessus

def parse_nessus(text: str) -> ParseResult:
    findings: List[Dict[str, Any]] = []
    assets: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return ParseResult("nessus", [], [], note="XML 解析失败")
    for rh in root.iter("ReportHost"):
        host = rh.get("name") or ""
        ip = ""
        for tag in rh.findall("./HostProperties/tag"):
            if tag.get("name") in ("host-ip", "host-fqdn") and tag.text:
                if tag.get("name") == "host-ip":
                    ip = tag.text
                elif not host:
                    host = tag.text
        for item in rh.iter("ReportItem"):
            sev = norm_sev(item.get("severity"))
            try:
                pnum = int(item.get("port") or 0)
            except ValueError:
                pnum = 0
            title = item.get("pluginName") or item.get("pluginID") or "nessus plugin"
            desc = item.findtext("description") or ""
            findings.append(_mk_finding(
                title=f"{title} (plugin {item.get('pluginID','')})".strip(),
                sev=sev, asset=host or ip, ip=ip, port=pnum,
                endpoint=f"{host or ip}:{pnum}", source="nessus", evidence=desc,
                cve=",".join(t.text.strip() for t in item.findall("cve") if t.text and t.text.strip()),
            ))
            assets.append(_mk_asset(host=host or ip, ip=ip, port=pnum, service=item.get("svc_name") or "",
                                    fingerprint=f"nessus:{item.get('pluginFamily','')}", source="nessus"))
    return ParseResult("nessus", findings, assets)


# ---------------------------------------------------------------- yakit 端口扫描

_YAKIT_LINE = re.compile(r"^\[Result\]\s*(\{.*\})\s*$")


def parse_yakit_port(text: str) -> ParseResult:
    assets: List[Dict[str, Any]] = []
    for line in text.splitlines():
        m = _YAKIT_LINE.match(line.strip())
        if not m:
            continue
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if not obj.get("isOpen"):
            continue
        host = obj.get("host") or obj.get("ip") or ""
        try:
            pnum = int(obj.get("port") or 0)
        except (TypeError, ValueError):
            pnum = 0
        assets.append(_mk_asset(
            host=host, ip=obj.get("ip") or (host if re.fullmatch(r"[\d.]+", host) else ""),
            port=pnum, proto="https" if str(obj.get("fingerprint", "")).find("https") >= 0 else "tcp",
            service=obj.get("fingerprint") or "", title=obj.get("htmlTitle") or "",
            fingerprint=obj.get("fingerprint") or "", source="yakit",
        ))
    return ParseResult("yakit_port", [], assets)


# ---------------------------------------------------------------- 通用 JSON / CSV / MD

_TITLE_KEYS = ("title", "vulnname", "vuln_name", "vulntitle", "vuln", "vulnerability", "name",
               "漏洞名称", "漏洞标题", "漏洞", "漏洞类型", "风险名称", "风险项", "检测项",
               "问题名称", "pluginname", "templateid", "template-id", "issue",
               # 繁体（港台报告）/ 其他常见叫法
               "發現", "发现", "漏洞名稱", "問題", "風險描述", "風險名稱", "標題", "检查项", "缺陷")
_SEV_KEYS = ("severity", "risk", "risklevel", "level", "危险等级", "风险等级", "严重程度", "等级", "cvss",
             "嚴重度", "嚴重程度", "風險等級", "危險等級", "分級", "風險")
# 宽松：只用来取值
_URL_KEYS = ("url", "target", "host", "asset", "endpoint", "ip", "地址", "url地址", "目标url", "目标地址",
             "affectedurl", "affected", "matched-at")
# 严格：只有这些键出现，才认为「这条记录描述的是某个端点上的问题」（host/ip 单独出现更像资产清单）
_STRICT_URL_KEYS = ("url", "target", "endpoint", "matched-at", "affectedurl", "affected",
                    "url地址", "目标url", "目标地址")
_HOST_KEYS = {"host", "hostname", "ip", "url", "地址", "主机", "ip地址"}
# 资产清单特征字段（端口探测/指纹/存活探测的产物大多是这种形状）
_INV_MARKERS = {"status", "statuscode", "server", "powered", "title", "ct", "len", "fw", "header", "code"}
_VULN_MARKERS = {"vuln", "vulnname", "vulnerability", "cve", "cwe", "template-id", "templateid", "payload"}
_CVE_KEYS = ("cve", "cveid", "cve_id", "cves", "cve编号", "漏洞编号", "vulnid", "vuln_id", "cvelist")
_PARAM_KEYS = ("param", "parameter", "参数", "参数名")
_EVID_KEYS = ("evidence", "detail", "description", "output", "payload", "proof", "描述", "证据", "详情")


def _json_items(obj: Any) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if isinstance(obj, list):
        items = [x for x in obj if isinstance(x, dict)]
    elif isinstance(obj, dict):
        for k in ("findings", "results", "data", "items", "vulns", "vulnerabilities", "rows", "list"):
            v = obj.get(k)
            if isinstance(v, list):
                items = [x for x in v if isinstance(x, dict)]
                break
        if not items:
            items = [obj]
    return items


def looks_like_inventory(items: List[Dict[str, Any]]) -> bool:
    """判断这批对象是不是「资产/存活/指纹清单」而不是漏洞记录。

    特征：有 host/ip 之类的键 + 至少两个 status/server/title/len/ct 这类探测字段，
    且没有 severity、也没有 vuln/cve/template 这类漏洞标记。
    """
    if not items:
        return False
    hit = 0
    for it in items:
        keys = {str(k).strip().lower() for k in it}
        has_host = bool(keys & _HOST_KEYS)
        markers = len(keys & _INV_MARKERS)
        has_sev = bool(keys & {k.lower() for k in _SEV_KEYS})
        has_vuln = bool(keys & _VULN_MARKERS)
        if has_host and markers >= 2 and not has_sev and not has_vuln:
            hit += 1
    return hit >= max(1, int(len(items) * 0.6))


def parse_host_inventory(obj: Any) -> ParseResult:
    """资产/指纹清单 → asset 记录（host + 标题 + 服务/指纹 + 端口）。"""
    assets: List[Dict[str, Any]] = []
    for it in _json_items(obj):
        host = _pick(it, "host", "hostname", "ip", "url", "地址", "主机")
        if not host:
            continue
        url_like = str(host)
        assets.append(_mk_asset(
            host=_asset_of(url_like) if "://" in url_like else str(host).strip(),
            ip=str(_pick(it, "ip", "ipaddr", "ip地址") or ""),
            port=_pick(it, "port", "端口") or _port_of(url_like),
            service=_pick(it, "server", "powered", "service", "services", "banner") or "",
            title=_pick(it, "title", "网页标题") or "",
            fingerprint=_pick(it, "fw", "framework", "fingerprint", "technologies") or "",
            source="inventory",
        ))
    return ParseResult("host_inventory", [], assets,
                       note="识别为资产清单" if assets else "资产清单里没有 host 字段")


def _is_finding_row(row: Dict[str, Any]) -> bool:
    """一行记录要算"漏洞"，至少得有分级，或者有明确的端点字段。"""
    if _pick(row, *_SEV_KEYS):
        return True
    return bool(_pick(row, *_STRICT_URL_KEYS))


_REQ_LINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/[0-9.]", re.I)
_HOST_LINE = re.compile(r"^host:\s*(\S+)", re.I)
_STATUS_LINE = re.compile(r"^HTTP/[0-9.]+\s+(\d{3})", re.I)


def _is_http_packet(it: Any) -> bool:
    """360/人工报告常见的「请求+响应」包记录：{title, level, req:[...], resp:[...]}。"""
    if not isinstance(it, dict):
        return False
    req = it.get("req") or it.get("request") or it.get("request_raw")
    if not (isinstance(req, list) and req and isinstance(req[0], str)):
        return False
    return any(_REQ_LINE.match(str(x).strip()) for x in req[:3])


def parse_http_packet(it: Dict[str, Any]) -> Dict[str, Any]:
    """把一条原始 HTTP 包记录还原成漏洞条目：Host 头给资产、请求行给端点、level 给分级。"""
    req = [str(x) for x in (it.get("req") or it.get("request") or [])]
    resp = [str(x) for x in (it.get("resp") or it.get("response") or [])]
    method, target, host, port = "", "", "", None
    for line in req:
        s = line.strip()
        m = _REQ_LINE.match(s)
        if m and not method:
            method, target = m.group(1).upper(), m.group(2)
            continue
        m = _HOST_LINE.match(s)
        if m and not host:
            hv = m.group(1).strip()
            if hv.count(":") == 1 and hv.rsplit(":", 1)[1].isdigit():
                host, port = hv.rsplit(":", 1)[0], int(hv.rsplit(":", 1)[1])
            else:
                host = hv
    # 请求行里可能是绝对 URL
    if "://" in target:
        u = urlsplit(target)
        host = host or (u.hostname or "")
        if u.port:
            port = u.port
        target = u.path + (("?" + u.query) if u.query else "")
    scheme = "https" if port in (443, 8443) else "http"
    endpoint = f"{scheme}://{host}{':' + str(port) if port else ''}{target}" if host else target
    # 请求体里形如 a=1&b=2 的参数
    params: List[str] = []
    if req:
        body_sep = req.index("") if "" in req else (len(req) - 1)
        for line in req[body_sep + 1:]:
            for k in re.findall(r"([A-Za-z_][\w\[\]\.-]*)\s*=", line):
                if k not in params:
                    params.append(k)
    status = ""
    for line in resp:
        m = _STATUS_LINE.match(line.strip())
        if m:
            status = m.group(1)
            break
    ev_bits = []
    if method:
        ev_bits.append(f"{method} {target}")
    if status:
        ev_bits.append(f"→ {status}")
    # 只在响应体里取证据（跳过响应头，否则抓到的是 Content-Type 这种噪声）
    resp_tail = resp[resp.index("") + 1:] if "" in resp else resp[1:]
    resp_body = next((x.strip() for x in resp_tail if x.strip()), "")
    if resp_body:
        ev_bits.append(resp_body[:160])
    n_pk = it.get("n_packets")
    if isinstance(n_pk, int) and n_pk > 1:
        ev_bits.append(f"（同一问题共 {n_pk} 个包）")
    is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))
    return _mk_finding(
        title=_pick(it, *_TITLE_KEYS) or "",
        sev=_pick(it, *_SEV_KEYS),
        endpoint=endpoint,
        asset=host,
        ip=(host if is_ip else ""),
        port=port,
        param=", ".join(params),
        source="packet",
        evidence=" ".join(ev_bits),
    )


def parse_json_generic(obj: Any) -> ParseResult:
    items = _json_items(obj)
    packets = [it for it in items if _is_http_packet(it)]
    if packets and len(packets) == len(items):
        findings = [f for f in (parse_http_packet(it) for it in packets) if f["title"]]
        note = f"{len(findings)} 个请求/响应包" if findings else "包里没有标题字段"
        return ParseResult("http_packet", findings, [], note=note)
    if looks_like_inventory(items):
        return parse_host_inventory(obj)
    findings: List[Dict[str, Any]] = []
    for it in items:
        title = _pick(it, *_TITLE_KEYS)
        if not title or not _is_finding_row(it):
            continue
        url = _pick(it, *_URL_KEYS) or ""
        findings.append(_mk_finding(
            title=title, sev=_pick(it, *_SEV_KEYS), endpoint=str(url),
            param=str(_pick(it, *_PARAM_KEYS) or ""), source="json",
            evidence=_pick(it, *_EVID_KEYS) or "",
        ))
    return ParseResult("json_generic", findings, [])


def _rows_to_findings(rows: List[Dict[str, str]], source: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in rows:
        title = _pick(row, *_TITLE_KEYS)
        if not title or not _is_finding_row(row):
            continue
        url = _pick(row, *_URL_KEYS) or ""
        out.append(_mk_finding(
            title=title, sev=_pick(row, *_SEV_KEYS), endpoint=str(url),
            param=str(_pick(row, *_PARAM_KEYS) or ""), source=source,
            evidence=_pick(row, *_EVID_KEYS) or "",
            cve=str(_pick(row, *_CVE_KEYS) or ""),
        ))
    return out


def parse_csv_table(text: str) -> ParseResult:
    sample = text[:4096]
    delimiter = ","
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        # 嗅探失败按扩展名习惯兜底：制表符多就用 \t
        if sample.count("\t") > sample.count(","):
            delimiter = "\t"
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    rows = [dict(r) for r in reader if r]
    if not rows:
        return ParseResult("csv_table", [], [], note="空表")
    findings = _rows_to_findings(rows, "csv")
    if not findings:
        cols = ", ".join(list(rows[0].keys())[:6])
        return ParseResult("csv_table", [], [], note=f"无漏洞列（首行表头：{cols}）")
    return ParseResult("csv_table", findings, [])


def parse_md_table(text: str) -> ParseResult:
    lines = text.splitlines()
    tables: List[Tuple[List[str], List[List[str]]]] = []
    i = 0
    while i < len(lines) - 1:
        if lines[i].strip().startswith("|") and re.match(r"^\s*\|[\s:\-|]+\|\s*$", lines[i + 1]):
            header = [c.strip() for c in lines[i].strip().strip("|").split("|")]
            rows: List[List[str]] = []
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("|"):
                cells = [c.strip() for c in lines[j].strip().strip("|").split("|")]
                rows.append(cells)
                j += 1
            tables.append((header, rows))
            i = j
        else:
            i += 1
    findings: List[Dict[str, Any]] = []
    for header, rows in tables:
        for cells in rows:
            row = {header[k] if k < len(header) else f"c{k}": (cells[k] if k < len(cells) else "")
                   for k in range(max(len(header), len(cells)))}
            findings.extend(_rows_to_findings([row], "md"))
    if not findings:
        return ParseResult("md_table", [], [], note="表格里没有可识别的漏洞列")
    return ParseResult("md_table", findings, [])


# ---------------------------------------------------------------- 分派

def sniff(filename: str, text: str) -> str:
    """按内容特征判断格式（不轻信扩展名）。"""
    head = text.lstrip()[:4000]
    low_name = os.path.basename(filename).lower()
    if low_name.endswith(".nessus") or "<NessusClientData_v2" in head:
        return "nessus"
    if head.startswith("<?xml") or head.startswith("<nmaprun"):
        if "<nmaprun" in head or "<host" in head[:2000]:
            return "nmap_xml"
    if any(l.startswith('{"template-id"') or '"template-id"' in l[:200] for l in head.splitlines()[:5]):
        return "nuclei_jsonl"
    if _NUCLEI_TEXT.match(head.splitlines()[0].strip()) if head.splitlines() else False:
        return "nuclei_text"
    if "[Result]" in head and '"isOpen"' in head:
        return "yakit_port"
    if head.startswith("{") or head.startswith("["):
        first = head[:200]
        if '"target"' in first and ('"plugin"' in first or '"vuln_class"' in first or '"detail"' in first):
            return "xray"
        return "json_generic"
    if re.search(r"^\s*\|.*\|\s*$", head, re.M) and re.search(r"^\s*\|[\s:\-|]+\|\s*$", head, re.M):
        return "md_table"
    if head and ("," in head.splitlines()[0] or "\t" in head.splitlines()[0]):
        return "csv_table"
    return "unknown"


def iter_json_objects(text: str) -> List[Any]:
    """JSONL → 对象列表；整体 JSON → 单元素列表。"""
    stripped = text.strip()
    if not stripped:
        return []
    if stripped[0] in "{[":
        try:
            return [json.loads(stripped)]
        except json.JSONDecodeError:
            pass
    out: List[Any] = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line.startswith(("{", "[")):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def parse_file(path: str) -> ParseResult:
    """解析单个文件。任何异常都收敛成 note，不向上抛。"""
    norm = path.replace("\\", "/")
    # 引擎把基线结果同时写在 out/<host>/ 和 out/<host>/evidence/baseline/ 两处，
    # 两份内容一致；只解析一份，否则每条基线风险都会被记成两次命中。
    if "/evidence/baseline/" in norm:
        return ParseResult("skipped", [], [], note="基线产物副本（同一份已在上级目录入账）")
    # 引擎每个模式同时写 <name>.json（机读）和 <name>.txt（人读摘要）。
    # 有 json 在场时 txt 只是同一批事实的另一种排版，再解析一遍就是重复计数。
    stem, ext = os.path.splitext(os.path.basename(path))
    if stem.lower() in ("ports", "jsintel", "paths", "api_unauth", "fingerprint",
                        "secheaders", "webfiles") and ext.lower() in (".txt", ".md"):
        if os.path.exists(os.path.join(os.path.dirname(path), stem + ".json")):
            return ParseResult("skipped", [], [], note="引擎文本摘要（数据已从同名 .json 入账）")
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return ParseResult("error", [], [], note=f"读取失败：{exc}")
    if size > MAX_BYTES:
        return ParseResult("skipped", [], [], note=f"超过 {MAX_BYTES // 1024 // 1024}MB 上限，跳过")
    if size == 0:
        return ParseResult("skipped", [], [], note="空文件")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return ParseResult("error", [], [], note=f"打开失败：{exc}")

    fmt = sniff(path, text)
    if text.lstrip()[:1] in "{[":
        # 自家引擎的原生产物优先：它们是结构化事实，命中率比通用嗅探高得多
        try:
            from . import parsers_sweep
            native = parsers_sweep.parse(text, path)
        except Exception as exc:  # 引擎解析器自身出错也不能拖垮摄入
            native = None
            _ = exc
        if native is not None:
            return native
    try:
        if fmt == "nessus":
            return parse_nessus(text)
        if fmt == "nmap_xml":
            return parse_nmap_xml(text)
        if fmt == "nuclei_jsonl":
            return parse_nuclei_jsonl(text)
        if fmt == "nuclei_text":
            return parse_nuclei_text(text)
        if fmt == "yakit_port":
            return parse_yakit_port(text)
        if fmt == "xray":
            objs = iter_json_objects(text)
            aggregated = ParseResult("xray", [], [])
            for obj in objs:
                r = parse_xray(obj)
                aggregated.findings.extend(r.findings)
                aggregated.assets.extend(r.assets)
            return aggregated
        if fmt == "json_generic":
            aggregated = ParseResult("json_generic", [], [])
            fmts, notes = set(), []
            for obj in iter_json_objects(text):
                r = parse_json_generic(obj)
                fmts.add(r.fmt)
                if r.note:
                    notes.append(r.note)
                aggregated.findings.extend(r.findings)
                aggregated.assets.extend(r.assets)
            if len(fmts) == 1:
                aggregated.fmt = fmts.pop()
            if notes:
                aggregated.note = "；".join(dict.fromkeys(notes))
            elif not aggregated.findings:
                aggregated.note = "JSON 里没有可识别的漏洞字段"
            return aggregated
        if fmt == "csv_table":
            return parse_csv_table(text)
        if fmt == "md_table":
            return parse_md_table(text)
    except Exception as exc:  # 解析器自身 bug 也不该拖垮摄入循环
        return ParseResult("error", [], [], note=f"解析异常：{type(exc).__name__}: {exc}")
    return ParseResult("unknown", [], [], note="格式无法识别")


def file_fingerprint(path: str) -> str:
    """内容指纹，用于判断文件是否变化。"""
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

"""扫描报告：每条漏洞都带「怎么发现的 + 证据 + 复现」。

为什么单独一个模块而不是塞进 cli：
  * 报告是要交给别人看的（客户/同事/留档），格式必须稳定、可 diff；
  * 用户明确要求「扫完自动出的报告要有证据、写清干了什么」——那就不该只是把表格
    抄一遍，每条都要能回答三个问题：哪一步发现的、凭什么算、怎么自己复现一遍。

三块内容固定：
  1) 本次做了什么（模式、目标、引擎、耗时、各模式产出多少条）
  2) 漏洞明细（发现方式 / 位置 / 判据 / 证据 / 复现 / 原始产物）
  3) 未验证与边界（跳过的检查、L1 与 L2 的区别、产物目录）
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional

SEV_ORDER = ("critical", "high", "medium", "low", "info")
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}

# 来源 → 「这一步干了什么」的人话。报告里必须写清方法论，不能只给个编号。
SOURCE_CN = [
    ("sweep-strike", "深度验证内核：对该端点真实发请求（端口/服务识别、未授权、注入、敏感路径），判定到 L1/L2"),
    ("sweep-cve", "离线 CVE 匹配：从响应头/正文提取产品与版本，比对内置规则库的受影响版本区间"),
    ("sweep-brute", "弱口令验证：按协议握手（FTP/MySQL/PostgreSQL/Redis/Telnet/HTTP-Basic），命中即停"),
    ("sweep-paths", "敏感路径探测：内置 19 条字典逐条请求，先做软 404 基线过滤，命中后存活复验"),
    ("sweep-api", "API 未授权探测：28 个候选端点（Swagger/Actuator/Druid/GraphQL/Nacos/pprof/heapdump…），"
                  "软 404 基线过滤 + 命中后取证"),
    ("sweep-jsintel", "JS 情报：抓目标页与外链 JS，提取接口线索与密钥线索（值打码）"),
    ("sweep-baseline", "暴露面基线：安全响应头 / 网站文件 / TLS 证书链（只请求目标本身）"),
    ("sweep-fingerprint", "指纹识别：响应头 + 正文双通道规则匹配"),
    ("sweep-portscan", "端口扫描：内置常用端口表 TCP connect + banner 服务识别"),
    ("sweep-evidence", "取证产物：命中点的原始响应片段"),
    ("nuclei", "外部产物导入：nuclei 结果归一化"),
    ("xray", "外部产物导入：xray 结果归一化"),
    ("nmap", "外部产物导入：nmap 结果归一化"),
    ("nessus", "外部产物导入：Nessus 结果归一化"),
    ("yakit", "外部产物导入：Yakit 结果归一化"),
    ("md", "文档导入：报告/表格里的既有结论（无回访目标，不可复验）"),
]


def source_cn(source: str) -> str:
    s = (source or "").strip()
    for prefix, text in SOURCE_CN:
        if s.startswith(prefix):
            return text
    return f"来源 {s or '未知'}"


def level_of(row: Dict[str, Any]) -> str:
    """从证据串里摘验证级别标记（strike 内核会写 [L2/confirmed]）。"""
    ev = row.get("evidence") or ""
    m = re.search(r"\[(L[123][^\]]*)\]", ev)
    return m.group(1) if m else ""


_SLUG_RX = re.compile(r"[^a-z0-9]+")


def _slug_of(endpoint: str) -> str:
    """端点路径 → 证据目录名（引擎把 /actuator/env 落成 actuator_env）。"""
    m = re.match(r"^[a-z]+://[^/]+(/.*)?$", endpoint or "", re.I)
    path = (m.group(1) if m and m.group(1) else endpoint or "")
    path = path.split("?")[0].strip("/")
    return _SLUG_RX.sub("_", path.lower()).strip("_")


def _evidence_files(files: str, endpoint: str = "", max_items: int = 4) -> List[str]:
    """只列**这条命中自己**的证据文件（引擎按 端点路径 建子目录）。"""
    out: List[str] = []
    if not files:
        return out
    ev = os.path.join(os.path.dirname(files), "evidence")
    if not os.path.isdir(ev):
        return out
    slug = _slug_of(endpoint)
    cands: List[str] = []
    for root, _dirs, names in os.walk(ev):
        if slug and os.path.basename(root) != slug:
            continue
        for n in sorted(names):
            cands.append(os.path.join(root, n))
    if not cands and slug:
        # 目录名没匹配上就退一步：文件名里含 slug 的也算
        for root, _dirs, names in os.walk(ev):
            for n in sorted(names):
                if slug and slug in n:
                    cands.append(os.path.join(root, n))
    return cands[:max_items]


def _evidence_snippet(ev_files: List[str], max_lines: int = 12, max_chars: int = 1200) -> str:
    """把响应片段摘几行进报告：光给路径，评审的人还得自己打开文件。

    优先 response.snippet.txt（引擎落盘的原始响应），其次 meta.json；
    repro.md 跳过——它是复现稿，正文已经在报告里单独给了，抄进来只会重复。
    """
    def rank(path: str) -> int:
        n = os.path.basename(path)
        if n.startswith("response"):
            return 0
        if n.endswith(".txt"):
            return 1
        if n.endswith(".json"):
            return 2
        return 9

    for p in sorted(ev_files, key=rank):
        if os.path.basename(p) == "repro.md" or rank(p) > 2:
            continue
        if not p.endswith((".txt", ".json")):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        head = "\n".join(lines[:max_lines]).strip()
        if head:
            return head[:max_chars]
    return ""


def _fence(text: str) -> str:
    return text.replace("```", "'''")


def render(rows: Iterable[Dict[str, Any]], *, title: str = "空境 Kara 扫描报告",
           target: str = "", mode: str = "", engine: str = "", db: str = "",
           started: Optional[str] = None, elapsed: Optional[float] = None,
           stats: Optional[Dict[str, Any]] = None, notes: Optional[List[str]] = None) -> str:
    rows = [dict(r) for r in rows]
    rows.sort(key=lambda r: (SEV_ORDER.index(r.get("sev") or "info")
                             if (r.get("sev") or "info") in SEV_ORDER else 9,
                             -(r.get("count") or 0)))
    counts = {k: sum(1 for r in rows if (r.get("sev") or "info") == k) for k in SEV_ORDER}

    L: List[str] = []
    a = L.append
    a(f"# {title}")
    a("")
    a(f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    if target:
        a(f"- 目标：`{target}`")
    if mode:
        a(f"- 扫描模式：`{mode}`")
    if engine:
        a(f"- 引擎：`{engine}`")
    if db:
        a(f"- 数据库：`{db}`")
    if started:
        a(f"- 开始时间：{started}")
    if elapsed is not None:
        a(f"- 耗时：{elapsed:.1f}s")
    a(f"- 命中：**{len(rows)}** 条（" +
      " / ".join(f"{SEV_CN[k]} {counts[k]}" for k in SEV_ORDER if counts[k]) + "）")
    if stats:
        a(f"- 入账：新解析 {stats.get('parsed', 0)} 个产物，新增 {stats.get('findings_added', 0)} 条，"
          f"合并 {stats.get('findings_merged', 0)} 条，资产 +{stats.get('assets', 0)}")
    a("")
    a("> 级别口径：**L1** = 只到「看得见 / 可能受影响」（未验证可利用）；"
      "**L2** = 拿到了真实数据或凭据；**L3** = 拿到内部权限。交付看 L2 及以上。")
    a("")

    if notes:
        a("## 本次做了什么")
        a("")
        for n in notes:
            a(f"- {n}")
        a("")

    a("## 漏洞明细")
    a("")
    if not rows:
        a("本次没有命中。注意：0 命中 ≠ 目标安全——看下面的「未验证/跳过」一节。")
        a("")

    for i, r in enumerate(rows, 1):
        sev = (r.get("sev") or "info")
        lvl = level_of(r)
        a(f"### {i}. [{SEV_CN.get(sev, sev)}] {r.get('title') or '（无标题）'}")
        a("")
        a(f"- **发现方式**：{source_cn(r.get('sources') or '')}"
          + (f"（来源标记 `{r.get('sources')}`）" if r.get("sources") else ""))
        if lvl:
            a(f"- **验证级别**：{lvl}")
        loc = []
        if r.get("endpoint"):
            loc.append(f"`{r['endpoint']}`")
        if r.get("asset"):
            host = str(r["asset"]) + (f":{r['port']}" if r.get("port") else "")
            loc.append(f"资产 `{host}`")
        if loc:
            a("- **位置**：" + "　".join(loc))
        if r.get("param"):
            a(f"- **参数**：`{r['param']}`")
        if r.get("cve"):
            a(f"- **CVE**：{r['cve']}")
        if r.get("evidence"):
            a(f"- **判据/证据**：{r['evidence']}")
        ev_files = _evidence_files(str(r.get("files") or ""), str(r.get("endpoint") or ""))
        snippet = _evidence_snippet(ev_files)
        if snippet:
            a("- **证据（响应片段）**：")
            a("")
            a("  ```text")
            for line in snippet.splitlines():
                a(f"  {_fence(line)}")
            a("  ```")
            a("")
        if ev_files:
            a("- **证据文件**：")
            for p in ev_files:
                a(f"  - `{p}`")
        if r.get("repro"):
            a("- **复现**：")
            a("")
            a("  ```bash")
            for line in str(r["repro"]).splitlines() or [""]:
                a(f"  {_fence(line)}")
            a("  ```")
            a("")
        a(f"- **状态**：{(r.get('status') or '待验证')}"
          + (f"　**复验**：{r.get('verify_state')}" if r.get("verify_state") else ""))
        if r.get("first_seen"):
            a(f"- **首次发现**：{r['first_seen']}　（最近：{r.get('last_seen') or '-'}）")
        if r.get("files"):
            a(f"- **原始产物**：`{r['files']}`")
        a("")

    # 未验证 / 未测项单列：这类条目最容易在报告里被当成「没有」而漏掉
    skipped = [r for r in rows if (r.get("sev") or "") == "info" and "未能验证" in str(r.get("title"))]
    if skipped:
        a("## 未验证 / 跳过（这些不是「没有漏洞」）")
        a("")
        for r in skipped:
            a(f"- {r.get('title')}　`{r.get('endpoint') or r.get('asset') or '-'}`"
              + (f"　—　{r.get('evidence')}" if r.get("evidence") else ""))
        a("")

    a("## 说明")
    a("")
    a("- 本工具在断网/内网环境运行：所有请求只发给目标本身，不访问任何第三方服务。")
    a("- 「版本区间命中」只说明组件版本落在受影响范围，是否可利用需按复现步骤人工/深度验证确认。")
    a("- 命中即证据：每条都附端点、判据、复现命令与原始产物路径，可逐条独立复核。")
    a("")
    return "\n".join(L)


def write(text: str, out_dir: str, name: str = "") -> str:
    """把报告写到 out_dir，返回绝对路径。"""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name or f"report-{time.strftime('%Y%m%d-%H%M%S')}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return os.path.abspath(path)

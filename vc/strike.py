"""strike —— 把 Kara 的命中移交给 litmus2 真打一遍，结论再回写本库。

分工（这条边界不许越）：
  * Kara 的引擎只读：只观测、只取证，不发一个写请求 → 它给的是「可疑面」。
  * 真要判定「是不是真漏洞、能不能打进去」，交给执行层 litmus2（内网授权验证框架，
    自带 injection / authz / authprobe / exposure 等检查与 replay 复现）。
  * 本模块只做三件事：挑命中 → 生成目标清单与 findings 雏形 → 跑 litmus → 把
    litmus 的 findings.json 归一化回 Kara 库（同一个库、同一套去重键）。

用法（由 vc/cli.py 的 strike 子命令驱动）：
    kara strike --ids 5,9,10
    kara strike --sev high --limit 10
    kara strike --sev critical --dry-run        # 只出清单，不发起任何请求
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------- 执行层定位

LITMUS_CANDIDATES = [
    "~/tools/litmus2-go/litmus",
    "~/.local/bin/litmus",
    "~/tools/litmus2/litmus",
]

HINT = ("没找到执行层 litmus2。它是「验证/利用」那一半，Kara 本身只读、不代替它。\n"
        "  · 现成的在 ~/tools/litmus2-go/litmus（Go 单文件，零依赖）\n"
        "  · 或显式指定：kara strike --litmus-bin /path/to/litmus\n"
        "  · 只想先出清单：加了 --dry-run 就不需要 litmus")


def find_litmus(explicit: str = "") -> str:
    """显式指定只认它；否则按 ~/tools/litmus2-go → PATH → ~/.local/bin 找。"""
    if explicit:
        p = os.path.abspath(os.path.expanduser(explicit))
        return p if os.path.isfile(p) and os.access(p, os.X_OK) else ""
    for cand in LITMUS_CANDIDATES:
        p = os.path.abspath(os.path.expanduser(cand))
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which("litmus") or ""


# ---------------------------------------------------------------- 挑命中 → 目标

_PRIVATE = re.compile(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|localhost)")


def _split_host_port(target: str) -> Tuple[str, Optional[int]]:
    """'http://h:8080/x' / 'h:8080' / 'h' → (host, port|None)。"""
    t = target.strip()
    if "://" in t:
        u = urllib.parse.urlsplit(t)
        try:
            port = u.port
        except ValueError:
            port = None
        return u.hostname or "", port
    if t.count(":") == 1 and not t.startswith("["):
        host, _, p = t.partition(":")
        return host, int(p) if p.isdigit() else None
    return t, None


def target_of(row: Dict[str, Any]) -> str:
    """一条命中 → 交给 litmus 的目标字符串。

    优先用端点（能带出 scheme 与端口），退回资产 + 端口。
    端点会被裁到 scheme://host:port —— litmus 自己会发它需要的路径探测，
    直接把 /actuator/env 这种具体路径丢过去，等于替它预设了结论。
    """
    ep = (row.get("endpoint") or "").strip()
    if ep.startswith(("http://", "https://")):
        u = urllib.parse.urlsplit(ep)
        if u.hostname:
            netloc = u.hostname if not u.port else f"{u.hostname}:{u.port}"
            return f"{u.scheme}://{netloc}"
    asset = (row.get("asset") or "").strip()
    port = row.get("port")
    if asset:
        if port and ":" not in asset:
            return f"{asset}:{port}"
        return asset
    return ""


def collect(rows: List[Dict[str, Any]]) -> List[str]:
    """去重保序；同一台机器的 http/https 两个写法都留着（端口不同就是两个入口）。"""
    out, seen = [], set()
    for r in rows:
        t = target_of(r)
        if not t:
            continue
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def needs_public_flag(targets: List[str]) -> bool:
    """有公网目标就要显式放开 litmus 的私网默认限制（它是内网框架）。"""
    for t in targets:
        host, _ = _split_host_port(t)
        if host and not _PRIVATE.match(host) and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            return True  # 域名一律按「可能公网」处理
        if host and re.match(r"^\d+\.\d+\.\d+\.\d+$", host) and not _PRIVATE.match(host):
            return True
    return False


# ---------------------------------------------------------------- 生成喂给 litmus 的 findings 雏形

def build_seed(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Kara 命中 → litmus model.Finding 形状（字段名照抄它的 json tag）。

    这些是「线索」，不是结论：level 固定 L1（只到可达/存在），confidence 标 suspected。
    litmus 跑完会给出自己的 level/confidence，别让上游把 L1 冒充成 L2。
    """
    seeds = []
    for r in rows:
        target = target_of(r)
        if not target:
            continue
        host, port = _split_host_port(target)
        scheme = ""
        if target.startswith(("http://", "https://")):
            scheme = target.split("://", 1)[0]
        seeds.append({
            "id": f"kara-{r.get('id')}",
            "check": "kara-finding",
            "name": r.get("title") or "",
            "severity": r.get("sev") or "info",
            "target": target,
            "host": host,
            "port": port or 0,
            "scheme": scheme,
            "category": "web" if scheme else "host",
            "level": "L1",
            "confidence": "suspected",
            "time": r.get("last_seen") or "",
            "evidence": (r.get("evidence") or "")[:600],
            "repro": r.get("repro") or "",
            "impact": "",
            "fix": "",
            "cvss": "",
            "poc": "",
            "raw_ref": r.get("files") or "",
        })
    return seeds


# ---------------------------------------------------------------- 跑 litmus

def run_litmus(bin_path: str, targets: List[str], out_dir: str, timeout: int = 1800,
               ports: str = "", extra: Optional[List[str]] = None,
               log=print) -> Tuple[int, str]:
    """跑一轮 litmus，返回 (退出码, 输出目录)。输出目录里应有 findings.json。"""
    os.makedirs(out_dir, exist_ok=True)
    argv = [bin_path, "run", "-out", out_dir]
    for t in targets:
        argv += ["-t", t]
    if ports:
        argv += ["-p", ports]
    if needs_public_flag(targets):
        argv.append("-allow-public")
    argv += list(extra or [])

    log(f"  $ {' '.join(argv)}")
    t0 = time.time()
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, errors="replace")
    except OSError as exc:
        return 127, f"起不来：{exc}"
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if line.strip():
            log(f"  │ {line[:200]}")
        if time.time() - t0 > timeout:
            proc.kill()
            log(f"  [!] 超过 {timeout}s，已掐掉")
            return 124, out_dir
    return proc.wait(), out_dir


# ---------------------------------------------------------------- 读回 litmus 结论

def read_litmus_findings(out_dir: str) -> List[Dict[str, Any]]:
    """litmus 的 findings.json → 原始 dict 列表。找不到就返回空。"""
    if not out_dir or not os.path.isdir(out_dir):
        return []
    for root, _dirs, files in os.walk(out_dir):
        if "findings.json" in files:
            path = os.path.join(root, "findings.json")
            try:
                with open(path, encoding="utf-8") as fh:
                    payload = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            items = payload.get("findings") if isinstance(payload, dict) else payload
            if isinstance(items, list):
                return [x for x in items if isinstance(x, dict)]
    return []


def to_kara(rows: List[Dict[str, Any]], src_file: str) -> List[Dict[str, Any]]:
    """litmus Finding → Kara 入库形状（Store.add_findings 的字段）。

    证据里保留它的 level/confidence：交付线是 L2，L1 的条目一眼能看出还没落地。
    """
    out = []
    for r in rows:
        sev = (r.get("severity") or "info").lower()
        level = r.get("level") or ""
        conf = r.get("confidence") or ""
        ev = r.get("evidence") or ""
        bits = [b for b in (ev, f"[{level}/{conf}]" if level or conf else "") if b]
        host, port = _split_host_port(r.get("target") or "")
        out.append({
            "asset": r.get("host") or host,
            "ip": r.get("host") or host,
            "port": r.get("port") or port,
            "endpoint": r.get("target") or "",
            "param": "",
            "title": r.get("name") or r.get("check") or "litmus 发现",
            "cve": "",
            "sev": sev if sev in ("critical", "high", "medium", "low", "info") else "info",
            "source": f"litmus2:{r.get('check') or ''}",
            "evidence": " · ".join(bits)[:600],
            "repro": (r.get("repro") or "")[:1200],
            "base": "",
        })
    return out


def summarize(items: List[Dict[str, Any]]) -> Dict[str, int]:
    mix: Dict[str, int] = {}
    for r in items:
        sev = (r.get("severity") or "info").lower()
        mix[sev] = mix.get(sev, 0) + 1
    return mix

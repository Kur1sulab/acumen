#!/usr/bin/env python3
"""离网守门：确认交付物不具备任何出站能力。

为什么不跟 check_zero_deps.py 合并：
    那个脚本守的是「不装第三方包」，靠 sys.stdlib_module_names 白名单放行。
    但标准库里本身就有一整套出站工具——urllib.request、http.client、
    smtplib、ftplib、socket——它们全在标准库里，零依赖检查一律放行，
    照样能把数据发出去。

    空境是扫描器：请求目标是它的本职，所以这里守的不是「一个包都不发」，
    而是「只朝目标发，不朝第三方发」——没有遥测、没有云查杀、没有更新检查。
    Python 侧唯一会自己建连的地方是 vc/cli.py 的 probe_scheme（先握手判 http/https，
    连的是用户给的目标）；真正的扫描由 Go 引擎子进程完成，不在本检查范围。

检查四类：
    A. Python 侧：出站模块 import（含标准库出站模块）
    B. Python 侧：socket 建连、子进程调用外部下载器
    C. 前端：HTML/CSS/JS 引用任何非回环的外部资源
    D. 白名单：127.0.0.1 / localhost / ::1 一律放行（本地服务正常需求）

退出码 0 = 干净，1 = 发现出站能力。
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist"}

# 测试自身可以 import 任何东西（它不随交付物运行）；
# 本文件自己也不检查自己——里面写满了 curl/wget 这些字面量。
SKIP_PREFIX = ("tests/",)
SKIP_FILES = {"tools/check_offline.py"}

# ── A. 出站模块黑名单 ────────────────────────────────────────────────
# 标准库里能往外发东西的，一个都不能留
BANNED_MODULES = {
    "urllib.request",
    "urllib.error",
    "http.client",       # 注意：http.server（本地服务）是允许的
    "smtplib",
    "ftplib",
    "telnetlib",
    "poplib",
    "imaplib",
    "nntplib",
    "xmlrpc.client",
    "socket",            # 裸 socket 一律禁（唯一例外见 ALLOW_MODULES）
    # 第三方出站库再列一遍：zero_deps 已经拦了，这里双保险
    "requests",
    "httpx",
    "aiohttp",
    "urllib3",
    "websocket",
    "websockets",
    "paramiko",
    "pycurl",
}

# 允许的例外：文件 → 模块。只为「对目标握手」开这一个口子，别的文件照样拦。
ALLOW_MODULES = {
    "vc/cli.py": {"socket"},
}

# ── B. 子进程外部下载器 ──────────────────────────────────────────────
BANNED_BINARIES = [
    "curl",
    "wget",
    "ncat",
    "aria2c",
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "DownloadString",
    "DownloadFile",
]

# ── C. 前端外链 ──────────────────────────────────────────────────────
LOOPBACK = re.compile(r"^(?:https?://)?(?:127\.0\.0\.1|localhost|\[::1\]|::1)(?::\d+)?(?:/|$)")

FRONTEND_PATTERNS = [
    # <script src="http...">  —— 离线环境直接白屏
    (re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["'](https?://[^"']+)""", re.I), "script src"),
    # <link href="http...">   —— CSS / 字体 / 图标
    (re.compile(r"""<link\b[^>]*\bhref\s*=\s*["'](https?://[^"']+)""", re.I), "link href"),
    # @import url(http...)    —— CSS 里的远程样式
    (re.compile(r"""@import\s+(?:url\()?["']?(https?://[^"')\s]+)""", re.I), "@import"),
    # CSS url(http...)
    (re.compile(r"""url\(\s*["']?(https?://[^"')]+)""", re.I), "css url()"),
    # fetch("http...")
    (re.compile(r"""\bfetch\s*\(\s*[`"'](https?://[^`"'$]+)""", re.I), "fetch"),
    # XMLHttpRequest.open("GET", "http...")
    (re.compile(r"""\.open\s*\(\s*[`"'][A-Za-z]+[`"']\s*,\s*[`"'](https?://[^`"']+)""", re.I), "xhr.open"),
    # <img src="http..."> / <iframe src="http...">
    (re.compile(r"""<(?:img|iframe|video|audio|source)\b[^>]*\bsrc\s*=\s*["'](https?://[^"']+)""", re.I), "媒体外链"),
    # new WebSocket("ws...")
    (re.compile(r"""new\s+WebSocket\s*\(\s*[`"'](wss?://[^`"']+)""", re.I), "WebSocket"),
]

FRONTEND_EXT = {".html", ".htm", ".css", ".js", ".mjs", ".svg"}
CODE_EXT = {".py", ".sh", ".bash", ".bat", ".cmd", ".ps1"}


def iter_files(exts: set[str]) -> list[pathlib.Path]:
    out = []
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith(SKIP_PREFIX) or rel in SKIP_FILES:
            continue
        out.append(p)
    return out


def module_name_of(node: ast.AST) -> list[tuple[str, int]]:
    """取出 import 的完整模块名（不只顶层，避免 urllib.request 被 urllib 掩盖）。"""
    found: list[tuple[str, int]] = []
    if isinstance(node, ast.Import):
        for a in node.names:
            found.append((a.name, node.lineno))
    elif isinstance(node, ast.ImportFrom):
        if node.level:            # 相对 import，自家模块
            return []
        if node.module:
            found.append((node.module, node.lineno))
    return found


def scan_python(path: pathlib.Path) -> list[str]:
    problems: list[str] = []
    # as_posix：ALLOW_MODULES 的键是字符串，纯 Path 查表永远查不到
    rel = path.relative_to(ROOT).as_posix()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except SyntaxError as exc:
        return [f"  {rel}: 语法错误，无法检查 ({exc})"]

    for node in ast.walk(tree):
        for name, line in module_name_of(node):
            # 精确匹配 + 父模块匹配（urllib.request.sub → urllib.request）
            hit = None
            for banned in BANNED_MODULES:
                if name == banned or name.startswith(banned + "."):
                    hit = banned
                    break
            if hit and hit in ALLOW_MODULES.get(rel, set()):
                hit = ""          # 文件级例外：vc/cli.py 的 probe_scheme 只对目标握手
            if hit:
                problems.append(f"  {rel}:{line}  import {name}（出站模块 {hit}）")

    # 子进程调外部下载器：扫源码文本，因为命令往往是拼接出来的字面量
    text = path.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for binary in BANNED_BINARIES:
            if binary in line and ("subprocess" in line or "os.system" in line or "Popen" in line or "call(" in line or "run(" in line):
                problems.append(f"  {rel}:{line_no}  疑似子进程调用 {binary}")
    return problems


def scan_shell(path: pathlib.Path) -> list[str]:
    problems: list[str] = []
    rel = path.relative_to(ROOT)
    text = path.read_text(encoding="utf-8", errors="replace")
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("::"):
            continue
        for binary in BANNED_BINARIES:
            # 命令位置出现（行首、管道后、&& 后）才算，避免把 echo 文案算成违规
            if re.search(rf"(^|[|&;]\s*){re.escape(binary)}\s+[-/\"'$]", stripped):
                problems.append(f"  {rel}:{line_no}  调用 {binary}")
                break
    return problems


def scan_frontend(path: pathlib.Path) -> list[str]:
    problems: list[str] = []
    rel = path.relative_to(ROOT)
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern, label in FRONTEND_PATTERNS:
        for m in pattern.finditer(text):
            url = m.group(1)
            if LOOPBACK.match(url):
                continue
            line_no = text[: m.start()].count("\n") + 1
            problems.append(f"  {rel}:{line_no}  {label} → {url}")
    return problems


def main() -> int:
    problems: list[str] = []

    py_files = iter_files({".py"})
    for p in py_files:
        problems += scan_python(p)

    sh_files = iter_files(CODE_EXT - {".py"})
    for p in sh_files:
        problems += scan_shell(p)

    fe_files = iter_files(FRONTEND_EXT)
    for p in fe_files:
        problems += scan_frontend(p)

    if problems:
        print("✗ 发现出站能力（离线环境里这些会让功能失效或触发违规外连）：")
        for line in problems:
            print(line)
        print("\n空境是离网工具：目标现场只进不出。上面每一条都要删掉或改成本地实现。")
        return 1

    print(
        f"✓ 通过：{len(py_files)} 个 Python 文件、{len(sh_files)} 个脚本、"
        f"{len(fe_files)} 个前端文件均无出站能力"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

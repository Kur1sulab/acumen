#!/usr/bin/env python3
r"""绿色版冒烟测试：用「当前解释器」把服务真跑起来，打 /api/health。

为什么要有这个文件：
    bundle 结构看起来对，不代表能跑。._pth 少一行 ".."、sqlite3.dll 缺一个、
    GBK 控制台解不了中文，任何一种都会让双击之后一闪而过。
    所以每次构建完必须用包内那颗 python.exe 真起一次服务、真取一次 HTTP 200。

用法（两个场景共用）：
    python tests/smoke_bundle.py          # 仓库内，系统解释器
    python\python.exe tests\smoke_bundle.py   # 解压后的绿色版，内置解释器
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def _force_utf8_stdout() -> None:
    """把 stdout/stderr 钉到 UTF-8。

    为什么必须做：Windows 控制台默认码页是 cp936，但 CI runner / 英文版
    Windows / 重定向到管道时是 cp1252 或 cp437，print 一个中文就
    UnicodeEncodeError 崩掉——而且崩在日志第一行，看起来像"程序根本没跑"。
    依赖外部设 PYTHONIOENCODING 不可靠（用户不会设），所以脚本自己钉。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass



def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def fail(msg: str) -> int:
    print(f"\n[X] {msg}")
    return 1


def check_engine() -> tuple[str, int]:
    """检查包内引擎。返回 (人话结论, 是否致命)。

    为什么单独查：绿色版最容易出的问题不是服务起不来，而是**引擎没进包**——
    界面照常打开、扫描页却永远显示「没找到扫描引擎」，用户会当成软件坏了。
    所以这里既查文件在不在，也查它是不是真的 Windows PE（7z 断掉、杀软隔离、
    只拷了个 0 字节占位文件都会在这里露出来）。
    """
    eng_dir = ROOT / "engine"
    if not eng_dir.is_dir():
        return "源码目录：跳过（引擎按 PATH 找）", 0
    for name in ("sweep.exe", "sweep"):
        p = eng_dir / name
        if not p.is_file():
            continue
        size = p.stat().st_size
        if size < 1_000_000:
            return f"engine/{name} 只有 {size:,} 字节，八成不是真二进制", 1
        head = p.open("rb").read(2)
        if name.endswith(".exe") and head != b"MZ":
            return f"engine/{name} 头两字节是 {head!r}，不是 PE 文件", 1
        return f"engine/{name} 就位，{size / 1048576:.1f} MB", 0
    return "engine/ 目录在，但里面没有 sweep 二进制", 1


def main() -> int:
    _force_utf8_stdout()
    port = free_port()
    tmp = tempfile.mkdtemp(prefix="kara-smoke-")
    db = os.path.join(tmp, "smoke.db")

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    cmd = [
        sys.executable, "-m", "vc.cli",
        "--db", db,
    ]

    print("=" * 62)
    print("空境 Kara · 绿色版冒烟测试")
    print("=" * 62)
    print(f"解释器 : {sys.executable}")
    print(f"版本   : {sys.version.split()[0]}  ({sys.platform})")
    print(f"根目录 : {ROOT}")
    print(f"端口   : {port}")
    print(f"临时库 : {db}")
    print("-" * 62)

    eng_msg, eng_fatal = check_engine()
    print(f"[0/4] 引擎 -> {eng_msg}")
    if eng_fatal:
        return fail("包内引擎缺失或损坏，这个包扫不了东西")

    proc = subprocess.Popen(
        cmd, cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base_url = f"http://127.0.0.1:{port}"
    health = None
    try:
        deadline = time.time() + 25
        while time.time() < deadline:
            if proc.poll() is not None:
                out = (proc.stdout.read() or b"").decode("utf-8", "replace")
                print("服务提前退出，输出如下：")
                print(out)
                return fail(f"进程退出码 {proc.returncode}")

            try:
                with urllib.request.urlopen(base_url + "/api/health", timeout=2) as r:
                    health = r.read().decode("utf-8", "replace")
                    print(f"[1/4] GET /api/health -> HTTP {r.status}")
                    print(f"      响应 {health[:300]}")
                    if r.status != 200:
                        return fail("健康检查非 200")
                    break
            except Exception:
                time.sleep(0.4)
        else:
            out = b""
            try:
                proc.terminate()
                out = proc.stdout.read() or b""
            except Exception:
                pass
            print("25 秒内服务没起来，输出：")
            print(out.decode("utf-8", "replace"))
            return fail("启动超时")

        with urllib.request.urlopen(base_url + "/", timeout=8) as r:
            html = r.read().decode("utf-8", "replace")
        if r.status != 200 or len(html) < 500:
            return fail(f"首页异常 HTTP {r.status} / {len(html)} 字节")
        print(f"[2/4] GET / -> HTTP {r.status}, 首页 {len(html):,} 字节")

        with urllib.request.urlopen(base_url + "/api/summary", timeout=8) as r:
            summary = r.read().decode("utf-8", "replace")
        print(f"[3/4] GET /api/summary -> HTTP {r.status}, {summary[:200]}")

        # 引擎对服务端可见才算真的能用：文件在包里、服务没认出来，一样是坏的
        with urllib.request.urlopen(base_url + "/api/scan/meta", timeout=10) as r:
            meta = json.loads(r.read().decode("utf-8", "replace"))
        eng = meta.get("engine", {})
        print(f"[4/4] GET /api/scan/meta -> 引擎 {eng.get('path') or '(空)'} "
              f"ok={eng.get('ok')} {eng.get('version', '')}")
        # 只在 Windows 上强制：这个 exe 在别的系统上本来就跑不起来
        if os.name == "nt" and (ROOT / "engine").is_dir() and not eng.get("ok"):
            return fail("包里有引擎，但服务端没认出来（路径或权限问题）")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("-" * 62)
    print("OK  冒烟通过：解释器可用、模块可导入、服务可监听、HTTP 可响应、引擎可用")
    return 0


if __name__ == "__main__":
    sys.exit(main())

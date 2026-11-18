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


def main() -> int:
    _force_utf8_stdout()
    port = free_port()
    tmp = tempfile.mkdtemp(prefix="acumen-smoke-")
    db = os.path.join(tmp, "smoke.db")

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    cmd = [
        sys.executable, "-m", "vc.server",
        "--port", str(port),
        "--host", "127.0.0.1",
        "--db", db,
        "--no-watch",
    ]

    print("=" * 62)
    print("鉴微 Acumen · 绿色版冒烟测试")
    print("=" * 62)
    print(f"解释器 : {sys.executable}")
    print(f"版本   : {sys.version.split()[0]}  ({sys.platform})")
    print(f"根目录 : {ROOT}")
    print(f"端口   : {port}")
    print(f"临时库 : {db}")
    print("-" * 62)

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
                    print(f"[1/3] GET /api/health -> HTTP {r.status}")
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
        print(f"[2/3] GET / -> HTTP {r.status}, 首页 {len(html):,} 字节")

        with urllib.request.urlopen(base_url + "/api/summary", timeout=8) as r:
            summary = r.read().decode("utf-8", "replace")
        print(f"[3/3] GET /api/summary -> HTTP {r.status}, {summary[:200]}")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("-" * 62)
    print("OK  冒烟通过：解释器可用、模块可导入、服务可监听、HTTP 可响应")
    return 0


if __name__ == "__main__":
    sys.exit(main())

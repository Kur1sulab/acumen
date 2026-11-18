#!/usr/bin/env python3
r"""绿色版冒烟测试（单一 CLI）：用「当前解释器」真跑一次命令，确认包是能用的。

为什么要有这个文件：
    bundle 结构看起来对，不代表能跑。._pth 少一行 ".."、sqlite3.dll 缺一个、
    GBK 控制台解不了中文，任何一种都会让双击之后一闪而过。
    所以每次构建完必须用包内那颗 python.exe 真跑命令、真拿到退出码。

检查顺序（任何一项失败都算包不合格）：
    0. 包内引擎在不在、是不是真 PE
    1. `kara`（裸命令）→ 状态页，退出码 0，输出里有产品名与引擎路径
    2. `kara list` → 列表命令可跑（空库也应是 0）
    3. `kara scan -t <不存在端口>` → 引擎真的被调起来了（超时/失败都行，只要进程没崩在 import）

用法（两个场景共用）：
    python tests/smoke_bundle.py                # 仓库内，系统解释器
    python\python.exe tests\smoke_bundle.py     # 解压后的绿色版，内置解释器
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _force_utf8_stdout() -> None:
    """把 stdout/stderr 钉到 UTF-8。

    Windows 控制台默认码页 cp936，CI runner / 英文版 Windows / 重定向到管道时
    是 cp1252 或 cp437，print 一个中文就 UnicodeEncodeError 崩在日志第一行，
    看起来像「程序根本没跑」。依赖外部设 PYTHONIOENCODING 不可靠，所以自己钉。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def fail(msg: str) -> int:
    print(f"\n[X] {msg}")
    return 1


def check_engine() -> tuple[str, int]:
    """包内引擎：在不在、是不是真二进制。绿色版最常见的坏法是引擎没进包。"""
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


def run_cli(args: list, db: str, env: dict, timeout: int = 120) -> tuple[int, str]:
    cmd = [sys.executable, "-m", "vc.cli", "--db", db] + args
    p = subprocess.run(cmd, cwd=str(ROOT), env=env, timeout=timeout,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, (p.stdout or b"").decode("utf-8", "replace")


def main() -> int:
    _force_utf8_stdout()
    tmp = tempfile.mkdtemp(prefix="kara-smoke-")
    db = os.path.join(tmp, "smoke.db")
    inbox = os.path.join(tmp, "inbox")

    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    print("=" * 62)
    print("空境 Kara · 绿色版冒烟测试（单一 CLI）")
    print("=" * 62)
    print(f"解释器 : {sys.executable}")
    print(f"版本   : {sys.version.split()[0]}  ({sys.platform})")
    print(f"根目录 : {ROOT}")
    print(f"临时库 : {db}")
    print("-" * 62)

    eng_msg, eng_fatal = check_engine()
    print(f"[0/3] 引擎 -> {eng_msg}")
    if eng_fatal:
        return fail("包内引擎缺失或损坏，这个包扫不了东西")

    code, out = run_cli(["--inbox", inbox], db, env)
    if code != 0:
        print(out)
        return fail(f"裸命令退出码 {code}")
    if "空境" not in out or "引擎" not in out:
        print(out)
        return fail("状态页没打出来，输出不符合预期")
    print("[1/3] kara -> 退出码 0")
    for line in out.splitlines()[:4]:
        print(f"      {line}")

    code, out = run_cli(["--inbox", inbox, "list"], db, env)
    if code != 0:
        print(out)
        return fail(f"list 退出码 {code}")
    print("[2/3] kara list -> 退出码 0")

    # 引擎真的被调起来：扫一个几乎肯定关着的回环端口，跑完（无论命中与否）不该崩在 import
    code, out = run_cli(["--inbox", inbox, "--timeout", "60",
                         "scan", "-t", "127.0.0.1:1", "-m", "api", "--scheme", "http"], db, env, timeout=180)
    if "Traceback" in out or "ModuleNotFoundError" in out:
        print(out)
        return fail(f"引擎调用崩了（退出码 {code}）")
    print(f"[3/3] kara scan -> 退出码 {code}（引擎已真实调用）")

    print("-" * 62)
    print("OK  冒烟通过：解释器可用、模块可导入、CLI 可跑、引擎可调")
    return 0


if __name__ == "__main__":
    sys.exit(main())

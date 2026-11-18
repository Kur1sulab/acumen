#!/usr/bin/env python3
"""把源码组装成 Windows 绿色版 zip（双击即跑，不需要装 Python）。

设计约束
--------
本脚本零出站：运行时绝不联网。官方 embeddable 运行时由调用方准备好后
用 --python-zip 传进来（CI 里 curl 取，本地手工取一次）。
这样 check_offline.py 不必为构建脚本开白名单例外。

为什么要改 ._pth（关键坑）
--------------------------
embeddable 版带的 python312._pth 内容只有两行有效路径：

    python312.zip
    .

而 ._pth 里的相对路径**以 python.exe 所在目录为基准**——也就是 python\，
不是解压根目录。更狠的是：._pth 一旦存在，Python 会进入 isolated 模式，
**完全忽略 PYTHONPATH 和 PYTHONHOME**，往环境变量里塞路径没有任何用。

不改的话，双击之后立刻 ModuleNotFoundError: No module named 'vc'。
所以必须往 ._pth 追加一行 ".."，把解压根纳入 sys.path。

编码
----
启动器和说明文件都用 GBK + CRLF 写入：cmd 默认码页 936，UTF-8 的 bat
在中文 Windows 上会显示成乱码；而 Python 侧同步用 PYTHONIOENCODING=gbk，
保证 print 里的中文在控制台读得懂。
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.1.0"
BUNDLE = f"acumen-{VERSION}-win64"

BAT = r"""@echo off
setlocal
cd /d "%~dp0"

rem 控制台走 GBK，和代码里的中文输出对齐
set "PYTHONIOENCODING=gbk"
set "PYTHONDONTWRITEBYTECODE=1"

if not exist "python\python.exe" goto :nopython

echo.
echo   鉴微 Acumen  v{ver}
echo   ---------------------------------------------
echo   本机看板 · 只监听 127.0.0.1 · 不联网
echo.
echo   启动后浏览器会自动打开；关掉这个窗口即停止服务。
echo   换端口：acumen.bat --port 7799
echo.

"python\python.exe" -m vc.server --port 7788 --open %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" goto :crashed
echo.
echo   [acumen] 已停止。
timeout /t 3 >nul 2>&1
goto :eof

:crashed
echo.
echo   [异常退出] 退出码 %RC%
echo.
pause
goto :eof

:nopython
echo.
echo   [错误] 找不到 python\python.exe —— 这个包不完整。
echo   请确认整个压缩包完整解压后再双击本文件。
echo.
pause
"""

README = r"""鉴微 Acumen v{ver} —— Windows 绿色版
================================================

不需要安装任何东西。不需要 Python，不需要 pip，不需要联网。

用法
----
1. 把整个压缩包解压到一个有写权限的目录
   （桌面、D 盘、U 盘都行；务必完整解压，别在压缩包里直接双击）

2. 双击 acumen.bat

3. 浏览器自动打开 http://127.0.0.1:7788/
   没自动开就手动输入这个地址

4. 用完关掉黑色窗口即停止

目录说明
--------
acumen.bat              启动器，双击这个
START-HERE.txt          就是你正在读的这份说明
python\                 内置 Python 3.12.8 运行时（约 25MB），不用管
vc\                     程序本体
tests\smoke_bundle.py   自检脚本，怀疑环境有问题时跑它
README.md               完整功能说明
CHANGELOG.md            版本更新记录

安全说明
--------
· 只监听 127.0.0.1，同网段其它机器访问不到
· 不发起任何外部网络请求，没有遥测、没有上报
· 数据全部存本机：%USERPROFILE%\.acumen\vuln.db
· 收件箱默认扫 %USERPROFILE%\pentest-inbox 等目录

常见问题
--------
Q: 双击后窗口一闪就没
A: 八成是压缩包没解压完整，重新完整解压。

Q: 提示端口被占用
A: 已有实例在跑，直接用浏览器开 127.0.0.1:7788。

Q: 杀软提示风险
A: Python 官方绿色版运行时的固有误报，程序本身没有网络行为。

Q: 想换端口
A: acumen.bat --port 7799

Q: 想确认包是好的
A: 在解压目录执行：
   python\python.exe tests\smoke_bundle.py
"""


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


def eprint(*a: object) -> None:
    print(*a)


def assemble(python_zip: Path, build_dir: Path) -> Path:
    if not python_zip.is_file():
        raise SystemExit(f"[X] 找不到运行时压缩包：{python_zip}")

    with zipfile.ZipFile(python_zip) as z:
        names = z.namelist()
        for must in ("python.exe", "_sqlite3.pyd", "sqlite3.dll", "python312.dll"):
            if must not in names:
                raise SystemExit(f"[X] 运行时包里没有 {must}，这不是官方的 embeddable 包")

    stage = build_dir / BUNDLE
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    eprint(f"[1/6] 解压官方运行时 -> {stage.name}/python/")
    with zipfile.ZipFile(python_zip) as z:
        z.extractall(stage / "python")
    eprint(f"      {len(list((stage / 'python').iterdir()))} 个文件")

    eprint("[2/6] 修正 python312._pth（补 ..，否则 import vc 失败）")
    pth = stage / "python" / "python312._pth"
    if not pth.is_file():
        raise SystemExit("[X] 运行时包里没有 python312._pth，结构异常")
    body = pth.read_text(encoding="utf-8")
    if "\n..\n" not in body and not body.rstrip().endswith(".."):
        lines = [ln for ln in body.splitlines()]
        # 插在 "." 之后、注释之前
        out, done = [], False
        for ln in lines:
            out.append(ln)
            if ln.strip() == "." and not done:
                out.append("..")
                done = True
        if not done:
            out = ["python312.zip", ".", ".."] + out
        body = "\n".join(out)
    pth.write_bytes(body.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8"))
    eprint(f"      路径表: {[l for l in pth.read_text().splitlines() if l.strip() and not l.startswith('#')]}")

    eprint("[3/6] 拷入产品代码")
    shutil.copytree(ROOT / "vc", stage / "vc",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (stage / "tests").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "tests" / "smoke_bundle.py", stage / "tests" / "smoke_bundle.py")
    for f in ("LICENSE", "README.md", "CHANGELOG.md"):
        src = ROOT / f
        if src.is_file():
            shutil.copy2(src, stage / f)
    eprint(f"      vc/ 下 {len(list((stage / 'vc').glob('*.py')))} 个 .py")

    eprint("[4/6] 生成启动器（GBK + CRLF）")
    (stage / "acumen.bat").write_bytes(
        BAT.replace("{ver}", VERSION).replace("\n", "\r\n").encode("gbk"))
    (stage / "START-HERE.txt").write_bytes(
        README.replace("{ver}", VERSION).replace("\n", "\r\n").encode("gbk"))
    eprint("      acumen.bat / START-HERE.txt")

    eprint("[5/6] 打包")
    out_zip = build_dir / f"{BUNDLE}.zip"
    if out_zip.exists():
        out_zip.unlink()
    count = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, dirs, files in os.walk(stage):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for fn in sorted(files):
                if fn.endswith(".pyc"):
                    continue
                fp = Path(root) / fn
                z.write(fp, fp.relative_to(stage))
                count += 1

    eprint("[6/6] 自检（回读压缩包）")
    problems = []
    with zipfile.ZipFile(out_zip) as z:
        got = set(z.namelist())
        for must in ("acumen.bat", "python/python.exe", "python/python312._pth",
                     "python/_sqlite3.pyd", "vc/server.py", "tests/smoke_bundle.py", "START-HERE.txt"):
            if must not in got:
                problems.append(f"缺 {must}")
        pth_txt = z.read("python/python312._pth").decode("utf-8")
        entries = [l.strip() for l in pth_txt.splitlines()
                   if l.strip() and not l.startswith("#")]
        if ".." not in entries:
            problems.append("._pth 里没有 ..（import vc 会失败）")
        bat = z.read("acumen.bat")
        if bat.count(b"\r\n") == 0 or bat.count(b"\n") != bat.count(b"\r\n"):
            problems.append("acumen.bat 换行不是纯 CRLF")
        try:
            bat.decode("gbk")
        except UnicodeDecodeError:
            problems.append("acumen.bat 不是 GBK 可解码")
    if problems:
        for pb in problems:
            eprint(f"      [X] {pb}")
        raise SystemExit(1)
    eprint(f"      OK  {count} 个条目，全部必需文件就位")

    return out_zip


def main() -> int:
    ap = argparse.ArgumentParser(description="组装 Windows 绿色版（零出站）")
    ap.add_argument("--python-zip", required=True,
                    help="官方 python-3.12.x-embed-amd64.zip 的本地路径")
    ap.add_argument("--out", default="dist", help="输出目录（默认 dist）")
    args = ap.parse_args()
    _force_utf8_stdout()

    py_zip = Path(args.python_zip).expanduser().resolve()
    out_dir = (ROOT / args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    eprint(f"鉴微 Acumen v{VERSION} · Windows 绿色版构建")
    eprint(f"运行时 : {py_zip}")
    eprint(f"输出   : {out_dir}")
    eprint("-" * 58)

    z = assemble(py_zip, out_dir)
    size = z.stat().st_size

    eprint("-" * 58)
    eprint(f"完成: {z}")
    eprint(f"      {size:,} 字节 ({size / 1048576:.1f} MB)")
    eprint("")
    eprint("下一步（必须在真 Windows 上做，结构对不等于能跑）：")
    eprint(f"      解压 {z.name} 后执行 python\\python.exe tests\\smoke_bundle.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())

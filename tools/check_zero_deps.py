#!/usr/bin/env python3
"""零依赖自检：确认这个项目真的只用 Python 标准库。

为什么值得单独一个脚本：这个仓库对外的承诺是「不需要 pip，拷进离线内网就能跑」。
本地开发机有网、有 venv、什么包都装得到，随手 import 一个 requests 完全不会有痛感，
但产物拿到内网就 ImportError。所以把承诺变成一条会失败的检查。

同时守住前端：前端也不许出现构建链。
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# 允许的顶层模块名：标准库 + 本项目自己的包
ALLOWED_TOP = set(sys.stdlib_module_names) | {"vc"}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist"}
# 引擎（Go）与它的素材不是 Python 交付物：里面的 .py 是上游 litmus2 的口径生成脚本，
# 不随包运行，也不该按「Python 零依赖」来判
SKIP_PREFIX_EXTRA = ("engine-go/",)

# 这些路径下的文件不参与检查（测试自己可以随便 import）
SKIP_PREFIX = ("tests/",)

FORBIDDEN_FRONTEND = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "vite.config.js",
    "vite.config.ts",
    "webpack.config.js",
    "rollup.config.js",
    "tsconfig.json",
]


def _tracked_py() -> list[pathlib.Path] | None:
    """git 仓库内只认被跟踪的文件——那才是真正会被拷走的交付面。

    本地随手丢的开发探针（_probe_*.py 之类）不该让门禁变红，但它们也不会进交付包，
    所以按 git 的视角判断比按目录视角更接近事实。没有 .git（zip 下载）时返回 None。
    """
    if not (ROOT / ".git").exists():
        return None
    try:
        raw = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--", "*.py"],
            capture_output=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    names = [n for n in raw.decode("utf-8", "replace").split("\0") if n]
    return [ROOT / n for n in sorted(names)]


def iter_py() -> tuple[list[pathlib.Path], bool]:
    """返回 (待检查文件, 是否只看了 git 跟踪的文件)。"""
    tracked = _tracked_py()
    if tracked is not None:
        files = [
            p for p in tracked
            if p.exists()
            and not any(part in SKIP_DIRS for part in p.parts)
            and not p.relative_to(ROOT).as_posix().startswith(SKIP_PREFIX)
            and not p.relative_to(ROOT).as_posix().startswith(SKIP_PREFIX_EXTRA)
        ]
        return files, True

    out = []
    for p in sorted(ROOT.rglob("*.py")):
        rel = p.relative_to(ROOT).as_posix()
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if rel.startswith(SKIP_PREFIX) or rel.startswith(SKIP_PREFIX_EXTRA) or p.name.startswith("_"):
            continue
        out.append(p)
    return out, False


def top_of(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [a.name.split(".")[0] for a in node.names]
    if isinstance(node, ast.ImportFrom):
        if node.level:          # 相对 import，必然是自家模块
            return []
        return [(node.module or "").split(".")[0]]
    return []


def main() -> int:
    files, tracked_only = iter_py()
    bad: list[str] = []

    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            print(f"语法错误 {path.relative_to(ROOT)}: {exc}")
            return 1
        for node in ast.walk(tree):
            for root in top_of(node):
                if root and root not in ALLOWED_TOP:
                    rel = path.relative_to(ROOT)
                    bad.append(f"  {rel}:{getattr(node, 'lineno', '?')}  import {root}")

    problems = 0
    if bad:
        problems += 1
        print("✗ 发现非标准库依赖：")
        print("\n".join(bad))

    fe = [f for f in FORBIDDEN_FRONTEND if (ROOT / f).exists()]
    if (ROOT / "node_modules").is_dir():
        fe.append("node_modules/")
    if fe:
        problems += 1
        print("✗ 前端混进了构建链：")
        print("\n".join(f"  {f}" for f in fe))

    if problems:
        print("\n这个项目的卖点就是零依赖，上面的东西会让它没法拷进离线环境。")
        return 1

    scope = "git 跟踪文件" if tracked_only else "全量遍历"
    print(f"✓ 通过：{len(files)} 个 Python 文件全部只用标准库（{scope}）；前端无构建链")
    return 0


if __name__ == "__main__":
    sys.exit(main())

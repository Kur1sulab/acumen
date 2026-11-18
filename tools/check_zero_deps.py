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
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# 允许的顶层模块名：标准库 + 本项目自己的包
ALLOWED_TOP = set(sys.stdlib_module_names) | {"vc"}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist"}

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


def iter_py() -> list[pathlib.Path]:
    out = []
    for p in sorted(ROOT.rglob("*.py")):
        rel = p.relative_to(ROOT).as_posix()
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if rel.startswith(SKIP_PREFIX):
            continue
        out.append(p)
    return out


def top_of(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [a.name.split(".")[0] for a in node.names]
    if isinstance(node, ast.ImportFrom):
        if node.level:          # 相对 import，必然是自家模块
            return []
        return [(node.module or "").split(".")[0]]
    return []


def main() -> int:
    files = iter_py()
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

    print(f"✓ 通过：{len(files)} 个 Python 文件全部只用标准库；前端无构建链")
    return 0


if __name__ == "__main__":
    sys.exit(main())

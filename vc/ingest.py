"""摄入器：遍历收件箱目录 → 判定是否需要解析 → 交给 parsers → 写入 Store。

判定规则（省时间的关键）：
  1. 扩展名白名单：.json .jsonl .txt .csv .tsv .xml .nessus .md
  2. 单个文件 > 20MB 跳过（记 note，不重复尝试）
  3. files 表里已有同 path 且 mtime+size 未变 → 直接跳过（不算错）
  4. mtime/size 变了才算内容指纹，指纹相同也跳过
体积/数量上限：单次扫描最多 MAX_FILES 个文件，防止误指到超大目录时卡死。
"""

from __future__ import annotations

import os
import time
from typing import Dict, List, Optional, Sequence

from . import parsers
from .store import Store

EXT_WHITELIST = {".json", ".jsonl", ".txt", ".csv", ".tsv", ".xml", ".nessus", ".md"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".idea", ".vscode", ".Trash", "Library", "hermes-wiki",
             # APK 反编译产物 / 前端打包目录：里面的 .json/.txt 是应用资源，不是扫描结果
             "smali", "smali_classes2", "smali_classes3", "smali_classes4",
             "original", "META-INF", "res", "assets", "apktool-i"}
MAX_FILES = 4000
MAX_DEPTH = 4


class Ingestor:
    def __init__(self, store: Store, inboxes: Sequence[str]):
        self.store = store
        self.inboxes = [os.path.abspath(os.path.expanduser(p)) for p in inboxes]
        self.last_run: Optional[Dict] = None
        self.running = False

    # ------------------------------------------------------------ 遍历

    def _iter_files(self, root: str):
        root_depth = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count(os.sep) - root_depth >= MAX_DEPTH:
                dirnames[:] = []
            # 引擎自己的运行时目录（scan-*/progress 进度事件、scan-*/logs 原始日志）
            # 不是扫描产物：解析它们只会往收件箱里塞一堆「格式无法识别」的噪音。
            parent = os.path.basename(os.path.dirname(dirpath))
            if os.path.basename(dirpath) in ("progress", "logs") and parent.startswith("scan-"):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            for name in filenames:
                if os.path.splitext(name)[1].lower() not in EXT_WHITELIST:
                    continue
                yield os.path.join(dirpath, name)

    # ------------------------------------------------------------ 主流程

    def scan(self, force: bool = False, budget_s: float = 45.0) -> Dict:
        """扫一遍所有收件箱。force=True 时忽略 mtime 缓存全部重解析。"""
        started = time.time()
        stats = {"inboxes": self.inboxes, "seen": 0, "parsed": 0, "unchanged": 0,
                 "skipped": 0, "errors": 0, "findings_added": 0, "findings_merged": 0,
                 "assets": 0, "elapsed": 0.0, "truncated": False}
        if self.running:
            return {"busy": True, **stats}
        self.running = True
        try:
            for root in self.inboxes:
                if not os.path.isdir(root):
                    self.store.log("warn", f"收件箱不存在：{root}")
                    continue
                for path in self._iter_files(root):
                    if stats["seen"] >= MAX_FILES:
                        stats["truncated"] = True
                        self.store.log("warn", f"达到单次扫瞄上限 {MAX_FILES} 个文件，剩余留到下次")
                        break
                    if time.time() - started > budget_s:
                        stats["truncated"] = True
                        self.store.log("info", f"本轮已达 {budget_s:.0f}s 时间预算，剩余文件下次继续")
                        break
                    stats["seen"] += 1
                    try:
                        self._one(path, stats, force)
                    except Exception as exc:  # 单文件失败不该中断整轮
                        stats["errors"] += 1
                        self.store.log("error", f"{path}：{type(exc).__name__}: {exc}")
        finally:
            stats["elapsed"] = round(time.time() - started, 2)
            self.running = False
            self.last_run = stats
            # 只在这轮真的发生了什么时才写日志：否则后台每 5s 一次「全部未变」会把日志刷爆
            if stats["parsed"] or stats["skipped"] or stats["errors"]:
                self.store.log("info",
                               f"扫描完成：文件 {stats['parsed']} 解析 / {stats['unchanged']} 未变 / "
                               f"{stats['skipped']} 跳过 / {stats['errors']} 失败；"
                               f"新增 {stats['findings_added']} 合并 {stats['findings_merged']}，资产 {stats['assets']}，"
                               f"耗时 {stats['elapsed']}s")
        return stats

    def _one(self, path: str, stats: Dict, force: bool) -> None:
        try:
            st = os.stat(path)
        except OSError as exc:
            stats["errors"] += 1
            self.store.log("warn", f"stat 失败 {path}：{exc}")
            return
        prev = self.store.file_state(path)
        # 缓存键带解析器代次：解析逻辑升级后（PARSER_GEN +1）旧指纹自然失效，
        # 全部产物重解析一次，用户不用记得加 --force。
        same_gen = bool(prev) and str(prev.get("digest") or "").startswith(f"g{parsers.PARSER_GEN}:")
        if (not force and same_gen and prev
                and abs(prev["mtime"] - st.st_mtime) < 1e-6 and prev["size"] == st.st_size):
            stats["unchanged"] += 1
            return

        digest = ""
        try:
            digest = parsers.gen_digest(path)
        except OSError as exc:
            stats["errors"] += 1
            self.store.log("warn", f"读取失败 {path}：{exc}")
            return
        if not force and prev and prev.get("digest") == digest:
            # 内容没变（只是被 touch 过）：更新一下状态，省掉解析
            self.store.upsert_file(path, st.st_mtime, st.st_size, digest, prev["fmt"],
                                   prev["findings"] or 0, prev["assets"] or 0, prev["note"] or "")
            stats["unchanged"] += 1
            return

        result = parsers.parse_file(path)
        if result.fmt in ("skipped", "unknown", "error"):
            stats["skipped"] += 1
            self.store.upsert_file(path, st.st_mtime, st.st_size, digest, result.fmt, 0, 0, result.note)
            self.store.log("detail",
                           f"{os.path.basename(path)} → {result.fmt}：{result.note}")
            return

        added, merged = self.store.add_findings(result.findings, path)
        n_assets = self.store.add_assets(result.assets, path)
        self.store.upsert_file(path, st.st_mtime, st.st_size, digest, result.fmt,
                               len(result.findings), len(result.assets), result.note)
        stats["parsed"] += 1
        stats["findings_added"] += added
        stats["findings_merged"] += merged
        stats["assets"] += n_assets
        self.store.log(
            "detail",
            f"{os.path.basename(path)}  [{result.fmt}]  漏洞 {len(result.findings)}"
            f"（新增 {added} / 合并 {merged}）资产 {n_assets}"
            + (f"　{result.note}" if result.note else ""),
        )

    # ------------------------------------------------------------ 变化检测（给前端轮询用）

    def dirty(self) -> bool:
        """收件箱里是否有新变化的文件（只看 mtime/size，不做内容指纹）。"""
        for root in self.inboxes:
            if not os.path.isdir(root):
                continue
            for path in self._iter_files(root):
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                prev = self.store.file_state(path)
                if not prev or abs(prev["mtime"] - st.st_mtime) > 1e-6 or prev["size"] != st.st_size:
                    return True
        return False

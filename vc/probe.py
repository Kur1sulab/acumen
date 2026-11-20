"""复验流水线的传输层：一次精确请求，由引擎子进程发出。

为什么不在这里建连
    tools/check_offline.py 把 Python 侧的出站能力全部禁掉了（产品纪律：空境自身不联网，
    扫描动作全部由本地引擎完成；唯一例外是 vc/cli.py 对目标的一次协议握手）。
    所以 L1/L2/L3 需要「把 payload 换到另一个参数名再打一枪」这种精确控制时，
    走的是引擎的 `replay` 子命令：发一次请求、把响应原样落成 JSON，Python 只读产物。

产物契约（engine-go/replay，与 sweep 的其它子命令同一套落盘习惯）
    <out>/replay.json:
        kind      "sweep_replay"
        url       请求 URL（原样）
        final_url 跟随重定向后的 URL
        method    GET/POST/…
        status    HTTP 状态码；0 = 没拿到响应
        size      正文字节数
        digest    sha256(正文) 前 16 位
        ms        引擎侧耗时
        headers   响应头（键小写）
        body      正文前 4096 字节
        error     传输层错误的原文（status=0 时才有意义）

降级行为
    引擎版本旧、没有 replay 子命令时，`available()` 返回 False：
    调用方据此走老的「重跑整个模式」复验，并明确告诉用户为什么没走三层流水线。
    绝不假装跑过——那会把「没验」记成「验过」。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

REPLAY_ARG = "replay"
ARTIFACT = "replay.json"


class EngineProber:
    """把一条探测请求交给引擎执行，返回 {status, headers, body, url, error}。"""

    def __init__(self, engine: str, timeout: int = 10, workdir: str = ""):
        self.engine = engine or ""
        self.timeout = max(1, int(timeout or 10))
        self.calls = 0                 # 给 CLI 报「这次一共打了几枪」
        self.failures = 0
        self._dir = workdir or tempfile.mkdtemp(prefix="kara-probe-")
        self._own_dir = not workdir
        self._supports: Optional[bool] = None

    # —— 能力探测 ——

    def available(self) -> bool:
        """引擎支不支持 replay。只问一次，结果缓存。

        判据是「缺参数时的用法提示里带 replay」：老引擎没有这个子命令，
        会走未知子命令分支（输出里不会有 replay 的用法行）。
        """
        if self._supports is not None:
            return self._supports
        if not self.engine or not os.path.isfile(self.engine):
            self._supports = False
            return False
        try:
            proc = subprocess.run([self.engine, REPLAY_ARG], capture_output=True,
                                  text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            self._supports = False
            return False
        blob = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        self._supports = REPLAY_ARG in blob and "-u" in blob
        return self._supports

    # —— 发一枪 ——

    def __call__(self, req: Dict[str, Any]) -> Dict[str, Any]:
        url = str(req.get("url") or "")
        method = str(req.get("method") or "GET").upper()
        body = str(req.get("body") or "")
        headers = req.get("headers") or {}
        if not url:
            return {"status": 0, "error": "空 URL"}

        self.calls += 1
        out = os.path.join(self._dir, f"p{self.calls:04d}")
        argv: List[str] = [self.engine, REPLAY_ARG, "-u", url, "-m", method,
                           "-o", out, "--timeout", str(self.timeout)]
        if body:
            argv += ["--data", body]
        for k, v in dict(headers).items():
            argv += ["--header", f"{k}: {v}"]

        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.timeout + 15)
        except subprocess.TimeoutExpired:
            self.failures += 1
            return {"status": 0, "error": f"引擎超时（>{self.timeout + 15}s）"}
        except (OSError, subprocess.SubprocessError) as exc:
            self.failures += 1
            return {"status": 0, "error": f"引擎没起来：{type(exc).__name__}: {exc}"}

        path = os.path.join(out, ARTIFACT)
        if not os.path.isfile(path):
            self.failures += 1
            tail = ((proc.stderr or proc.stdout or "").strip().splitlines() or [""])[-1]
            return {"status": 0, "error": f"引擎没落出 {ARTIFACT}（rc={proc.returncode}）：{tail[:160]}"}
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            self.failures += 1
            return {"status": 0, "error": f"产物读不出来：{exc}"}
        if not isinstance(doc, dict):
            self.failures += 1
            return {"status": 0, "error": "产物不是 JSON 对象"}

        status = doc.get("status")
        try:
            status = int(status or 0)
        except (TypeError, ValueError):
            status = 0
        err = str(doc.get("error") or "")
        if status:
            self.failures += 0        # 有状态码就算打到了，传输层不算失败
        else:
            self.failures += 1
        return {
            "status": status,
            "headers": doc.get("headers") or {},
            "body": str(doc.get("body") or ""),
            "url": str(doc.get("final_url") or url),
            "error": err,
            "ms": doc.get("ms") or 0,
        }

    # —— 收尾 ——

    def close(self) -> None:
        if self._own_dir:
            shutil.rmtree(self._dir, ignore_errors=True)

    def __enter__(self) -> "EngineProber":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def stats(self) -> Dict[str, int]:
        return {"calls": self.calls, "failures": self.failures}

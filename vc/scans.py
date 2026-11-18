"""扫描控制（Scan Control）—— 把本机 sweep 引擎接进控制台。

边界（延续 v1 的本地/只读基调，扫的是哥哥授权的目标，控制面只在本机）：
  * 零三方依赖，只用标准库；引擎是本地二进制，subprocess **列表参数**启动，绝不拼 shell；
  * 目标先过字符白名单再上命令行，空格/引号/分号/换行这类注入形状直接拒；
  * 并发有上限、单目标有超时、停止走进程组 TERM→KILL；
  * 产物只落在收件箱内的任务目录 <inbox>/scan-<时间>-<id>/out/<target>/，
    由既有摄入器收进库——扫描器不直接写控制台数据表。

进度来自引擎自己的 --progress-file JSONL 契约（ts/event/module/detail），
不是猜 stdout：pipeline_start → start(x) → done|fail(x) → pipeline_end。
"""

from __future__ import annotations

import collections
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import threading
import time

# ---------------------------------------------------------------- 模式表

# flag 与 sweep 子命令一一对应（见 sweep help）：
#   all/portscan 吃 -t（域名或 IP 都行）；fingerprint/api/paths/jsintel 吃 -u；
#   baseline/subdomain 吃 -d。
MODES = {
    "all": {
        "label": "全流程", "sub": "all", "flag": "-t", "kind": "target", "expect": 10,
        "hint": "子域→验活→资产→备案→指纹→路径→API→JS→端口→报告",
    },
    "portscan": {
        "label": "端口扫描", "sub": "portscan", "flag": "-t", "kind": "target", "expect": 1,
        "hint": "TCP connect 常用端口表 + 旗帜抓取识别服务",
    },
    "fingerprint": {
        "label": "指纹识别", "sub": "fingerprint", "flag": "-u", "kind": "url", "expect": 1,
        "hint": "headers + body 双通道指纹规则",
    },
    "api": {
        "label": "API 未授权", "sub": "api", "flag": "-u", "kind": "url", "expect": 1,
        "hint": "27 个候选端点，软 404 基线过滤 + 命中取证",
    },
    "jsintel": {
        "label": "JS 情报", "sub": "jsintel", "flag": "-u", "kind": "url", "expect": 1,
        "hint": "外链 JS 抽接口/密钥线索（只 GET，并发 ≤6）",
    },
    "paths": {
        "label": "敏感路径", "sub": "paths", "flag": "-u", "kind": "url", "expect": 1,
        "hint": ".git/.env/swagger/actuator/druid 等路径探测",
    },
    "baseline": {
        "label": "域名基线", "sub": "baseline", "flag": "-d", "kind": "domain", "expect": 1,
        "hint": "域名暴露面 8 项基线检查",
    },
    "subdomain": {
        "label": "子域枚举", "sub": "subdomain", "flag": "-d", "kind": "domain", "expect": 1,
        "hint": "证书日志枚举子域（crt.sh → certspotter 兜底）",
    },
    "strike": {
        "label": "深度验证", "sub": "strike", "flag": "-t", "kind": "any", "expect": 1,
        "hint": "内建验证内核：端口/服务真登/未授权/注入/敏感路径，判定到 L1/L2（真发请求）",
    },
}

MAX_TARGETS = 64
MAX_PARALLEL = 4
DEFAULT_PARALLEL = 2
DEFAULT_TIMEOUT = 900
LOG_KEEP = 900          # 内存里保留的日志行数
ENGINE_HINT = ("未找到扫描引擎 sweep。\n"
               "  · 绿色版：确认包内 engine\\sweep.exe 还在（杀软有时会吞掉它）\n"
               "  · 源码目录：cd ~/tools/sweep/engine-go && "
               "go build -o ~/.local/bin/sweep ./cmd/atlas\n"
               "  · 或手动指定：kara --engine /path/to/sweep …")


class ScanError(Exception):
    """参数/引擎问题——直接回给界面看的中文错误。"""


# ---------------------------------------------------------------- 目标校验

# 允许出现在目标里的字符。刻意不含空格、引号、分号、管道、$、反引号、换行——
# 即便我们用列表传参不需要转义，也不让这类形状进命令行与目录名。
_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]")
_URL_CHARS = _HOST_CHARS | set("/?=&%#~+")


def _valid_target(t: str, kind: str) -> str:
    """校验并归一化单个目标；不合法抛 ScanError（带人话原因）。"""
    t = (t or "").strip()
    if not t:
        raise ScanError("目标为空")
    if len(t) > 300:
        raise ScanError("目标过长（>300 字符）")
    head = ""
    if "://" in t:
        scheme, rest = t.split("://", 1)
        if scheme.lower() not in ("http", "https"):
            raise ScanError("只支持 http/https 目标")
        if kind not in ("url", "any"):
            raise ScanError("该模式吃域名/IP，不要带 http:// 前缀")
        head = scheme.lower() + "://"
    else:
        rest = t
    if kind in ("url", "any"):
        # 从浏览器地址栏复制来的 URL 几乎都带尾斜杠，那是合法目标，不该被拒收
        rest = rest.rstrip("/") or rest
    allowed = _URL_CHARS if kind in ("url", "any") else _HOST_CHARS
    bad = sorted({c for c in rest if c not in allowed})
    if bad:
        raise ScanError("目标含非法字符：" + " ".join(repr(c) for c in bad[:4]))
    if ".." in rest:
        raise ScanError("目标含 '..'（不允许路径穿越形状）")
    if rest.startswith((".", "-", "/")) or rest.endswith((".", "-", "/")):
        raise ScanError("目标不能以 . - / 开头或结尾")
    if kind == "any":
        return head + rest
    if kind == "url":
        return (head or "https://") + rest
    if kind == "domain" and ("[" in rest or ":" in rest):
        raise ScanError("该模式只吃域名，不要带端口")
    return rest


def normalize_targets(mode: str, raw) -> list:
    """多行文本/数组 → 去重后的合法目标列表（保持输入顺序）。"""
    spec = MODES.get(mode) or (_ for _ in ()).throw(ScanError("未知扫描模式：" + str(mode)))
    if isinstance(raw, str):
        items = re.split(r"[\s,]+", raw)
    else:
        items = list(raw or [])
    out, seen, errors = [], set(), []
    for it in items:
        if isinstance(it, str) and not it.strip():
            continue
        try:
            t = _valid_target(str(it), spec["kind"])
        except ScanError as e:
            errors.append(f"{str(it).strip()}: {e}")
            continue
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    if errors:
        raise ScanError("目标不合法 —— " + "；".join(errors[:5]))
    if not out:
        raise ScanError("没有有效目标")
    if len(out) > MAX_TARGETS:
        raise ScanError(f"单次最多 {MAX_TARGETS} 个目标（收到 {len(out)} 个）")
    return out


# ---------------------------------------------------------------- 引擎发现

# 包根 = vc/ 的上一级。绿色版把引擎放在这里，随包分发，不依赖机器上装过什么。
PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_EXE = ".exe" if os.name == "nt" else ""


def _bundled_engines() -> list:
    """包内引擎候选路径（绿色版 / 源码目录 / vendor）。"""
    return [
        os.path.join(PKG_ROOT, "engine", "sweep" + _EXE),
        os.path.join(PKG_ROOT, "sweep" + _EXE),
        os.path.join(PKG_ROOT, "vendor", "sweep" + _EXE),
    ]


def find_engine(explicit: str = "") -> str:
    """按优先级找 sweep 二进制；找不到返回空串。

    显式指定（--engine / VC_RECON_BIN）时**只认它**——指错了就明确报找不到，
    免得悄悄换成另一个二进制跑，排查时看不到真相。

    其它情况先看包内再看系统 PATH：绿色版自带的引擎版本跟当前界面是一起发的，
    优先级低于机器上那个同名旧二进制的话，会出现「界面新、引擎旧」的错配。
    """
    if explicit:
        p = os.path.abspath(os.path.expanduser(explicit))
        return p if os.path.isfile(p) and os.access(p, os.X_OK) else ""
    cands = [os.environ.get("VC_RECON_BIN", "")] + _bundled_engines() + [
        shutil.which("sweep") or "",
        "~/.local/bin/sweep",
        "~/tools/sweep/engine-go/sweep",
        "~/go/bin/sweep",
    ]
    for c in cands:
        if not c:
            continue
        p = os.path.abspath(os.path.expanduser(c))
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return ""


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(target: str) -> str:
    """目标 → 安全文件名（进度/日志用；产物目录名由引擎自己清洗）。"""
    base = _SAFE_NAME.sub("_", target).strip("._") or "target"
    return base[:60]


# ---------------------------------------------------------------- 管理器

class ScanManager:
    """扫描任务管理器：一个后台 worker 池 + 内存态 + SQLite 持久化。

    - 任务（job）一次提交一批目标；每个目标一条 run；
    - run 的步骤实时来自引擎 --progress-file；
    - 结果落在收件箱里，由 Ingestor 自动入账（本类只在结束时踢一脚 ingest）。
    """

    def __init__(self, db_path: str, inbox_root: str, engine: str = "",
                 mode_args: Optional[list] = None, timeout: int = DEFAULT_TIMEOUT, max_parallel: int = DEFAULT_PARALLEL,
                 ingest_cb=None):
        self.db_path = db_path
        self.inbox_root = os.path.abspath(os.path.expanduser(inbox_root))
        self.engine = find_engine(engine)
        # 深层模式（strike）要往引擎追加参数（--ports/--intensity…）；普通模式为空
        self.mode_args = [str(a) for a in (mode_args or [])]
        self.timeout = max(30, int(timeout))
        self.max_parallel = max(1, min(MAX_PARALLEL, int(max_parallel)))
        self.ingest_cb = ingest_cb
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, timeout=15, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        # 运行时态：run_id -> {"steps": [...], "proc": Popen, "stop": Event, ...}
        self._live = {}
        # 任务级日志：job_id -> {"lines": deque, "next": int}
        self._logs = {}
        self._stopping = set()
        self._reap_orphans()

    # ------------------------------------------------------------ 存储

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_jobs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mode TEXT, targets TEXT, status TEXT, parallel INTEGER,
                    timeout INTEGER, created REAL, started REAL, finished REAL,
                    dir TEXT, note TEXT
                );
                CREATE TABLE IF NOT EXISTS scan_runs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id INTEGER, target TEXT, status TEXT, step TEXT,
                    steps TEXT, exit_code INTEGER, started REAL, finished REAL,
                    findings INTEGER DEFAULT 0, error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_sr_job ON scan_runs(job_id);
                """
            )
            self._conn.commit()

    def _exec(self, sql: str, args=()) -> None:
        with self._lock:
            self._conn.execute(sql, args)
            self._conn.commit()

    def _rows(self, sql: str, args=()) -> list:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def _reap_orphans(self) -> None:
        """上个进程留下的 running/queued —— 进程已不在，标记中断而不是骗人。"""
        self._exec("UPDATE scan_jobs SET status='interrupted', finished=? "
                   "WHERE status IN ('queued','running')", (time.time(),))
        self._exec("UPDATE scan_runs SET status='interrupted', finished=? "
                   "WHERE status IN ('queued','running')", (time.time(),))

    # ------------------------------------------------------------ 元信息

    def meta(self) -> dict:
        ok = bool(self.engine)
        ver = ""
        if ok:
            # 先问 `version` 子命令；问不出来再退回无参输出的横幅。
            # 无参直接打印的还是帮助文本——第一行含 sweep 的是用法标题，不是版本号。
            for argv in ([self.engine, "version"], [self.engine]):
                try:
                    cp = subprocess.run(argv, capture_output=True, text=True,
                                        encoding="utf-8", errors="replace", timeout=5)
                except Exception:
                    continue
                lines = [ln for ln in (cp.stdout or "").splitlines() if "sweep" in ln]
                picked = next((ln for ln in lines if re.search(r"\bv?\d+\.\d+\.\d+", ln)), "")
                picked = picked or (lines[0] if lines else "")
                ver = picked.strip()[:120]
                if ver:
                    break
        return {
            "engine": {"path": self.engine, "ok": ok, "version": ver,
                       "hint": "" if ok else ENGINE_HINT},
            "modes": [{"id": k, "label": v["label"], "kind": v["kind"],
                       "expect": v["expect"], "hint": v["hint"]} for k, v in MODES.items()],
            "inbox_root": self.inbox_root,
            "limits": {"max_targets": MAX_TARGETS, "max_parallel": MAX_PARALLEL,
                       "timeout": self.timeout},
            "defaults": {"parallel": self.max_parallel, "timeout": self.timeout},
        }

    # ------------------------------------------------------------ 启动 / 查询 / 停止

    def start(self, mode: str, targets, parallel=None, timeout=None) -> dict:
        if mode not in MODES:
            raise ScanError("未知扫描模式：" + str(mode))
        if not self.engine:
            raise ScanError(ENGINE_HINT)
        tset = normalize_targets(mode, targets)
        par = max(1, min(self.max_parallel, int(parallel or self.max_parallel)))
        tmo = max(30, min(7200, int(timeout or self.timeout)))

        stamp = time.strftime("%Y%m%d-%H%M%S")
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scan_jobs(mode,targets,status,parallel,timeout,created) "
                "VALUES(?,?,?,?,?,?)",
                (mode, json.dumps(tset, ensure_ascii=False), "queued", par, tmo, time.time()))
            self._conn.commit()
            job_id = cur.lastrowid
            job_dir = os.path.join(self.inbox_root, f"scan-{stamp}-{job_id}")
            for sub in ("out", "progress", "logs"):
                os.makedirs(os.path.join(job_dir, sub), exist_ok=True)
            self._exec("UPDATE scan_jobs SET dir=? WHERE id=?", (job_dir, job_id))
            for t in tset:
                self._conn.execute(
                    "INSERT INTO scan_runs(job_id,target,status,steps) VALUES(?,?,?,?)",
                    (job_id, t, "queued", "[]"))
            self._conn.commit()
            self._logs[job_id] = {"lines": collections.deque(maxlen=LOG_KEEP), "next": 0}
            self._log(job_id, None, f"任务 #{job_id} 排队：{MODES[mode]['label']} · "
                                    f"{len(tset)} 个目标 · 并发 {par} · 超时 {tmo}s")

        th = threading.Thread(target=self._run_job, args=(job_id, mode, tset, par, tmo),
                              name=f"scan-job-{job_id}", daemon=True)
        th.start()
        return {"ok": True, "job_id": job_id, "dir": job_dir, "count": len(tset)}

    def jobs(self, limit: int = 12) -> list:
        rows = self._rows(
            "SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ?", (max(1, int(limit)),))
        out = []
        for r in rows:
            counts = self._run_counts(r["id"])
            out.append({
                "id": r["id"], "mode": r["mode"],
                "mode_label": MODES.get(r["mode"], {}).get("label", r["mode"]),
                "status": r["status"], "created": r["created"], "finished": r["finished"],
                "targets": json.loads(r["targets"] or "[]"),
                "counts": counts,
                "findings": self._count_findings(r["dir"] or "", None),
                "elapsed": self._elapsed(r["created"], r["finished"]),
            })
        return out

    def job(self, job_id: int, log_from=None, log_limit: int = 300) -> dict:
        rows = self._rows("SELECT * FROM scan_jobs WHERE id=?", (int(job_id),))
        if not rows:
            return {}
        j = rows[0]
        runs_rows = self._rows("SELECT * FROM scan_runs WHERE job_id=? ORDER BY id", (j["id"],))
        runs = []
        for r in runs_rows:
            live = self._live.get(r["id"])
            steps = live["steps"] if live else json.loads(r["steps"] or "[]")
            status = live["status"] if live else r["status"]
            started = (live or {}).get("started") or r["started"]
            finished = (live or {}).get("finished") or r["finished"]
            expect = self._expect(j["mode"], steps)
            done = sum(1 for s in steps if s["status"] in ("done", "failed", "skipped"))
            pct = 100 if status in ("ok", "failed", "stopped", "timeout", "interrupted") \
                else min(99, int(round(done * 100.0 / max(1, expect))))
            runs.append({
                "id": r["id"], "target": r["target"], "status": status,
                "step": (live or {}).get("step") or r["step"] or "",
                "steps": steps, "done": done, "expect": expect, "pct": pct,
                "started": started, "finished": finished,
                "elapsed": self._elapsed(started, finished),
                "exit_code": (live or {}).get("exit_code", r["exit_code"]),
                "error": (live or {}).get("error") or r["error"] or "",
                "findings": self._count_findings(j["dir"] or "", r["target"]),
            })
        log = self._logs.get(j["id"])
        if log_from is None:
            log_from = max(0, log["next"] - log_limit) if log else 0
        lines = list(log["lines"])[-log_limit:] if log else []
        if log:
            first_idx = log["next"] - len(lines)
            lines = [ln for i, ln in enumerate(lines, start=first_idx) if i >= int(log_from)]
        return {
            "id": j["id"], "mode": j["mode"],
            "mode_label": MODES.get(j["mode"], {}).get("label", j["mode"]),
            "status": j["status"], "created": j["created"], "started": j["started"],
            "finished": j["finished"], "parallel": j["parallel"], "timeout": j["timeout"],
            "dir": j["dir"] or "", "runs": runs,
            "counts": self._run_counts(j["id"]),
            "findings": self._count_findings(j["dir"] or "", None),
            "elapsed": self._elapsed(j["created"], j["finished"]),
            "log": {"from": int(log_from), "next": log["next"] if log else 0, "lines": lines},
        }

    def stop(self, job_id: int) -> dict:
        with self._lock:
            self._stopping.add(int(job_id))
            killed = 0
            for rid, st in list(self._live.items()):
                if st.get("job_id") != int(job_id):
                    continue
                proc = st.get("proc")
                if proc and proc.poll() is None:
                    self._kill(proc)
                    killed += 1
            self._log(job_id, None, f"收到停止指令，终止 {killed} 个运行中的进程")
            self._exec("UPDATE scan_jobs SET status='stopping' WHERE id=? AND "
                       "status IN ('queued','running')", (int(job_id),))
        return {"ok": True, "killed": killed}

    def active(self) -> int:
        return sum(1 for st in self._live.values() if st.get("proc")
                   and st["proc"].poll() is None)

    def shutdown(self) -> None:
        for rid, st in list(self._live.items()):
            proc = st.get("proc")
            if proc and proc.poll() is None:
                self._kill(proc)

    # ------------------------------------------------------------ 执行

    def _run_job(self, job_id: int, mode: str, targets: list, parallel: int, tmo: int) -> None:
        self._exec("UPDATE scan_jobs SET status='running', started=? WHERE id=?",
                   (time.time(), job_id))
        queue = collections.deque(targets)
        qlock = threading.Lock()

        def worker():
            while True:
                with qlock:
                    if not queue or job_id in self._stopping:
                        return
                    target = queue.popleft()
                try:
                    self._run_target(job_id, mode, target, tmo)
                except Exception as e:  # 单目标崩不拖垮整个任务
                    self._log(job_id, target, f"[!] 运行异常: {e}")

        ths = [threading.Thread(target=worker, daemon=True,
                                name=f"scan-{job_id}-w{i}")
               for i in range(min(parallel, len(targets)))]
        for t in ths:
            t.start()
        for t in ths:
            t.join()

        rows = self._rows("SELECT status FROM scan_runs WHERE job_id=?", (job_id,))
        st = [r["status"] for r in rows]
        if job_id in self._stopping:
            job_status = "stopped"
        elif st and all(s == "ok" for s in st):
            job_status = "ok"
        elif any(s == "ok" for s in st):
            job_status = "partial"
        else:
            job_status = "failed"
        self._exec("UPDATE scan_jobs SET status=?, finished=? WHERE id=?",
                   (job_status, time.time(), job_id))
        self._log(job_id, None, f"任务 #{job_id} 结束：{job_status} · "
                                f"入账 {self._count_findings(self._job_dir(job_id), None)} 条")
        self._kick_ingest()
        with self._lock:
            self._stopping.discard(job_id)

    def _run_target(self, job_id: int, mode: str, target: str, tmo: int) -> None:
        spec = MODES[mode]
        job_dir = self._job_dir(job_id)
        row = self._rows("SELECT id FROM scan_runs WHERE job_id=? AND target=? "
                         "ORDER BY id LIMIT 1", (job_id, target))
        if not row:
            return
        run_id = row[0]["id"]
        slug = safe_name(target)
        progress_path = os.path.join(job_dir, "progress", slug + ".jsonl")
        log_path = os.path.join(job_dir, "logs", slug + ".log")
        argv = [self.engine, "--progress-file", progress_path, spec["sub"], spec["flag"], target]
        if spec["sub"] == "strike" and self.mode_args:
            argv += self.mode_args

        with self._lock:
            self._live[run_id] = {"job_id": job_id, "target": target, "status": "running",
                                  "steps": [], "step": "", "started": time.time(),
                                  "finished": None, "exit_code": None, "error": "",
                                  "proc": None, "log_next": 0}
        self._exec("UPDATE scan_runs SET status='running', started=? WHERE id=?",
                   (time.time(), run_id))
        self._log(job_id, target, f"$ {' '.join(argv[3:])}   (cwd={job_dir})")

        stop_evt = threading.Event()
        tail = threading.Thread(target=self._tail_progress, args=(run_id, progress_path, stop_evt),
                                daemon=True)
        tail.start()

        status, code, err = "failed", None, ""
        proc = None
        try:
            with open(log_path, "w", encoding="utf-8") as logf:
                proc = subprocess.Popen(
                    argv, cwd=job_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    bufsize=1, start_new_session=True)
                with self._lock:
                    self._live[run_id]["proc"] = proc
                deadline = time.time() + tmo
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if line:
                        logf.write(line + "\n")
                        logf.flush()
                        self._log(job_id, target, line)
                    if time.time() > deadline:
                        self._kill(proc)
                        status, err = "timeout", f"超过 {tmo}s 超时被终止"
                        break
                code = proc.wait(timeout=30)
                if status != "timeout":
                    if job_id in self._stopping:
                        status = "stopped"
                    elif code == 0:
                        status = "ok"
                    else:
                        status, err = "failed", f"引擎退出码 {code}"
        except FileNotFoundError:
            status, err = "failed", "引擎二进制不见了：" + self.engine
        except Exception as e:
            status, err = "failed", f"启动失败：{e}"
        finally:
            stop_evt.set()
            tail.join(timeout=2)
            self._drain_progress(run_id, progress_path, 0)   # 兜底：全量补一次（幂等）
            if proc and proc.poll() is None:
                self._kill(proc)
            if proc and proc.stdout:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            if job_id in self._stopping:
                status = "stopped"

        with self._lock:
            st = self._live.get(run_id) or {}
            st.update({"status": status, "finished": time.time(), "exit_code": code, "error": err})
            steps = st.get("steps") or []
            self._live[run_id] = st
        self._exec("UPDATE scan_runs SET status=?, step=?, steps=?, exit_code=?, finished=?, "
                   "error=?, findings=? WHERE id=?",
                   (status, st.get("step") or "", json.dumps(steps, ensure_ascii=False), code,
                    time.time(), err, self._count_findings(job_dir, target), run_id))
        self._log(job_id, target, f"— {status.upper()} 用时 {self._elapsed(st.get('started'), st.get('finished'))}s"
                                 + (f" · {err}" if err else ""))
        self._kick_ingest()

    def _tail_progress(self, run_id: int, path: str, stop_evt: threading.Event) -> None:
        seen = 0
        while True:
            seen = self._drain_progress(run_id, path, seen)
            if stop_evt.wait(0.4):
                # 收尾再抽一次：秒级就结束的模块（端口/指纹）不能因为没等到下一个 tick 丢事件
                self._drain_progress(run_id, path, seen)
                return

    def _drain_progress(self, run_id: int, path: str, seen: int = 0) -> int:
        """把进度文件里新增的行喂给状态机；返回已消费的行数（重复喂是幂等的）。"""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except (FileNotFoundError, OSError):
            return seen
        for ln in lines[seen:]:
            self._apply_event(run_id, ln)
        return max(seen, len(lines))

    def _apply_event(self, run_id: int, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except Exception:
            return
        e = ev.get("event") or ""
        mod = ev.get("module") or ""
        detail = ev.get("detail") or ""
        ts = ev.get("ts")
        with self._lock:
            st = self._live.get(run_id)
            if not st:
                return
            steps = st["steps"]
            idx = next((i for i, s in enumerate(steps) if s["name"] == mod), -1)
            if e == "start":
                st["step"] = mod
                if idx < 0:
                    steps.append({"name": mod, "status": "running", "ts": ts, "detail": ""})
                else:
                    steps[idx].update({"status": "running", "ts": ts})
            elif e in ("done", "fail"):
                if idx < 0:
                    steps.append({"name": mod, "status": "done" if e == "done" else "failed",
                                  "ts": ts, "detail": detail})
                else:
                    steps[idx].update({"status": "done" if e == "done" else "failed",
                                       "ts": ts, "detail": detail})
                if st.get("step") == mod:
                    st["step"] = ""
            elif e == "pipeline_start":
                st["step"] = detail or mod

    # ------------------------------------------------------------ 小工具

    def _job_dir(self, job_id: int) -> str:
        rows = self._rows("SELECT dir FROM scan_jobs WHERE id=?", (int(job_id),))
        return (rows[0]["dir"] if rows else "") or ""

    def _run_counts(self, job_id: int) -> dict:
        out = {"total": 0, "queued": 0, "running": 0, "ok": 0, "failed": 0,
               "stopped": 0, "timeout": 0, "interrupted": 0}
        for r in self._rows("SELECT status, COUNT(*) c FROM scan_runs WHERE job_id=? "
                            "GROUP BY status", (int(job_id),)):
            out[r["status"]] = r["c"]
            out["total"] += r["c"]
        # 内存里跑着的 run 以实时状态为准（DB 里还没落）
        for st in self._live.values():
            if st.get("job_id") == int(job_id) and st.get("status") == "running":
                pass
        return out

    def _count_findings(self, job_dir: str, target) -> int:
        """统计这批产物入账了多少条命中（按来源文件路径反查，不猜）。"""
        if not job_dir:
            return 0
        like = job_dir.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        try:
            if target:
                host = target.split("://")[-1].split("/")[0]
                rows = self._rows(
                    "SELECT COUNT(*) c FROM findings WHERE files LIKE ? ESCAPE '\\' "
                    "AND (asset LIKE ? OR endpoint LIKE ?)",
                    (f"%{like}%", f"%{host}%", f"%{host}%"))
            else:
                rows = self._rows("SELECT COUNT(*) c FROM findings WHERE files LIKE ? ESCAPE '\\'",
                                  (f"%{like}%",))
            return int(rows[0]["c"]) if rows else 0
        except Exception:
            return 0

    @staticmethod
    def _elapsed(a, b) -> float:
        if not a:
            return 0.0
        return round((b or time.time()) - a, 1)

    @staticmethod
    def _expect(mode: str, steps: list) -> int:
        """预期步骤数：all 有 IP/域名两条分支（7 / 10），按首个步骤判，别让进度条撒谎。"""
        if mode != "all":
            return 1
        if steps and steps[0]["name"] == "reverse":
            return 7
        return 10

    def _log(self, job_id: int, target, line: str) -> None:
        with self._lock:
            log = self._logs.get(int(job_id))
            if log is None:
                log = {"lines": collections.deque(maxlen=LOG_KEEP), "next": 0}
                self._logs[int(job_id)] = log
            prefix = f"[{target}] " if target and self._multi_target(job_id) else ""
            log["lines"].append(prefix + line)
            log["next"] += 1

    def _multi_target(self, job_id: int) -> bool:
        rows = self._rows("SELECT targets FROM scan_jobs WHERE id=?", (int(job_id),))
        if not rows:
            return False
        try:
            return len(json.loads(rows[0]["targets"] or "[]")) > 1
        except Exception:
            return False

    def _kick_ingest(self) -> None:
        if not self.ingest_cb:
            return
        try:
            self.ingest_cb()
        except Exception:
            pass

    @staticmethod
    def _kill(proc) -> None:
        """整组 TERM，2.5s 后还在就 KILL（start_new_session=True 建的进程组）。"""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                return

        def later():
            try:
                proc.wait(timeout=2.5)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        threading.Thread(target=later, daemon=True).start()

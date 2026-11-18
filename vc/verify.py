"""命中复验：把「扫出来的结果」变成「能复现的结论」。

为什么要有这一层（这也是它和看板的分界线）
    看板把结果画出来就结束了；漏扫工具的活是让每一条命中都回答三个问题：
        凭什么算命中（证据）—— 怎么复现（命令）—— 现在还活着吗（复验）。
    三个问题答不上来，那条记录就只是一行好看的数字。

复验为什么是「重跑引擎」而不是自己发请求
    ① Python 侧出站被 tools/check_offline.py 拦着（标准库的出站模块一律禁用），
       这是产品纪律：空境自身不联网，扫描动作全部由本地引擎完成；
    ② 引擎自己带 soft-404 基线和 digest 二次确认，重跑一遍比手拼一次请求更可信；
    ③ 复验要和首次扫描走同一条代码路径，否则「变了」到底是目标变了还是工具变了，
       分不清。

判定只有三种，宁可说不知道也不猜
    仍存在    重跑成功，同一条命中再次出现
    已消失    重跑成功、这一类检查确实跑完了，命中没有再次出现
    无法判定  引擎不在 / 超时 / 退出码非 0 / 产物认不出 —— 一律不下结论

「不可复验」是第四种，给的不是引擎产物的条目（离线报告 MD、nuclei、nessus…）：
    它们没有可回访的目标，写「已消失」就是编造。宁可显示不可复验。

引擎产物落在 <cwd>/out/<host>/*.json（引擎没有 --out 参数），
所以每次复验都用一个临时目录做 cwd，跑完即弃，不污染工作区。
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from . import parsers_sweep as ps

# 来源标签 → 引擎子命令。只有本机引擎跑出来的条目才谈得上复验。
SOURCE_MODE = {
    "sweep-paths": "paths",
    "sweep-api": "api",
    "sweep-evidence": "api",
    "sweep-jsintel": "jsintel",
    "sweep-secheaders": "baseline",
    "sweep-webfiles": "baseline",
}

# 模式 → 产物里应该认得出的结果类型。跑完却没认到这一类结果 = 这次复验不算数。
MODE_KIND = {
    "paths": "sweep_paths",
    "api": "sweep_api",
    "jsintel": "sweep_jsintel",
    "baseline": "sweep_baseline",
}

STILL, GONE, UNKNOWN, NA = "仍存在", "已消失", "无法判定", "不可复验"
VERIFY_STATES = (STILL, GONE, UNKNOWN, NA)

MAX_BATCH = 60          # 一次最多复验多少条：重跑引擎是要花时间的，别让一个按钮把机器按住
DEFAULT_TIMEOUT = 300   # 单组（一个模式 × 一个目标）超时

_URL_HEAD = re.compile(r"^(https?)://([^/\s]+)", re.I)
_HOSTPORT = re.compile(r"^([^:/\s]+)(?::(\d{1,5}))?$")


# ------------------------------------------------------------------ 目标还原


def base_url(row: Dict[str, Any]) -> str:
    """从一条命中还原出「当初扫的那个入口」。

    优先级：引擎自己记下的 base（扫描时写进库，scheme/host/port 一个不差）→
    endpoint 自带的 scheme+host（引擎写的是 final_url）→ asset+port 拼一个。
    最后那条是猜的：http 目标猜成 https 会让引擎空手而归，
    所以这种「猜出来的入口」在 run_group 里要靠可达性判据兜底，不许直接下「已消失」。
    """
    saved = str(row.get("base") or "").strip()
    m0 = _URL_HEAD.match(saved)
    if m0:
        return f"{m0.group(1).lower()}://{m0.group(2).rstrip('/')}"
    ep = str(row.get("endpoint") or "").strip()
    m = _URL_HEAD.match(ep)
    if m:
        return f"{m.group(1).lower()}://{m.group(2).rstrip('/')}"
    host = str(row.get("asset") or "").strip()
    if not host:
        return ""
    host = host.split("://")[-1].split("/")[0]
    m2 = _HOSTPORT.match(host)
    if not m2:
        return ""
    port = row.get("port") or (int(m2.group(2)) if m2.group(2) else None)
    if port and not m2.group(2):
        host = f"{m2.group(1)}:{int(port)}"
    # 443 是 https 的常识，其余一律按 http 猜——猜错了可达性判据会拦住假结论
    scheme = "https" if str(port or "") == "443" else "http"
    # 默认端口写进 URL 只会让人以为特意指定过，去掉更干净（http://h、https://h 等价）
    for dflt in (":443" if scheme == "https" else ":80",):
        if host.endswith(dflt):
            host = host[: -len(dflt)]
    return f"{scheme}://{host}"


def domain_of(base: str) -> str:
    m = _URL_HEAD.match(base or "")
    if not m:
        return ""
    return m.group(2).split(":")[0]


def first_source(row: Dict[str, Any]) -> str:
    return str(row.get("sources") or "").split(",")[0].strip()


def plan_of(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """这条命中能不能复验？能的话怎么复验。返回 None = 不可复验。"""
    src = first_source(row)
    mode = SOURCE_MODE.get(src)
    if not mode:
        return None
    base = base_url(row)
    if not base:
        return None
    if mode == "baseline":
        check = src.split("-", 1)[1] if "-" in src else "secheaders"
        argv = ["baseline", "-d", domain_of(base) or base, "-u", base, "--checks", check]
    else:
        argv = [mode, "-u", base]
    return {"mode": mode, "base": base, "src": src, "argv": argv,
            "check": src.split("-", 1)[1] if "-" in src else "",
            "kind": MODE_KIND.get(mode, "")}


def ident(title: Any) -> str:
    """命中的身份：标题。

    不用 URL 当身份——跳转会让 final_url 变（/admin → /admin/login），
    端口/协议也随入口写法变；标题是解析层按命中点生成的，同一问题重跑必然同名。
    """
    return re.sub(r"\s+", " ", str(title or "")).strip().lower()


def repro_of(row: Dict[str, Any]) -> str:
    """复现命令。

    首选引擎取证目录里现成的那段（带判据、带预期现象，报告里能直接粘）；
    没有就按命中端点给一条最朴素的 GET —— 不写花的东西，命令越短越容易被人复跑。
    """
    saved = str(row.get("repro") or "").strip()
    if saved:
        return saved
    ep = str(row.get("endpoint") or "").strip()
    if not ep:
        return ""
    if not _URL_HEAD.match(ep):
        base = base_url(row)
        if not base:
            return ""
        ep = base + (ep if ep.startswith("/") else "/" + ep)
    return f"# 按命中端点原样请求（不带任何凭证）\ncurl -sk -i '{ep}' | head -c 2000"


def enrich(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """给列表补三个前端要用的派生字段（不改库里任何东西）。"""
    for r in rows:
        p = plan_of(r)
        r["verifiable"] = bool(p)
        r["verify_hint"] = "" if p else "这条不是本机引擎产物，没有可回访的目标"
        r["repro"] = repro_of(r)
    return rows


# ------------------------------------------------------------------ 重跑与比对

# 引擎自己会说「我到底连上目标没有」：paths 写 baseline，api 写每条的 error，jsintel 写 page_status。
# 这三种都要读——不看这个，http 目标被当成 https 重跑会得到「空手而归」，
# 然后顺理成章地报一个假的「已消失」。宁可说无法判定。
def _reach(doc: Dict[str, Any]) -> Optional[bool]:
    """这个产物能不能证明目标真被访问到了。True 能 / False 明确没连上 / None 说不准。"""
    bl = doc.get("baseline")
    if isinstance(bl, dict) and bl:
        kind = str(bl.get("kind") or "").lower()
        if kind == "unknown":
            return False
        return True
    entries = doc.get("all")
    if isinstance(entries, list) and entries and all(isinstance(x, dict) for x in entries):
        if all(x.get("status") in (None, 0, "") for x in entries):
            return False        # 每条都是 status=null + error，说明一个请求都没通
        return True
    if "page_status" in doc:
        return bool(doc.get("page_status")) and not doc.get("error")
    return None


def _collect(root: str) -> Tuple[set, List[Dict[str, Any]], str]:
    """读一遍新产物：认出哪些类型的结果、解析出哪些命中。

    返回 (认到的结果类型集合, 命中列表, 错误说明)。错误说明非空表示产物不可信。
    """
    kinds: set = set()
    items: List[Dict[str, Any]] = []
    reach: Optional[bool] = None
    rootp = pathlib.Path(root)
    if not rootp.is_dir():
        return kinds, items, "引擎没有产出目录"
    files = 0
    for p in sorted(rootp.rglob("*.json")):
        try:
            text = p.read_text("utf-8", "ignore")
        except OSError:
            continue
        files += 1
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, (dict, list)):
            kind = ps.detect(obj)
            if kind:
                kinds.add(kind)
            one = _reach(obj) if isinstance(obj, dict) else None
            # 只要有一份产物能证明连上了，就当连上了（不同模式各写各的）
            if one is True:
                reach = True
            elif one is False and reach is None:
                reach = False
        res = ps.parse(text, str(p))
        if res:
            items.extend(res.findings)
    if not files:
        return kinds, items, "产物目录是空的"
    if reach is False:
        return kinds, items, "引擎没连上目标（产物里全是失败记录），这次重跑不作数"
    return kinds, items, ""


def _fresh_note(items: List[Dict[str, Any]], want: str) -> str:
    for f in items:
        if ident(f.get("title")) == want:
            ev = str(f.get("evidence") or "").strip()
            return ev
    return ""


def run_group(engine: str, plan: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    """跑一组（一个模式 × 一个目标），只看结果不下结论。"""
    tmp = tempfile.mkdtemp(prefix="kara-verify-")
    out = {"kinds": set(), "items": [], "error": "", "elapsed": 0.0, "note": ""}
    t0 = time.time()
    try:
        proc = subprocess.run([engine] + plan["argv"], cwd=tmp, capture_output=True,
                              text=True, timeout=timeout)
        out["elapsed"] = round(time.time() - t0, 1)
        tail = " ".join(((proc.stderr or "") + " " + (proc.stdout or "")).split())[-160:]
        if proc.returncode != 0:
            out["error"] = f"引擎退出码 {proc.returncode}" + (f"：{tail}" if tail else "")
            return out
        kinds, items, err = _collect(os.path.join(tmp, "out"))
        out.update(kinds=kinds, items=items, error=err)
        return out
    except subprocess.TimeoutExpired:
        out["elapsed"] = round(time.time() - t0, 1)
        out["error"] = f"重跑超时（{timeout}s）"
        return out
    except OSError as exc:
        out["error"] = f"引擎起不来：{exc}"
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ 调度


class Verifier:
    """后台复验。一次一批，进度可查——按钮点完立刻返回，页面自己轮询。"""

    def __init__(self, store: Any, engine: str = "", timeout: int = DEFAULT_TIMEOUT, log=None):
        self.store = store
        self.engine = engine
        self.timeout = max(30, int(timeout))
        self.log = log or (lambda *a, **k: None)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._st: Dict[str, Any] = {
            "running": False, "total": 0, "done": 0, "current": "", "started": 0.0,
            "finished": 0.0, "summary": {}, "last": [],
        }

    # -------------------------------------------------------- 对外

    def status(self) -> Dict[str, Any]:
        with self._lock:
            st = dict(self._st)
        st["elapsed"] = round((st["finished"] or time.time()) - st["started"], 1) if st["started"] else 0.0
        st["engine"] = self.engine
        return st

    def start(self, ids: List[int]) -> Dict[str, Any]:
        ids = [int(x) for x in (ids or []) if str(x).strip().lstrip("-").isdigit()][:MAX_BATCH]
        if not ids:
            raise ValueError("没有要复验的条目")
        if not self.engine:
            raise RuntimeError("没找到引擎，复验需要它重跑一遍")
        with self._lock:
            if self._st["running"]:
                raise RuntimeError("上一批复验还没跑完")
        rows = self.store.findings_by_ids(ids)
        if not rows:
            raise ValueError("这些 id 已经不在库里了")
        with self._lock:
            self._st = {"running": True, "total": len(rows), "done": 0, "current": "准备重跑…",
                        "started": time.time(), "finished": 0.0, "summary": {}, "last": []}
        self._thread = threading.Thread(target=self._run, args=(rows,), name="kara-verify", daemon=True)
        self._thread.start()
        return {"ok": True, "queued": len(rows)}

    # -------------------------------------------------------- 内部

    def _mark(self, row_id: int, state: str, note: str) -> None:
        self.store.set_verify([(row_id, state, note)])

    def _progress(self, **kw) -> None:
        with self._lock:
            self._st.update(kw)

    def _run(self, rows: List[Dict[str, Any]]) -> None:
        summary = {STILL: 0, GONE: 0, UNKNOWN: 0, NA: 0}
        last: List[Dict[str, Any]] = []
        done = 0
        try:
            groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
            for r in rows:
                p = plan_of(r)
                if not p:
                    self._mark(int(r["id"]), NA,
                               f"来源「{first_source(r) or '未知'}」不是本机引擎产物，没有可回访的目标")
                    summary[NA] += 1
                    done += 1
                    self._progress(done=done)
                    continue
                # baseline 是按 check 单项跑的，得一项一跑；paths/api/jsintel 一次跑全量，
                # 同一目标的多条命中合并成一组，别为了几条命中把整个模式重跑五遍。
                gkey = (p["mode"], p["base"], p["check"] if p["mode"] == "baseline" else "")
                groups.setdefault(gkey, {"plan": p, "rows": []})["rows"].append(r)

            for (mode, base, _check), g in groups.items():
                self._progress(current=f"{mode} · {base}")
                res = run_group(self.engine, g["plan"], self.timeout)
                kind = g["plan"]["kind"]
                ran_ok = not res["error"] and (not kind or kind in res["kinds"])
                for r in g["rows"]:
                    want = ident(r.get("title"))
                    if ran_ok:
                        note = _fresh_note(res["items"], want)
                        if note:
                            state, txt = STILL, f"重跑命中 · {note}"
                        else:
                            state, txt = GONE, (f"{mode} 重跑完成（{res['elapsed']}s，目标 {base}），"
                                                f"这一类结果跑出来了但没有这条")
                    else:
                        state = UNKNOWN
                        why = res["error"] or (f"产物里没认到 {kind} 的结果，这次不算数")
                        txt = f"{why}（{res['elapsed']}s）"
                    self._mark(int(r["id"]), state, txt)
                    summary[state] += 1
                    done += 1
                    last.append({"id": int(r["id"]), "title": r.get("title"), "state": state, "note": txt})
                self._progress(done=done, last=last[-20:])
                self.log("info", f"复验 {mode} · {base}：{len(g['rows'])} 条（{res['elapsed']}s）")
        except Exception as exc:  # 复验崩了也不能把「running」挂死
            self.log("error", f"复验失败：{type(exc).__name__}: {exc}")
            summary[UNKNOWN] += 0
        finally:
            self._progress(running=False, finished=time.time(), current="", summary=summary,
                           last=last[-20:])

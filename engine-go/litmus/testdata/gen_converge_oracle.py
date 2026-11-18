#!/usr/bin/env python3
"""用 Python 原版的 Engine._dedupe_and_number 生成收敛基准。

为什么值得单独做一个 oracle：去重合并是有状态的取舍（谁留、谁被吞、
证据怎么拼、extra 里塞什么），凭读代码复现有把握，但只有真跑过
原版才算证据。这里 object.__new__ 绕过 __init__，只喂 findings。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY_SRC = os.path.join(os.path.dirname(ROOT), "litmus2")
if not os.path.isdir(PY_SRC):
    sys.exit("找不到 Python 原版目录: " + PY_SRC)
sys.path.insert(0, PY_SRC)

import model   # noqa: E402
import engine  # noqa: E402


def F(check, name, sev, target, host, port, evidence="", poc="", level="L2"):
    # poc / raw_ref / id / time 不在 __init__ 签名里，是构造后赋值的槽位
    f = model.Finding(check, name, sev, target, host=host, port=port,
                      evidence=evidence, level=level,
                      confidence="confirmed")
    f.poc = poc
    return f


def case_family_merge():
    """内建检查与模板命中同一件事：应合并成一条"""
    return [
        F("git-leak", "Git 配置泄露", "high", "http://10.0.0.1:80",
          "10.0.0.1", 80, evidence="GET /.git/config -> 200\n[core]\n\trepositoryformatversion = 0",
          poc="poc/git-leak.sh"),
        F("tpl-git-config-disclosure", "Git 配置泄露（模板）", "high",
          "http://10.0.0.1:80", "10.0.0.1", 80,
          evidence="matched at http://10.0.0.1:80/.git/config"),
    ]


def case_severity_wins():
    """同族但等级不同：保留严重的那条，哪怕它证据更短"""
    return [
        F("actuator-env", "Actuator env 泄露", "critical", "http://10.0.0.2:8080",
          "10.0.0.2", 8080, evidence="200 env"),
        F("tpl-spring-actuator-env", "Actuator env（模板）", "medium",
          "http://10.0.0.2:8080", "10.0.0.2", 8080,
          evidence="很长的模板证据" * 30),
    ]


def case_diff_host_port():
    """不同主机 / 不同端口不能合并"""
    return [
        F("git-leak", "Git 泄露", "high", "http://10.0.0.3:80", "10.0.0.3", 80,
          evidence="a"),
        F("git-leak", "Git 泄露", "high", "http://10.0.0.3:8080", "10.0.0.3", 8080,
          evidence="b"),
        F("git-leak", "Git 泄露", "high", "http://10.0.0.4:80", "10.0.0.4", 80,
          evidence="c"),
    ]


def case_evidence_substring():
    """被吞方的证据已经包含在保留方里：不要重复拼接"""
    return [
        F("phpinfo-exposure", "phpinfo 泄露", "medium", "http://10.0.0.5:80",
          "10.0.0.5", 80, evidence="phpinfo() page at /info.php; PHP Version 7.4.3"),
        F("tpl-phpinfo-exposure", "phpinfo（模板）", "medium", "http://10.0.0.5:80",
          "10.0.0.5", 80, evidence="phpinfo() page at /info.php"),
    ]


def case_poc_inherit():
    """保留方没有 PoC，被吞方有 —— 必须继承"""
    return [
        F("git-leak", "Git 泄露", "high", "http://10.0.0.6:80", "10.0.0.6", 80,
          evidence="短证据", poc=""),
        F("tpl-git-config-disclosure", "模板", "high", "http://10.0.0.6:80",
          "10.0.0.6", 80, evidence="长一点的证据在这里", poc="poc/git.sh"),
    ]


def case_sort_order():
    """排序：等级升序 → target → check；编号 LS-001 起"""
    return [
        F("info-x", "信息项", "info", "http://10.0.0.9:80", "10.0.0.9", 80,
          evidence="i"),
        F("crit-x", "严重项", "critical", "http://10.0.0.9:80", "10.0.0.9", 80,
          evidence="c"),
        F("med-x", "中危项", "medium", "http://10.0.0.9:80", "10.0.0.9", 80,
          evidence="m"),
        F("low-x", "低危项", "low", "http://10.0.0.9:80", "10.0.0.9", 80,
          evidence="l"),
        F("crit-a", "严重项A", "critical", "http://10.0.0.1:80", "10.0.0.1", 80,
          evidence="c2"),
    ]


CASES = {
    "family_merge": case_family_merge,
    "severity_wins": case_severity_wins,
    "diff_host_port": case_diff_host_port,
    "evidence_substring": case_evidence_substring,
    "poc_inherit": case_poc_inherit,
    "sort_order": case_sort_order,
}


def run_case(fn):
    eng = object.__new__(engine.Engine)   # 绕过 __init__，只要 findings 这一个状态
    eng.findings = fn()
    eng._dedupe_and_number()
    out = []
    for f in eng.findings:
        out.append({
            "id": f.id,
            "check": f.check,
            "host": f.host,
            "port": f.port,
            "severity": f.severity,
            "evidence": f.evidence,
            "poc": f.poc,
            "extra": f.extra,
        })
    return out


def main():
    result = {}
    for name, fn in CASES.items():
        result[name] = run_case(fn)
        print(f"-- {name}: {len(result[name])} 条")
        for it in result[name]:
            print(f"   {it['id']} {it['check']:32} {it['severity']:9} "
                  f"ev={len(it['evidence'])}B extra={it['extra']}")
    p = os.path.join(ROOT, "testdata", "converge_oracle.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2, sort_keys=True)
    print("\n写出:", p)


if __name__ == "__main__":
    main()

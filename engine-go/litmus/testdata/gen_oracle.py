#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 oracle 差分夹具：Python 版渲染结果就是 Go 版的验收基准。

用法（在 ~/tools/litmus2-go 目录下）：
    python3 testdata/gen_oracle.py

产出：
    testdata/fixture.json        输入夹具（Go 测试读它）
    testdata/expect_report.md    Python 版 render_markdown 的逐字输出
    testdata/expect_report.html  Python 版 render_html 的逐字输出

注意：报告里的「生成时间」两边必然不同（各自 now_iso()），
Go 测试会在比对前把这一行归一化，其余内容必须逐字节一致。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                 # ~/tools/litmus2-go
PY_SRC = os.path.join(os.path.dirname(ROOT), "litmus2")   # ~/tools/litmus2
if not os.path.isdir(PY_SRC):
    raise SystemExit("找不到 Python 版源码目录: %s" % PY_SRC)
sys.path.insert(0, PY_SRC)

import model   # noqa: E402
import report  # noqa: E402


def build():
    fs = []

    # 1) critical，带 creds + rpc_shares，测多行证据与表格
    f1 = model.Finding(
        check="smb_anon_shares", name="SMB 匿名会话可枚举共享",
        severity="critical", target="10.0.0.5:445", host="10.0.0.5", port=445,
        scheme="", category="host", level="L2", confidence="confirmed",
        evidence="SMB2 NEGOTIATE -> Dialect 0x0210\n"
                 "SESSION_SETUP(NTLM Type3 匿名) -> STATUS_SUCCESS\n"
                 "IPC$ TREE_CONNECT -> STATUS_SUCCESS\n"
                 "NetrShareEnum -> 12 项\n"
                 "  DATA  | 可写 | 财务共享\n"
                 "  HR    | 可读 | 人事档案",
        repro="smbclient -N -L //10.0.0.5\n"
              "python3 poc/smb_anon_shares_10_0_0_5.py",
        impact="未授权者可枚举全部共享名，并直接读取 HR 共享内的人事档案。",
        fix="禁用匿名会话；关闭 SMB1；对共享启用最小权限 ACL。",
        cvss="9.8", title_en="Anonymous SMB session allows share enumeration",
        extra={"rpc_shares": [
            {"name": "DATA", "type": "disk", "remark": "财务共享|可写"},
            {"name": "HR", "type": "disk", "remark": "人事档案"},
        ]},
        creds=[model.Cred("smb", "10.0.0.5", 445, "guest", "TESTPASS123",
                          kind="password", source="F-001", note="匿名会话")],
    )
    f1.id = "F-001"
    f1.poc = "poc/smb_anon_shares_10_0_0_5.py"
    f1.raw_ref = "evidence/F-001-smb.txt"
    fs.append(f1)

    # 2) high，无 poc/raw_ref/creds，测「不出现」分支
    f2 = model.Finding(
        check="redis_noauth", name="Redis 未授权访问",
        severity="high", target="10.0.0.9:6379", host="10.0.0.9", port=6379,
        category="host", level="L2", confidence="confirmed",
        evidence="PING -> +PONG\nINFO server -> redis_version:6.2.6\n"
                 "DBSIZE -> 14823",
        repro="redis-cli -h 10.0.0.9 PING",
        impact="可读取/覆盖全部键值，并可写 crontab 或 SSH 公钥获取系统权限。",
        fix="绑定 127.0.0.1；设置 requirepass；禁止外网暴露 6379。",
        cvss="8.6", title_en="Redis unauthenticated access",
    )
    f2.id = "F-002"
    fs.append(f2)

    # 3) medium，evidence/repro 全空，测 (无)/(未提供) 分支
    f3 = model.Finding(
        check="tls_weak", name="TLS 支持弱套件",
        severity="medium", target="10.0.0.12:443", host="10.0.0.12", port=443,
        scheme="https", category="web", level="L1", confidence="suspect",
        evidence="", repro="", impact="中间人可降级协商到 3DES。",
        fix="禁用 3DES/RC4，启用 TLS1.2+。", cvss="5.3",
    )
    f3.id = "F-003"
    fs.append(f3)

    # 4) low，带 HTML/特殊字符，测转义
    f4 = model.Finding(
        check="http_headers", name="缺少安全响应头 <script> & \"引号\"",
        severity="low", target="https://10.0.0.12/", host="10.0.0.12", port=443,
        scheme="https", category="web", level="L1", confidence="confirmed",
        evidence='GET / HTTP/1.1\nHost: 10.0.0.12\n<无 Content-Security-Policy>',
        repro="curl -skI https://10.0.0.12/",
        impact="XSS 与点击劫持的缓解措施缺失。",
        fix="下发 CSP / X-Frame-Options / X-Content-Type-Options。", cvss="3.1",
    )
    f4.id = "F-004"
    fs.append(f4)

    # 5) info
    f5 = model.Finding(
        check="banner", name="服务指纹识别",
        severity="info", target="10.0.0.20:22", host="10.0.0.20", port=22,
        category="host", level="L1", confidence="confirmed",
        evidence="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        repro="nc -v 10.0.0.20 22", impact="版本信息暴露，便于针对性选型。",
        fix="按需隐藏 banner。", cvss="0.0",
    )
    f5.id = "F-005"
    fs.append(f5)

    cov = [
        model.Coverage("10.0.0.5", "host", "smb_anon_shares", "ok", "", 12),
        model.Coverage("10.0.0.9", "host", "redis_noauth", "ok", "", 1),
        model.Coverage("10.0.0.12", "web", "nuclei_templates", "skip",
                       "目标返回 403，模板无法判断命中", 0),
        model.Coverage("10.0.0.12", "web", "dir_bruteforce", "na",
                       "强度档位 normal 下不启用目录爆破", 0),
        model.Coverage("10.0.0.20", "host", "smb_anon_shares", "na",
                       "22 端口未开放 SMB", 0),
    ]

    diff = {
        "new": [{"id": "F-001", "name": "SMB 匿名会话可枚举共享", "target": "10.0.0.5:445"}],
        "still": [{"id": "F-002", "name": "Redis 未授权访问", "target": "10.0.0.9:6379"}],
        "fixed": [{"id": "F-000", "name": "旧版 Redis 未授权", "target": "10.0.0.7:6379"}],
    }

    res = {
        "run_id": 7,
        "opts": {"intensity": "normal", "ports": "top1000", "threads": 64},
        "elapsed": 12.5,
        "findings": fs,
        "coverage": cov,
        "diff": diff,
    }
    return res


def to_fixture(res):
    """夹具 = 报告渲染所需的最小信息，creds 用原始 secret（报告自己打码）。"""
    out_fs = []
    for f in res["findings"]:
        d = f.to_dict()
        d.pop("creds", None)
        d["creds_plain"] = [
            {"proto": c.proto, "host": c.host, "port": c.port, "user": c.user,
             "secret": c.secret, "kind": c.kind, "source": c.source, "note": c.note}
            for c in f.creds
        ]
        out_fs.append(d)
    return {
        "run_id": res["run_id"],
        "opts": res["opts"],
        "elapsed": res["elapsed"],
        "findings": out_fs,
        "coverage": [c.to_dict() for c in res["coverage"]],
        "diff": res["diff"],
    }


def main():
    res = build()
    fx = to_fixture(res)

    with open(os.path.join(HERE, "fixture.json"), "w", encoding="utf-8") as f:
        json.dump(fx, f, ensure_ascii=False, indent=2)

    md = report.render_markdown(res)
    with open(os.path.join(HERE, "expect_report.md"), "w", encoding="utf-8") as f:
        f.write(md)

    html = report.render_html(res)
    with open(os.path.join(HERE, "expect_report.html"), "w", encoding="utf-8") as f:
        f.write(html)

    print("fixture.json         %d bytes" % os.path.getsize(os.path.join(HERE, "fixture.json")))
    print("expect_report.md     %d bytes" % os.path.getsize(os.path.join(HERE, "expect_report.md")))
    print("expect_report.html   %d bytes" % os.path.getsize(os.path.join(HERE, "expect_report.html")))
    print("\n--- 基准 md 前 30 行 ---")
    for line in md.splitlines()[:30]:
        print(line)


if __name__ == "__main__":
    main()

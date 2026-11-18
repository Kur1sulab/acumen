#!/usr/bin/env python3
"""用 Python 原版 winproto.py 生成字节级真值，用于裁决移植是否等价。

为什么需要这个：子代理写 golden_test.go 时 want 值是它自己填的 ——
跟我上次凭记忆填 MD4 向量是同一类风险。这里不信任任何一方的手写值，
只信 Python 原版真跑出来的字节。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY_SRC = os.path.join(os.path.dirname(ROOT), "litmus2")
if not os.path.isdir(PY_SRC):
    sys.exit("找不到 Python 原版: " + PY_SRC)
sys.path.insert(0, PY_SRC)

import winproto as w   # noqa: E402


def hx(b):
    return b.hex()


def main():
    out = {}

    out["smbHdr"] = hx(w._hdr(0, 0, tree=0, session=0, flags=0, credit=1, status=0))
    out["smbHdr(mid=7)"] = hx(w._hdr(0, 7))

    # _neg_req 内部 os.urandom(16) 做 ClientGuid，没法固定；
    # 只把「去掉 ClientGuid 后的骨架」当基准，逐段比
    neg = w._neg_req(0)
    out["negReq.len"] = len(neg)
    out["negReq.hdr"] = hx(neg[:64])
    out["negReq.body.head"] = hx(neg[64:76])      # StructureSize..Capabilities
    out["negReq.body.tail"] = hx(neg[92:])        # ClientStartTime + dialects
    out["negReq.guid"] = hx(neg[76:92])

    out["ntlmType1"] = hx(w._ntlm_type1())
    out["ntlmType3(0)"] = hx(w._ntlm_type3(0))
    out["ntlmType3(0xe2088297)"] = hx(w._ntlm_type3(0xe2088297))
    out["spnegoInit(ntlmType1)"] = hx(w._spnego_init(w._ntlm_type1()))
    out["spnegoResp(ntlmType3(0x12345678))"] = hx(w._spnego_resp(w._ntlm_type3(0x12345678)))

    out["ssReq(abc,mid=1,sess=0)"] = hx(w._ss_req(b"abc", 1, 0))
    out["tcReq(10.0.0.5,IPC$,mid=3,sess=0x1122334455667788)"] = hx(
        w._tc_req("10.0.0.5", "IPC$", 3, 0x1122334455667788))
    out["createReq(srvsvc,mid=4,sess=0x1122334455667788,tree=7)"] = hx(
        w._create_req("srvsvc", 4, 0x1122334455667788, 7))
    out["rpcBind(1,0)"] = hx(w._rpc_bind(1, 0))
    out["rpcReq(15,20*00,2,0)"] = hx(w._rpc_req(15, b"\x00" * 20, 2, 0))
    out["rpcReq(len=0 ndr,15)"] = hx(w._rpc_req(15, b"", 2, 0))

    # DER 编码器（LDAP/LDAPS 用）
    out["der.int(1)"] = hx(w._der_int(1))
    out["der.int(0)"] = hx(w._der_int(0))
    out["der.int(255)"] = hx(w._der_int(255))
    out["der.int(256)"] = hx(w._der_int(256))
    out["der.int(65535)"] = hx(w._der_int(65535))
    out["der.bool(True)"] = hx(w._der_bool(True))
    out["der.bool(False)"] = hx(w._der_bool(False))
    out["der.octets(abc)"] = hx(w._der_octets(b"abc"))
    out["der.octets(empty)"] = hx(w._der_octets(b""))
    out["der.enum(0)"] = hx(w._der_enum(0))
    out["der.enum(3)"] = hx(w._der_enum(3))

    # 长度编码边界：127/128/255/256 是 DER 长短格式的分界
    for n in (0, 1, 127, 128, 255, 256, 65535):
        out[f"der.len({n})"] = hx(w._der_len(n))

    # TLV 解码
    # _tlv 返回 (tag, content, next_index) —— 顺序是 tag/content/next，
    # 不是 tag/next/content。第一版这里解包错了，报的
    # 「object of type int has no len()」是我脚本的 bug，不是模块的。
    for name, blob in [
        ("tlv(short)", bytes.fromhex("3003020161")),
        ("tlv(long-1byte)", bytes.fromhex("3081023000")),
        ("tlv(long-2byte)", bytes.fromhex("308200023000")),
        ("tlv(empty-content)", bytes.fromhex("3000")),
        ("tlv(long-len-zero)", bytes.fromhex("308000")),
        ("tlv(long-len-overrun)", bytes.fromhex("30810230")),
        ("tlv(content-overrun)", bytes.fromhex("3005616263")),
        ("tlv(truncated-header)", bytes.fromhex("30")),
    ]:
        try:
            tag, content, nxt = w._tlv(blob, 0)
            out[name] = {"tag": tag, "next": nxt, "content": content.hex(), "err": None}
        except Exception as e:
            out[name] = {"err": type(e).__name__ + ": " + str(e)}

    p = os.path.join(ROOT, "testdata", "winproto_oracle.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2, sort_keys=True)

    for k in sorted(out):
        v = out[k]
        if isinstance(v, dict):
            print(f"{k:52} {v}")
        elif k.startswith("der.len") or k.startswith("negReq."):
            print(f"{k:52} {v}")
        else:
            print(f"{k:52} {v[:60]}{'…' if len(v) > 60 else ''} ({len(v)//2}B)")
    print("\n写出:", p)


if __name__ == "__main__":
    main()

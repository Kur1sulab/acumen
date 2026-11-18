#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 Python 原版 authprobe.py 生成「客户端字节」真值，供 Go 移植做 golden 比对。

为什么不手写 hex：手写的期望值是「我以为 Python 会发什么」，不是「Python 实际
发了什么」。这里把 _conn 换成记录型假 socket，让原版代码原样跑一遍握手/查询，
把它 sendall 出去的字节存下来。

输出：internal/authprobe/testdata/authprobe_builders.json
"""
import json
import os
import socket
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GO_ROOT = os.path.dirname(HERE)
PY_SRC = os.path.join(os.path.dirname(GO_ROOT), "litmus2")
if not os.path.isdir(PY_SRC):
    sys.exit("找不到 Python 原版: " + PY_SRC)
sys.path.insert(0, PY_SRC)

import authprobe as a  # noqa: E402


class FakeSock:
    """按脚本吐响应、记录所有 sendall 的假 socket。"""

    def __init__(self, chunks=None):
        self.chunks = list(chunks or [])
        self.sent = b""
        self.closed = False

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        if not self.chunks:
            raise socket.timeout("timed out")
        head = self.chunks[0]
        take, rest = head[:n], head[n:]
        if rest:
            self.chunks[0] = rest
        else:
            self.chunks.pop(0)
        return take

    def settimeout(self, _t):
        pass

    def close(self):
        self.closed = True


def with_sock(sock, fn):
    """把 authprobe._conn 临时换成返回 sock，执行 fn。"""
    orig = a._conn
    a._conn = lambda *args, **kw: sock
    try:
        try:
            return fn()
        except (socket.timeout, TimeoutError):
            return None
    finally:
        a._conn = orig


def mysql_handshake(salt1=b"abcdefgh", salt2=b"ijklmnopqrst"):
    """服务端 handshake v10，字段布局与 authprobe 的解析器对齐。"""
    body = b"\x0a" + b"8.0.36-litmus\x00"
    body += struct.pack("<I", 42)          # thread id
    body += salt1 + b"\x00"                # auth-plugin-data-part-1 + filler
    body += struct.pack("<H", 0xFFFF)      # capability flags lower
    body += b"\x21"                        # charset utf8_general_ci
    body += struct.pack("<H", 2)           # status flags
    body += struct.pack("<H", 0xFFFF)      # capability flags upper
    body += b"\x15"                        # auth plugin data len = 21
    body += b"\x00" * 10                   # reserved
    body += salt2 + b"\x00"
    return struct.pack("<I", len(body))[:3] + b"\x00" + body


def pg_msg(typ, body):
    return typ + struct.pack("!I", 4 + len(body)) + body


def bson_doc():
    """{"ok": 1.0, "ismaster": true, "maxWireVersion": 17}"""
    doc = b""
    doc += b"\x01ok\x00" + struct.pack("<d", 1.0)
    doc += b"\x08ismaster\x00\x01"
    doc += b"\x10maxWireVersion\x00" + struct.pack("<i", 17)
    doc += b"\x00"
    return struct.pack("<i", len(doc) + 4) + doc


def mongo_reply(req_len=0):
    doc = bson_doc()
    body = struct.pack("<iqii", 0, 0, 0, 1) + doc
    return struct.pack("<iiii", 16 + len(body), 1, 0, 1) + body


def main():
    out = {}

    # ---------------- MySQL：握手响应（含 mysql_native_password scramble）
    #
    # 【原版缺陷】authprobe.py:190 的定义是 _mysql_pkt(s, payload, seq)，
    # 但 258/276 两处调用都只传了 (payload, seq) —— 真打 MySQL 会在 sendall
    # 前抛 TypeError，probe_service 吞成 None。也就是说 Python 版的 MySQL
    # 探针是死的。这里按「作者本意」把首参 s 去掉再让原版代码跑，
    # 得到的是 _mysql_login 其余部分（caps/payload 拼接）的真字节。
    if a._mysql_pkt.__code__.co_argcount == 3:
        a._mysql_pkt = lambda payload, seq: (
            struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload)

    salt = b"abcdefgh" + b"ijklmnopqrst"
    hs = mysql_handshake()
    sock = FakeSock([hs])
    with_sock(sock, lambda: a._mysql_login("127.0.0.1", 3306, "root", "p@ss", 1.0))
    out["mysql.handshake"] = hs.hex()
    out["mysql.salt"] = salt.hex()
    out["mysql.login(root,p@ss)"] = sock.sent.hex()

    sock = FakeSock([hs])
    with_sock(sock, lambda: a._mysql_login("127.0.0.1", 3306, "root", "", 1.0))
    out["mysql.login(root,empty)"] = sock.sent.hex()

    out["mysql.native(p@ss,salt)"] = a._mysql_native("p@ss", salt).hex()
    out["mysql.native(empty,salt)"] = a._mysql_native("", salt).hex()

    # ---------------- PostgreSQL：startup / cleartext / md5
    sock = FakeSock([])
    state, _raw = with_sock(sock, lambda: a._pg_startup(sock, "postgres", None))
    out["pg.startup(postgres)"] = sock.sent.hex()
    out["pg.startup.state"] = state

    sock = FakeSock([pg_msg(b"R", struct.pack("!I", 3)),
                     pg_msg(b"R", struct.pack("!I", 0))])
    state, _raw = with_sock(sock, lambda: a._pg_startup(sock, "postgres", "s3cr3t"))
    out["pg.cleartext(postgres,s3cr3t)"] = sock.sent.hex()
    out["pg.cleartext.state"] = state

    pg_salt = bytes.fromhex("0102030405060708")
    sock = FakeSock([pg_msg(b"R", struct.pack("!I", 5) + pg_salt),
                     pg_msg(b"R", struct.pack("!I", 0))])
    state, _raw = with_sock(sock, lambda: a._pg_startup(sock, "postgres", "s3cr3t"))
    out["pg.md5.salt"] = pg_salt.hex()
    out["pg.md5(postgres,s3cr3t)"] = sock.sent.hex()
    out["pg.md5.state"] = state

    # ---------------- MongoDB：OP_QUERY admin.$cmd {isMaster:1}
    sock = FakeSock([mongo_reply()])
    with_sock(sock, lambda: a.probe_mongo("127.0.0.1", 27017, timeout=1.0))
    out["mongo.query"] = sock.sent.hex()

    # ---------------- 文本协议：命令字节（探针只发这些）
    sock = FakeSock([b"+PONG\r\n",
                     b"$91\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"
                     b"tcp_port:6379\r\nrun_id:litmus-golden\r\n\r\n",
                     b":42\r\n"])
    with_sock(sock, lambda: a.probe_redis("127.0.0.1", 6379, timeout=1.0))
    out["redis.commands"] = sock.sent.hex()

    sock = FakeSock([b"STAT pid 1234\r\nSTAT curr_items 7\r\nEND\r\n"])
    with_sock(sock, lambda: a.probe_memcached("127.0.0.1", 11211, timeout=1.0))
    out["memcached.commands"] = sock.sent.hex()

    sock = FakeSock([b"220 litmus FTP ready\r\n", b"331 need password\r\n",
                     b"230 anonymous ok\r\n", b'257 "/" is current directory\r\n'])
    with_sock(sock, lambda: a.probe_ftp("127.0.0.1", 21, timeout=1.0))
    out["ftp.commands"] = sock.sent.hex()

    sock = FakeSock([b"RFB 003.008\n", b"\x02", b"\x02\x01",
                     b"\x00\x00\x00\x00"])
    with_sock(sock, lambda: a.probe_vnc("127.0.0.1", 5900, timeout=1.0))
    out["vnc.commands"] = sock.sent.hex()

    sock = FakeSock([b"@RSYNCD: 31.0\n",
                     b"backup\tbackup files\n@RSYNCD: EXIT\n"])
    with_sock(sock, lambda: a.probe_rsync("127.0.0.1", 873, timeout=1.0))
    out["rsync.commands"] = sock.sent.hex()

    path = os.path.join(GO_ROOT, "internal", "authprobe", "testdata",
                        "authprobe_builders.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2, sort_keys=True)
    for k in sorted(out):
        v = str(out[k])
        print(f"{k:34} {v[:68]}{'…' if len(v) > 68 else ''} ({len(v)//2}B)")
    print("\n写出:", path)


if __name__ == "__main__":
    main()

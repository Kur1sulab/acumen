package winproto

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ================================================================ DCE/RPC over 命名管道
//
// 全部结论来自对 Samba 4.22（dperson/samba 容器）的实测 + 源码对照
// （source3/smbd/smb2_read.c、smb2_server.c:smbd_smb2_request_verify_sizes）。
// 踩过的坑，改这段代码前先看：
//
//  1. 管道 RPC 首选 FSCTL_PIPE_TRANSCEIVE（SMB2 IOCTL），Flags 必须置
//     SMB2_0_IOCTL_IS_FSCTL(1)，否则 Samba 回 STATUS_NOT_SUPPORTED。
//  2. 用 SMB2 WRITE/READ 也能跑通，但 READ 请求体 48 字节后必须再补 ≥1
//     字节动态区（Buffer），否则 verify_sizes 判 INVALID_PARAMETER；
//     且管道 READ 的 Length 不能超过 65536，1MB 会被 Samba 直接断链。
//  3. RPC 请求 PDU 的 frag_len 必须含 24 字节头（16 通用 + 8 请求头）。
//     只写 16+stub 会让服务端 NDR 拉取越界（fault 或 UNK_IF 假象）。
//  4. BIND 头是 max_xmit(2) max_recv(2) assoc(4) num_ctx(1) rsv(1) rsv2(2)，
//     每个 ctx 项 = p_cont_id(2) n_transfer_syn(1) rsv(1) abstract(20)
//     transfer(20)。把 num_ctx 当成 p_cont_id 会让 bind 直接 NAK。
//  5. NetrShareEnum(opnum 15) 的 NDR 顺序是 PIDL「指针即写即填」顺序：
//     server_unc ptr → WSTR → level → tag → ctr ptr → count → array ptr
//     → max_buffer → totalentries ptr → resume_handle；响应同序。

const fsctlPipeTransceive = 0x0011C017

var (
	// RPC_UUID_SRVSVC c84f324b-7016-d301-1278-5a47bf6ee188（srvsvc v3.0）
	rpcUUIDSrvsvc = []byte{
		0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
	}
	// RPC_UUID_NDR 045d888a-eb1c-c911-9fe8-08002b104860（NDR32 v2.0）
	rpcUUIDNDR = []byte{
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	}
)

var rpcPType = map[byte]string{
	0: "request", 2: "response", 3: "fault", 11: "bind",
	12: "bind_ack", 13: "bind_nak", 14: "alter_context",
}

func rpcPTypeName(t byte) string {
	if n, ok := rpcPType[t]; ok {
		return n
	}
	return fmt.Sprintf("%d", t)
}

var rpcFaultNames = map[uint32]string{
	0x1C010002: "nca_s_op_rng_error（opnum 在该接口不存在）",
	0x1C010003: "nca_s_unk_if（接口/上下文未绑定）",
	0x1C000008: "nca_s_fault_ndr（NDR 编解码失败）",
}

// rpcHdr 组 DCE/RPC 通用头 16 字节。fragLen 含自身。
func rpcHdr(ptype byte, fragLen, authLen uint16, callID uint32, flags byte) []byte {
	b := make([]byte, 16)
	b[0] = 5 // rpc_vers
	b[1] = 0 // rpc_vers_minor
	b[2] = ptype
	b[3] = flags
	copy(b[4:], []byte{0x10, 0x00, 0x00, 0x00}) // drep：小端、ASCII、IEEE 浮点
	binary.LittleEndian.PutUint16(b[8:], fragLen)
	binary.LittleEndian.PutUint16(b[10:], authLen)
	binary.LittleEndian.PutUint32(b[12:], callID)
	return b
}

// rpcBind 组 BIND：SRVSVC v3.0 + NDR32 v2.0。
func rpcBind(callID uint32, ctx uint16) []byte {
	body := make([]byte, 0, 12+4+24+24)
	var head [12]byte
	binary.LittleEndian.PutUint16(head[0:], 4280) // max_xmit
	binary.LittleEndian.PutUint16(head[2:], 4280) // max_recv
	// assoc_group (4..8) = 0
	head[8] = 1 // num_ctx=1（不是 p_cont_id）
	// head[9] reserved、head[10:12] reserved2 = 0
	body = append(body, head[:]...)

	var c [4]byte
	binary.LittleEndian.PutUint16(c[0:], ctx) // p_cont_id
	c[2] = 1                                  // n_transfer_syn
	body = append(body, c[:]...)
	body = append(body, rpcUUIDSrvsvc...)
	body = append(body, 3, 0, 0, 0) // abstract syntax version 3.0（<HH>）
	body = append(body, rpcUUIDNDR...)
	body = append(body, 2, 0, 0, 0) // transfer syntax version 2.0（<HH>）
	return append(rpcHdr(11, uint16(16+len(body)), 0, callID, 3), body...)
}

// rpcReq 组 REQUEST：alloc_hint / p_cont_id / opnum 共 8 字节，frag_len 要带上。
func rpcReq(opnum uint16, ndr []byte, callID uint32, ctx uint16) []byte {
	h := rpcHdr(0, uint16(24+len(ndr)), 0, callID, 3)
	rh := make([]byte, 8)
	binary.LittleEndian.PutUint32(rh[0:], uint32(len(ndr))) // alloc_hint
	binary.LittleEndian.PutUint16(rh[4:], ctx)
	binary.LittleEndian.PutUint16(rh[6:], opnum)
	return append(append(h, rh...), ndr...)
}

// bindAckResult 解析 bind_ack 的 per-context result（0 = acceptance）。
// ok=false 对应 Python 的 None。
func bindAckResult(d []byte) (uint16, bool) {
	if len(d) < 26 || d[2] != 12 {
		return 0, false
	}
	sal := int(binary.LittleEndian.Uint16(d[24:26]))
	off := 26 + sal
	off += (4 - off%4) % 4
	if off+6 > len(d) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(d[off+4 : off+6]), true
}

// ioctlPipe 发 FSCTL_PIPE_TRANSCEIVE：一次 IOCTL 完成写+读。
//
// 返回值语义对齐 Python 的 _ioctl_pipe()：
//   - hasResp=false → 没拿到 SMB2 头（Python 的 None）
//   - hasResp=true, status≠0 → 服务端拒绝（out 为空）
//   - hasResp=true, status==0 → out 是输出缓冲区
func ioctlPipe(c net.Conn, fid, data []byte, mid uint64, tree uint32,
	session uint64, maxOut uint32, timeout time.Duration) (status uint32, out []byte, hasResp bool, err error) {

	body := ioctlBody(fid, data, maxOut)
	req := append(append(smbHdr(0x000B, mid, tree, session, 0, 1, 0), body...), data...)
	if err := nbSend(c, req, timeout); err != nil {
		return 0, nil, false, err
	}
	r, err := nbRecv(c, timeout)
	if err != nil {
		return 0, nil, false, err
	}
	h := parseHdr(r)
	if h == nil {
		return 0, nil, false, nil
	}
	if h.status != 0 {
		return h.status, nil, true, nil
	}
	b := r[64:]
	if len(b) < 48 {
		return h.status, nil, true, nil
	}
	ooff := int(binary.LittleEndian.Uint32(b[32:36]))
	ocnt := int(binary.LittleEndian.Uint32(b[36:40]))
	if ocnt == 0 {
		return 0, nil, true, nil
	}
	return 0, sliceFrom(r, ooff, ocnt), true, nil
}

// ioctlBody 组 FSCTL_PIPE_TRANSCEIVE 的 56 字节请求体。
//
// 字段顺序（MS-SMB2 §2.2.31）：
//
//	StructureSize H / Reserved H / CtlCode I / FileId 16B /
//	InputOffset I / InputCount I / MaxInputResponse I / OutputOffset I /
//	OutputCount I / MaxOutputResponse I / Flags I / Reserved2 I
//
// 用 append 而不是定长 copy：Python 版 body + fid 是拼接语义，
// fid 短了就是短 body（正常路径永远是 16 字节），这里保持逐字节一致。
func ioctlBody(fid, data []byte, maxOut uint32) []byte {
	body := make([]byte, 0, 56)
	var head [8]byte
	binary.LittleEndian.PutUint16(head[0:], 57) // StructureSize
	// Reserved (2..4) = 0
	binary.LittleEndian.PutUint32(head[4:], fsctlPipeTransceive)
	body = append(body, head[:]...)
	body = append(body, fid...)
	var fields [32]byte
	binary.LittleEndian.PutUint32(fields[0:], 120)               // InputOffset = 64+56
	binary.LittleEndian.PutUint32(fields[4:], uint32(len(data))) // InputCount
	// MaxInputResponse (8..12) = 0
	// OutputOffset (12..16) = 0
	// OutputCount (16..20) = 0
	binary.LittleEndian.PutUint32(fields[20:], maxOut) // MaxOutputResponse
	binary.LittleEndian.PutUint32(fields[24:], 1)      // Flags = SMB2_0_IOCTL_IS_FSCTL
	// Reserved2 (28..32) = 0
	body = append(body, fields[:]...)
	return body
}

// ndrWstr 读 NDR 的 [string] WSTR：max_count / offset / actual_count / UTF-16。
// ok=false 对应 Python 的 (None, off)。
func ndrWstr(ndr []byte, off int) (string, int, bool) {
	if off < 0 || off+12 > len(ndr) {
		return "", off, false
	}
	mx := binary.LittleEndian.Uint32(ndr[off:])
	of := binary.LittleEndian.Uint32(ndr[off+4:])
	ac := binary.LittleEndian.Uint32(ndr[off+8:])
	if of != 0 || ac == 0 || ac > 4096 || mx < ac {
		return "", off, false
	}
	end := off + 12 + int(ac)*2
	if end > len(ndr) || end < off {
		return "", off, false
	}
	txt := strings.TrimRight(utf16leString(ndr[off+12:end]), "\x00")
	for _, ch := range txt {
		if ch < ' ' {
			return "", off, false
		}
	}
	return txt, end + ((4 - end%4) % 4), true
}

// share 是 NetrShareEnum(level 1) 的一条共享。
type share struct {
	name   string
	typ    uint32
	remark string
}

// shareEnumResult 是 NDR 解析结果。
//
// Python 版用 (level, shares) 两个返回值表达三态，Go 版拆成两个显式标志：
//   - levelOK=false：缓冲区太短，连 level 都没读到（Python 的 (None, None)）
//   - sharesOK=false：level 读到了但 NDR 结构没解出来（Python 的 (level, None)）
//   - sharesOK=true：shares 有效，可能是空列表
type shareEnumResult struct {
	level    uint32
	levelOK  bool
	shares   []share
	sharesOK bool
}

// parseShareEnum 解析 NetrShareEnum level 1 响应。
//
// 服务端把 level/tag/ctr 指针/count/array 指针/totalentries 依次写出，
// 数组紧随其后（Samba 在 24 字节处），个别实现从 20 起 —— 两处都试，
// 用「12 字节步长 + 2n 个 WSTR 全部可解」来判定哪个对。
func parseShareEnum(ndr []byte) shareEnumResult {
	if len(ndr) < 24 {
		return shareEnumResult{}
	}
	res := shareEnumResult{level: binary.LittleEndian.Uint32(ndr[0:4]), levelOK: true}
	if res.level != 1 {
		return res
	}
	n := binary.LittleEndian.Uint32(ndr[12:16])
	if n == 0 {
		res.shares = []share{}
		res.sharesOK = true
		return res
	}
	if n > 4096 {
		return res
	}
	for _, base := range []int{24, 20} {
		if base+12*int(n) > len(ndr) {
			continue
		}
		ents := make([]share, 0, n)
		ok := true
		for i := 0; i < int(n); i++ {
			off := base + 12*i
			nm := binary.LittleEndian.Uint32(ndr[off:])
			ty := binary.LittleEndian.Uint32(ndr[off+4:])
			rm := binary.LittleEndian.Uint32(ndr[off+8:])
			if nm == 0 || rm == 0 || ty > 0x8000FFFF {
				ok = false
				break
			}
			ents = append(ents, share{typ: ty})
		}
		if !ok {
			continue
		}
		off := base + 12*int(n)
		for i := range ents { // 每个条目的 name、remark 交错排布
			s, next, good := ndrWstr(ndr, off)
			if !good {
				ok = false
				break
			}
			ents[i].name, off = s, next
			s, next, good = ndrWstr(ndr, off)
			if !good {
				ok = false
				break
			}
			ents[i].remark, off = s, next
		}
		if ok {
			res.shares = ents
			res.sharesOK = true
			return res
		}
	}
	return res
}

var shareTypeNames = map[uint32]string{0: "disk", 1: "print", 2: "device", 3: "IPC"}

func shareTypeName(t uint32) string {
	base := t & 0x0000FFFF
	name, ok := shareTypeNames[base]
	if !ok {
		name = fmt.Sprintf("0x%X", base)
	}
	if t&0x80000000 != 0 {
		name = "hidden-" + name
	}
	if t&0x40000000 != 0 {
		name += "+special"
	}
	if t&0x20000000 != 0 {
		name += "+temporary"
	}
	return name
}

func appendU32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// rpcShareEnum 在已打开的 srvsvc 管道上 bind + NetrShareEnum(level 1)。
//
// 返回 (shares, evidence 行列表, err)；shares 为 nil 表示没枚举到。
func rpcShareEnum(c net.Conn, fid []byte, tree uint32, session uint64,
	host string, mid0 uint64, timeout time.Duration) ([]share, []string, error) {

	ev := []string{}
	st, d, hasResp, err := ioctlPipe(c, fid, rpcBind(1, 0), mid0, tree, session, 65536, timeout)
	if err != nil {
		return nil, ev, err
	}
	if !hasResp {
		ev = append(ev, "RPC BIND（srvsvc）无应答 —— 管道可能被中间设备截断")
		return nil, ev, nil
	}
	if st != 0 {
		ev = append(ev, "RPC BIND（srvsvc）→ "+stName(st))
		return nil, ev, nil
	}
	if len(d) < 3 || d[2] != 12 {
		ptype := "空"
		if len(d) >= 3 {
			ptype = rpcPTypeName(d[2])
		}
		ev = append(ev, fmt.Sprintf("RPC BIND 未拿到 bind_ack（ptype=%s，%dB）", ptype, len(d)))
		return nil, ev, nil
	}
	res, ok := bindAckResult(d)
	if !ok || res != 0 {
		if !ok {
			ev = append(ev, "RPC BIND → bind_ack result=None（非 0 即拒绝）")
		} else {
			ev = append(ev, fmt.Sprintf("RPC BIND → bind_ack result=%d（非 0 即拒绝）", res))
		}
		return nil, ev, nil
	}
	ev = append(ev, fmt.Sprintf("RPC BIND srvsvc v3.0 → bind_ack result=0（acceptance），关联组 0x%X",
		binary.LittleEndian.Uint32(d[20:24])))

	// NetrShareEnum level 1：只读，不改任何状态
	ndr := netrShareEnumNDR(host)
	st, d, hasResp, err = ioctlPipe(c, fid, rpcReq(15, ndr, 2, 0), mid0+1, tree, session, 65536, timeout)
	if err != nil {
		return nil, ev, err
	}
	if !hasResp {
		ev = append(ev, "NetrShareEnum → 无应答")
		return nil, ev, nil
	}
	if st != 0 {
		ev = append(ev, "NetrShareEnum → "+stName(st))
		return nil, ev, nil
	}
	if len(d) == 0 {
		ev = append(ev, "NetrShareEnum → 空响应")
		return nil, ev, nil
	}
	if d[2] == 3 {
		// FAULT PDU 布局（DCE 1.1 / MS-RPCE 2.2.2.5）：
		//   通用头 16B + alloc_hint(4) + p_cont_id(2) + cancel_count(1)
		//   + reserved(1) + status(4)
		// 所以 status 在 PDU 偏移 24，不是 16 —— 16 处是 alloc_hint。
		// 这里必须与 Python 版 d[24:28] 一致：Python 是契约里的 oracle，
		// 改这个偏移前先改 Python 版并重跑 winproto 的 oracle 差分，
		// 否则两边证据会对不上（曾有人按「fault 只有 16 字节头」改成 16，
		// 实际跳过了 alloc_hint/p_cont_id/cancel/reserved 这 8 字节）。
		code := uint32(0)
		if len(d) >= 28 {
			code = binary.LittleEndian.Uint32(d[24:28])
		}
		ev = append(ev, fmt.Sprintf("NetrShareEnum → FAULT 0x%08X %s", code, rpcFaultNames[code]))
		return nil, ev, nil
	}
	if d[2] != 2 {
		ev = append(ev, "NetrShareEnum → 非预期 PDU（ptype="+rpcPTypeName(d[2])+"）")
		return nil, ev, nil
	}
	parsed := parseShareEnum(sliceFrom(d, 24, len(d)-24))
	if !parsed.sharesOK {
		levelTxt := "None"
		if parsed.levelOK {
			levelTxt = fmt.Sprintf("%d", parsed.level)
		}
		ev = append(ev, fmt.Sprintf("NetrShareEnum → 响应 %dB，level=%s，但 NDR 结构没解出来", len(d), levelTxt))
		return nil, ev, nil
	}
	shares := parsed.shares
	parts := make([]string, 0, len(shares))
	for _, s := range shares {
		remark := ""
		if s.remark != "" {
			remark = "(" + s.remark + ")"
		}
		parts = append(parts, fmt.Sprintf("%s[%s]%s", s.name, shareTypeName(s.typ), remark))
	}
	ev = append(ev, fmt.Sprintf("NetrShareEnum(level 1) → %d 个共享：%s", len(shares), strings.Join(parts, ", ")))
	return shares, ev, nil
}

// netrShareEnumNDR 组 NetrShareEnum(level 1) 的请求 stub。
//
// 顺序是 PIDL「指针即写即填」顺序：
// server_unc ptr → WSTR → level → tag → ctr ptr → count → array ptr
// → max_buffer → totalentries ptr → resume_handle。
func netrShareEnumNDR(host string) []byte {
	ndr := make([]byte, 0, 64+2*len(host))
	ndr = appendU32(ndr, 0x00020000) // server_unc ptr
	u := append(utf16le(host), 0, 0)
	ndr = appendU32(ndr, uint32(len(u)/2))
	ndr = appendU32(ndr, 0)
	ndr = appendU32(ndr, uint32(len(u)/2))
	ndr = append(ndr, u...)
	ndr = append(ndr, make([]byte, (4-len(ndr)%4)%4)...)
	ndr = appendU32(ndr, 1)          // level=1
	ndr = appendU32(ndr, 1)          // tag=1
	ndr = appendU32(ndr, 0x00020010) // ctr1 ptr
	ndr = appendU32(ndr, 0)          // count=0
	ndr = appendU32(ndr, 0)          // array=NULL
	ndr = appendU32(ndr, 0xFFFFFFFF) // max_buffer
	ndr = appendU32(ndr, 0x00020014) // totalentries ptr
	ndr = appendU32(ndr, 0)          // resume_handle=NULL
	return ndr
}

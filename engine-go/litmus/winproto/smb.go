package winproto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ================================================================ SMB2
//
// 参考：MS-SMB2 §2.2.1（头）/ §2.2.3（NEGOTIATE）/ §2.2.5（SESSION_SETUP）
// / §2.2.9（TREE_CONNECT）/ §2.2.13（CREATE）
//
// 与 Python 版 _nb_send / _nb_recv / _hdr / _parse_hdr / _neg_req /
// _parse_neg / _ntlm_type1 / _ntlm2_flags / _ntlm_type3 / _spnego_init /
// _spnego_resp / _find_ntlmssp / _ss_req / _tc_req / _create_req 一一对应。

var smb2Magic = []byte{0xfe, 'S', 'M', 'B'}

var smbStatusNames = map[uint32]string{
	0x00000000: "STATUS_SUCCESS",
	0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
	0xC000006D: "STATUS_LOGON_FAILURE",
	0xC0000022: "STATUS_ACCESS_DENIED",
	0xC00000CC: "STATUS_BAD_NETWORK_NAME",
	0xC00000BB: "STATUS_NOT_SUPPORTED",
	0xC000015C: "STATUS_ACCOUNT_LOCKED_OUT",
	0xC0000234: "STATUS_ACCOUNT_DISABLED",
	0xC000018B: "STATUS_NO_SUCH_USER",
}

func stName(code uint32) string {
	if n, ok := smbStatusNames[code]; ok {
		return n
	}
	return fmt.Sprintf("STATUS_0x%08X", code)
}

// nbSend 是 NetBIOS Session Service 封装：1 字节类型 + 3 字节大端长度。
func nbSend(c net.Conn, payload []byte, timeout time.Duration) error {
	buf := make([]byte, 4+len(payload))
	buf[0] = 0x00
	buf[1] = byte(len(payload) >> 16)
	buf[2] = byte(len(payload) >> 8)
	buf[3] = byte(len(payload))
	copy(buf[4:], payload)
	return writeAll(c, buf, timeout)
}

// nbRecv 读一个 NetBIOS 会话报文。
//
// 返回 (nil, nil) 表示「协议层没有可用应答」——对齐 Python 版 _nb_recv
// 返回 b"" 的几种情形：对端关闭、类型字节不是 0x00（0x81/0x82/0x83/0x85
// 是其他 NetBIOS 报文，SMB over 445 只该是 0x00）、长度为 0 或超过 8MB。
//
// 返回 error 表示传输层异常（读超时、连接重置）。Python 版此时抛异常，
// 由 probe 的外层 except 兜住并返回 None —— Go 版由调用方做同样处理。
func nbRecv(c net.Conn, timeout time.Duration) ([]byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	got := 0
	for got < 4 {
		n, err := c.Read(hdr[got:])
		got += n
		if n == 0 && err == nil {
			// 不会自旋：零字节读当作对端没话说（正常 TCP 不会这样返回）
			return nil, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Python: recv 返回 b"" → return b""
				return nil, nil
			}
			return nil, err
		}
	}
	if hdr[0] != 0x00 {
		return nil, nil
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n == 0 || n > 8*1024*1024 {
		return nil, nil
	}
	buf := make([]byte, 0, n)
	deadline := time.Now().Add(timeout)
	tmp := make([]byte, 65536)
	for len(buf) < n && time.Now().Before(deadline) {
		want := n - len(buf)
		if want > len(tmp) {
			want = len(tmp)
		}
		if err := c.SetReadDeadline(deadline); err != nil {
			return buf, nil
		}
		m, err := c.Read(tmp[:want])
		if m > 0 {
			buf = append(buf, tmp[:m]...)
		}
		if err != nil {
			var nerr net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &nerr) && nerr.Timeout()) {
				// Python: 超时 break（保留已读部分）、EOF 也 break
				break
			}
			return buf, err
		}
	}
	return buf, nil
}

// smbHdr 组 64 字节 SMB2 同步头。参数顺序对齐 Python 的 _hdr()。
func smbHdr(cmd uint16, mid uint64, tree uint32, session uint64, flags uint32, credit uint16, status uint32) []byte {
	b := make([]byte, 64)
	copy(b, smb2Magic)
	binary.LittleEndian.PutUint16(b[4:], 64) // StructureSize
	binary.LittleEndian.PutUint16(b[6:], 1)  // CreditCharge
	binary.LittleEndian.PutUint32(b[8:], status)
	binary.LittleEndian.PutUint16(b[12:], cmd)
	binary.LittleEndian.PutUint16(b[14:], credit)
	binary.LittleEndian.PutUint32(b[16:], flags)
	// NextCommand (20..24) = 0
	binary.LittleEndian.PutUint64(b[24:], mid)
	// Reserved (32..36) = 0
	binary.LittleEndian.PutUint32(b[36:], tree)
	binary.LittleEndian.PutUint64(b[40:], session)
	// Signature (48..64) 全 0
	return b
}

// smbHeader 是从应答头里读出来的判定字段。
type smbHeader struct {
	status  uint32
	cmd     uint16
	tree    uint32
	session uint64
}

// parseHdr 对应 Python 的 _parse_hdr()：头不合法返回 nil。
func parseHdr(resp []byte) *smbHeader {
	if len(resp) < 64 || !bytes.Equal(resp[:4], smb2Magic) {
		return nil
	}
	return &smbHeader{
		status:  binary.LittleEndian.Uint32(resp[8:12]),
		cmd:     binary.LittleEndian.Uint16(resp[12:14]),
		tree:    binary.LittleEndian.Uint32(resp[36:40]),
		session: binary.LittleEndian.Uint64(resp[40:48]),
	}
}

// ---- NEGOTIATE (0x0000) ----

var dialectNames = map[uint16]string{
	0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
	0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB 2.0",
	0xFFFF: "SMB 1.x（仅老协议）",
}

func dialectName(d uint16) string {
	if n, ok := dialectNames[d]; ok {
		return n
	}
	return fmt.Sprintf("0x%04X", d)
}

// negReq 组 NEGOTIATE 请求，ClientGuid 由调用方给（Python 用 os.urandom(16)）。
//
// 故意不报 0x0311：3.1.1 会引入 NegotiateContext 加密协商，解析复杂度翻倍
// 而安全判定不增值。报到 3.0.2 足够读签名策略。
func negReq(mid uint64, guid []byte) []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302}
	body := make([]byte, 0, 36+2*len(dialects))
	var head [8]byte
	binary.LittleEndian.PutUint16(head[0:], 36)                    // StructureSize
	binary.LittleEndian.PutUint16(head[2:], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(head[4:], 1)                     // SecurityMode = SIGNING_ENABLED
	binary.LittleEndian.PutUint16(head[6:], 0)                     // Reserved
	body = append(body, head[:]...)
	body = append(body, 0, 0, 0, 0) // Capabilities
	g := make([]byte, 16)
	copy(g, guid)
	body = append(body, g...)                   // ClientGuid
	body = append(body, 0, 0, 0, 0, 0, 0, 0, 0) // ClientStartTime
	for _, d := range dialects {
		body = append(body, byte(d), byte(d>>8))
	}
	return append(smbHdr(0, mid, 0, 0, 0, 1, 0), body...)
}

// negReqRandom 是 negReq 的随机 GUID 版本，对应 Python 的 os.urandom(16)。
func negReqRandom(mid uint64) []byte {
	guid := make([]byte, 16)
	if _, err := rand.Read(guid); err != nil {
		// 随机源不可用时退化成全 0 GUID：只影响请求的唯一性，不影响判定，
		// 不值得让整个探针失败。
		guid = make([]byte, 16)
	}
	return negReq(mid, guid)
}

// negResult 是 NEGOTIATE 应答里真正被用到的两个字段。
type negResult struct {
	securityMode uint16
	dialect      uint16
}

// parseNeg 对应 Python 的 _parse_neg()：长度不足或 StructureSize 不是 65 返回 nil。
func parseNeg(resp []byte) *negResult {
	if len(resp) < 128 {
		return nil
	}
	b := resp[64:]
	if binary.LittleEndian.Uint16(b[0:2]) != 65 {
		return nil
	}
	return &negResult{
		securityMode: binary.LittleEndian.Uint16(b[2:4]),
		dialect:      binary.LittleEndian.Uint16(b[4:6]),
	}
}

// ---- NTLMSSP ----

const ntlmsspSig = "NTLMSSP\x00"

// ntlmType1 是最小 NEGOTIATE 消息。flags=0 表示「我什么都不要求」，匿名用最合适。
func ntlmType1() []byte {
	b := make([]byte, 32)
	copy(b, ntlmsspSig)
	binary.LittleEndian.PutUint32(b[8:], 1) // MessageType = NEGOTIATE
	// 12..16 flags=0；16..24 DomainName；24..32 Workstation，全空
	return b
}

// ntlm2Flags 从 Type2 challenge 里取 NegotiateFlags（offset 20）。
//
// 实测教训：Type3 里 NegotiateFlags 写 0，Samba 会回
// STATUS_INVALID_PARAMETER（0xC000000D）而不是 LOGON_FAILURE ——
// 规范要求客户端 echo 服务端给出的 flags 子集。
func ntlm2Flags(challenge []byte) uint32 {
	if len(challenge) < 24 || !bytes.HasPrefix(challenge, []byte(ntlmsspSig)) {
		return 0
	}
	return binary.LittleEndian.Uint32(challenge[20:24])
}

// ntlmType3 组匿名 AUTHENTICATE：六个字段全空。
//
// 这是关键判据所在 —— 只有服务端真的把空凭据当合法会话接受，
// 才会回 STATUS_SUCCESS；否则回 STATUS_LOGON_FAILURE / ACCESS_DENIED。
// flags 必须从 Type2 echo，写 0 会被判参数非法。
func ntlmType3(flags uint32) []byte {
	b := make([]byte, 64)
	copy(b, ntlmsspSig)
	binary.LittleEndian.PutUint32(b[8:], 3) // MessageType = AUTHENTICATE
	for i := 0; i < 6; i++ {                // LM/NT/域名/用户名/工作站/会话密钥
		off := 12 + i*8
		binary.LittleEndian.PutUint16(b[off:], 0)    // len
		binary.LittleEndian.PutUint16(b[off+2:], 0)  // maxlen
		binary.LittleEndian.PutUint32(b[off+4:], 64) // offset
	}
	binary.LittleEndian.PutUint32(b[60:], flags)
	return b
}

var (
	oidSPNEGO  = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                         // 1.3.6.1.5.5.2
	oidNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10
)

// spnegoInit 组 NegTokenInit（0x60）。
func spnegoInit(token []byte) []byte {
	mechTypes := der(0xA0, der(0x30, der(0x06, oidNTLMSSP)))
	mechToken := der(0xA2, derOctets(token))
	negToken := der(0x30, append(mechTypes, mechToken...))
	return der(0x60, append(der(0x06, oidSPNEGO), der(0xA0, negToken)...))
}

// spnegoResp 组 negTokenResp：
//
//	negTokenResp ::= SEQUENCE {
//	    negState [0], supportedMech [1], responseToken [2], mechListMIC [3] }
//
// responseToken 是 [2]（0xA2）。写成 [1] 会把 OCTET STRING 塞进
// supportedMech 的位置，服务端解析成非法参数 —— 实测 Samba 直接回
// STATUS_INVALID_PARAMETER（0xC000000D）而不是 LOGON_FAILURE。
func spnegoResp(token []byte) []byte {
	return der(0xA1, der(0x30, der(0xA2, derOctets(token))))
}

// findNTLMSSP 在 SPNEGO 包装里定位 NTLMSSP token（服务端可能回裸 token 也可能
// 回 negTokenResp 包着，两种都要认）。
func findNTLMSSP(blob []byte) []byte {
	i := bytes.Index(blob, []byte(ntlmsspSig))
	if i < 0 {
		return nil
	}
	return blob[i:]
}

// ---- SESSION_SETUP (0x0001) ----

func ssReq(token []byte, mid uint64, session uint64) []byte {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 25) // StructureSize
	// Flags (2) = 0
	body[3] = 1 // SecurityMode = SIGNING_ENABLED
	// Capabilities (4..8) = 0
	// Channel (8..12) = 0
	binary.LittleEndian.PutUint16(body[12:], 88) // SecurityBufferOffset = 64+24
	binary.LittleEndian.PutUint16(body[14:], uint16(len(token)))
	// PreviousSessionId (16..24) = 0
	return append(append(smbHdr(1, mid, 0, session, 0, 1, 0), body...), token...)
}

// ---- TREE_CONNECT (0x0003) ----

func tcReq(host, share string, mid uint64, session uint64) []byte {
	path := utf16le(`\\` + host + `\` + share)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:], 9) // StructureSize
	// Reserved (2..4) = 0
	binary.LittleEndian.PutUint16(body[4:], 72) // PathOffset = 64+8
	binary.LittleEndian.PutUint16(body[6:], uint16(len(path)))
	return append(append(smbHdr(3, mid, 0, session, 0, 1, 0), body...), path...)
}

// ---- CREATE (0x0005) ----

// createAccessReadPipe 是只读打开命名管道的 DesiredAccess，
// 取自真实 rpcclient 抓包（打开 \\IPC$\srvsvc）。
const createAccessReadPipe = 0x0002019F

// createReq 只读地打开一个命名管道（FILE_OPEN，不是 FILE_OVERWRITE/CREATE）。
//
// 参数取自真实 rpcclient 抓包（打开 \\IPC$\srvsvc）：
//
//	DesiredAccess=0x0002019F  FileAttributes=0  ShareAccess=0x3
//	CreateDisposition=1 (FILE_OPEN)  CreateOptions=0
//
// 教训：管道不能带 FILE_NON_DIRECTORY_FILE(0x40)，Samba 会静默丢弃
// 请求（不回错误也不回成功，客户端只看到超时）。
//
// 字段顺序（MS-SMB2 §2.2.13）：StructureSize H / SecurityFlags B /
// OplockLevel B / ImpersonationLevel I / SmbCreateFlags Q / Reserved Q /
// DesiredAccess I / FileAttributes I / ShareAccess I /
// CreateDisposition I / CreateOptions I / NameOffset H / NameLength H /
// CreateContextsOffset I / CreateContextsLength I  = 56 字节
func createReq(name string, mid uint64, session uint64, tree uint32, access uint32) []byte {
	nb := utf16le(name)
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:], 57) // StructureSize
	body[2] = 0                                 // SecurityFlags
	body[3] = 0                                 // RequestedOplockLevel = LEVEL_NONE
	binary.LittleEndian.PutUint32(body[4:], 2)  // ImpersonationLevel = Impersonation
	// SmbCreateFlags (8..16) = 0, Reserved (16..24) = 0
	binary.LittleEndian.PutUint32(body[24:], access)
	// FileAttributes (28..32) = 0
	binary.LittleEndian.PutUint32(body[32:], 0x03) // ShareAccess = READ|WRITE
	binary.LittleEndian.PutUint32(body[36:], 1)    // FILE_OPEN（已存在才打开，绝不新建）
	// CreateOptions (40..44) = 0（管道不能用 FILE_NON_DIRECTORY_FILE）
	binary.LittleEndian.PutUint16(body[44:], 120) // NameOffset = 64+56
	binary.LittleEndian.PutUint16(body[46:], uint16(len(nb)))
	// CreateContextsOffset (48..52) / CreateContextsLength (52..56) = 0
	return append(append(smbHdr(5, mid, tree, session, 0, 1, 0), body...), nb...)
}

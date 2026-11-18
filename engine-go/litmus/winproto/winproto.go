// Package winproto 实现 SMB2 / LDAP / RDP 三协议的只读探针。
//
// 为什么单独一个包：SMB2 / LDAP / RDP 都是「客户端先说话」的协议，
// 被动 banner 永远是空的，netprobe 的 banner 识别对它们完全失效
// （端口开着但 identify 返回 unknown）。所以必须主动构造协议报文。
//
// 三个探针都只做只读动作，一行写操作都没有：
//
//	SMB2  NEGOTIATE（读签名策略）→ SESSION_SETUP 匿名会话 → TREE_CONNECT IPC$
//	      · 判据：服务端回 STATUS_SUCCESS 且给出非零 SessionId / TreeId
//	      · 只连 IPC$，不 TREE_CONNECT 任何磁盘共享，不 CREATE 任何文件
//	LDAP  anonymous simple bind → rootDSE 查询 → 有 namingContext 时
//	      再做一次 sizeLimit=5 的只读 search
//	      · 判据：bindResponse resultCode==0 且 search 真返回条目
//	      · 只 search，不 add/modify/delete
//	RDP   X.224 Connection Request → 解析 RDP Negotiation Response
//	      · 判据：真读到 selectedProtocol 字段，不是猜 banner
//	      · 只协商，不建 MCS 通道，不碰图形层
//
// 判定纪律：端口开着、收到 SYN-ACK、看到 "Microsoft-DS" 都不算命中。
// 必须走到只有漏洞成立才会出现的字节，否则返回 nil。
//
// # 移植说明（与 Python 版 winproto.py 的差异，均为语言能力差异）
//
//   - Python 用 ssl.SSLContext + set_ciphers("DEFAULT:@SECLEVEL=0") 放宽
//     OpenSSL 安全级别；Go 没有对应旋钮，改用 InsecureSkipVerify +
//     MinVersion=TLS1.0 达到同样的「接受老服务端」效果。
//   - Python 的 socket.timeout 在证据里显示 "timed out"，Go 是 "i/o timeout"；
//     Python 用 type(e).__name__ 前缀的异常类名，Go 没有对应概念，只保留错误文本。
//   - Python 的 utf-16-le 解码遇到孤立代理项会抛 UnicodeDecodeError（解析函数
//     因此返回 None）；Go 的 utf16.Decode 会替换成 U+FFFD。畸形共享名上取舍
//     不同，正常流量无差异。
//   - Python 里畸形输入可能抛异常并中断整个探针；Go 版一律降级为「这条报文
//     不认」并继续（契约 §4.3：解析失败不许 panic）。
package winproto

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

const (
	// MaxEvid 证据文本上限，对齐 Python 的 MAX_EVID
	MaxEvid = 1200

	// DefaultSMBPort / DefaultLDAPPort / DefaultRDPPort 与 Python 版
	// probe_* 的默认参数一致
	DefaultSMBPort  = 445
	DefaultLDAPPort = 389
	DefaultRDPPort  = 3389

	// DefaultTimeout 对齐 Python 版 probe_smb / probe_ldap 的 6.0 秒默认值
	DefaultTimeout = 6 * time.Second

	// DefaultRDPTimeout 对齐 Python 版 probe_rdp 的 5.0 秒默认值
	DefaultRDPTimeout = 5 * time.Second

	// IdentifyTimeout 对齐 Python 版 identify() 的 2.0 秒默认值
	IdentifyTimeout = 2 * time.Second
)

// target 是一次探测的落点，用来给 finding 填 target / host / port。
// Python 版由 engine 回填这三个字段，Go 版在包内一次填好，避免调用方漏填。
type target struct {
	host string
	port int
}

// result 是 Python 版 _res() 的等价物：一条发现的全部内容。
type result struct {
	check      string
	name       string
	severity   string
	level      string
	evidence   string
	repro      string
	impact     string
	fix        string
	extra      map[string]interface{}
	creds      []model.Cred
	confidence string
	category   string
}

func (t target) finding(r result) *model.Finding {
	conf := r.confidence
	if conf == "" {
		conf = "confirmed"
	}
	cat := r.category
	if cat == "" {
		cat = "host"
	}
	return model.NewFinding(r.check, r.name, r.severity,
		fmt.Sprintf("%s:%d", t.host, t.port),
		model.FindingOpts{
			Host:       t.host,
			Port:       t.port,
			Category:   cat,
			Level:      r.level,
			Confidence: conf,
			Evidence:   r.evidence,
			Repro:      r.repro,
			Impact:     r.impact,
			Fix:        r.fix,
			Extra:      r.extra,
			Creds:      r.creds,
		})
}

// dial 对应 Python 的 _conn()：TCP 连接，可选 TLS。
//
// 超时是显式参数而不是全局默认值 —— Go 的 net.Dial 不设超时就是永久挂住，
// 这是契约 §4.3 明令禁止的。
func dial(host string, port int, timeout time.Duration, useTLS bool) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return c, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tc := tls.Client(c, &tls.Config{
		// 对齐 Python 的 check_hostname=False / CERT_NONE：探针只关心
		// 服务端说什么，不做证书校验。
		InsecureSkipVerify: true,
		ServerName:         host,
		// 对齐 Python 的 @SECLEVEL=0：允许连 TLS1.0 的老设备。
		MinVersion: tls.VersionTLS10,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close() // 握手失败时关闭底层连接；关闭错误无处理价值
		return nil, err
	}
	return tc, nil
}

// writeAll 写一整块，并带上写超时（Python 的 settimeout 同时管读和写）。
func writeAll(c net.Conn, b []byte, timeout time.Duration) error {
	if timeout > 0 {
		if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
	}
	_, err := c.Write(b)
	return err
}

// hexPreview 对应 Python 的 _hex()：短就全给，长就截断并标注总长度。
func hexPreview(b []byte, limit int) string {
	if len(b) <= limit {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:limit]) + fmt.Sprintf("…(%dB)", len(b))
}

// txtPreview 对应 Python 的 _txt()：把控制字符转义后截断，便于塞进证据。
// Python 版定义了但没调用，这里同样保留同名能力（逐函数移植，不做裁剪）。
func txtPreview(b []byte, limit int) string {
	s := string(b)
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\x00", "\\x00")
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

// utf16le 对应 Python 的 s.encode("utf-16-le")：无 BOM，纯小端码元。
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// utf16leString 对应 Python 的 b.decode("utf-16-le")。
// 末尾奇数字节被丢弃（Python 会抛 UnicodeDecodeError，见包注释）。
func utf16leString(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u))
}

// utf8Replace 对应 Python 的 decode("utf-8", "replace")。
func utf8Replace(b []byte) string {
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// sliceFrom 是 Python 切片语义的等价物：起点越界给空，终点越界就截到末尾。
// Python 的 b[off:off+n] 从不报错，Go 的裸切片会 panic，所以统一走这里。
func sliceFrom(b []byte, off, n int) []byte {
	if off < 0 || off > len(b) || n <= 0 {
		return nil
	}
	end := off + n
	if end > len(b) || end < off {
		end = len(b)
	}
	return b[off:end]
}

// reproReplay 是报告里「复现」一栏的主路径。
//
// 这个二进制是泡在客户内网 VDI 里跑的：那边没有 nmap、没有 ldapsearch、更没有
// Python。报告让客户去装工具跑一遍，等于给一条跑不通的路。所以主路径固定成
// litmus 自己的 replay 子命令 —— 它一定能跑；{ID} 由 report 渲染时替换成实际编号。
// 真实工具的命令保留在后面当交叉对照，手上有工具链的团队照样能用。
const reproReplay = "litmus replay -f findings.json --id {ID}"

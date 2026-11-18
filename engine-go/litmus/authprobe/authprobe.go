// Package authprobe 是服务级「真登验证」内核（Python 版 authprobe.py 的逐函数移植）。
//
// 为什么需要它：nmap 的脚本引擎告诉你「3306 open」，但那不叫漏洞。
// 判据铁律（DESIGN 里写死的）：必须走完协议拿到「只有漏洞成立才会出现」的字节。
//
//	Redis     → 发 PING 收到 +PONG 才算无认证
//	MySQL     → 走完 handshake + native_password 认证，收到 OK 包才算登进去
//	Postgres  → 收到 AuthenticationOk 才算 trust/免密
//	Memcached → stats 有返回才算暴露
//	FTP       → USER anonymous / PASS 后收到 230 才算匿名可登
//	VNC       → SecurityResult == 0 才算无认证
//	rsync     → #list 返回模块名才算可列
//	ES        → _cat/indices 拿到索引 JSON 才算可读
//	SMB2      → 匿名 SESSION_SETUP 回 SUCCESS 且能 CREATE 打开 srvsvc 管道
//	LDAP      → 匿名 bind resultCode=0 且 subtree search 真返回条目
//	RDP       → 读到 RDP_NEG_RSP 的 selectedProtocol，不是猜 banner
//
// 所有探针只读：PING / stats / 版本查询 / 列目录 / 列表名。
// 不发写命令，不改配置，不删数据。取到表名和行数就停（L3 不抽样明文）。
//
// # 与 Python 版的对应关系
//
// 一个函数一个函数对着 authprobe.py 搬，连字符串标点都不改 —— 报告层要能和
// Python 版逐字 diff（见 oracle_test.go）。三处语言差异是显式的：
//
//   - Python 的 **kw 吞掉未知关键字（probe_redis 收到 tls=True 也不会走 TLS）；
//     Go 没有关键字参数，探针统一签名 (host, port, timeout, useTLS)，
//     真正用 TLS 的只有 Elasticsearch 与 LDAP，其余在函数体内忽略 useTLS，
//     与 Python 的 **kw 行为一致。
//   - Python 的 socket.timeout 是「每次读写」超时；这里每次 Read 前刷新
//     SetReadDeadline，连接用 net.Dialer.Timeout，语义对齐。
//   - Python 的 str.decode("utf-8","replace") 是「每个坏字节替换一个 U+FFFD」；
//     Go 的 string(b) 不替换，encoding/json 又会整段替换，所以 _txt 先用
//     utf8.DecodeRune 逐字节解码（decodeRepl），保证证据文本与 Python 同形。
//
// SMB2 / LDAP / RDP 三个客户端先说话的协议已经在 internal/winproto 移植过，
// 这里只做分派（PROBES 注册表），不重复实现协议。
//
// # 移植中修正的两个原版缺陷（不是行为偏差，是不修就没有正确证据）
//
//  1. MySQL 探针在 Python 版里是死的：_mysql_pkt 定义成 (s, payload, seq)，
//     258/276 两处调用却只传 (payload, seq)，一进 sendall 就 TypeError，
//     被 probe_service 吞成 None。Go 版按作者本意实现两参签名。
//     testdata/gen_authprobe_builders.py 与 oracle_test.go 对 Python 侧做了
//     同样补丁，字节真值仍然来自原版代码。
//  2. PostgreSQL 的 _pg_startup 收到 AuthenticationOk 就返回，把随后的
//     ParameterStatus / BackendKeyData / ReadyForQuery 留在缓冲区；第一次
//     _pg_query 会读到残留的 ReadyForQuery 并立刻结束 —— 结果 version 恒为空、
//     「表数量」拿到的是 version 那一行。Go 版认证成功后继续读到 ReadyForQuery
//     再返回（协议本来就应该这样），否则写进报告的是错位数据。
//
// 另有一处纯加固：PG / Mongo 的报文长度上限（16MB），防止恶意长度触发
// 几 GB 的内存申请；原版会直接 recv 那个长度。
package authprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/winproto"
)

// MaxEvid 证据片段上限，够复现就行（对齐 Python 的 MAX_EVID）
const MaxEvid = 900

// DefaultTimeout 对齐 authprobe.probe_service 的 timeout=4.0 默认值。
const DefaultTimeout = 4 * time.Second

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

// finding 把 result 落成 model.Finding，字段填法与 winproto 的 target.finding 一致。
func (r result) finding(host string, port int) *model.Finding {
	conf := r.confidence
	if conf == "" {
		conf = "confirmed"
	}
	cat := r.category
	if cat == "" {
		cat = "host"
	}
	return model.NewFinding(r.check, r.name, r.severity,
		fmt.Sprintf("%s:%d", host, port),
		model.FindingOpts{
			Host:       host,
			Port:       port,
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

// ------------------------------------------------------------------ 网络工具

// dial 对应 Python 的 _conn()：TCP 连接，可选 TLS。
//
// Python 用 ssl.PROTOCOL_TLS_CLIENT + check_hostname=False + CERT_NONE，
// 并尝试 set_ciphers("DEFAULT:@SECLEVEL=0") 放开弱套件。Go 没有 SECLEVEL
// 旋钮，用 InsecureSkipVerify + MinVersion=TLS1.0 逼近同样的「老服务端也连」。
func dial(host string, port int, timeout time.Duration, useTLS bool) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return c, nil
	}
	tc := tls.Client(c, &tls.Config{
		InsecureSkipVerify: true, // 探针只关心服务端说什么，不校验证书
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close() // 握手失败的连接没有保留价值
		return nil, err
	}
	return tc, nil
}

// recv 对应 Python 的 _recv()：单次读取，超时/对端关闭都返回空。
func recv(c net.Conn, n int, timeout time.Duration) []byte {
	if n <= 0 {
		return nil
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, n)
	k, err := c.Read(buf)
	if k > 0 {
		return buf[:k]
	}
	if err != nil {
		return nil
	}
	return nil
}

// recvUntil 对应 Python 的 _recv_until()：读到 stop 或超时/上限为止。
//
// Python 的超时是每次 recv 的超时（settimeout 在循环外设一次，语义是每读一次
// 最多等 timeout），这里每次 Read 前刷新 deadline，保持一致。
func recvUntil(c net.Conn, stop []byte, limit int, timeout time.Duration) []byte {
	var buf []byte
	for len(buf) < limit {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		chunk := make([]byte, 4096)
		k, err := c.Read(chunk)
		if k > 0 {
			buf = append(buf, chunk[:k]...)
		}
		if err != nil || k == 0 {
			break
		}
		if len(stop) > 0 && bytes.Contains(buf, stop) {
			break
		}
	}
	return buf
}

// txt 对应 Python 的 _txt()：UTF-8 替换解码、\r 与 NUL 转义、按字符截断。
func txt(b []byte, limit int) string {
	s := decodeRepl(b)
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\x00", "\\x00")
	r := []rune(s)
	if len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}

// decodeRepl 复刻 CPython bytes.decode("utf-8", "replace") 的替换粒度。
//
// 不是「每个坏字节一个 U+FFFD」：CPython 按 Unicode 的 maximal subpart 规则，
// 一个被截断的多字节前缀只算一个错误（\xe4\xb8 → 1 个 U+FFFD），
// 而 ED A0 80（代理区）会拆成 3 个错误。Go 的 utf8.DecodeRune 一律按单字节
// 处理，直接用会与 Python 证据文本不一致（BSON/错误报文里很常见）。
func decodeRepl(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			sb.WriteByte(c)
			i++
			continue
		}
		size := utf8SeqLen(c)
		if size == 0 {
			sb.WriteRune(utf8.RuneError)
			i++
			continue
		}
		ok, prefix := utf8SeqValid(b[i:], size)
		if ok {
			r, n := utf8.DecodeRune(b[i:])
			sb.WriteRune(r)
			i += n
			continue
		}
		sb.WriteRune(utf8.RuneError)
		i += prefix
	}
	return sb.String()
}

// utf8SeqLen 是 CPython 解码器认可的 lead byte 长度，非法 lead 返回 0。
func utf8SeqLen(c byte) int {
	switch {
	case c >= 0xC2 && c <= 0xDF:
		return 2
	case c >= 0xE0 && c <= 0xEF:
		return 3
	case c >= 0xF0 && c <= 0xF4:
		return 4
	default:
		return 0
	}
}

// utf8SeqValid 判断从 lead 开始的 size 字节序列是否完整合法；
// 不合法时 prefix 是「已经合法的前缀长度」（至少 1），用于 maximal subpart。
func utf8SeqValid(b []byte, size int) (ok bool, prefix int) {
	for pos := 1; pos < size; pos++ {
		if pos >= len(b) { // 截断
			return false, pos
		}
		if !utf8ContOK(b[0], pos, b[pos]) {
			return false, pos
		}
	}
	return true, size
}

// utf8ContOK 是各 lead byte 在 pos 位置允许的 continuation 范围
// （E0/ED/F0/F4 有额外约束，代理区与超范围在第一步就被拒）。
func utf8ContOK(lead byte, pos int, c byte) bool {
	if c < 0x80 || c > 0xBF {
		return false
	}
	if pos != 1 {
		return true
	}
	switch lead {
	case 0xE0:
		return c >= 0xA0
	case 0xED:
		return c <= 0x9F
	case 0xF0:
		return c >= 0x90
	case 0xF4:
		return c <= 0x8F
	}
	return true
}

// ------------------------------------------------------------------ Python 风格格式化
//
// 证据里 Python 版直接 str(list) / str(dict)，要与它逐字对齐就得复刻 repr。
// 只覆盖探针实际会产生的形状（字符串列表、字符串键的计数字典）。

// pyReprStr 复刻 Python 对 str 的 repr（单引号包裹 + 反斜杠/引号转义）。
func pyReprStr(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return "'" + s + "'"
}

// pyReprAny 是 str(value) 的最小子集：None/int/str。
func pyReprAny(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint32:
		return strconv.FormatUint(uint64(x), 10)
	default:
		return fmt.Sprint(x)
	}
}

// pyReprList 复刻 str(["a","b"]) → "['a', 'b']"。
func pyReprList(vals []interface{}) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		if v == nil {
			parts = append(parts, "None")
			continue
		}
		parts = append(parts, pyReprStr(pyReprAny(v)))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// pyReprIntMap 复刻 str({"app": 12, "mysql": 3})，keys 给出 Python dict 的插入顺序。
func pyReprIntMap(keys []string, m map[string]int) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, pyReprStr(k)+": "+strconv.Itoa(m[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// ------------------------------------------------------------------ 注册表

// ProbeFunc 是所有探针的统一签名。useTLS 只被 elasticsearch / ldap 使用，
// 其余探针忽略它 —— 对应 Python 版探针函数用 **kw 吞掉 tls 关键字的行为。
type ProbeFunc func(host string, port int, timeout time.Duration, useTLS bool) *model.Finding

// Probes 与 Python 版 PROBES 逐键对齐。
var Probes = map[string]ProbeFunc{
	"redis": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbeRedis(h, p, t)
	},
	"memcached": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbeMemcached(h, p, t)
	},
	"mysql": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbeMySQL(h, p, t)
	},
	"postgres": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbePostgres(h, p, t)
	},
	"mongodb": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbeMongo(h, p, t)
	},
	"elasticsearch": ProbeElasticsearch,
	"ftp": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbeFTP(h, p, t)
	},
	"vnc": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbeVNC(h, p, t)
	},
	"rsync": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		return ProbeRsync(h, p, t)
	},
	"smb": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		if t <= 0 {
			t = winproto.DefaultTimeout
		}
		return winproto.ProbeSMB(h, p, t)
	},
	"ldap": func(h string, p int, t time.Duration, useTLS bool) *model.Finding {
		if t <= 0 {
			t = winproto.DefaultTimeout
		}
		return winproto.ProbeLDAP(h, p, t, useTLS)
	},
	"rdp": func(h string, p int, t time.Duration, _ bool) *model.Finding {
		if t <= 0 {
			t = winproto.DefaultRDPTimeout
		}
		return winproto.ProbeRDP(h, p, t)
	},
}

// Alias 是服务名归一规则，顺序即匹配优先级（Python dict 保序，Go map 不保序，
// 所以这里用切片）。匹配是「子串包含」，与 key_for 的 `name in c` 一致。
type Alias struct{ Name, Key string }

// Aliases 与 Python 版 ALIAS 逐项同序。顺序有语义：
// "postgresql" 必须排在 "postgres" 前、"mongodb" 在 "mongo" 前，否则归一名会变。
var Aliases = []Alias{
	{"redis", "redis"}, {"memcached", "memcached"}, {"mysql", "mysql"},
	{"mariadb", "mysql"}, {"postgresql", "postgres"}, {"postgres", "postgres"},
	{"mongodb", "mongodb"}, {"mongo", "mongodb"},
	{"elasticsearch", "elasticsearch"}, {"elastic", "elasticsearch"},
	{"ftp", "ftp"}, {"vsftpd", "ftp"}, {"proftpd", "ftp"}, {"pure-ftpd", "ftp"},
	{"vnc", "vnc"}, {"rfb", "vnc"}, {"rsync", "rsync"},
	{"microsoft-ds", "smb"}, {"netbios-ssn", "smb"}, {"smb", "smb"}, {"cifs", "smb"},
	{"ldap", "ldap"}, {"ldaps", "ldap"}, {"globalcatldap", "ldap"},
	{"ms-wbt-server", "rdp"}, {"rdp", "rdp"}, {"terminal services", "rdp"},
}

// PortHint 是服务缺席时的端口兜底（只在 netprobe 认不出服务时用）。
var PortHint = map[int]string{
	6379: "redis", 11211: "memcached", 3306: "mysql", 5432: "postgres",
	27017: "mongodb", 9200: "elasticsearch", 21: "ftp", 5900: "vnc",
	5901: "vnc", 873: "rsync",
	445: "smb", 139: "smb", 389: "ldap", 636: "ldap",
	3268: "ldap", 3269: "ldap", 3389: "rdp",
}

// KeyFor 返回该服务/端口对应的探针 key；没有对应探针返回空串。
//
// 与 probe_service 共用同一套匹配规则，供编排层区分「有探针但没结论」
// 和「根本没有对应探针」—— 后者必须记 na。把它记成 ok 等于把
// 「未测」说成「测过」，是覆盖表造假。
func KeyFor(service, product string, port int) string {
	return KeyForOpts(service, product, port, true)
}

// KeyForOpts 是 key_for(allow_ports=...) 的完整形态。
// allowPorts=false 时不做端口兜底（Python 的 allow_ports=False）。
func KeyForOpts(service, product string, port int, allowPorts bool) string {
	for _, cand := range []string{service, product} {
		if cand == "" {
			continue
		}
		c := strings.ToLower(cand)
		for _, a := range Aliases {
			if strings.Contains(c, a.Name) {
				return a.Key
			}
		}
	}
	if port != 0 && allowPorts {
		return PortHint[port]
	}
	return ""
}

// Options 是 probe_service(host, port, service=..., product=..., tls=...,
// timeout=..., allow_ports=...) 的具名参数版本。
type Options struct {
	Service string
	Product string
	TLS     bool
	Timeout time.Duration
	// NoPortHint 对应 allow_ports=False。默认 false：允许按端口兜底。
	NoPortHint bool
}

// ProbeService 按服务名挑探针并执行。返回 nil 表示「已尝试，无未授权结论」。
//
// Python 版把所有异常都吞成 None；这里用 recover 兜住任何意外 panic，
// 保证编排层永远拿到 nil 而不是进程崩溃（契约 §4.3）。
func ProbeService(host string, port int, o Options) (f *model.Finding) {
	defer func() {
		if r := recover(); r != nil {
			f = nil
		}
	}()
	key := KeyForOpts(o.Service, o.Product, port, !o.NoPortHint)
	fn := Probes[key]
	if fn == nil {
		return nil
	}
	t := o.Timeout
	if t <= 0 {
		t = DefaultTimeout
	}
	return fn(host, port, t, o.TLS)
}

// Probe 是 probe(host, port, **kw) 的别名。
func Probe(host string, port int, o Options) *model.Finding {
	return ProbeService(host, port, o)
}

// Dict 把 Finding 转成 Python 版 _res() 的字典形状。
//
// 编排层（engine.ProbeAuth hook）按 map 取值，Python 版返回的也是 dict；
// 两边共用同一套字段名。creds 里的 secret 是明文 —— 只在本进程内流转，
// 报告层统一走 model.MaskSecret。
func Dict(f *model.Finding) map[string]interface{} {
	if f == nil {
		return nil
	}
	creds := make([]interface{}, 0, len(f.Creds))
	for _, c := range f.Creds {
		creds = append(creds, map[string]interface{}{
			"proto": c.Proto, "host": c.Host, "port": c.Port,
			"user": c.User, "secret": c.Secret, "kind": c.Kind,
		})
	}
	return map[string]interface{}{
		"check":      f.Check,
		"name":       f.Name,
		"severity":   f.Severity,
		"level":      f.Level,
		"evidence":   f.Evidence,
		"repro":      f.Repro,
		"impact":     f.Impact,
		"fix":        f.Fix,
		"extra":      f.Extra,
		"creds":      creds,
		"confidence": f.Confidence,
		"category":   f.Category,
	}
}

// ProbeDict 是 probe_service 的字典版，直接对接 engine.ProbeAuth hook。
func ProbeDict(host string, port int, o Options) map[string]interface{} {
	return Dict(ProbeService(host, port, o))
}

// ------------------------------------------------------------------ 字节工具

// be32 / le32 是大端/小端 32 位的简写，协议报文里用得多。
func be32(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
	return b
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return b
}

// lowerASCII 是 Python bytes.lower() 的等价物：只折叠 ASCII A-Z。
// 不能用 bytes.ToLower —— 它是 UTF-8 感知的，遇到 BSON 里的裸浮点字节
// 会把非法字节替换成 3 字节的 U+FFFD，索引整体错位（实测偏移 +2）。
func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// splitLines 复刻 Python str.splitlines 的常用子集（\r\n / \r / \n）。
// Python 的 splitlines 不产生末尾空串，这里也一样。
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

package netprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

// 连接失败的分类串，与 Python 版 _connect 的返回值逐字一致。
const (
	errTimeout = "timeout"
	errRefused = "refused"
)

// 探针阶梯的固定部分，与 Python 的 _PROBE_HTTP / _PROBE_REDIS / _PROBE_MEMC 对应。
var (
	probeHTTP      = []byte("GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
	probeRedis     = []byte("PING\r\n")
	probeMemcached = []byte("stats\r\n")
)

// mongoIsMaster 是 MongoDB 的 legacy isMaster 查询（只读，不写任何文档）。
// 用 hex 写是为了能和 Python 源码里的 bytes.fromhex(...) 逐字节对照，
// 测试里也用同一个哈希钉死。
var mongoIsMaster = mustHex("3a0000000100000000000000d407000000000000" +
	"61646d696e2e24636d640000000000ffffffff" +
	"130000001069734d6173746572000100000000")

// mustHex 只在包初始化时跑，出错说明常量写错了（程序员错误，不是网络失败）。
// 契约禁止的是「用 panic 处理正常的网络失败」，这里不冲突。
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("netprobe: 内置探针常量不是合法 hex: " + err.Error())
	}
	return b
}

// activeProbe 是一条主动只读探针：(名字, 端口提示, 发送字节)。
// hint == 0 表示没有端口提示（Python 里的 None）。
type activeProbe struct {
	name    string
	hint    int
	payload []byte
}

// activeProbes 全部是只读命令：PING / stats / 版本查询 / 模块列表，没有一条会改服务端状态。
var activeProbes = []activeProbe{
	// Redis：只读 PING（不写任何 key）
	{"redis", 6379, probeRedis},
	// Memcached：只读 stats
	{"memcached", 11211, probeMemcached},
	// HTTP：请求根路径
	{"http", 0, probeHTTP},
	// Elasticsearch / Docker / K8s API 也走 HTTP，靠 body 区分
	// MySQL 服务端先发 greeting，不用探针
	// PostgreSQL：SSLRequest 会得到 S/N 单字节
	{"postgres", 5432, []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}},
	// MongoDB：legacy isMaster 查询
	{"mongodb", 27017, mongoIsMaster},
	// rsync 模块列表（只读）
	{"rsync", 873, []byte("@RSYNCD: 31.0\n#list\n")},
	// Docker API 版本（只读）
	{"docker", 2375, []byte("GET /version HTTP/1.0\r\nHost: t\r\n\r\n")},
}

// probe 是阶梯里的一步。
type probe struct {
	name    string
	payload []byte
}

// probeHint 按端口取探针字节。多个探针同端口时后者覆盖前者 —— 与 Python 的
// {h: p for n, h, p in ACTIVE_PROBES if h is not None} 字典推导语义一致。
func probeHint(port int) ([]byte, bool) {
	var payload []byte
	found := false
	for _, ap := range activeProbes {
		if ap.hint != 0 && ap.hint == port {
			payload, found = ap.payload, true
		}
	}
	return payload, found
}

// ladderFor 按端口相关度排序的只读探针阶梯。端口只影响顺序，不影响是否尝试。
//
// 这样即使服务跑在非标准端口（8081 上的 Redis、12345 上的 HTTP）也能识别，
// 而不是靠端口号硬猜。最多走 3 步，避免对同一个端口无休止地灌探针。
func ladderFor(port int) []probe {
	var ladder []probe
	if payload, ok := probeHint(port); ok {
		ladder = append(ladder, probe{name: "port-" + strconv.Itoa(port), payload: payload})
	}
	ladder = append(ladder,
		probe{"http", probeHTTP},
		probe{"redis", probeRedis},
		probe{"memcached", probeMemcached},
	)
	seen := make(map[string]bool, len(ladder))
	out := make([]probe, 0, 3)
	for _, pr := range ladder {
		key := string(pr.payload)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, pr)
	}
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

// connect 建一条带超时的 TCP 连接。成功返回 (conn, "")，失败返回 (nil, 分类串)。
//
// 分类串的取值与 Python 版一致："timeout" / "refused" / "<类型>: <详情>"。
func connect(host string, port int, timeout time.Duration) (net.Conn, string) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		return c, ""
	}
	return nil, classifyDialError(err)
}

// classifyDialError 把 Go 的拨号错误映射成 Python 版的分类串。
func classifyDialError(err error) string {
	switch {
	case isTimeout(err):
		return errTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return errRefused
	}
	return fmt.Sprintf("%T: %v", err, err)
}

// isTimeout 判定超时。Go 的拨号超时会被包成 *net.OpError，要用 Timeout() 才认得出。
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// readSome 读一次，最多 n 字节。超时/出错返回 nil —— 对应 Python 的 _read_some。
func readSome(c net.Conn, n int, timeout time.Duration) []byte {
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}
	buf := make([]byte, n)
	// 与 Python 的 _read_some 一致：读超时、对端关闭、对端 RST 一律归为「没读到」，
	// 不区分原因 —— 上层只关心 len(buf) 是不是 0。
	k, _ := c.Read(buf)
	if k > 0 {
		return buf[:k]
	}
	return nil
}

// drain 连续读到静默为止。
//
// 为什么不能只 recv 一次：HTTP 响应常被拆成多个 TCP 段（headers 一段、body 一段）。
// 只读一次常常只拿到 headers，body 里的应用层特征（"cluster_name" 之类）全丢，
// ES 就被识别成通用 http —— 于是整类未授权验证被静默跳过。
// 这是 Python 版实测到的偶发漏报根因，Go 版保持同样的「读到静默」语义。
//
// 参数：limit 总字节上限，timeout 总时长上限，quiet 静默判定窗口。
func drain(c net.Conn, limit int, timeout, quiet time.Duration) []byte {
	var out []byte
	deadline := time.Now().Add(timeout)
	for len(out) < limit {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		wait := quiet
		if left < wait {
			wait = left
		}
		if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
			break
		}
		n := limit - len(out)
		if n > 4096 {
			n = 4096
		}
		buf := make([]byte, n)
		k, err := c.Read(buf)
		if k > 0 {
			out = append(out, buf[:k]...)
		}
		if err != nil {
			// 静默（读超时）或对端关闭 → 认为读完了
			break
		}
	}
	return out
}

// tlsVersionName 把 crypto/tls 的版本号转成 Python ssl 模块的字符串形式。
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// cipherNames 把 Go 的套件 ID 映射成 OpenSSL 命名（= Python 的 s.cipher()[0]）。
// TLS 1.3 的三套在两边本来就同名，不用列。
var cipherNames = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:                      "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "DES-CBC3-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:                  "AES128-SHA",
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:                  "AES256-SHA",
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:               "AES128-SHA256",
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:               "AES128-GCM-SHA256",
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:               "AES256-GCM-SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "ECDHE-ECDSA-RC4-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "ECDHE-ECDSA-AES128-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "ECDHE-ECDSA-AES256-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "ECDHE-RSA-RC4-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "ECDHE-RSA-DES-CBC3-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "ECDHE-RSA-AES128-SHA",
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "ECDHE-RSA-AES256-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "ECDHE-ECDSA-AES128-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "ECDHE-RSA-AES128-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "ECDHE-RSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "ECDHE-ECDSA-AES128-GCM-SHA256",
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "ECDHE-RSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "ECDHE-ECDSA-AES256-GCM-SHA384",
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "ECDHE-RSA-CHACHA20-POLY1305",
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "ECDHE-ECDSA-CHACHA20-POLY1305",
}

// cipherName 取 OpenSSL 风格套件名，未知 ID 退回 Go 自己的名字（至少不丢信息）。
func cipherName(id uint16) string {
	if n, ok := cipherNames[id]; ok {
		return n
	}
	return tls.CipherSuiteName(id)
}

// legacyCipherSuites 对应 Python 的 ctx.set_ciphers("DEFAULT:@SECLEVEL=0")：
// 把 Go 默认不启用的弱套件也带上，否则对着一台只开 RC4/3DES 的老设备会直接握手失败，
// 白白漏掉一台真实存在的资产。探测场景下验证本来就不做（InsecureSkipVerify）。
func legacyCipherSuites() []uint16 {
	ids := make([]uint16, 0, 32)
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

var (
	oidEmailAddress    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
)

// dnToMap 把 pkix.Name 摊平成 Python getpeercert()["subject"] 那套短名映射。
func dnToMap(n pkix.Name) map[string]string {
	m := make(map[string]string, 8)
	put := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	put("commonName", n.CommonName)
	put("countryName", firstOrEmpty(n.Country))
	put("localityName", firstOrEmpty(n.Locality))
	put("stateOrProvinceName", firstOrEmpty(n.Province))
	put("organizationName", firstOrEmpty(n.Organization))
	put("organizationalUnitName", firstOrEmpty(n.OrganizationalUnit))
	put("streetAddress", firstOrEmpty(n.StreetAddress))
	put("postalCode", firstOrEmpty(n.PostalCode))
	put("serialNumber", n.SerialNumber)
	for _, atv := range n.Names {
		switch {
		case atv.Type.Equal(oidEmailAddress):
			put("emailAddress", fmt.Sprint(atv.Value))
		case atv.Type.Equal(oidDomainComponent):
			put("domainComponent", fmt.Sprint(atv.Value))
		}
	}
	return m
}

func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// tlsProbe 做一次 TLS 握手，返回 (tls_info, 错误串)。
//
// 与 Python 版的差异见包注释：握手失败不再抛异常，且 subject/issuer/notAfter 会真的填上
// （Python 版设了 CERT_NONE，getpeercert() 恒为空 dict，那三个字段是死代码）。
func tlsProbe(host string, port int, timeout time.Duration) (*TLSInfo, string) {
	raw, cerr := connect(host, port, timeout)
	if raw == nil {
		return nil, "tls: " + cerr
	}
	defer raw.Close()

	cfg := &tls.Config{
		InsecureSkipVerify: true, // 探测只看「能不能握手、协商出什么」，不做信任判定
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       legacyCipherSuites(),
	}
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Sprintf("%T: %v", err, err)
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Sprintf("%T: %v", err, err)
	}
	st := tc.ConnectionState()
	info := &TLSInfo{
		Version: tlsVersionName(st.Version),
		Cipher:  cipherName(st.CipherSuite),
		Subject: map[string]string{},
		Issuer:  map[string]string{},
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		info.Subject = dnToMap(leaf.Subject)
		info.Issuer = dnToMap(leaf.Issuer)
		info.NotAfter = leaf.NotAfter.UTC().Format("Jan _2 15:04:05 2006 GMT")
		sum := sha256.Sum256(leaf.Raw)
		info.SHA256 = hex.EncodeToString(sum[:])
	}
	return info, ""
}

// Grab 连接并采集 banner；按端口挑一个只读主动探针。
//
// 流程（与 Python 版 grab 逐段对应）：
//  1. connect 失败 → state = closed(refused) / filtered(其它)，直接返回
//  2. useTLS → 先做 TLS 握手拿证书信息，再重连回明文做后续探测
//  3. 被动读一次（SSH/FTP/SMTP/VNC/MySQL 会主动打招呼）
//  4. 认不出来才走探针阶梯；某一步拿到噪声响应也继续下一步
//  5. TLS 成功但认不出协议 → 标 https；端口提示兜底只在「有响应」时生效
func Grab(host string, port int, timeout time.Duration, useTLS, active bool) *PortResult {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	res := &PortResult{Host: host, Port: port, State: StateClosed}
	t0 := time.Now()

	sock, cerr := connect(host, port, timeout)
	if sock == nil {
		if cerr == errRefused {
			res.State = StateClosed
		} else {
			res.State = StateFiltered
		}
		res.Error = cerr
		res.Elapsed = time.Since(t0).Seconds()
		return res
	}
	res.State = StateOpen

	// closeSock 对应 Python 的 finally: sock.close()。置 nil 是为了让后面的重连
	// 不会在 defer 里再关一次已经关掉的 fd。
	closeSock := func() {
		if sock != nil {
			sock.Close()
			sock = nil
		}
	}
	defer closeSock()

	if useTLS {
		closeSock()
		info, terr := tlsProbe(host, port, timeout+time.Second)
		res.TLS = info
		// Python 版在这里无论 info 是否为空都去重连；info 为空时它拿着已关闭的 socket
		// 继续 read，直接抛 OSError（实测）。Go 版两条路都重连，把失败原因记下来。
		s2, rerr := connect(host, port, timeout)
		if s2 == nil {
			if info == nil {
				res.Error = terr
			} else {
				// Python 版这里只会拿到一个空结果（原因被丢了）；Go 版把原因记下来，
				// Error 不进 JSON，不影响与 oracle 的逐字段对齐。
				res.Error = rerr
			}
			res.Elapsed = time.Since(t0).Seconds()
			return res
		}
		sock = s2
		if info == nil {
			res.Error = terr
		}
	}

	// 先被动听
	buf := readSome(sock, 4096, minDur(1500*time.Millisecond, timeout))

	// 没听到，或者听到了但认不出来 → 走探针阶梯（不依赖端口号）。
	// 注意：某个探针被服务端回了「错误命令」这种噪声响应，不能就此收手，
	// 必须继续下一个探针 —— 否则非标准端口上的 Redis/Memcached 会漏识别。
	if active {
		svc0 := "unknown"
		if len(buf) > 0 {
			svc0, _, _, _ = identify(buf)
		}
		if svc0 == "unknown" {
			for _, pr := range ladderFor(port) {
				if err := sock.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
					break
				}
				if _, err := sock.Write(pr.payload); err != nil {
					break
				}
				chunk := drain(sock, 16384, minDur(1200*time.Millisecond, timeout), 120*time.Millisecond)
				if len(chunk) == 0 {
					continue
				}
				buf = append(buf, chunk...)
				if svc, _, _, _ := identify(buf); svc != "unknown" {
					break
				}
			}
		}
	}

	res.Banner = buf
	svc, prod, ver, ev := identify(buf)

	// TLS 端口没识别出来但握手成功 → 标 https
	if svc == "unknown" && res.TLS != nil {
		svc, prod = "https", "TLS"
		ev = fmt.Sprintf("TLS %s cipher=%s", res.TLS.Version, res.TLS.Cipher)
	}
	// 端口提示兜底（只在有响应时用，纯猜不算）
	if svc == "unknown" && len(buf) > 0 {
		switch {
		case port == 3306:
			svc = "mysql"
		case port == 6379:
			svc = "redis"
		case port == 27017:
			svc = "mongodb"
		case webPortSet[port]:
			svc = "http"
		}
	}
	res.Service, res.Product, res.Version, res.Evidence = svc, prod, ver, ev
	res.Elapsed = time.Since(t0).Seconds()
	return res
}

// minDur 对应 Python 的 min(a, b)（Duration 版）。
func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

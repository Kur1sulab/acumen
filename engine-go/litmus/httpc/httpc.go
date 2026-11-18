// Package httpc 是纯标准库的 HTTP/1.1 客户端内核（Python 版 httpc.py 的逐函数移植）。
//
// 设计目标（与 Python 版一致 —— 为渗透取证服务，不是给业务当 SDK）：
//  1. 原始报文双向留存：请求字节 + 响应字节原样返回，报告可直接回源
//  2. 畸形服务端容忍：坏 header、无 Content-Length、HTTP/1.0、裸关闭都能收
//  3. 不校验证书（渗透常态），但记录证书指纹供证据用
//  4. 重定向链完整记录，每跳都留 raw
//  5. 并发 + 限速一体，不给目标打崩
//
// 与 Python 版的行为差异（都是语言能力边界，不是语义改动，逐条可解释）：
//   - Go 没有函数重载：Python build_url 的双参形态（base_url, path）拆成
//     BuildURLJoin；四参形态是 BuildURL。webcheck 里的 httpc.build_url(base, path)
//     对应 BuildURLJoin。
//   - Go 没有 OpenSSL 的 SECLEVEL：Python 用 "DEFAULT:@SECLEVEL=0" 放开弱套件，
//     这里显式列上 tls.InsecureCipherSuites() + MinVersion=TLS1.0 逼近同样的宽松度；
//     但 Go 不支持 <2048 位 DH 参数与自定义曲线，极老服务端仍可能握手失败（会落成 Err，
//     不会 panic）。
//   - Text() 的 GB18030 回退无法实现：标准库没有该编码，契约禁止外部依赖。
//     非 UTF-8 / Latin-1 声明的页面会拿到替换字符；TextAs 会明确返回 ok=false，
//     绝不假装解码成功。webcheck 只用 UTF-8 替换解码（与 Python 的 _body_text 一致），
//     不受影响。
//   - Python 的 socket 超时是「每次读写」的超时；这里用每次读写前刷新的
//     SetReadDeadline / SetWriteDeadline 对齐，连接建立用 net.Dialer.Timeout。
//   - 无 Content-Length 的响应 Python 读到关闭为止，这里同样，但统一有
//     ReadToCloseLimit(8MB) / MaxBodyBytes(256MB) 的硬上限：超限截断并置 Truncated，
//     不改变 Status/Err（Python 侧无上限，恶意 CL 会直接把进程 OOM 掉）。
package httpc

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 常量：与 Python 版同名同值
const (
	// DefaultUA 默认 User-Agent（与 Python 版逐字一致，指纹要能对上）
	DefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	// MaxRedirects 默认最大重定向跳数
	MaxRedirects = 10
	// ReadChunk 单次读取块大小
	ReadChunk = 65536
	// HeaderLimit header 洪水保护阈值
	HeaderLimit = 262144
	// ReadToCloseLimit 无长度响应读到这里的上限（对齐 Python 的 8MB）
	ReadToCloseLimit = 8 << 20
	// MaxBodyBytes body 硬上限（Python 无上限，这里防 OOM）
	MaxBodyBytes = 256 << 20
	// DefaultTimeout 默认超时（Python timeout=10.0）
	DefaultTimeout = 10 * time.Second
)

// CRLF 换行
var CRLF = []byte("\r\n")

// Header 一个 header 项。
//
// 响应里 Name 一律小写（对齐 Python 的 [(name_lower, value)]），保序、允许重复；
// 请求里保留调用方写的大小写（Python 的 _build_request 也是原样写出去的）。
type Header struct {
	Name  string
	Value string
}

// H 构造一个 header 项的简写
func H(name, value string) Header { return Header{Name: name, Value: value} }

// TLSInfo 证书/连接信息（对应 Python _tls_info 的 dict）
type TLSInfo struct {
	Version  string            `json:"version"`
	Cipher   string            `json:"cipher"`
	Subject  map[string]string `json:"subject"`
	Issuer   map[string]string `json:"issuer"`
	NotAfter string            `json:"notAfter"`
	SHA256   string            `json:"sha256"`
	DERLen   int               `json:"der_len"`
}

// Response 一次请求（含重定向链）的完整结果。
//
// 字段与 Python 版 __slots__ 一一对应，只是 error(None|str) 变成 Go 的 Err error，
// peer((ip,port)) 变成 "ip:port" 字符串。
type Response struct {
	URL         string
	Status      int
	Reason      string
	Headers     []Header
	Body        []byte
	Elapsed     time.Duration
	History     []*Response
	RawRequest  []byte
	RawResponse []byte
	Err         error
	Peer        string
	TLS         *TLSInfo
	HTTPVersion string
	// Truncated body 因硬上限被截断（Python 版没有这个字段，见包注释）
	Truncated bool
}

// Header 取首个同名 header（大小写不敏感）；缺失返回空串。
// 需要区分「空值」与「不存在」时用 HeaderOK。
func (r *Response) Header(name string) string {
	v, _ := r.HeaderOK(name)
	return v
}

// HeaderOK 取首个同名 header，并告知是否存在
func (r *Response) HeaderOK(name string) (string, bool) {
	n := strings.ToLower(name)
	for _, h := range r.Headers {
		if h.Name == n {
			return h.Value, true
		}
	}
	return "", false
}

// HeaderDefault 对应 Python 的 r.header(name, default)
func (r *Response) HeaderDefault(name, def string) string {
	if v, ok := r.HeaderOK(name); ok {
		return v
	}
	return def
}

// HeaderAll 取全部同名 header（保序）
func (r *Response) HeaderAll(name string) []string {
	n := strings.ToLower(name)
	out := []string{}
	for _, h := range r.Headers {
		if h.Name == n {
			out = append(out, h.Value)
		}
	}
	return out
}

// HasHeader 是否存在该 header
func (r *Response) HasHeader(name string) bool {
	_, ok := r.HeaderOK(name)
	return ok
}

var charsetRe = regexp.MustCompile(`(?i)charset=([\w\-]+)`)

// Text 按 charset 声明解码正文。
//
// 回退顺序对齐 Python：声明编码 → utf-8 → latin-1。
// gb18030 一级在 Go 标准库没有实现（见包注释），此时返回 UTF-8 替换解码的结果。
func (r *Response) Text() string {
	enc := ""
	if m := charsetRe.FindStringSubmatch(r.Header("content-type")); m != nil {
		enc = m[1]
	}
	if s, ok := decodeCharset(r.Body, enc); ok {
		return s
	}
	if s, ok := decodeCharset(r.Body, "utf-8"); ok {
		return s
	}
	if s, ok := decodeCharset(r.Body, "latin-1"); ok {
		return s
	}
	return strings.ToValidUTF8(string(r.Body), "\uFFFD")
}

// TextAs 显式指定编码解码；不支持的编码返回 ok=false（不猜、不假装成功）。
func (r *Response) TextAs(charset string) (string, bool) { return decodeCharset(r.Body, charset) }

// decodeCharset 只实现 utf-8 系与 latin-1 系。
// Python 里 decode(..., errors="replace") 对任何已知编码都不抛异常，
// 所以这里对已知编码也用替换语义，行为一致。
func decodeCharset(b []byte, enc string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return strings.ToValidUTF8(string(b), "\uFFFD"), true
	case "latin-1", "latin1", "iso-8859-1", "iso8859-1", "8859":
		return latin1String(b), true
	}
	return "", false
}

// OK 对应 Python 的 r.ok
func (r *Response) OK() bool { return r.Err == nil && r.Status >= 100 && r.Status < 600 }

// JSON 把 body 当 JSON 解析（先做 UTF-8 替换解码，对齐 Python 的 decode(..., "replace")）
func (r *Response) JSON() (interface{}, error) {
	var v interface{}
	err := json.Unmarshal([]byte(strings.ToValidUTF8(string(r.Body), "\uFFFD")), &v)
	return v, err
}

// Seconds 耗时（秒），对齐 Python 的 float 语义
func (r *Response) Seconds() float64 { return r.Elapsed.Seconds() }

// ErrText 错误文本；无错误时为空串
func (r *Response) ErrText() string {
	if r.Err == nil {
		return ""
	}
	return r.Err.Error()
}

// String 对应 Python 的 __repr__
func (r *Response) String() string {
	tail := ""
	if r.Err != nil {
		tail = " err=" + r.Err.Error()
	}
	return fmt.Sprintf("<Response %d %s %dB %.2fs%s>", r.Status, r.URL, len(r.Body), r.Seconds(), tail)
}

// ---------------------------------------------------------------- 工具

// BuildURL 把 host/port 拼成 URL，自动推断 scheme 与默认端口。
// 对应 Python build_url(host, port=None, scheme=None, path="/")。
// port<=0 表示未指定；scheme=="" 表示按端口推断。
func BuildURL(host string, port int, scheme, path string) string {
	if scheme == "" {
		if port == 443 || port == 8443 || port == 9443 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if port <= 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	def := 80
	if scheme == "https" {
		def = 443
	}
	hostpart := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		// IPv6 字面量要加方括号
		if port == def {
			hostpart = "[" + host + "]"
		} else {
			hostpart = "[" + host + "]:" + strconv.Itoa(port)
		}
	} else if port != def {
		hostpart = host + ":" + strconv.Itoa(port)
	}
	return scheme + "://" + hostpart + path
}

// BuildURLJoin 对应 Python build_url 的双参形态 build_url(base_url, path)。
//
// 与 Python 的两点差异（都是修 bug，且线上路径不会触发）：
//   - 路径部分用字符串拼接而不是 url.URL 重组，这样 "/x?a=1&b=2" 里的 "?" 保持字面量
//     （Python 的 urlunsplit 就是这么干的；Go 走 URL.String() 会把它转义成 %3F）。
//   - Python 会把裸 "host:port" 误当成 IPv6 加方括号（build_url("h:8080", "/x") →
//     "http://[h:8080]:/x/"）；这里先补 scheme 再解析，得到正确的 "http://h:8080/x"。
func BuildURLJoin(base, sub string) string {
	if strings.HasPrefix(sub, "http://") || strings.HasPrefix(sub, "https://") {
		return NormURL(sub)
	}
	p, err := url.Parse(NormURL(base))
	if err != nil {
		return sub
	}
	if !strings.HasPrefix(sub, "/") {
		sub = "/" + sub
	}
	scheme := strings.ToLower(p.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	def := 80
	if scheme == "https" {
		def = 443
	}
	curPort := def
	if ps := p.Port(); ps != "" {
		if n, e := strconv.Atoi(ps); e == nil {
			curPort = n
		}
	}
	hostpart := p.Hostname()
	if hostpart == "" {
		hostpart = p.Host
	}
	if strings.Contains(hostpart, ":") && !strings.HasPrefix(hostpart, "[") {
		hostpart = "[" + hostpart + "]"
	}
	if curPort != def {
		hostpart += ":" + strconv.Itoa(curPort)
	}
	return scheme + "://" + hostpart + sub
}

// NormURL 规范化 URL：补 scheme、补路径、去 fragment。
func NormURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if !strings.Contains(u, "://") {
		if strings.HasSuffix(u, ":443") {
			u = "https://" + u
		} else {
			u = "http://" + u
		}
	}
	p, err := url.Parse(u)
	if err != nil {
		// Python 的 urlsplit 不会因为畸形串抛异常；这里保持「原样返回」而不是报错，
		// 让调用方（报告/证据）能看到原始输入。
		return u
	}
	scheme := strings.ToLower(p.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	p.Scheme = scheme
	p.Fragment = ""
	if p.Path == "" && p.Opaque == "" {
		p.Path = "/"
	}
	return p.String()
}

// URLSplit 对齐 Python 的 urlsplit（engine/tpl 里用它取 netloc/hostname）
func URLSplit(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return &url.URL{}
	}
	return u
}

// URLJoin 对齐 Python 的 urljoin
func URLJoin(base, ref string) string { return resolveRef(base, ref) }

// resolveRef 解析相对引用
func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

// latin1String 把字节按 latin-1 解成字符串（0x00-0xFF → U+0000-U+00FF）
func latin1String(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// writeLatin1 按 latin-1 写字符串，>0xFF 的字符写成 '?'
// （对齐 Python 的 s.encode("latin-1", "replace")）
func writeLatin1(buf *bytes.Buffer, s string) {
	for _, r := range s {
		if r > 0xFF {
			buf.WriteByte('?')
		} else {
			buf.WriteByte(byte(r))
		}
	}
}

// errText 对齐 Python 的 f"{type(e).__name__}: {e}"
func errText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%T: %v", err, err)
}

// ---------------------------------------------------------------- 报文构造

// defaultHeaders 默认请求头，顺序与 Python 版一致（raw_request 要能逐字对上）
var defaultHeaders = []Header{
	{"User-Agent", DefaultUA},
	{"Accept", "*/*"},
	{"Accept-Encoding", "gzip, deflate"},
	{"Connection", "close"},
}

func isDefaultName(lower string) bool {
	for _, d := range defaultHeaders {
		if strings.ToLower(d.Name) == lower {
			return true
		}
	}
	return false
}

// mergeHeaders 复刻 Python _once 的 header 合并逻辑：
// 默认头在前（用户给了同名就用用户的值，但保留用户写的大小写），
// 其余用户头按原顺序追加（重复保留）。
func mergeHeaders(user []Header) []Header {
	um := make(map[string]Header, len(user))
	for _, h := range user {
		um[strings.ToLower(h.Name)] = h // Python 的 dict 推导：后出现的胜出
	}
	out := make([]Header, 0, len(user)+len(defaultHeaders))
	seen := make(map[string]bool, len(defaultHeaders))
	for _, d := range defaultHeaders {
		n := strings.ToLower(d.Name)
		if h, ok := um[n]; ok {
			out = append(out, Header{Name: h.Name, Value: h.Value})
			seen[n] = true
		} else {
			out = append(out, d)
		}
	}
	for _, h := range user {
		n := strings.ToLower(h.Name)
		if !seen[n] && !isDefaultName(n) {
			out = append(out, h)
		}
	}
	return out
}

// buildRequest 对应 Python _build_request
func buildRequest(method, target string, headers []Header, body []byte, hostHeader string) []byte {
	var b bytes.Buffer
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(target)
	b.WriteString(" HTTP/1.1\r\n")
	if hostHeader != "" {
		b.WriteString("Host: ")
		writeLatin1(&b, hostHeader)
		b.WriteString("\r\n")
	}
	for _, h := range headers {
		writeLatin1(&b, h.Name)
		b.WriteString(": ")
		writeLatin1(&b, h.Value)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes()
}

// ---------------------------------------------------------------- 响应解析

// readLineN 读一行，最多 max 字节（对齐 Python 的 fp.readline(max)）。
// 返回的字节不含被截断的部分；io.EOF 时返回已读内容。
func readLineN(br *bufio.Reader, max int) []byte {
	var buf []byte
	for len(buf) < max {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		break
	}
	if len(buf) > max {
		buf = buf[:max]
	}
	return buf
}

// readHeaders 读状态行 + header，容忍裸 LF、坏行、无 header。
// 对应 Python _read_headers：raw 含结尾空行。
func readHeaders(br *bufio.Reader) (raw []byte, statusLine string, headers []Header) {
	first := readLineN(br, 65536)
	if len(first) == 0 {
		return nil, "", nil
	}
	raw = append(raw, first...)
	statusLine = strings.TrimSpace(latin1String(first))
	for {
		line := readLineN(br, 65536)
		if len(line) == 0 {
			break
		}
		raw = append(raw, line...)
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
		if len(raw) > HeaderLimit { // header 洪水保护
			break
		}
	}
	lines := bytes.Split(raw, []byte("\n"))
	for _, line := range lines[1:] {
		line = bytes.Trim(line, "\r")
		if len(line) == 0 || !bytes.Contains(line, []byte(":")) {
			continue // 坏行（无冒号）跳过：畸形服务端常态，不是错误
		}
		i := bytes.IndexByte(line, ':')
		name := strings.ToLower(strings.TrimSpace(latin1String(line[:i])))
		val := strings.TrimSpace(latin1String(line[i+1:]))
		headers = append(headers, Header{Name: name, Value: val})
	}
	return raw, statusLine, headers
}

// firstValue 取首个同名 header（对齐 Python 的 setdefault 语义）
func firstValue(hs []Header, name string) (string, bool) {
	for _, h := range hs {
		if h.Name == name {
			return h.Value, true
		}
	}
	return "", false
}

// bodyResult 收 body 的结果
type bodyResult struct {
	body      []byte
	tail      []byte
	truncated bool
}

// readBody 按 CL / chunked / 关闭 三种方式收 body。
// 对应 Python _read_body，返回 (body, raw_tail)。
func readBody(br *bufio.Reader, headers []Header, method string) bodyResult {
	// RFC 9110 §9.3.2：HEAD 响应不得含内容，一律不读 body
	if strings.EqualFold(method, "HEAD") {
		return bodyResult{}
	}
	te, _ := firstValue(headers, "transfer-encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		return readChunked(br)
	}
	if cl, ok := firstValue(headers, "content-length"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err == nil && n >= 0 {
			return readExact(br, n)
		}
	}
	// 无长度：读到关闭（带 8MB 上限，防大文件拖死）
	var buf bytes.Buffer
	total := 0
	trunc := false
	for total < ReadToCloseLimit {
		chunk := make([]byte, ReadChunk)
		m, err := br.Read(chunk)
		if m > 0 {
			buf.Write(chunk[:m])
			total += m
		}
		if err != nil {
			break
		}
	}
	if total >= ReadToCloseLimit {
		trunc = true
	}
	d := buf.Bytes()
	return bodyResult{body: d, tail: d, truncated: trunc}
}

// readExact 按 Content-Length 精确读 n 字节
func readExact(br *bufio.Reader, n int) bodyResult {
	trunc := false
	if n > MaxBodyBytes {
		n = MaxBodyBytes
		trunc = true
	}
	data := make([]byte, 0, min(n, 1<<20))
	remaining := n
	for remaining > 0 {
		step := min(ReadChunk, remaining)
		chunk := make([]byte, step)
		m, err := io.ReadFull(br, chunk)
		data = append(data, chunk[:m]...)
		remaining -= m
		if err != nil {
			break
		}
	}
	return bodyResult{body: data, tail: data, truncated: trunc}
}

// readChunked 解 chunked，同时把原始分块字节留作 tail
func readChunked(br *bufio.Reader) bodyResult {
	var raw, out bytes.Buffer
	trunc := false
	for {
		line := readLineN(br, 65536)
		if len(line) == 0 {
			break
		}
		raw.Write(line)
		sizeStr := string(line)
		if i := strings.IndexByte(sizeStr, ';'); i >= 0 {
			sizeStr = sizeStr[:i]
		}
		sizeStr = strings.TrimSpace(sizeStr)
		if sizeStr == "" {
			sizeStr = "0"
		}
		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			break // 畸形块长度：停止解析，保留已收内容
		}
		if size == 0 {
			// 吃掉 trailer
			for {
				t := readLineN(br, 65536)
				raw.Write(t)
				if len(t) == 0 || bytes.Equal(t, []byte("\r\n")) || bytes.Equal(t, []byte("\n")) {
					break
				}
			}
			break
		}
		if size > int64(MaxBodyBytes) || int64(out.Len())+size > int64(MaxBodyBytes) {
			trunc = true
			break
		}
		chunk := make([]byte, size)
		m, err := io.ReadFull(br, chunk)
		raw.Write(chunk[:m])
		out.Write(chunk[:m])
		if err != nil {
			break
		}
		tail := make([]byte, 2)
		k, err := io.ReadFull(br, tail)
		raw.Write(tail[:k])
		if err != nil {
			break
		}
	}
	return bodyResult{body: out.Bytes(), tail: raw.Bytes(), truncated: trunc}
}

// decodeBody 按 Content-Encoding 解压；解不开就返回原始字节（对齐 Python）
func decodeBody(body []byte, headers []Header) []byte {
	enc, _ := firstValue(headers, "content-encoding")
	enc = strings.ToLower(enc)
	if strings.Contains(enc, "gzip") {
		if out, err := gunzip(body); err == nil {
			return out
		}
		return body
	}
	if strings.Contains(enc, "deflate") {
		if out, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer out.Close()
			if b, err2 := io.ReadAll(out); err2 == nil {
				return b
			}
		}
		// 裸 deflate（无 zlib 头）
		fr := flate.NewReader(bytes.NewReader(body))
		defer fr.Close()
		if b, err := io.ReadAll(fr); err == nil {
			return b
		}
	}
	return body
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// ---------------------------------------------------------------- TLS

// tlsInfo 采集证书信息（对应 Python _tls_info）。
// 失败返回 nil —— 证书信息拿不到不该让整次请求失败。
func tlsInfo(cs tls.ConnectionState) *TLSInfo {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	cert := cs.PeerCertificates[0]
	info := &TLSInfo{
		Version:  tlsVersionName(cs.Version),
		Cipher:   tls.CipherSuiteName(cs.CipherSuite),
		Subject:  rdnMap(cert.Subject),
		Issuer:   rdnMap(cert.Issuer),
		NotAfter: cert.NotAfter.UTC().Format("Jan 02 15:04:05 2006 GMT"),
		SHA256:   hex.EncodeToString(sum256(cert.Raw)),
		DERLen:   len(cert.Raw),
	}
	return info
}

func sum256(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

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

// oidNames 把 x509 的 OID 映射到 Python ssl 证书字典用的名字。
//
// 用 asn1.ObjectIdentifier 构造而不是写点分字符串：这样常量是代码而不是数据，
// 不会被任何「看起来像 IP/OID 的文本」的清洗规则动到。
var oidNames = func() map[string]string {
	type pair struct {
		oid  asn1.ObjectIdentifier
		name string
	}
	pairs := []pair{
		{asn1.ObjectIdentifier{2, 5, 4, 3}, "commonName"},
		{asn1.ObjectIdentifier{2, 5, 4, 4}, "surname"},
		{asn1.ObjectIdentifier{2, 5, 4, 5}, "serialNumber"},
		{asn1.ObjectIdentifier{2, 5, 4, 6}, "countryName"},
		{asn1.ObjectIdentifier{2, 5, 4, 7}, "localityName"},
		{asn1.ObjectIdentifier{2, 5, 4, 8}, "stateOrProvinceName"},
		{asn1.ObjectIdentifier{2, 5, 4, 10}, "organizationName"},
		{asn1.ObjectIdentifier{2, 5, 4, 11}, "organizationalUnitName"},
		{asn1.ObjectIdentifier{2, 5, 4, 42}, "givenName"},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "emailAddress"},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 2}, "unstructuredName"},
		{asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, "domainComponent"},
		{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}, "jurisdictionCountryName"},
	}
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p.oid.String()] = p.name
	}
	return m
}()

// rdnMap 把 DN 展平成 map（与 Python dict(cert["subject"]) 一致：同名后者覆盖前者）
func rdnMap(name pkix.Name) map[string]string {
	out := map[string]string{}
	for _, rdn := range name.ToRDNSequence() {
		for _, atv := range rdn {
			key := atv.Type.String()
			if n, ok := oidNames[key]; ok {
				key = n
			}
			out[key] = fmt.Sprint(atv.Value)
		}
	}
	return out
}

// legacyCipherSuites 对应 OpenSSL 的 "DEFAULT:@SECLEVEL=0"：
// 标准套件 + 不安全套件（RC4/3DES/CBC/RSA 密钥交换）全开，专为老服务端。
func legacyCipherSuites() []uint16 {
	suites := tls.CipherSuites()
	ids := make([]uint16, 0, len(suites)+16)
	for _, s := range suites {
		if len(s.SupportedVersions) == 1 && s.SupportedVersions[0] == tls.VersionTLS13 {
			continue // TLS 1.3 套件不接受外部配置
		}
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// deadlineReader 每次读前刷新读超时，复刻 Python socket 超时的「每次操作」语义
type deadlineReader struct {
	c net.Conn
	d time.Duration
}

func (r *deadlineReader) Read(p []byte) (int, error) {
	if r.d > 0 {
		_ = r.c.SetReadDeadline(time.Now().Add(r.d)) // 设不上只会退化成无超时，不该中断请求
	}
	return r.c.Read(p)
}

// ---------------------------------------------------------------- 单跳请求

// exchange 建立连接、发字节、收响应。req 已就绪，r.URL/r.RawRequest 由调用方预置。
func (r *Response) exchange(scheme, host string, port int, req []byte, method string, timeout time.Duration, verify bool) {
	if r.HTTPVersion == "" {
		r.HTTPVersion = "1.1"
	}
	t0 := time.Now()
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close() // 关闭失败不影响结论（连接已不可用）
		}
		r.Elapsed = time.Since(t0)
	}()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		r.Err = errors.New(errText(err))
		return
	}
	conn = c
	r.Peer = conn.RemoteAddr().String()
	if scheme == "https" {
		cfg := &tls.Config{
			InsecureSkipVerify: !verify, // 渗透常态：不校验证书，但记录指纹
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
			CipherSuites:       legacyCipherSuites(),
		}
		tc := tls.Client(conn, cfg)
		_ = tc.SetDeadline(time.Now().Add(timeout))
		if err := tc.Handshake(); err != nil {
			r.Err = errors.New(errText(err))
			return
		}
		_ = tc.SetDeadline(time.Time{})
		conn = tc
		r.TLS = tlsInfo(tc.ConnectionState())
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(req); err != nil {
		r.Err = errors.New(errText(err))
		return
	}
	br := bufio.NewReaderSize(&deadlineReader{c: conn, d: timeout}, 4096)
	rawHead, statusLine, hdrs := readHeaders(br)
	if statusLine == "" {
		r.Err = errors.New("ConnectionError: 空响应（服务端未返回状态行）")
		return
	}
	parts := splitFieldsN(statusLine, 3)
	if len(parts) > 0 {
		r.HTTPVersion = strings.Replace(parts[0], "HTTP/", "", 1)
	}
	if len(parts) > 1 {
		if n, ok := atoiDigits(parts[1]); ok {
			r.Status = n
		}
	}
	if len(parts) > 2 {
		// Python 的 split(None, 2) 只切两刀，reason 保留中间的空格
		r.Reason = parts[2]
	}
	r.Headers = hdrs
	res := readBody(br, hdrs, method)
	r.RawResponse = append(append([]byte{}, rawHead...), res.tail...)
	r.Body = decodeBody(res.body, hdrs)
	r.Truncated = res.truncated
}

// once 单跳请求，不做重定向。对应 Python _once。
func once(rawURL, method string, headers []Header, body []byte, timeout time.Duration, verify bool) *Response {
	r := &Response{URL: rawURL, HTTPVersion: "1.1"}
	p, err := url.Parse(rawURL)
	if err != nil {
		r.Err = errors.New(errText(err))
		return r
	}
	scheme := strings.ToLower(p.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := p.Hostname()
	port := 443
	if scheme != "https" {
		port = 80
	}
	if ps := p.Port(); ps != "" {
		if n, e := strconv.Atoi(ps); e == nil {
			port = n
		}
	}
	path := p.EscapedPath()
	if path == "" {
		path = "/"
	}
	if p.RawQuery != "" {
		path += "?" + p.RawQuery
	}
	hdrs := mergeHeaders(headers)
	// Python 用 p.netloc；这里用 p.Host（不带 userinfo —— 带 userinfo 的 URL 不该把
	// 凭据塞进 Host 头，那是个 bug 而不是特性）
	r.RawRequest = buildRequest(method, path, hdrs, body, p.Host)
	r.exchange(scheme, host, port, r.RawRequest, method, timeout, verify)
	return r
}

// ---------------------------------------------------------------- 公开入口

// Opts 请求选项。零值即 Python 的默认参数：
// Method="GET"、Timeout=10s、跟随重定向、不校验证书。
//
// Python 的 allow_redirects=True 在 Go 里用反义的 NoRedirect 表达
// （零值必须是「默认行为」，否则每次调用都得显式写一遍）。
type Opts struct {
	Method       string
	Headers      []Header
	Body         []byte
	Timeout      time.Duration
	NoRedirect   bool // Python allow_redirects=False
	MaxRedirects int
	Verify       bool // Python verify=True（默认 false）
}

func (o Opts) normalized() Opts {
	if o.Method == "" {
		o.Method = "GET"
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.MaxRedirects <= 0 {
		o.MaxRedirects = MaxRedirects
	}
	return o
}

// Request 带重定向链的请求。返回最终 Response，链在 .History 里。
func Request(rawURL string, o Opts) *Response {
	o = o.normalized()
	u := NormURL(rawURL)
	method := o.Method
	body := o.Body
	var hist []*Response
	cur := u
	for i := 0; i <= o.MaxRedirects; i++ {
		r := once(cur, method, o.Headers, body, o.Timeout, o.Verify)
		r.History = snapshot(hist)
		if o.NoRedirect || !isRedirect(r.Status) {
			return r
		}
		loc := r.Header("location")
		if loc == "" {
			return r
		}
		hist = append(hist, r)
		nxt := resolveRef(cur, loc)
		// 303 / 302 对 POST 降级为 GET（浏览器行为）
		if (r.Status == 302 || r.Status == 303) &&
			!strings.EqualFold(method, "GET") && !strings.EqualFold(method, "HEAD") {
			method, body = "GET", nil
		}
		cur = NormURL(nxt)
	}
	r := once(cur, method, o.Headers, body, o.Timeout, o.Verify)
	r.History = snapshot(hist)
	if r.Err == nil {
		r.Err = errors.New("超过最大重定向次数")
	}
	return r
}

// snapshot 拷贝重定向链。
// Python 里每跳的 .history 都指向同一个 list（后面 append 会一起变长），
// 这里取快照 —— 语义更干净，报告里「第 N 跳之前的历史」才是真历史。
func snapshot(hist []*Response) []*Response {
	if len(hist) == 0 {
		return nil
	}
	out := make([]*Response, len(hist))
	copy(out, hist)
	return out
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// Get 发 GET
func Get(rawURL string, o Opts) *Response {
	o.Method = "GET"
	return Request(rawURL, o)
}

// Head 发 HEAD
func Head(rawURL string, o Opts) *Response {
	o.Method = "HEAD"
	return Request(rawURL, o)
}

// splitFieldsN 复刻 Python 的 s.split(None, n)：按空白run切，最多 n 段，
// 最后一段保留内部空白。
func splitFieldsN(s string, n int) []string {
	if n <= 0 {
		return nil
	}
	var out []string
	i := 0
	for len(out) < n-1 {
		for i < len(s) && isSpaceByte(s[i]) {
			i++
		}
		if i >= len(s) {
			return out
		}
		j := i
		for j < len(s) && !isSpaceByte(s[j]) {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	for i < len(s) && isSpaceByte(s[i]) {
		i++
	}
	if i < len(s) {
		out = append(out, s[i:])
	}
	return out
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

// atoiDigits 对齐 Python 的 str.isdigit() 判定（只认 0-9，不收正负号）
func atoiDigits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

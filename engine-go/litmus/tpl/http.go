package tpl

// http.go — httpc.py 里 tpl.py 真正用到的那一层（纯 net 标准库，无第三方）。
//
// 保留原版的几个硬要求：
//   - 原始报文双向留存（raw_request / raw_response），part=header / part=raw
//     的 matcher 直接吃线上字节；
//   - 容忍畸形响应：裸 LF、无 Content-Length、HTTP/1.0、坏 header 行；
//   - 默认不校验证书（渗透场景常态），Connection: close 逐请求新建连接；
//   - 重定向链语义与 Python 一致（302/303 把非 GET/HEAD 降级成 GET）。

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	maxRedirects = 10
	readChunk    = 65536
	maxHeader    = 262144
	maxBodyNoCL  = 8 * 1024 * 1024
)

// Header 保序、可重复的响应头。
type Header struct {
	Name  string // 已小写
	Value string
}

// Response 一次请求（含重定向链）的完整结果。
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
	HTTPVersion string
	Peer        string
}

func newResponse() *Response { return &Response{HTTPVersion: "1.1"} }

// Header 返回首个同名头的值（大小写不敏感）。
func (r *Response) Header(name string) (string, bool) {
	n := strings.ToLower(name)
	for _, h := range r.Headers {
		if h.Name == n {
			return h.Value, true
		}
	}
	return "", false
}

func (r *Response) headerOr(name, def string) string {
	if v, ok := r.Header(name); ok {
		return v
	}
	return def
}

// HeaderBytes 原始响应头字节（状态行 + headers，不含结尾空行）。
func (r *Response) HeaderBytes() []byte {
	raw := r.RawResponse
	if len(raw) > 0 {
		if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
			return raw[:idx]
		}
		if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
			return raw[:idx]
		}
		return raw
	}
	head := []string{strings.TrimSpace("HTTP/" + r.HTTPVersion + " " + strconv.Itoa(r.Status) + " " + r.Reason)}
	for _, h := range r.Headers {
		head = append(head, h.Name+": "+h.Value)
	}
	return latin1Encode(strings.Join(head, "\r\n"))
}

// Ctx 构造 nuclei DSL 上下文（变量名对齐 nuclei）。
func (r *Response) Ctx() map[string]any {
	body := r.Body
	hb := r.HeaderBytes()
	all := make([]byte, 0, len(hb)+2+len(body))
	all = append(all, hb...)
	all = append(all, '\r', '\n')
	all = append(all, body...)
	p := splitURL(r.URL)
	host, scheme, path := p.Netloc, p.Scheme, "/"
	if p.Path != "" {
		path = p.Path
	}
	return map[string]any{
		"status_code":    int64(r.Status),
		"body":           utf8DecodeReplace(body),
		"header":         latin1Decode(hb),
		"all":            utf8DecodeReplace(all),
		"raw":            latin1Decode(r.RawResponse),
		"content_length": int64(len(body)),
		"duration":       math.Round(r.Elapsed.Seconds()*1e4) / 1e4,
		"host":           host,
		"scheme":         scheme,
		"path":           path,
		"content_type":   r.headerOr("content-type", ""),
		"location":       r.headerOr("location", ""),
		"server":         r.headerOr("server", ""),
	}
}

// ---------------------------------------------------------------- URL 工具

type urlParts struct {
	Scheme, Netloc, Path, Query, Fragment string
}

// splitURL 复刻 urllib.parse.urlsplit 的常用行为。
func splitURL(raw string) urlParts {
	var p urlParts
	if k := strings.IndexByte(raw, '#'); k >= 0 {
		p.Fragment = raw[k+1:]
		raw = raw[:k]
	}
	if k := strings.IndexByte(raw, '?'); k >= 0 {
		p.Query = raw[k+1:]
		raw = raw[:k]
	}
	if i := schemeEnd(raw); i > 0 {
		p.Scheme = strings.ToLower(raw[:i])
		raw = raw[i+1:]
	}
	if strings.HasPrefix(raw, "//") {
		rest := raw[2:]
		k := strings.IndexByte(rest, '/')
		if k < 0 {
			k = len(rest)
		}
		p.Netloc = rest[:k]
		raw = rest[k:]
	}
	p.Path = raw
	return p
}

func schemeEnd(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':':
			return i
		case c == '/' || c == '?' || c == '#':
			return -1
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9', c == '+' || c == '-' || c == '.':
			if i == 0 {
				return -1
			}
		default:
			return -1
		}
	}
	return -1
}

// hostname 复刻 urlsplit().hostname（去 userinfo、去 v6 方括号、转小写）。
func (p urlParts) hostname() string {
	h := p.Netloc
	if k := strings.LastIndexByte(h, '@'); k >= 0 {
		h = h[k+1:]
	}
	if strings.HasPrefix(h, "[") {
		if k := strings.IndexByte(h, ']'); k >= 0 {
			return strings.ToLower(h[1:k])
		}
	}
	if k := strings.LastIndexByte(h, ':'); k >= 0 {
		h = h[:k]
	}
	return strings.ToLower(h)
}

// portOf 复刻 urlsplit().port：缺省返回 def。
func (p urlParts) portOf(def int) int {
	h := p.Netloc
	if k := strings.LastIndexByte(h, '@'); k >= 0 {
		h = h[k+1:]
	}
	if strings.HasPrefix(h, "[") {
		if k := strings.IndexByte(h, ']'); k >= 0 {
			rest := h[k+1:]
			if strings.HasPrefix(rest, ":") {
				if n, err := strconv.Atoi(rest[1:]); err == nil {
					return n
				}
			}
			return def
		}
	}
	if k := strings.LastIndexByte(h, ':'); k >= 0 {
		if n, err := strconv.Atoi(h[k+1:]); err == nil {
			return n
		}
	}
	return def
}

// NormalizeURL 复刻 httpc.norm_url：补 scheme、补路径、去 fragment。
func NormalizeURL(u string) string {
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
	p := splitURL(u)
	scheme := p.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := p.Path
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + p.Netloc + path
	if p.Query != "" {
		out += "?" + p.Query
	}
	return out
}

// BuildURL 复刻 httpc.build_url(base, path) 的双参形态：
// 子路径本身是绝对 URL 时直接用，否则套用 base 的 scheme/host/port。
func BuildURL(base, sub string) string {
	p := splitURL(NormalizeURL(base))
	if strings.HasPrefix(sub, "http://") || strings.HasPrefix(sub, "https://") {
		return NormalizeURL(sub)
	}
	if !strings.HasPrefix(sub, "/") {
		sub = "/" + sub
	}
	scheme := p.Scheme
	if scheme == "" {
		scheme = "http"
	}
	def := 80
	if scheme == "https" {
		def = 443
	}
	hostpart := p.hostname()
	if hostpart == "" {
		hostpart = p.Netloc
	}
	if cur := p.portOf(def); cur != def {
		hostpart = hostpart + ":" + strconv.Itoa(cur)
	}
	return scheme + "://" + hostpart + sub
}

// joinURL 对应 urljoin（重定向用），语义交给 net/url。
func joinURL(base, ref string) string {
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

// ---------------------------------------------------------------- 连接池

// Pool 复刻 httpc.Pool 里模板引擎用到的部分：超时、证书校验开关、限速。
type Pool struct {
	Timeout time.Duration
	Verify  bool
	Rate    float64

	mu       sync.Mutex
	nextSlot time.Time
}

// NewPool 创建请求池。
func NewPool(timeout time.Duration) *Pool {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &Pool{Timeout: timeout}
}

func (p *Pool) throttle() {
	if p.Rate <= 0 {
		return
	}
	now := time.Now()
	p.mu.Lock()
	if p.nextSlot.Before(now) {
		p.nextSlot = now
	}
	wait := p.nextSlot.Sub(now)
	p.nextSlot = p.nextSlot.Add(time.Duration(float64(time.Second) / p.Rate))
	p.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

// Request 带重定向链的请求。返回最终 Response，链在 History 里。
func (p *Pool) Request(method, rawURL string, headers map[string]string, body []byte, allowRedirects bool, maxRedir int) *Response {
	p.throttle()
	timeout := p.Timeout
	cur := NormalizeURL(rawURL)
	var hist []*Response
	for i := 0; i <= maxRedir; i++ {
		r := p.once(cur, method, headers, body, timeout)
		r.History = hist
		if !allowRedirects || !isRedirect(r.Status) {
			return r
		}
		loc, ok := r.Header("location")
		if !ok || loc == "" {
			return r
		}
		hist = append(hist, r)
		nxt := joinURL(cur, loc)
		if (r.Status == 302 || r.Status == 303) && strings.ToUpper(method) != "GET" && strings.ToUpper(method) != "HEAD" {
			method, body = "GET", nil
		}
		cur = NormalizeURL(nxt)
	}
	r := p.once(cur, method, headers, body, timeout)
	r.History = hist
	if r.Err == nil {
		r.Err = fmt.Errorf("超过最大重定向次数")
	}
	return r
}

func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// RawExchange 把一段已经拼好的原始请求逐字节发出去（raw 模板用）。
func (p *Pool) RawExchange(target string, data []byte, timeout time.Duration) *Response {
	p.throttle()
	if timeout <= 0 {
		timeout = p.Timeout
	}
	r := newResponse()
	t := splitURL(NormalizeURL(target))
	scheme := t.Scheme
	if scheme == "" {
		scheme = "http"
	}
	port := t.portOf(portDefault(scheme))
	host := t.hostname()
	r.URL = scheme + "://" + t.Netloc + "/"
	r.RawRequest = data
	start := time.Now()
	conn, err := p.dial(host, port, timeout)
	if err != nil {
		r.Err = err
		r.Elapsed = time.Since(start)
		return r
	}
	defer conn.Close()
	if scheme == "https" {
		if err := p.tlsHandshake(&conn, host, timeout); err != nil {
			r.Err = err
			r.Elapsed = time.Since(start)
			return r
		}
	}
	r.Peer = conn.RemoteAddr().String()
	if _, err := conn.Write(data); err != nil {
		r.Err = err
		r.Elapsed = time.Since(start)
		return r
	}
	method := "GET"
	if k := bytes.IndexByte(data, ' '); k > 0 {
		method = strings.ToUpper(string(data[:k]))
	}
	br := bufio.NewReader(conn)
	rawHead, statusLine, hdrs, err := readHeaders(br)
	if err != nil {
		r.Err = err
	}
	if statusLine == "" && r.Err == nil {
		r.Err = fmt.Errorf("空响应（服务端未返回状态行）")
	}
	r.HTTPVersion, r.Status, r.Reason = parseStatusLine(statusLine)
	r.Headers = hdrs
	bodyBytes, tail, berr := readBody(br, hdrs, method)
	if berr != nil && r.Err == nil {
		r.Err = berr
	}
	r.RawResponse = append(append([]byte{}, rawHead...), tail...)
	r.Body = decodeBody(bodyBytes, hdrs)
	r.Elapsed = time.Since(start)
	return r
}

func (p *Pool) dial(host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func (p *Pool) tlsHandshake(conn *net.Conn, host string, timeout time.Duration) error {
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !p.Verify,
		MinVersion:         tls.VersionTLS10,
	}
	c := tls.Client(*conn, cfg)
	if err := c.Handshake(); err != nil {
		return err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	*conn = c
	return nil
}

func portDefault(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// once 单跳请求，不做重定向。
func (p *Pool) once(rawURL, method string, headers map[string]string, body []byte, timeout time.Duration) *Response {
	r := newResponse()
	r.URL = rawURL
	u := splitURL(rawURL)
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := u.hostname()
	port := u.portOf(portDefault(scheme))
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.Query != "" {
		path += "?" + u.Query
	}
	reqBytes := buildRequestBytes(method, path, headers, body, u.Netloc)
	r.RawRequest = reqBytes
	start := time.Now()
	conn, err := p.dial(host, port, timeout)
	if err != nil {
		r.Err = err
		r.Elapsed = time.Since(start)
		return r
	}
	defer conn.Close()
	if scheme == "https" {
		if err := p.tlsHandshake(&conn, host, timeout); err != nil {
			r.Err = err
			r.Elapsed = time.Since(start)
			return r
		}
	}
	r.Peer = conn.RemoteAddr().String()
	if _, err := conn.Write(reqBytes); err != nil {
		r.Err = err
		r.Elapsed = time.Since(start)
		return r
	}
	br := bufio.NewReader(conn)
	rawHead, statusLine, hdrs, _ := readHeaders(br)
	if statusLine == "" {
		r.Err = fmt.Errorf("空响应（服务端未返回状态行）")
		r.Elapsed = time.Since(start)
		return r
	}
	r.HTTPVersion, r.Status, r.Reason = parseStatusLine(statusLine)
	r.Headers = hdrs
	bodyBytes, tail, berr := readBody(br, hdrs, method)
	if berr != nil {
		r.Err = berr
	}
	r.RawResponse = append(append([]byte{}, rawHead...), tail...)
	r.Body = decodeBody(bodyBytes, hdrs)
	r.Elapsed = time.Since(start)
	return r
}

// buildRequestBytes 复刻 httpc._build_request + 默认头归一化逻辑。
func buildRequestBytes(method, target string, headers map[string]string, body []byte, hostHeader string) []byte {
	type kv struct{ k, v string }
	defaults := []struct{ name, val string }{
		{"User-Agent", defaultUA},
		{"Accept", "*/*"},
		{"Accept-Encoding", "gzip, deflate"},
		{"Connection", "close"},
	}
	user := map[string]kv{}
	for k, v := range headers {
		user[strings.ToLower(k)] = kv{k, v}
	}
	var hdrs []kv
	seen := map[string]bool{}
	for _, d := range defaults {
		if u, ok := user[strings.ToLower(d.name)]; ok {
			hdrs = append(hdrs, kv{u.k, u.v})
			seen[strings.ToLower(d.name)] = true
		} else {
			hdrs = append(hdrs, kv{d.name, d.val})
		}
	}
	// 原版按 dict 插入序追加；Go map 无序，排序保证可复现
	var extraKeys []string
	for k := range headers {
		lk := strings.ToLower(k)
		if seen[lk] {
			continue
		}
		isDefault := false
		for _, d := range defaults {
			if strings.ToLower(d.name) == lk {
				isDefault = true
				break
			}
		}
		if !isDefault {
			extraKeys = append(extraKeys, k)
		}
	}
	sortStrings(extraKeys)
	for _, k := range extraKeys {
		hdrs = append(hdrs, kv{k, headers[k]})
	}
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\n")
	if hostHeader != "" {
		b.WriteString("Host: " + hostHeader + "\r\n")
	}
	for _, h := range hdrs {
		b.WriteString(h.k + ": " + h.v + "\r\n")
	}
	b.WriteString("\r\n")
	out := latin1Encode(b.String())
	out = append(out, body...)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func parseStatusLine(line string) (version string, status int, reason string) {
	version = "1.1"
	if line == "" {
		return
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) > 0 {
		version = strings.TrimPrefix(parts[0], "HTTP/")
	}
	if len(parts) > 1 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			status = n
		}
	}
	if len(parts) > 2 {
		reason = parts[2]
	}
	return
}

// readHeaders 读状态行 + header，容忍裸 LF、坏行、无 header。
func readHeaders(br *bufio.Reader) (raw []byte, statusLine string, headers []Header, err error) {
	first, rerr := br.ReadString('\n')
	if first == "" {
		return nil, "", nil, rerr
	}
	raw = append(raw, first...)
	statusLine = strings.TrimSpace(first)
	for {
		line, e := br.ReadString('\n')
		if line == "" {
			break
		}
		raw = append(raw, line...)
		if line == "\r\n" || line == "\n" {
			break
		}
		if len(raw) > maxHeader {
			break
		}
		if e != nil {
			break
		}
	}
	for _, ln := range bytes.Split(raw, []byte("\n"))[1:] {
		ln = bytes.TrimSuffix(ln, []byte("\r"))
		if len(ln) == 0 {
			continue
		}
		k := bytes.IndexByte(ln, ':')
		if k < 0 {
			continue
		}
		headers = append(headers, Header{
			Name:  strings.ToLower(strings.TrimSpace(latin1Decode(ln[:k]))),
			Value: strings.TrimSpace(latin1Decode(ln[k+1:])),
		})
	}
	return raw, statusLine, headers, nil
}

func headerMap(headers []Header) map[string]string {
	m := map[string]string{}
	for _, h := range headers {
		if _, ok := m[h.Name]; !ok {
			m[h.Name] = h.Value
		}
	}
	return m
}

// readBody 按 CL / chunked / 关闭 三种方式收 body。
func readBody(br *bufio.Reader, headers []Header, method string) (body []byte, tail []byte, err error) {
	if strings.ToUpper(method) == "HEAD" {
		return nil, nil, nil
	}
	hl := headerMap(headers)
	if strings.Contains(strings.ToLower(hl["transfer-encoding"]), "chunked") {
		var raw []byte
		var out bytes.Buffer
		for {
			line, e := br.ReadString('\n')
			if line == "" {
				if e != nil {
					break
				}
				break
			}
			raw = append(raw, line...)
			num := strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
			if num == "" {
				num = "0"
			}
			size, perr := strconv.ParseInt(num, 16, 64)
			if perr != nil {
				break
			}
			if size == 0 {
				for {
					t, e2 := br.ReadString('\n')
					raw = append(raw, t...)
					if t == "\r\n" || t == "\n" || t == "" {
						break
					}
					if e2 != nil {
						break
					}
				}
				break
			}
			chunk := make([]byte, size)
			n, _ := io.ReadFull(br, chunk)
			raw = append(raw, chunk[:n]...)
			out.Write(chunk[:n])
			crlf := make([]byte, 2)
			m, _ := io.ReadFull(br, crlf)
			raw = append(raw, crlf[:m]...)
			_ = e
		}
		return out.Bytes(), raw, nil
	}
	if cl, ok := hl["content-length"]; ok {
		if n, e := strconv.Atoi(strings.TrimSpace(cl)); e == nil && n >= 0 {
			data := make([]byte, 0, n)
			remaining := n
			for remaining > 0 {
				want := readChunk
				if remaining < want {
					want = remaining
				}
				buf := make([]byte, want)
				m, _ := io.ReadFull(br, buf)
				data = append(data, buf[:m]...)
				remaining -= m
				if m < want {
					break
				}
			}
			return data, data, nil
		}
	}
	var buf bytes.Buffer
	total := 0
	for total < maxBodyNoCL {
		chunk := make([]byte, readChunk)
		n, e := br.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			total += n
		}
		if e != nil {
			break
		}
	}
	d := buf.Bytes()
	return d, d, nil
}

// decodeBody 处理 gzip / deflate（zlib 或裸 deflate）。
func decodeBody(body []byte, headers []Header) []byte {
	enc := strings.ToLower(headerMap(headers)["content-encoding"])
	if strings.Contains(enc, "gzip") {
		if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			if out, err := io.ReadAll(zr); err == nil {
				return out
			}
		}
		return body
	}
	if strings.Contains(enc, "deflate") {
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			if out, err := io.ReadAll(zr); err == nil {
				return out
			}
		}
		fr := flate.NewReader(bytes.NewReader(body))
		if out, err := io.ReadAll(fr); err == nil {
			return out
		}
	}
	return body
}

// Package exposure 是「云与文件面」暴露检测家族：14 个只读检查项。
//
// 为什么这些检查放在一起：它们的判据都不是「打出了漏洞」，而是「不该被外部
// 看到的东西被看到了」—— 云存储桶能匿名列、云主机元数据端点能直达、前端 JS
// 里躺着 AccessKey、源码映射/工作区/日志文件挂在 Web 根下。这类发现的共同点
// 是**证据本身就是数据**，所以本包比别处多两条硬纪律：
//
//  1. 只读。全部 GET / HEAD / ZK 四字命令。唯一的「写」动作是 SMTP 的 RCPT TO，
//     而且绝不再发 DATA（发了就等于替客户往外发信）。上传点只登记，不试上传。
//     堆转储只读前 1KB 就断连接，绝不整个下载。
//  2. 打码。AK/SK/口令只出前 4 位 + ****，连原始长度都不泄露；Evidence 里
//     不许出现任何一个可用的明文凭据。
//
// 三态纪律与其他家族一致：每个检查项自己报 ok / skip(带原因) / na。
// 「没找到」是 ok，不是失败；「没条件测」必须写清为什么，不许静默略过。
//
// 与相邻包的分工：webcheck 管「路径存在且产品可识别」的常规泄露（.git/.env/
// actuator 索引），本包管需要**二次判定**的：桶要拿 List 结果与对照桶比、
// 元数据要限定视角、密钥要打码、堆转储只能看头部。
package exposure

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// DefaultTimeout 单项探测的默认超时（ctx.Timeout 缺省时用）
const DefaultTimeout = 8 * time.Second

// maxBodySniff 受限读取的默认上限（堆转储头部）
const maxBodySniff = 1024

// timeoutOf 取本次探测超时
func timeoutOf(c *scan.Ctx) time.Duration {
	if c != nil && c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// probeTimeout 用指定超时发一次请求（元数据端点要短超时，不能各等 8 秒）。
func probeTimeout(c *scan.Ctx, method, u string, hdrs []httpc.Header, d time.Duration) *httpc.Response {
	o := httpc.Opts{Method: method, Headers: hdrs, NoRedirect: true, Timeout: d}
	if c != nil && c.Pool != nil {
		return c.Pool.Request(method, u, o)
	}
	return httpc.Request(u, o)
}

// probe 发一次只读请求（不跟随重定向：我们要看清是哪一跳给了什么）。
func probe(c *scan.Ctx, method, u string, hdrs []httpc.Header) *httpc.Response {
	return probeTimeout(c, method, u, hdrs, timeoutOf(c))
}

// bodyOf 正文按 UTF-8 替换解码（日志/JSON/XML 混合内容一律这么读，不猜编码）
func bodyOf(r *httpc.Response) string {
	if r == nil {
		return ""
	}
	return strings.ToValidUTF8(string(r.Body), "\uFFFD")
}

// headerText 把响应头拼成可扫描文本（桶名可能只出现在 Location / x-oss-* 里）
func headerText(r *httpc.Response) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	for _, h := range r.Headers {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\n")
	}
	return b.String()
}

// baseOf 归一化根 URL（去尾斜杠）
func baseOf(c *scan.Ctx) string {
	if c == nil {
		return ""
	}
	if c.Base != "" {
		return strings.TrimSuffix(c.Base, "/")
	}
	return strings.TrimSuffix(httpc.BuildURL(c.Host, c.Port, c.Scheme, "/"), "/")
}

// urlFor 把路径拼到目标根上
func urlFor(c *scan.Ctx, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseOf(c) + path
}

// okN 自报「测了」（没命中也是 ok，reason 写清判据）
func okN(tested int, reason string, fs ...*model.Finding) scan.Result {
	return scan.Result{Findings: fs, State: scan.StateOK, Reason: reason, Tested: tested}
}

// findingSpec 发现项的构造参数（位置参数太多，用结构体防串位）
type findingSpec struct {
	Check, Name, Severity, Level, Category string
	Target, Evidence, Repro, Impact, Fix   string
	Confidence                             string
	Extra                                  map[string]interface{}
}

// newFinding 按 ctx 补全 host/port/scheme，其余字段由检查项自己给
func newFinding(c *scan.Ctx, s findingSpec) *model.Finding {
	host, port, scheme := "", 0, "http"
	if c != nil {
		host, port = c.Host, c.Port
		if c.Scheme != "" {
			scheme = c.Scheme
		}
	}
	target := s.Target
	if target == "" && c != nil {
		target = c.Target
		if target == "" {
			target = c.Base
		}
	}
	return model.NewFinding(s.Check, s.Name, s.Severity, target, model.FindingOpts{
		Host: host, Port: port, Scheme: scheme,
		Category:   orDefault(s.Category, "web"),
		Level:      orDefault(s.Level, "L1"),
		Confidence: s.Confidence, Evidence: s.Evidence, Repro: s.Repro,
		Impact: s.Impact, Fix: s.Fix, Extra: s.Extra,
	})
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// clip 截断加省略号（按字符，避免把多字节字符切坏）
func clip(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n]) + "…"
}

// headN 取前 n 个字符
func headN(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// firstLine 首个非空行（证据里放完整响应没意义，放能对得上的一行）
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.TrimSpace(ln) != "" {
			return ln
		}
	}
	return ""
}

// randToken 随机串（对照桶名 / 随机路径）
func randToken(n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[rand.Intn(len(cs))]
	}
	return string(b)
}

// ---------------------------------------------------------------- 预算

// budget 单项检查的探测次数上限。防的是「目标自己挂了个桶的索引页，
// 一次抽出 60 个桶名，然后我们真的去打了 60 次」。
type budget struct {
	used, max int
}

func newBudget(c *scan.Ctx) *budget {
	max := 400
	if c != nil {
		max = c.ProbeBudget()
	}
	return &budget{max: max}
}

func (b *budget) take() bool {
	if b.used >= b.max {
		return false
	}
	b.used++
	return true
}

// ---------------------------------------------------------------- 打码

// maskSecret 只保留前 4 位，其余一律四个星号。
//
// 星号数量固定为 4：连「密钥有多长」都不给。报告是要交出去的，
// 交付物里出现可用凭据等于二次泄露。
func maskSecret(v string) string {
	if len(v) <= 4 {
		return "****"
	}
	return v[:4] + "****"
}

// maskAll 把文本里出现过的敏感值逐个替换成打码版
func maskAll(text string, values []string) string {
	for _, v := range values {
		if len(v) < 4 {
			continue // 太短的值不做全局替换，否则会把正常文本打碎
		}
		text = strings.ReplaceAll(text, v, maskSecret(v))
	}
	return text
}

// ---------------------------------------------------------------- 拨号接缝

// dialHook 拨号入口。变量而非直接调用 net.Dialer 的原因：
// 单测要把「逻辑端口 25/2181」重定向到本地临时端口（没人能用非 root 绑 25），
// 受限网络里也可能要走固定出口。生产路径就是 net.Dialer。
var dialHook = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.Dial(network, addr)
}

// ---------------------------------------------------------------- 受限读取

// sniffResult 裸连接读到的最小响应（状态行 + 头 + 前若干字节）
type sniffResult struct {
	Status  int
	Headers map[string]string
	Body    []byte
	Err     error
}

// rawSniff 发一个 GET，读到头 + 最多 maxBody 字节就立刻断开。
//
// 这个函数存在的唯一理由：heapdump 检查。服务端完全可能忽略 Range 头，
// 用常规 HTTP 客户端就会把整个堆转储（几百 MB 到几 GB）拉进内存 ——
// 那是拿目标的内存换我们自己的内存，绝不允许。这里读完 1KB 就关连接，
// 对端怎么回都不会整个下载。
func rawSniff(rawURL string, hdrs []httpc.Header, maxBody int, timeout time.Duration) sniffResult {
	if maxBody <= 0 {
		maxBody = maxBodySniff
	}
	u, err := url.Parse(httpc.NormURL(rawURL))
	if err != nil || u.Host == "" {
		return sniffResult{Err: fmt.Errorf("非法 URL: %s", rawURL)}
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := u.Hostname()
	port := 80
	if scheme == "https" {
		port = 443
	}
	if ps := u.Port(); ps != "" {
		if n, e := strconv.Atoi(ps); e == nil {
			port = n
		}
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	conn, err := dialHook("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return sniffResult{Err: err}
	}
	defer func() { _ = conn.Close() }() // 提前关连接就是本函数的核心语义
	if scheme == "https" {
		tc := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true, // 渗透常态，与 httpc 一致
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
		})
		_ = tc.SetDeadline(time.Now().Add(timeout))
		if err := tc.Handshake(); err != nil {
			return sniffResult{Err: err}
		}
		conn = tc
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&b, "User-Agent: %s\r\n", httpc.DefaultUA)
	b.WriteString("Accept: */*\r\nAccept-Encoding: identity\r\n")
	for _, h := range hdrs {
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, h.Value)
	}
	b.WriteString("Connection: close\r\n\r\n")

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(b.Bytes()); err != nil {
		return sniffResult{Err: err}
	}

	br := bufio.NewReaderSize(conn, 4096)
	statusLine, err := br.ReadString('\n')
	if err != nil && strings.TrimSpace(statusLine) == "" {
		return sniffResult{Err: err}
	}
	res := sniffResult{Headers: map[string]string{}}
	if parts := strings.Fields(statusLine); len(parts) >= 2 {
		if n, e := strconv.Atoi(parts[1]); e == nil {
			res.Status = n
		}
	}
	for i := 0; i < 128; i++ {
		line, err := br.ReadString('\n')
		t := strings.TrimRight(line, "\r\n")
		if t == "" {
			break
		}
		if k := strings.IndexByte(t, ':'); k > 0 {
			res.Headers[strings.ToLower(strings.TrimSpace(t[:k]))] = strings.TrimSpace(t[k+1:])
		}
		if err != nil {
			break
		}
	}
	res.Body = readSniffBody(br, res.Headers, maxBody)
	return res
}

// readSniffBody 只读前 maxBody 字节；chunked 时只解第一个块（够判魔数了）。
func readSniffBody(br *bufio.Reader, hdrs map[string]string, maxBody int) []byte {
	limit := maxBody
	if cl := hdrs["content-length"]; cl != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(cl)); err == nil && n >= 0 && n < limit {
			limit = n
		}
	}
	if strings.Contains(strings.ToLower(hdrs["transfer-encoding"]), "chunked") {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil
		}
		sizeStr := strings.TrimSpace(strings.SplitN(strings.TrimSpace(line), ";", 2)[0])
		n, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil || n <= 0 {
			return nil
		}
		if int(n) < limit {
			limit = int(n)
		}
	}
	if limit <= 0 {
		return nil
	}
	buf := make([]byte, limit)
	n, _ := io.ReadFull(br, buf) // 读不满是正常的：对端可能只给这么多，或读超时
	return buf[:n]
}

// ---------------------------------------------------------------- 执行入口

// Run 对一个扫描上下文跑本家族全部检查项，返回发现与三态覆盖记录。
//
// 检查项 panic 会被兜成 state=skip（理由写明「结果不计入结论」），
// 绝不让一条崩掉的检查在覆盖表上显示成 ok。
func Run(ctx *scan.Ctx) ([]*model.Finding, []*model.Coverage) {
	checks := scan.Family("exposure")
	target := ""
	if ctx != nil {
		target = ctx.Target
		if target == "" {
			target = ctx.Base
		}
	}
	var fs []*model.Finding
	covs := make([]*model.Coverage, 0, len(checks))
	for _, ch := range checks {
		res := runOne(ch, ctx)
		state, reason := res.State, res.Reason
		if state == "" {
			state, reason = scan.StateSkip, "检查项未自报三态（实现缺陷）"
		}
		covs = append(covs, model.NewCoverage(target, coverCategory(ch.Name),
			ch.Name, state, reason, res.Tested))
		fs = append(fs, res.Findings...)
	}
	return fs, covs
}

// coverCategory 覆盖表分类：TCP 协议面归 host，其余归 web
func coverCategory(name string) string {
	switch name {
	case "exposure/zookeeper-unauth", "exposure/smtp-open-relay", "exposure/oss-metadata":
		return "host"
	}
	return "web"
}

// guard 注册时包一层 panic 兜底。
//
// engine 直接调 Check.Run（不经 exposure.Run），一个检查项崩掉会带走整轮扫描。
// 兜成 skip 而不是 ok：崩了就是没测出来，不能让覆盖表显示成「没问题」。
func guard(name string, fn func(*scan.Ctx) scan.Result) func(*scan.Ctx) scan.Result {
	return func(c *scan.Ctx) (res scan.Result) {
		defer func() {
			if rec := recover(); rec != nil {
				res = scan.Skip(fmt.Sprintf("检查项 %s 异常（结果不计入结论）: %v", name, rec))
			}
		}()
		return fn(c)
	}
}

// runOne 跑单个检查项，兜住 panic
func runOne(ch scan.Check, ctx *scan.Ctx) (res scan.Result) {
	defer func() {
		if rec := recover(); rec != nil {
			res = scan.Skip(fmt.Sprintf("检查项异常（结果不计入结论）: %v", rec))
		}
	}()
	return ch.Run(ctx)
}

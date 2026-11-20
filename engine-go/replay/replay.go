// Package replay：把「一次精确指定的 HTTP 请求」做成可复验的产物。
//
// 为什么单独一个包：Python 侧（vc/）被 tools/check_offline.py 禁止自己发
// HTTP 请求，所有外联必须由引擎子进程完成。三层复验流水线要的不是「再探一遍」，
// 而是「按我给的方法/头/体发一次，把响应原样带回来」——所以这里不做路径枚举、
// 不做软 404 基线、不做指纹识别，只做一件事：发出去，把
// status/头/体/耗时/摘要落成 <out>/replay.json。
//
// 边界（有意为之）：
//   - 不做目标范围判定：授权范围由调用方（流水线/CLI 上层）持有，传输层重复
//     加闸只会让合法复验请求被误杀；
//   - 传输层失败不是崩溃：status=0 + error 写人话，产物照写、进程 exit 0——
//     「连不上」本身就是复验结论的一部分（目标下线/端口关闭/被拦）；
//   - digest 对全量 body 流式计算（内存只留前 4096 字节给 body 字段），
//     大响应不会把内存打爆，摘要仍是全量字节的 sha256 前 16 位；
//   - 不自动把 --data 改写成 POST：精确复验里方法是被验证的变量之一，
//     自动改写会让「GET 带体」这类被测行为消失。
package replay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kur1sulab/kara/engine-go/netutil"
)

const (
	// FileName 产物文件名（<out>/replay.json）。
	FileName = "replay.json"
	// BodyLimit body 字段保留的原始字节上限（超出部分只进 size/digest）。
	BodyLimit = 4096
	// DefaultTimeout 未指定超时时的兜底秒数。
	DefaultTimeout = 10
	// MaxRedirects 跟随重定向的跳数上限（对齐 netutil/urllib 的 10 跳）。
	MaxRedirects = 10
)

// ErrBadArgs 参数层错误（URL 非法 / 协议不支持 / 头格式错 / 超时非正 / 输出目录空）。
// CLI 据此区分退出码：参数错 exit 2，写盘失败 exit 1，传输失败 exit 0。
var ErrBadArgs = errors.New("参数错误")

// Record replay.json 的全部字段。字段顺序即产物里的键序，Python 侧按
// kind 判别产物类型，其余字段逐一对应一次真实响应。
type Record struct {
	Kind      string            `json:"kind"`      // 固定 sweep_replay
	URL       string            `json:"url"`       // 请求 URL（原样）
	FinalURL  string            `json:"final_url"` // 跟随重定向后的落点
	Method    string            `json:"method"`    // 实际使用的方法（大写）
	Status    int               `json:"status"`    // HTTP 状态码；传输失败为 0
	Size      int64             `json:"size"`      // 全量 body 字节数
	Digest    string            `json:"digest"`    // sha256(全量 body) 的 hex 前 16 位
	MS        int64             `json:"ms"`        // 整次请求耗时（毫秒）
	Headers   map[string]string `json:"headers"`   // 键全小写，同键多值 ", " 连接
	Body      string            `json:"body"`      // body 前 4096 字节（UTF-8 安全）
	Redirects int               `json:"redirects"` // 实际跟随的跳数
	Error     string            `json:"error"`     // 传输层错误人话；成功为空串
}

// Path 返回产物路径（<out>/replay.json），供 CLI 打印与调用方取用。
func Path(outDir string) string { return filepath.Join(outDir, FileName) }

// HostOf 从 URL 取 host[:port] 作为默认产物目录名；解析失败回原串
// （目录名清洗交给 CLI 的 MakeOutdir，与其它子命令同一套规则）。
func HostOf(raw string) string {
	u, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// Run 发一次精确请求并把结果写成 <outPath>/replay.json。
//
// 返回 error 只表示「没做成这件事」：参数错（ErrBadArgs，CLI exit 2）或
// 产物写不下去（CLI exit 1）。传输层失败不算 error——status=0 + Error 人话，
// 产物照写，调用方看 JSON 判定。
//
// headers 每项形如 "K: V"；键 Host 特殊处理（改写 req.Host，否则 Go 会忽略
// Header 里的 Host）。未显式给 User-Agent 时补 netutil.DefaultUA（与引擎其它
// 模块一致，且可被 --header 'User-Agent: ...' 覆盖）。
func Run(url, method, data string, headers []string, timeoutSec int, followRedirect bool, outPath string) error {
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("%w: 输出目录为空", ErrBadArgs)
	}
	if timeoutSec <= 0 {
		return fmt.Errorf("%w: --timeout 必须为正整数（秒），收到 %d", ErrBadArgs, timeoutSec)
	}
	u, perr := neturl.Parse(strings.TrimSpace(url))
	if perr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%w: 需要 http/https 绝对 URL，收到 %q", ErrBadArgs, url)
	}

	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	rec := Record{
		Kind: "sweep_replay", URL: url, FinalURL: url, Method: m,
		Headers: map[string]string{},
	}

	// ── 请求头：'K: V' 逐条解析，Host 走 req.Host 旁路 ──
	hdr := http.Header{}
	hostOverride := ""
	for _, raw := range headers {
		k, v, ok := strings.Cut(raw, ":")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return fmt.Errorf("%w: --header 需要 'K: V' 形式，收到 %q", ErrBadArgs, raw)
		}
		v = strings.TrimSpace(v)
		if strings.EqualFold(k, "host") {
			hostOverride = v // Go 的 Header 里写 Host 不生效，必须落到 req.Host
			continue
		}
		hdr.Add(k, v)
	}

	var body io.Reader
	if data != "" {
		body = strings.NewReader(data)
	}
	req, err := http.NewRequest(m, url, body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadArgs, err)
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", netutil.DefaultUA)
	}
	if hostOverride != "" {
		req.Host = hostOverride
	}

	timeout := time.Duration(timeoutSec) * time.Second
	transport := netutil.ProbeTransport() // 探测语义：自签/过期证书放行，且不自动加 Accept-Encoding
	transport.TLSHandshakeTimeout = timeout
	client := &http.Client{Timeout: timeout, Transport: transport}

	followed := 0
	client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
		if !followRedirect || len(via) >= MaxRedirects {
			return http.ErrUseLastResponse // 返回 3xx 响应本身（含超限场景）
		}
		followed++
		return nil
	}

	start := time.Now()
	resp, doErr := client.Do(req)
	if doErr != nil {
		// 传输层失败：status=0、error 人话、产物照写，调用方 exit 0
		rec.MS = time.Since(start).Milliseconds()
		rec.Error = errText(doErr)
		return writeRecord(outPath, rec)
	}
	defer resp.Body.Close()

	// 全量 body 边读边哈希，只在内存里留前 BodyLimit 字节
	h := sha256.New()
	head := &headWriter{limit: BodyLimit}
	n, readErr := io.Copy(io.MultiWriter(h, head), resp.Body)

	rec.Status = resp.StatusCode
	rec.Size = n
	rec.Digest = hex.EncodeToString(h.Sum(nil))[:16]
	rec.Body = sanitizeUTF8(head.buf.Bytes())
	rec.FinalURL = resp.Request.URL.String()
	rec.Redirects = followed
	rec.Headers = flattenHeaders(resp.Header)
	rec.MS = time.Since(start).Milliseconds()
	if readErr != nil { // 头已到手、体读断了：状态保留，错误如实记
		rec.Error = errText(readErr)
	}
	return writeRecord(outPath, rec)
}

// headWriter 只保留前 limit 字节，其余照常「写成功」让 io.Copy 继续流式读完。
type headWriter struct {
	limit int
	buf   bytes.Buffer
}

func (w *headWriter) Write(p []byte) (int, error) {
	if rem := w.limit - w.buf.Len(); rem > 0 {
		if len(p) <= rem {
			w.buf.Write(p)
		} else {
			w.buf.Write(p[:rem])
		}
	}
	return len(p), nil
}

// sanitizeUTF8 把原始字节转成合法 UTF-8：非法字节替换为 U+FFFD，不 panic。
// 4096 字节截断可能切在多字节字符中间，尾部残片同样被替换成一个替换符。
func sanitizeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// flattenHeaders 键全小写、同键多值 ", " 连接（JSON 里一个键只能有一个字符串）。
func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		lk := strings.ToLower(k)
		joined := strings.Join(vs, ", ")
		if prev, ok := out[lk]; ok && prev != "" {
			out[lk] = prev + ", " + joined
			continue
		}
		out[lk] = joined
	}
	return out
}

// errText 剥掉 *url.Error 的 `Get "URL": ` 前缀：错误里不该把 query 上的
// token/api_key 带进产物与日志（与 netutil.errReason 同一口径）。
func errText(err error) string {
	var ue *neturl.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}

// writeRecord 落盘。写不下去才返回 error（CLI 据此 exit 1）。
func writeRecord(outPath string, rec Record) error {
	if err := os.MkdirAll(outPath, 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	// 关掉 HTML 转义：body 里的 < > & 原样保留，与 Python json.dumps 默认口径
	// 一致（否则复验时肉眼/文本 diff 会把 `&` 看成 `\u0026`）。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return fmt.Errorf("序列化 %s 失败: %w", FileName, err)
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n")) // Encode 会补换行，产物不要
	if err := os.WriteFile(Path(outPath), b, 0o644); err != nil {
		return fmt.Errorf("写 %s 失败: %w", FileName, err)
	}
	return nil
}

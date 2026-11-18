package httpc

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pool 带并发上限 + 全局速率限制的请求池（对应 Python 的 class Pool）。
//
// 用法::
//
//	pool := httpc.NewPool(10, 20, 10*time.Second, false)
//	rs := httpc.Map(pool, func(u string) *httpc.Response { return httpc.Get(u, httpc.Opts{}) }, urls)
//
// 与 Python 的差异：Python 的 Pool.map/imap 是实例方法（鸭子类型 fn 任意）；
// Go 的方法不能带类型参数，所以 Map/IMap 做成接收 *Pool 的泛型函数。
// 语义（并发上限、限速、保持输入顺序 / 流式产出）与 Python 一致。
type Pool struct {
	Threads int
	Rate    float64 // 每秒请求数上限，<=0 表示不限速
	Timeout time.Duration
	Verify  bool

	mu       sync.Mutex
	nextSlot time.Time
	closed   bool
}

// NewPool 构造请求池。threads<1 会被抬到 1（与 Python 的 max(1, int(threads)) 一致）。
func NewPool(threads int, rate float64, timeout time.Duration, verify bool) *Pool {
	if threads < 1 {
		threads = 1
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Pool{Threads: threads, Rate: rate, Timeout: timeout, Verify: verify}
}

// DefaultPool 对齐 Python 的 Pool() 默认值（threads=10, rate=0, timeout=10s, verify=False）
func DefaultPool() *Pool { return NewPool(10, 0, DefaultTimeout, false) }

// Close 标记池已关闭（Python 里只置 _closed 标志，不影响在途请求；这里保持一致）
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

// Closed 池是否已关闭
func (p *Pool) Closed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// throttle 全局匀速放行：把「下一个可用时刻」往后推 1/rate 秒。
// 与 Python 的 _throttle 逐行对应（含 next_slot 的漂移修正）。
func (p *Pool) throttle() {
	if p.Rate <= 0 {
		return
	}
	p.mu.Lock()
	now := time.Now()
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

// Request 池版 request：走并发槽位 + 限速。
// 对齐 Python 的 _pool_request：verify 一律取池上的值，timeout 缺省取池上的值。
func (p *Pool) Request(method, rawURL string, o Opts) *Response {
	p.throttle()
	if o.Timeout <= 0 {
		o.Timeout = p.Timeout
	}
	o.Verify = p.Verify
	o.Method = method
	return Request(rawURL, o)
}

// Get 池版 GET
func (p *Pool) Get(rawURL string, o Opts) *Response { return p.Request("GET", rawURL, o) }

// Head 池版 HEAD
func (p *Pool) Head(rawURL string, o Opts) *Response { return p.Request("HEAD", rawURL, o) }

// RawExchange 把一个「已经拼好的原始请求」逐字节发出去（nuclei raw 模板用）。
//
// target 是 URL 字符串（Python 版还接受 urlsplit 的结果，Go 里对应 *url.URL，
// 用 RawExchangeURL）。返回的 Response.RawRequest 就是发出去的字节，证据链完整。
func (p *Pool) RawExchange(target string, data []byte, timeout time.Duration) *Response {
	u, err := url.Parse(NormURL(target))
	if err != nil {
		return &Response{URL: target, RawRequest: data,
			Err: errors.New(errText(err)), HTTPVersion: "1.1"}
	}
	return p.RawExchangeURL(u, data, timeout)
}

// RawExchangeURL 同 RawExchange，但直接收已解析的 URL
func (p *Pool) RawExchangeURL(u *url.URL, data []byte, timeout time.Duration) *Response {
	p.throttle()
	if timeout <= 0 {
		timeout = p.Timeout
	}
	r := &Response{HTTPVersion: "1.1"}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := u.Hostname()
	port := 443
	if scheme != "https" {
		port = 80
	}
	if ps := u.Port(); ps != "" {
		if n, e := strconv.Atoi(ps); e == nil {
			port = n
		}
	}
	netloc := u.Host
	if netloc == "" {
		netloc = host
	}
	r.URL = scheme + "://" + netloc + "/"
	r.RawRequest = data
	// 从请求首行推方法（决定要不要读 body）
	method := "GET"
	if i := strings.IndexByte(string(data), ' '); i > 0 {
		method = strings.ToUpper(latin1String(data[:i]))
	}
	r.exchange(scheme, host, port, data, method, timeout, p.Verify)
	return r
}

// Pair IMap 产出的 (输入项, 结果)
type Pair[T any] struct {
	Item T
	Resp *Response
}

// Map 并发执行 fn(item)，保持输入顺序返回。
//
// 并发上限由信号量（chan struct{}）控制，不许无限制 go func（几千目标会打爆 fd）。
func Map[T any](p *Pool, fn func(T) *Response, items []T) []*Response {
	results := make([]*Response, len(items))
	sem := make(chan struct{}, p.Threads)
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = safeCall(p, fn, items[i])
		}(i)
	}
	wg.Wait()
	return results
}

// IMap 流式产出 (item, result)，用于边扫边落盘。
func IMap[T any](p *Pool, fn func(T) *Response, items []T) <-chan Pair[T] {
	out := make(chan Pair[T], p.Threads)
	sem := make(chan struct{}, p.Threads)
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			out <- Pair[T]{Item: it, Resp: safeCall(p, fn, it)}
		}(it)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// safeCall 对齐 Python _wrap：限速 + 兜住 fn 的 panic，统一落成带 Err 的 Response。
// 网络失败不是 panic（见契约 4.3），这里兜的是调用方自己的 bug，不让它带崩整轮扫描。
func safeCall[T any](p *Pool, fn func(T) *Response, item T) (res *Response) {
	p.throttle()
	defer func() {
		if rec := recover(); rec != nil {
			res = &Response{Err: fmt.Errorf("panic: %v", rec), HTTPVersion: "1.1"}
		}
	}()
	res = fn(item)
	if res == nil {
		res = &Response{Err: errors.New("nil response"), HTTPVersion: "1.1"}
	}
	return res
}

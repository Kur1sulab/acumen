package tpl

// engine.go — 执行引擎（tpl.py 的 1:1 移植）。
//
// 两条执行路径，语义与 nuclei 对齐：
//   - path 列表：逐个请求，任一命中即停；
//   - raw 链：整串按顺序发完，matcher 只判最后一个响应，前一步的
//     internal extractor 抽出的值通过 {{var}} 喂给后一步。

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

// Result 一个模板对一个目标的执行结果。
type Result struct {
	Template     string         `json:"template"`
	Name         string         `json:"name"`
	Severity     string         `json:"severity"`
	Target       string         `json:"target"`
	Matched      bool           `json:"matched"`
	Evidence     []string       `json:"evidence"`
	Extracts     map[string]any `json:"extracts"`
	RequestsMade int            `json:"requests_made"`
	Error        string         `json:"error"`
}

// Map 返回与原版 dict 同形的结构（测试/报告层用）。
func (r *Result) Map() map[string]any {
	var errVal any
	if r.Error != "" {
		errVal = r.Error
	}
	return map[string]any{
		"template":      r.Template,
		"name":          r.Name,
		"severity":      r.Severity,
		"target":        r.Target,
		"matched":       r.Matched,
		"evidence":      r.Evidence,
		"extracts":      r.Extracts,
		"requests_made": int64(r.RequestsMade),
		"error":         errVal,
	}
}

// Engine 把一个模板打到目标上。
type Engine struct {
	Timeout time.Duration
	Pool    *Pool
	Verify  bool
}

// NewEngine 创建引擎；timeout<=0 时用原版默认的 8 秒。
func NewEngine(timeout time.Duration) *Engine {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &Engine{Timeout: timeout, Pool: NewPool(timeout)}
}

// NewEngineWithPool 复用调用方的连接池（限速/证书设置跟着池走）。
func NewEngineWithPool(p *Pool) *Engine {
	if p == nil {
		return NewEngine(0)
	}
	return &Engine{Timeout: p.Timeout, Pool: p, Verify: p.Verify}
}

// Run 执行模板，返回结构化结果（不 panic：所有异常折进 Result.Error）。
func (e *Engine) Run(t *Template, baseURL string) *Result {
	if e.Pool == nil {
		e.Pool = NewPool(e.Timeout)
	}
	res := &Result{
		Template: t.ID,
		Name:     t.Name,
		Severity: t.Severity,
		Target:   baseURL,
		Evidence: []string{},
		Extracts: map[string]any{},
	}
	for _, rspec := range t.Requests {
		hit, ev, exts, n, err := e.runRequest(rspec, baseURL)
		if err != nil {
			// 原版是 `hit, ev, exts, n = self._run_request(...)`，抛异常时这次
			// 调用的 requests_made / evidence 整体丢失，这里保持一致。
			if isUnsupported(err) {
				res.Error = "不支持: " + err.Error()
			} else {
				res.Error = errorLabel(err)
			}
			return res
		}
		res.RequestsMade += n
		res.Evidence = append(res.Evidence, ev...)
		for k, v := range exts {
			res.Extracts[k] = v
		}
		if hit {
			res.Matched = true
			break
		}
	}
	return res
}

// Subst 做 nuclei 变量替换（path 与 raw 共用）。
//
// 坑（原版注释里踩过）：path 分支漏了 {{BaseURL}} 替换，所有模板都会去请求
// `http://host/{{BaseURL}}/actuator/env`，结果全量假阴性。这里两条路径都走它。
func (e *Engine) Subst(text, baseURL string, vars map[string]any) string {
	u := splitURL(NormalizeURL(baseURL))
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	hostport := u.Netloc
	if hostport == "" {
		hostport = u.hostname()
	}
	port := u.portOf(portDefault(scheme))
	base := strings.TrimRight(baseURL, "/")
	path := u.Path
	if path == "" {
		path = "/"
	}
	out := text
	// 顺序与原版一致：标准变量先替换，模板变量最后覆盖不了它们
	pairs := []string{
		"{{BaseURL}}", base,
		"{{RootURL}}", base,
		"{{Hostname}}", hostport,
		"{{Host}}", hostport,
		"{{Port}}", strconv.Itoa(port),
		"{{Scheme}}", scheme,
		"{{Path}}", path,
	}
	for i := 0; i < len(pairs); i += 2 {
		out = strings.ReplaceAll(out, pairs[i], pairs[i+1])
	}
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{{"+k+"}}", pyStr(v))
	}
	return out
}

func (e *Engine) runRequest(rspec *RequestSpec, baseURL string) (bool, []string, map[string]any, int, error) {
	evAll := []string{}
	exts := map[string]any{}
	made := 0

	// ---- raw 链 ----
	if boolOf(rspec.Raw) {
		raws, err := iterate(rspec.Raw)
		if err != nil {
			return false, evAll, exts, made, err
		}
		vars := map[string]any{}
		var last *Response
		for _, raw := range raws {
			resp := e.sendRaw(baseURL, pyStr(raw), vars)
			made++
			last = resp
			e.extractInto(rspec, resp, vars, exts, &evAll)
			if resp.Err != nil {
				break // 链断了，后面的请求发出去也是废的
			}
		}
		if last == nil {
			return false, evAll, exts, made, nil
		}
		ctx := last.Ctx()
		for k, v := range vars {
			ctx[k] = v
		}
		hit, ev, err := EvaluateMatchers(rspec.Matchers, rspec.MatchersCondition, last, ctx)
		if err != nil {
			return false, evAll, exts, made, err
		}
		if last.Err != nil {
			ev = append(ev, "传输错误: "+last.Err.Error())
		}
		return hit, ev, exts, made, nil
	}

	// ---- path 列表 ----
	paths, err := iterate(rspec.Paths)
	if err != nil {
		return false, evAll, exts, made, err
	}
	hitAny := false
	for _, p := range paths {
		url := BuildURL(baseURL, e.Subst(pyStr(p), baseURL, nil))
		resp := e.request(rspec, url)
		made++
		hit, ev, jerr := e.judge(rspec, resp, exts)
		evAll = append(evAll, ev...)
		if jerr != nil {
			return false, evAll, exts, made, jerr
		}
		hitAny = hitAny || hit
		if hit {
			break
		}
	}
	return hitAny, evAll, exts, made, nil
}

// request 发一次普通请求；body 非字符串时复刻原版在拼报文阶段炸掉的 TypeError。
func (e *Engine) request(rspec *RequestSpec, url string) *Response {
	var body []byte
	switch bv := rspec.BodyValue.(type) {
	case nil:
		body = rspec.Body
	case string:
		body = []byte(bv)
	case []byte:
		body = bv
	default:
		// 原版是 `head + (body or b"")`：假值（0/false/空容器）当空 body，
		// 真值非字符串才在拼报文时炸 TypeError。
		if !boolOf(bv) {
			body = nil
			break
		}
		r := newResponse()
		r.URL = url
		r.Err = raiseType("can't concat %s to bytes", pyTypeName(bv))
		return r
	}
	return e.Pool.Request(rspec.Method, url, rspec.Headers, body, rspec.Redirects, rspec.MaxRedirects)
}

// sendRaw 把 raw 请求发出去。HTTP 报文必须是 CRLF；模板里写的是 LF，
// 不归一化的话多请求链会被服务端当成畸形报文。
func (e *Engine) sendRaw(baseURL, raw string, vars map[string]any) *Response {
	text := e.Subst(raw, baseURL, vars)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	data := []byte(text)
	if !bytes.HasSuffix(data, []byte("\r\n\r\n")) {
		if bytes.HasSuffix(data, []byte("\r\n")) {
			data = append(data, '\r', '\n')
		} else {
			data = append(data, '\r', '\n', '\r', '\n')
		}
	}
	return e.Pool.RawExchange(baseURL, data, e.Timeout)
}

// extractInto 跑 extractor：internal 的进 vars（供后续请求替换），
// 其余进 exts（进报告）。extractor 写错只记警告，不否决 matcher 结论。
func (e *Engine) extractInto(rspec *RequestSpec, resp *Response, vars, exts map[string]any, warns *[]string) {
	for _, ex := range rspec.Extractors {
		vals, err := ex.Extract(resp)
		if err != nil {
			if warns != nil {
				if isUnsupported(err) {
					*warns = append(*warns, "extractor 不支持: "+err.Error())
				} else {
					*warns = append(*warns, "extractor 异常: "+err.Error())
				}
			}
			continue
		}
		if len(vals) == 0 {
			continue
		}
		if ex.Internal && boolOf(ex.Name) {
			vars[pyStr(ex.Name)] = vals[0]
		} else if boolOf(ex.Name) {
			key := pyStr(ex.Name)
			if len(vals) == 1 {
				exts[key] = vals[0]
			} else {
				exts[key] = vals
			}
		}
	}
}

func (e *Engine) judge(rspec *RequestSpec, resp *Response, exts map[string]any) (bool, []string, error) {
	ctx := resp.Ctx()
	vars := map[string]any{}
	warns := []string{}
	// 先跑 internal extractor 填充上下文，再判定 matcher
	e.extractInto(rspec, resp, vars, exts, &warns)
	for k, v := range vars {
		ctx[k] = v
	}
	hit, ev, err := EvaluateMatchers(rspec.Matchers, rspec.MatchersCondition, resp, ctx)
	if err != nil {
		return false, nil, err
	}
	ev = append(ev, warns...)
	if resp.Err != nil {
		ev = append(ev, "传输错误: "+resp.Err.Error())
	}
	return hit, ev, nil
}

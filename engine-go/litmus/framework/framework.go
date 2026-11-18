// Package framework 是「框架指纹 + 已知高危配置存在性」检查族。
//
// 两类的纪律不同，代码里也按两条路径实现：
//
//	framework/*-detect                    只回答「这是什么组件」：
//	                                      severity=info/low，Level=L1，
//	                                      Confidence 只到 confirmed（产品独有特征）
//	                                      或 likely（路径/行为形态）
//	framework/shiro-rememberme-key 等     只回答「这个已知风险点在不在这里」：
//	                                      severity=high，Confidence=confirmed，
//	                                      Evidence 必须是真实响应原文
//
// 三条硬约束（违反任何一条，结论就是假的）：
//
//  1. **必须有对照**。每项开跑先 GET 一个随机不存在路径，把状态码、长度、正文 +
//     响应头的小写文本存成基线。产品通用词（spring / struts / nacos / tomcat ...）
//     只有「基线里没有」时才计为命中 —— 否则任何一个写着「我们支持 Spring 迁移」的
//     404 页面都会变成一条假指纹。结构类特征（Set-Cookie 回写、响应头、状态码、
//     路径是否与基线不同）另算，见 distinct / served / setCookieNamed。
//  2. **只做识别，不 exploit**。除 fastjson 的畸形 JSON 之外全部是 GET；fastjson
//     只发 {"@type":"java.lang.AutoType"} 这一个类型名，不含任何 gadget，也不会
//     命中业务实体。rememberMe 只发固定串 bGl0bXVzMi1wcm9iZQ==（base64 的
//     "litmus2-probe"），不是 Java 序列化流，不爆破密钥。全程没有写操作。
//  3. **三态不许塌缩**。发出过有效探测响应 → ok（没命中也是 ok）；
//     全部探测请求网络失败/超时 → skip + 原因原文（超时、拒绝连接都照抄）。
//
// 与 webcheck 的分工：webcheck 的 chk_actuator / chk_nacos / chk_druid 是「暴露面」
// 视角（路径通不通）；本包是做「组件归属 + 已知风险点」判定，带更强的对照逻辑，
// 两者结论可以并存（覆盖表按 Name 分行，不会互相覆盖）。
package framework

import (
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// Family 覆盖表上的家族名。所有检查项都必须用它。
const Family = "framework"

// DefaultTimeout 单项请求默认超时。与 webcheck 的 8s 一致 —— 指纹探测是串行小请求，
// 目标慢的时候不能把整轮拖死。
const DefaultTimeout = 8 * time.Second

// maxEvidence 单条 evidence 的字符上限（与 engine.Sanitize 的 1200 上限配合，
// 这里先自剪一次，避免整页 HTML 进报告）。
const maxEvidence = 1200

// baselineBodyCap 基线文本只留前 32KB 做特征比对。
// 不设上限的话，一个 200MB 的软 404 页面会被完整小写化复制一遍 —— 纯粹是浪费内存。
const baselineBodyCap = 32 << 10

// ---------------------------------------------------------------- 探测上下文

// probe 一次检查的探测器：统一管 URL 拼接、超时、预算、基线、三态计数。
//
// 一个检查一个实例，不跨 goroutine 共享（scan.Ctx 的约定也是单检查单线程），
// 所以 tested / answered 这些计数不需要加锁。
type probe struct {
	ctx     *scan.Ctx
	pool    *httpc.Pool
	base    string
	timeout time.Duration
	budget  int

	tested        int      // 发出的请求总数（含基线）
	probeAnswered int      // 除基线之外拿到状态码的响应数（判 ok/skip 用这个）
	errs          []string // 连接失败原文，最多留 3 条
	downErr       string   // 本轮已被前序检查项判定不可达时的原因原文

	bl *baseline
}

// newProbe 构造探测器。c 为 nil 也安全（单测直接塞空 ctx 时不会 panic）。
func newProbe(c *scan.Ctx) *probe {
	if c == nil {
		c = &scan.Ctx{}
	}
	p := &probe{ctx: c, timeout: DefaultTimeout}
	if c.Timeout > 0 {
		p.timeout = c.Timeout
	}
	p.base = strings.TrimRight(strings.TrimSpace(c.Base), "/")
	if p.base == "" && strings.TrimSpace(c.Host) != "" {
		p.base = httpc.BuildURL(c.Host, c.Port, c.Scheme, "/")
	}
	p.pool = c.Pool
	if p.pool == nil {
		p.pool = httpc.NewPool(2, 0, p.timeout, false)
	}
	p.budget = c.ProbeBudget()
	p.downErr = downReason(p.base)
	return p
}

func (p *probe) url(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return httpc.NormURL(path)
	}
	return httpc.BuildURLJoin(p.base, path)
}

func (p *probe) target() string {
	if p.ctx != nil && strings.TrimSpace(p.ctx.Target) != "" {
		return p.ctx.Target
	}
	return p.base
}

// do 发一个请求。NoRedirect 固定为 true：指纹判定要看第一跳的 Set-Cookie / Location，
// 跟着 302 跑会把 Shiro 的 rememberMe 回写、WebLogic 的 /console 跳转全部丢掉。
func (p *probe) do(method, path string, hdrs []httpc.Header, body []byte) *httpc.Response {
	return p.send(method, path, hdrs, body, false)
}

func (p *probe) send(method, path string, hdrs []httpc.Header, body []byte, control bool) *httpc.Response {
	// 目标在本轮已经被别的检查项判过「连不上/超时」：不再一项项重付超时。
	// 仍然落 skip（不是 ok），原因里带原始错误。
	if p.downErr != "" {
		return &httpc.Response{Err: errors.New("本轮已判定不可达：" + p.downErr)}
	}
	if p.tested >= p.budget {
		return &httpc.Response{Err: fmt.Errorf("探测预算耗尽（MaxProbe=%d）", p.budget)}
	}
	p.tested++
	r := p.pool.Request(method, p.url(path), httpc.Opts{
		Headers:    hdrs,
		Body:       body,
		Timeout:    p.timeout,
		NoRedirect: true,
	})
	if r == nil {
		r = &httpc.Response{Err: errors.New("nil response")}
	}
	if r.Status > 0 && !control {
		p.probeAnswered++
	}
	if r.Err != nil && len(p.errs) < 3 {
		msg := r.Err.Error()
		dup := false
		for _, e := range p.errs {
			if e == msg {
				dup = true
				break
			}
		}
		if !dup {
			p.errs = append(p.errs, msg)
		}
	}
	return r
}

func (p *probe) get(path string) *httpc.Response { return p.do("GET", path, nil, nil) }

func (p *probe) getH(path string, hdrs ...httpc.Header) *httpc.Response {
	return p.do("GET", path, hdrs, nil)
}

// postJSON 只用于 fastjson 的畸形类型名探测；报文本身就是判定依据，不含业务字段。
func (p *probe) postJSON(path, body string) *httpc.Response {
	return p.do("POST", path, []httpc.Header{
		httpc.H("Content-Type", "application/json"),
		httpc.H("Accept", "application/json"),
		// httpc.buildRequest 只写调用方给的 header，不会自动补 Content-Length；
		// 不显式写的话服务端会把 body 当成空（Go/Python 的 HTTP 服务端都如此）。
		httpc.H("Content-Length", fmt.Sprintf("%d", len(body))),
	}, []byte(body))
}

// result 统一三态出口：
//   - 没有一次非基线探测拿到状态码 → skip + 原因（超时/连不上/预算耗尽都照抄）
//   - 其余一律 ok（没命中也是 ok —— 「测了没问题」必须能和「没测」区分开）
func (p *probe) result(fs []*model.Finding) scan.Result {
	if p.probeAnswered == 0 {
		if p.tested >= p.budget && p.budget > 0 {
			return scan.Skip(fmt.Sprintf("探测预算耗尽（MaxProbe=%d），本项未完成", p.budget))
		}
		reason := "未拿到有效探测响应（超时或连接失败）"
		if len(p.errs) > 0 {
			reason += "：" + strings.Join(p.errs, "；")
		} else if p.downErr != "" {
			reason = "本轮已判定目标不可达，未重复探测：" + p.downErr
		}
		return scan.Skip(reason)
	}
	return scan.OK(p.tested, fs...)
}

// ---------------------------------------------------------------- 不可达短路

// downTTL 一个 base 的「不可达」结论最多复用这么久。
//
// 存在理由：engine.runScanFamilies 对每个 Web 端口跑全部注册项；目标如果根本不
// 回 HTTP，14 个检查项会各付一遍超时（按 6.5s 超时算就是好几分钟）。
// 缓存只影响「同一 base 的后续检查项」，且只改 skip 的原因，不改 ok 的判定。
const downTTL = 45 * time.Second

type downMark struct {
	at  time.Time
	err string
}

var downMarks sync.Map // base -> downMark

func markDown(base, errText string) {
	if base == "" || errText == "" {
		return
	}
	downMarks.Store(base, downMark{at: time.Now(), err: errText})
}

func downReason(base string) string {
	v, ok := downMarks.Load(base)
	if !ok {
		return ""
	}
	m := v.(downMark)
	if time.Since(m.at) > downTTL {
		downMarks.Delete(base)
		return ""
	}
	return m.err
}

// ---------------------------------------------------------------- 基线（对照组）

// baseline 随机不存在路径的响应快照 —— 所有「路径存在/特征串命中」判定的对照组。
type baseline struct {
	path   string
	status int
	length int
	sig    string
	low    string // 正文前 32KB + 全部响应头的小写文本
	snip   string // 正文前 200 字符，写证据用
	err    error
}

// control 取基线，只发一次。
func (p *probe) control() *baseline {
	if p.bl != nil {
		return p.bl
	}
	path := "/" + randToken(8) + "/" + randToken(6) + ".litmus-not-exist"
	r := p.send("GET", path, nil, nil, true)
	b := &baseline{path: path}
	if r == nil {
		r = &httpc.Response{Err: errors.New("nil response")}
	}
	b.err = r.Err
	b.status = r.Status
	b.length = len(r.Body)
	b.sig = scan.SigOf(r.Body)
	body := r.Body
	if len(body) > baselineBodyCap {
		body = body[:baselineBodyCap]
	}
	b.low = strings.ToLower(strings.ToValidUTF8(string(body), "\uFFFD") + "\n" + headerText(r))
	b.snip = oneLine(clip(bodyOf(r), 200))
	// 只登记真实请求的失败；p.downErr 非空说明这条 err 是短路生成的，
	// 再登记会把「本轮已判定不可达」前缀一层层套下去。
	if r.Err != nil && p.base != "" && p.downErr == "" {
		markDown(p.base, r.Err.Error())
	}
	p.bl = b
	return b
}

// has 基线里是否出现过该串（大小写不敏感）。
func (b *baseline) has(marker string) bool {
	return b != nil && marker != "" && strings.Contains(b.low, strings.ToLower(marker))
}

// admit 特征串是不是「基线解释不了」的。返回 false 说明这个串在随便一个不存在的
// 路径上也会出现（模板页、WAF 提示页、产品宣传页），不能算命中。
func (p *probe) admit(marker string) bool {
	b := p.control()
	if b.err != nil {
		// 基线没拿到（目标只在这个路径上超时之类），退化成「只信特征串本身」，
		// 并在证据里如实写「无基线可比」。
		return true
	}
	return !b.has(marker)
}

// distinct 响应是否真的跟「不存在的路径」不一样。
//
// 判定顺序：先看状态码，再看正文指纹，最后看长度差（5% 且 ≥48B）。
// 软 404 站点会把路径原样回显，指纹必然不同 —— 靠长度差挡掉。
func (p *probe) distinct(r *httpc.Response) bool {
	if r == nil || r.Err != nil || r.Status == 0 {
		return false
	}
	if r.Status == 404 {
		return false
	}
	b := p.control()
	if b.err != nil {
		return len(r.Body) > 0
	}
	if r.Status != b.status {
		return true
	}
	if scan.SigOf(r.Body) == b.sig {
		return false
	}
	diff := len(r.Body) - b.length
	if diff < 0 {
		diff = -diff
	}
	threshold := b.length / 20
	if threshold < 48 {
		threshold = 48
	}
	return diff >= threshold
}

// served 路径像是真的被服务了：2xx/3xx 且与基线不同。
// 401/403 不算 —— 很多站点对任何未授权路径都回 401，那不叫「这个路径存在」。
func (p *probe) served(r *httpc.Response) bool {
	if r == nil || r.Err != nil {
		return false
	}
	switch r.Status {
	case 200, 201, 202, 204, 301, 302, 303, 307, 308:
		return p.distinct(r)
	}
	return false
}

// controlLine 证据里的对照组一行。
func (p *probe) controlLine() string {
	b := p.control()
	if b.err != nil {
		return fmt.Sprintf("对照：随机路径 %s → 请求失败（%s），本项无基线可比（特征串只按自身判定）",
			b.path, b.err.Error())
	}
	s := fmt.Sprintf("对照：随机路径 %s → %d, %dB, 正文指纹 %s", b.path, b.status, b.length, b.sig[:8])
	if b.has("whitelabel error page") {
		s += "；该基线页面本身含 \"Whitelabel Error Page\"（Spring Boot 默认错误页）"
	}
	return s
}

// ---------------------------------------------------------------- 证据拼装

// line 一条探测记录：方法、路径、状态码、长度、关键响应头。
// 不输出 Set-Cookie 原文（可能是真实会话 ID）—— 需要时由各检查显式挑自己的 cookie 写。
func (p *probe) line(method, path string, r *httpc.Response) string {
	if r == nil {
		return fmt.Sprintf("%s %s → 无响应", method, path)
	}
	if r.Err != nil {
		return fmt.Sprintf("%s %s → 请求失败：%s", method, path, r.Err.Error())
	}
	s := fmt.Sprintf("%s %s → %d, %dB", method, path, r.Status, len(r.Body))
	if ct := r.Header("content-type"); ct != "" {
		s += ", " + clip(oneLine(ct), 60)
	}
	if srv := r.Header("server"); srv != "" {
		s += ", Server: " + clip(oneLine(srv), 60)
	}
	if loc := r.Header("location"); loc != "" {
		s += ", Location: " + clip(oneLine(loc), 120)
	}
	if xp := r.Header("x-powered-by"); xp != "" {
		s += ", X-Powered-By: " + clip(oneLine(xp), 60)
	}
	return s
}

// snippet 响应正文片段（压成一行、脱敏、截断），用于证据。
func (p *probe) snippet(r *httpc.Response, n int) string {
	if r == nil || r.Err != nil {
		return ""
	}
	s := oneLine(bodyOf(r))
	if s == "" {
		return ""
	}
	return clip(maskSecrets(s), n)
}

// whereMarker 特征串出现在哪里。返回 "" 表示没出现。
// 只看正文与响应头，不看状态行 —— 状态行里的 "404 Not Found" 之类的词没有鉴别力。
func whereMarker(r *httpc.Response, marker string) string {
	if r == nil || r.Err != nil || marker == "" {
		return ""
	}
	if containsFold(bodyOf(r), marker) {
		return "正文"
	}
	for _, h := range r.Headers {
		if containsFold(h.Name, marker) {
			return "响应头名"
		}
		if containsFold(h.Value, marker) {
			return "响应头 " + h.Name
		}
	}
	return ""
}

// ---------------------------------------------------------------- 发现构造

// findingSpec 一条发现的全部可变部分。用结构体而不是 12 个位置参数：
// 这个包里每条发现的 check/level/category 都一样，只有下面这些不同。
type findingSpec struct {
	check      string
	name       string
	severity   string
	confidence string
	titleEN    string
	evidence   string
	repro      string
	impact     string
	fix        string
	cvss       string
	path       string
	markers    []string
	extra      map[string]interface{}
}

// finding 构造发现。Level 一律 L1：本包没有任何一项拿到了「真实数据」或「内部权限」，
// 把指纹写成 L2 就是把「看见了」吹成「进去了」。
func (p *probe) finding(spec findingSpec) *model.Finding {
	host, port, scheme := splitBase(p.base)
	extra := map[string]interface{}{}
	for k, v := range spec.extra {
		extra[k] = v
	}
	extra["path"] = spec.path
	extra["markers"] = spec.markers
	if b := p.bl; b != nil {
		ctrl := map[string]interface{}{
			"path": b.path, "status": b.status, "len": b.length, "sig": b.sig,
		}
		if b.err != nil {
			ctrl["error"] = b.err.Error()
		}
		extra["control"] = ctrl
	}
	return model.NewFinding(spec.check, spec.name, spec.severity, p.target(), model.FindingOpts{
		Host: host, Port: port, Scheme: scheme, Category: "web", Level: "L1",
		Confidence: spec.confidence, Evidence: clip(spec.evidence, maxEvidence),
		Repro: spec.repro, Impact: spec.impact, Fix: spec.fix, CVSS: spec.cvss,
		TitleEN: spec.titleEN, Extra: extra,
	})
}

func splitBase(base string) (host string, port int, scheme string) {
	u, err := url.Parse(httpc.NormURL(base))
	if err != nil || u == nil || u.Hostname() == "" {
		return base, 0, ""
	}
	scheme = strings.ToLower(u.Scheme)
	def := 80
	if scheme == "https" {
		def = 443
	}
	port = def
	if ps := u.Port(); ps != "" {
		if n, e := strconv.Atoi(ps); e == nil {
			port = n
		}
	}
	return u.Hostname(), port, scheme
}

// ---------------------------------------------------------------- 响应小工具

const tokenChars = "abcdefghijklmnopqrstuvwxyz0123456789"

func randToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = tokenChars[rand.Intn(len(tokenChars))]
	}
	return string(b)
}

func bodyOf(r *httpc.Response) string {
	if r == nil {
		return ""
	}
	return strings.ToValidUTF8(string(r.Body), "\uFFFD")
}

func headerText(r *httpc.Response) string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	for _, h := range r.Headers {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	return b.String()
}

func containsFold(s, sub string) bool {
	if sub == "" {
		return false
	}
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// oneLine 把多行文本压成一行，证据里每条记录占一行才读得懂。
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func clip(s string, n int) string {
	if n <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// setCookieNamed 取指定名字的 Set-Cookie（前缀匹配，大小写不敏感）。
//
// 合并成一行的 Set-Cookie 会按 "," 切开 —— Expires 里的逗号会误切，
// 但这里只做前缀匹配，切错也只影响后面的片段，不影响首个 cookie 的判定。
func setCookieNamed(r *httpc.Response, name string) []string {
	if r == nil || r.Err != nil {
		return nil
	}
	pref := strings.ToLower(name) + "="
	var out []string
	for _, sc := range r.HeaderAll("set-cookie") {
		for _, part := range strings.Split(sc, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), pref) {
				out = append(out, part)
			}
		}
	}
	return out
}

// headerHasToken 某个响应头里是否含指定子串（大小写不敏感）。
func headerHasToken(r *httpc.Response, header, token string) bool {
	if r == nil || r.Err != nil {
		return false
	}
	return containsFold(r.Header(header), token)
}

// looksJSON 响应像不像 JSON：Content-Type 声明或正文以 { / [ 开头。
func looksJSON(r *httpc.Response) bool {
	if r == nil || r.Err != nil {
		return false
	}
	if containsFold(r.Header("content-type"), "json") {
		return true
	}
	body := strings.TrimSpace(bodyOf(r))
	return strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")
}

// secretFieldRe 证据里必须脱敏的 JSON 字段（Nacos 用户列表会带 password 哈希，网关路由可能带 token）。
var secretFieldRe = regexp.MustCompile(
	`(?i)("(` + "pass" + `word|passwd|secret|accesskey|secretkey|token|accesstoken)"\s*:\s*")[^"]{0,400}(")`)

// maskSecrets 只保留键名，值整体替换成 ***。报告与证据里不出现任何口令/哈希原文。
func maskSecrets(s string) string {
	return secretFieldRe.ReplaceAllString(s, "${1}***${2}")
}

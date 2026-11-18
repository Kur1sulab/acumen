// Package injection 是注入类漏洞的检测家族（12 个检查项，见 register.go）。
//
// 四条纪律，每条都是踩过的坑，改代码前先读完：
//
//  1. **只读**。全部 payload 只做「读」：报错、布尔、延时、回显、读 /etc/passwd、
//     读云元数据。没有 DROP/DELETE/UPDATE/INSERT，命令注入只跑 id，不写文件、
//     不上传、不反弹。目标被扫完不该有任何状态残留。
//
//  2. **对照**。任何一个「命中」都必须先有一份无害基线：payload 响应里的特征串
//     不许在基线里出现过；布尔/时间/NoSQL 这类靠差异判定的，还要成对请求 + 多轮
//     重复，只有每轮结论一致才报。只按「响应里出现某关键字」判定是这类扫描器最
//     常见的误报来源，这个包里没有这种写法。
//
//  3. **三态**。没有可注入参数 → skip 并写清为什么（几个落点、几条参数）；
//     目标不是 Web → na；只有真发出探测且比过对照 → ok。ok 的 reason 也带
//     「N 个参数点 / M 次请求」的计数，报告里能核对强度。
//
//  4. **不拼 shell、不走第三方库、只走 httpc.Pool**（并发与限速由池统一管）。
//
// 注入面目前只有 GET 查询参数：scan.Ctx 只带 URL，不带表单字段名（crawl 抽到了
// <form action> 但不抽字段）。所以「表单字段」不是假装测了，而是不会出现在 ok 的
// 理由里 —— 没有参数的端点一律 skip，理由里写明这一点。
package injection

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// family 覆盖表上的家族名
const family = "injection"

const (
	defaultTimeout      = 10 * time.Second
	maxProbesPerCheck   = 180 // 单项请求硬上限：宁可少测几个点，也不把目标打挂
	maxFindingsPerCheck = 5   // 单项最多报几条，避免同一类问题刷满报告
)

// errBudget 探测预算用尽（不是网络错误，用来让调用方自然走 !ok 分支）
var errBudget = errors.New("探测次数已达上限")

// ---------------------------------------------------------------- 随机标记

// randHex 取 n 字节随机数的 hex（2n 个字符）
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败在正常系统上不会发生；退化成时间派生，
		// 绝不让标记退化成固定串（固定串会让「基线里已有该串」变成常态）。
		ns := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(ns >> (uint(i) * 8 % 64))
		}
	}
	return hex.EncodeToString(b)
}

// marker 生成唯一标记，前缀便于人工在报告里一眼认出是自己的探测
func marker(prefix string) string { return prefix + randHex(5) }

// randInRange 取 [lo, hi) 内的随机整数（SSTI 用它挑操作数，避免撞上页面里的固定数字）
func randInRange(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)))
	if err != nil {
		return lo
	}
	return lo + int(n.Int64())
}

// ---------------------------------------------------------------- 请求形状

// request 一次探测请求的全部要素（不含超时 —— 超时由 prober 决定）
type request struct {
	method  string
	url     string
	body    []byte
	hdrs    []httpc.Header
	follow  bool // 是否跟随重定向
	timeout time.Duration
}

// get 构造 GET 请求，默认跟随重定向（对齐浏览器行为，也让 SPA 的跳转不影响判定）
func get(u string) request { return request{method: "GET", url: u, follow: true} }

// noRedirect 关闭重定向跟随：开放重定向 / CRLF 必须看第一跳的响应头
func (r request) noRedirect() request { r.follow = false; return r }

// withTimeout 覆盖超时（时间盲注必须等比放大，否则会把自己的 sleep 掐断）
func (r request) withTimeout(d time.Duration) request { r.timeout = d; return r }

// postXML 构造 XML POST。
//
// Content-Length 必须显式写：httpc.buildRequest 不自动补长度，缺了它
// 服务端会认为没有 body（实测：cl=0，body 被丢弃）。
func postXML(u string, body []byte) request {
	return request{
		method: "POST",
		url:    u,
		body:   body,
		hdrs: []httpc.Header{
			{Name: "Content-Type", Value: "application/xml"},
			{Name: "Content-Length", Value: strconv.Itoa(len(body))},
			{Name: "Accept", Value: "application/xml, text/xml, */*"},
		},
		follow: true,
	}
}

// ---------------------------------------------------------------- prober

// prober 统一出口：所有探测都从这里走，负责预算计数、超时与快照
type prober struct {
	c          *scan.Ctx
	pool       *httpc.Pool
	timeout    time.Duration
	max        int
	n          int
	blockedMsg string
	host       string // 目标主机名，用于「同域/外域」判断
}

func newProber(c *scan.Ctx, host string) *prober {
	t := c.Timeout
	if t <= 0 {
		t = defaultTimeout
	}
	if t > 60*time.Second {
		t = 60 * time.Second
	}
	max := c.ProbeBudget()
	if max > maxProbesPerCheck {
		max = maxProbesPerCheck
	}
	if max < 1 {
		max = 1
	}
	return &prober{c: c, pool: c.Pool, timeout: t, max: max, host: host}
}

// prepare 三态入口：不是 Web → na；池没装配 → skip；否则给一个 prober。
func prepare(c *scan.Ctx) (*prober, *scan.Result) {
	if c == nil {
		r := scan.NA("无扫描上下文")
		return nil, &r
	}
	base := strings.TrimSpace(c.Base)
	if base == "" {
		r := scan.NA("目标没有 HTTP 根地址，按非 Web 目标处理")
		return nil, &r
	}
	u := httpc.URLSplit(httpc.NormURL(base))
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") {
		r := scan.NA("根地址不是 http(s)：" + base)
		return nil, &r
	}
	if c.Pool == nil {
		r := scan.Skip("未装配 httpc.Pool，注入探测无法发起")
		return nil, &r
	}
	return newProber(c, u.Hostname()), nil
}

// charge 记一次预算消耗；用尽时置 blockedMsg 并返回 false。
func (p *prober) charge() bool {
	if p.n >= p.max {
		if p.blockedMsg == "" {
			p.blockedMsg = fmt.Sprintf("探测次数达上限 %d，其余参数点未测", p.max)
		}
		return false
	}
	p.n++
	return true
}

func (p *prober) doHTTP(r request, to time.Duration, noRedirect bool) *httpc.Response {
	return p.pool.Request(r.method, r.url, httpc.Opts{
		Method:     r.method,
		Headers:    r.hdrs,
		Body:       r.body,
		Timeout:    to,
		NoRedirect: noRedirect,
	})
}

// fetch 发一次探测。
//
// 重定向策略：先发一跳不跟随，只有 Location 仍指向同一 Host:Port 才跟随重发。
// 理由很硬 —— 注入 payload 里就带着 127.0.0.1:22 / 169.254.169.254 这类地址，
// 如果目标把它们原样写进 Location，跟随一次就等于**扫描器自己**去连内网。
// 实测过：跟到 127.0.0.1:22 会读到本机 SSH banner，既越界又浪费一次 12s 超时。
func (p *prober) fetch(r request) *snap {
	if !p.charge() {
		return &snap{req: r, resp: &httpc.Response{URL: r.url, Err: errBudget}}
	}
	to := p.timeout
	if r.timeout > 0 {
		to = r.timeout
	}
	first := p.doHTTP(r, to, true)
	if r.follow && isRedirectStatus(first.Status) {
		if loc := first.Header("location"); loc != "" && sameTargetHost(loc, r.url) && p.charge() {
			return newSnap(r, p.doHTTP(r, to, false))
		}
	}
	return newSnap(r, first)
}

// isRedirectStatus 与 httpc.isRedirect 同集合（那个没导出）
func isRedirectStatus(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// sameTargetHost Location 解析后是否仍指向同一个 Host:Port。
// 相对路径算同目标；//evil.com、http://127.0.0.1:22 都不算。
func sameTargetHost(loc, rawURL string) bool {
	base, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ref, err := url.Parse(strings.TrimSpace(loc))
	if err != nil {
		return false
	}
	u := base.ResolveReference(ref)
	if u.Host == "" {
		return true
	}
	return strings.EqualFold(u.Host, base.Host)
}

// ---------------------------------------------------------------- 响应快照

// snap 响应快照：正文文本、指纹、响应头文本一次算好，比较逻辑只用这些。
type snap struct {
	req     request
	resp    *httpc.Response
	text    string // UTF-8 替换解码后的正文
	low     string // 正文小写（特征匹配用）
	headRaw string // 响应头拼成的文本
	headLow string
	sig     string // 正文指纹（scan.SigOf）
}

func newSnap(r request, resp *httpc.Response) *snap {
	s := &snap{req: r, resp: resp}
	if resp == nil {
		return s
	}
	s.text = strings.ToValidUTF8(string(resp.Body), "\uFFFD")
	s.low = strings.ToLower(s.text)
	s.sig = scan.SigOf(resp.Body)
	var b strings.Builder
	for _, h := range resp.Headers {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\n")
	}
	s.headRaw = b.String()
	s.headLow = strings.ToLower(s.headRaw)
	return s
}

func (s *snap) ok() bool {
	return s != nil && s.resp != nil && s.resp.Err == nil && s.resp.Status > 0
}

func (s *snap) status() int {
	if !s.ok() {
		return 0
	}
	return s.resp.Status
}

func (s *snap) length() int {
	if s == nil || s.resp == nil {
		return 0
	}
	return len(s.resp.Body)
}

func (s *snap) elapsed() time.Duration {
	if s == nil || s.resp == nil {
		return 0
	}
	return s.resp.Elapsed
}

func (s *snap) errText() string {
	if s == nil || s.resp == nil {
		return "无响应"
	}
	if s.resp.Err != nil {
		return s.resp.ErrText()
	}
	return ""
}

// sigText 正文 + 响应头的小写并集：有些框架把报错塞进 X-Debug 之类的头里
func (s *snap) sigText() string { return s.low + "\n" + s.headLow }

// rawText 与 sigText 对应的原文（取证据片段用）
func (s *snap) rawText() string { return s.text + "\n" + s.headRaw }

// 比较用的两种口径：
//
//	similar  —— 同一张页面（允许 CSRF token / 时间戳造成的微小差异）
//	differs  —— 明显不同的页面（长度差超过 5% 或状态码不同）
func (s *snap) similar(o *snap) bool {
	if !s.ok() || !o.ok() {
		return false
	}
	if s.status() != o.status() {
		return false
	}
	if s.sig == o.sig {
		return true
	}
	return absInt(s.length()-o.length()) <= tolerance(s.length(), o.length(), 1, 24)
}

func (s *snap) differs(o *snap) bool {
	if !s.ok() || !o.ok() {
		return false
	}
	if s.status() != o.status() {
		return true
	}
	if s.sig == o.sig {
		return false
	}
	return absInt(s.length()-o.length()) >= tolerance(s.length(), o.length(), 5, 48)
}

func tolerance(a, b, pct, floor int) int {
	t := max(a, b) * pct / 100
	if t < floor {
		t = floor
	}
	return t
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// ---------------------------------------------------------------- outcome

// outcome 一次检查的累计结果，最后统一折成三态。
type outcome struct {
	findings []*model.Finding
	points   int
	okPoints int    // 基线能拿到的参数点数（真正被判定过的）
	unit     string // 计数单位：默认「参数点」，XXE 用「XML 端点」
	scope    string // 本项实际覆盖的注入面；留空用默认（仅 GET 查询参数）
	errs     []string
	notes    []string
}

func (o *outcome) unitName() string {
	if o.unit == "" {
		return "参数点"
	}
	return o.unit
}

// scopeText 覆盖面说明。写进 ok 的 reason 里，避免读者把
// 「GET 参数没注入点」误读成「表单也测过了」。
func (o *outcome) scopeText() string {
	if o.scope != "" {
		return o.scope
	}
	return "仅 GET 查询参数面，表单字段未覆盖"
}

func (o *outcome) add(f *model.Finding) {
	if f == nil {
		return
	}
	if len(o.findings) >= maxFindingsPerCheck {
		o.note(fmt.Sprintf("已报 %d 条，后续同类命中不再重复上报", maxFindingsPerCheck))
		return
	}
	o.findings = append(o.findings, f)
}

func (o *outcome) fail(msg string) {
	for _, e := range o.errs {
		if e == msg {
			return
		}
	}
	if len(o.errs) < 3 {
		o.errs = append(o.errs, msg)
	}
}

// noteTruncated 参数点超过单项上限时如实记一笔，别让「8 个参数点」读起来像全测了。
func (o *outcome) noteTruncated(total, tested int) {
	if total > tested {
		o.note(fmt.Sprintf("另有 %d 个参数点因单项上限未测", total-tested))
	}
}

func (o *outcome) note(msg string) {
	if msg == "" {
		return
	}
	for _, n := range o.notes {
		if n == msg {
			return
		}
	}
	if len(o.notes) < 5 {
		o.notes = append(o.notes, msg)
	}
}

// result 折成三态：
//
//	有命中 → ok（reason 带计数）
//	基线全失败 → skip（绝不写成「没漏洞」）
//	其余 → ok（真测过、有对照）
func (o *outcome) result(p *prober) scan.Result {
	if len(o.findings) > 0 {
		return scan.Result{Findings: o.findings, State: scan.StateOK,
			Tested: p.n, Reason: o.reason(p, true)}
	}
	if o.okPoints == 0 {
		why := "全部参数点的基线请求都失败"
		if len(o.errs) > 0 {
			why += "：" + o.errs[0]
		}
		if p.blockedMsg != "" {
			why += "；" + p.blockedMsg
		}
		return scan.Result{Findings: nil, State: scan.StateSkip, Tested: p.n, Reason: why}
	}
	return scan.Result{Findings: nil, State: scan.StateOK,
		Tested: p.n, Reason: o.reason(p, false)}
}

func (o *outcome) reason(p *prober, hit bool) string {
	s := fmt.Sprintf("%d 个%s / %d 次请求", o.points, o.unitName(), p.n)
	if hit {
		s += fmt.Sprintf("，命中 %d 处", len(o.findings))
	} else {
		s += "，未命中"
	}
	s += "；" + o.scopeText()
	if len(o.notes) > 0 {
		s += "；" + strings.Join(o.notes, "；")
	}
	if p.blockedMsg != "" {
		s += "；" + p.blockedMsg
	}
	if len(o.errs) > 0 {
		s += fmt.Sprintf("；%d 类请求失败（%s）", len(o.errs), o.errs[0])
	}
	return s
}

// ---------------------------------------------------------------- 发现构造

type findingOpts struct {
	sev, level, conf             string
	evidence, repro, impact, fix string
	extra                        map[string]interface{}
}

func newFinding(c *scan.Ctx, m scan.Meta, o findingOpts) *model.Finding {
	if o.conf == "" {
		o.conf = "confirmed"
	}
	if o.extra == nil {
		o.extra = map[string]interface{}{}
	}
	if _, ok := o.extra["path"]; !ok {
		o.extra["path"] = "/"
	}
	scheme := c.Scheme
	if scheme == "" {
		if u := httpc.URLSplit(httpc.NormURL(c.Base)); u != nil {
			scheme = u.Scheme
		}
	}
	return model.NewFinding(m.Name, m.Title, o.sev, c.Base, model.FindingOpts{
		Host:       c.Host,
		Port:       c.Port,
		Scheme:     scheme,
		Category:   "web",
		Level:      o.level,
		Confidence: o.conf,
		Evidence:   o.evidence,
		Repro:      o.repro,
		Impact:     o.impact,
		Fix:        o.fix,
		Extra:      o.extra,
	})
}

// curlGet 复现命令。查询串里的特殊字符已被 QueryEscape 处理，
// 所以这里可以安全用双引号（URL 里不会出现引号、$、反引号）。
func curlGet(u string) string { return `curl -s -i "` + u + `"` }

// curlXML 复现命令
func curlXML(u, body string) string {
	return `curl -s -i -X POST -H "Content-Type: application/xml" --data-binary '` + body + `' "` + u + `"`
}

// pathOf 取 URL 的路径+查询，用于 Finding.Extra["path"]（去重键的一部分）
func pathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	s := u.Path
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	return s
}

// ---------------------------------------------------------------- 证据片段

// snippetCI 在 text 里大小写不敏感地找 needle，取前后 radius 字节。
// 按 UTF-8 边界对齐，避免把多字节字符切成替换字符。
func snippetCI(text, needle string, radius int) string {
	if needle == "" || text == "" {
		return ""
	}
	i := strings.Index(strings.ToLower(text), strings.ToLower(needle))
	if i < 0 {
		return ""
	}
	lo := alignDown(text, max(0, i-radius))
	hi := alignUp(text, min(len(text), i+len(needle)+radius))
	s := strings.Join(strings.Fields(text[lo:hi]), " ")
	if lo > 0 {
		s = "…" + s
	}
	if hi < len(text) {
		s = s + "…"
	}
	return s
}

func alignDown(s string, i int) int {
	for i > 0 && i < len(s) && s[i]&0xC0 == 0x80 {
		i--
	}
	return i
}

func alignUp(s string, i int) int {
	for i > 0 && i < len(s) && s[i]&0xC0 == 0x80 {
		i++
	}
	return i
}

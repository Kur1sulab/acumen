// Package authz 是「认证与授权」族的内建检查（scan 家族 authz）。
//
// 这个包的每条铁律都是为了压误报，而不是为了提覆盖率：
//
//  1. **只读**。全部 GET/HEAD + 登录尝试，不注册、不写、不删、不 PUT/PATCH。
//     默认口令与口令策略检查必然要 POST 登录接口 —— 那是登录尝试，不是写操作；
//     除此之外不发任何带副作用的请求。
//  2. **对照组是硬要求**。任何「成功」判定都必须与一次必然失败的尝试做对比：
//     默认口令先打 litmus_probe_xxxxxxxx/wrongpass 拿失败基线，只有出现基线里
//     没有的会话 Cookie / 跳转 / JSON success|token 才算命中；未授权 API 必须先
//     拿一份带认证的响应做对照，公开接口不许报成未授权。
//  3. **不做真爆破**。字典硬编码且故意很小（每产品 3-6 对），每账号最多 5 次；
//     响应里出现验证码/锁定特征立刻停手。宁可漏，不可误报。
//  4. **凭据打码**。口令只留前 4 位（model.MaskSecret），明文绝不进
//     Evidence / Extra / JSON；JWT 一样打码（只留前 8 位）。
//  5. **三态**。没条件测就 skip 并写清原因：「未发现登录入口」比「没问题」诚实得多。
//
// 与 scan.Ctx 的关系：本包只读 ctx，不写 ctx；探测次数全部经过 prober 计数器，
// 受 ctx.MaxProbe（ProbeBudget）约束 —— 不允许某个检查把预算吃光。
package authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// Family 覆盖表里的家族名。scan.Register 要求每个检查项都带家族。
const Family = "authz"

const (
	// ProbeUser 对照组账号：一个必然不存在的名字。
	ProbeUser = "litmus_probe_xxxxxxxx"
	// ProbePass 对照组口令：必然是错的。
	ProbePass = "wrongpass"

	// EvilOrigin CORS 探测用的外部源。
	EvilOrigin = "https://evil-litmus.example"

	// maxAttemptsPerAccount 每账号最多尝试次数。这是铁律，不许改大：
	// 超过 5 次就不叫探测，叫爆破。
	maxAttemptsPerAccount = 5

	// maxLoginPaths 单次登录入口发现最多请求多少个候选路径。
	maxLoginPaths = 10

	// defaultTimeout ctx 没给超时时的兜底（契约 4.3：超时必须显式）。
	defaultTimeout = 8 * time.Second
)

// mk 造一个检查项元信息，少写点样板。
func mk(name, title, severity, cwe string) scan.Meta {
	return scan.Meta{
		Name:     Family + "/" + name,
		Family:   Family,
		Title:    title,
		Severity: severity,
		Owasp:    "A07:2021 Identification and Authentication Failures",
		CWE:      cwe,
	}
}

func timeoutOf(c *scan.Ctx) time.Duration {
	if c != nil && c.Timeout > 0 {
		return c.Timeout
	}
	return defaultTimeout
}

// ---------------------------------------------------------------- 探测计数

// prober 是唯一发请求的出口。
//
// 存在的理由：预算。scan.Ctx.MaxProbe 是「本项最多发几次」，如果各检查直接调
// pool.Get，谁都能把目标打挂。所有请求都必须过这里，顺手还能给 Result.Tested
// 一个准确值（覆盖表上的「探测次数」不该是编的）。
type prober struct {
	ctx  *scan.Ctx
	pool *httpc.Pool
	n    int
	max  int
}

func newProber(c *scan.Ctx) *prober {
	pool := c.Pool
	if pool == nil {
		// 调用方没给池也要能跑（单测/嵌入场景）。池本身无资源，不需要关。
		pool = httpc.NewPool(4, 0, timeoutOf(c), false)
	}
	max := c.ProbeBudget()
	if max > 400 {
		max = 400
	}
	return &prober{ctx: c, pool: pool, max: max}
}

func (p *prober) left() bool { return p.n < p.max }

func (p *prober) used() int { return p.n }

// do 发一次请求。一律 NoRedirect：3xx 的 Location 本身就是判定依据
// （登录成功靠跳转、未授权靠跳登录页），跟随后就看不见了。
func (p *prober) do(method, rawURL string, hdrs []httpc.Header, body []byte) *httpc.Response {
	p.n++
	o := httpc.Opts{
		Method:     method,
		Headers:    hdrs,
		Body:       body,
		Timeout:    timeoutOf(p.ctx),
		NoRedirect: true,
	}
	return p.pool.Request(method, rawURL, o)
}

// ---------------------------------------------------------------- 响应视图

// respView 是响应的只读视图：判定要的那几项一次算好，避免每个检查各写一遍。
type respView struct {
	Status      int
	Body        []byte
	Text        string // UTF-8 替换解码（与 webcheck 的 bodyText 一致）
	Sig         string // sha1 前 16 位，比「内容不同」好用
	Len         int
	Location    string // 已归一化成绝对 URL
	SetCookies  []string
	Headers     []httpc.Header
	ContentType string
	JSON        interface{}
	JSONOK      bool
	Err         error
}

func viewOf(r *httpc.Response) *respView {
	if r == nil {
		return &respView{Err: fmt.Errorf("nil response")}
	}
	v := &respView{
		Status:      r.Status,
		Body:        r.Body,
		Text:        strings.ToValidUTF8(string(r.Body), "\uFFFD"),
		Sig:         scan.SigOf(r.Body),
		Len:         len(r.Body),
		Location:    r.Header("location"),
		SetCookies:  r.HeaderAll("set-cookie"),
		Headers:     r.Headers,
		ContentType: r.Header("content-type"),
		Err:         r.Err,
	}
	if v.Location != "" {
		v.Location = httpc.URLJoin(r.URL, v.Location)
	}
	if b := bytes.TrimSpace(r.Body); len(b) > 0 && (b[0] == '{' || b[0] == '[') {
		var x interface{}
		if json.Unmarshal(b, &x) == nil {
			v.JSON = x
			v.JSONOK = true
		}
	}
	return v
}

// header 取响应头（大小写不敏感，首个同名头）。
func (v *respView) header(name string) string {
	n := strings.ToLower(name)
	for _, h := range v.Headers {
		if h.Name == n {
			return h.Value
		}
	}
	return ""
}

// scanText 关键词判定用的文本：原始正文 + JSON 里解码后的字符串值。
//
// 为什么需要它：不少服务端把中文转义成 \uXXXX 再发（Python json.dumps 默认如此）。
// 直接对原文搜「验证码」「未授权」会漏，后果是一边把有验证码的入口报成
// 「可无限爆破」，一边把「token 无效」的 200 错误页报成认证绕过 —— 都是假阳性。
func (v *respView) scanText() string {
	if v == nil {
		return ""
	}
	if !v.JSONOK {
		return v.Text
	}
	var b strings.Builder
	b.WriteString(v.Text)
	collectStrings(v.JSON, 0, &b, 0)
	return b.String()
}

// collectStrings 递归收集 JSON 里的字符串（键名也算），带深度与长度预算。
func collectStrings(v interface{}, depth int, b *strings.Builder, budget int) int {
	if depth > 5 || budget > 8192 {
		return budget
	}
	switch t := v.(type) {
	case string:
		b.WriteString(" ")
		b.WriteString(t)
		return budget + len(t)
	case []interface{}:
		for _, x := range t {
			budget = collectStrings(x, depth+1, b, budget)
		}
	case map[string]interface{}:
		for k, x := range t {
			b.WriteString(" ")
			b.WriteString(k)
			budget = collectStrings(x, depth+1, b, budget)
		}
	}
	return budget
}

// cookieNames 全部 Set-Cookie 的名字（不含值）。
func (v *respView) cookieNames() []string {
	out := make([]string, 0, len(v.SetCookies))
	for _, sc := range v.SetCookies {
		if c := parseCookie(sc); c != nil {
			out = append(out, c.Name)
		}
	}
	return dedupeStrings(out)
}

// sessionCookieNames 只取会话类 Cookie 名（判定「拿到会话」靠它）。
func (v *respView) sessionCookieNames() []string {
	var out []string
	for _, n := range v.cookieNames() {
		if isSessionCookie(n) {
			out = append(out, n)
		}
	}
	return out
}

// ---------------------------------------------------------------- JSON 小工具

// jsonTruthy 对齐 Python 的「真值」直觉：true / 非空串 / 非零数。
//
// 特意把字符串 "false"/"0"/"" 当假：不少框架把布尔写成字符串，
// 只看「字段非空」会把 success:"false" 判成成功（经典假阳性）。
func jsonTruthy(x interface{}) bool {
	switch t := x.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		return s != "" && s != "false" && s != "0" && s != "null" && s != "none"
	case float64:
		return t != 0
	case json.Number:
		f, err := t.Float64()
		return err == nil && f != 0
	case []interface{}:
		return len(t) > 0
	case map[string]interface{}:
		return len(t) > 0
	}
	return true
}

// innerObject 把 data / result / payload 这类包一层的结果摊平（深度 1）。
func innerObjects(v interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	if m, ok := v.(map[string]interface{}); ok {
		out = append(out, m)
		for _, k := range []string{"data", "result", "payload", "body", "response"} {
			if sub, ok := m[k].(map[string]interface{}); ok {
				out = append(out, sub)
			}
		}
	}
	return out
}

// collectKeys 递归收集 JSON 对象的全部键名（小写），用于「敏感字段」判定。
func collectKeys(v interface{}, depth int, out map[string]bool) {
	if depth > 6 {
		return
	}
	switch t := v.(type) {
	case map[string]interface{}:
		for k, sub := range t {
			out[strings.ToLower(k)] = true
			collectKeys(sub, depth+1, out)
		}
	case []interface{}:
		// 数组只看第一个元素：几百条记录没必要全走一遍
		if len(t) > 0 {
			collectKeys(t[0], depth+1, out)
		}
	}
}

// ---------------------------------------------------------------- 文本小工具

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// diffStrings 在 a 里但不在 b 里的项（保序）。
func diffStrings(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, s := range b {
		have[s] = true
	}
	var out []string
	for _, s := range a {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// pathOf 取 URL 的路径部分（小写），畸形串不报错、尽力而为。
func pathOf(raw string) string {
	p := httpc.URLSplit(raw)
	if p == nil {
		return ""
	}
	if p.Path == "" {
		return "/"
	}
	return strings.ToLower(p.Path)
}

// errorPageMarkers 「这不是有效对象」的通用提示。IDOR 用它排除错误页，
// 避免把「换了 ID 返回 200 + 不存在」当成「拿到了别人的对象」。
var errorPageMarkers = []string{
	"not found", "no such", "does not exist", "不存在", "无此", "找不到",
	"无权限", "没有权限", "无权访问", "forbidden", "access denied",
	"unauthorized", "未授权", "未登录", "请先登录", "login required",
	"login_required", "permission denied", "invalid id", "参数错误", "illegal",
	// 认证类：不少框架把「token 无效」渲染成 200 + 这种 JSON。
	// 缺了这几条，alg=none / 弱密钥检查会把「认证失败页」报成「认证绕过」，
	// 这是本族最严重的一类假阳性。
	"invalid token", "token invalid", "token expired", "invalid signature",
	"signature verification failed", "missing token", "token missing",
	"not authenticated", "authentication required", "令牌无效", "令牌已过期",
	"未携带令牌", "缺少令牌",
}

func isErrorBody(s string) bool {
	low := strings.ToLower(s)
	if len(low) > 4096 {
		low = low[:4096]
	}
	return containsAny(low, errorPageMarkers...)
}

// captchaWords 出现即视为「有人机验证」——立刻停手，不猜验证码。
//
// 连裸的 "captcha" 也算：宁可把「页面脚本里带个 captcha.js」误当成有防护
// （少报一条 low），也不能把真有人机验证的入口报成「可无限爆破」（误报）。
// 零误报优先于覆盖率，这里的取舍是故意的。
var captchaWords = []string{
	"请输入验证码", "验证码错误", "验证码不正确", "图形验证码", "验证码已发送",
	"人机验证", "滑动验证", "captcha", "recaptcha", "g-recaptcha", "hcaptcha",
}

// lockWords 锁定/限速特征。命中就是「这个账号不能再试了」，不是「口令错了」。
var lockWords = []string{
	"账号已锁定", "账户已锁定", "帐号已锁定", "已锁定", "锁定中", "账号被锁",
	"尝试次数过多", "次数过多", "尝试过于频繁", "访问过于频繁",
	"too many attempts", "too many failed", "too many requests",
	"account locked", "account has been locked", "account disabled",
	"账号已禁用", "账户已禁用", "temporarily blocked", "请稍后再试",
	"请稍后重试", "请 5 分钟后再试", "请五分钟后再试", "稍后再试",
}

// lockSignal 返回命中的防护特征；空串 = 未见防护。
//
// 429 单独判：很多网关只回状态码不回文案。
func lockSignal(v *respView) string {
	if v == nil {
		return ""
	}
	if v.Status == 429 {
		return "HTTP 429（限速）"
	}
	low := strings.ToLower(v.scanText())
	if len(low) > 20000 {
		low = low[:20000]
	}
	for _, w := range captchaWords {
		if strings.Contains(low, w) {
			return "验证码特征：" + w
		}
	}
	for _, w := range lockWords {
		if strings.Contains(low, w) {
			return "锁定特征：" + w
		}
	}
	return ""
}

// hasCaptchaField 页面里是否有验证码输入框（比命中文案更硬的判据）。
var captchaFieldRe = regexp.MustCompile(`(?is)<input[^>]*name\s*=\s*["']?(captcha|verifycode|verify_code|checkcode|vcode|validatecode|code)[^>]*>`)

func hasCaptchaField(s string) bool {
	return captchaFieldRe.MatchString(strings.ToLower(s))
}

// productHints 登录页 → 产品名（只用于挑默认口令字典，猜错不影响判定）。
var productHints = []struct{ key, name string }{
	{"tomcat", "tomcat"},
	{"jenkins", "jenkins"},
	{"weblogic", "weblogic"},
	{"jboss", "jboss"},
	{"wildfly", "jboss"},
	{"wordpress", "wordpress"},
	{"gitlab", "gitlab"},
	{"zabbix", "zabbix"},
	{"grafana", "grafana"},
	{"phpmyadmin", "phpmyadmin"},
	{"nacos", "nacos"},
	{"keycloak", "keycloak"},
}

func productHint(v *respView) string {
	if v == nil {
		return ""
	}
	head := v.Text
	if len(head) > 4096 {
		head = head[:4096]
	}
	low := strings.ToLower(head)
	for _, h := range productHints {
		if strings.Contains(low, h.key) {
			return h.name
		}
	}
	return ""
}

// ---------------------------------------------------------------- 请求辅助

func bearer(tok string) []httpc.Header {
	return []httpc.Header{{Name: "Authorization", Value: "Bearer " + tok}}
}

// maskToken token 也是凭据，报告里只留前 8 位。
func maskToken(tok string) string { return model.MaskSecret(tok, 8) }

// sameOrigin 只允许与 ctx 同源的 URL。
//
// 爬虫落点理论上同源，但「理论上」在渗透现场经常不成立：
// 一条外链就能把探测打到客户没授权的第三方资产上。这一层是范围守卫。
func sameOrigin(ctx *scan.Ctx, raw string) bool {
	p := httpc.URLSplit(raw)
	if p == nil || p.Hostname() == "" {
		return false
	}
	if !strings.EqualFold(p.Hostname(), ctx.Host) {
		return false
	}
	if ctx.Port <= 0 {
		return true
	}
	port := 0
	if ps := p.Port(); ps != "" {
		port, _ = strconv.Atoi(ps)
	} else if strings.EqualFold(p.Scheme, "https") {
		port = 443
	} else if strings.EqualFold(p.Scheme, "http") {
		port = 80
	}
	return port == ctx.Port
}

// probeURLs 探测地址表：ctx.Base 打头，再补 ctx.URLs 里同源的落点。
//
// 顺序有意义：base 是客户给的那个入口，响应最稳；爬虫落点可能带一次性的
// 查询串，放后面先不浪费预算。
func probeURLs(ctx *scan.Ctx, max int) []string {
	var out []string
	add := func(u string) {
		if u == "" || len(out) >= max {
			return
		}
		u = httpc.NormURL(u)
		for _, e := range out {
			if e == u {
				return
			}
		}
		out = append(out, u)
	}
	if ctx.Base != "" {
		add(ctx.Base)
	}
	for _, u := range ctx.URLs {
		if sameOrigin(ctx, u) {
			add(u)
		}
	}
	return out
}

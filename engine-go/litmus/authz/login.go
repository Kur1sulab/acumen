package authz

// login.go —— 登录入口发现 + 默认口令 + 登录防护缺失。
//
// 三个检查共用一套发现逻辑（discoverLogin），原因很实际：登录入口的形状
// 决定了后面所有探测怎么发（表单字段名、CSRF 隐藏域、JSON 还是 form）。
// 各写一套必然漂移，最后「发现了一个入口」和「测的是另一个入口」。
//
// 判定纪律：
//   - 登录成功**只看正面信号**：新的会话 Cookie / 跳到非登录页 / JSON success
//     或 token。响应体「不一样」永远不算 —— 失败页会回显账号名，字节必然不同。
//   - 还在登录页（响应里有口令输入框）一律判失败。
//   - 出现验证码/锁定特征立刻停手，不猜、不绕。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		scan.Check{
			Meta: mk("login-form-detect", "登录入口可发现", "info", "CWE-200"),
			Run:  runLoginFormDetect,
		},
		scan.Check{
			Meta: mk("weak-password-policy", "登录接口缺少验证码/锁定防护", "low", "CWE-307"),
			Run:  runWeakPasswordPolicy,
		},
	)
}

// ---------------------------------------------------------------- HTML 解析

var (
	formBlockRe = regexp.MustCompile(`(?is)<form\b[^>]*>.*?</form>`)
	inputTagRe  = regexp.MustCompile(`(?is)<input\b[^>]*>`)

	// 属性解析：双引号 / 单引号 / 裸值三种形态。Go 的 RE2 不支持 (?:)，
	// 所以用三个捕获组，取值时挑第一个非空组。
	attrActionRe = regexp.MustCompile(`(?is)\baction\s*=\s*"([^"]*)"|\baction\s*=\s*'([^']*)'|\baction\s*=\s*([^\s>]+)`)
	attrNameRe   = regexp.MustCompile(`(?is)\bname\s*=\s*"([^"]*)"|\bname\s*=\s*'([^']*)'|\bname\s*=\s*([^\s>]+)`)
	attrTypeRe   = regexp.MustCompile(`(?is)\btype\s*=\s*"([^"]*)"|\btype\s*=\s*'([^']*)'|\btype\s*=\s*([^\s>]+)`)
	attrValueRe  = regexp.MustCompile(`(?is)\bvalue\s*=\s*"([^"]*)"|\bvalue\s*=\s*'([^']*)'|\bvalue\s*=\s*([^\s>]+)`)
)

// userFieldNames 账号字段候选（按优先级）。
var userFieldNames = []string{
	"username", "user_name", "userid", "user_id", "uname", "account", "account_name",
	"loginname", "login_name", "email", "login", "j_username", "name",
}

// passFieldNames 口令字段候选（按优先级）。第一个就是最常见的那个。
var passFieldNames = []string{
	"password", "passwd", "pwd", "pass_word", "pass", "j_password",
}

func containsFold(list []string, s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, v := range list {
		if strings.ToLower(v) == s {
			return true
		}
	}
	return false
}

// firstAttr 从标签里取第一个非空的捕获组。
func firstAttr(re *regexp.Regexp, tag string) string {
	m := re.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

type inputField struct {
	Name  string
	Type  string
	Value string
}

func parseInputs(html string) []inputField {
	tags := inputTagRe.FindAllString(html, 40)
	out := make([]inputField, 0, len(tags))
	for _, tag := range tags {
		out = append(out, inputField{
			Name:  firstAttr(attrNameRe, tag),
			Type:  strings.ToLower(firstAttr(attrTypeRe, tag)),
			Value: firstAttr(attrValueRe, tag),
		})
	}
	return out
}

// hasPasswordInput 判断 HTML 里有没有口令输入框。
//
// 用途有二：发现登录页；以及在判定登录结果时识别「还站在登录页上」——
// 失败页通常把表单原样回显，光看「响应体变了」会把失败判成成功。
func hasPasswordInput(s string) bool {
	for _, in := range parseInputs(s) {
		if in.Type == "password" {
			return true
		}
		if containsFold(passFieldNames, in.Name) {
			// 隐藏域里叫 pass 的不算（有些框架回填用 hidden）
			if in.Type != "hidden" {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- 登录入口

// loginEndpoint 一个可尝试登录的入口。
type loginEndpoint struct {
	URL       string
	Kind      string // form | json
	Method    string
	UserField string
	PassField string
	Hidden    map[string]string // CSRF / 一次性 token 等隐藏域
	Guess     bool              // 字段名是推断的（JSON 响应里没直接看到口令字段）
	Captcha   bool              // 登录页本身带验证码字段：不必再尝试口令
	Product   string            // 登录页露出的产品特征，用于选字典
	Evidence  string
}

// commonLoginPaths 常见登录路径（与任务清单一致）。
var commonLoginPaths = []string{
	"/login", "/admin", "/login.jsp", "/auth/login",
	"/api/login", "/user/login", "/sso/login", "/cas/login",
}

// loginishPath 路径是否形似登录/认证入口。
func loginishPath(raw string) bool {
	p := pathOf(raw)
	return containsAny(p, "login", "signin", "sign-in", "sign_in", "logon",
		"auth/", "/sso", "cas/", "session", "logoff")
}

func loginCandidates(ctx *scan.Ctx) []string {
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	// 爬虫落点优先：那是目标自己暴露的真实入口，命中率比猜路径高。
	for _, u := range ctx.URLs {
		if loginishPath(u) && sameOrigin(ctx, u) {
			add(httpc.NormURL(u))
		}
	}
	for _, p := range commonLoginPaths {
		add(httpc.BuildURLJoin(ctx.Base, p))
	}
	return out
}

// discoverLogin 找出最多 want 个登录入口。
//
// 只看 GET 的响应形态（表单口令框 / JSON 登录结构）—— 不发任何猜测性 POST：
// 猜字段名乱打一通，等于对着目标做模糊测试，噪声大且容易触发防护。
func discoverLogin(ctx *scan.Ctx, p *prober, want int) []loginEndpoint {
	if ctx.Base == "" || want <= 0 {
		return nil
	}
	var out []loginEndpoint
	seen := map[string]bool{}
	n := 0
	for _, u := range loginCandidates(ctx) {
		if len(out) >= want || !p.left() || n >= maxLoginPaths {
			break
		}
		n++
		v := viewOf(p.do("GET", u, nil, nil))
		if v.Err != nil {
			continue
		}
		ep := parseLoginPage(u, v)
		if ep == nil || seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true
		out = append(out, *ep)
	}
	return out
}

func parseLoginPage(pageURL string, v *respView) *loginEndpoint {
	// 1) HTML 表单
	if ep := parseLoginForm(pageURL, v.Text); ep != nil {
		ep.Product = productHint(v)
		ep.Captcha = hasCaptchaField(v.Text)
		return ep
	}
	// 2) JSON 登录 API
	if v.JSONOK {
		low := strings.ToLower(v.Text)
		if containsAny(low, `"password"`, `"passwd"`, `"pwd"`, `"pass_word"`) {
			return &loginEndpoint{
				URL: pageURL, Kind: "json", Method: "POST",
				UserField: guessUserField(low), PassField: "password",
				Product:  productHint(v),
				Captcha:  hasCaptchaField(v.Text),
				Evidence: "JSON 响应含口令字段",
			}
		}
		// 只看到 JSON 错误结构（GET 打 POST-only 接口的典型响应）。
		// 字段名是猜的，所以标 Guess，后续判定靠对照组而不是靠字段名。
		if loginishPath(pageURL) && containsAny(low, `"code"`, `"message"`, `"msg"`, `"error"`, `"detail"`) {
			return &loginEndpoint{
				URL: pageURL, Kind: "json", Method: "POST",
				UserField: "username", PassField: "password",
				Guess: true, Product: productHint(v),
				Captcha:  hasCaptchaField(v.Text),
				Evidence: "路径形似登录且返回 JSON 错误结构（字段名为推断）",
			}
		}
	}
	return nil
}

func guessUserField(lowBody string) string {
	for _, f := range userFieldNames {
		if strings.Contains(lowBody, `"`+f+`"`) {
			return f
		}
	}
	return "username"
}

// parseLoginForm 从页面里挑出「含口令框」的那个表单。
func parseLoginForm(pageURL, html string) *loginEndpoint {
	blocks := formBlockRe.FindAllString(html, 8)
	for _, block := range blocks {
		if !hasPasswordInput(block) {
			continue
		}
		end := strings.Index(block, ">")
		openTag := block
		if end > 0 {
			openTag = block[:end+1]
		}
		action := strings.TrimSpace(firstAttr(attrActionRe, openTag))
		target := pageURL
		if action != "" && !strings.HasPrefix(strings.ToLower(action), "javascript:") {
			target = httpc.URLJoin(pageURL, action)
		}
		ep := &loginEndpoint{URL: target, Kind: "form", Method: "POST", Hidden: map[string]string{}}
		pass := ""
		for _, in := range parseInputs(block) {
			switch {
			case in.Type == "password" && pass == "":
				pass = in.Name
			case containsFold(passFieldNames, in.Name) && pass == "":
				pass = in.Name
			case ep.UserField == "" && containsFold(userFieldNames, in.Name):
				ep.UserField = in.Name
			case in.Type == "hidden" && in.Name != "" && len(ep.Hidden) < 6:
				ep.Hidden[in.Name] = in.Value
			}
		}
		if pass == "" {
			pass = "password"
		}
		ep.PassField = pass
		if ep.UserField == "" {
			ep.UserField = "username"
		}
		// 隐藏域里如果混进了账号/口令字段，剔掉（否则会被覆盖成固定值）
		delete(ep.Hidden, ep.UserField)
		delete(ep.Hidden, ep.PassField)
		ep.Evidence = fmt.Sprintf("页面含口令输入框的登录表单（action=%s，字段 %s/%s）",
			target, ep.UserField, ep.PassField)
		return ep
	}
	return nil
}

// ---------------------------------------------------------------- 登录尝试

// loginAttempt 一次登录尝试的可判定特征。
type loginAttempt struct {
	Status      int
	Sig         string
	Len         int
	Location    string
	SessionCook []string // 会话类 Cookie 名（不含值）
	TokenKey    string   // JSON 里出现的会话 token 字段名
	Success     bool     // JSON success 为真
	AtLoginPage bool     // 响应里仍有口令输入框
	Captcha     bool     // 响应里有验证码字段
	Lock        string   // 非空 = 命中验证码/锁定
	Err         error
}

var tokenKeys = []string{
	"token", "access_token", "accessToken", "accesstoken", "jwt",
	"id_token", "idToken", "session", "sessionid", "sessionId", "ticket",
}

func (p *prober) loginAttempt(ep loginEndpoint, user, pass string) *loginAttempt {
	var (
		body []byte
		ct   string
	)
	userField := ep.UserField
	if userField == "" {
		userField = "username"
	}
	passField := ep.PassField
	if passField == "" {
		passField = "password"
	}
	if ep.Kind == "json" {
		m := map[string]string{userField: user, passField: pass}
		body, _ = json.Marshal(m)
		ct = "application/json"
	} else {
		vals := url.Values{}
		for k, v := range ep.Hidden {
			vals.Set(k, v)
		}
		vals.Set(userField, user)
		vals.Set(passField, pass)
		body = []byte(vals.Encode())
		ct = "application/x-www-form-urlencoded"
	}
	// Content-Length 必须显式写：httpc 不自动补长度，缺了它服务端按 CL 读时
	// 会认为 body 是空的 —— 那所有登录尝试都会失败，检查静默失效。
	hdrs := []httpc.Header{
		{Name: "Content-Type", Value: ct},
		{Name: "Content-Length", Value: strconv.Itoa(len(body))},
	}
	return classifyLogin(viewOf(p.do("POST", ep.URL, hdrs, body)))
}

func classifyLogin(v *respView) *loginAttempt {
	a := &loginAttempt{
		Status:      v.Status,
		Sig:         v.Sig,
		Len:         v.Len,
		Location:    v.Location,
		SessionCook: v.sessionCookieNames(),
		Err:         v.Err,
	}
	if v.Err != nil {
		return a
	}
	a.AtLoginPage = hasPasswordInput(v.Text)
	a.Captcha = hasCaptchaField(v.Text)
	a.Lock = lockSignal(v)
	if a.Lock == "" && a.Captcha {
		a.Lock = "验证码字段"
	}
	if v.JSONOK {
		for _, obj := range innerObjects(v.JSON) {
			if x, ok := obj["success"]; ok && jsonTruthy(x) {
				a.Success = true
			}
			if x, ok := obj["ok"]; ok && jsonTruthy(x) {
				a.Success = true
			}
			if a.TokenKey != "" {
				continue
			}
			for _, k := range tokenKeys {
				if x, ok := obj[k]; ok && jsonTruthy(x) {
					a.TokenKey = k
					break
				}
			}
		}
	}
	return a
}

// credVerdict 判断候选口令是否成功 —— 必须与失败基线对比。
//
// 返回 (命中, 依据)。判定表见函数体，宁严不宽：拿不准就算没命中。
func credVerdict(base, cand *loginAttempt) (bool, string) {
	if base == nil || cand == nil || cand.Err != nil {
		return false, ""
	}
	// 与失败基线逐字节一致 → 一定失败（连回显都一样）
	if cand.Sig == base.Sig {
		return false, ""
	}
	// 明确被拒
	if cand.Status == 401 || cand.Status == 403 {
		return false, ""
	}
	// 还在登录页且没有任何正面信号 → 失败
	if cand.AtLoginPage && !cand.Success && cand.TokenKey == "" {
		return false, ""
	}
	// 判定顺序按证据强度：JSON 明确成功 > token 字段 > 新会话 Cookie > 跳转。
	// 都只是「相对失败基线新出现的东西」，所以顺序不影响是否命中。
	if cand.Success && !base.Success {
		return true, "JSON success 为真（失败基线为假）"
	}
	if cand.TokenKey != "" && base.TokenKey == "" {
		return true, "响应出现会话 token 字段 " + cand.TokenKey + "（失败基线没有）"
	}
	if newCk := diffStrings(cand.SessionCook, base.SessionCook); len(newCk) > 0 {
		return true, "响应下发新会话 Cookie " + strings.Join(newCk, ",") + "（失败基线没有）"
	}
	if cand.Location != "" && cand.Location != base.Location && !loginishPath(cand.Location) {
		back := base.Location
		if back == "" {
			back = "无跳转"
		}
		return true, "跳转到 " + cand.Location + "（失败基线：" + back + "）"
	}
	return false, ""
}

// ---------------------------------------------------------------- 字典

type credPair struct{ user, pass string }

// genericDict 通用弱口令。故意只有 4 对：覆盖率高不了一点，但误报为零。
var genericDict = []credPair{
	{"admin", "admin"},
	{"admin", "123456"},
	{"admin", "admin@123"},
	{"test", "test"},
}

// productDict 产品默认口令，每产品 3 对（出厂默认值，公开资料）。
//
// 这些是产品出厂值，不是从目标偷来的口令，所以字典可以留在代码里；
// 一旦命中，报告里只出现打码后的口令。
var productDict = map[string][]credPair{
	"tomcat":     {{"tomcat", "tomcat"}, {"admin", "admin"}, {"admin", "tomcat"}},
	"jenkins":    {{"admin", "admin"}, {"jenkins", "jenkins"}, {"admin", "jenkins"}},
	"weblogic":   {{"weblogic", "weblogic"}, {"admin", "weblogic"}, {"weblogic", "12345678"}},
	"jboss":      {{"admin", "admin"}, {"jboss", "jboss"}, {"admin", "jboss"}},
	"wordpress":  {{"admin", "admin"}, {"admin", "wordpress"}, {"admin", "123456"}},
	"gitlab":     {{"root", "5iveL!fe"}, {"root", "root"}, {"admin", "admin"}},
	"zabbix":     {{"admin", "zabbix"}, {"Admin", "zabbix"}, {"admin", "admin"}},
	"grafana":    {{"admin", "admin"}, {"admin", "grafana"}, {"admin", "123456"}},
	"phpmyadmin": {{"root", "root"}, {"root", "123456"}, {"root", "admin"}},
	"nacos":      {{"nacos", "nacos"}, {"admin", "admin"}, {"nacos", "123456"}},
}

// dictFor 产品字典在前、通用字典补位；去重后截到每账号尝试上限。
//
// 去重是必须的：产品字典里的 admin/admin 与通用字典重复，不去重会白打一次，
// 把宝贵的 5 次预算浪费在同一个口令上。
func dictFor(product string) []credPair {
	out := make([]credPair, 0, maxAttemptsPerAccount)
	seen := map[string]bool{}
	add := func(ps []credPair) {
		for _, c := range ps {
			k := c.user + "\x00" + c.pass
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, c)
		}
	}
	if ps, ok := productDict[product]; ok {
		add(ps)
	}
	add(genericDict)
	if len(out) > maxAttemptsPerAccount {
		out = out[:maxAttemptsPerAccount]
	}
	return out
}

// ---------------------------------------------------------------- 检查 1

func runLoginFormDetect(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	p := newProber(ctx)
	eps := discoverLogin(ctx, p, 3)
	if len(eps) == 0 {
		return scan.Skip("未发现登录入口")
	}
	var fs []*model.Finding
	for _, ep := range eps {
		extra := map[string]interface{}{
			"path":       pathOf(ep.URL),
			"endpoint":   ep.URL,
			"kind":       ep.Kind,
			"method":     ep.Method,
			"user_field": ep.UserField,
			"pass_field": ep.PassField,
		}
		if ep.Product != "" {
			extra["product"] = ep.Product
		}
		if ep.Guess {
			extra["field_guess"] = true
		}
		if ep.Captcha {
			extra["captcha"] = true
		}
		conf := "confirmed"
		if ep.Guess {
			conf = "likely"
		}
		f := model.NewFinding("authz/login-form-detect", "登录入口可发现", "info", ctx.Base, model.FindingOpts{
			Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
			Level: "L1", Confidence: conf,
			Evidence: fmt.Sprintf("%s：GET %s 返回登录入口（%s）。", ep.URL, ep.URL, ep.Evidence),
			Repro:    fmt.Sprintf("curl -sS -i '%s' | head -40", ep.URL),
			Impact: "登录入口可枚举，为口令猜测与钓鱼提供了确定的目标地址。" +
				"（本条只是信息项：登录页本身不是漏洞。）",
			Fix:     "无需修复。若暴露面要求更严，可对登录页加访问控制、限速与告警，并纳入登录监控。",
			TitleEN: "Login Endpoint Discoverable",
			Extra:   extra,
		})
		fs = append(fs, f)
	}
	return scan.OK(p.used(), fs...)
}

// ---------------------------------------------------------------- 检查 9

func runWeakPasswordPolicy(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	p := newProber(ctx)
	eps := discoverLogin(ctx, p, 1)
	if len(eps) == 0 {
		return scan.Skip("未发现登录入口")
	}
	ep := eps[0]
	if ep.Captcha {
		// 登录页本来就要求验证码：这项要测的弱点不存在，不必发口令。
		return scan.OK(p.used())
	}

	var got []*loginAttempt
	for i := 0; i < 3; i++ {
		if !p.left() {
			break
		}
		a := p.loginAttempt(ep, ProbeUser, fmt.Sprintf("litmus_wrong_pass_%d", i+1))
		if a.Err != nil {
			break
		}
		if a.Lock != "" {
			// 有人机验证/锁定：这项本来要测的弱点不存在，如实记「测了、没问题」
			return scan.OK(p.used())
		}
		got = append(got, a)
	}
	if len(got) < 3 {
		return scan.Skip(fmt.Sprintf("探测预算不足，仅完成 %d 次失败尝试", len(got)))
	}

	same := got[0].Status == got[1].Status &&
		got[1].Status == got[2].Status &&
		got[0].Sig == got[1].Sig &&
		got[1].Sig == got[2].Sig
	if !same {
		// 三次响应不一致：可能有随机 nonce，也可能已有失败计数。不下结论。
		return scan.OK(p.used())
	}
	for _, a := range got {
		if a.Captcha {
			return scan.OK(p.used())
		}
	}

	extra := map[string]interface{}{
		"path":     pathOf(ep.URL),
		"endpoint": ep.URL,
		"attempts": 3,
		"status":   got[0].Status,
		"len":      got[0].Len,
		"marker":   got[0].Sig,
	}
	f := model.NewFinding("authz/weak-password-policy",
		"登录接口缺少验证码/锁定防护", "low", ctx.Base, model.FindingOpts{
			Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
			Level: "L1", Confidence: "confirmed",
			Evidence: fmt.Sprintf(
				"对 %s 连续 3 次错误口令（账号 %s）：3 次失败响应无差异（HTTP %d / %d 字节 / 指纹 %s），"+
					"响应中未见验证码字段与锁定提示，同一账号可被无限次尝试。",
				ep.URL, ProbeUser, got[0].Status, got[0].Len, got[0].Sig),
			Repro: fmt.Sprintf("for i in 1 2 3; do curl -sS -o /dev/null -w '%%{http_code} %%{size_download}\\n' "+
				"-X POST '%s' -d '%s=%s&%s=wrong$i'; done", ep.URL, ep.UserField, ProbeUser, ep.PassField),
			Impact: "缺少速率限制/锁定/验证码，攻击者可对同一账号持续猜口令；" +
				"配合弱口令字典（本工具只做 5 次探测，不做真爆破）实际可利用。" +
				"（本条未尝试任何真实口令，不代表口令强度足够。）",
			Fix:     "登录接口加失败计数与账号锁定（如 5 次失败锁定 15 分钟）、逐步引入验证码、按账号与源 IP 双维度限速，并对失败登录告警。",
			CVSS:    "3.7",
			TitleEN: "No Captcha or Lockout on Login Endpoint",
			Extra:   extra,
		})
	return scan.OK(p.used(), f)
}

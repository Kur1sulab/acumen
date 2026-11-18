package framework

// A 组：框架指纹识别。
//
// 本组全部是「识别」：severity 只允许 info / low，Level 固定 L1，Name 一律带 (detect)。
// 命中判据分两类，证据里必须能看出用的是哪一类：
//
//   - 结构类：Set-Cookie 是否回写、响应头字段、状态码、路径响应与基线是否不同。
//     这类特征不依赖「产品词」，但每条都要么有同路径对照（不带 cookie 的请求），
//     要么有随机路径对照（distinct / served）。
//   - 文本类：产品独有串。一律要求「随机路径的基线响应里没有这个串」才算命中；
//     spring 的 "Whitelabel Error Page" 是唯一例外 —— 它本身就是 Spring Boot
//     默认错误页的标题，出现在 404 页里恰恰是证据，代码里显式标注。
//
// 不下的结论：版本号、是否存在已知 RCE、rememberMe 是否可反序列化。那些在 B 组或人工。

import (
	"fmt"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		shiroDetect,
		fastjsonDetect,
		springDetect,
		struts2Detect,
		thinkphpDetect,
		weblogicDetect,
		tomcatDetect,
		weaverDetect,
		seeyonDetect,
		landrayDetect,
	)
}

// detectMeta 指纹项的元信息：统一 A06（安全配置错误）与 CWE-200（信息暴露），
// 因为「组件可见」本身只是信息暴露，不是漏洞。
func detectMeta(name, title, severity string) scan.Meta {
	return scan.Meta{
		Name: name, Family: Family, Title: title, Severity: severity,
		Owasp: "A06:2021", CWE: "CWE-200",
	}
}

// pathResp 一个「路径 → 响应」对，给批量特征串扫描用。
type pathResp struct {
	path string
	r    *httpc.Response
}

// markerHits 在若干响应里找产品特征串。
//
// 规则：第一个出现该串的响应算「命中位置」；但只要随机路径基线里也有这个串，
// 就降级为「忽略」，并在证据里写明原因 —— 这是本包防误报的主闸门。
func (p *probe) markerHits(resps []pathResp, markers []string) (hits, notes []string) {
	for _, m := range markers {
		found := ""
		for _, pr := range resps {
			if w := whereMarker(pr.r, m); w != "" {
				found = fmt.Sprintf("GET %s（%s）", pr.path, w)
				break
			}
		}
		if found == "" {
			continue
		}
		if !p.admit(m) {
			notes = append(notes, fmt.Sprintf("  忽略 %q：%s 出现，但随机路径基线里同样有该串（通用词，不计指纹）", m, found))
			continue
		}
		hits = append(hits, m)
		notes = append(notes, fmt.Sprintf("  命中 %q：%s", m, found))
	}
	return hits, notes
}

// ---------------------------------------------------------------- A1 Shiro

var shiroDetect = scan.Check{
	Meta: detectMeta("framework/shiro-detect", "Apache Shiro 组件指纹识别 (detect)", "info"),
	Run:  runShiroDetect,
}

func runShiroDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 Shiro 指纹识别")
	}
	lines := []string{p.controlLine()}

	// 同路径对照：不带 rememberMe 的请求。Shiro 的「回写 rememberMe」必须由
	// 客户端先带这个 cookie 才触发；站点本来就无条件下发的话不算指纹。
	plain := p.get("/")
	withCookie := p.getH("/", httpc.H("Cookie", "rememberMe=deleteMe"))
	plainCookie := strings.Join(setCookieNamed(plain, "rememberMe"), " | ")
	probeCookie := strings.Join(setCookieNamed(withCookie, "rememberMe"), " | ")

	lines = append(lines, p.line("GET", "/（对照：不带 Cookie）", plain))
	lines = append(lines, p.line("GET", "/（Cookie: rememberMe=deleteMe）", withCookie))
	if probeCookie != "" {
		lines = append(lines, "  响应 Set-Cookie: "+clip(probeCookie, 160))
	}
	if plainCookie != "" {
		lines = append(lines, "  对照请求的 Set-Cookie: "+clip(plainCookie, 160))
	}

	// Shiro 的签名值是 deleteMe：不是「任何同名 cookie 回写」都算，
	// 否则自定义 remember-me 实现也会被认成 Shiro。
	cookieHit := probeCookie != "" && containsFold(probeCookie, "deleteMe") && plainCookie == ""
	if cookieHit {
		lines = append(lines, "  判定：只有带 rememberMe 的请求被回写 rememberMe=deleteMe —— Shiro 清除无效 rememberMe 的默认行为")
	}

	// /login.jsp;jsessionid= 形态：只算弱指纹（任何 Java 容器都接受 URL 重写会话）。
	jsPath := "/login.jsp;jsessionid=" + randToken(16)
	js := p.get(jsPath)
	jsCookie := strings.Join(setCookieNamed(js, "JSESSIONID"), " | ")
	jsHit := jsCookie != "" && p.admit("JSESSIONID") && p.distinct(js)
	lines = append(lines, p.line("GET", jsPath, js))
	if jsCookie != "" {
		note := "基线里没有 JSESSIONID"
		if !p.admit("JSESSIONID") {
			note = "基线里同样下发 JSESSIONID，不能作为指纹"
		}
		lines = append(lines, "  响应 Set-Cookie: "+clip(jsCookie, 120)+"；"+note)
	}

	var fs []*model.Finding
	switch {
	case cookieHit:
		if jsHit {
			lines = append(lines, "  旁证："+jsPath+" 可达且下发 JSESSIONID（Java 会话 URL 重写）")
		}
		lines = append(lines, "说明：本项只识别组件。未验证 Shiro 版本、未验证 rememberMe 密钥、未发送任何反序列化链。")
		fs = append(fs, p.finding(findingSpec{
			check: "framework/shiro-detect", name: "Apache Shiro 组件指纹 (detect)",
			severity: "info", confidence: "confirmed",
			titleEN:  "Apache Shiro detected (fingerprint only)",
			evidence: strings.Join(lines, "\n"),
			repro:    "curl -si -H 'Cookie: rememberMe=deleteMe' " + p.url("/"),
			impact: "仅确认目标是 Apache Shiro 应用。Shiro <1.2.5 存在硬编码 rememberMe 密钥（Shiro-550），" +
				"<1.7.1 存在 Padding Oracle（Shiro-721）；是否可利用需另行验证，本项不下结论。",
			fix:     "确认 Shiro 版本并升级到 >=1.7.1；轮换 rememberMe 密钥；不需要 rememberMe 就关闭。",
			path:    "/",
			markers: []string{"Set-Cookie: rememberMe"},
			extra:   map[string]interface{}{"product": "Apache Shiro", "jsessionid_style_url": jsHit},
		}))
	case jsHit:
		lines = append(lines, "说明：/login.jsp;jsessionid= 是 Shiro 常见部署形态，但任何 Java Web 容器都接受 "+
			"URL 重写会话；本项只记弱指纹，单独不足以确认 Shiro，也不构成漏洞。")
		fs = append(fs, p.finding(findingSpec{
			check: "framework/shiro-detect", name: "Shiro 风格 URL 可达（jsessionid 弱指纹） (detect)",
			severity: "info", confidence: "likely",
			titleEN:  "Shiro-style URL reachable (weak fingerprint)",
			evidence: strings.Join(lines, "\n"),
			repro:    "curl -si '" + p.url(jsPath) + "'",
			impact:   "仅说明目标接受 ;jsessionid= 形态的会话 URL（Java 容器常见），不等同于 Shiro，也不构成漏洞。",
			fix:      "无需处置；若怀疑是 Shiro，按 shiro-detect 的 rememberMe 主特征复核。",
			path:     jsPath,
			markers:  []string{"Set-Cookie: JSESSIONID", "/login.jsp;jsessionid="},
			extra:    map[string]interface{}{"product": "Java Web", "weak": true},
		}))
	}
	return p.result(fs)
}

// ---------------------------------------------------------------- A2 fastjson

var fastjsonDetect = scan.Check{
	Meta: detectMeta("framework/fastjson-detect", "fastjson 组件指纹识别 (detect)", "info"),
	Run:  runFastjsonDetect,
}

func runFastjsonDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 fastjson 指纹识别")
	}
	lines := []string{p.controlLine()}

	// 两条对照：
	//  1) 合法 JSON —— 证明「会报错」不是这个端点的常态；
	//  2) 随机路径基线 —— 证明特征串不是站点模板里的通用词。
	// 探针只发类型名，不构造任何 gadget，也不会命中业务实体（没有业务字段）。
	clean := p.postJSON("/", `{"litmus":"probe"}`)
	malformed := p.postJSON("/", `{"@type":"java.lang.AutoType"}`)
	lines = append(lines, p.line("POST", "/（对照：合法 JSON）", clean))
	lines = append(lines, p.line("POST", "/（畸形 @type）", malformed))

	markers := []string{"autoType is not support", "com.alibaba.fastjson", "JSONException"}
	var matched []string
	for _, m := range markers {
		w := whereMarker(malformed, m)
		if w == "" {
			continue
		}
		if whereMarker(clean, m) != "" {
			lines = append(lines, fmt.Sprintf("  忽略 %q：合法 JSON 的对照响应里也有该串", m))
			continue
		}
		if !p.admit(m) {
			lines = append(lines, fmt.Sprintf("  忽略 %q：随机路径基线里也有该串（通用词）", m))
			continue
		}
		matched = append(matched, m)
		lines = append(lines, fmt.Sprintf("  命中 %q（%s），两个对照都不含该串", m, w))
	}
	if len(matched) == 0 {
		lines = append(lines, "  未命中：响应里没有 fastjson 特征串（或该串在对照/基线里同样出现）")
		if s := p.snippet(malformed, 200); s != "" {
			lines = append(lines, "  畸形 JSON 的响应正文："+s)
		}
		return p.result(nil)
	}
	if s := p.snippet(malformed, 240); s != "" {
		lines = append(lines, "  响应正文："+s)
	}
	lines = append(lines, "说明：仅用类型名触发解析报错。报文不含任何 gadget / 序列化链，也不是业务写操作；"+
		"本项不判断 AutoType 是否可绕过。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/fastjson-detect", name: "fastjson 组件指纹 (detect)",
		severity: "info", confidence: "confirmed",
		titleEN:  "fastjson detected via autotype error (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro: "curl -si -X POST -H 'Content-Type: application/json' " +
			"--data '{\"@type\":\"java.lang.AutoType\"}' " + p.url("/"),
		impact: "仅确认目标使用 fastjson 解析 JSON（报错信息暴露了库名/异常类型）。" +
			"具体版本与 AutoType 绕过能力需另行验证；本项不下 RCE 结论。",
		fix:     "升级 fastjson 到 1.2.83+/2.x 并开启 safeMode；不要在错误响应里回显解析异常。",
		path:    "/",
		markers: matched,
		extra:   map[string]interface{}{"product": "fastjson", "post_body": `{"@type":"java.lang.AutoType"}`},
	})})
}

// ---------------------------------------------------------------- A3 Spring

var springDetect = scan.Check{
	Meta: detectMeta("framework/spring-detect", "Spring / Spring Boot 组件指纹识别 (detect)", "info"),
	Run:  runSpringDetect,
}

func runSpringDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 Spring 指纹识别")
	}
	lines := []string{p.controlLine()}
	b := p.control()

	root := p.get("/")
	login := p.get("/login")
	act := p.get("/actuator")
	lines = append(lines, p.line("GET", "/", root))
	lines = append(lines, p.line("GET", "/login", login))
	lines = append(lines, p.line("GET", "/actuator", act))

	var signals, markers []string

	// 结构类 1：Spring Boot / Cloud 会在响应头回带 X-Application-Context。
	if headerHasToken(root, "x-application-context", "application") ||
		headerHasToken(root, "x-application-context", "boot") ||
		(root != nil && root.Header("x-application-context") != "") ||
		(login != nil && login.Header("x-application-context") != "") {
		signals = append(signals, "响应头含 X-Application-Context")
		markers = append(markers, "X-Application-Context")
	}

	// 文本类（强）：Whitelabel Error Page 是 Spring Boot 默认错误页的页面标题。
	// 它是本包唯一允许「基线里也有」的特征：随机路径返回这个页面，本身就是证据。
	if b.err == nil && b.has("Whitelabel Error Page") {
		signals = append(signals, "随机路径错误页是 Spring Boot 默认错误页（Whitelabel Error Page）")
		markers = append(markers, "Whitelabel Error Page")
		lines = append(lines, "  基线页面正文："+clip(b.snip, 200))
	}

	// 结构类 2：/actuator 根端点可读且返回 _links（HAL 风格）。
	if act != nil && act.Err == nil && act.Status == 200 && p.distinct(act) &&
		looksJSON(act) && containsFold(bodyOf(act), "_links") && p.admit("_links") {
		signals = append(signals, "/actuator 可匿名访问并返回 _links 端点清单")
		markers = append(markers, "_links")
		if s := p.snippet(act, 200); s != "" {
			lines = append(lines, "  /actuator 正文："+s)
		}
	}

	// 结构类 3：Spring Security 默认登录页（Please sign in + form-signin/username 表单）。
	if login != nil && login.Err == nil && login.Status == 200 && p.admit("Please sign in") &&
		containsFold(bodyOf(login), "Please sign in") &&
		(containsFold(bodyOf(login), "form-signin") || containsFold(bodyOf(login), `name="username"`)) {
		signals = append(signals, "Spring Security 默认登录页（Please sign in + username 表单）")
		markers = append(markers, "Please sign in")
	}

	if len(signals) == 0 {
		lines = append(lines, "  未命中：无 X-Application-Context、无 Whitelabel 错误页、/actuator 与 /login 也不像 Spring 默认页")
		return p.result(nil)
	}
	for _, s := range signals {
		lines = append(lines, "  信号："+s)
	}
	lines = append(lines, "说明：本项只识别框架。actuator 是否还暴露 env/heapdump、Spring Security 是否有默认口令，均需另行检查。")
	conf := "likely"
	if len(signals) >= 2 {
		conf = "confirmed"
	}
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/spring-detect", name: "Spring / Spring Boot 组件指纹 (detect)",
		severity: "info", confidence: conf,
		titleEN:  "Spring / Spring Boot detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/") + " ; curl -si " + p.url("/actuator"),
		impact: "仅确认目标是 Spring 技术栈。Spring Boot actuator 若未鉴权可能泄露配置/堆转储，" +
			"但本项只做组件识别，不对具体端点下漏洞结论。",
		fix:     "收敛 management.endpoints.web.exposure.include，关闭不需要的 actuator 端点；对外统一错误页。",
		path:    "/",
		markers: markers,
		extra:   map[string]interface{}{"product": "Spring", "signals": signals},
	})})
}

// ---------------------------------------------------------------- A4 Struts2

var struts2Detect = scan.Check{
	Meta: detectMeta("framework/struts2-detect", "Struts2 组件指纹识别 (detect)", "info"),
	Run:  runStruts2Detect,
}

func runStruts2Detect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 Struts2 指纹识别")
	}
	lines := []string{p.controlLine()}

	action := p.get("/index.action")
	doPath := p.get("/index.do")
	static := p.get("/struts/utils.js")
	lines = append(lines, p.line("GET", "/index.action", action))
	lines = append(lines, p.line("GET", "/index.do", doPath))
	lines = append(lines, p.line("GET", "/struts/utils.js", static))

	markers := []string{
		"Struts Problem Report", "org.apache.struts2", "struts2",
		"OGNL", "No result defined for action", "struts",
	}
	hits, notes := p.markerHits([]pathResp{
		{"/index.action", action},
		{"/index.do", doPath},
		{"/struts/utils.js", static},
	}, markers)
	lines = append(lines, notes...)

	// 结构类：.action 与 .do 两个后缀都返回「与 404 不同的页面」。
	// 单独一个后缀命中不够（Spring MVC 的 suffix pattern 也会这样），必须两个都在。
	suffixHit := p.served(action) && p.served(doPath)
	if suffixHit {
		lines = append(lines, "  信号：/index.action 与 /index.do 都返回与随机路径不同的页面（*.action / *.do 后缀映射）")
	}
	// 结构类：Struts2 的静态资源目录。
	staticHit := p.served(static) && (headerHasToken(static, "content-type", "javascript") ||
		containsFold(bodyOf(static), "Struts"))
	if staticHit {
		lines = append(lines, "  信号：/struts/utils.js 可访问（Struts2 默认静态资源目录）")
	}

	if len(hits) == 0 && !suffixHit && !staticHit {
		lines = append(lines, "  未命中：没有 Struts 特征串，.action/.do 也不构成独立页面")
		return p.result(nil)
	}

	conf := "likely"
	for _, h := range hits {
		if h == "Struts Problem Report" || h == "org.apache.struts2" || h == "No result defined for action" {
			conf = "confirmed"
		}
	}
	if len(hits) >= 2 {
		conf = "confirmed"
	}
	lines = append(lines, "说明：本项只识别 Struts2。OGNL 报错特征只作为指纹，未发送任何 OGNL 表达式，"+
		"不判断 S2-xxx 是否可利用。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/struts2-detect", name: "Apache Struts2 组件指纹 (detect)",
		severity: "info", confidence: conf,
		titleEN:  "Apache Struts2 detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/index.action") + " ; curl -si " + p.url("/struts/utils.js"),
		impact: "仅确认目标使用 Struts2（或至少暴露 *.action/*.do 映射）。" +
			"Struts2 历史 OGNL 注入漏洞多，但版本与可利用性未在本项验证。",
		fix:     "确认 Struts2 版本并升级到当前受支持版本；关闭 devMode；生产环境不要回显 OGNL 异常栈。",
		path:    "/index.action",
		markers: hits,
		extra:   map[string]interface{}{"product": "Apache Struts2", "suffix_mapping": suffixHit, "static_dir": staticHit},
	})})
}

// ---------------------------------------------------------------- A5 ThinkPHP

var thinkphpDetect = scan.Check{
	Meta: detectMeta("framework/thinkphp-detect", "ThinkPHP 组件指纹识别 (detect)", "info"),
	Run:  runThinkphpDetect,
}

func runThinkphpDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 ThinkPHP 指纹识别")
	}
	lines := []string{p.controlLine()}

	root := p.get("/")
	route := p.get("/index.php?s=/index/index")
	index := p.get("/index.php")
	lines = append(lines, p.line("GET", "/", root))
	lines = append(lines, p.line("GET", "/index.php?s=/index/index", route))
	lines = append(lines, p.line("GET", "/index.php", index))

	var signals, markers []string

	// 结构类（强）：X-Powered-By 直接写 ThinkPHP。
	for _, r := range []*httpc.Response{root, route, index} {
		if headerHasToken(r, "x-powered-by", "ThinkPHP") {
			signals = append(signals, "响应头 X-Powered-By 含 ThinkPHP")
			markers = append(markers, "X-Powered-By: ThinkPHP")
			break
		}
	}

	// 文本类：ThinkPHP 字样。必须是基线里没有的，否则就是通用词。
	hits, notes := p.markerHits([]pathResp{
		{"/", root}, {"/index.php?s=/index/index", route}, {"/index.php", index},
	}, []string{"ThinkPHP"})
	lines = append(lines, notes...)
	if len(hits) > 0 {
		signals = append(signals, "页面含 ThinkPHP 字样（基线不含）")
		markers = append(markers, hits...)
	}

	// 结构类：/index.php?s=/ 路由形态 + PHP 会话 cookie。
	// 单看 ?s= 200 不够（很多 PHP 站对任意 query 都回同一页），所以要求
	// 正文含 think 或下发 PHPSESSID 之一作为旁证。
	phpSession := len(setCookieNamed(route, "PHPSESSID")) > 0
	routeHit := p.served(route) && (phpSession || containsFold(bodyOf(route), "think"))
	if routeHit {
		detail := "且正文含 think"
		if phpSession {
			detail = "并下发 PHPSESSID"
		}
		signals = append(signals, "/index.php?s=/index/index 返回独立页面"+detail)
		markers = append(markers, "/index.php?s=/")
	}

	if len(signals) == 0 {
		lines = append(lines, "  未命中：无 ThinkPHP 字样 / X-Powered-By，?s= 路由也没有独立页面特征")
		return p.result(nil)
	}
	for _, s := range signals {
		lines = append(lines, "  信号："+s)
	}
	lines = append(lines, "说明：本项只识别 ThinkPHP。版本、调试模式、历史 RCE（如 thinkphp 5.x 参数注入）均未验证。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/thinkphp-detect", name: "ThinkPHP 组件指纹 (detect)",
		severity: "info", confidence: "confirmed",
		titleEN:  "ThinkPHP detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/index.php?s=/index/index"),
		impact:   "仅确认目标使用 ThinkPHP。ThinkPHP 3/5 历史版本存在多处 RCE，但版本与可利用性需另行验证。",
		fix:      "升级到受支持的 ThinkPHP 版本；关闭 app_debug；生产环境隐藏 X-Powered-By。",
		path:     "/index.php?s=/index/index",
		markers:  markers,
		extra:    map[string]interface{}{"product": "ThinkPHP", "signals": signals},
	})})
}

// ---------------------------------------------------------------- A6 WebLogic

var weblogicDetect = scan.Check{
	Meta: detectMeta("framework/weblogic-detect", "WebLogic 组件指纹识别 (detect)", "low"),
	Run:  runWeblogicDetect,
}

func runWeblogicDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 WebLogic 指纹识别")
	}
	lines := []string{p.controlLine()}

	root := p.get("/")
	console := p.get("/console")
	login := p.get("/console/login/LoginForm.jsp")
	lines = append(lines, p.line("GET", "/", root))
	lines = append(lines, p.line("GET", "/console", console))
	lines = append(lines, p.line("GET", "/console/login/LoginForm.jsp", login))

	var signals, markers []string

	// 结构类（强）：Server 头直接自报 WebLogic。
	for _, r := range []*httpc.Response{root, console, login} {
		if headerHasToken(r, "server", "WebLogic") {
			signals = append(signals, "响应头 Server 含 WebLogic")
			markers = append(markers, "Server: WebLogic")
			break
		}
	}
	// 结构类（强）：/console 302 到登录表单。
	if console != nil && (containsFold(console.Header("location"), "LoginForm.jsp") ||
		containsFold(console.Header("location"), "/console/")) {
		signals = append(signals, "/console 跳转到 WebLogic 管理控制台登录页")
		markers = append(markers, "Location: /console/login/LoginForm.jsp")
	}
	// 文本类：产品独有页面标题（强），以及裸 "WebLogic"（要求基线不含）。
	if (whereMarker(login, "Oracle WebLogic Server Administration Console") != "" ||
		whereMarker(console, "Oracle WebLogic Server Administration Console") != "") &&
		p.admit("Oracle WebLogic Server Administration Console") {
		signals = append(signals, "控制台页面标题为 Oracle WebLogic Server Administration Console")
		markers = append(markers, "Oracle WebLogic Server Administration Console")
	}
	hits, notes := p.markerHits([]pathResp{{"/console", console}, {"/", root}}, []string{"WebLogic"})
	lines = append(lines, notes...)
	if len(hits) > 0 {
		signals = append(signals, "页面含 WebLogic 字样（基线不含）")
		markers = append(markers, hits...)
	}

	if len(signals) == 0 {
		lines = append(lines, "  未命中：/console 无控制台特征，Server 头也不含 WebLogic")
		return p.result(nil)
	}
	for _, s := range signals {
		lines = append(lines, "  信号："+s)
	}
	lines = append(lines, "说明：本项只识别 WebLogic。控制台是否弱口令、是否受 IIOP/T3 反序列化影响，均未验证。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/weblogic-detect", name: "Oracle WebLogic 组件指纹 (detect)",
		severity: "low", confidence: "confirmed",
		titleEN:  "Oracle WebLogic detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/console"),
		impact: "仅确认目标是 WebLogic（管理控制台可达本身扩大了攻击面：弱口令、T3/IIOP 反序列化历史漏洞）。" +
			"本项不判断任何 CVE 是否可利用。",
		fix:     "管理控制台不要暴露到非管理网段；升级到最新补丁集；启用 T3/IIOP 过滤。",
		path:    "/console",
		markers: markers,
		extra:   map[string]interface{}{"product": "Oracle WebLogic", "signals": signals},
	})})
}

// ---------------------------------------------------------------- A7 Tomcat

var tomcatDetect = scan.Check{
	Meta: detectMeta("framework/tomcat-detect", "Apache Tomcat 组件指纹识别 (detect)", "info"),
	Run:  runTomcatDetect,
}

func runTomcatDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做 Tomcat 指纹识别")
	}
	lines := []string{p.controlLine()}

	root := p.get("/")
	manager := p.get("/manager/html")
	lines = append(lines, p.line("GET", "/", root))
	lines = append(lines, p.line("GET", "/manager/html", manager))

	var signals, markers []string

	// 结构类（强）：Coyote 是 Tomcat 的 HTTP 连接器，Server 头几乎只有它会这么写。
	if headerHasToken(root, "server", "Apache-Coyote") || headerHasToken(root, "server", "Apache Tomcat") ||
		headerHasToken(manager, "server", "Apache-Coyote") {
		signals = append(signals, "响应头 Server 含 Apache-Coyote / Apache Tomcat")
		markers = append(markers, "Server: Apache-Coyote")
	}
	// 文本类（强）：默认页标题 "Apache Tomcat/9.0.x"。
	if whereMarker(root, "Apache Tomcat") != "" && p.admit("Apache Tomcat") {
		signals = append(signals, "默认页含 Apache Tomcat（Tomcat 默认欢迎页）")
		markers = append(markers, "Apache Tomcat")
	}
	// 结构类（强）：/manager/html 401 + Basic realm="Tomcat Manager Application"。
	if manager != nil && manager.Status == 401 &&
		headerHasToken(manager, "www-authenticate", "Tomcat Manager") &&
		p.admit("Tomcat Manager Application") {
		signals = append(signals, "/manager/html 返回 401 且 realm 为 Tomcat Manager Application")
		markers = append(markers, `realm="Tomcat Manager Application"`)
	}
	// 文本类（弱）：裸 Tomcat，要求基线不含。
	hits, notes := p.markerHits([]pathResp{{"/", root}}, []string{"Tomcat"})
	lines = append(lines, notes...)
	if len(hits) > 0 {
		signals = append(signals, "页面含 Tomcat 字样（基线不含）")
		markers = append(markers, hits...)
	}

	if len(signals) == 0 {
		lines = append(lines, "  未命中：无 Apache-Coyote / 默认页 / manager 认证特征")
		return p.result(nil)
	}
	for _, s := range signals {
		lines = append(lines, "  信号："+s)
	}
	lines = append(lines, "说明：本项只识别 Tomcat。manager 是否弱口令、AJP 是否暴露等均未验证。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/tomcat-detect", name: "Apache Tomcat 组件指纹 (detect)",
		severity: "info", confidence: "confirmed",
		titleEN:  "Apache Tomcat detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/manager/html"),
		impact: "仅确认目标是 Tomcat。/manager 与 /host-manager 暴露会扩大弱口令与部署接口的攻击面，" +
			"但本项不对其可利用性下结论。",
		fix:     "升级 Tomcat；/manager 与 /host-manager 限制来源 IP；删除默认应用与默认账号。",
		path:    "/manager/html",
		markers: markers,
		extra:   map[string]interface{}{"product": "Apache Tomcat", "signals": signals},
	})})
}

// ---------------------------------------------------------------- A8 泛微 e-cology

var weaverDetect = scan.Check{
	Meta: detectMeta("framework/weaver-detect", "泛微 e-cology 指纹识别 (detect)", "low"),
	Run:  runWeaverDetect,
}

func runWeaverDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做泛微 e-cology 指纹识别")
	}
	lines := []string{p.controlLine()}

	root := p.get("/")
	login := p.get("/login/Login.jsp")
	weaverPath := p.get("/weaver/")
	lines = append(lines, p.line("GET", "/", root))
	lines = append(lines, p.line("GET", "/login/Login.jsp", login))
	lines = append(lines, p.line("GET", "/weaver/", weaverPath))

	var signals, markers []string
	hits, notes := p.markerHits([]pathResp{
		{"/login/Login.jsp", login}, {"/weaver/", weaverPath}, {"/", root},
	}, []string{"weaver", "e-cology", "ecology", "泛微"})
	lines = append(lines, notes...)
	if len(hits) > 0 {
		signals = append(signals, "页面含泛微特征串："+strings.Join(hits, ", "))
		markers = append(markers, hits...)
	}

	// 结构类：/weaver/ 与 /login/Login.jsp 都是独立页面。
	// 单条路径可能是巧合（很多 OA 都用 /login/Login.jsp），所以要求两条同时成立。
	if p.served(weaverPath) && p.served(login) {
		signals = append(signals, "/weaver/ 与 /login/Login.jsp 都返回独立页面（e-cology 默认部署形态）")
		markers = append(markers, "/weaver/", "/login/Login.jsp")
	}

	if len(signals) == 0 {
		lines = append(lines, "  未命中：无 weaver 特征串，默认路径也没有独立页面")
		return p.result(nil)
	}
	for _, s := range signals {
		lines = append(lines, "  信号："+s)
	}
	conf := "likely"
	if len(hits) > 0 {
		conf = "confirmed"
	}
	lines = append(lines, "说明：本项只识别泛微 e-cology。历史版本存在多处未授权 SQL 注入/文件上传/反序列化问题，"+
		"但版本与可利用性未在本项验证。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/weaver-detect", name: "泛微 e-cology 指纹 (detect)",
		severity: "low", confidence: conf,
		titleEN:  "Weaver e-cology detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/login/Login.jsp") + " ; curl -si " + p.url("/weaver/"),
		impact: "仅确认疑似泛微 e-cology。该类 OA 历史上多次出现未授权访问/RCE，" +
			"但本项只做识别，不对任何具体漏洞下结论。",
		fix:     "把 OA 收到 VPN/内网后面；跟进厂商安全补丁；关闭不需要的对外端口。",
		path:    "/login/Login.jsp",
		markers: markers,
		extra:   map[string]interface{}{"product": "Weaver e-cology", "signals": signals},
	})})
}

// ---------------------------------------------------------------- A9 致远 OA

var seeyonDetect = scan.Check{
	Meta: detectMeta("framework/seeyon-detect", "致远 OA 指纹识别 (detect)", "low"),
	Run:  runSeeyonDetect,
}

func runSeeyonDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做致远 OA 指纹识别")
	}
	lines := []string{p.controlLine()}

	root := p.get("/")
	seeyonRoot := p.get("/seeyon/")
	seeyonIndex := p.get("/seeyon/index.jsp")
	lines = append(lines, p.line("GET", "/", root))
	lines = append(lines, p.line("GET", "/seeyon/", seeyonRoot))
	lines = append(lines, p.line("GET", "/seeyon/index.jsp", seeyonIndex))

	var signals, markers []string
	hits, notes := p.markerHits([]pathResp{
		{"/seeyon/", seeyonRoot}, {"/seeyon/index.jsp", seeyonIndex}, {"/", root},
	}, []string{"seeyon", "Seeyon", "致远", "协同管理"})
	lines = append(lines, notes...)
	if len(hits) > 0 {
		signals = append(signals, "页面含致远特征串："+strings.Join(hits, ", "))
		markers = append(markers, hits...)
	}

	// 结构类：/seeyon/ 跳转或独立页面 + /seeyon/index.jsp 可访问。
	if (p.served(seeyonRoot) || containsFold(seeyonRoot.Header("location"), "/seeyon")) && p.served(seeyonIndex) {
		signals = append(signals, "/seeyon/ 与 /seeyon/index.jsp 都是致远默认部署路径")
		markers = append(markers, "/seeyon/", "/seeyon/index.jsp")
	}

	if len(signals) == 0 {
		lines = append(lines, "  未命中：无 seeyon 特征串，/seeyon/ 路径也没有独立页面")
		return p.result(nil)
	}
	for _, s := range signals {
		lines = append(lines, "  信号："+s)
	}
	conf := "likely"
	if len(hits) > 0 {
		conf = "confirmed"
	}
	lines = append(lines, "说明：本项只识别致远 OA。历史版本存在未授权访问/文件上传等公开漏洞，但本项不验证版本与可利用性。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/seeyon-detect", name: "致远 OA 指纹 (detect)",
		severity: "low", confidence: conf,
		titleEN:  "Seeyon OA detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/seeyon/") + " ; curl -si " + p.url("/seeyon/index.jsp"),
		impact:   "仅确认疑似致远 OA。该类系统历史漏洞多，但本项只做识别，不对具体漏洞下结论。",
		fix:      "OA 限制在 VPN/内网；跟进厂商补丁；关闭不必要的对外映射。",
		path:     "/seeyon/index.jsp",
		markers:  markers,
		extra:    map[string]interface{}{"product": "Seeyon OA", "signals": signals},
	})})
}

// ---------------------------------------------------------------- A10 蓝凌 OA

var landrayDetect = scan.Check{
	Meta: detectMeta("framework/landray-detect", "蓝凌 OA 指纹识别 (detect)", "low"),
	Run:  runLandrayDetect,
}

func runLandrayDetect(c *scan.Ctx) scan.Result {
	p := newProbe(c)
	if p.base == "" {
		return scan.Skip("无 Web 根（Base 为空），未做蓝凌 OA 指纹识别")
	}
	lines := []string{p.controlLine()}

	root := p.get("/")
	sysUI := p.get("/sys/ui/")
	css := p.get("/sys/ui/extend/theme/default/style.css")
	lines = append(lines, p.line("GET", "/", root))
	lines = append(lines, p.line("GET", "/sys/ui/", sysUI))
	lines = append(lines, p.line("GET", "/sys/ui/extend/theme/default/style.css", css))

	var signals, markers []string
	hits, notes := p.markerHits([]pathResp{
		{"/sys/ui/", sysUI}, {"/sys/ui/extend/theme/default/style.css", css}, {"/", root},
	}, []string{"kmss", "landray", "Landray", "蓝凌"})
	lines = append(lines, notes...)
	if len(hits) > 0 {
		signals = append(signals, "页面含蓝凌特征串："+strings.Join(hits, ", "))
		markers = append(markers, hits...)
	}

	// 结构类：/sys/ui/ 独立页面 + 默认主题静态资源（text/css）。
	if p.served(sysUI) && css != nil && css.Err == nil && css.Status == 200 &&
		headerHasToken(css, "content-type", "css") {
		signals = append(signals, "/sys/ui/ 与默认主题 style.css 均可访问（蓝凌默认前端路径）")
		markers = append(markers, "/sys/ui/", "/sys/ui/extend/theme/default/style.css")
	}
	// 结构类：kmss 是蓝凌内部产品代号，出现在任何响应里都算强特征，
	// 但仍走 admit —— 避免把「kmss」当成普通英文出现在模板里时误报。
	if whereMarker(sysUI, "kmss") != "" || whereMarker(root, "kmss") != "" {
		if p.admit("kmss") && !containsIn(hits, "kmss") {
			signals = append(signals, "响应含 kmss（蓝凌产品代号）")
			hits = append(hits, "kmss")
			markers = append(markers, "kmss")
		}
	}

	if len(signals) == 0 {
		lines = append(lines, "  未命中：无 kmss/蓝凌特征串，/sys/ui/ 也不像蓝凌前端目录")
		return p.result(nil)
	}
	for _, s := range signals {
		lines = append(lines, "  信号："+s)
	}
	conf := "likely"
	if len(hits) > 0 {
		conf = "confirmed"
	}
	lines = append(lines, "说明：本项只识别蓝凌 OA（EKP）。历史版本存在未授权 SQL 注入/文件读取等问题，"+
		"本项不验证版本与可利用性。")
	return p.result([]*model.Finding{p.finding(findingSpec{
		check: "framework/landray-detect", name: "蓝凌 OA 指纹 (detect)",
		severity: "low", confidence: conf,
		titleEN:  "Landray OA detected (fingerprint only)",
		evidence: strings.Join(lines, "\n"),
		repro:    "curl -si " + p.url("/sys/ui/") + " ; curl -si " + p.url("/sys/ui/extend/theme/default/style.css"),
		impact:   "仅确认疑似蓝凌 OA（EKP）。该类系统历史漏洞多，但本项只做识别，不对具体漏洞下结论。",
		fix:      "OA 限制在 VPN/内网；跟进厂商补丁；不要暴露 /sys/ 目录到公网。",
		path:     "/sys/ui/",
		markers:  markers,
		extra:    map[string]interface{}{"product": "Landray EKP", "signals": signals},
	})})
}

func containsIn(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

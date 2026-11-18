// 前端面：硬编码密钥、source map 泄露、上传点登记。
//
// 三项都从 ctx.URLs（爬虫落点）出发，但只碰**同源**资源：跨域 CDN 上的 JS 属于
// 第三方资产，不在授权范围内，扫它就是把客户变成原告。
//
// 密钥项的纪律比别处更硬：命中即打码，Evidence / Extra / 日志里只允许出现
// 前 4 位 + ****。报告是要交出去的，贴出可用的 AK 等于我们自己制造了二次泄露。
package exposure

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/frontend-secret", Family: "exposure",
				Title:    "前端 JS 硬编码密钥",
				Severity: "high",
				Owasp:    "A02:2021 加密机制失效",
				CWE:      "CWE-798",
			},
			Run: guard("exposure/frontend-secret", ChkFrontendSecret),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/source-map", Family: "exposure",
				Title:    "前端 source map 泄露",
				Severity: "medium",
				Owasp:    "A05:2021 安全配置错误",
				CWE:      "CWE-540",
			},
			Run: guard("exposure/source-map", ChkSourceMap),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/file-upload-form", Family: "exposure",
				Title:    "上传点发现",
				Severity: "info",
				Owasp:    "A04:2021 不安全设计",
				CWE:      "CWE-434",
			},
			Run: guard("exposure/file-upload-form", ChkFileUploadForm),
		},
	)
}

// ---------------------------------------------------------------- 同源脚本收集

// scriptRef 一个同源 JS 文件
type scriptRef struct {
	URL  string
	Body string
}

func isScriptURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	return strings.HasSuffix(strings.ToLower(p.Path), ".js")
}

// isHTMLish 值得当页面解析的 URL（其余是图片/CSS/接口，爬了也没表单）
func isHTMLish(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	path := strings.ToLower(p.Path)
	if path == "" || strings.HasSuffix(path, "/") {
		return true
	}
	i := strings.LastIndexByte(path, '/')
	seg := path[i+1:]
	j := strings.LastIndexByte(seg, '.')
	if j < 0 {
		return true // 无扩展名：多半是路由
	}
	switch seg[j:] {
	case ".html", ".htm", ".shtml", ".php", ".jsp", ".jspx", ".asp",
		".aspx", ".do", ".action", ".cgi", ".xhtml":
		return true
	}
	return false
}

// sameHost 同源判定（只比主机名：同机不同端口/协议仍是客户自己的资产）
func sameHost(a, b string) bool {
	ua, err1 := url.Parse(httpc.NormURL(a))
	ub, err2 := url.Parse(httpc.NormURL(b))
	if err1 != nil || err2 != nil {
		return false
	}
	ha, hb := strings.ToLower(ua.Hostname()), strings.ToLower(ub.Hostname())
	return ha != "" && ha == hb
}

var scriptSrcRe = regexp.MustCompile(`(?is)<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))`)

// scriptSrcs 页面里的 <script src>（含无引号写法 —— 畸形页面很常见）
func scriptSrcs(html string) []string {
	var out []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		for i := 1; i < len(m); i++ {
			if s := strings.TrimSpace(m[i]); s != "" {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// collectScripts 收集同源 JS 并取回内容。
//
// 返回 (脚本列表, 实际发出的请求数)。ctx.URLs 为空时仍会抓目标首页找 <script src>，
// 否则「爬虫没跑」会直接把这项变成一份假的 ok。
func collectScripts(c *scan.Ctx, b *budget, max int) ([]scriptRef, int, bool) {
	if max <= 0 {
		max = 12
	}
	var urls []string
	seen := map[string]bool{}
	add := func(u string) {
		u = httpc.NormURL(strings.TrimSpace(u))
		if u == "" || seen[u] || len(urls) >= max {
			return
		}
		if !isScriptURL(u) || !sameHost(u, baseOf(c)) {
			return
		}
		seen[u] = true
		urls = append(urls, u)
	}
	if c != nil {
		for _, u := range c.URLs {
			add(u)
		}
	}

	tested := 0
	reachable := false
	if len(urls) < max && b.take() {
		page := probe(c, "GET", urlFor(c, "/"), nil)
		tested++
		if page != nil && page.Err == nil {
			reachable = true
		}
		if page != nil && page.Err == nil && page.Status == 200 {
			for _, src := range scriptSrcs(bodyOf(page)) {
				add(httpc.URLJoin(urlFor(c, "/"), src))
			}
		}
	}

	out := make([]scriptRef, 0, len(urls))
	for _, u := range urls {
		if !b.take() {
			break
		}
		r := probe(c, "GET", u, nil)
		tested++
		if r != nil && r.Err == nil {
			reachable = true
		}
		if r == nil || r.Err != nil || r.Status != 200 || len(r.Body) == 0 {
			continue
		}
		out = append(out, scriptRef{URL: u, Body: bodyOf(r)})
	}
	return out, tested, reachable
}

// ---------------------------------------------------------------- 硬编码密钥

// secretRule 一条前端密钥识别规则
type secretRule struct {
	Label string
	Re    *regexp.Regexp
	Group int // 值所在的捕获组；0 = 整个匹配
}

var secretRules = []secretRule{
	{"阿里云 AccessKeyId", regexp.MustCompile(`LTAI[A-Za-z0-9]{12,}`), 0},
	{"AWS AccessKeyId", regexp.MustCompile(`AKIA[A-Z0-9]{16}`), 0},
	{"通用 sk- 密钥", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), 0},
	{"api key 赋值", regexp.MustCompile(`(?i)api[_-]?key["']?\s*[:=]\s*["']([^"']{16,})["']`), 1},
}

// secretHit 一处命中（Value 只在内存里短暂存在，绝不进 Finding）
type secretHit struct {
	Rule  string
	Line  int
	Value string
}

// scanSecrets 在文本里按规则找凭据，返回命中与去重后的明文值（供打码用）
func scanSecrets(text string) ([]secretHit, []string) {
	var hits []secretHit
	var values []string
	seen := map[string]bool{}
	for _, rule := range secretRules {
		for _, m := range rule.Re.FindAllStringSubmatch(text, -1) {
			if len(m) <= rule.Group {
				continue
			}
			v := m[rule.Group]
			if len(v) < 8 {
				continue // 太短的不当凭据（防把普通字符串统计成密钥）
			}
			key := rule.Label + "|" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			line := 1
			if i := strings.Index(text, v); i > 0 {
				line += strings.Count(text[:i], "\n")
			}
			hits = append(hits, secretHit{Rule: rule.Label, Line: line, Value: v})
			values = append(values, v)
		}
	}
	return hits, values
}

// ChkFrontendSecret 前端硬编码密钥。
func ChkFrontendSecret(c *scan.Ctx) scan.Result {
	b := newBudget(c)
	scripts, tested, reachable := collectScripts(c, b, 12)
	if len(scripts) == 0 {
		if !reachable {
			// 一个都没连上 = 没测，不能报 ok
			return scan.Skip("目标不可达，未取得任何 JS，前端密钥未判定")
		}
		return okN(tested, "未发现同源 JS 文件（URLs 与首页 <script src> 均为空）")
	}

	var fs []*model.Finding
	for _, s := range scripts {
		hits, values := scanSecrets(s.Body)
		if len(hits) == 0 {
			continue
		}
		var lines []string
		var types []string
		extraHits := make([]map[string]interface{}, 0, len(hits))
		seenType := map[string]bool{}
		for _, h := range hits {
			masked := maskSecret(h.Value)
			lines = append(lines, fmt.Sprintf("  - %s（第 %d 行）: %s", h.Rule, h.Line, masked))
			if !seenType[h.Rule] {
				seenType[h.Rule] = true
				types = append(types, h.Rule)
			}
			extraHits = append(extraHits, map[string]interface{}{
				"rule": h.Rule, "line": h.Line, "value_masked": masked,
			})
		}
		// 证据里绝不放原文：这里只放打码值，连上下文行都不贴，
		// 因为上下文里可能还有我们没模式匹配到的其它密钥。
		ev := fmt.Sprintf("GET %s → HTTP 200 | 长度 %dB\n命中 %d 处硬编码凭据（值已打码，只保留前 4 位）:\n%s\n"+
			"说明: 仅做模式匹配，未调用任何接口验证凭据有效性。",
			s.URL, len(s.Body), len(hits), strings.Join(lines, "\n"))
		ev = maskAll(ev, values)
		fs = append(fs, newFinding(c, findingSpec{
			Check: "exposure/frontend-secret", Name: "前端 JS 硬编码密钥",
			Severity: "high", Level: "L2", Category: "web", Target: s.URL,
			Evidence: ev,
			Repro:    "curl -s '" + s.URL + "' | grep -nE 'LTAI[A-Za-z0-9]{12,}|AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9]{20,}'",
			Impact: "任何人打开 DevTools 就能取到凭据，可直接调用云 API（对象存储、短信、地图…）、" +
				"读写后端数据或伪造身份，且凭据通常长期有效、无法按客户端区分。",
			Fix: "立即轮换已泄露的密钥；密钥只放后端，前端经自有网关代理；" +
				"CI 加入密钥扫描（gitleaks/trufflehog），构建产物禁止打包 .env。",
			Extra: map[string]interface{}{
				"path":        scriptPath(s.URL),
				"file":        s.URL,
				"hits":        extraHits,
				"types":       types,
				"masked_only": true,
			},
		}))
	}
	if len(fs) == 0 {
		return okN(tested, fmt.Sprintf("已分析 %d 个同源 JS，未命中 AK/SK/api-key 模式", len(scripts)))
	}
	return okN(tested, fmt.Sprintf("已分析 %d 个同源 JS，%d 个文件命中", len(scripts), len(fs)), fs...)
}

func scriptPath(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Path == "" {
		return "/"
	}
	return p.Path
}

// ---------------------------------------------------------------- source map

var (
	mapVersionRe    = regexp.MustCompile(`"version"\s*:\s*3\b`)
	mapSourcesRe    = regexp.MustCompile(`"sources"\s*:`)
	mapSourceItemRe = regexp.MustCompile(`"([^"]{1,200})"`)
)

// mapURL 同名 .js.map（去掉 ?v=xxx 缓存参数，否则会请求到 app.js?v=1.map）
func mapURL(jsURL string) string {
	u, err := url.Parse(jsURL)
	if err != nil {
		return jsURL + ".map"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String() + ".map"
}

// ChkSourceMap 前端 source map 泄露。
func ChkSourceMap(c *scan.Ctx) scan.Result {
	b := newBudget(c)
	scripts, tested, reachable := collectScripts(c, b, 8)
	if len(scripts) == 0 {
		if !reachable {
			return scan.Skip("目标不可达，未取得任何 JS，source map 未判定")
		}
		return okN(tested, "未发现同源 JS 文件，无法推导 source map 路径")
	}

	var fs []*model.Finding
	probed := 0
	for _, s := range scripts {
		if probed >= 8 || !b.take() {
			break
		}
		mu := mapURL(s.URL)
		r := probe(c, "GET", mu, nil)
		tested++
		probed++
		if r == nil || r.Err != nil || r.Status != 200 {
			continue
		}
		body := bodyOf(r)
		trimmed := strings.TrimSpace(body)
		// 三重判据：JSON 对象 + "version":3 + sources 字段。
		// 缺一个都可能是软 404 或反代的固定 JSON 回包。
		if !strings.HasPrefix(trimmed, "{") || len(trimmed) < 40 {
			continue
		}
		if !mapVersionRe.MatchString(trimmed) || !mapSourcesRe.MatchString(trimmed) {
			continue
		}
		if strings.Contains(strings.ToLower(r.Header("content-type")), "html") {
			continue
		}
		sources := mapSourceItems(trimmed)
		ev := fmt.Sprintf("GET %s → HTTP %d | Content-Type: %s | 长度 %dB\n"+
			"判据: JSON 含 \"version\":3 与 \"sources\" 字段，源码映射可还原\n"+
			"源文件数: %d\n样本: %s",
			mu, r.Status, orDefault(r.Header("content-type"), "(无)"), len(r.Body),
			len(sources), orDefault(strings.Join(firstN(sources, 5), ", "), "(空)"))
		fs = append(fs, newFinding(c, findingSpec{
			Check: "exposure/source-map", Name: "前端 source map 泄露",
			Severity: "medium", Level: "L2", Category: "web", Target: mu,
			Evidence: ev,
			Repro:    "curl -s '" + mu + "' | head -c 400",
			Impact: "可还原完整前端源码（含注释、内部接口路径、测试地址、未上线的功能），" +
				"把黑盒测试变成白盒，显著降低后续漏洞挖掘成本。",
			Fix: "生产构建关闭 sourcemap（webpack devtool=false / Vite build.sourcemap=false），" +
				"确需上报错误时只上传到私有 Sentry 并从产物删除 .map。",
			Extra: map[string]interface{}{
				"path":    scriptPath(mu),
				"js":      s.URL,
				"map":     mu,
				"sources": len(sources),
			},
		}))
	}
	if len(fs) == 0 {
		return okN(tested, fmt.Sprintf("已探测 %d 个 .js.map，未命中可还原的映射", probed))
	}
	return okN(tested, fmt.Sprintf("已探测 %d 个 .js.map，命中 %d 个", probed, len(fs)), fs...)
}

// mapSourceItems 从 sources 数组里取源文件名（只取前 40 个，够展示了）
func mapSourceItems(body string) []string {
	i := strings.Index(body, `"sources"`)
	if i < 0 {
		return nil
	}
	seg := body[i:]
	if j := strings.Index(seg, "]"); j > 0 {
		seg = seg[:j]
	}
	var out []string
	for _, m := range mapSourceItemRe.FindAllStringSubmatch(seg, 40) {
		if m[1] != "sources" {
			out = append(out, m[1])
		}
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---------------------------------------------------------------- 上传点

var (
	formTagRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
	inputTagRe = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	attrRe     = regexp.MustCompile(`(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

// uploadForm 页面上的一个上传点
type uploadForm struct {
	Page     string
	Action   string
	Method   string
	Enctype  string
	Fields   []string // 全部字段名（最多 12 个）
	FileKeys []string // type=file 的字段名
}

// parseAttrs 解析标签属性
func parseAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(m[1])
		val := m[2]
		if val == "" {
			val = m[3]
		}
		if val == "" {
			val = m[4]
		}
		out[name] = strings.TrimSpace(val)
	}
	return out
}

// parseUploadForms 从 HTML 里找「可能用于上传」的表单。
//
// 判定只有两条：enctype=multipart/form-data，或者页面上有 type=file。
// 这不足以证明存在上传漏洞 —— 所以本项只到 info/L1，Extra 里只记 endpoint
// 与字段名，不写任何「可上传 webshell」之类的结论。
func parseUploadForms(html, pageURL string) []uploadForm {
	var out []uploadForm
	for _, m := range formTagRe.FindAllStringSubmatch(html, -1) {
		attrs := parseAttrs(m[1])
		inner := m[2]
		f := uploadForm{
			Page:    pageURL,
			Action:  attrs["action"],
			Method:  strings.ToUpper(orDefault(attrs["method"], "GET")),
			Enctype: strings.ToLower(attrs["enctype"]),
		}
		for _, im := range inputTagRe.FindAllStringSubmatch(inner, -1) {
			ia := parseAttrs(im[1])
			name := ia["name"]
			if name == "" {
				continue
			}
			if len(f.Fields) < 12 {
				f.Fields = append(f.Fields, name)
			}
			if strings.EqualFold(ia["type"], "file") && !containsStr(f.FileKeys, name) {
				f.FileKeys = append(f.FileKeys, name)
			}
		}
		isUpload := strings.Contains(f.Enctype, "multipart/form-data") || len(f.FileKeys) > 0
		if !isUpload {
			continue
		}
		if f.Action == "" {
			f.Action = pageURL
		} else {
			f.Action = httpc.URLJoin(pageURL, f.Action)
		}
		out = append(out, f)
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// pickPages 选值得解析的页面（目标根 + 爬虫落点里的 HTML 页面）
func pickPages(c *scan.Ctx, max int) []string {
	if max <= 0 {
		max = 12
	}
	var out []string
	seen := map[string]bool{}
	add := func(u string) {
		u = httpc.NormURL(strings.TrimSpace(u))
		if u == "" || seen[u] || len(out) >= max {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	add(urlFor(c, "/"))
	if c != nil {
		for _, u := range c.URLs {
			if isHTMLish(u) && sameHost(u, baseOf(c)) {
				add(u)
			}
		}
	}
	return out
}

// ChkFileUploadForm 上传点发现（info 级，只登记不试探）
func ChkFileUploadForm(c *scan.Ctx) scan.Result {
	b := newBudget(c)
	pages := pickPages(c, 12)
	tested := 0
	reachable := 0
	var found []uploadForm
	seen := map[string]bool{}
	for _, pu := range pages {
		if !b.take() {
			break
		}
		r := probe(c, "GET", pu, nil)
		tested++
		if r != nil && r.Err == nil {
			reachable++
		}
		if r == nil || r.Err != nil || r.Status != 200 {
			continue
		}
		for _, f := range parseUploadForms(bodyOf(r), pu) {
			if seen[f.Action] {
				continue
			}
			seen[f.Action] = true
			found = append(found, f)
		}
	}
	if len(found) == 0 {
		if reachable == 0 {
			return scan.Skip("目标不可达，页面未解析，上传点未判定")
		}
		return okN(tested, fmt.Sprintf("已解析 %d 个页面，未发现 multipart/type=file 表单", len(pages)))
	}
	var fs []*model.Finding
	for i, f := range found {
		if i >= 8 { // 一个站几十个上传点也很常见，报告里给前 8 个就够定位
			break
		}
		ev := fmt.Sprintf("页面: %s\n表单: %s %s | enctype=%s\n"+
			"文件字段: %s\n其余字段: %s\n"+
			"说明: 仅登记上传点。是否可上传恶意文件、是否有类型/内容校验，需后续 L2 验证；"+
			"本项未上传任何文件。",
			f.Page, f.Method, f.Action, orDefault(f.Enctype, "(无)"),
			orDefault(strings.Join(f.FileKeys, ", "), "(无 type=file)"),
			orDefault(strings.Join(f.Fields, ", "), "(无)"))
		fs = append(fs, newFinding(c, findingSpec{
			Check: "exposure/file-upload-form", Name: "上传点发现",
			Severity: "info", Level: "L1", Category: "web", Target: f.Action,
			Evidence: ev,
			Repro:    "curl -s '" + f.Page + "' | grep -iE 'multipart/form-data|type=\"?file'",
			Impact:   "上传点是后续任意文件写入/webshell 的主要入口，需按上传校验（类型、内容、落地目录执行权限）单独评估。",
			Fix:      "上传目录禁止脚本执行；服务端校验扩展名+内容类型+文件头；上传后重命名并隔离存储。",
			Extra: map[string]interface{}{
				"path":      scriptPath(f.Action),
				"endpoint":  f.Action,
				"page":      f.Page,
				"method":    f.Method,
				"enctype":   f.Enctype,
				"fields":    f.Fields,
				"file_keys": f.FileKeys,
			},
		}))
	}
	return okN(tested, fmt.Sprintf("已解析 %d 个页面，登记 %d 个上传点", len(pages), len(fs)), fs...)
}

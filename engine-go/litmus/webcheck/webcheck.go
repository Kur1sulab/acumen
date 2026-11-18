// Package webcheck 是 Web 侧内建检查（不依赖 nuclei 模板），逐函数移植自 Python 版
// webcheck.py。
//
// 设计要点（都是踩过的坑）：
//   - **软 404 基线**：先请求两个随机路径。如果站点对任何路径都回 200，那所有
//     「路径存在」类判断全部失效 —— 必须拿响应体跟基线比，只认长度/内容明显不同，
//     或者命中该产品独有的标记串。
//   - **独有标记**：每个检查都必须给「只有这个产品才有」的字符串（actuator 的
//     propertySources、Druid 的 Druid Stat Index、.git/HEAD 的 ref: refs/）。
//     只回 200 不算，长度不同不算。
//   - **只读**：全部 GET / HEAD / OPTIONS，不 POST、不 PUT、不 DELETE。
//
// 与 Python 版的接口差异（不是行为差异）：
//   - Python 返回 dict 列表、由引擎再包成 model.Finding；Go 里 webcheck 直接产出
//     *model.Finding（契约要求 finding 是唯一交付形状）。Target 记 base，
//     host/port/scheme 已从 base 解出填好；引擎侧再按 extra["path"] 拼完整 URL。
//   - Python 的 CHECKS 是函数列表；Go 的 Checks 带上 Name 字段，异常兜底时用它拼
//     「检查项异常 chk_actuator」，与 Python 的 fn.__name__ 逐字一致。
package webcheck

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// UA 检查专用 UA（与 Python 版逐字一致）
const UA = "Mozilla/5.0 (compatible; Litmus/1.0; +local)"

// DefaultTimeout 各检查项默认超时（Python 的 opts.get("timeout", 8.0)）
const DefaultTimeout = 8 * time.Second

// uaHeader 默认请求头
var uaHeader = []httpc.Header{{Name: "User-Agent", Value: UA}}

// Opts 检查选项
type Opts struct {
	Timeout time.Duration
}

func (o Opts) t() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// ---------------------------------------------------------------- 小工具

const randChars = "abcdefghijklmnopqrstuvwxyz0123456789"

// randStr 随机路径段（对应 Python _rand）
func randStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = randChars[rand.Intn(len(randChars))]
	}
	return string(b)
}

// bodyText 正文按 UTF-8 替换解码（对应 Python _body_text 的 decode("utf-8", "replace")）
func bodyText(r *httpc.Response) string {
	if r == nil {
		return ""
	}
	return strings.ToValidUTF8(string(r.Body), "\uFFFD")
}

// clip 截断并加省略号（按字符数，对齐 Python 的 s[:n] + "…"）
func clip(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n]) + "…"
}

// headN 取前 n 个字符，不加省略号（对齐 Python 的 s[:n]）
func headN(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// pyHeader 复刻 Python 的 r.header(name) → 缺失时返回 None 的字符串表现（"None"），
// 保证 evidence 文本与 Python 版逐字一致（oracle diff 靠这个）。
func pyHeader(r *httpc.Response, name string) string {
	if v, ok := r.HeaderOK(name); ok {
		return v
	}
	return "None"
}

// pyReprBytes 复刻 Python 的 repr(bytes)，用于证据里的魔数（b'PK\x03\x04'）。
//
// 引号规则也照抄：只在「含单引号且不含双引号」时用双引号包，
// 否则一律单引号并把单引号转义。
func pyReprBytes(b []byte) string {
	hasS, hasD := false, false
	for _, c := range b {
		if c == '\'' {
			hasS = true
		}
		if c == '"' {
			hasD = true
		}
	}
	q := byte('\'')
	if hasS && !hasD {
		q = '"'
	}
	var sb strings.Builder
	sb.WriteByte('b')
	sb.WriteByte(q)
	for _, c := range b {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c == q:
			sb.WriteByte('\\')
			sb.WriteByte(q)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	sb.WriteByte(q)
	return sb.String()
}

func sha1sig(b []byte) string {
	s := sha1.Sum(b)
	return hex.EncodeToString(s[:])[:12]
}

// ---------------------------------------------------------------- 抹密

var secretPairRe = regexp.MustCompile(
	`(?i)("?[\w.\-]*(?:password|secret|token|apikey|api_key|` +
		`access_key|private_key)[\w.\-]*"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;}"']+)`)

var secretValueRe = regexp.MustCompile(`"value"\s*:\s*"[^"]*"`)

// Redact 证据里抹掉明文口令/密钥：留前 4 位，其余打星。
//
// 这条不是洁癖：报告是要交出去的，/env 里的值直接贴出去等于二次泄露。
// 对应 Python 的 _redact（正则、替换顺序、掩码长度规则全部一致，
// 包括它对 {"a.password": {"value": ...}} 这类嵌套结构先误伤 group2 再被
// "value" 规则整体抹掉的既有行为）。
func Redact(txt string) string {
	out := secretPairRe.ReplaceAllStringFunc(txt, func(m string) string {
		sub := secretPairRe.FindStringSubmatch(m)
		if sub == nil {
			return m
		}
		raw := sub[2]
		q := ""
		if len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') {
			q = string(raw[0])
			raw = raw[1 : len(raw)-1]
		}
		rs := []rune(raw)
		var masked string
		if len(rs) > 4 {
			n := len(rs) - 4
			if n < 4 {
				n = 4
			}
			masked = string(rs[:4]) + strings.Repeat("*", n)
		} else {
			masked = strings.Repeat("*", len(rs))
		}
		return sub[1] + q + masked + q
	})
	// actuator 的嵌套结构：{"xxx": {"value": "真实值"}}
	return secretValueRe.ReplaceAllString(out, `"value": "****"`)
}

// ---------------------------------------------------------------- 结果构造

// res 构造一条 confirmed 发现（对应 Python _res）
func res(target, check, name, severity, level, evidence, repro, impact, fix string,
	extra map[string]interface{}) *model.Finding {
	return resConf(target, check, name, severity, level, evidence, repro, impact, fix, extra, "confirmed")
}

// resConf 指定置信度
func resConf(target, check, name, severity, level, evidence, repro, impact, fix string,
	extra map[string]interface{}, confidence string) *model.Finding {
	host, port, scheme := splitBase(target)
	return model.NewFinding(check, name, severity, target, model.FindingOpts{
		Host: host, Port: port, Scheme: scheme, Category: "web", Level: level,
		Confidence: confidence, Evidence: evidence, Repro: repro,
		Impact: impact, Fix: fix, Extra: extra,
	})
}

// splitBase 从 base URL 解出 host/port/scheme（Python 版由引擎负责这一段）
func splitBase(base string) (host string, port int, scheme string) {
	u, err := url.Parse(httpc.NormURL(base))
	if err != nil || u == nil {
		return base, 0, ""
	}
	scheme = strings.ToLower(u.Scheme)
	host = u.Hostname()
	if scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	if ps := u.Port(); ps != "" {
		if n, e := strconv.Atoi(ps); e == nil {
			port = n
		}
	}
	return host, port, scheme
}

// ---------------------------------------------------------------- 软 404

// Soft404 软 404 基线（对应 Python soft404 返回的 dict）
type Soft404 struct {
	Soft   bool   `json:"soft"`
	Status int    `json:"status"`
	Len    int    `json:"len"`
	Sig    string `json:"sig"`
	Same   bool   `json:"same"`
	Sample string `json:"sample"`
}

// Soft404Probe 请求两个随机路径，建立软 404 基线
func Soft404Probe(p *httpc.Pool, base string, timeout time.Duration) *Soft404 {
	outs := make([]*httpc.Response, 0, 2)
	for i := 0; i < 2; i++ {
		r := p.Request("GET", httpc.BuildURLJoin(base, "/"+randStr(18)+".html"), httpc.Opts{
			Headers: uaHeader, NoRedirect: true, Timeout: timeout,
		})
		outs = append(outs, r)
	}
	b0, b1 := outs[0].Body, outs[1].Body
	soft := outs[0].Status == 200 && outs[1].Status == 200
	sig := sha1sig(b0)
	return &Soft404{
		Soft:   soft,
		Status: outs[0].Status,
		Len:    len(b0),
		Sig:    sig,
		Same:   sha1sig(b1) == sig,
		Sample: clip(bodyText(outs[0]), 200),
	}
}

// IsReal 判断响应是不是「真内容」而不是软 404 的同一张皮。
// minLen<=0 时取 40（对齐 Python 的默认参数）。
//
// 注意：当前各检查项都用「独有标记串」判定，不走这条软 404 比较
// （与 Python 版一致 —— 它定义了 _is_real 但检查项里没调用）。
// 保留它是为了后续爬虫/模板匹配复用同一套判据。
func IsReal(baseline *Soft404, r *httpc.Response, marker string, minLen int) bool {
	if minLen <= 0 {
		minLen = 40
	}
	if r == nil {
		return false
	}
	body := r.Body
	if r.Status != 200 && r.Status != 206 {
		return false
	}
	if marker != "" && strings.Contains(bodyText(r), marker) {
		return true
	}
	if !baseline.Soft {
		return len(body) >= minLen
	}
	// 软 404：必须跟基线明显不同
	if sha1sig(body) == baseline.Sig {
		return false
	}
	diff := len(body) - baseline.Len
	if diff < 0 {
		diff = -diff
	}
	thresh := int(float64(baseline.Len) * 0.05)
	if thresh < 32 {
		thresh = 32
	}
	if diff < thresh {
		return false
	}
	return len(body) >= minLen
}

// ---------------------------------------------------------------- 各检查

// ChkActuator Spring Boot Actuator 端点暴露
func ChkActuator(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	out := []*model.Finding{}
	probes := []struct {
		path, marker, check, name, sev, lvl, impact, fix string
	}{
		{"/actuator/env", "propertySources", "actuator-env",
			"Spring Boot Actuator /env 配置泄露", "high", "L2",
			"配置项含数据库口令、密钥、内网地址；直接给出后续横向所需的凭据。",
			"关闭 /env 暴露（management.endpoints.web.exposure.include 白名单）或加认证。"},
		{"/actuator/heapdump", "JAVA PROFILE", "actuator-heapdump",
			"Spring Boot Actuator /heapdump 堆转储下载", "critical", "L2",
			"堆转储含内存中的会话、口令、密钥，可离线提取凭据接管应用。",
			"关闭 heapdump 端点并限制 /actuator/** 访问来源。"},
		{"/actuator/gateway/routes", "route_id", "actuator-gateway",
			"Spring Cloud Gateway 路由泄露", "high", "L2",
			"泄露内部路由与下游地址，可配合 SpEL 注入（CVE-2022-22947）执行命令。",
			"升级 Spring Cloud Gateway 并关闭 gateway 端点。"},
		{"/actuator/mappings", "dispatcherServlets", "actuator-mappings",
			"Spring Boot Actuator /mappings 接口清单泄露", "medium", "L1",
			"暴露全部内部接口路径，缩小攻击面枚举成本。",
			"关闭 /mappings 或加认证。"},
		{"/actuator", "_links", "actuator-index",
			"Spring Boot Actuator 端点暴露", "medium", "L1",
			"可枚举全部已开放管理端点（含 env/heapdump 等）。",
			"仅暴露 health/info，其余端点关闭。"},
	}
	for _, pr := range probes {
		r := p.Request("GET", httpc.BuildURLJoin(base, pr.path), httpc.Opts{
			Headers: uaHeader, NoRedirect: true, Timeout: o.t(),
		})
		txt := bodyText(r)
		if !strings.Contains(txt, pr.marker) {
			continue
		}
		ev := fmt.Sprintf("GET %s → HTTP %d | Content-Type: %s | 长度 %dB\n标记串 '%s' 命中\n片段: %s",
			pr.path, r.Status, pyHeader(r, "content-type"), len(r.Body), pr.marker,
			clip(Redact(txt), 400))
		extra := map[string]interface{}{"path": pr.path}
		if pr.check == "actuator-env" {
			// 只统计敏感键名，不回显值（报告里绝不出现完整口令）
			keys := sensitiveKeys(txt)
			extra["sensitive_keys"] = keys
			if len(keys) > 0 {
				ev += "\n敏感键名: " + strings.Join(keys, ", ")
			}
		}
		out = append(out, res(base, pr.check, pr.name, pr.sev, pr.lvl, ev,
			"curl -s "+httpc.BuildURLJoin(base, pr.path), pr.impact, pr.fix, extra))
	}
	return out
}

var sensitiveKeyRe = regexp.MustCompile(`(?i)"([\w.\-]*(?:password|secret|key|token)[\w.\-]*)"`)

// sensitiveKeys 提取敏感键名（去重排序，最多 15 个）
func sensitiveKeys(txt string) []string {
	ms := sensitiveKeyRe.FindAllStringSubmatch(txt, -1)
	set := map[string]bool{}
	for _, m := range ms {
		set[m[1]] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 15 {
		out = out[:15]
	}
	return out
}

// ChkCommonLeaks .git / .env / 目录列举 / 备份包
func ChkCommonLeaks(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	out := []*model.Finding{}
	t := o.t()
	// .git
	r := p.Request("GET", httpc.BuildURLJoin(base, "/.git/HEAD"), httpc.Opts{
		Headers: uaHeader, NoRedirect: true, Timeout: t,
	})
	txt := bodyText(r)
	if r.Status == 200 && strings.HasPrefix(txt, "ref:") {
		out = append(out, res(base, "git-leak", ".git 目录可读（源码泄露）", "high", "L2",
			fmt.Sprintf("GET /.git/HEAD → HTTP %d\n%s", r.Status, headN(txt, 200)),
			"curl -s "+httpc.BuildURLJoin(base, "/.git/HEAD"),
			"攻击者可还原完整源码（含硬编码凭据、内网地址、签名密钥），并据源码定位后续漏洞。",
			"禁止 Web 根目录下 .git 可访问（Nginx location ~ /\\.git { deny all; }）。",
			map[string]interface{}{"path": "/.git/HEAD"}))
	}
	// .env
	r = p.Request("GET", httpc.BuildURLJoin(base, "/.env"), httpc.Opts{
		Headers: uaHeader, NoRedirect: true, Timeout: t,
	})
	txt = bodyText(r)
	if r.Status == 200 && envLineRe.MatchString(txt) && envHintRe.MatchString(txt) {
		names := envNameRe.FindAllStringSubmatch(txt, -1)
		vals := make([]string, 0, len(names))
		for _, m := range names {
			vals = append(vals, m[1])
		}
		if len(vals) > 20 {
			vals = vals[:20]
		}
		out = append(out, res(base, "env-leak", ".env 配置文件可下载", "critical", "L2",
			fmt.Sprintf("GET /.env → HTTP %d | 长度 %dB\n键名（值已隐去）: %s",
				r.Status, len(r.Body), strings.Join(vals, ", ")),
			"curl -s "+httpc.BuildURLJoin(base, "/.env"),
			"直接泄露数据库/对象存储/第三方服务凭据，通常一步到业务数据。",
			"把 .env 移出 Web 根目录并加访问控制。",
			map[string]interface{}{"path": "/.env", "keys": vals}))
	}
	// 目录列举
	for _, d := range []string{"/uploads/", "/backup/", "/static/", "/files/"} {
		r = p.Request("GET", httpc.BuildURLJoin(base, d), httpc.Opts{
			Headers: uaHeader, NoRedirect: true, Timeout: t,
		})
		txt = bodyText(r)
		if r.Status == 200 && (strings.Contains(txt, "Index of /") ||
			strings.Contains(txt, "<title>Directory listing")) {
			out = append(out, res(base, "dir-listing", "目录可列举 "+d, "medium", "L1",
				fmt.Sprintf("GET %s → HTTP %d\n片段: %s", d, r.Status, clip(txt, 300)),
				"curl -s "+httpc.BuildURLJoin(base, d),
				"可枚举全部文件名，常直接暴露备份包、数据库导出、上传的证件照。",
				"关闭 autoindex；上传目录禁止脚本执行。",
				map[string]interface{}{"path": d}))
			break
		}
	}
	// 备份包
	for _, f := range []string{"/www.zip", "/wwwroot.zip", "/backup.zip", "/db.sql", "/web.tar.gz"} {
		r = p.Request("GET", httpc.BuildURLJoin(base, f), httpc.Opts{
			Headers: uaHeader, NoRedirect: true, Timeout: t,
		})
		body := r.Body
		if r.Status == 200 && (bytesHasPrefix(body, []byte("PK")) ||
			bytesHasPrefix(body, []byte{0x1f, 0x8b}) ||
			strings.Contains(headStr(body, 2000), "-- MySQL dump") ||
			strings.Contains(headStr(body, 4000), "CREATE TABLE")) {
			magic := body
			if len(magic) > 8 {
				magic = magic[:8]
			}
			out = append(out, res(base, "backup-leak", "备份/导出文件可下载 "+f, "critical", "L2",
				fmt.Sprintf("GET %s → HTTP %d | 长度 %dB | 魔数 %s",
					f, r.Status, len(body), pyReprBytes(magic)),
				"curl -sO "+httpc.BuildURLJoin(base, f),
				"备份包含源码与数据库导出，等于一次性交出全部业务数据。",
				"删除服务器上的临时备份，禁止 Web 目录存放 .zip/.sql。",
				map[string]interface{}{"path": f}))
			break
		}
	}
	return out
}

var (
	envLineRe = regexp.MustCompile(`(?m)^[A-Z_]{2,}=.{1,}`)
	envHintRe = regexp.MustCompile(`(?i)(password|secret|key|token|dsn|host)`)
	envNameRe = regexp.MustCompile(`(?m)^([A-Za-z0-9_]+)=`)
)

func bytesHasPrefix(b, p []byte) bool {
	if len(b) < len(p) {
		return false
	}
	return string(b[:len(p)]) == string(p)
}

// headStr 取前 n 字节（按字节，对齐 Python 的 body[:n]）
func headStr(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

// ChkSwagger 接口文档未授权
func ChkSwagger(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	t := o.t()
	for _, pr := range []struct{ path, marker string }{
		{"/v2/api-docs", `"swagger"`},
		{"/v3/api-docs", `"openapi"`},
		{"/swagger-ui.html", "swagger-ui"},
	} {
		r := p.Request("GET", httpc.BuildURLJoin(base, pr.path), httpc.Opts{
			Headers: uaHeader, NoRedirect: true, Timeout: t,
		})
		txt := bodyText(r)
		if r.Status == 200 && strings.Contains(txt, pr.marker) {
			return []*model.Finding{res(base, "swagger-open", "接口文档未授权可访问", "low", "L1",
				fmt.Sprintf("GET %s → HTTP %d | 长度 %dB\n片段: %s",
					pr.path, r.Status, len(r.Body), clip(txt, 300)),
				"curl -s "+httpc.BuildURLJoin(base, pr.path),
				"暴露全部接口定义与参数结构，可据此定向构造越权/注入测试。",
				"生产环境关闭 swagger-ui 与 api-docs。",
				map[string]interface{}{"path": pr.path})}
		}
	}
	return []*model.Finding{}
}

// ChkNacos Nacos 用户列表未授权
func ChkNacos(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	const path = "/nacos/v1/auth/users?pageNo=1&pageSize=1"
	r := p.Request("GET", httpc.BuildURLJoin(base, path), httpc.Opts{
		Headers: uaHeader, NoRedirect: true, Timeout: o.t(),
	})
	txt := bodyText(r)
	if r.Status == 200 && (strings.Contains(txt, "pageItems") || strings.Contains(txt, `"username"`)) {
		return []*model.Finding{res(base, "nacos-unauth", "Nacos 用户列表未授权可读", "high", "L2",
			fmt.Sprintf("GET /nacos/v1/auth/users → HTTP %d\n片段: %s", r.Status, clip(Redact(txt), 400)),
			"curl -s '"+httpc.BuildURLJoin(base, path)+"'",
			"可直接读取后台账户（含口令哈希），配合默认口令或 JWT 伪造接管配置中心，进而改写全部微服务配置。",
			"开启 Nacos 鉴权（nacos.core.auth.enabled=true）并修改默认 nacos/nacos。",
			map[string]interface{}{"path": "/nacos/v1/auth/users"})}
	}
	return []*model.Finding{}
}

// ChkDruid Druid 监控台未授权
func ChkDruid(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	t := o.t()
	for _, path := range []string{"/druid/index.html", "/druid/websession.html"} {
		r := p.Request("GET", httpc.BuildURLJoin(base, path), httpc.Opts{
			Headers: uaHeader, NoRedirect: true, Timeout: t,
		})
		txt := bodyText(r)
		// Python 的优先级：A or (B and C)
		if r.Status == 200 && (strings.Contains(txt, "Druid Stat") ||
			(strings.Contains(strings.ToLower(txt), "druid") && strings.Contains(txt, "StatViewServlet"))) {
			return []*model.Finding{res(base, "druid-open", "Druid 监控台未授权访问", "medium", "L1",
				fmt.Sprintf("GET %s → HTTP %d\n片段: %s", path, r.Status, clip(txt, 300)),
				"curl -s "+httpc.BuildURLJoin(base, path),
				"暴露 SQL 语句、会话列表与数据源连接串（含账号口令）。",
				"为 Druid StatViewServlet 设置 login-username/login-password。",
				map[string]interface{}{"path": path})}
		}
	}
	return []*model.Finding{}
}

var versionRe = regexp.MustCompile(`\d+\.\d+`)

// ChkHeaders 版本号泄露 / 缺安全响应头
func ChkHeaders(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	r := p.Request("GET", httpc.BuildURLJoin(base, "/"), httpc.Opts{
		Headers: uaHeader, Timeout: o.t(), // allow_redirects=True
	})
	if r.Status == 0 {
		return []*model.Finding{}
	}
	out := []*model.Finding{}
	server := r.Header("server")
	powered := r.Header("x-powered-by")
	if versionRe.MatchString(server) || powered != "" {
		out = append(out, res(base, "banner-version", "响应头泄露服务版本", "info", "L1",
			fmt.Sprintf("GET / → HTTP %d\nServer: %s\nX-Powered-By: %s", r.Status, server, powered),
			"curl -sI "+base+"/",
			"版本号可直接映射到已知 CVE，降低攻击者试错成本。",
			"隐藏版本号（server_tokens off / 移除 X-Powered-By）。",
			map[string]interface{}{"server": server, "powered": powered}))
	}
	missing := []string{}
	for _, h := range []string{"content-security-policy", "x-frame-options",
		"x-content-type-options", "strict-transport-security"} {
		if !r.HasHeader(h) {
			missing = append(missing, h)
		}
	}
	if len(missing) >= 3 {
		out = append(out, res(base, "sec-headers", "缺少安全响应头", "low", "L1",
			fmt.Sprintf("GET / → HTTP %d\n缺失: %s", r.Status, strings.Join(missing, ", ")),
			"curl -sI "+base+"/",
			"缺少 CSP/X-Frame-Options 时点击劫持与 XSS 利用门槛更低。",
			"按需补齐 CSP、X-Frame-Options、X-Content-Type-Options、HSTS。",
			map[string]interface{}{"missing": missing}))
	}
	return out
}

// evilOrigin CORS 探测用的恶意来源
const evilOrigin = "https://evil.litmus.test"

// ChkCORS CORS 配置过宽
func ChkCORS(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	hdrs := []httpc.Header{{Name: "User-Agent", Value: UA}, {Name: "Origin", Value: evilOrigin}}
	r := p.Request("GET", httpc.BuildURLJoin(base, "/"), httpc.Opts{
		Headers: hdrs, NoRedirect: true, Timeout: o.t(),
	})
	acao := r.Header("access-control-allow-origin")
	acac := r.Header("access-control-allow-credentials")
	if acao == "*" || acao == evilOrigin {
		sev := "low"
		if strings.ToLower(acac) == "true" && acao != "*" {
			sev = "medium"
		}
		acacShow := acac
		if acacShow == "" {
			acacShow = "(空)"
		}
		return []*model.Finding{res(base, "cors-misconfig", "CORS 配置过宽", sev, "L1",
			fmt.Sprintf("GET / (Origin: %s) → HTTP %d\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s",
				evilOrigin, r.Status, acao, acacShow),
			"curl -sI -H 'Origin: "+evilOrigin+"' "+base+"/",
			"任意站点可跨域读取响应；若同时允许携带凭据，可直接窃取登录态数据。",
			"白名单固定来源，禁止 * 与 credentials 同时出现。",
			map[string]interface{}{"acao": acao, "acac": acac})}
	}
	return []*model.Finding{}
}

// ChkMethods 高风险 HTTP 方法
func ChkMethods(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding {
	r := p.Request("OPTIONS", httpc.BuildURLJoin(base, "/"), httpc.Opts{
		Headers: uaHeader, NoRedirect: true, Timeout: o.t(),
	})
	allow := r.Header("allow")
	if allow == "" {
		allow = r.Header("access-control-allow-methods")
	}
	allow = strings.ToUpper(allow)
	risky := []string{}
	for _, m := range []string{"PUT", "DELETE", "TRACE", "PROPFIND"} {
		if strings.Contains(allow, m) {
			risky = append(risky, m)
		}
	}
	if len(risky) > 0 {
		return []*model.Finding{res(base, "risky-methods", "启用了高风险 HTTP 方法", "low", "L1",
			fmt.Sprintf("OPTIONS / → HTTP %d\nAllow: %s", r.Status, allow),
			"curl -s -X OPTIONS -i "+base+"/",
			"PUT/DELETE 可能导致任意文件写入或删除；TRACE 可辅助 XST 攻击。",
			"在 Web 服务器层关闭不需要的方法。",
			map[string]interface{}{"allow": allow, "risky": risky})}
	}
	return []*model.Finding{}
}

// Check 一个内建检查项。
// Name 对齐 Python 版的函数名（chk_actuator ...），异常兜底时用它拼
// 「检查项异常 chk_actuator」，与 Python 的 fn.__name__ 逐字一致。
type Check struct {
	Name string
	Run  func(p *httpc.Pool, base string, bl *Soft404, o Opts) []*model.Finding
}

// Checks 全部内建检查（顺序与 Python 版 CHECKS 一致）
// checkTitles 检查项的中文名。
//
// 覆盖表的 item 列必须保持稳定的英文 ID（客户拿两次报告 diff 时不会因为
// 改了文案就以为「检查项变了」），中文名只出现在说明列里给人看。
var checkTitles = map[string]string{
	"chk_actuator":     "Actuator 端点暴露",
	"chk_common_leaks": "常见泄露文件（.git/.env/.svn/.DS_Store 等）",
	"chk_swagger":      "Swagger/OpenAPI 文档暴露",
	"chk_nacos":        "Nacos 未授权",
	"chk_druid":        "Druid 监控台未授权",
	"chk_headers":      "安全响应头缺失",
	"chk_cors":         "CORS 配置不当",
	"chk_methods":      "危险的 HTTP 方法",
}

var Checks = []Check{
	{"chk_actuator", ChkActuator},
	{"chk_common_leaks", ChkCommonLeaks},
	{"chk_swagger", ChkSwagger},
	{"chk_nacos", ChkNacos},
	{"chk_druid", ChkDruid},
	{"chk_headers", ChkHeaders},
	{"chk_cors", ChkCORS},
	{"chk_methods", ChkMethods},
}

// CheckWeb 对一个 Web 根跑全部内建检查，返回 findings 列表 + 软 404 基线。
//
// 单个检查项 panic 不会带走整轮：兜成一条 check-error（confidence=suspect），
// 明确写「该检查项未完成，结果不计入结论」—— 绝不冒充「已测且没问题」。
func CheckWeb(p *httpc.Pool, base string, o Opts) ([]*model.Finding, *Soft404) {
	bl := Soft404Probe(p, base, o.t())
	out := []*model.Finding{}
	for _, c := range Checks {
		out = append(out, runCheck(c, p, base, bl, o)...)
	}
	return out, bl
}

func runCheck(c Check, p *httpc.Pool, base string, bl *Soft404, o Opts) (out []*model.Finding) {
	defer func() {
		if rec := recover(); rec != nil {
			out = append(out, resConf(base, "check-error", "检查项异常 "+c.Name, "info", "L1",
				fmt.Sprintf("%T: %v", rec, rec), "", "该检查项未完成，结果不计入结论。", "",
				map[string]interface{}{"error": fmt.Sprint(rec)}, "suspect"))
		}
	}()
	return c.Run(p, base, bl, o)
}

// ---------------------------------------------------------------- 逐项结果

// ItemResult 单个检查项的执行结果。
//
// Error 非空表示该项没跑成（panic 或异常）—— 覆盖表要把它记成 skip 而不是 ok，
// 否则「检查项崩了」和「检查项跑完没命中」在报告里长得一模一样。
type ItemResult struct {
	Name     string
	Title    string // 中文名，给报告说明列用
	Findings []*model.Finding
	Error    string
}

// CheckWebDetail 与 CheckWeb 行为一致，但返回逐项结果。
//
// 存在的唯一理由是把覆盖表从「webcheck@18099 ok」下钻到
//
//	webcheck/chk_actuator  ok
//	webcheck/chk_swagger   ok
//	webcheck/chk_nacos     skip  ...
//
// 客户问「你测 Nacos 了吗」，答得出来。
func CheckWebDetail(p *httpc.Pool, base string, o Opts) ([]ItemResult, *Soft404) {
	bl := Soft404Probe(p, base, o.t())
	out := make([]ItemResult, 0, len(Checks))
	for _, c := range Checks {
		fs, errMsg := runCheckSafe(c, p, base, bl, o)
		out = append(out, ItemResult{
			Name: c.Name, Title: checkTitles[c.Name],
			Findings: fs, Error: errMsg,
		})
	}
	return out, bl
}

// runCheckSafe 跑一个检查项，panic 兜成错误文本而不是带走整轮。
func runCheckSafe(c Check, p *httpc.Pool, base string, bl *Soft404, o Opts) (out []*model.Finding, errMsg string) {
	defer func() {
		if rec := recover(); rec != nil {
			errMsg = fmt.Sprintf("%v", rec)
			out = []*model.Finding{resConf(base, "check-error", "检查项异常 "+c.Name, "info", "L1",
				fmt.Sprintf("%T: %v", rec, rec), "", "该检查项未完成，结果不计入结论。", "",
				map[string]interface{}{"error": fmt.Sprint(rec)}, "suspect")}
		}
	}()
	return c.Run(p, base, bl, o), ""
}

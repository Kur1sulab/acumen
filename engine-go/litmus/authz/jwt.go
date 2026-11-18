package authz

// jwt.go —— JWT 两条硬伤：alg=none 绕过、签名密钥可猜。
//
// 共同前提：必须先有一个**服务端接受**的 token。没有基线就没法证明「伪造的
// token 也被接受了」——否则把「匿名能看」误报成「绕过成功」。所以两个检查都
// 先 harvest 一个 JWT，再确认它能换到 200 + 非空响应；拿不到就 skip。
//
// 判定表（两个检查共用）：
//   伪造 token → 401/403            → 没绕过，ok
//   伪造 token → 200 且与匿名响应同  → 分不清是不是公开接口，skip（不报）
//   伪造 token → 200 且与匿名响应不同 → 命中（服务端按已认证处理）
//
// token 是凭据：证据里只留前 8 位。JWT 的 payload 也不落报告（可能含邮箱/工号）。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		scan.Check{
			Meta: mk("jwt-none", "JWT alg=none 认证绕过", "critical", "CWE-347"),
			Run:  runJWTNone,
		},
		scan.Check{
			Meta: mk("jwt-weak-key", "JWT 使用可猜测的签名密钥", "critical", "CWE-321"),
			Run:  runJWTWeakKey,
		},
	)
}

// jwtRe 三段的 base64url。第一段一定以 eyJ 开头（{" 的 base64url）。
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]*`)

type jwtInfo struct {
	Raw     string
	Header  map[string]interface{}
	Payload []byte
	Alg     string
	FoundAt string
}

func b64decode(s string) ([]byte, bool) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	// 有的实现带 padding
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

func parseJWT(raw string) *jwtInfo {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil
	}
	hb, ok := b64decode(parts[0])
	if !ok {
		return nil
	}
	pb, ok := b64decode(parts[1])
	if !ok {
		return nil
	}
	var h map[string]interface{}
	if json.Unmarshal(hb, &h) != nil {
		return nil
	}
	alg, _ := h["alg"].(string)
	if alg == "" {
		return nil
	}
	return &jwtInfo{Raw: raw, Header: h, Payload: pb, Alg: alg}
}

func encSegment(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwtHeaderSeg 克隆原 header，改 alg 后重新编码。
// 保留 typ/kid 等字段：有的网关按 kid 选密钥，删了就测不出真实行为。
func jwtHeaderSeg(base map[string]interface{}, alg string) string {
	h := make(map[string]interface{}, len(base)+1)
	for k, v := range base {
		h[k] = v
	}
	h["alg"] = alg
	b, err := json.Marshal(h)
	if err != nil {
		return ""
	}
	return encSegment(b)
}

// forgeAlgNone 把 header 改成 alg=none 并去掉签名。
func forgeAlgNone(t *jwtInfo) string {
	h := jwtHeaderSeg(t.Header, "none")
	if h == "" {
		return ""
	}
	return h + "." + encSegment(t.Payload) + "."
}

// signHS256 用给定密钥重算 HS256 签名。
func signHS256(t *jwtInfo, key string) string {
	h := jwtHeaderSeg(t.Header, "HS256")
	if h == "" {
		return ""
	}
	signing := h + "." + encSegment(t.Payload)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signing))
	return signing + "." + encSegment(mac.Sum(nil))
}

// weakJWTKeys 常见弱密钥（公开字典里排名最靠前的那批）。
//
// 命中后这把密钥**会写进报告**：它是我们猜出来的字典项，不是从目标拿到的
// 凭据，报告里必须点名是哪把，否则客户无法修。
var weakJWTKeys = []string{
	"secret", "key", "123456", "admin", "jwt_secret", "your-256-bit-secret",
}

// ---------------------------------------------------------------- 发现

// findJWT 从响应体 / Set-Cookie 里捞一个 JWT。
func findJWT(v *respView) string {
	for _, m := range jwtRe.FindAllString(v.Text, 4) {
		if parseJWT(m) != nil {
			return m
		}
	}
	for _, sc := range v.SetCookies {
		val := sc
		if i := strings.IndexByte(val, '='); i > 0 {
			val = val[i+1:]
			if j := strings.IndexByte(val, ';'); j >= 0 {
				val = val[:j]
			}
		}
		val = strings.TrimSpace(val)
		if parseJWT(val) != nil {
			return val
		}
	}
	return ""
}

// jwtCandidates 可能吐 token 的地址，按「信息密度」排序：
//
//  1. ctx.URLs 里形似 API / 登录的落点（token 基本都在这）
//  2. 常见的登录/令牌接口（爬虫没爬到时的兜底）
//  3. ctx.URLs 的其余落点（静态页里偶尔也有 SSR 注入的 token）
//
// 排序而不是简单拼接：harvest 只有 5 次预算，爬虫落点前 5 条往往是首页和
// 静态资源，直接拼接会让 /api/login 永远轮不上，检查就静默失效了。
func jwtCandidates(ctx *scan.Ctx) []string {
	var apiish, others []string
	for _, u := range ctx.URLs {
		if !sameOrigin(ctx, u) {
			continue
		}
		n := httpc.NormURL(u)
		p := pathOf(n)
		if containsAny(p, "/api/", "/v1/", "/v2/", "/v3/", "graphql") || loginishPath(n) {
			apiish = append(apiish, n)
			continue
		}
		others = append(others, n)
	}

	seen := map[string]bool{}
	out := make([]string, 0, len(apiish)+len(others)+8)
	addOne := func(u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	addAll := func(us []string) {
		for _, u := range us {
			addOne(u)
		}
	}
	addAll(apiish)
	for _, p := range []string{
		"/api/login", "/api/auth/login", "/api/auth/token", "/login",
		"/api/user/info", "/api/me", "/api/v1/user/info", "/api/user/current",
	} {
		addOne(httpc.BuildURLJoin(ctx.Base, p))
	}
	addAll(others)
	return out
}

// jwtTargets 复放地址：排除登录入口（往登录接口带 token 没有意义）。
func jwtTargets(ctx *scan.Ctx) []string {
	var out []string
	for _, u := range jwtCandidates(ctx) {
		if loginishPath(u) {
			continue
		}
		out = append(out, u)
	}
	if len(out) == 0 && ctx.Base != "" {
		out = append(out, httpc.BuildURLJoin(ctx.Base, "/"))
	}
	if len(out) > 4 {
		out = out[:4]
	}
	return out
}

func harvestJWT(ctx *scan.Ctx, p *prober, maxProbes int) *jwtInfo {
	n := 0
	for _, u := range jwtCandidates(ctx) {
		if n >= maxProbes || !p.left() {
			break
		}
		n++
		v := viewOf(p.do("GET", u, nil, nil))
		if v.Err != nil {
			continue
		}
		if raw := findJWT(v); raw != "" {
			if j := parseJWT(raw); j != nil {
				j.FoundAt = u
				return j
			}
		}
	}
	return nil
}

// jwtBaseline 可信认证基线：原 token 能换到 200 + 非空响应，
// 而且**这个接口确实在看 token**（匿名响应与带 token 的响应不同）。
//
// 为什么后者是硬条件：真实目标里最先命中的往往是公开接口（/api/order/12、
// /api/public），它对谁都是 200。拿它当基线，之后「伪造 token 也返回 200」
// 什么都证明不了 —— 要么误报，要么只能 skip 掉整项检查。
// 实测（litmus run 打本地靶场）就踩过这个坑：基线落在公开的 /api/order/12，
// alg=none 检查整项退化成 skip。
type jwtBaseline struct {
	URL  string
	Resp *respView // 带原 token
	Anon *respView // 不带任何认证头
}

func establishJWTBaseline(ctx *scan.Ctx, p *prober, tok *jwtInfo) (*jwtBaseline, string) {
	var publicOnly *jwtBaseline
	for _, u := range jwtTargets(ctx) {
		if !p.left() {
			break
		}
		v := viewOf(p.do("GET", u, bearer(tok.Raw), nil))
		if v.Err != nil || v.Status != 200 || v.Len == 0 {
			continue
		}
		if isErrorBody(v.scanText()) || hasPasswordInput(v.Text) {
			continue
		}
		anon := viewOf(p.do("GET", u, nil, nil))
		if anon.Err != nil {
			continue
		}
		bl := &jwtBaseline{URL: u, Resp: v, Anon: anon}
		// 匿名被拒 / 匿名内容不同 → 这个接口真的在按 token 区分身份。
		if anon.Status != 200 || anon.Sig != v.Sig {
			return bl, ""
		}
		if publicOnly == nil {
			publicOnly = bl
		}
	}
	if publicOnly != nil {
		return nil, "候选接口对匿名与带 token 的响应完全一致，无法确认 token 是否被接受"
	}
	return nil, "发现 JWT 但无接口接受该 token，无法建立认证基线"
}

// ---------------------------------------------------------------- 检查 3

func runJWTNone(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	p := newProber(ctx)
	tok := harvestJWT(ctx, p, 5)
	if tok == nil {
		return scan.Skip("未发现 JWT")
	}
	bl, reason := establishJWTBaseline(ctx, p, tok)
	if bl == nil {
		return scan.Skip(reason)
	}
	forged := forgeAlgNone(tok)
	if forged == "" {
		return scan.Skip("无法构造 alg=none token（header 不可解析）")
	}
	att := viewOf(p.do("GET", bl.URL, bearer(forged), nil))
	if att.Err != nil {
		return scan.Skip("alg=none 复放请求失败：" + att.Err.Error())
	}
	switch {
	case att.Status == 401 || att.Status == 403:
		return scan.OK(p.used()) // 已拒绝
	case att.Status != 200:
		return scan.OK(p.used()) // 302/400 都不算绕过
	case att.Len == 0 || isErrorBody(att.scanText()) || hasPasswordInput(att.Text):
		// 200 但落地页是「token 无效」/登录页：这是错误页伪装成 200，
		// 不算通过认证。没有这道闸，空响应 + 回显错误文案会被报成绕过。
		return scan.OK(p.used())
	case bl.Anon.Status == 200 && att.Sig == bl.Anon.Sig:
		// 基线接口已知会按 token 区分身份；伪造 token 得到的就是匿名那份内容
		// → 服务端没把它当已认证请求，不是绕过。
		return scan.OK(p.used())
	}

	extra := map[string]interface{}{
		"path":         pathOf(bl.URL),
		"endpoint":     bl.URL,
		"original_alg": tok.Alg,
		"forged_alg":   "none",
		"token_masked": maskToken(tok.Raw),
		"status":       att.Status,
		"anon_status":  bl.Anon.Status,
	}
	f := model.NewFinding("authz/jwt-none", "JWT alg=none 认证绕过", "critical", ctx.Base, model.FindingOpts{
		Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
		Level: "L2", Confidence: "confirmed",
		Evidence: fmt.Sprintf(
			"对 %s 复放去掉签名的 JWT（header.alg 由 %s 改为 none）：原 token → HTTP 200；"+
				"alg=none token → HTTP 200，且响应体与匿名请求（HTTP %d）不同，说明服务端把它当作已认证请求处理。"+
				"token 已打码：%s",
			bl.URL, tok.Alg, bl.Anon.Status, maskToken(tok.Raw)),
		Repro: fmt.Sprintf("把 token 的 header 解出、alg 改为 none、删掉第三段，再 curl -sS -i -H 'Authorization: Bearer <改造后的 token>' '%s'，观察是否仍为 200。", bl.URL),
		Impact: "攻击者无需任何密钥即可伪造任意身份的 token（改 payload 里的 sub/role 即可），" +
			"等同于完全接管认证体系。",
		Fix: "服务端显式白名单允许的 alg（只允许 RS256/ES256 或 HS256），拒绝 none 与空签名；" +
			"升级/替换不校验 alg 的 JWT 库；在网关层统一校验 token 头。",
		CVSS:    "9.1",
		TitleEN: "JWT alg=none Authentication Bypass",
		Extra:   extra,
	})
	return scan.OK(p.used(), f)
}

// ---------------------------------------------------------------- 检查 4

func runJWTWeakKey(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	p := newProber(ctx)
	tok := harvestJWT(ctx, p, 5)
	if tok == nil {
		return scan.Skip("未发现 JWT")
	}
	bl, reason := establishJWTBaseline(ctx, p, tok)
	if bl == nil {
		return scan.Skip(reason)
	}

	var (
		cand *respView
		hits []string
	)
	for _, key := range weakJWTKeys {
		if !p.left() {
			break
		}
		forged := signHS256(tok, key)
		if forged == "" {
			continue
		}
		v := viewOf(p.do("GET", bl.URL, bearer(forged), nil))
		if v.Err != nil || v.Status != 200 || v.Len == 0 {
			continue
		}
		if isErrorBody(v.scanText()) || hasPasswordInput(v.Text) {
			continue // 200 的错误页不算签名被接受
		}
		// 与匿名响应一致 = 这个接口本来就公开，不能算「签名被接受」
		if bl.Anon.Status == 200 && v.Sig == bl.Anon.Sig {
			continue
		}
		cand = v
		hits = append(hits, key)
		break // 一把弱密钥就够定论了
	}
	if cand == nil {
		return scan.OK(p.used())
	}

	extra := map[string]interface{}{
		"path":           pathOf(bl.URL),
		"endpoint":       bl.URL,
		"original_alg":   tok.Alg,
		"weak_key":       hits[0],
		"status":         cand.Status,
		"anon_status":    bl.Anon.Status,
		"token_masked":   maskToken(tok.Raw),
		"keys_attempted": len(weakJWTKeys),
	}
	f := model.NewFinding("authz/jwt-weak-key", "JWT 使用可猜测的签名密钥", "critical", ctx.Base, model.FindingOpts{
		Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
		Level: "L2", Confidence: "confirmed",
		Evidence: fmt.Sprintf(
			"对 %s：用常见弱密钥字典中的 %q 重算 HS256 签名后，服务端返回 HTTP 200（匿名请求为 HTTP %d），"+
				"说明该密钥就是服务端签名密钥。可据此伪造任意身份的 token。token 已打码：%s",
			bl.URL, hits[0], bl.Anon.Status, maskToken(tok.Raw)),
		Repro: fmt.Sprintf("用密钥 %q 对「原 token 的 header.payload」重算 HMAC-SHA256 并拼成新 token，"+
			"curl -sS -i -H 'Authorization: Bearer <新 token>' '%s'，观察是否 200。", hits[0], bl.URL),
		Impact: "签名密钥是字典词，攻击者可离线签发任意用户/任意角色的 token，无需触碰服务端。" +
			"（本工具只做了 6 次字典验证，未做大字典爆破。）",
		Fix: "更换为 256 位以上随机密钥（openssl rand -base64 48），从配置/密钥管理系统注入，" +
			"轮换所有已签发 token；禁止使用产品默认密钥或可猜测短语。",
		CVSS:    "9.8",
		TitleEN: "JWT Signed With Guessable Key",
		Extra:   extra,
	})
	return scan.OK(p.used(), f)
}

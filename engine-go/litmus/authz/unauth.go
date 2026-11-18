package authz

// unauth.go —— 未授权 API 探测（带对照，容不下「公开接口」被当成漏洞）。
//
// 这类检查的误报来源只有一个：把本来就公开的接口（/api/version、公开文章列表）
// 报成「未授权访问」。所以判据不是「匿名能读」——那本来就是事实——而是
// 「匿名能读，且带认证的请求看到的东西**不一样**」。
//
// 两段式：
//  1. 有可信认证基线（harvest 到的 JWT 且服务端接受）：
//     匿名响应 == 认证响应  → 公开接口，压掉不报（对照生效）
//     匿名响应 != 认证响应  → 命中，L2 confirmed
//  2. 没有认证基线：用「伪造凭据」做对照。
//     伪造响应与匿名响应逐字节一致 → 接口不区分凭据；只能报 L1 likely，
//     并在证据里写明「未取得有效认证基线，不能排除该接口本就公开」。
//     这正是三态原则：判不准就降级 + 说清楚，而不是硬报一条中危。

import (
	"fmt"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(scan.Check{
		Meta: mk("unauth-api", "未授权访问 API", "medium", "CWE-306"),
		Run:  runUnauthAPI,
	})
}

// sensitiveKeys 任务要求的敏感字段集。
var sensitiveKeys = []string{"users", "data", "list", "total", "records", "token"}

// strongKeys 单独出现就能说明「这是业务数据」的字段。
//
// 为什么还要这一层：{"data":[],"list":[]} 这种空壳结构在公开接口里遍地都是，
// 只按敏感字段集判定会把一半的官网新闻列表报成未授权。要求至少一个强标记
// 或两个普通标记，是为了压掉这一类。
var strongKeys = []string{
	"users", "records", "total", "accounts", "orders", "members", "userlist", "employees",
}

func strongEnough(fields []string) bool {
	n := 0
	for _, f := range fields {
		for _, s := range strongKeys {
			if f == s {
				return true
			}
		}
		n++
	}
	return n >= 2
}

// bogusAuth 伪造凭据对照组：语法合法但一定无效。
func bogusAuth() []httpc.Header {
	return []httpc.Header{
		{Name: "Authorization", Value: "Bearer litmus_probe..."},
		{Name: "Cookie", Value: "litmus_probe=0000"},
	}
}

// apiCandidates 从爬虫落点里挑形似 API 的地址（任务要求只从 ctx.URLs 里取）。
func apiCandidates(ctx *scan.Ctx, max int) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range ctx.URLs {
		if !sameOrigin(ctx, u) {
			continue
		}
		p := pathOf(u)
		if !containsAny(p, "/api/", "/v1/", "/v2/", "/v3/") && !strings.HasSuffix(p, "/api") {
			continue
		}
		n := httpc.NormURL(u)
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
		if len(out) >= max {
			break
		}
	}
	return out
}

// sensitiveFields 响应里出现了哪些敏感字段名（只回名字，不回内容）。
func sensitiveFields(v *respView) []string {
	found := map[string]bool{}
	if v.JSONOK {
		collectKeys(v.JSON, 0, found)
	}
	if len(found) == 0 {
		// JSON 解析失败时的兜底：按 `"key":` 形态找
		low := strings.ToLower(v.Text)
		for _, k := range sensitiveKeys {
			if strings.Contains(low, `"`+k+`"`) {
				found[k] = true
			}
		}
	}
	var out []string
	for _, k := range sensitiveKeys {
		if found[k] {
			out = append(out, k)
		}
	}
	return out
}

func runUnauthAPI(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	cands := apiCandidates(ctx, 4)
	if len(cands) == 0 {
		return scan.Skip("未发现形似 API 的路径")
	}
	p := newProber(ctx)

	// 认证基线：能拿到并且被服务端接受的 JWT 才算数。
	// 预算给到 5：爬虫落点前几条常是首页/公开接口，令牌一般在登录接口里，
	// 给少了就只能退化成「伪造凭据」那档（L1 likely），判不出真结论。
	tok := harvestJWT(ctx, p, 5)
	var authHdr []httpc.Header
	if tok != nil {
		authHdr = bearer(tok.Raw)
	}

	var (
		fs       []*model.Finding
		compared int
	)
	for _, u := range cands {
		if !p.left() {
			break
		}
		anon := viewOf(p.do("GET", u, nil, nil))
		if anon.Err != nil || anon.Status != 200 || anon.Len == 0 {
			continue
		}
		fields := sensitiveFields(anon)
		if len(fields) == 0 || !strongEnough(fields) {
			continue
		}

		// ---- 第一段：有可信认证基线，做真正的差分对照
		if authHdr != nil {
			auth := viewOf(p.do("GET", u, authHdr, nil))
			// 「200 + 错误页」不算认证基线：拿它去比会把认证失败页当成「能看到更多」，
			// 直接把公开接口报成未授权。宁可退回伪造凭据对照，也不在这里下结论。
			if auth.Err == nil && auth.Status == 200 && auth.Len > 0 &&
				!isErrorBody(auth.scanText()) && !hasPasswordInput(auth.Text) {
				compared++
				if auth.Sig == anon.Sig {
					// 公开接口：带上会话看到的是同一份内容 → 对照生效，压掉不报。
					continue
				}
				fs = append(fs, unauthFinding(ctx, u, fields, anon, auth, "confirmed", "L2",
					"带认证基线的响应与匿名响应不同"))
				continue
			}
			// token 没被这个接口接受：退回伪造凭据对照
		}

		// ---- 第二段：没有认证基线，用伪造凭据做对照
		bogus := viewOf(p.do("GET", u, bogusAuth(), nil))
		if bogus.Err != nil {
			continue
		}
		compared++
		if bogus.Sig != anon.Sig {
			// 接口对伪造凭据的反应与匿名不同 → 说明它确实在区分凭据，
			// 此时无法排除匿名 200 是设计如此，不下结论。
			continue
		}
		fs = append(fs, unauthFinding(ctx, u, fields, anon, bogus, "likely", "L1",
			"未取得有效认证基线；伪造凭据与匿名响应逐字节一致"))
	}

	if len(fs) > 0 {
		return scan.OK(p.used(), fs...)
	}
	if compared == 0 {
		return scan.Skip("形似 API 的路径均未返回 200 + 敏感字段，未做访问控制对比")
	}
	// 测了但没命中：要么是被对照压掉的公开接口，要么敏感字段不够强。
	// 两种都不该报 —— 这条检查的误报代价比漏报高得多。
	return scan.OK(p.used())
}

func unauthFinding(ctx *scan.Ctx, u string, fields []string,
	anon, other *respView, conf, level, control string) *model.Finding {

	var ev string
	if conf == "confirmed" {
		ev = fmt.Sprintf(
			"GET %s 不带任何 Cookie/Authorization → HTTP 200，响应含字段 %s；"+
				"带认证基线（既有 JWT 会话）→ 响应与匿名响应不同（%d 字节 vs %d 字节）。"+
				"说明匿名请求读到了需要认证才能看到的数据。（只记录字段名，不保留内容。）",
			u, strings.Join(fields, ","), anon.Len, other.Len)
	} else {
		ev = fmt.Sprintf(
			"GET %s 不带任何 Cookie/Authorization → HTTP 200，响应含字段 %s；"+
				"对照：带伪造凭据的请求与匿名响应逐字节一致（%d 字节，指纹 %s）。"+
				"未取得有效认证基线，因此不能排除该接口本就公开 —— 按「疑似」记录，需人工确认。"+
				"（只记录字段名，不保留内容。）",
			u, strings.Join(fields, ","), anon.Len, anon.Sig)
	}

	return model.NewFinding("authz/unauth-api", "未授权访问 API", "medium", ctx.Base, model.FindingOpts{
		Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
		Level: level, Confidence: conf,
		Evidence: ev,
		Repro: fmt.Sprintf("curl -sS -i '%s'（不带 Cookie/Authorization）；"+
			"再带一个有效会话打同一地址，对比两者返回的数据范围。", u),
		Impact: "匿名用户可以读取接口返回的业务数据（用户/记录/配置）。" +
			"若该接口本应要求登录，等于访问控制完全缺失。",
		Fix: "在网关或框架层对该路径强制鉴权（默认拒绝），匿名可访问的路径显式列入白名单；" +
			"补一条「匿名访问受保护接口」的自动化回归测试。",
		CVSS:    "5.3",
		TitleEN: "Unauthenticated API Access",
		Extra: map[string]interface{}{
			"path":          pathOf(u),
			"endpoint":      u,
			"sensitive":     fields,
			"control":       control,
			"anon_len":      anon.Len,
			"control_len":   other.Len,
			"baseline_kind": baselineKind(conf),
		},
	})
}

func baselineKind(conf string) string {
	if conf == "confirmed" {
		return "authenticated-session"
	}
	return "bogus-credential"
}

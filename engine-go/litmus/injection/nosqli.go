package injection

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ NoSQL 注入

// nosqlRounds 成对请求重复轮数：只有每轮「恒真 ≠ 恒假」都成立才报。
const nosqlRounds = 3

// nosqlPair 一对逻辑上互斥的查询操作符：
// 恒真分支（$ne / $gt / $regex）匹配所有文档，恒假分支（$eq 一个不存在的值）匹配零文档。
// 两者响应稳定不同 = 服务端把操作符当查询语义执行了。
type nosqlPair struct {
	label      string
	name       string // 参数名模板，%s 是原参数名
	value      string
	falseName  string
	falseValue string
}

func nosqlPairs(mk string) []nosqlPair {
	return []nosqlPair{
		{"$ne 恒真 / $eq 恒假", "%s[$ne]", mk, "%s[$eq]", mk},
		{"$gt 恒真 / $eq 恒假", "%s[$gt]", "", "%s[$eq]", mk},
		{"$regex 恒真 / $eq 恒假", "%s[$regex]", "^.*$", "%s[$eq]", mk},
	}
}

// jsonPair JSON 值形态：值本身是 JSON 对象时，替换成带操作符的对象。
type jsonPair struct{ label, truthy, falsy string }

func jsonPairs(mk string) []jsonPair {
	return []jsonPair{
		{"JSON $ne 恒真 / $eq 恒假",
			`{"$ne":"` + mk + `"}`, `{"$eq":"` + mk + `"}`},
	}
}

func looksJSONObject(v string) bool {
	t := strings.TrimSpace(v)
	if !strings.HasPrefix(t, "{") || !strings.HasSuffix(t, "}") {
		return false
	}
	return json.Valid([]byte(t))
}

// pairDiffers 判断一对响应是否构成「恒真 ≠ 恒假」。
//
// 额外约束：两者状态码必须相同且是成功响应 —— 一个 400 一个 200 通常只说明
// 服务端不认识 [$ne] 这种参数名，不是注入。
func pairDiffers(t, f *snap) bool {
	if !t.ok() || !f.ok() {
		return false
	}
	if t.status() != f.status() {
		return false
	}
	if t.status() < 200 || t.status() >= 400 {
		return false
	}
	return t.differs(f)
}

func runNoSQL(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	pts, total := pointsOf(c, 8, nil)
	if len(pts) == 0 {
		return scan.Skip(noPointReason(c))
	}
	o := &outcome{points: len(pts)}
	o.noteTruncated(total, len(pts))
	mk := marker("nosql")

	for _, pt := range pts {
		if p.blockedMsg != "" {
			break
		}
		b := p.fetch(get(pt.rawURL))
		if !b.ok() {
			o.fail("基线不可达 " + pt.endpoint() + "：" + b.errText())
			continue
		}
		o.okPoints++
		if f := probeNoSQL(p, c, pt, b, mk); f != nil {
			o.add(f)
		} else if p.blockedMsg != "" {
			break
		}
	}
	return o.result(p)
}

func probeNoSQL(p *prober, c *scan.Ctx, pt point, b *snap, mk string) *model.Finding {
	for _, pr := range nosqlPairs(mk) {
		tu := pt.withName(fmt.Sprintf(pr.name, pt.name), url.QueryEscape(pr.value))
		fu := pt.withName(fmt.Sprintf(pr.falseName, pt.name), url.QueryEscape(pr.falseValue))
		if f := verifyNoSQLPair(p, c, pt, tu, fu, pr.label, b); f != nil {
			return f
		}
	}
	if looksJSONObject(pt.value) {
		for _, jp := range jsonPairs(mk) {
			tu := pt.withValueOnly(jp.truthy)
			fu := pt.withValueOnly(jp.falsy)
			if f := verifyNoSQLPair(p, c, pt, tu, fu, jp.label+"（JSON 值）", b); f != nil {
				return f
			}
		}
	}
	return nil
}

// verifyNoSQLPair 多轮验证一对恒真/恒假请求，全部轮次结论一致才出发现。
func verifyNoSQLPair(p *prober, c *scan.Ctx, pt point, truthyURL, falsyURL, label string,
	b *snap) *model.Finding {

	var firstT, firstF *snap
	for round := 0; round < nosqlRounds; round++ {
		t := p.fetch(get(truthyURL))
		f := p.fetch(get(falsyURL))
		if !t.ok() || !f.ok() || !pairDiffers(t, f) {
			return nil
		}
		if round == 0 {
			firstT, firstF = t, f
			continue
		}
		if !firstT.similar(t) || !firstF.similar(f) {
			return nil // 不稳定：响应随轮次漂移，不能归因于注入
		}
	}
	if firstT == nil || firstF == nil {
		return nil
	}
	return newFinding(c, metaNoSQL, findingOpts{
		sev:   "high",
		level: "L2",
		conf:  "likely",
		evidence: fmt.Sprintf("参数: %s = %s（%s）\n恒真分支: GET %s → HTTP %d / %dB / %s\n恒假分支: GET %s → HTTP %d / %dB / %s\n基线:     GET %s → HTTP %d / %dB / %s\n%d 轮结果一致：恒真与恒假响应稳定不同（Δ%dB）",
			pt.name, pt.value, label,
			truthyURL, firstT.status(), firstT.length(), firstT.sig[:12],
			falsyURL, firstF.status(), firstF.length(), firstF.sig[:12],
			pt.rawURL, b.status(), b.length(), b.sig[:12],
			nosqlRounds, absInt(firstT.length()-firstF.length())),
		repro:  curlGet(truthyURL),
		impact: "查询操作符被直接传入数据库层，可绕过登录条件或读出未授权文档（NoSQL 注入）。",
		fix:    "对入参做类型白名单（字符串强制转字符串、拒绝对象/数组），禁止把请求结构直接交给查询构造器。",
		extra: map[string]interface{}{
			"path": pathOf(truthyURL), "param": pt.name,
			"truthy": truthyURL, "falsy": falsyURL, "rounds": nosqlRounds,
		},
	})
}

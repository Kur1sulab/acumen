package authz

// idor.go —— 越权 / IDOR 的低风险探测。
//
// 只改路径里的数字 ID（+1 / -1 / 0），只发 GET，绝不带写操作。三道闸：
//  1. 路径里只允许**一个**数字段。没有这道闸，/news/2024/05/12 这种日期路径
//     会被当成 ID，改一位就「返回了不同对象」，全是误报。
//  2. 路径里出现 delete/update/reset 这类动词直接跳过 —— 有些框架真用 GET 干活，
//     对着这种路径做探测就是越界。
//  3. 变异后的响应必须是 200、非空、且不像错误页（不存在/无权/参数错误）。
//
// 报告里**不 dump 任何响应内容**：越权拿到的往往就是别人的个人信息，
// 把它原样写进报告，等于我们自己又泄露一次。证据只说「ID 从 X 改到 Y 后
// 返回了不同对象」+ 两个响应的长度，够复现，不泄数据。

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(scan.Check{
		Meta: mk("idor-probe", "越权/IDOR（低风险探测）", "medium", "CWE-639"),
		Run:  runIDORProbe,
	})
}

// dangerousVerbs 路径里出现这些词就不碰：不是「读」的语义。
var dangerousVerbs = []string{
	"delete", "remove", "destroy", "update", "edit", "create", "add",
	"import", "upload", "reset", "logout", "grant", "revoke", "pay",
	"submit", "cancel", "approve", "reject",
}

type idorTarget struct {
	URL string
	ID  int
	Mut func(int) string
}

// splitID 找出路径里唯一的数字段并返回改名函数。
func splitID(rawURL string) (int, func(int) string, bool) {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return 0, nil, false
	}
	prefix := rawURL[:i+3]
	rest := rawURL[i+3:]
	query := ""
	if k := strings.IndexAny(rest, "?#"); k >= 0 {
		query = rest[k:]
		rest = rest[:k]
	}
	segs := strings.Split(rest, "/")
	idx := -1
	count := 0
	for k := 1; k < len(segs); k++ {
		if isDigits(segs[k]) {
			count++
			idx = k
		}
	}
	if count != 1 || idx < 0 {
		return 0, nil, false
	}
	id, err := strconv.Atoi(segs[idx])
	if err != nil || id < 0 || len(segs[idx]) > 10 {
		return 0, nil, false
	}
	mut := func(newID int) string {
		cp := make([]string, len(segs))
		copy(cp, segs)
		cp[idx] = strconv.Itoa(newID)
		return prefix + strings.Join(cp, "/") + query
	}
	return id, mut, true
}

func idorCandidates(ctx *scan.Ctx, max int) []idorTarget {
	var out []idorTarget
	seen := map[string]bool{}
	for _, u := range ctx.URLs {
		if !sameOrigin(ctx, u) {
			continue
		}
		if containsAny(pathOf(u), dangerousVerbs...) {
			continue
		}
		n := httpc.NormURL(u)
		if seen[n] {
			continue
		}
		seen[n] = true
		id, mut, ok := splitID(n)
		if !ok {
			continue
		}
		out = append(out, idorTarget{URL: n, ID: id, Mut: mut})
		if len(out) >= max {
			break
		}
	}
	return out
}

func runIDORProbe(ctx *scan.Ctx) scan.Result {
	if ctx.Base == "" {
		return scan.Skip("无 Web 探测目标")
	}
	cands := idorCandidates(ctx, 3)
	if len(cands) == 0 {
		return scan.Skip("未发现带数字 ID 的路径")
	}
	p := newProber(ctx)
	var (
		fs       []*model.Finding
		compared int
	)
	for _, c := range cands {
		if !p.left() {
			break
		}
		orig := viewOf(p.do("GET", c.URL, nil, nil))
		if orig.Err != nil || orig.Status != 200 || orig.Len < 32 {
			continue
		}
		if isErrorBody(orig.scanText()) {
			continue
		}
		compared++
		for _, delta := range []int{1, -1, 0} {
			if !p.left() {
				break
			}
			nid := c.ID + delta
			if nid < 0 || nid == c.ID {
				continue
			}
			mut := viewOf(p.do("GET", c.Mut(nid), nil, nil))
			if mut.Err != nil || mut.Status != 200 || mut.Len < 32 {
				continue
			}
			if mut.Sig == orig.Sig {
				continue // 同一份内容（常见的「ID 不存在就回列表」）
			}
			if isErrorBody(mut.scanText()) {
				continue // 200 + 错误页
			}
			fs = append(fs, idorFinding(ctx, c.ID, nid, c.URL, c.Mut(nid), orig, mut))
			break
		}
	}
	if len(fs) == 0 {
		if compared == 0 {
			return scan.Skip("数字 ID 路径均不可达、返回非 200 或响应过短（<32 字节），未做对比")
		}
		return scan.OK(p.used())
	}
	return scan.OK(p.used(), fs...)
}

func idorFinding(ctx *scan.Ctx, from, to int, origURL, mutURL string, orig, mut *respView) *model.Finding {
	return model.NewFinding("authz/idor-probe", "越权/IDOR（疑似）", "medium", ctx.Base, model.FindingOpts{
		Host: ctx.Host, Port: ctx.Port, Scheme: ctx.Scheme, Category: "web",
		Level: "L1", Confidence: "likely",
		Evidence: fmt.Sprintf(
			"对 %s：ID 从 %d 改为 %d 后返回了不同对象（两请求均 HTTP 200，响应 %d → %d 字节，指纹不同）。"+
				"未保留响应内容（脱敏）；需人工确认 %d 号对象是否属于其他用户/租户。",
			origURL, from, to, orig.Len, mut.Len, to),
		Repro: fmt.Sprintf("curl -sS -o /tmp/a '%s'；curl -sS -o /tmp/b '%s'；diff <(wc -c </tmp/a) <(wc -c </tmp/b)"+
			"——两次返回不同对象即可复现。用两个不同账号交叉验证归属后即可定为越权。",
			origURL, mutURL),
		Impact: "若能以当前身份读到他人对象，即可批量遍历 ID 拉取全量数据（用户资料、订单、工单）。" +
			"本条只证明「不同 ID 返回不同对象」，尚未证明归属，因此定为 L1 疑似。",
		Fix: "在服务端按对象做归属校验（当前用户 ID 与对象 owner 比对），不要只依赖前端隐藏 ID；" +
			"对批量遍历做频率限制与告警；ID 改为不可枚举的 UUID 只能降低风险、不能替代归属校验。",
		CVSS:    "5.3",
		TitleEN: "Suspected IDOR / Broken Object Level Authorization",
		Extra: map[string]interface{}{
			"path":        pathOf(origURL),
			"endpoint":    origURL,
			"mutated":     mutURL,
			"from_id":     from,
			"to_id":       to,
			"len_before":  orig.Len,
			"len_after":   mut.Len,
			"sample_kept": false,
		},
	})
}

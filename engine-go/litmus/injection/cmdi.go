package injection

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ 命令注入

// 只读命令：id 的输出格式稳定（uid=…(…)，gid=…(…)，groups=…），
// 拿它做特征最可靠；whoami 的输出是任意用户名，无法与页面文本区分，故不用于判定。
var cmdiPayloads = []struct{ label, text string }{
	{"分号", ";id"},
	{"管道", "|id"},
	{"反引号", "`id`"},
	{"命令替换 $()", "$(id)"},
	{"与号", "&&id"},
	{"换行", "\nid"},
}

var (
	// idStrongRe uid=0(root) 这种带括号的形态，几乎只可能来自 id 命令
	idStrongRe = regexp.MustCompile(`uid=\d+\([^)]{0,40}\)`)
	// idWeakRe uid=1000 这种无括号形态：只有基线里完全没有 uid=/gid= 时才采信
	idWeakRe = regexp.MustCompile(`\b(uid|gid)=\d+`)
)

// matchID 在响应里找 id 命令输出。返回 (命中片段, 是否强特征)。
func matchID(text string) (string, bool) {
	if m := idStrongRe.FindString(text); m != "" {
		return m, true
	}
	if m := idWeakRe.FindString(text); m != "" {
		return m, false
	}
	return "", false
}

func cmdiTimePairs() []struct{ label, slow, fast string } {
	n := itoa(sleepSeconds)
	return []struct{ label, slow, fast string }{
		{"分号 sleep", ";sleep " + n, ";sleep 0"},
		{"管道 sleep", "|sleep " + n, "|sleep 0"},
	}
}

func runCMDI(c *scan.Ctx) scan.Result {
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
		if hit, _ := matchID(b.text); hit != "" {
			o.note("基线响应已含 " + hit + "，该点无法用 id 输出归因")
			continue
		}
		found := false
		for _, pl := range cmdiPayloads {
			u := pt.withValueAppend(pl.text)
			r := p.fetch(get(u))
			if !r.ok() {
				o.fail("payload 请求失败：" + r.errText())
				continue
			}
			hit, strong := matchID(r.text)
			if hit == "" {
				continue
			}
			// 基线里已经有同一个片段 → 不是 payload 带来的
			if strings.Contains(b.text, hit) {
				continue
			}
			// 复现：同 payload 再打一发
			r2 := p.fetch(get(u))
			hit2, _ := matchID(r2.text)
			if !r2.ok() || hit2 == "" {
				continue
			}
			conf := "likely"
			if strong && hit2 == hit {
				conf = "confirmed"
			}
			o.add(newFinding(c, metaCMDI, findingOpts{
				sev:   "critical",
				level: "L2",
				conf:  conf,
				evidence: fmt.Sprintf("参数: %s = %s\npayload: %s\n请求: GET %s\n基线: HTTP %d / %dB / 无 id 输出特征\npayload 响应: HTTP %d / %dB\n命令输出片段: %s\n二次请求复现: 是（%s）",
					pt.name, pt.value, pl.text, u, b.status(), b.length(),
					r.status(), r.length(), snippetCI(r.text, hit, 80), hit2),
				repro:  curlGet(u),
				impact: "攻击者可在服务器上以 Web 进程权限执行任意系统命令，通常等同于服务器失守。",
				fix:    "禁止把用户输入拼进 shell；改用 exec 数组参数（不经 shell），并对参数做严格白名单校验。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "payload": pl.text,
					"output": hit, "strong_signal": strong,
				},
			}))
			found = true
			break
		}
		if found {
			continue
		}
		// 第二路验证：时间盲注（无回显时命令注入仍然成立）
		if f := probeTiming(p, c, metaCMDI, pt, max(b.elapsed(), time.Millisecond), cmdiTimePairs()); f != nil {
			o.add(f)
		}
	}
	return o.result(p)
}

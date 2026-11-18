package injection

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

// ================================================================ 报错注入

// sqlErrSigs 各数据库的报错特征。全部小写，匹配的是「正文+响应头」拼接后的文本。
//
// 为什么把 "sql syntax" 这种宽泛串也收进来：契约要求覆盖 MySQL/PostgreSQL/
// MSSQL/Oracle/SQLite 五家，宽泛串是兜底；误报由「基线必须不含该特征 + 复现一次」
// 两道对照挡住，不靠特征串本身精确。
var sqlErrSigs = []struct{ db, key string }{
	{"MySQL", "you have an error in your sql syntax"},
	{"MySQL", "sql syntax"},
	{"MySQL", "supplied argument is not a valid mysql"},
	{"MySQL", "mysql_fetch_"},
	{"MySQL", "warning: mysql_"},
	{"PostgreSQL", "error: syntax error at or near"},
	{"PostgreSQL", "pg_query"},
	{"PostgreSQL", "pg_exec"},
	{"PostgreSQL", "unterminated quoted string at or near"},
	{"MSSQL", "incorrect syntax near"},
	{"MSSQL", "unclosed quotation mark after the character string"},
	{"MSSQL", "microsoft ole db provider for sql server"},
	{"Oracle", "ora-0"},
	{"Oracle", "quoted string not properly terminated"},
	{"SQLite", "sqlite_error"},
	{"SQLite", "sqlite3::"},
	{"SQLite", "unrecognized token:"},
	{"通用", "sqlstate["},
	{"通用", "sqlexception"},
}

// sqlErrRes 需要结构化匹配的两条：SQLite 的 near "xxx"，以及 MySQL 的完整报错句
var sqlErrRes = []struct {
	db string
	re *regexp.Regexp
}{
	{"SQLite", regexp.MustCompile(`near\s+"[^"]{1,40}"`)},
	{"MySQL", regexp.MustCompile(`sql syntax[^<\n]{0,80}`)},
}

// matchSQL 在文本里找数据库报错特征，返回 (数据库名, 命中的片段)
func matchSQL(text string) (string, string) {
	for _, s := range sqlErrSigs {
		if i := strings.Index(text, s.key); i >= 0 {
			return s.db, text[i : i+len(s.key)]
		}
	}
	for _, r := range sqlErrRes {
		if m := r.re.FindString(text); m != "" {
			return r.db, m
		}
	}
	return "", ""
}

// sqlQuotePayloads 只做「让 SQL 语法崩掉」的 payload，没有 UNION/SELECT 数据、
// 没有写操作。加注释符是为了让后续条件不干扰报错。
var sqlQuotePayloads = []struct{ label, text string }{
	{"单引号", "'"},
	{"双引号", "\""},
	{"反斜杠", "\\"},
	{"反斜杠+引号", "\\'"},
	{"单引号+右括号", "')"},
	{"单引号+注释", "'-- "},
	{"单引号+井号注释", "'#"},
}

func runSqliError(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	pts, total := pointsOf(c, 12, nil)
	if len(pts) == 0 {
		return scan.Skip(noPointReason(c))
	}
	m := metaSqliError
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
		if db, hit := matchSQL(b.sigText()); db != "" {
			// 基线自己就在报 SQL 错：无法把报错归因到 payload，如实记成「测不了」。
			o.note("基线响应已含 " + db + " 报错特征（" + hit + "），该点不做结论")
			continue
		}
		for _, pl := range sqlQuotePayloads {
			u := pt.withValueAppend(pl.text)
			r := p.fetch(get(u))
			if !r.ok() {
				o.fail("payload 请求失败：" + r.errText())
				continue
			}
			db, hit := matchSQL(r.sigText())
			if db == "" {
				continue
			}
			if strings.Contains(b.sigText(), hit) {
				continue // 基线里有的片段，不能算 PAYLOAD 带来的
			}
			// 复现一次：同一 payload 再打一发，报错特征必须还在。
			// 这一发同时排除了「偶发 500 页面里恰好带 SQL 字样」。
			r2 := p.fetch(get(u))
			db2, _ := matchSQL(r2.sigText())
			if !r2.ok() || db2 == "" || db2 != db {
				continue
			}
			o.add(newFinding(c, m, findingOpts{
				sev:   "high",
				level: "L2",
				conf:  "confirmed",
				evidence: fmt.Sprintf("参数: %s = %s%s\n请求: GET %s\n基线: HTTP %d / %dB / 无 SQL 报错特征\npayload: HTTP %d / %dB / 命中 %s: %q\n响应片段: %s\n二次请求复现: 是",
					pt.name, pt.value, pl.text, u, b.status(), b.length(),
					r.status(), r.length(), db, hit, snippetCI(r.rawText(), hit, 70)),
				repro:  curlGet(u),
				impact: "参数值直接进入 SQL 语句，攻击者可读取任意表数据；若数据库账号权限过高，还可写入或执行系统命令。",
				fix:    "改用参数化查询（预编译绑定），不要拼接 SQL；同时给数据库账号最小权限，并关闭详细报错回显。",
				extra: map[string]interface{}{
					"path": pathOf(u), "param": pt.name, "payload": pl.text,
					"db": db, "signature": hit, "baseline_status": b.status(),
				},
			}))
			break
		}
	}
	return o.result(p)
}

// ================================================================ 布尔盲注

// boolRounds 成对请求重复轮数。3 轮全一致才报 —— 单轮差异在真实站点上
// 可能来自轮询/AB 测试/缓存在热身，重复是唯一便宜的证伪手段。
const boolRounds = 3

type boolPair struct{ label, truePl, falsePl string }

var numericValRe = regexp.MustCompile(`^-?\d+(\.\d+)?$`)

func boolPairs(value string) []boolPair {
	pairs := []boolPair{{"单引号布尔", "' AND '1'='1", "' AND '1'='2"}}
	if numericValRe.MatchString(strings.TrimSpace(value)) {
		pairs = append(pairs, boolPair{"数字布尔", " AND 1=1", " AND 1=2"})
	}
	return pairs
}

func runSqliBoolean(c *scan.Ctx) scan.Result {
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
		if f := probeBoolean(p, c, pt, b, o); f != nil {
			o.add(f)
		}
	}
	return o.result(p)
}

// probeBoolean 对一个参数点做成对请求。
//
// 判定链（缺一不可）：
//  1. 真条件响应 ≈ 基线（差在 1% 内）—— 挡掉「payload 只是被回显」造成的长度变化
//  2. 假条件响应明显偏离基线（长度差 ≥5% 或状态码不同）
//  3. 真 ≠ 假
//  4. 上述结论连续 boolRounds 轮一致
func probeBoolean(p *prober, c *scan.Ctx, pt point, b *snap, o *outcome) *model.Finding {
	for _, pr := range boolPairs(pt.value) {
		var firstT, firstF *snap
		stable := true
		for round := 0; round < boolRounds; round++ {
			tu := pt.withValueAppend(pr.truePl)
			fu := pt.withValueAppend(pr.falsePl)
			t := p.fetch(get(tu))
			f := p.fetch(get(fu))
			if !t.ok() || !f.ok() {
				o.fail("布尔成对请求失败：" + t.errText() + f.errText())
				stable = false
				break
			}
			if !t.similar(b) || !f.differs(b) || !t.differs(f) {
				stable = false
				break
			}
			if round == 0 {
				firstT, firstF = t, f
			}
		}
		if !stable || firstT == nil {
			continue
		}
		tu := pt.withValueAppend(pr.truePl)
		fu := pt.withValueAppend(pr.falsePl)
		conf := "likely"
		if firstT.status() != firstF.status() {
			conf = "confirmed" // 假条件把请求打成 4xx/5xx，是数据库真的在求值
		}
		return newFinding(c, metaSqliBoolean, findingOpts{
			sev:   "high",
			level: "L2",
			conf:  conf,
			evidence: fmt.Sprintf("参数: %s = %s（%s）\n真条件: GET %s → HTTP %d / %dB / %s\n假条件: GET %s → HTTP %d / %dB / %s\n基线:   GET %s → HTTP %d / %dB / %s\n%d 轮成对请求结论一致：真条件≈基线，假条件偏离 %dB",
				pt.name, pt.value, pr.label,
				tu, firstT.status(), firstT.length(), firstT.sig[:12],
				fu, firstF.status(), firstF.length(), firstF.sig[:12],
				pt.rawURL, b.status(), b.length(), b.sig[:12],
				boolRounds, absInt(firstF.length()-b.length())),
			repro:  curlGet(fu),
			impact: "布尔条件可被用来逐字符推断数据库内容（盲注），不需要回显或报错。",
			fix:    "改用参数化查询；对返回内容做统一错误页，避免真假条件产生可区分响应。",
			extra: map[string]interface{}{
				"path": pathOf(fu), "param": pt.name,
				"true_payload": pr.truePl, "false_payload": pr.falsePl,
				"rounds": boolRounds, "true_len": firstT.length(), "false_len": firstF.length(),
			},
		})
	}
	return nil
}

// ================================================================ 时间盲注

// 生产参数：sleep 3 秒，命中要求 ① ≥ 基线 3 倍 ② 至少多 2.5 秒。
// 两个 var 只为单测缩短时间，生产路径从不修改。
var (
	sleepSeconds  = 3
	minSleepDelta = 2500 * time.Millisecond
)

// slowHit 时间盲注的判定阈值（契约原文：>= 基线 3 倍且至少多出 2.5 秒）
func slowHit(base, got time.Duration) bool {
	if base <= 0 {
		base = time.Millisecond
	}
	return got >= 3*base && got-base >= minSleepDelta
}

// timePairs sleep payload 与其「同语法零延迟」对照。
// 对照不能只靠重测基线：网络抖动会让基线本身变慢，而 SLEEP(0) 版本走的是
// 同一条注入路径，它不慢才说明慢是 sleep 带来的。
func timePairs() []struct{ label, slow, fast string } {
	n := itoa(sleepSeconds)
	return []struct{ label, slow, fast string }{
		{"MySQL SLEEP()", "' AND SLEEP(" + n + ")-- -", "' AND SLEEP(0)-- -"},
		{"MySQL SLEEP() 无引号", " AND SLEEP(" + n + ")", " AND SLEEP(0)"},
		{"PostgreSQL pg_sleep()", "';SELECT pg_sleep(" + n + ")-- -", "';SELECT pg_sleep(0)-- -"},
		{"MSSQL WAITFOR", "';WAITFOR DELAY '0:0:" + n + "'-- -", "';WAITFOR DELAY '0:0:0'-- -"},
	}
}

func runSqliTime(c *scan.Ctx) scan.Result {
	p, na := prepare(c)
	if na != nil {
		return *na
	}
	need := time.Duration(sleepSeconds)*time.Second + 2*time.Second
	if p.timeout < need {
		return scan.Skip(fmt.Sprintf("请求超时仅 %.0fs，短于 %ds 延时探测所需的 %.0fs，时间盲注无法可靠判定",
			p.timeout.Seconds(), sleepSeconds, need.Seconds()))
	}
	pts, total := pointsOf(c, 6, nil)
	if len(pts) == 0 {
		return scan.Skip(noPointReason(c))
	}
	o := &outcome{points: len(pts)}
	o.noteTruncated(total, len(pts))

	for _, pt := range pts {
		if p.blockedMsg != "" {
			break
		}
		// 基线取两次中的较小值：抖动只会让耗时变大，最小值最接近真实处理时间。
		b1 := p.fetch(get(pt.rawURL))
		b2 := p.fetch(get(pt.rawURL))
		if !b1.ok() || !b2.ok() {
			o.fail("基线不可达 " + pt.endpoint() + "：" + b1.errText())
			continue
		}
		o.okPoints++
		base := min(b1.elapsed(), b2.elapsed())
		if base > 3*time.Second {
			o.note(fmt.Sprintf("基线耗时 %.1fs 过长，时间盲注不可靠，该点不判定", base.Seconds()))
			continue
		}
		if f := probeTiming(p, c, metaSqliTime, pt, base, timePairs()); f != nil {
			o.add(f)
		} else if p.blockedMsg != "" {
			break
		}
	}
	return o.result(p)
}

// timingTimeout 给慢请求留够时间：至少 sleep+4s，且不小于池默认超时的 3 倍余量。
func timingTimeout(p *prober, base time.Duration) time.Duration {
	t := time.Duration(sleepSeconds+4) * time.Second
	if v := 3*base + 2*time.Second; v > t {
		t = v
	}
	if t < p.timeout {
		t = p.timeout
	}
	return t
}

// probeTiming 通用延时判定：慢 payload 命中后必须过三关
// （同语法零延迟对照不慢、基线重测不慢），才报。
func probeTiming(p *prober, c *scan.Ctx, m scan.Meta, pt point,
	base time.Duration, pairs []struct{ label, slow, fast string }) *model.Finding {

	for _, pr := range pairs {
		slowURL := pt.withValueAppend(pr.slow)
		slow := p.fetch(get(slowURL).withTimeout(timingTimeout(p, base)))
		if p.blockedMsg != "" || !slow.ok() {
			continue
		}
		if !slowHit(base, slow.elapsed()) {
			continue
		}
		// 对照一：同语法零延迟版本必须快 —— 排除「这个参数本来就走慢查询」
		fastURL := pt.withValueAppend(pr.fast)
		fast := p.fetch(get(fastURL).withTimeout(timingTimeout(p, base)))
		if !fast.ok() || slowHit(base, fast.elapsed()) {
			continue
		}
		// 对照二：再测一次基线，排除「目标整体变慢」的网络抖动
		again := p.fetch(get(pt.rawURL).withTimeout(timingTimeout(p, base)))
		if !again.ok() || slowHit(base, again.elapsed()) {
			continue
		}
		return newFinding(c, m, findingOpts{
			sev:   "high",
			level: "L2",
			conf:  "confirmed",
			evidence: fmt.Sprintf("参数: %s = %s\n慢 payload: %s\n  → 耗时 %.2fs（HTTP %d / %dB）\n零延迟对照: %s\n  → 耗时 %.2fs（HTTP %d / %dB）\n基线重测: %s\n  → 耗时 %.2fs\n基线基准: %.2fs（两次取小）\n判定: 慢请求 ≥ 基线 3 倍且多出 ≥ %.1fs，对照均不慢",
				pt.name, pt.value, slowURL, slow.elapsed().Seconds(), slow.status(), slow.length(),
				fastURL, fast.elapsed().Seconds(), fast.status(), fast.length(),
				pt.rawURL, again.elapsed().Seconds(),
				base.Seconds(), minSleepDelta.Seconds()),
			repro:  curlGet(slowURL),
			impact: "可用延时条件逐字符推断数据库内容；也可被用来放大服务端资源消耗。",
			fix:    "改用参数化查询；给数据库查询设置语句超时，并限制单 IP 请求频率。",
			extra: map[string]interface{}{
				"path": pathOf(slowURL), "param": pt.name, "payload": pr.slow,
				"slow_seconds": slow.elapsed().Seconds(), "base_seconds": base.Seconds(),
				"control_seconds": fast.elapsed().Seconds(),
			},
		})
	}
	return nil
}

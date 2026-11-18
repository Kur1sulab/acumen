package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/report"
)

// ctrlRe 清 NUL 与控制字符，但保留 \t \n \r。
//
// 为什么要清：二进制响应体（SMB/TLS/MySQL 握手）里全是 NUL 与随机字节，
// 直接写进 evidence/*.txt 会让文件变成「二进制」，grep、编辑器、
// 报告渲染全都会出问题 —— 而且会让审证据的人以为产物坏了。
var ctrlRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)

// Sanitize 证据文本清洗，行为对齐 Python 的
// engine.sanitize(s, limit)：
//
//	s = CTRL_RE.sub("", str(s));  s = s[:limit] + ("…" if len(s) > limit else "")
//
// 两个必须照抄的细节：
//  1. 截断是「字符」不是「字节」。Python 的 str 切片按字符走，
//     Go 直接 s[:limit] 会把中文/UTF-8 序列切一半，产出乱码 ——
//     而截断后的乱码比不截断更糟（报告里出现问号方块）。
//  2. 判定用的是截断前长度（Python 先算 len(s) 再切片），
//     所以恰好等于 limit 时**不加**省略号。
func Sanitize(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD") // 等 Python 的 decode("utf-8", "replace")
	s = ctrlRe.ReplaceAllString(s, "")
	if limit > 0 {
		r := []rune(s)
		if len(r) > limit {
			return string(r[:limit]) + "…"
		}
	}
	return s
}

// runeLen 对齐 Python 的 len(str)：数的是字符不是字节。
//
// 这个函数存在的唯一原因就是去重时的「证据更短者胜」比较 ——
// 用 len(string) 的话，中文证据会被当成比等长英文证据更长，
// 合并方向就反了。
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// Family 同一问题的不同发现路径归到一族，用于跨引擎去重。
//
// 为什么必须做：内建检查与 nuclei 模板经常命中同一件事
// （git-leak 与 tpl-git-config-disclosure、actuator-env 与
// tpl-spring-actuator-env）。报两条等于把同一漏洞计两次，
// 而「跨报告重复计入」是交付红线。
var Family = map[string]string{
	"tpl-git-config-disclosure": "git-leak",
	"tpl-spring-actuator-env":   "actuator-env",
	"tpl-phpinfo-exposure":      "phpinfo-exposure",
	// 堆转储两路判据：webcheck 靠 GET 探 "JAVA PROFILE" 标记（会把整份文件
	// 拉下来），exposure 只读 1KB 头部 + Range。同一端点报两条＝同一漏洞计两次，
	// 所以归一族；保留方会带上 also_seen_by，两路独立命中反而是加分项。
	"exposure/actuator-heapdump": "actuator-heapdump",
	// framework 族与 webcheck 的内建检查是同一件事的两条判定路径：
	// 同一端点报两条等于把同一漏洞计两次。归一族，保留方带 also_seen_by。
	"framework/actuator-gateway": "actuator-gateway",
	"framework/druid-weak":       "druid-open",
	"framework/nacos-weak":       "nacos-unauth",
}

// Converge 收敛：同主机同端口的同类问题合并为一条，再按等级排序编号。
//
// 合并规则（对齐 Python 版）：
//   - 保留等级更高（sev_rank 更小）的那条；同等级时保留证据更短的那条
//     （短证据通常更精准，长证据往往是拼接产物）
//   - 被合并方的证据追加到 extra 之外，以「[另一路独立验证]」标注接在后面
//   - 被合并方的 check 名记进 extra["also_seen_by"] —— 两路独立命中是加分项
//   - 被合并方有 PoC 而保留方没有，就继承过来
func Converge(findings []*model.Finding) []*model.Finding {
	type key struct {
		host string
		port int
		fam  string
	}
	seen := map[key]*model.Finding{}
	order := []key{}

	for _, f := range findings {
		fam, ok := Family[f.Check]
		if !ok {
			fam = f.Check
		}
		k := key{f.Host, f.Port, fam}
		keep, exists := seen[k]
		if !exists {
			seen[k] = f
			order = append(order, k)
			continue
		}

		var better, other *model.Finding
		fr, kr := f.SevRankOf(), keep.SevRankOf()
		if fr < kr || (fr == kr && runeLen(f.Evidence) < runeLen(keep.Evidence)) {
			better, other = f, keep
		} else {
			better, other = keep, f
		}

		if other.Evidence != "" && !strings.Contains(better.Evidence, other.Evidence) {
			better.Evidence = strings.TrimSpace(
				better.Evidence + "\n\n[另一路独立验证] " + other.Evidence)
		}
		if other.Check != better.Check {
			if better.Extra == nil {
				better.Extra = map[string]interface{}{}
			}
			var list []interface{}
			if cur, ok := better.Extra["also_seen_by"]; ok && cur != nil {
				if l, ok := cur.([]interface{}); ok {
					list = l
				}
			}
			better.Extra["also_seen_by"] = append(list, other.Check)
		}
		if other.PoC != "" && better.PoC == "" {
			better.PoC = other.PoC
		}
		seen[k] = better
	}

	out := make([]*model.Finding, 0, len(seen))
	for _, k := range order {
		out = append(out, seen[k])
	}
	// 去重后可能同一对象被替换，按 key 再取一遍保证不重不漏
	uniq := make([]*model.Finding, 0, len(seen))
	emitted := map[*model.Finding]bool{}
	for _, k := range order {
		f := seen[k]
		if emitted[f] {
			continue
		}
		emitted[f] = true
		uniq = append(uniq, f)
	}

	sort.SliceStable(uniq, func(i, j int) bool {
		ri, rj := uniq[i].SevRankOf(), uniq[j].SevRankOf()
		if ri != rj {
			return ri < rj
		}
		if uniq[i].Target != uniq[j].Target {
			return uniq[i].Target < uniq[j].Target
		}
		return uniq[i].Check < uniq[j].Check
	})
	for i, f := range uniq {
		f.ID = fmt.Sprintf("LS-%03d", i+1)
		// 有些 check 在构造时还拿不到 ID（ID 要等排序去重后统一编号），
		// 所以 repro 里先写 {ID} 占位，到这里统一换成真实编号。
		// 否则报告里会出现「litmus replay --id 」这种照着敲不通的命令。
		if strings.Contains(f.Repro, "{ID}") {
			f.Repro = strings.ReplaceAll(f.Repro, "{ID}", f.ID)
		}
	}
	return uniq
}

// WriteEvidence 每条发现落一份 evidence/<id>-<check>.txt，并回填 RawRef。
//
// 为什么证据要单独落文件而不是只塞 JSON：审证据的人要能直接 cat 一个文件
// 看到完整原文，而不是从 JSON 里扒转义字符串。
func WriteEvidence(findings []*model.Finding, outDir string) (map[string]string, error) {
	dir := filepath.Join(outDir, "evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	paths := map[string]string{}
	for _, f := range findings {
		fn := f.ID + "-" + model.Slug(f.Check, 40) + ".txt"
		p := filepath.Join(dir, fn)
		var b strings.Builder
		fmt.Fprintf(&b, "编号: %s\n", f.ID)
		fmt.Fprintf(&b, "标题: %s\n", f.Name)
		fmt.Fprintf(&b, "等级: %s (%s) / %s\n", f.SevCNOf(), f.Severity, f.Level)
		fmt.Fprintf(&b, "目标: %s\n", f.Target)
		fmt.Fprintf(&b, "时间: %s\n", f.Time)
		fmt.Fprintf(&b, "置信度: %s\n", f.Confidence)
		fmt.Fprintf(&b, "\n=== 证据 ===\n%s\n", Sanitize(f.Evidence, 0))
		fmt.Fprintf(&b, "\n=== 复现 ===\n%s\n", f.Repro)
		if len(f.Creds) > 0 {
			b.WriteString("\n=== 凭据（已打码，完整值不进报告）===\n")
			for _, c := range f.Creds {
				fmt.Fprintf(&b, "  %s %s:%d user=%s secret=%s\n",
					c.Proto, c.Host, c.Port, c.User, model.MaskSecret(c.Secret, 4))
			}
		}
		if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
			return paths, err
		}
		rel, err := filepath.Rel(outDir, p)
		if err != nil {
			rel = p
		}
		f.RawRef = rel
		paths[f.ID] = p
	}
	return paths, nil
}

// ComputeDiff 与上一轮对比：新增 / 仍在 / 已修复。
//
// 比对键用 Finding.Key()（check|target|extra 的短哈希），
// 不用 id —— id 是按等级排序后重新编号的，两轮之间不稳定。
func ComputeDiff(cur, prev []*model.Finding) *report.Diff {
	prevSet := map[string]*model.Finding{}
	for _, f := range prev {
		prevSet[f.Key()] = f
	}
	curSet := map[string]*model.Finding{}
	for _, f := range cur {
		curSet[f.Key()] = f
	}

	var newItems, stillItems, fixedItems []report.DiffItem
	for _, f := range cur {
		k := f.Key()
		item := report.DiffItem{"id": f.ID, "name": f.Name, "target": f.Target,
			"severity": f.Severity, "check": f.Check}
		if _, ok := prevSet[k]; ok {
			stillItems = append(stillItems, item)
		} else {
			newItems = append(newItems, item)
		}
	}
	for _, f := range prev {
		if _, ok := curSet[f.Key()]; ok {
			continue
		}
		fixedItems = append(fixedItems, report.DiffItem{"id": f.ID, "name": f.Name,
			"target": f.Target, "severity": f.Severity, "check": f.Check})
	}
	if newItems == nil {
		newItems = []report.DiffItem{}
	}
	if stillItems == nil {
		stillItems = []report.DiffItem{}
	}
	if fixedItems == nil {
		fixedItems = []report.DiffItem{}
	}
	return &report.Diff{New: newItems, Still: stillItems, Fixed: fixedItems}
}

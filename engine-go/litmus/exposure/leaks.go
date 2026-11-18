// 文件面泄露：SVN 元数据、.DS_Store、JetBrains 工作区、日志文件。
//
// 四项都是「静态文件被 Web 服务器当普通资源吐出来」。判定难点不在路径，
// 在**区分真文件与软 404**：很多站点对任意路径回 200 + 首页模板，
// 只判 status 会把整站都报成泄露。所以每项都要求内容特征：
//   - SVN：entries 的版本号行 + svn:/dir 关键字；wc.db 要 SQLite 魔数
//   - .DS_Store：Content-Type 或 4 字节魔数 \x00\x00\x00\x01Bud1
//   - .idea：workspace.xml 必须含 <project version=
//   - 日志：必须同时像日志（IP + 时间戳 / HTTP/1.1" / Exception），且不是 HTML
package exposure

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
)

func init() {
	scan.Register(
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/svn-leak", Family: "exposure",
				Title:    "SVN 元数据泄露",
				Severity: "high",
				Owasp:    "A05:2021 安全配置错误",
				CWE:      "CWE-538",
			},
			Run: guard("exposure/svn-leak", ChkSVNLeak),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/ds-store", Family: "exposure",
				Title:    ".DS_Store 泄露",
				Severity: "low",
				Owasp:    "A05:2021 安全配置错误",
				CWE:      "CWE-538",
			},
			Run: guard("exposure/ds-store", ChkDSStore),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/idea-leak", Family: "exposure",
				Title:    "JetBrains .idea 工作区泄露",
				Severity: "medium",
				Owasp:    "A05:2021 安全配置错误",
				CWE:      "CWE-538",
			},
			Run: guard("exposure/idea-leak", ChkIdeaLeak),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/log-file", Family: "exposure",
				Title:    "日志文件暴露",
				Severity: "medium",
				Owasp:    "A09:2021 日志与监控失效",
				CWE:      "CWE-532",
			},
			Run: guard("exposure/log-file", ChkLogFile),
		},
	)
}

// looksLikeHTML 软 404 的最后一道闸：HTML 页面不可能是我们要找的静态文件
func looksLikeHTML(r *httpc.Response) bool {
	ct := strings.ToLower(r.Header("content-type"))
	if strings.Contains(ct, "html") {
		return true
	}
	head := strings.ToLower(headN(bodyOf(r), 512))
	return strings.Contains(head, "<!doctype html") || strings.Contains(head, "<html")
}

// ---------------------------------------------------------------- SVN

var svnEntriesHeadRe = regexp.MustCompile(`^\s*\d{1,2}\s*$`)

// looksSVNEntries 判定 .svn/entries。
//
// 1.6 及更早是纯文本：首行是格式版本号（8/9/10/12），第二段出现 "dir"，
// 目录项里带 "svn://" 或相对 URL；1.7+ 该文件不存在（改成 wc.db）。
// 判据用「首行是数字」+「含 dir 或 svn:」两项同时成立，单靠 200 不算。
func looksSVNEntries(txt string) bool {
	if len(txt) < 8 {
		return false
	}
	first := firstLine(txt)
	if !svnEntriesHeadRe.MatchString(first) {
		return false
	}
	low := strings.ToLower(txt)
	return strings.Contains(low, "\ndir") || strings.HasPrefix(low, "dir") ||
		strings.Contains(low, "svn:") || strings.Contains(low, "svn://")
}

// looksSQLite 判定 wc.db 魔数
func looksSQLite(b []byte) bool {
	const magic = "SQLite format 3\x00"
	return len(b) >= len(magic) && string(b[:len(magic)]) == magic
}

// ChkSVNLeak SVN 元数据泄露（.svn/entries 与 .svn/wc.db）。
func ChkSVNLeak(c *scan.Ctx) scan.Result {
	b := newBudget(c)
	tested := 0
	var hits []string
	var evidence []string
	notes := []string{}
	reachable := 0

	if b.take() {
		const p = "/.svn/entries"
		r := probe(c, "GET", urlFor(c, p), nil)
		tested++
		if r != nil && r.Err == nil {
			reachable++
		}
		switch {
		case r == nil || r.Err != nil:
			notes = append(notes, p+" 不可达")
		case r.Status == 200 && looksSVNEntries(bodyOf(r)):
			hits = append(hits, p)
			evidence = append(evidence, fmt.Sprintf("GET %s → HTTP 200 | 长度 %dB\n片段: %s",
				p, len(r.Body), clip(bodyOf(r), 200)))
		case r.Status == 200 && looksLikeHTML(r):
			notes = append(notes, p+" 返回 HTML（软 404），不计命中")
		default:
			notes = append(notes, fmt.Sprintf("%s → HTTP %d", p, r.Status))
		}
	}
	if b.take() {
		const p = "/.svn/wc.db"
		r := probe(c, "GET", urlFor(c, p), nil)
		tested++
		if r != nil && r.Err == nil {
			reachable++
		}
		switch {
		case r == nil || r.Err != nil:
			notes = append(notes, p+" 不可达")
		case r.Status == 200 && looksSQLite(r.Body):
			hits = append(hits, p)
			evidence = append(evidence, fmt.Sprintf("GET %s → HTTP 200 | 长度 %dB | 魔数 SQLite format 3",
				p, len(r.Body)))
		case r.Status == 200 && looksLikeHTML(r):
			notes = append(notes, p+" 返回 HTML（软 404），不计命中")
		default:
			notes = append(notes, fmt.Sprintf("%s → HTTP %d", p, r.Status))
		}
	}

	reason := "已探测 .svn/entries 与 .svn/wc.db"
	if len(notes) > 0 {
		reason += "：" + strings.Join(notes, "；")
	}
	if len(hits) == 0 {
		if reachable == 0 {
			// 一条都没连上 = 没测，绝不能报成「已测且没问题」
			return scan.Skip("目标不可达，SVN 元数据未判定：" + strings.Join(notes, "；"))
		}
		return okN(tested, reason)
	}
	f := newFinding(c, findingSpec{
		Check: "exposure/svn-leak", Name: "SVN 元数据泄露（" + strings.Join(hits, ", ") + "）",
		Severity: "high", Level: "L2", Category: "web",
		Target:   urlFor(c, hits[0]),
		Evidence: strings.Join(evidence, "\n"),
		Repro:    "curl -sI '" + urlFor(c, hits[0]) + "'",
		Impact: "entries/wc.db 给出仓库地址、版本号与全部受控文件名，可据此按版本逐个拉取源码，" +
			"拿到源码后硬编码口令、内网地址、签名密钥基本都在明面上。",
		Fix: "Web 根目录禁止访问 .svn（Nginx: location ~ /\\.svn { deny all; }），" +
			"发布时用 svn export 而不是直接检出目录。",
		Extra: map[string]interface{}{
			"path":  hits[0],
			"paths": hits,
		},
	})
	// 两条路径都命中时仍只报一条：客户要的是「SVN 元数据在这」，不是两份清单。
	return okN(tested, reason, f)
}

// ---------------------------------------------------------------- .DS_Store

// dsStoreMagic macOS Finder 的 .DS_Store 固定魔数
var dsStoreMagic = []byte{0x00, 0x00, 0x00, 0x01, 'B', 'u', 'd', '1'}

// ChkDSStore .DS_Store 泄露（low：泄露文件名清单，本身不含凭据）。
func ChkDSStore(c *scan.Ctx) scan.Result {
	const p = "/.DS_Store"
	r := probe(c, "GET", urlFor(c, p), nil)
	if r == nil || r.Err != nil {
		if r == nil {
			return scan.Skip("目标无响应（连接未建立）")
		}
		return scan.Skip("目标不可达: " + r.ErrText())
	}
	ct := strings.ToLower(r.Header("content-type"))
	magic := hasPrefixBytes(r.Body, dsStoreMagic)
	octet := strings.Contains(ct, "application/octet-stream")
	if r.Status != 200 || !(magic || octet) || looksLikeHTML(r) {
		return okN(1, fmt.Sprintf("GET /.DS_Store → HTTP %d | Content-Type: %s | 魔数匹配: %v",
			r.Status, orDefault(r.Header("content-type"), "(无)"), magic))
	}
	ev := fmt.Sprintf("GET /.DS_Store → HTTP 200 | Content-Type: %s | 长度 %dB\n"+
		"判据: Content-Type 为 application/octet-stream 或正文以 \\x00\\x00\\x00\\x01Bud1 开头（魔数匹配: %v）\n"+
		"头 16 字节(hex): %s",
		orDefault(r.Header("content-type"), "(无)"), len(r.Body), magic,
		hexPrefix(r.Body, 16))
	return okN(1, "", newFinding(c, findingSpec{
		Check: "exposure/ds-store", Name: ".DS_Store 文件可下载",
		Severity: "low", Level: "L1", Category: "web",
		Target: urlFor(c, p), Evidence: ev,
		Repro: "curl -sI '" + urlFor(c, p) + "'",
		Impact: "macOS 打包时留下的目录索引，可解析出服务器上的全部文件名，" +
			"常直接暴露备份包、未上线的页面与内部目录结构。",
		Fix: "发布流程排除 .DS_Store（tar --exclude），Web 服务器拒绝 dotfile：" +
			"location ~ /\\.(?!well-known) { deny all; }。",
		Extra: map[string]interface{}{"path": p, "magic": magic, "content_type": ct},
	}))
}

// ---------------------------------------------------------------- .idea

// ChkIdeaLeak JetBrains .idea/workspace.xml 泄露。
func ChkIdeaLeak(c *scan.Ctx) scan.Result {
	const p = "/.idea/workspace.xml"
	r := probe(c, "GET", urlFor(c, p), nil)
	if r == nil || r.Err != nil {
		if r == nil {
			return scan.Skip("目标无响应（连接未建立）")
		}
		return scan.Skip("目标不可达: " + r.ErrText())
	}
	body := bodyOf(r)
	hit := r.Status == 200 && strings.Contains(body, "<project version=") && !looksLikeHTML(r)
	if !hit {
		return okN(1, fmt.Sprintf("GET /.idea/workspace.xml → HTTP %d | 含 <project version=: %v",
			r.Status, strings.Contains(body, "<project version=")))
	}
	ev := fmt.Sprintf("GET /.idea/workspace.xml → HTTP %d | Content-Type: %s | 长度 %dB\n"+
		"判据: 含 <project version=，是 JetBrains 工作区文件\n片段: %s",
		r.Status, orDefault(r.Header("content-type"), "(无)"), len(r.Body),
		clip(body, 300))
	return okN(1, "", newFinding(c, findingSpec{
		Check: "exposure/idea-leak", Name: "JetBrains .idea 工作区文件可下载",
		Severity: "medium", Level: "L1", Category: "web",
		Target: urlFor(c, p), Evidence: ev,
		Repro: "curl -s '" + urlFor(c, p) + "' | head -c 400",
		Impact: "workspace.xml 含项目目录结构、运行配置、数据源连接名（甚至部署脚本路径），" +
			"配合 .idea/dataSources.xml 常能拿到数据库地址与账号名。",
		Fix:   "Web 根目录禁止 .idea（location ~ /\\.idea { deny all; }），构建产物不要带 IDE 目录。",
		Extra: map[string]interface{}{"path": p},
	}))
}

// ---------------------------------------------------------------- 日志

var (
	logIPRe     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	logTimeRe   = regexp.MustCompile(`\d{2}:\d{2}:\d{2}`)
	logDateRe   = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}`)
	logApacheRe = regexp.MustCompile(`"?(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) \S+ HTTP/1\.[01]"`)
	logLevelRe  = regexp.MustCompile(`(?i)\b(?:ERROR|WARN|WARNING|INFO|DEBUG|FATAL)\b`)
)

// logSignals 日志行特征数（拿满 2 个才算日志，单条 200 不算）
func logSignals(body string) []string {
	var sig []string
	if logIPRe.MatchString(body) && (logTimeRe.MatchString(body) || logDateRe.MatchString(body)) {
		sig = append(sig, "IP+时间戳")
	}
	if logApacheRe.MatchString(body) {
		sig = append(sig, "HTTP 请求行")
	}
	if strings.Contains(body, "Exception") || strings.Contains(body, "at java.") ||
		strings.Contains(body, "#0 ") {
		sig = append(sig, "异常栈")
	}
	if logLevelRe.MatchString(body) {
		sig = append(sig, "日志级别")
	}
	return sig
}

// ChkLogFile 日志文件暴露。
func ChkLogFile(c *scan.Ctx) scan.Result {
	b := newBudget(c)
	paths := []string{"/access.log", "/error.log", "/debug.log", "/app.log"}
	tested := 0
	reachable := 0
	var hits []string
	var details []string
	for _, p := range paths {
		if !b.take() {
			break
		}
		r := probe(c, "GET", urlFor(c, p), nil)
		tested++
		if r != nil && r.Err == nil {
			reachable++
		}
		if r == nil || r.Err != nil || r.Status != 200 || looksLikeHTML(r) {
			continue
		}
		body := bodyOf(r)
		sig := logSignals(body)
		if len(sig) < 2 || len(body) < 64 {
			continue
		}
		hits = append(hits, p)
		details = append(details, fmt.Sprintf("GET %s → HTTP 200 | 长度 %dB | 特征: %s\n片段: %s",
			p, len(r.Body), strings.Join(sig, ", "), clip(body, 200)))
	}
	if len(hits) == 0 {
		if reachable == 0 {
			return scan.Skip("目标不可达，日志文件未判定（发出 " + fmt.Sprint(tested) + " 次请求全部失败）")
		}
		return okN(tested, fmt.Sprintf("已探测 %d 个常见日志路径，均无日志特征", tested))
	}
	f := newFinding(c, findingSpec{
		Check: "exposure/log-file", Name: "日志文件可下载（" + strings.Join(hits, ", ") + "）",
		Severity: "medium", Level: "L2", Category: "web",
		Target:   urlFor(c, hits[0]),
		Evidence: strings.Join(details, "\n\n"),
		Repro:    "curl -s '" + urlFor(c, hits[0]) + "' | head -c 400",
		Impact: "访问/错误日志含真实客户端 IP、UA、完整请求行（含 URL 上的 token、手机号、身份参数），" +
			"错误日志常带堆栈、SQL 与配置路径；可直接支撑后续定向攻击与信息收集。",
		Fix: "日志目录移出 Web 根；Nginx 禁止 \\.log$ 访问；日志脱敏（URL 中的 token/手机号）并设置轮转与保留期。",
		Extra: map[string]interface{}{
			"path":  hits[0],
			"files": hits,
		},
	})
	return okN(tested, fmt.Sprintf("命中 %d 个日志文件: %s", len(hits), strings.Join(hits, ", ")), f)
}

// ---------------------------------------------------------------- 字节小工具

func hasPrefixBytes(b, p []byte) bool {
	if len(b) < len(p) {
		return false
	}
	for i := range p {
		if b[i] != p[i] {
			return false
		}
	}
	return true
}

// hexPrefix 前 n 字节的 hex（解析失败时留原始字节，便于现场排查）
func hexPrefix(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	var sb strings.Builder
	for _, c := range b[:n] {
		sb.WriteString(fmt.Sprintf("%02x", c))
	}
	return sb.String()
}

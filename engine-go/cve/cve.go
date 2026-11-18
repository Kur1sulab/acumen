// Package cve：离线 CVE 匹配 —— 版本指纹 → 本地规则库 → L1 结论。
//
// 这块的定位必须说清楚，因为它最容易被当成「扫出漏洞」：
//   **版本在受影响区间，只说明"可能受影响"，不说明可利用。**
//   所以这里产出的每一条都带 confidence=version-range、level=L1，
//   并且都给出「怎么验证」的下一步（strike / poc 模板），而不是直接写成已确认漏洞。
//
// 数据从哪来：规则库 `rules.json` 编译进二进制（go:embed）。断网环境没有 NVD 可查，
// 也不该临时去查——版本区间是行业公开知识，出厂时固化，跑的时候零外联。
// 规则维护纪律：只收「版本区间明确 + 影响面广」的条目；区间写不准的宁可不收。
package cve

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/netutil"
)

//go:embed rules.json
var rulesJSON []byte

// Range 版本区间：Gte <= v < Lt（空串表示不设边界）。
type Range struct {
	Gte string `json:"gte"`
	Lt  string `json:"lt"`
}

// Rule 一条离线规则。
type Rule struct {
	ID       string  `json:"id"`       // CVE 或行业惯用编号（如 SHIRO-4437）
	Product  string  `json:"product"`  // 内部产品名，与 detect 的输出对齐
	Title    string  `json:"title"`
	Severity string  `json:"severity"`
	Affects  []Range `json:"affects"`
	Verify   string  `json:"verify"`   // 下一步怎么验证（命令或模板名）
	Note     string  `json:"note"`
}

// Product 从目标身上提取到的产品/版本。
type Product struct {
	Product  string `json:"product"`
	Version  string `json:"version"`
	Evidence string `json:"evidence"`
}

// Match 一条命中。
type Match struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Product    string `json:"product"`
	Version    string `json:"version"`
	Evidence   string `json:"evidence"`
	Verify     string `json:"verify"`
	Confidence string `json:"confidence"` // 固定 version-range
	Level      string `json:"level"`      // 固定 L1：只到「可能受影响」
}

// Result 产物内容。
type Result struct {
	Target   string    `json:"target"`
	Products []Product `json:"products"`
	Matches  []Match   `json:"matches"`
	Elapsed  float64   `json:"elapsed"`
	Note     string    `json:"note,omitempty"`
}

// Rules 载入内置规则库。
func Rules() ([]Rule, error) {
	var rs []Rule
	if err := json.Unmarshal(rulesJSON, &rs); err != nil {
		return nil, fmt.Errorf("规则库损坏: %w", err)
	}
	return rs, nil
}

// 版本提取规则：只认「产品 + 明确版本号」的组合，拿不到版本就不猜。
var (
	reApache = regexp.MustCompile(`(?i)apache/(\d+\.\d+\.\d+)`)
	reNginx  = regexp.MustCompile(`(?i)nginx/(\d+\.\d+\.\d+)`)
	reJenkins = regexp.MustCompile(`(?i)jenkins(?:/|:)?\s*(\d+\.\d+(?:\.\d+)?)`)
	reGrafana = regexp.MustCompile(`(?i)grafana[^\d]{0,10}(\d+\.\d+\.\d+)`)
	reWp      = regexp.MustCompile(`(?i)wordpress\s*(\d+\.\d+(?:\.\d+)?)`)
	reDrupal  = regexp.MustCompile(`(?i)drupal\s*(\d+\.\d+(?:\.\d+)?)`)
	rePhp     = regexp.MustCompile(`(?i)php/(\d+\.\d+\.\d+)`)
	reZabbix  = regexp.MustCompile(`(?i)zabbix[^\d]{0,10}(\d+\.\d+\.\d+)`)
	reGitlab  = regexp.MustCompile(`(?i)gitlab[^\d]{0,10}(\d+\.\d+\.\d+)`)
	reSonic   = regexp.MustCompile(`(?i)sonicwall`)
	reWebmin  = regexp.MustCompile(`(?i)webmin[^\d]{0,10}(\d+\.\d+)`)
	reSolr    = regexp.MustCompile(`(?i)solr[^\d]{0,10}(\d+\.\d+\.\d+)`)
)

// Detect 从响应头/正文里抽产品与版本。只做「看得见」的判断，不主动探测指纹路径。
func Detect(rawHdr map[string]string, body string) []Product {
	// netutil 落盘的头是小写键，这里统一归一化，别让大小写把版本号吃掉
	hdr := make(map[string]string, len(rawHdr))
	for k, v := range rawHdr {
		hdr[strings.ToLower(k)] = v
	}
	var out []Product
	joined := strings.Join([]string{hdr["server"], hdr["x-powered-by"], hdr["x-jenkins"],
		hdr["x-grafana"], hdr["set-cookie"], body}, "\n")

	add := func(product, version, ev string) {
		if version == "" {
			return
		}
		for _, p := range out {
			if p.Product == product {
				return
			}
		}
		out = append(out, Product{Product: product, Version: version, Evidence: ev})
	}

	if m := reApache.FindStringSubmatch(joined); m != nil {
		add("apache_httpd", m[1], "Server: "+hdr["server"])
	}
	if m := reNginx.FindStringSubmatch(joined); m != nil {
		add("nginx", m[1], "Server: "+hdr["server"])
	}
	if m := reJenkins.FindStringSubmatch(joined); m != nil {
		add("jenkins", m[1], "X-Jenkins/正文")
	}
	if m := reGrafana.FindStringSubmatch(joined); m != nil {
		add("grafana", m[1], "正文/头")
	}
	if m := reWp.FindStringSubmatch(joined); m != nil {
		add("wordpress", m[1], "generator meta")
	}
	if m := reDrupal.FindStringSubmatch(joined); m != nil {
		add("drupal", m[1], "CHANGELOG/正文")
	}
	if m := rePhp.FindStringSubmatch(joined); m != nil {
		add("php", m[1], "X-Powered-By")
	}
	if m := reZabbix.FindStringSubmatch(joined); m != nil {
		add("zabbix", m[1], "正文")
	}
	if m := reGitlab.FindStringSubmatch(joined); m != nil {
		add("gitlab", m[1], "正文")
	}
	if m := reWebmin.FindStringSubmatch(joined); m != nil {
		add("webmin", m[1], "正文")
	}
	if m := reSolr.FindStringSubmatch(joined); m != nil {
		add("solr", m[1], "正文")
	}
	// 无版本但有产品特征的：只用于「跑验证」，不进版本区间匹配
	if strings.Contains(strings.ToLower(body), "whitelabel error page") {
		out = append(out, Product{Product: "spring_boot", Version: "", Evidence: "Whitelabel Error Page"})
	}
	return out
}

// versionLT 比较点分版本：a < b 返回 true。非数字段按字符串比较兜底。
func versionLT(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		nx, ex := strconv.Atoi(x)
		ny, ey := strconv.Atoi(y)
		if ex == nil && ey == nil {
			if nx != ny {
				return nx < ny
			}
			continue
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// InRange 版本是否落在区间内（version 为空 → 一律 false，不猜）。
func InRange(version string, r Range) bool {
	if version == "" {
		return false
	}
	if r.Gte != "" && versionLT(version, r.Gte) {
		return false
	}
	if r.Lt != "" && !versionLT(version, r.Lt) {
		return false
	}
	return true
}

// MatchAll 把产品列表对规则库，产出命中。
func MatchAll(products []Product, rules []Rule) []Match {
	var out []Match
	for _, p := range products {
		for _, r := range rules {
			if r.Product != p.Product {
				continue
			}
			for _, ar := range r.Affects {
				if !InRange(p.Version, ar) {
					continue
				}
				out = append(out, Match{
					ID: r.ID, Title: r.Title, Severity: r.Severity,
					Product: p.Product, Version: p.Version, Evidence: p.Evidence,
					Verify: r.Verify, Confidence: "version-range", Level: "L1",
				})
				break
			}
		}
	}
	return out
}

// Run 对着一个 base URL 跑一轮：取首页 → 抽产品 → 匹配规则 → 落盘 cve.json。
func Run(base string) (Result, error) {
	res := Result{Target: base, Note: "版本区间命中只是「可能受影响」（L1），要下结论请用 strike / poc 模板验证"}
	t0 := time.Now()
	defer func() { res.Elapsed = time.Since(t0).Seconds() }()

	if base == "" {
		return res, fmt.Errorf("缺少目标")
	}
	// 授权内网目标：显式允许私网（这一步只是形状/协议校验，不是外联）
	if _, err := netutil.CheckHTTPURL(base, true); err != nil {
		return res, fmt.Errorf("目标不合法: %w", err)
	}
	f := netutil.Fetch(base, netutil.FetchOpt{
		Timeout: 10 * time.Second, MaxBytes: 512 * 1024, Follow: true,
	})
	if f.Err != "" {
		return res, fmt.Errorf("目标不可达: %s", f.Err)
	}
	hdr := map[string]string{}
	for k, v := range f.Headers {
		hdr[k] = v
	}
	res.Products = Detect(hdr, f.Body)

	rules, err := Rules()
	if err != nil {
		return res, err
	}
	res.Matches = MatchAll(res.Products, rules)
	if res.Products == nil {
		res.Products = []Product{}
	}
	if res.Matches == nil {
		res.Matches = []Match{}
	}
	return res, nil
}

// Write 把结果写到 out/<target>/cve.json。
func Write(outDir string, res Result) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(outDir, "cve.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// HostOf 从 URL 里取 host（写产物目录名用）。
func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return raw
	}
	if u.Port() != "" {
		return u.Hostname() + "_" + u.Port()
	}
	return u.Hostname()
}

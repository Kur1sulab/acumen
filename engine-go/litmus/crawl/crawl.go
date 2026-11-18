// Package crawl 是极简爬虫，只为一件事：给模板引擎扩大覆盖面。
//
// 三条硬限制（照抄 Python crawl.py 的设计）：
//   - 同源：scheme + host + port 必须一致，绝不越界到第三方资产
//   - 双上限：页数与深度都由 --intensity 决定，不做无限爬
//   - 正则不用 HTML 解析器：畸形页面会让解析器抛异常，正则反而更抗造
package crawl

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
)

var (
	hrefRe   = regexp.MustCompile(`(?is)<a\s[^>]*href\s*=\s*["']([^"'#]+)["']`)
	formRe   = regexp.MustCompile(`(?is)<form\s[^>]*action\s*=\s*["']([^"'#]*)["']`)
	scriptRe = regexp.MustCompile(`(?is)<script\s[^>]*src\s*=\s*["']([^"'#]+)["']`)
)

// skipExt 静态资源后缀：爬它们除了浪费预算没有任何收益
var skipExt = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff",
	".woff2", ".ttf", ".mp4", ".mp3", ".pdf", ".zip", ".rar", ".7z",
}

// Form 页面上的一个表单
type Form struct {
	Page   string `json:"page"`
	Action string `json:"action"`
}

// Result 一轮爬取的结果
type Result struct {
	URLs   []string `json:"urls"`
	Forms  []Form   `json:"forms"`
	Errors []string `json:"errors"`
}

// ExtractLinks 从 HTML 里抽链接（href / form action / script src）
func ExtractLinks(html, baseURL string) []string {
	out := []string{}
	for _, rx := range []*regexp.Regexp{hrefRe, formRe, scriptRe} {
		for _, m := range rx.FindAllStringSubmatch(html, -1) {
			if len(m) < 2 {
				continue
			}
			href := strings.TrimSpace(m[1])
			if href == "" {
				continue
			}
			low := strings.ToLower(href)
			if hasAnyPrefix(low, "javascript:", "mailto:", "tel:", "data:") {
				continue
			}
			if hasAnySuffix(strings.SplitN(low, "?", 2)[0], skipExt) {
				continue
			}
			out = append(out, httpc.URLJoin(baseURL, href))
		}
	}
	return out
}

// Crawl BFS 爬同源页面。maxPages / maxDepth <= 0 时取保守默认值。
func Crawl(pool *httpc.Pool, base string, maxPages, maxDepth int, timeout time.Duration) *Result {
	if maxPages <= 0 {
		maxPages = 40
	}
	if maxDepth < 0 {
		maxDepth = 0
	}
	if pool == nil {
		return &Result{Errors: []string{"pool 为空"}}
	}

	res := &Result{URLs: []string{}, Forms: []Form{}, Errors: []string{}}
	seen := map[string]bool{norm(base): true}
	type item struct {
		url   string
		depth int
	}
	queue := []item{{norm(base), 0}}

	for len(queue) > 0 && len(seen) < maxPages {
		cur := queue[0]
		queue = queue[1:]

		r := pool.Request("GET", cur.url, httpc.Opts{
			Timeout:    timeout,
			NoRedirect: false,
		})
		if r == nil {
			res.Errors = append(res.Errors, cur.url+": 无响应")
			continue
		}
		if r.Status == 0 || r.Err != nil {
			res.Errors = append(res.Errors, cur.url+": "+r.ErrText())
			continue
		}
		ctype := strings.ToLower(r.Header("content-type"))
		if ctype != "" && !strings.Contains(ctype, "html") {
			continue
		}
		html := r.Text()

		for _, m := range formRe.FindAllStringSubmatch(html, -1) {
			act := cur.url
			if len(m) >= 2 && strings.TrimSpace(m[1]) != "" {
				act = httpc.URLJoin(cur.url, strings.TrimSpace(m[1]))
			}
			res.Forms = append(res.Forms, Form{Page: cur.url, Action: act})
		}

		if cur.depth >= maxDepth {
			continue
		}
		for _, link := range ExtractLinks(html, cur.url) {
			if !sameOrigin(link, base) {
				continue
			}
			n := norm(link)
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			queue = append(queue, item{n, cur.depth + 1})
		}
	}

	for u := range seen {
		res.URLs = append(res.URLs, u)
	}
	sort.Strings(res.URLs)
	return res
}

// norm 对齐 Python 的 _norm：path 为空补 "/"，丢掉 fragment
func norm(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" {
		return u
	}
	path := p.Path
	if path == "" {
		path = "/"
	}
	q := ""
	if p.RawQuery != "" {
		q = "?" + p.RawQuery
	}
	return p.Scheme + "://" + p.Host + path + q
}

// sameOrigin scheme + host + 有效端口 三元组全等
func sameOrigin(u, base string) bool {
	a, err1 := url.Parse(u)
	b, err2 := url.Parse(base)
	if err1 != nil || err2 != nil {
		return false
	}
	return a.Scheme == b.Scheme &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effPort(a) == effPort(b)
}

func effPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

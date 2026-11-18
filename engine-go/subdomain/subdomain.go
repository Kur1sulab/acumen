// Package subdomain：子域枚举 —— 纯本地 DNS 字典爆破，零外联。
//
// 为什么不是证书日志：crt.sh / certspotter 都是公网服务，断网环境（内网、VDI、
// 只进不出的评测现场）一个包都发不出去，只会挂着等超时，然后让人误以为「没有子域」。
// 内网里唯一可靠的子域来源就是内网自己的 DNS —— 所以这里只做一件事：
// 拿本地字典逐条查 A/AAAA 记录，命中就记下来。
//
// 三条纪律：
//  1. 只问 DNS，不问第三方 HTTP；解析器默认用系统配置（内网就是内网 DNS），
//     需要时可用 --resolver 指定内网 DNS 服务器。
//  2. 先做泛解析探测：随机标签也能解析的域名，逐条比对解析结果集，
//     命中同一组 IP 的一律丢弃——否则会把「泛解析」写成几千个子域。
//  3. 产物与老版本兼容：out/subdomains.txt（一行一个 FQDN）+ out/subdomains.json。
package subdomain

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed words.txt
var embeddedWords string

// DefaultWorkers 并发查询数：内网 DNS 通常扛得住，但对老设备留点余量。
const DefaultWorkers = 32

// DefaultTimeout 单次查询超时。
const DefaultTimeout = 3 * time.Second

// Options 爆破参数。零值 = 内置字典 + 系统解析器。
type Options struct {
	Words    []string      // 自定义字典（空 = 内置约 4.8k 条）
	Workers  int           // 并发（0 = DefaultWorkers）
	Timeout  time.Duration // 单次超时（0 = DefaultTimeout）
	Resolver string        // "10.0.0.2:53"；空 = 系统解析器
	Progress func(done, total int, fqdn string)
}

// Found 一条命中。
type Found struct {
	Name string   `json:"name"`
	FQDN string   `json:"fqdn"`
	IPs  []string `json:"ips"`
}

// Result 整轮结果（= subdomains.json 的内容）。
type Result struct {
	Domain      string   `json:"domain"`
	Source      string   `json:"source"`
	Words       int      `json:"words"`
	Scanned     int      `json:"scanned"`
	Wildcard    bool     `json:"wildcard"`
	WildcardIPs []string `json:"wildcard_ips,omitempty"`
	Found       []Found  `json:"found"`
	Elapsed     float64  `json:"elapsed"`
	Resolver    string   `json:"resolver"`
}

// Words 内置字典（去重、去空行）。
func Words() []string {
	out := make([]string, 0, 5000)
	for _, ln := range strings.Split(embeddedWords, "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

// Run 兼容旧签名：默认参数跑一轮，返回命中的 FQDN 列表。
func Run(domain, out string) ([]string, error) {
	res, err := RunOptions(context.Background(), domain, out, Options{})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.Found))
	for _, f := range res.Found {
		names = append(names, f.FQDN)
	}
	return names, nil
}

// RunOptions 跑一轮本地 DNS 字典爆破，并把结果写进 out 目录。
func RunOptions(ctx context.Context, domain, out string, opt Options) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	d := normalizeDomain(domain)
	if d == "" {
		return Result{}, fmt.Errorf("非法域名: %q", domain)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return Result{}, fmt.Errorf("输出目录不可写: %w", err)
	}

	words := opt.Words
	if len(words) == 0 {
		words = Words()
	}
	workers := opt.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	resolver := net.DefaultResolver
	if opt.Resolver != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", opt.Resolver)
			},
		}
	}

	t0 := time.Now()
	wildcardIPs := detectWildcard(ctx, resolver, d, timeout)
	res := Result{
		Domain: d, Source: "dns-brute", Words: len(words),
		Wildcard: len(wildcardIPs) > 0, WildcardIPs: wildcardIPs,
		Resolver: opt.Resolver,
	}
	if res.Wildcard {
		fmt.Printf("[!] 泛解析：*.%s → %s（命中同组 IP 的子域会被丢弃）\n", d, strings.Join(wildcardIPs, ","))
	}

	type job struct{ name string }
	jobs := make(chan job)
	var mu sync.Mutex
	var found []Found
	var scanned int

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				fqdn := j.name + "." + d
				ips := lookupIPs(ctx, resolver, fqdn, timeout)
				mu.Lock()
				scanned++
				if len(ips) > 0 && !sameSet(ips, wildcardIPs) {
					found = append(found, Found{Name: j.name, FQDN: fqdn, IPs: ips})
				}
				done := scanned
				mu.Unlock()
				if opt.Progress != nil {
					opt.Progress(done, len(words), fqdn)
				}
			}
		}()
	}
	for _, w := range words {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return res, ctx.Err()
		case jobs <- job{name: w}:
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(found, func(i, j int) bool { return found[i].FQDN < found[j].FQDN })
	res.Found = found
	res.Scanned = scanned
	res.Elapsed = time.Since(t0).Seconds()
	if res.Found == nil {
		res.Found = []Found{}
	}

	if err := writeArtifacts(out, res); err != nil {
		return res, err
	}
	return res, nil
}

func writeArtifacts(out string, res Result) error {
	lines := make([]string, 0, len(res.Found))
	for _, f := range res.Found {
		lines = append(lines, f.FQDN)
	}
	if err := os.WriteFile(filepath.Join(out, "subdomains.txt"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("写 subdomains.txt 失败: %w", err)
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "subdomains.json"), b, 0o644); err != nil {
		return fmt.Errorf("写 subdomains.json 失败: %w", err)
	}
	return nil
}

// detectWildcard 随机标签解析：能解析说明域名开了泛解析，记下 IP 集合用于比对。
func detectWildcard(ctx context.Context, r *net.Resolver, domain string, timeout time.Duration) []string {
	var union []string
	for i := 0; i < 2; i++ {
		label := fmt.Sprintf("kara-wildcard-%d%d", time.Now().UnixNano()%100000, i)
		for _, ip := range lookupIPs(ctx, r, label+"."+domain, timeout) {
			union = append(union, ip)
		}
	}
	return uniq(union)
}

func lookupIPs(ctx context.Context, r *net.Resolver, fqdn string, timeout time.Duration) []string {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := r.LookupHost(c, fqdn)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	return uniq(addrs)
}

func sameSet(a, b []string) bool {
	if len(b) == 0 || len(a) == 0 {
		return false
	}
	bs := map[string]bool{}
	for _, x := range b {
		bs[x] = true
	}
	for _, x := range a {
		if !bs[x] {
			return false
		}
	}
	return true
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func normalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if i := strings.IndexAny(d, "/:"); i >= 0 {
		d = d[:i]
	}
	d = strings.Trim(d, ".")
	if d == "" || len(d) > 253 || strings.Contains(d, "..") {
		return ""
	}
	return d
}

// marshalPretty 供 verify.go 复用：带缩进的 JSON（人工看产物时友好）。
func marshalPretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

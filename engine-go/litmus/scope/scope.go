// Package scope 负责目标解析与范围守卫。
//
// 范围守卫是这条工具链的安全底线：默认只放行私网/回环/链路本地/保留段，
// 公网目标必须显式 --allow-public。这不是「礼貌」——是防止一次手滑的
// 通配符把扫描打到别人的生产环境上。
package scope

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Parsed 一条展开后的目标
type Parsed struct {
	Host   string
	Port   int // 0 = 未指定，后续用默认端口表
	Scheme string
	Raw    string
}

// ParseTargets 把 -t 参数与目标文件读成原始字符串列表（去空行/注释/去重）。
func ParseTargets(items, files []string) ([]string, error) {
	var out []string
	for _, it := range items {
		s := strings.TrimSpace(it)
		if s != "" {
			out = append(out, s)
		}
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("读目标文件 %s 失败: %w", path, err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.Index(line, "#"); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	uniq := make([]string, 0, len(out))
	for _, t := range out {
		if t != "" && !seen[t] {
			seen[t] = true
			uniq = append(uniq, t)
		}
	}
	return uniq, nil
}

// 对齐 Python ipaddress 的 is_private 需要补的网段。
//
// Go 的 IP.IsPrivate() 只覆盖 RFC1918 + fc00::/7，而 Python 的 is_private
// 还包含 TEST-NET 1/2/3、基准测试段、IETF 协议分配段与 0.0.0.0/8。
// 这些段恰恰是靶场和演练环境最常用的（192.0.2.0/24 就是经典黑洞地址），
// 不补齐的话 Go 版会把自己人的靶场当公网拒绝掉。
//
// 数据来源：python3 3.12.16 实测 is_private/is_loopback/is_link_local/is_reserved
// 的并集，逐条核对过（见 scope_test.go 的 TestIsPrivateMatchesPython）。
var extraPrivate4 = []*net.IPNet{
	mustCIDR("0.0.0.0/8"),         // "本网络"
	mustCIDR("192.0.0.0/29"),      // IETF 协议分配
	mustCIDR("192.0.2.0/24"),      // TEST-NET-1
	mustCIDR("198.18.0.0/15"),     // 网络设备基准测试
	mustCIDR("198.51.100.0/24"),   // TEST-NET-2
	mustCIDR("203.0.113.0/24"),    // TEST-NET-3
	mustCIDR("240.0.0.0/4"),       // 保留（含 255.255.255.255）
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("scope: 非法 CIDR 常量 " + s)
	}
	return n
}

// IsPrivate 对齐 Python 的 a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
//
// 注意不要用 Go 的 IsLinkLocalMulticast()：Python 的 is_link_local 只认
// 169.254/16 与 fe80::/10，而 224.0.0.1 在 Python 侧是被拒的。
func IsPrivate(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		for _, n := range extraPrivate4 {
			if n.Contains(ip4) {
				return true
			}
		}
	}
	return false
}

// ScopeResult 范围判定结果
type ScopeResult struct {
	OK     bool
	Reason string
	IPs    []string
}

// ScopeOK 范围守卫：默认只放行私网/回环。返回判定 + 解析出的 IP。
func ScopeOK(host string, allowPublic bool) ScopeResult {
	var ips []string
	if ip := net.ParseIP(host); ip != nil {
		ips = []string{host}
	} else {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return ScopeResult{OK: false, Reason: "DNS 解析失败: " + err.Error()}
		}
		set := map[string]bool{}
		for _, a := range addrs {
			set[a] = true
		}
		for a := range set {
			ips = append(ips, a)
		}
		sort.Strings(ips)
	}
	if len(ips) == 0 {
		return ScopeResult{OK: false, Reason: "无法解析出 IP"}
	}
	var bad []string
	for _, s := range ips {
		ip := net.ParseIP(s)
		if !IsPrivate(ip) {
			bad = append(bad, s)
		}
	}
	if len(bad) > 0 && !allowPublic {
		return ScopeResult{OK: false, IPs: ips,
			Reason: fmt.Sprintf("解析到公网地址 %v（需要 --allow-public）", bad)}
	}
	return ScopeResult{OK: true, IPs: ips}
}

var (
	cidrRe     = regexp.MustCompile(`^[\d.]+/\d+$`)
	hostPortRe = regexp.MustCompile(`^([^:]+):(\d+)$`)
)

// Expand 展开 CIDR / host:port / URL，返回去重后的目标列表。
func Expand(rawList []string, maxHosts int) ([]Parsed, error) {
	var out []Parsed
	for _, raw := range rawList {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		low := strings.ToLower(s)
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
			scheme := "http"
			if strings.HasPrefix(low, "https://") {
				scheme = "https"
			}
			rest := s[strings.Index(s, "://")+3:]
			host := rest
			path := "/"
			if i := strings.IndexAny(rest, "/?"); i >= 0 {
				host = rest[:i]
				path = rest[i:]
			}
			port := 80
			if scheme == "https" {
				port = 443
			}
			if h, p, err := net.SplitHostPort(host); err == nil {
				host = h
				if n, e := strconv.Atoi(p); e == nil {
					port = n
				}
			}
			_ = path
			out = append(out, Parsed{Host: host, Port: port, Scheme: scheme, Raw: s})
			continue
		}
		if strings.Contains(s, "/") && cidrRe.MatchString(s) {
			_, ipnet, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("CIDR 解析失败 %s: %w", s, err)
			}
			var hosts []string
			for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				hosts = append(hosts, ip.String())
			}
			// Python 版用 net.hosts()：去掉网络号与广播地址（>2 个地址时）
			if len(hosts) > 2 {
				hosts = hosts[1 : len(hosts)-1]
			}
			if len(hosts) > maxHosts {
				return nil, fmt.Errorf(
					"%s 展开后有 %d 个主机，超过 --max-hosts=%d；确需全扫请显式调大 --max-hosts",
					s, len(hosts), maxHosts)
			}
			for _, h := range hosts {
				out = append(out, Parsed{Host: h, Raw: raw})
			}
			continue
		}
		if m := hostPortRe.FindStringSubmatch(s); m != nil {
			n, _ := strconv.Atoi(m[2])
			out = append(out, Parsed{Host: m[1], Port: n, Raw: s})
			continue
		}
		out = append(out, Parsed{Host: s, Raw: s})
	}
	// 去重（host, port）
	seen := map[string]bool{}
	uniq := make([]Parsed, 0, len(out))
	for _, p := range out {
		k := fmt.Sprintf("%s|%d", p.Host, p.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		uniq = append(uniq, p)
	}
	return uniq, nil
}

// incIP 原地自增 IP（大端）
func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

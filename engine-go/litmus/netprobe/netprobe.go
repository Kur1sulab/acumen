// Package netprobe 是 netprobe.py 的逐函数移植：纯标准库端口扫描 + 服务指纹内核。
//
// 与 nmap 的差异（有意保留，与 Python 版一致）：
//   - 只用 TCP connect()，不需要 root，不依赖 raw socket，穿透任何用户态环境
//   - 不做 SYN 半开，但「连接成功即 open」是硬事实
//   - 指纹靠「被动 banner + 主动只读探针 + 响应正则」，每条指纹都给出命中依据
//
// 三条铁律（与 Python 版逐字对应）：
//  1. open 判定只认 connect 成功，不认超时推断
//  2. 服务识别必须给出 evidence（原始响应片段），识别不出就写 unknown
//  3. 任何探针都是只读的：PING / stats / 版本查询，不发写命令
//
// 与 Python 版的已知差异，逐条说明（契约 4.1 要求行为差异可解释）：
//
//   - 时间参数用 time.Duration 而不是 float 秒。DefaultTimeout 等常量与 Python 的
//     默认值（timeout=2.5 / threads=64 / host_threads=4）一一对应。
//
//   - 签名匹配前先把响应字节按 latin-1 解码成「字节↔rune 一一对应」的字符串。
//     Python 的 re 作用在 bytes 上，模式里的 \xff 就是字节 0xFF；Go 的 regexp 作用在
//     UTF-8 上，裸 0xFF 是非法 UTF-8，会被解成 U+FFFD 而匹配不到（实测：
//     `(?is)\xff\xfd` 对原始字节返回 false，对 latin-1 解码后的串返回 true）。
//     latin-1 解码后 U+00FF 恰好对应字节 0xFF，于是 \xff、.、[^<]{0,160}、[:160]
//     这些计数单位全都回到「一个字节 = 一个 rune」，正则语义与 Python 完全一致。
//
//   - Python 正则的 \s 在 bytes 模式下是 [ \t\n\r\f\v]，Go 的 \s 少了 \v（0x0B）。
//     这里用 pyWS 常量显式展开，避免畸形响应（header 里混 0x0B）上出现分歧。
//
//   - TLS 证书的 subject / issuer / notAfter：Python 版把 verify_mode 设成 CERT_NONE 之后
//     getpeercert() 返回空 dict，这三个字段永远是空的（等于死代码）；Go 版按 DER 真实解析
//     填充。sha256、version、cipher 仍与 Python 版逐字一致。
//
//   - TLS 握手失败时，Python 版会拿着已经 close 的 socket 继续 read，直接抛 OSError
//     冒到调用方（实测：对明文端口 grab(tls=True) → OSError: Bad file descriptor）。
//     Go 版按契约 4.3 不抛：重连后当普通端口继续探测，错误记进 PortResult.Error。
//
//   - Python 的 _connect 用「host 里有没有冒号」决定 AF_INET6 / AF_INET，即主机名只查 A 记录；
//     Go 的 Dial 走 happy-eyeballs 同时尝试 A/AAAA。后者严格更好，保留。
package netprobe

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// 并发与超时默认值，与 Python 版的函数默认参数一一对应。
const (
	// DefaultThreads 端口级并发数（Python: threads=64）
	DefaultThreads = 64
	// DefaultHostThreads host 级并发数（Python: host_threads=4）
	DefaultHostThreads = 4
	// DefaultTimeout 单端口总超时（Python: timeout=2.5）
	DefaultTimeout = 2500 * time.Millisecond
)

// 连接状态。只有 connect 成功才算 open，超时/拒绝都不算。
const (
	StateOpen     = "open"
	StateClosed   = "closed"
	StateFiltered = "filtered"
)

// TOP100 是 nmap top-ports 的常用子集（98 个，与 Python 版逐项一致）。
var TOP100 = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
	119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
	515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
	1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
	2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
	5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
	8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9999, 10000, 32768,
	49152, 49153, 49154,
}

// WEB_PORTS 常见 Web 端口。只在「有响应但认不出协议」时做兜底提示，纯猜不算。
var WEB_PORTS = []int{
	80, 81, 82, 83, 84, 85, 88, 443, 8000, 8008, 8009, 8010, 8080, 8081, 8082,
	8088, 8090, 8161, 8180, 8443, 8880, 8888, 9000, 9001, 9043, 9080, 9090,
	9443, 10000, 10443, 18080, 28017,
}

// DB_PORTS 常见数据端口
var DB_PORTS = []int{
	1433, 1521, 3306, 5432, 6379, 9042, 9200, 27017, 11211, 5984, 8086, 50000,
	50070, 8088,
}

// TOP1000 是 TOP100 + WEB_PORTS + DB_PORTS + 一批中间件端口的去重升序合集。
// 注意：名字叫 TOP1000 但实际只有 159 个端口 —— 这是 Python 版的既有事实，
// 不是移植时漏了，测试里钉死了长度与内容哈希。
var TOP1000 = sortedUnique(append(append(append(append([]int{},
	TOP100...), WEB_PORTS...), DB_PORTS...),
	2181, 2375, 2376, 2379, 2380, 3128, 4444, 4848, 5005, 5601, 5672, 5901, 5985,
	5986, 6443, 7001, 7002, 7077, 8088, 8161, 8500, 8529, 8686, 9000, 9042, 9092,
	9093, 9418, 9443, 9999, 10250, 11211, 15672, 16379, 25565, 27017, 27018,
	50000, 50060, 50070, 50075, 50090, 61616,
))

// webPortSet / tlsPortSet 都是查表用的，避免在热路径上线性扫切片。
var webPortSet = func() map[int]bool {
	m := make(map[int]bool, len(WEB_PORTS))
	for _, p := range WEB_PORTS {
		m[p] = true
	}
	return m
}()

// DefaultTLSPorts TLS 探测端口（Python 版 scan_host 的 tls_ports 默认值）。
var DefaultTLSPorts = []int{443, 8443, 9443, 10443, 993, 995, 465, 636, 990, 5986}

func sortedUnique(in []int) []int {
	seen := make(map[int]bool, len(in))
	out := make([]int, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// ParsePorts 解析 "80,443,8000-8100" → 有序去重列表。
//
// 与 Python 版 parse_ports 的边界行为逐条对齐：
//   - 空格全部剔除；空段跳过（"80,,443" 合法）
//   - 区间反向自动翻转（"5-1" → 1..5）
//   - 区间两端各自夹到 [1, 65535]（"0-3" → 1,2,3；"65534-70000" → 65534,65535）
//   - 任一端解析失败整段丢弃（"80-abc" / "-5" / "80-" 都返回空）
//   - 单值越界丢弃（"0" / "65536" 丢弃）
//   - 结果保持首次出现顺序去重（"1-3,2-5" → 1,2,3,4,5）
//
// 与 Python 的差异：Python 版会先做 str(spec)，所以传整数也能解析；
// Go 版签名收窄为 string，传整数请自己 strconv.Itoa。
func ParsePorts(spec string) []int {
	out := make([]int, 0, 16)
	seen := make(map[int]bool, 16)
	for _, part := range strings.Split(strings.ReplaceAll(spec, " ", ""), ",") {
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '-'); i >= 0 {
			a, errA := strconv.Atoi(part[:i])
			b, errB := strconv.Atoi(part[i+1:])
			if errA != nil || errB != nil {
				continue // 与 Python 的 try/except ValueError 一致：任一端坏掉就整段丢
			}
			if a > b {
				a, b = b, a
			}
			if a < 1 {
				a = 1
			}
			if b > 65535 {
				b = 65535
			}
			for p := a; p <= b; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

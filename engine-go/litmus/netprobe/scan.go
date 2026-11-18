package netprobe

import (
	"sort"
	"sync"
	"time"
)

// ScanOpts 是扫描参数。零值 == Python 版的默认参数：
// threads=64 / timeout=2.5 / tls_ports=默认集合 / active=True / host_threads=4。
//
// Passive 的含义是「不发主动探针」，对应 Python 的 active=False。
// 之所以不叫 Active：Go 的零值必须是默认行为，否则调用方忘了赋值就会静默降级。
type ScanOpts struct {
	Threads     int
	Timeout     time.Duration
	TLSPorts    []int
	Passive     bool
	HostThreads int
}

// withDefaults 把零值补齐成 Python 的默认参数。
func (o ScanOpts) withDefaults() ScanOpts {
	if o.Threads <= 0 {
		o.Threads = DefaultThreads
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.HostThreads <= 0 {
		o.HostThreads = DefaultHostThreads
	}
	return o
}

// tlsPortSet 把 TLSPorts 变成查表结构；空则用默认集合（Python: tls_ports or [...]）。
func (o ScanOpts) tlsPortSet() map[int]bool {
	src := o.TLSPorts
	if len(src) == 0 {
		src = DefaultTLSPorts
	}
	m := make(map[int]bool, len(src))
	for _, p := range src {
		m[p] = true
	}
	return m
}

// ScanHost 扫单个 host 的一组端口，返回 open 的 PortResult 列表（按端口升序）。
//
// 并发纪律（契约 4.4）：信号量 chan struct{} 卡住并发数，WaitGroup 等齐，
// 结果走带缓冲的 channel 汇总，绝不直接写共享 map/slice。
func ScanHost(host string, ports []int, o ScanOpts) []*PortResult {
	o = o.withDefaults()
	tlsSet := o.tlsPortSet()

	results := make(chan *PortResult, len(ports))
	sem := make(chan struct{}, o.Threads)
	var wg sync.WaitGroup

	for _, p := range ports {
		wg.Add(1)
		sem <- struct{}{} // 先占坑再造 goroutine：几千端口也不会把 fd 打爆
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			results <- Grab(host, port, o.Timeout, tlsSet[port], !o.Passive)
		}(p)
	}
	wg.Wait()
	close(results)

	out := make([]*PortResult, 0, 8)
	for r := range results {
		if r.State == StateOpen {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// Scan 扫多 host。host 间并发受 HostThreads 限制，避免打爆，也避免把目标侧 IDS 一次点着。
// 返回 {host: [open PortResult]}，未在 hosts 里的键不会出现（Python 的 dict 语义一致）。
func Scan(hosts []string, ports []int, o ScanOpts) map[string][]*PortResult {
	o = o.withDefaults()

	type hostResult struct {
		host string
		rs   []*PortResult
	}
	results := make(chan hostResult, len(hosts))
	sem := make(chan struct{}, o.HostThreads)
	var wg sync.WaitGroup

	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			results <- hostResult{host: host, rs: ScanHost(host, ports, o)}
		}(h)
	}
	wg.Wait()
	close(results)

	out := make(map[string][]*PortResult, len(hosts))
	for hr := range results {
		out[hr.host] = hr.rs
	}
	return out
}

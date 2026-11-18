// Package engine 是整条流水线的调度层：目标 → 端口 → 服务 → 真登 → Web → 模板 → 收敛 → 报告。
//
// 与 Python 版 engine.py 的对应关系是逐行的，但对「尚未移植的模块」
// 用可注入的 hook 而非硬 import —— 这样框架在 authprobe / crawl / tpl
// 到位之前就能真跑（把对应项如实记成 skip），而不是整仓编译不了。
// 三态原则在这里的具体含义：没有实现 ≠ 通过，必须落一条带原因的 skip。
package engine

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/crawl"
	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/netprobe"
	"github.com/Kur1sulab/kara/engine-go/litmus/report"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
	"github.com/Kur1sulab/kara/engine-go/litmus/scope"
	"github.com/Kur1sulab/kara/engine-go/litmus/store"
	"github.com/Kur1sulab/kara/engine-go/litmus/tpl"
	"github.com/Kur1sulab/kara/engine-go/litmus/webcheck"
	"github.com/Kur1sulab/kara/engine-go/litmus/winproto"
)

// TLSPorts 与 Python engine.TLS_PORTS 一致
var TLSPorts = map[int]bool{
	443: true, 8443: true, 9443: true, 10443: true, 993: true,
	995: true, 465: true, 636: true, 990: true, 5986: true,
}

// WebHints 与 Python engine.WEB_HINTS 一致
var WebHints = []string{
	"http", "nginx", "apache", "tomcat", "jetty", "iis", "openresty",
	"lighttpd", "caddy", "gunicorn", "werkzeug", "spring",
}

// ------------------------------------------------------------------ hooks
//
// 这些是「已设计、未移植」的模块接口。装配方（cmd/litmus）在对应包到位后
// 赋值即可，engine 本体不改。nil 时一律记 skip 并写清原因。
var (
	// KeyFor 对应 authprobe.key_for：服务名 → 探针 key，无对应探针返回 ""
	KeyFor func(service, product string, port int) string

	// ProbeAuth 对应 authprobe.probe_service：返回单条结论，nil = 已尝试无结论
	ProbeAuth func(host string, port int, service, product string,
		tls bool, timeout time.Duration) map[string]interface{}

	// CrawlFn 对应 crawl.crawl：返回 (urls, forms, errs)
	CrawlFn func(pool *httpc.Pool, base string, maxPages, maxDepth int,
		timeout time.Duration) ([]string, []interface{}, []error)
)

// Engine 一轮运行的运行时状态
type Engine struct {
	Opts     *Options
	State    *store.Store
	RunID    int
	PrevRun  int
	Findings []*model.Finding
	Coverage []*model.Coverage
	Pool     *httpc.Pool
	Log      []string

	// Tpls 是载入后的模板列表（对应 Python 的 self.templates）。
	// Opts.Templates 只存目录路径 —— 与 Python 的两层结构一致：
	// opts.templates（目录） / self.templates（加载后的列表）。
	Tpls []*tpl.Template

	t0 time.Time
	mu sync.Mutex
}

// New 建引擎。StateDir 为空时用 ./state（与 Python 的 --state 默认值对齐）。
func New(opts *Options) *Engine {
	return &Engine{Opts: opts, t0: time.Now()}
}

// Say 记一行日志。并发下加锁，否则 race detector 会叫。
func (e *Engine) Say(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	e.mu.Lock()
	e.Log = append(e.Log, line)
	e.mu.Unlock()
	// 与原版 Python Engine.say 逐条对齐：总是记日志，verbose 时才同时打到终端。
	// 现场扫描动辄几分钟，终端一个字不出会被当成卡死，所以这条不能省。
	if e.Opts.Verbose {
		fmt.Fprintln(os.Stdout, line)
	}
}

// Cover 记一条三态覆盖。
//
// reason 在 state=ok 时也允许非空 —— 例如「软404=是」「发现 12 个 URL」，
// 这些是判读依据不是借口。真正表示「没测」的只有 skip / na。
func (e *Engine) Cover(target, category, item, state, reason string, count ...int) {
	n := 0
	if len(count) > 0 {
		n = count[0]
	}
	c := model.NewCoverage(target, category, item, state, reason, n)
	e.mu.Lock()
	e.Coverage = append(e.Coverage, c)
	e.mu.Unlock()
}

// AddFinding 收一条发现（并发安全）
func (e *Engine) AddFinding(f *model.Finding) {
	if f == nil {
		return
	}
	e.mu.Lock()
	e.Findings = append(e.Findings, f)
	e.mu.Unlock()
}

// ------------------------------------------------------------------ 主流程

// Run 跑完整一轮，返回可直接交给 report 渲染的结果。
func (e *Engine) Run(rawTargets []string) (*report.Result, error) {
	opts := e.Opts
	if opts == nil {
		return nil, fmt.Errorf("engine: Options 不能为空")
	}
	e.t0 = time.Now()

	// 1) 目标解析
	targets, err := scope.Expand(rawTargets, opts.MaxHosts)
	if err != nil {
		return nil, err
	}
	e.Say("[*] 目标 %d 个（intensity=%s ports=%s threads=%d）",
		len(targets), opts.Intensity, opts.Ports, opts.Threads)

	// 2) 范围守卫
	type allowedHost struct {
		parsed scope.Parsed
		ips    []string
	}
	var allowed []allowedHost
	seen := map[string]bool{}
	for _, t := range targets {
		res := scope.ScopeOK(t.Host, opts.AllowPublic)
		if !res.OK {
			e.Cover(t.Host, "network", "scope", "skip", res.Reason)
			e.Say("[!] 跳过 %s: %s", t.Host, res.Reason)
			continue
		}
		h := t.Host
		if seen[h] {
			continue
		}
		seen[h] = true
		allowed = append(allowed, allowedHost{parsed: t, ips: res.IPs})
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("没有通过范围守卫的目标（私网默认放行，公网需 --allow-public）")
	}

	// 3) 状态库
	dir := opts.StateDir
	if dir == "" {
		dir = "state"
	}
	st, err := store.Open(dir)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	e.State = st

	hosts := make([]string, 0, len(allowed))
	for _, a := range allowed {
		hosts = append(hosts, a.parsed.Host)
	}
	sort.Strings(hosts)
	thash := model.DedupeKey("targets", strings.Join(hosts, ","), "")

	prevRun := 0
	if opts.Diff {
		prevRun = st.LastRun(0, true)
	}
	e.PrevRun = prevRun

	skipHosts := map[string]bool{}
	if opts.Resume {
		skipHosts = st.DoneHostsForHash(thash)
		if len(skipHosts) > 0 {
			e.Say("[*] 续跑：跳过 %d 个已完成主机", len(skipHosts))
		}
	}
	runID, err := st.NewRun(opts, thash)
	if err != nil {
		return nil, err
	}
	e.RunID = runID

	// 载入模板（Python 版在同一位置调 _load_templates）
	e.loadTemplates()

	// 4) 端口表
	ports := e.portPlan()

	// 5) 扫描
	pool := httpc.NewPool(opts.Threads, float64(opts.RPS), seconds(opts.Timeout+4), false)
	e.Pool = pool

	for _, a := range allowed {
		host := a.parsed.Host
		if skipHosts[host] {
			e.Cover(host, "network", "scan", "skip", "续跑跳过（上一轮已完成）")
			continue
		}
		e.doHost(host, a.parsed.Port, ports)
		if err := st.MarkHost(runID, host, "done", nil); err != nil {
			e.Say("[!] 记录主机状态失败 %s: %v", host, err)
		}
	}

	// 6) 收敛
	e.Findings = Converge(e.Findings)
	// 编号定下来之后才能写 PoC —— 命令里带的就是这个 ID。
	// Go 版不生成 poc/*.py（目标机没 Python，生成了也跑不起来），
	// 改成让交付的二进制自己复验，见 cmd/litmus/replay.go。
	for _, f := range e.Findings {
		if f.PoC == "" {
			f.PoC = fmt.Sprintf("litmus replay -f findings.json --id %s", f.ID)
		}
	}
	if err := st.SaveFindings(runID, e.Findings); err != nil {
		e.Say("[!] 保存发现失败: %v", err)
	}
	if err := st.FinishRun(runID); err != nil {
		e.Say("[!] 收尾 run 失败: %v", err)
	}

	// 7) 差异
	var diff *report.Diff
	if opts.Diff && prevRun > 0 {
		prevFindings, err := st.FindingsOf(prevRun)
		if err == nil {
			diff = ComputeDiff(e.Findings, prevFindings)
			e.Say("[*] 差异：新增 %d / 仍在 %d / 已修复 %d",
				len(diff.New), len(diff.Still), len(diff.Fixed))
		}
	}

	res := &report.Result{
		RunID:    runID,
		Elapsed:  round1(time.Since(e.t0).Seconds()),
		Findings: e.Findings,
		Coverage: e.Coverage,
		Diff:     diff,
	}
	if ob, err := opts.asMap(); err == nil {
		res.Opts = ob
	}
	return res, nil
}

// portPlan 决定这一轮扫哪些端口（对齐 Python Run 里的四分支）。
func (e *Engine) portPlan() []int {
	spec := e.Opts.Ports
	switch spec {
	case "full":
		out := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			out = append(out, p)
		}
		return out
	case "top1000":
		return netprobe.TOP1000
	case "", "top100":
		return netprobe.TOP100
	}
	// "22,80,443,8000-8100" 这类显式端口表优先于档位
	if regexp.MustCompile(`^[\d,\-]+$`).MatchString(spec) {
		if ps := netprobe.ParsePorts(spec); len(ps) > 0 {
			return ps
		}
	}
	return netprobe.TOP100
}

// ------------------------------------------------------------------ 单主机

func (e *Engine) doHost(host string, fixedPort int, ports []int) {
	opts := e.Opts
	if fixedPort > 0 {
		ports = []int{fixedPort}
	}
	e.Say("[*] %s 扫描 %d 个端口 …", host, len(ports))

	results := netprobe.ScanHost(host, ports, netprobe.ScanOpts{
		Threads:  opts.Threads,
		Timeout:  seconds(opts.Timeout),
		TLSPorts: mapKeys(TLSPorts),
	})
	if results == nil {
		e.Cover(host, "network", "port-scan", "skip", "端口扫描无返回")
		return
	}
	for _, r := range results {
		e.Say("    %s:%d open  %s%s%s", host, r.Port, orDefault(r.Service, "unknown"),
			prefixIf("/", r.Product), prefixIf(" ", r.Version))
	}
	e.Cover(host, "network", "port-scan", "ok", "", len(results))
	if len(results) == 0 {
		return
	}

	// 端口开着但认不出服务：SMB2 / LDAP / RDP 都是客户端先说话，
	// banner 抓取对它们完全失效。不补这一步，authprobe 拿不到 key，
	// 服务级探针不会被调度，整类未授权被静默漏成「na」。
	idTimeout := 2.0
	if opts.Timeout < idTimeout {
		idTimeout = opts.Timeout
	}
	for _, r := range results {
		svc := strings.ToLower(r.Service)
		if svc != "" && svc != "unknown" && svc != "tcp" {
			continue
		}
		if proto := winproto.Identify(host, r.Port, seconds(idTimeout)); proto != "" {
			r.Service = proto
			e.Say("    %s:%d 协议指纹 → %s", host, r.Port, proto)
		}
	}

	for _, r := range results {
		svc := strings.ToLower(r.Service)
		isWeb := false
		for _, h := range WebHints {
			if strings.Contains(svc, h) {
				isWeb = true
				break
			}
		}
		if !isWeb {
			for _, wp := range netprobe.WEB_PORTS {
				if wp == r.Port {
					isWeb = true
					break
				}
			}
		}

		// 服务级真登验证
		// 不能因为 isWeb 就跳过：ES / Docker / K8s / CouchDB 本身就是
		// HTTP 协议上的服务，指纹一旦偏成 "http"，整类未授权就被静默漏掉。
		if !opts.NoAuthProbe {
			if f := e.authProbe(host, r, isWeb); f != nil {
				e.AddFinding(f)
			}
		} else if !isWeb {
			e.Cover(host, "host", fmt.Sprintf("authprobe@%d", r.Port), "skip",
				"--no-auth-probe：本轮跳过服务级真登验证")
		}

		item := fmt.Sprintf("web@%d", r.Port)
		switch {
		case isWeb && !opts.NoWeb:
			tls := TLSPorts[r.Port] || strings.Contains(svc, "https") || r.TLS != nil
			scheme := "http"
			if tls {
				scheme = "https"
			}
			e.doWeb(host, r, fmt.Sprintf("%s://%s:%d", scheme, host, r.Port))
		case isWeb:
			// 【修正 Python 版缺陷】原版在 --no-web 时对 Web 端口既不测也不记，
			// 覆盖表上直接消失 —— 而这正是「没测的伪装成没问题」。
			// 三态原则是不可让步的设计线，所以这里偏离原版行为，补记 skip。
			e.Cover(host, "web", item, "skip", "--no-web：本轮跳过 Web 侧检查")
		default:
			e.Cover(host, "web", item, "na", "该端口不是 Web 服务")
		}
	}
}

// ------------------------------------------------------------------ 服务级验证

func (e *Engine) authProbe(host string, r *netprobe.PortResult, isWeb bool) *model.Finding {
	opts := e.Opts
	svc := r.Service
	item := fmt.Sprintf("authprobe:%s", orDefault(svc, fmt.Sprint(r.Port)))

	if KeyFor == nil || ProbeAuth == nil {
		// 模块未装配：如实记 na，绝不留空
		if !isWeb {
			e.Cover(host, "host", item, "na", "服务级探针模块未装配（authprobe 未移植）")
		}
		return nil
	}

	key := KeyFor(svc, r.Product, r.Port)
	if key == "" {
		// 没有对应探针：绝不能记 ok。Web 端口由 web 分支负责覆盖，
		// 非 Web 端口在这里明确记 na，让覆盖表如实反映「没测」。
		if !isWeb {
			e.Cover(host, "host", item, "na", "无对应服务级探针")
		}
		return nil
	}
	if opts.Creds <= 0 && (key == "mysql" || key == "postgres" || key == "ftp") {
		e.Cover(host, "host", fmt.Sprintf("authprobe:%s@%d", key, r.Port), "skip",
			fmt.Sprintf("intensity=%s 不尝试口令", opts.Intensity))
		return nil
	}

	d := ProbeAuth(host, r.Port, svc, r.Product, r.TLS != nil, seconds(opts.Timeout+2))
	if d == nil {
		e.Cover(host, "host", fmt.Sprintf("authprobe:%s@%d", key, r.Port), "ok",
			"已尝试，无未授权结论")
		return nil
	}

	check := asStr(d["check"])
	e.Cover(host, "host", "authprobe:"+check, "ok", "", 1)

	fo := model.FindingOpts{
		Host: host, Port: r.Port,
		Category:   orDefault(asStr(d["category"]), "host"),
		Level:      asStr(d["level"]),
		Confidence: orDefault(asStr(d["confidence"]), "confirmed"),
		Evidence:   Sanitize(asStr(d["evidence"]), 0),
		Repro:      asStr(d["repro"]),
		Impact:     asStr(d["impact"]),
		Fix:        asStr(d["fix"]),
	}
	f := model.NewFinding(check, asStr(d["name"]), asStr(d["severity"]),
		fmt.Sprintf("%s:%d", host, r.Port), fo)
	if extra, ok := d["extra"].(map[string]interface{}); ok && extra != nil {
		f.Extra = extra
	}
	if creds, ok := d["creds"].([]interface{}); ok {
		for _, cv := range creds {
			cm, ok := cv.(map[string]interface{})
			if !ok {
				continue
			}
			c := model.NewCred(
				asStr(cm["proto"]), asStr(cm["host"]), asInt(cm["port"]),
				asStr(cm["user"]), asStr(cm["secret"]),
				orDefault(asStr(cm["kind"]), "password"), check, "")
			f.Creds = append(f.Creds, *c)
		}
		f.SyncCredsJSON()
	}
	return f
}

// ------------------------------------------------------------------ Web

func (e *Engine) doWeb(host string, r *netprobe.PortResult, base string) {
	opts := e.Opts
	tls := strings.HasPrefix(base, "https")

	// 1) 内建检查（逐项记覆盖）
	//
	// 早先这里是一条 "webcheck@porт ok" 概括全部 11 个检查项 —— 等于把
	// 「某项没测」藏在「模块跑过了」里面。现在改成逐项落覆盖：
	// 每个检查项自己一行 ok/skip，客户问「你测 Nacos 了吗」答得出来。
	items, soft := webcheck.CheckWebDetail(e.Pool, base, webcheck.Opts{
		Timeout: seconds(opts.Timeout + 4),
	})
	var res []*model.Finding
	for _, it := range items {
		res = append(res, it.Findings...)
	}
	for _, f := range res {
		if f.Host == "" {
			f.Host = host
		}
		if f.Port == 0 {
			f.Port = r.Port
		}
		// Target 在 engine 层拼，与 Python engine.py:485 一致：
		// 原版是 f"{base}{extra.get('path', '/')}" —— 没有 path 就落到 "/"。
		// webcheck 只认 base，尾部斜杠由这里补，否则 findings.json 差一个字节。
		path, _ := f.Extra["path"].(string)
		if path == "" {
			path = "/"
		}
		f.Target = base + path
		if f.Scheme == "" {
			if tls {
				f.Scheme = "https"
			} else {
				f.Scheme = "http"
			}
		}
		e.AddFinding(f)
	}
	softNote := "软404=否"
	if soft != nil && soft.Soft {
		softNote = "软404=是"
	}
	for _, it := range items {
		name := "webcheck/" + strings.TrimPrefix(it.Name, "chk_")
		state, reason := "ok", softNote
		if it.Error != "" {
			state, reason = "skip", "检查项异常："+it.Error
		}
		// 说明列 = 中文名（做了什么）+ 状态备注，客户不用去查代码才知道这是什么项。
		if it.Title != "" {
			if reason != "" {
				reason = it.Title + "（" + reason + "）"
			} else {
				reason = it.Title
			}
		}
		e.Cover(host, "web", fmt.Sprintf("%s@%d", name, r.Port), state, reason, len(it.Findings))
	}

	// 2) 爬虫扩面
	var urls []string
	var crawlRes *crawl.Result
	if CrawlFn != nil {
		u, forms, _ := CrawlFn(e.Pool, base, opts.CrawlPages, opts.CrawlDepth,
			seconds(opts.Timeout+4))
		urls = u
		crawlRes = &crawl.Result{URLs: u}
		for _, f := range forms {
			if m, ok := f.(crawl.Form); ok {
				crawlRes.Forms = append(crawlRes.Forms, m)
			}
		}
	} else {
		crawlRes = crawl.Crawl(e.Pool, base, opts.CrawlPages, opts.CrawlDepth,
			seconds(opts.Timeout+4))
		urls = crawlRes.URLs
	}
	e.Cover(host, "web", fmt.Sprintf("crawl@%d", r.Port), "ok",
		fmt.Sprintf("发现 %d 个 URL / %d 个表单", len(crawlRes.URLs), len(crawlRes.Forms)),
		len(crawlRes.URLs))
	_ = urls

	// 3) 模板
	if len(e.Tpls) > 0 {
		e.runTemplates(host, r, base)
	} else {
		e.Cover(host, "web", fmt.Sprintf("templates@%d", r.Port), "skip",
			"未提供模板目录（--templates），本项未测")
	}

	// 4) 扩展检查族（注入 / 框架 / 认证 / 暴露面）
	e.runScanFamilies(host, r, base, soft, urls)
}

// runScanFamilies 跑所有通过 scan.Register 注册的检查项。
//
// 每个检查项自己上报三态，engine 只负责记账 —— 这样新增一个检查包
// 不需要改 engine，只要在 allcheck 包里 import 一下就会自动装配。
func (e *Engine) runScanFamilies(host string, r *netprobe.PortResult, base string,
	soft *webcheck.Soft404, urls []string) {

	all := scan.All()
	if len(all) == 0 {
		return
	}
	scheme := "http"
	if strings.HasPrefix(base, "https") {
		scheme = "https"
	}
	h := host
	if u, err := url.Parse(base); err == nil && u.Hostname() != "" {
		h = u.Hostname()
	}
	ctx := &scan.Ctx{
		Target:  base,
		Base:    base,
		Host:    h,
		Port:    r.Port,
		Scheme:  scheme,
		Pool:    e.Pool,
		Timeout: seconds(e.Opts.Timeout + 4),
		URLs:    urls,
	}
	if soft != nil {
		ctx.Soft404 = &scan.Soft404{
			Soft: soft.Soft, Status: soft.Status, Len: soft.Len,
			Sig: soft.Sig, Same: soft.Same, Sample: soft.Sample,
		}
	}

	for _, c := range all {
		if e.Pool.Closed() {
			e.Cover(host, c.Family, c.Name, "skip", "连接池已关闭，未执行")
			continue
		}
		res := c.Run(ctx)
		for _, f := range res.Findings {
			if f == nil {
				continue
			}
			if f.Host == "" {
				f.Host = host
			}
			if f.Port == 0 {
				f.Port = r.Port
			}
			if f.Scheme == "" {
				f.Scheme = scheme
			}
			if f.Target == "" {
				f.Target = base
			}
			e.AddFinding(f)
		}
		state := res.State
		if state == "" {
			// 检查项没自报状态是缺陷，但不能因此让覆盖表撒谎。
			state = "skip"
			res.Reason = "检查项未上报状态（实现缺陷），本项结果不计入结论"
		}
		e.Cover(host, c.Family, c.Name, state, res.Reason, len(res.Findings))
	}
}

// loadTemplates 对应 Python 的 Engine._load_templates。
//
// 三个要点与原版逐条对齐：
//  1. 目录为空 → 直接返回（不落 skip，skip 由 doWeb 的 else 分支负责，
//     保证「所有 web 端口各记一条 skip」而不是全局一条）；
//  2. 目录不存在 → 记一条全局 skip，理由是带路径的原文；
//  3. 单个模板加载失败 → 记一条 template:<文件名> 的 skip 带异常文本，
//     不让一个坏模板拖垮整批（原版也是 try/except 逐文件吞）。
func (e *Engine) loadTemplates() {
	d := e.Opts.Templates
	if d == "" {
		return
	}
	// 先把目录转成绝对路径再记进 Opts：报告和 findings.json 常被拷到别的
	// 目录再看，相对路径到那时就废了，replay 会报「模板目录不存在」。
	if abs, err := filepath.Abs(d); err == nil {
		d = abs
		e.Opts.Templates = abs
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		e.Cover("-", "web", "templates", "skip", fmt.Sprintf("模板目录不存在: %s", d))
		return
	}
	tmpls, errs := tpl.LoadDir(d, e.Opts.MaxTpl)
	for _, le := range errs {
		e.Cover("-", "web", "template:"+filepath.Base(le.Path), "skip",
			"加载失败: "+le.Message)
	}
	e.Tpls = append(e.Tpls, tmpls...)
	e.Say("[*] 载入模板 %d 个（上限 %d）", len(e.Tpls), e.Opts.MaxTpl)
}

// runTemplates 对应 Python 的 Engine._run_templates。
//
// 命中即落一条 tpl-<id> 的 L2 发现（模板判定本身就是「打到真回显」），
// 执行报错则记 skip 带错误原文 —— 不把「模板跑挂了」当成「目标没问题」。
func (e *Engine) runTemplates(host string, r *netprobe.PortResult, base string) {
	eng := tpl.NewEngine(seconds(e.Opts.Timeout + 4))
	hit, tried := 0, 0
	for _, t := range e.Tpls {
		out := eng.Run(t, base)
		if out.Error != "" {
			e.Cover(host, "web", "tpl:"+t.ID, "skip", out.Error)
			continue
		}
		tried++
		if !out.Matched {
			continue
		}
		hit++
		name := t.Name
		if name == "" {
			name = t.ID
		}
		scheme := "http"
		if strings.HasPrefix(base, "https") {
			scheme = "https"
		}
		// 影响和修复建议从模板里取 —— 报告里写「见证据」「见模板」等于没写，
		// 客户拿着报告要能直接照着改。
		impact := strings.TrimSpace(t.Description)
		if impact == "" {
			impact = "模板命中，具体影响见上方证据原文。"
		}
		fix := ""
		if info, ok := t.RawYAML["info"].(map[string]any); ok {
			if r, ok := info["remediation"].(string); ok {
				fix = strings.TrimSpace(r)
			}
		}
		if fix == "" {
			fix = "按模板对应的暴露面加固：对外接口做鉴权与访问控制，关闭不必要的管理端暴露。"
		}
		f := model.NewFinding(
			"tpl-"+t.ID, name, t.Severity, base, model.FindingOpts{
				Host:     host,
				Port:     r.Port,
				Scheme:   scheme,
				Category: "web",
				Level:    "L2",
				Evidence: Sanitize(strings.Join(out.Evidence, "\n"), 0),
				Impact:   impact,
				Fix:      fix,
				Extra: map[string]interface{}{
					"template": t.ID,
					"extracts": out.Extracts,
					"requests": out.RequestsMade,
				},
			})
		// ID 要等 converge 编号后才存在，这里先写 {ID} 占位，由 converge 统一回填。
		f.Repro = fmt.Sprintf("litmus replay -f findings.json --id {ID}   # 模板 %s", t.ID)
		e.AddFinding(f)
	}
	e.Cover(host, "web", fmt.Sprintf("templates@%d", r.Port), "ok",
		fmt.Sprintf("跑 %d 个模板，命中 %d 个", tried, hit), tried)
}

// ------------------------------------------------------------------ 小工具

func seconds(f float64) time.Duration {
	if f <= 0 {
		return 0
	}
	return time.Duration(f * float64(time.Second))
}

func mapKeys(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func prefixIf(sep, s string) string {
	if s == "" {
		return ""
	}
	return sep + s
}

func asStr(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func asInt(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		var i int
		fmt.Sscanf(n, "%d", &i)
		return i
	}
	return 0
}

// round1 对齐 Python 的 round(x, 1)
func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// ensureOutDir 建输出目录（run-<id> 形式，与 Python 一致）
func ensureOutDir(root string, runID int) (string, error) {
	d := filepath.Join(root, fmt.Sprintf("run-%03d", runID))
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

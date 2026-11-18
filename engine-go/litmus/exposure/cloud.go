// 云存储桶与云主机元数据。
//
// 这两项的共同点是「判定必须带对照/带视角」，否则几乎全是误报：
//   - 桶：公网上一堆反向代理对任意子域都回 200；判据必须落在
//     <ListBucketResult>/<Contents> 上，并且拿一个随机桶名做对照 ——
//     对不存在的桶也必须能返回 NoSuchBucket，否则端点就没有区分度。
//   - 元数据端点：169.254.169.254 是扫描器所在主机能看到的地址，
//     不是目标主机的。只有目标是内网地址时才谈得上「同网段可达」，
//     且结论仅限扫描器视角，绝不写成「目标存在 SSRF」。
package exposure

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
	"github.com/Kur1sulab/kara/engine-go/litmus/scan"
	"github.com/Kur1sulab/kara/engine-go/litmus/scope"
)

func init() {
	scan.Register(
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/s3-bucket", Family: "exposure",
				Title:    "云存储桶未授权列举",
				Severity: "high",
				Owasp:    "A01:2021 访问控制失效",
				CWE:      "CWE-284",
			},
			Run: guard("exposure/s3-bucket", ChkS3Bucket),
		},
		scan.Check{
			Meta: scan.Meta{
				Name: "exposure/oss-metadata", Family: "exposure",
				Title:    "云主机元数据端点可达",
				Severity: "high",
				Owasp:    "A10:2021 服务端请求伪造",
				CWE:      "CWE-918",
			},
			Run: guard("exposure/oss-metadata", ChkMetadata),
		},
	)
}

// ---------------------------------------------------------------- 桶名提取

// 四家厂商的域名各写一遍，而不是「含 amazonaws 就算」：
// 判据要能区分「桶端点」和「厂商控制台/文档页」。
var (
	awsVHostRe    = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.(s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com(?:\.cn)?)$`)
	aliyunVHostRe = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.(oss-[a-z0-9\-]+\.aliyuncs\.com)$`)
	cosVHostRe    = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.(cos\.[a-z0-9\-]+\.myqcloud\.com)$`)
	bceVHostRe    = regexp.MustCompile(`(?i)^([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.((?:bj|gz|su|hkg|fwh|bd)\.bcebos\.com)$`)
)

// 从任意文本里捞「像桶端点」的域名（虚拟主机式）
var cloudHostRe = regexp.MustCompile(`(?i)(?:https?://)?\b([a-z0-9][a-z0-9.\-]{2,120}\.(?:amazonaws\.com(?:\.cn)?|aliyuncs\.com|myqcloud\.com|bcebos\.com))\b`)

// 路径式引用：https://oss-cn-hangzhou.aliyuncs.com/my-bucket/logo.png
var pathStyleRe = regexp.MustCompile(`(?i)(?:https?://)?(s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com(?:\.cn)?|oss-[a-z0-9\-]+\.aliyuncs\.com|cos\.[a-z0-9\-]+\.myqcloud\.com)/([a-z0-9][a-z0-9.\-]{2,61})/`)

// bucketRef 一个云存储桶引用
type bucketRef struct {
	Host       string // 端点域名
	Bucket     string
	Provider   string // aws / aliyun / tencent / bcebos
	Suffix     string // 去掉桶名后的域名后缀（拼对照桶用）
	PathStyle  bool   // 路径式：host/bucket
	FromTarget bool   // 目标本身就是桶端点
	Source     string // 出处：目标主机 / 响应头 / 页面
}

func classifyBucketHost(host string) (bucketRef, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, re := range []struct {
		rx   *regexp.Regexp
		name string
	}{
		{awsVHostRe, "aws"},
		{aliyunVHostRe, "aliyun"},
		{cosVHostRe, "tencent"},
		{bceVHostRe, "bcebos"},
	} {
		if m := re.rx.FindStringSubmatch(h); m != nil {
			return bucketRef{Host: h, Bucket: m[1], Provider: re.name,
				Suffix: "." + m[2]}, true
		}
	}
	return bucketRef{}, false
}

func providerOfHost(h string) string {
	switch {
	case strings.Contains(h, "amazonaws"):
		return "aws"
	case strings.Contains(h, "aliyuncs"):
		return "aliyun"
	case strings.Contains(h, "myqcloud"):
		return "tencent"
	case strings.Contains(h, "bcebos"):
		return "bcebos"
	}
	return "unknown"
}

func providerLabel(p string) string {
	switch p {
	case "aws":
		return "AWS S3"
	case "aliyun":
		return "阿里云 OSS"
	case "tencent":
		return "腾讯云 COS"
	case "bcebos":
		return "百度云 BOS"
	}
	return p
}

// extractBucketRefs 从文本里抽桶引用（去重，保持首次出现顺序）
func extractBucketRefs(text, source string) []bucketRef {
	var out []bucketRef
	for _, m := range cloudHostRe.FindAllStringSubmatch(text, -1) {
		if ref, ok := classifyBucketHost(m[1]); ok {
			ref.Source = source
			out = append(out, ref)
		}
	}
	// 路径式必须排除「虚拟主机式 URL 里的目录段」：
	// lab-cdn.bj.bcebos.com/static/x.js 里的 static 是目录，不是桶。
	// 判据是 host 组前面紧挨着 '.'（说明 host 本身是个子域）。
	for _, idx := range pathStyleRe.FindAllStringSubmatchIndex(text, -1) {
		if idx[2] > 0 && text[idx[2]-1] == '.' {
			continue
		}
		host := strings.ToLower(text[idx[2]:idx[3]])
		bucket := strings.ToLower(text[idx[4]:idx[5]])
		out = append(out, bucketRef{
			Host: host, Bucket: bucket,
			Provider: providerOfHost(host), PathStyle: true, Source: source,
		})
	}
	return dedupeBucketRefs(out)
}

func dedupeBucketRefs(in []bucketRef) []bucketRef {
	seen := map[string]bool{}
	out := make([]bucketRef, 0, len(in))
	for _, r := range in {
		if r.Bucket == "" || r.Host == "" {
			continue
		}
		k := r.Provider + "|" + r.Bucket + "|" + r.Host
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	return out
}

// bucketRefsFromTarget 目标本身就是桶端点时，直接拿它自己当引用
func bucketRefsFromTarget(c *scan.Ctx) []bucketRef {
	if c == nil {
		return nil
	}
	if ref, ok := classifyBucketHost(c.Host); ok {
		ref.FromTarget = true
		ref.Source = "目标主机"
		return []bucketRef{ref}
	}
	// 路径式目标：https://oss-cn-hangzhou.aliyuncs.com/my-bucket
	h := strings.ToLower(c.Host)
	for _, rx := range []*regexp.Regexp{
		regexp.MustCompile(`^s3(?:[.\-][a-z0-9\-]+)*\.amazonaws\.com(?:\.cn)?$`),
		regexp.MustCompile(`^oss-[a-z0-9\-]+\.aliyuncs\.com$`),
		regexp.MustCompile(`^cos\.[a-z0-9\-]+\.myqcloud\.com$`),
	} {
		if !rx.MatchString(h) {
			continue
		}
		p := strings.Trim(baseOf(c), "/")
		if k := strings.Index(p, "://"); k >= 0 {
			p = p[k+3:]
		}
		if i := strings.IndexByte(p, '/'); i >= 0 {
			seg := strings.SplitN(strings.Trim(p[i:], "/"), "/", 2)[0]
			if seg != "" {
				return []bucketRef{{Host: h, Bucket: seg, Provider: providerOfHost(h),
					PathStyle: true, FromTarget: true, Source: "目标主机"}}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- 探测

// bucketProbeURL 把桶引用映射成实际要探测的 List URL。
//
// 变量是接缝：单测指向本地假桶服务（真实 S3 域名在离线环境里解析不了），
// 受限网络里也可能要走内网 S3 代理。
var bucketProbeURL func(ref bucketRef, v2 bool) string

// listURL 拼 List 请求。只读：GET，最多列 1 个 key。
func listURL(c *scan.Ctx, ref bucketRef, v2 bool) string {
	if bucketProbeURL != nil {
		return bucketProbeURL(ref, v2)
	}
	var base string
	switch {
	case ref.FromTarget && baseOf(c) != "":
		base = baseOf(c)
	case c != nil && strings.EqualFold(ref.Host, c.Host) && baseOf(c) != "":
		base = baseOf(c)
		if ref.PathStyle {
			base += "/" + ref.Bucket
		}
	default:
		// 始终 https：桶端点基本都只开 443，http 会拿到 301 到 https
		base = "https://" + ref.Host
		if ref.PathStyle {
			base += "/" + ref.Bucket
		}
	}
	if v2 {
		return base + "/?list-type=2&max-keys=1"
	}
	// v1 列举：老网关/私有化部署不一定支持 list-type=2
	return base + "/?prefix=&max-keys=1"
}

// controlRef 对照桶：同端点上的随机桶名
func controlRef(ref bucketRef) bucketRef {
	ctl := ref
	ctl.Bucket = "litmusctl" + randToken(10)
	ctl.Source = "对照桶"
	ctl.FromTarget = false
	if !ref.PathStyle {
		ctl.Host = ctl.Bucket + ref.Suffix
	}
	return ctl
}

// classifyListResponse List 请求的判定。
//
// 关键的一行是 nosuchbucket：不存在的桶返回 NoSuchBucket，绝不算命中。
// 这条不是「顺便处理一下」，而是本检查唯一的假阳性闸门。
func classifyListResponse(status int, body string) string {
	if status != 200 && status != 206 {
		if s3ErrorCode(body) == "NoSuchBucket" {
			return "nosuchbucket"
		}
		return "other"
	}
	if strings.Contains(body, "<ListBucketResult") || strings.Contains(body, "<Contents") {
		return "public"
	}
	switch s3ErrorCode(body) {
	case "NoSuchBucket":
		return "nosuchbucket"
	case "AccessDenied", "AllAccessDisabled", "InvalidAccessKeyId", "SignatureDoesNotMatch":
		return "denied"
	}
	return "other"
}

var s3CodeRe = regexp.MustCompile(`<Code>([^<]{1,64})</Code>`)

func s3ErrorCode(body string) string {
	if m := s3CodeRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

var s3KeyRe = regexp.MustCompile(`<Key>([^<]{1,200})</Key>`)

// s3KeySamples 列举结果里的对象名（最多 n 个，仅作证据）
func s3KeySamples(body string, n int) []string {
	ms := s3KeyRe.FindAllStringSubmatch(body, n)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[1])
	}
	return out
}

// ChkS3Bucket 云存储桶未授权列举。
func ChkS3Bucket(c *scan.Ctx) scan.Result {
	b := newBudget(c)
	tested := 0
	refs := bucketRefsFromTarget(c)
	src := "目标主机"
	if len(refs) == 0 {
		if !b.take() {
			return scan.Skip("探测预算不足，未发起请求")
		}
		r := probe(c, "GET", urlFor(c, "/"), nil)
		tested++
		if r == nil || r.Err != nil {
			if r == nil {
				return scan.Skip("目标无响应（连接未建立）")
			}
			return scan.Skip("目标不可达: " + r.ErrText())
		}
		src = "响应头/页面"
		refs = extractBucketRefs(headerText(r)+"\n"+bodyOf(r), src)
	}
	if len(refs) == 0 {
		return okN(tested, "目标"+src+"未出现云存储桶引用（amazonaws/aliyuncs/myqcloud/bcebos）")
	}
	const maxBuckets = 4
	if len(refs) > maxBuckets {
		refs = refs[:maxBuckets]
	}

	var fs []*model.Finding
	var notes []string
	for _, ref := range refs {
		if !b.take() {
			notes = append(notes, "探测预算耗尽，剩余桶未测")
			break
		}
		u := listURL(c, ref, true)
		r := probe(c, "GET", u, nil)
		tested++
		if r == nil || r.Err != nil {
			notes = append(notes, ref.Bucket+": 端点不可达")
			continue
		}
		kind := classifyListResponse(r.Status, bodyOf(r))
		if kind == "other" && b.take() {
			// v2 不被支持时退回 v1（很多私有化 OSS 网关只认 v1）
			u2 := listURL(c, ref, false)
			r2 := probe(c, "GET", u2, nil)
			tested++
			if r2 != nil && r2.Err == nil {
				if k2 := classifyListResponse(r2.Status, bodyOf(r2)); k2 != "other" {
					kind, u, r = k2, u2, r2
				}
			}
		}
		switch kind {
		case "public":
			ctl := controlRef(ref)
			cu := listURL(c, ctl, true)
			cr := probe(c, "GET", cu, nil)
			tested++
			if cr != nil && cr.Err == nil && classifyListResponse(cr.Status, bodyOf(cr)) == "public" {
				// 对照桶也能列 —— 端点对任意桶名都返回同一份列举结果，
				// 说明这是网关/反代的固定回包，不是真的可列举。
				notes = append(notes, ref.Bucket+": 对照桶同样返回列举内容，端点无区分度（判为假阳性）")
				continue
			}
			fs = append(fs, s3Finding(c, ref, u, r, ctl, cr))
		case "nosuchbucket":
			notes = append(notes, ref.Bucket+": NoSuchBucket（桶不存在，不计命中）")
		case "denied":
			notes = append(notes, ref.Bucket+": AccessDenied（桶存在但拒绝匿名列举）")
		default:
			notes = append(notes, fmt.Sprintf("%s: HTTP %d，非列举响应", ref.Bucket, r.Status))
		}
	}

	reason := "已探测 " + strconv.Itoa(len(refs)) + " 个桶引用"
	if len(notes) > 0 {
		reason += "：" + strings.Join(notes, "；")
	}
	if len(fs) == 0 {
		return okN(tested, reason)
	}
	return okN(tested, reason, fs...)
}

func s3Finding(c *scan.Ctx, ref bucketRef, u string, r *httpc.Response,
	ctl bucketRef, cr *httpc.Response) *model.Finding {
	body := bodyOf(r)
	keys := s3KeySamples(body, 3)
	ctlVerdict := "无响应（区分度未验证）"
	if cr != nil {
		switch code := s3ErrorCode(bodyOf(cr)); {
		case cr.Err != nil:
			ctlVerdict = "连接失败（区分度未验证）"
		case code != "":
			ctlVerdict = fmt.Sprintf("HTTP %d %s（端点行为可区分）", cr.Status, code)
		default:
			ctlVerdict = fmt.Sprintf("HTTP %d（端点行为可区分）", cr.Status)
		}
	}
	ev := fmt.Sprintf("GET %s → HTTP %d | Content-Type: %s | 长度 %dB\n"+
		"判据: 响应含 <ListBucketResult>/<Contents>，桶 %s（%s）允许匿名列举对象\n"+
		"对照: 同端点随机桶 %s → %s\n"+
		"对象样本: %s\n片段: %s",
		u, r.Status, orDefault(r.Header("content-type"), "(无)"), len(r.Body),
		ref.Bucket, providerLabel(ref.Provider), ctl.Bucket, ctlVerdict,
		orDefault(strings.Join(keys, ", "), "(无)"), clip(body, 320))
	return newFinding(c, findingSpec{
		Check: "exposure/s3-bucket", Name: "云存储桶未授权列举 " + ref.Bucket,
		Severity: "high", Level: "L2", Category: "web", Target: u,
		Evidence: ev,
		Repro:    "curl -s '" + u + "' | head -c 400",
		Impact: "任何人可匿名列出并下载桶内全部对象（数据备份、日志、证件照、导出报表），" +
			"常见一步到业务数据泄露；若桶内还有前端打包产物，可进一步还原源码。",
		Fix: "关闭公共读/公共读写 ACL，开启「阻止公共访问」；桶策略只允许指定 VPC/角色访问；" +
			"为静态资源改用 CDN 回源并隐藏桶域名。",
		Extra: map[string]interface{}{
			"path":      "/?list-type=2",
			"bucket":    ref.Bucket,
			"provider":  ref.Provider,
			"endpoint":  ref.Host,
			"source":    ref.Source,
			"objects":   keys,
			"control":   ctl.Bucket,
			"control_r": ctlVerdict,
		},
	})
}

// ---------------------------------------------------------------- 元数据端点

// metadataEndpoint 一个云厂商的元数据根地址
type metadataEndpoint struct {
	Name string
	URL  string
}

// metadataEndpoints 变量而非常量：单测与隔离网络环境要替换它
// （沙箱里连不到 169.254.169.254，替换成假端点才能验证判定逻辑）。
var metadataEndpoints = []metadataEndpoint{
	{Name: "AWS/GCP/Azure 通用（IMDSv1）", URL: "http://169.254.169.254/latest/meta-data/"},
	{Name: "阿里云", URL: "http://100.100.100.200/latest/meta-data/"},
}

// metadataObservation 一次元数据探测的观察结果（缓存用）
type metadataObservation struct {
	at      time.Time
	status  int
	ctype   string
	body    string
	errText string
}

// 元数据端点是**扫描器所在主机**的链路本地地址，与具体目标无关：
// 一台机器上扫 200 个 Web 端口，探测结论完全一样。不缓存的话每端口白等
// 2×5 秒；缓存反而比重复探测更符合「扫描器视角」的语义。
var (
	metadataMu    sync.Mutex
	metadataCache = map[string]metadataObservation{}
	metadataTTL   = 5 * time.Minute
)

// observeMetadata 带缓存的单次探测（返回值里的 tested 表示是否真的发了请求）
func observeMetadata(c *scan.Ctx, ep metadataEndpoint, d time.Duration) (metadataObservation, bool) {
	metadataMu.Lock()
	o, ok := metadataCache[ep.URL]
	metadataMu.Unlock()
	if ok && time.Since(o.at) < metadataTTL {
		return o, false
	}
	r := probeTimeout(c, "GET", ep.URL, nil, d)
	o = metadataObservation{at: time.Now()}
	switch {
	case r == nil:
		o.errText = "无响应"
	case r.Err != nil:
		o.errText = r.ErrText()
	default:
		o.status = r.Status
		o.ctype = r.Header("content-type")
		o.body = clip(bodyOf(r), 600)
	}
	metadataMu.Lock()
	metadataCache[ep.URL] = o
	metadataMu.Unlock()
	return o, true
}

// targetIsInternal 目标是否内网/回环/链路本地地址。
//
// 用 scope.IsPrivate 而不是 net.IP.IsPrivate：范围守卫放行的那批保留段
// （192.0.2.0/24、198.18.0.0/15 等靶场段）必须口径一致，否则会出现
// 「扫描器放行了，检查项却说这不是内网」的自相矛盾。
func targetIsInternal(c *scan.Ctx) (bool, string) {
	if c == nil {
		return false, "上下文为空"
	}
	h := c.Host
	if h == "" {
		return false, "主机为空"
	}
	if ip := net.ParseIP(h); ip != nil {
		if scope.IsPrivate(ip) {
			return true, h
		}
		return false, h + " 是公网地址"
	}
	ips, err := net.LookupHost(h)
	if err != nil {
		return false, "DNS 解析失败: " + err.Error()
	}
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && scope.IsPrivate(ip) {
			return true, s
		}
	}
	return false, h + " 解析到公网地址"
}

// ChkMetadata 云主机元数据端点可达。
//
// 视角必须写清楚：本项由**扫描器**发起请求，证明的是「扫描器所在网段能直达
// 元数据端点」。目标机自己能不能访问，取决于目标上的 SSRF/命令执行，
// 那属于注入类检查的结论。所以：
//   - 目标不是内网地址 → Skip（判定不适用，不能拿公网目标的结论说事）
//   - 命中 → 只说「本网段可直达」，不写成「目标存在 SSRF」
func ChkMetadata(c *scan.Ctx) scan.Result {
	if internal, _ := targetIsInternal(c); !internal {
		return scan.Skip("目标非内网地址，元数据端点判定不适用")
	}
	// 元数据端点只在内网，给短超时：串行等两个 8 秒没有意义
	d := timeoutOf(c)
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	tested := 0
	var fs []*model.Finding
	var notes []string
	for _, ep := range metadataEndpoints {
		obs, sent := observeMetadata(c, ep, d)
		if sent {
			tested++
		}
		if obs.errText != "" {
			notes = append(notes, ep.Name+" 不可达")
			continue
		}
		body := obs.body
		if obs.status != 200 {
			notes = append(notes, fmt.Sprintf("%s → HTTP %d", ep.Name, obs.status))
			continue
		}
		low := strings.ToLower(body)
		if strings.Contains(low, "<html") || strings.Contains(low, "<!doctype") {
			// 200 + HTML：典型是热点门户/代理劫持，不是元数据服务
			notes = append(notes, ep.Name+" 返回 HTML（门户/代理劫持），不计命中")
			continue
		}
		var markers []string
		for _, m := range []string{"ami-id", "instance-id", "security-credentials"} {
			if strings.Contains(low, m) {
				markers = append(markers, m)
			}
		}
		if len(markers) == 0 {
			notes = append(notes, ep.Name+" 无元数据特征串")
			continue
		}
		fs = append(fs, newFinding(c, findingSpec{
			Check: "exposure/oss-metadata", Name: "云主机元数据端点可达（" + ep.Name + "）",
			Severity: "high", Level: "L2", Category: "host",
			Target: orDefault(c.Target, c.Host),
			Evidence: fmt.Sprintf("GET %s → HTTP %d | Content-Type: %s | 长度 %dB\n"+
				"命中特征: %s\n"+
				"视角: 由扫描器发起，证明「扫描器所在网段可直达元数据端点」；"+
				"目标机自身可达性需由 SSRF/命令执行类检查确认，本项不下跨主机结论。\n"+
				"片段: %s",
				ep.URL, obs.status, orDefault(obs.ctype, "(无)"), len(body),
				strings.Join(markers, ", "), clip(body, 300)),
			Repro: "curl -s '" + ep.URL + "'",
			Impact: "能访问元数据端点的主机可读取实例角色临时凭据（security-credentials）、" +
				"instance-id、用户数据，直接获得云账号/实例权限，是最短的一条云内横向路径。",
			Fix: "启用 IMDSv2（强制 token）并限制跳数；对实例角色做最小授权；" +
				"在主机侧封禁 169.254.169.254 与 100.100.100.200 的出站访问（除元数据代理）。",
			Extra: map[string]interface{}{
				"path":        "/latest/meta-data/",
				"endpoint":    ep.URL,
				"markers":     markers,
				"perspective": "scanner",
			},
		}))
	}
	if len(fs) == 0 {
		reason := "已探测 " + strconv.Itoa(len(metadataEndpoints)) + " 个元数据端点"
		if len(notes) > 0 {
			reason += "：" + strings.Join(notes, "；")
		}
		if len(notes) == len(metadataEndpoints) && allUnreachable(notes) {
			return scan.Skip("元数据端点从扫描器侧不可达：" + strings.Join(notes, "；"))
		}
		return okN(tested, reason)
	}
	return okN(tested, strings.Join(notes, "；"), fs...)
}

func allUnreachable(notes []string) bool {
	for _, n := range notes {
		if !strings.Contains(n, "不可达") {
			return false
		}
	}
	return len(notes) > 0
}

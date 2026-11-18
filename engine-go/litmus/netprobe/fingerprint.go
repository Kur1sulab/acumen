package netprobe

import (
	"regexp"
	"strings"
	"time"
)

// 字符类的区别是 Python 的硬事实，不能一律照抄：
//   - pyWS 是 bytes 模式下的 \s，恰好等于 [ \t\n\r\f\v]（Go 的 \s 少了 \v）
//   - pyWSUni / pyWordChars 是 str 模式下的 \s 与 \w（Unicode 语义，比 bytes 版多出
//     \x1c-\x1f / \x85 / \xa0 这些空白，以及拉丁字母等非 ASCII 字母数字）
//
// 哪条用哪个，看 Python 源码里那个模式的 r 前缀有没有 b：
// _PRODUCT_VER 是 r"..."（str 模式），其余指纹全是 rb"..."（bytes 模式）。
const (
	pyWS    = `[ \t\n\r\f\v]`
	pyWSUni = `[ \t\n\r\f\v\x{1c}-\x{1f}\x{85}\x{a0}]`
	// pyWordChars 是 str 模式 \w 的**内容**（不带方括号），方便嵌进更大的字符类
	pyWordChars = `\p{L}\p{N}_`
)

// sig 是一条指纹。对应 Python 元组 (正则, service, product, version_group)。
//
// 版本号有两种取法，与 Python 的 _sig_match 完全一致：
//   - vgroup > 0：版本号是**同一条正则**的第 vgroup 个分组
//   - vre != nil：版本号来自**另一条正则**，在整段数据里再搜一次（应用层指纹用）
type sig struct {
	re      *regexp.Regexp
	service string
	product string
	vgroup  int
	vre     *regexp.Regexp
}

func mustRe(pattern string) *regexp.Regexp {
	// (?is) == Python 的 re.I | re.S：忽略大小写 + . 匹配换行
	return regexp.MustCompile("(?is)" + pattern)
}

// bannerSigs 全部针对「被动 banner」或「只读探针响应」，顺序即优先级（先命中先返回）。
// 改动顺序会改变识别结果，别按字母序整理。
var bannerSigs = []sig{
	{re: mustRe(`SSH-([\d.]+)-OpenSSH[_-]([\w.]+)`), service: "ssh", product: "OpenSSH", vgroup: 2},
	{re: mustRe(`SSH-([\d.]+)-dropbear[_-]?([\w.]*)`), service: "ssh", product: "Dropbear", vgroup: 2},
	{re: mustRe(`SSH-([\d.]+)-Cisco`), service: "ssh", product: "Cisco SSH", vgroup: 1},
	{re: mustRe(`SSH-([\d.]+)-([\w.\-]+)`), service: "ssh", vgroup: 2},

	{re: mustRe(`^220[ -]([\w.\-]*) ?(?:FTP|ftp) server`), service: "ftp", vgroup: 1},
	{re: mustRe(`220[ -](?:\(vsFTPd ([\d.]+)\)|.*vsFTPd)`), service: "ftp", product: "vsftpd", vgroup: 1},
	{re: mustRe(`220.*ProFTPD ([\d.]+)`), service: "ftp", product: "ProFTPD", vgroup: 1},
	{re: mustRe(`220.*FileZilla Server`), service: "ftp", product: "FileZilla"},
	{re: mustRe(`220.*Pure-FTPd`), service: "ftp", product: "Pure-FTPd"},
	{re: mustRe(`220.*Microsoft FTP Service`), service: "ftp", product: "Microsoft FTP"},
	// 通用 FTP banner：各家欢迎语差异极大，只认 220 + FTP 关键字，别写死产品名
	{re: mustRe(`^220[ -][^\r\n]{0,120}?(?:FTP|ftp)`), service: "ftp"},

	{re: mustRe(`^STAT [a-z_]+ \d+`), service: "memcached", product: "Memcached"},
	{re: mustRe(`^VERSION [\d.]+`), service: "memcached", product: "Memcached"},

	{re: mustRe(`220[ -].*SMTP`), service: "smtp"},
	{re: mustRe(`220.*(?:ESMTP|Postfix|Exim|Sendmail|Exchange)`), service: "smtp"},
	{re: mustRe(`220 (?:mail|smtp)`), service: "smtp"},
	{re: mustRe(`\+OK.*(?:Dovecot|Courier)`), service: "pop3"},
	{re: mustRe(`\+OK`), service: "pop3"},
	{re: mustRe(`\* OK.*(?:Dovecot|Courier|IMAP)`), service: "imap"},
	{re: mustRe(`\* OK`), service: "imap"},

	{re: mustRe(`HTTP/1\.[01] \d{3}`), service: "http"},
	{re: mustRe(`RFB (\d{3}\.\d{3})`), service: "vnc", product: "VNC", vgroup: 1},
	{re: mustRe(`Telnet`), service: "telnet"},
	{re: mustRe(`MySQL|mariadb|MariaDB`), service: "mysql"},
	{re: mustRe(`-ERR unknown command`), service: "redis", product: "Redis"},
	{re: mustRe(`\+PONG`), service: "redis", product: "Redis"},
	{re: mustRe(`AMQP\x00\x00\x09\x01`), service: "amqp", product: "RabbitMQ"},
	{re: mustRe(`220.*Microsoft ESMTP`), service: "smtp", product: "Exchange"},
	{re: mustRe(`\xff\xfd`), service: "telnet"},
	{re: mustRe(`@RSYNCD:`), service: "rsync", product: "rsync"},
	{re: mustRe(`Escape character is`), service: "telnet"},
}

// httpBodySigs 是应用层强特征。必须排在协议 banner 之前：
// 否则 "HTTP/1.1 200" 会先把 Elasticsearch 吞成通用 http，
// 于是整类未授权验证被静默跳过（这是 Python 版实测到的漏报根因）。
var httpBodySigs = []sig{
	{re: mustRe(`"cluster_name"` + pyWS + `*:`), service: "elasticsearch", product: "Elasticsearch",
		vre: mustRe(`"number"` + pyWS + `*:` + pyWS + `*"([\d.]+)"`)},
	{re: mustRe(`"tagline"` + pyWS + `*:` + pyWS + `*"You Know, for Search"`), service: "elasticsearch", product: "Elasticsearch",
		vre: mustRe(`"number"` + pyWS + `*:` + pyWS + `*"([\d.]+)"`)},
	{re: mustRe(`"ApiVersion"` + pyWS + `*:|:` + pyWS + `*"moby"|"Name"` + pyWS + `*:` + pyWS + `*"(?:docker|moby)`), service: "docker", product: "Docker Engine",
		vre: mustRe(`"Version"` + pyWS + `*:` + pyWS + `*"([\d.]+)"`)},
	{re: mustRe(`"gitVersion"` + pyWS + `*:` + pyWS + `*"v?[\d.]+`), service: "kubernetes", product: "Kubernetes API",
		vre: mustRe(`"gitVersion"` + pyWS + `*:` + pyWS + `*"(v[\d.]+)"`)},
	{re: mustRe(`\{"id":\d+,"name":"`), service: "grafana", product: "Grafana"},
	{re: mustRe(`"cluster_name"|"nodes"` + pyWS + `*:` + pyWS + `*\{.*"http"`), service: "couchdb", product: "CouchDB",
		vre: mustRe(`"version"` + pyWS + `*:` + pyWS + `*"([\d.]+)"`)},
}

var (
	// 与 Python 的 _SERVER_RE / _POWERED_RE / _TITLE_RE / _PRODUCT_VER 逐条对应。
	// 前三条是 rb"..."（bytes 模式），最后一条是 r"..."（str 模式，Unicode 字符类）。
	serverRe  = regexp.MustCompile(`(?im)^Server:` + pyWS + `*([^\r\n]+)`)
	poweredRe = regexp.MustCompile(`(?im)^X-Powered-By:` + pyWS + `*([^\r\n]+)`)
	titleRe   = regexp.MustCompile(`(?is)<title[^>]*>([^<]{0,160})</title>`)
	// _PRODUCT_VER 作用在**已解码的 str** 上，所以 \w / \s 走 Unicode 语义：
	// "Server: clouåflare" 在 Python 里能整段当成产品名（å 是 Unicode 字母），
	// 用 Go 的 ASCII \w 就会变成「解析不出产品名」。这一条是差分实测出来的。
	productVerRe = regexp.MustCompile(`^([A-Za-z][` + pyWordChars + `.\-+]*?)(?:/([` + pyWordChars + `.\-+]+))?(?:` + pyWSUni + `|$)`)
)

// latin1 把字节按 latin-1 解码成字符串：一个字节 ↔ 一个 rune，绝不丢信息。
//
// 这一步是整个包的地基，理由见包注释：Go 的 regexp 是 rune 语义，
// 直接喂裸字节（0xFF 这种非法 UTF-8）会让 \xff 之类的模式匹配不到。
func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// pySpace 判定一个 rune 是不是 Python str.isspace() 认可的空白。
// 范围限定在 latin-1（解码后只可能是 U+0000..U+00FF），逐项对齐 CPython：
// \t \n \v \f \r 空格、\x1c-\x1f、\x85(NEL)、\xa0(NBSP)。
func pySpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x1c, 0x1d, 0x1e, 0x1f, 0x85, 0xa0:
		return true
	}
	return false
}

// pyStrip 等价于 Python 的 str.strip()（无参）。
// Go 的 strings.TrimSpace 用的是 unicode.IsSpace，不含 \x1c-\x1f，所以不能直接用。
func pyStrip(s string) string {
	return strings.TrimFunc(s, pySpace)
}

// truncRunes 截前 n 个 rune，对应 Python 的 s[:n]（bytes 切片）。
// 不能直接 s[:n] 切 Go 字符串：latin-1 解码后一个字节可能占两个 UTF-8 字节，
// 按字节切会切出半个 rune，evidence 就变成乱码了。
func truncRunes(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// sigMatch 按顺序找第一条命中的指纹，返回 (service, product, version, evidence)。
// evidence 是命中片段的前 160 个字符（Python: m.group(0)[:160]）。
func sigMatch(data string, sigs []sig) (service, product, version, evidence string, ok bool) {
	for _, s := range sigs {
		m := s.re.FindStringSubmatch(data)
		if m == nil {
			continue
		}
		switch {
		case s.vgroup > 0:
			if s.vgroup < len(m) {
				version = m[s.vgroup]
			}
		case s.vre != nil:
			if vm := s.vre.FindStringSubmatch(data); vm != nil && len(vm) > 1 {
				version = vm[1]
			}
		}
		return s.service, s.product, version, truncRunes(m[0], 160), true
	}
	return "", "", "", "", false
}

// refineHTTP 从 HTTP 响应里精化 product/version：Server 头 > X-Powered-By > title。
//
// 顺序不能换：Server 是服务端自报的权威信息，X-Powered-By 是框架自报，
// title 只是页面文字，可靠性依次下降。三者都拿不到就返回空，让上层保留原 evidence。
func refineHTTP(banner string) (product, version, evidence string) {
	if m := serverRe.FindStringSubmatch(banner); m != nil {
		server := pyStrip(m[1])
		evidence = "Server: " + server
		if pm := productVerRe.FindStringSubmatch(server); pm != nil {
			product, version = pm[1], pm[2]
		}
	}
	if product == "" {
		if m := poweredRe.FindStringSubmatch(banner); m != nil {
			powered := pyStrip(m[1])
			if evidence == "" {
				evidence = "X-Powered-By: " + powered
			}
			if pm := productVerRe.FindStringSubmatch(powered); pm != nil {
				product, version = pm[1], pm[2]
			}
		}
	}
	if product == "" {
		if m := titleRe.FindStringSubmatch(banner); m != nil && evidence == "" {
			evidence = "<title> " + pyStrip(m[1])
		}
	}
	return product, version, evidence
}

// Identify 给定 banner 返回 (service, product, version, evidence)。识别不出返回 "unknown"。
//
// 判定顺序：应用层强特征（ES/Docker/K8s）→ 协议 banner → HTTP 精化。
// 应用层优先，避免 "HTTP/1.1 200" 先把 ES 吞成通用 http。
//
// host / port / timeout 三个参数当前不参与判定 —— 这一点照抄 Python 的 identify()，
// 保留它们只为与 Python 版签名对齐，调用方不用猜「哪个参数才是真的」。
func Identify(host string, port int, banner []byte, timeout time.Duration) (service, product, version, evidence string) {
	return identify(banner)
}

// identify 是真正的判定内核，只吃 banner 字节。
func identify(banner []byte) (service, product, version, evidence string) {
	if len(banner) == 0 {
		return "unknown", "", "", ""
	}
	data := latin1(banner)
	if svc, prod, ver, ev, ok := sigMatch(data, httpBodySigs); ok {
		return svc, prod, ver, ev
	}
	if svc, prod, ver, ev, ok := sigMatch(data, bannerSigs); ok {
		if svc == "http" {
			p, v, e := refineHTTP(data)
			if e == "" {
				e = ev
			}
			return "http", p, v, e
		}
		return svc, prod, ver, ev
	}
	return "unknown", "", "", ""
}

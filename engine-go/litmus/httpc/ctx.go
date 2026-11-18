package httpc

import (
	"bytes"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// HeaderBytes 原始响应头字节（状态行 + headers，不含结尾空行）。
//
// part=header 的 matcher 用它，必须与线上字节一致 —— 所以优先切 RawResponse，
// 只有拿不到原始报文（构造出来的 Response）时才从字段重建。
// 对应 Python 的 _resp_header_bytes。
func (r *Response) HeaderBytes() []byte {
	raw := r.RawResponse
	if len(raw) > 0 {
		if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
			return raw[:i]
		}
		if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
			return raw[:i]
		}
		return raw
	}
	var b bytes.Buffer
	b.WriteString("HTTP/")
	b.WriteString(r.HTTPVersion)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(r.Status))
	if r.Reason != "" {
		b.WriteByte(' ')
		b.WriteString(r.Reason)
	}
	for _, h := range r.Headers {
		b.WriteString("\r\n")
		writeLatin1(&b, h.Name)
		b.WriteString(": ")
		writeLatin1(&b, h.Value)
	}
	return b.Bytes()
}

// Ctx nuclei DSL 上下文（变量名对齐 nuclei，模板里直接写 status_code / body ...）。
// 对应 Python 的 _resp_ctx。
func (r *Response) Ctx() map[string]interface{} {
	body := r.Body
	if body == nil {
		body = []byte{}
	}
	hb := r.HeaderBytes()
	p, err := url.Parse(r.URL)
	if err != nil || p == nil {
		p = &url.URL{}
	}
	path := p.EscapedPath()
	if path == "" {
		path = "/"
	}
	all := make([]byte, 0, len(hb)+2+len(body))
	all = append(all, hb...)
	all = append(all, CRLF...)
	all = append(all, body...)
	return map[string]interface{}{
		"status_code":    r.Status,
		"body":           strings.ToValidUTF8(string(body), "\uFFFD"),
		"header":         latin1String(hb),
		"all":            strings.ToValidUTF8(string(all), "\uFFFD"),
		"raw":            latin1String(r.RawResponse),
		"content_length": len(body),
		"duration":       math.Round(r.Seconds()*1e4) / 1e4,
		"host":           p.Host,
		"scheme":         p.Scheme,
		"path":           path,
		"content_type":   r.Header("content-type"),
		"location":       r.Header("location"),
		"server":         r.Header("server"),
	}
}

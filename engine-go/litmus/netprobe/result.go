package netprobe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// PortResult 是单个 host:port 的探测结果，字段与 Python 版 PortResult.__slots__ 一一对应。
//
// None 的表示：Python 里 service/product/version/tls/error 初值是 None，Go 用零值
// （"" / nil）表示同一个意思。AsDict / MarshalJSON 会把 "" 还原成 JSON null，
// 保证两边输出能逐字段 diff（契约三：JSON 字段名与 Python 逐字一致）。
//
// Banner 与 Error 不参与序列化 —— 这一点也是照抄 Python 的 as_dict()。
type PortResult struct {
	Host     string
	Port     int
	State    string
	Service  string
	Product  string
	Version  string
	Banner   []byte
	Evidence string
	TLS      *TLSInfo
	Elapsed  float64 // 秒，序列化时 round(x, 3)
	Error    string  // 不序列化（照抄 Python 的 as_dict 不含 error）；TLS 握手失败这类「没拦住探测但值得记一笔」的原因也记在这
}

// TLSInfo 是 _tls_probe 返回的 dict 的 Go 版本，键顺序与 Python 版构造顺序一致。
//
// Subject / Issuer 的键是证书 RDN 的短名（commonName / organizationName …），
// 与 Python 的 getpeercert()["subject"] 同一套命名。
type TLSInfo struct {
	Version  string            `json:"version"`
	Cipher   string            `json:"cipher"`
	Subject  map[string]string `json:"subject"`
	Issuer   map[string]string `json:"issuer"`
	NotAfter string            `json:"notAfter"`
	SHA256   string            `json:"sha256"`
}

// String 对应 Python 的 __repr__：
//
//	<host:port state service/product version>
func (r *PortResult) String() string {
	svc := r.Service
	if svc == "" {
		svc = "?"
	}
	if r.Product != "" {
		svc += "/" + r.Product
	}
	if r.Version != "" {
		svc += " " + r.Version
	}
	return fmt.Sprintf("<%s:%d %s %s>", r.Host, r.Port, r.State, svc)
}

// AsDict 对应 Python 的 as_dict()。键与值语义逐项对齐，不含 banner / error。
func (r *PortResult) AsDict() map[string]interface{} {
	return map[string]interface{}{
		"host":     r.Host,
		"port":     r.Port,
		"state":    r.State,
		"service":  orNil(r.Service),
		"product":  orNil(r.Product),
		"version":  orNil(r.Version),
		"evidence": r.Evidence,
		"tls":      r.TLS,
		"elapsed":  round3(r.Elapsed),
	}
}

// portResultJSON 只用于序列化：字段声明顺序 == Python dict 的插入顺序，
// 这样 json.Marshal 出来的键序与 Python 的 json.dumps 完全一致。
type portResultJSON struct {
	Host     string      `json:"host"`
	Port     int         `json:"port"`
	State    string      `json:"state"`
	Service  *string     `json:"service"`
	Product  *string     `json:"product"`
	Version  *string     `json:"version"`
	Evidence string      `json:"evidence"`
	TLS      *TLSInfo    `json:"tls"`
	Elapsed  pyFloatJSON `json:"elapsed"`
}

// MarshalJSON 让 PortResult 直接 json.Marshal 就能得到与 Python as_dict() 同序的 JSON。
//
// 注意：encoding/json 在调用完 MarshalJSON 之后会用「开启 HTML 转义」的配置重新压实
// 一遍输出，所以经过 json.Marshal 的串里 < > & 仍会变成 \u003c 这种形式。
// 要拿和 Python 逐字节一致的串，用 JSON() 而不是 json.Marshal。
func (r *PortResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.jsonView())
}

// JSON 输出与 Python json.dumps(as_dict(), separators=(",", ":")) 逐字节一致的串。
//
// 关掉 Go 默认的 HTML 转义：Python 的 json.dumps 不会把 < > & 转成 \u003c，
// 而 evidence 里恰好经常出现 "<title> xxx"，不关就永远 diff 不上。
func (r *PortResult) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r.jsonView()); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsonView 是 MarshalJSON / JSON 共用的视图：字段顺序 == Python dict 的插入顺序。
func (r *PortResult) jsonView() portResultJSON {
	return portResultJSON{
		Host:     r.Host,
		Port:     r.Port,
		State:    r.State,
		Service:  strPtr(r.Service),
		Product:  strPtr(r.Product),
		Version:  strPtr(r.Version),
		Evidence: r.Evidence,
		TLS:      r.TLS,
		Elapsed:  pyFloatJSON(r.Elapsed),
	}
}

// pyFloatJSON 按 Python 的风格序列化浮点数。
//
// 为什么要自己写：Go 的 encoding/json 把 2.0 写成 2，Python 的 json.dumps 写 2.0。
// 差这一个字符，oracle 差分就永远对不上。
type pyFloatJSON float64

// MarshalJSON 输出 round(x,3) 之后的最短十进制表示，整数补 ".0"。
func (f pyFloatJSON) MarshalJSON() ([]byte, error) {
	v := round3(float64(f))
	if math.IsNaN(v) || math.IsInf(v, 0) {
		// elapsed 来自 time.Since，不可能是 NaN/Inf；真出现了也不能吐非法 JSON。
		return []byte("0.0"), nil
	}
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return []byte(s), nil
}

// round3 对应 Python 的 round(x, 3)。
//
// 不能写 math.Round(x*1000)/1000：1.2345 的 double 实际是 1.23449999999999993…，
// Python 对**这个精确值**做十进制舍入得到 1.234；而 x*1000 在浮点里会先变成
// 1234.5000000000002，math.Round 就给出 1.235。实测两边确实分叉，所以这里走
// FormatFloat 的「对精确值正确舍入到 3 位小数」再解析回来，与 Python 逐位对齐。
// 代价是每端口多一次字符串往返 —— 相对于 connect 的耗时可以忽略。
func round3(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return x
	}
	v, err := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 3, 64), 64)
	if err != nil {
		return x
	}
	return v
}

// orNil 把「空串」还原成 Python 的 None。
// 必须返回无类型 nil：返回 (*string)(nil) 的话存进 interface{} 之后就不是 nil 了。
func orNil(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// strPtr 给 JSON 视图用：空串 → nil → 序列化成 null。
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

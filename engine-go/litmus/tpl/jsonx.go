package tpl

// jsonx.go — 有序 JSON 解析 + Python json.dumps 兼容输出。
//
// 为什么不用 encoding/json：
//   1. json 提取器的值如果不是字符串，原版会用 `json.dumps(v, ensure_ascii=False)`
//      写进 extracts，而 Python 的 dict 序是插入序 —— encoding/json 的 map 序是随机的；
//   2. json.loads 对数字的类型划分（7 → int，7.0 → float）会直接影响
//      提取结果 "7" 还是 "7.0"。

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

type jsonObject struct {
	keys []string
	vals map[string]any
}

func newJSONObject() *jsonObject { return &jsonObject{vals: map[string]any{}} }

func (o *jsonObject) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *jsonObject) get(k string) (any, bool) {
	v, ok := o.vals[k]
	return v, ok
}

type jsonParser struct {
	s     []rune
	i     int
	depth int
}

func parseJSON(text string) (any, error) {
	p := &jsonParser{s: []rune(text)}
	p.ws()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("json: 多余字符 at %d", p.i)
	}
	return v, nil
}

func (p *jsonParser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *jsonParser) value() (any, error) {
	if p.depth > 200 {
		return nil, fmt.Errorf("json: 嵌套过深")
	}
	p.ws()
	if p.i >= len(p.s) {
		return nil, fmt.Errorf("json: 意外结束")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		return p.str()
	case c == 't':
		if p.lit("true") {
			return true, nil
		}
	case c == 'f':
		if p.lit("false") {
			return false, nil
		}
	case c == 'n':
		if p.lit("null") {
			return nil, nil
		}
	case c == 'N':
		if p.lit("NaN") {
			return math.NaN(), nil
		}
	case c == '-':
		if strings.HasPrefix(string(p.s[p.i:]), "-Infinity") {
			p.i += len("-Infinity")
			return math.Inf(-1), nil
		}
		return p.number()
	case c >= '0' && c <= '9':
		return p.number()
	case c == 'I':
		if p.lit("Infinity") {
			return math.Inf(1), nil
		}
	}
	return nil, fmt.Errorf("json: 非法起始字符 %q", string(p.s[p.i]))
}

func (p *jsonParser) lit(word string) bool {
	w := []rune(word)
	if p.i+len(w) > len(p.s) {
		return false
	}
	for k, r := range w {
		if p.s[p.i+k] != r {
			return false
		}
	}
	p.i += len(w)
	return true
}

func (p *jsonParser) object() (any, error) {
	p.i++ // {
	p.depth++
	defer func() { p.depth-- }()
	o := newJSONObject()
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return o, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, fmt.Errorf("json: 对象键必须是字符串")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, fmt.Errorf("json: 缺少 ':'")
		}
		p.i++
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		o.set(k, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("json: 对象未闭合")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			return o, nil
		}
		return nil, fmt.Errorf("json: 对象内意外字符 %q", string(p.s[p.i]))
	}
}

func (p *jsonParser) array() (any, error) {
	p.i++ // [
	p.depth++
	defer func() { p.depth-- }()
	out := []any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return out, nil
	}
	for {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, fmt.Errorf("json: 数组未闭合")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		return nil, fmt.Errorf("json: 数组内意外字符 %q", string(p.s[p.i]))
	}
}

func (p *jsonParser) str() (string, error) {
	p.i++ // "
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == '"' {
			p.i++
			return b.String(), nil
		}
		if c != '\\' {
			b.WriteRune(c)
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.s) {
			break
		}
		e := p.s[p.i]
		p.i++
		switch e {
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case '/':
			b.WriteByte('/')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			if p.i+4 > len(p.s) {
				return "", fmt.Errorf("json: 非法 \\u 转义")
			}
			n, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 32)
			if err != nil {
				return "", fmt.Errorf("json: 非法 \\u 转义")
			}
			p.i += 4
			r := rune(n)
			if utf16.IsSurrogate(r) && p.i+6 <= len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
				n2, err := strconv.ParseUint(string(p.s[p.i+2:p.i+6]), 16, 32)
				if err == nil {
					r = utf16.DecodeRune(r, rune(n2))
					p.i += 6
				}
			}
			b.WriteRune(r)
		default:
			return "", fmt.Errorf("json: 未知转义 \\%c", e)
		}
	}
	return "", fmt.Errorf("json: 字符串未闭合")
}

func (p *jsonParser) number() (any, error) {
	start := p.i
	if p.i < len(p.s) && p.s[p.i] == '-' {
		p.i++
	}
	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		p.i++
	}
	isFloat := false
	if p.i < len(p.s) && p.s[p.i] == '.' {
		isFloat = true
		p.i++
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		isFloat = true
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	}
	text := string(p.s[start:p.i])
	if isFloat {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("json: 非法数字 %s", text)
		}
		return f, nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(text, 64)
		if ferr != nil {
			return nil, fmt.Errorf("json: 非法数字 %s", text)
		}
		return f, nil
	}
	return n, nil
}

// ---------------------------------------------------------------- 输出

// pyJSONDumps 复刻 json.dumps(v, ensure_ascii=False) 的默认分隔符。
func pyJSONDumps(v any) string {
	var b strings.Builder
	writeJSON(&b, v)
	return b.String()
}

func writeJSON(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJSONString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		switch {
		case math.IsNaN(x):
			b.WriteString("NaN")
		case math.IsInf(x, 1):
			b.WriteString("Infinity")
		case math.IsInf(x, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(pyFloatStr(x))
		}
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeJSON(b, e)
		}
		b.WriteByte(']')
	case *jsonObject:
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			writeJSONString(b, k)
			b.WriteString(": ")
			writeJSON(b, x.vals[k])
		}
		b.WriteByte('}')
	default:
		writeJSONString(b, pyStr(v))
	}
}

func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

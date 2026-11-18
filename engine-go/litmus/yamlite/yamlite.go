// Package yamlite 是 litmus2/yamlite.py 的 Go 移植：纯标准库 YAML 子集解析器。
//
// 覆盖面与 Python 版一致（按 nuclei 模板的真实用法裁剪）：
//
//	块映射 / 块序列 / 嵌套 / 注释
//	标量：plain、'单引号'、"双引号"（含转义）
//	块标量：| |- |+ > >- >+ 及缩进指示符
//	流集合：[a, b] {k: v}（含跨行）
//	多文档 ---（取首个）
//	锚点 &x / 别名 *x / 合并键 <<
//	类型：null、bool、int(含 0x/0o/1_000)、float、date/datetime
//
// 不实现（模板里不出现）：制表符缩进、复杂键 ? :、标签库、二进制 tag。
//
// 与 Python 版的已知差异（都是语言层无法 1:1 的地方，逐条记录，不隐瞒）：
//
//  1. 整数用 int64。Python int 是任意精度；超出 int64 的字面量这里回落成字符串
//     （Python 会返回大整数）。nuclei 模板里不存在这种值。
//  2. 映射键统一为 string。块映射的键在 Python 里本来就是 str（_split_key 只返回
//     str，_parse_map 里的 _coerce(key) 是死代码）；只有流映射 {1: x} 会产生非
//     字符串键，这里按 Python str() 规则编码（1 → "1"，True → "True"）。
//     副作用：{1: a, "1": b} 在 Go 侧会撞成一个键，Python 侧是两个键。
//  3. Python str 是码点序列，Go string 是字节序列。所有扫描按字节进行，
//     对 ASCII 分隔符（引号、冒号、#、括号）语义完全一致；只有 \uXXXX 落在
//     UTF-16 代理区时 Python 会保留孤立代理码点，Go 写成 U+FFFD。
//  4. 文件读取的 UTF-8 容错：Python 用 errors="replace" 逐字节替换，Go 侧用
//     strings.ToValidUTF8 按「无效字节段」替换，坏字节段长度不同则替换符数量不同。
//
// 对外入口：SafeLoad / Loads / SafeLoadFile。
package yamlite

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// YamlError 对应 Python 的 YamlError。
type YamlError struct{ Msg string }

func (e *YamlError) Error() string { return e.Msg }

func yamlErrorf(format string, a ...any) *YamlError {
	return &YamlError{Msg: fmt.Sprintf(format, a...)}
}

// Date 对应 Python 的 datetime.date（只保留年月日）。
type Date struct {
	Year, Month, Day int
}

func (d Date) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day)
}

// ISO 对应 Python 的 date.isoformat()。
func (d Date) ISO() string { return d.String() }

// DateTime 对应 Python 的 datetime.datetime（Python 版丢弃小数秒与时区，
// 这里保持一致，只留到秒）。
type DateTime struct {
	Year, Month, Day, Hour, Minute, Second int
}

func (d DateTime) String() string {
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
		d.Year, d.Month, d.Day, d.Hour, d.Minute, d.Second)
}

// ISO 对应 Python 的 datetime.isoformat()。
func (d DateTime) ISO() string {
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d",
		d.Year, d.Month, d.Day, d.Hour, d.Minute, d.Second)
}

// ─────────────────────────── 标量类型推断 ───────────────────────────

var boolTrue = map[string]struct{}{
	"y": {}, "Y": {}, "yes": {}, "Yes": {}, "YES": {},
	"true": {}, "True": {}, "TRUE": {}, "on": {}, "On": {}, "ON": {},
}

var boolFalse = map[string]struct{}{
	"n": {}, "N": {}, "no": {}, "No": {}, "NO": {},
	"false": {}, "False": {}, "FALSE": {}, "off": {}, "Off": {}, "OFF": {},
}

var nulls = map[string]struct{}{"": {}, "~": {}, "null": {}, "Null": {}, "NULL": {}}

var (
	reInt = regexp.MustCompile(`^[-+]?(0b[0-1_]+|0x[0-9a-fA-F_]+|0o?[0-7_]+|[0-9][0-9_]*)$`)
	reFloat = regexp.MustCompile(
		`^[-+]?(\.[0-9]+|[0-9][0-9_]*(\.[0-9_]*)?)([eE][-+]?[0-9]+)?$`)
	reDate = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)
	reDateTime = regexp.MustCompile(
		`^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(\.\d+)?` +
			`([ \t]*(Z|[-+]\d{1,2}(:?\d{2})?))?$`)
)

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// toInt 对应 _to_int：支持 0b/0x/0o 前缀、下划线分隔、YAML 1.1 前导零八进制。
func toInt(s string) (int64, bool) {
	s2 := strings.ReplaceAll(s, "_", "")
	neg := strings.HasPrefix(s2, "-")
	body := strings.TrimLeft(s2, "+-")
	var (
		v   int64
		err error
	)
	switch {
	case strings.HasPrefix(body, "0b"):
		v, err = strconv.ParseInt(body[2:], 2, 64)
	case strings.HasPrefix(body, "0x"):
		v, err = strconv.ParseInt(body[2:], 16, 64)
	case strings.HasPrefix(body, "0o"):
		v, err = strconv.ParseInt(body[2:], 8, 64)
	case len(body) > 1 && strings.HasPrefix(body, "0") && allDigits(body):
		v, err = strconv.ParseInt(body, 8, 64) // YAML 1.1 前导零 = 八进制
	default:
		v, err = strconv.ParseInt(body, 10, 64)
	}
	if err != nil {
		return 0, false
	}
	if neg {
		v = -v
	}
	return v, true
}

func validDate(y, m, d int) bool {
	if y < 1 || y > 9999 || m < 1 || m > 12 || d < 1 {
		return false
	}
	days := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	dm := days[m-1]
	if m == 2 && (y%4 == 0 && (y%100 != 0 || y%400 == 0)) {
		dm = 29
	}
	return d <= dm
}

// coerce 把 plain 标量转成对应的 Go 类型。
func coerce(s string) any {
	t := strings.TrimSpace(s)
	if _, ok := nulls[t]; ok {
		return nil
	}
	if _, ok := boolTrue[t]; ok {
		return true
	}
	if _, ok := boolFalse[t]; ok {
		return false
	}
	if reInt.MatchString(t) {
		if v, ok := toInt(t); ok {
			return v
		}
		return s
	}
	if reFloat.MatchString(t) && strings.ContainsAny(t, "0123456789") {
		v, err := strconv.ParseFloat(strings.ReplaceAll(t, "_", ""), 64)
		// Python float() 对超出范围的值返回 inf，不报错；Go 会同时返回 ErrRange。
		if err == nil || errors.Is(err, strconv.ErrRange) {
			return v
		}
		return s
	}
	if m := reDate.FindStringSubmatch(t); m != nil {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		if validDate(y, mo, d) {
			return Date{Year: y, Month: mo, Day: d}
		}
		return s
	}
	if m := reDateTime.FindStringSubmatch(t); m != nil {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		h, _ := strconv.Atoi(m[4])
		mi, _ := strconv.Atoi(m[5])
		se, _ := strconv.Atoi(m[6])
		if validDate(y, mo, d) && h >= 0 && h < 24 && mi >= 0 && mi < 60 && se >= 0 && se < 60 {
			return DateTime{Year: y, Month: mo, Day: d, Hour: h, Minute: mi, Second: se}
		}
		return s
	}
	return s
}

// ─────────────────────────── 转义 ───────────────────────────

var doubleEscapes = map[byte]string{
	'0': "\x00", 'a': "\a", 'b': "\b", 't': "\t", '\t': "\t", 'n': "\n",
	'v': "\v", 'f': "\f", 'r': "\r", 'e': "\x1b", ' ': " ", '"': `"`,
	'/': "/", '\\': `\`, 'N': "\u0085", '_': "\u00a0", 'L': "\u2028",
	'P': "\u2029",
}

// unescapeDouble 对应 _unescape_double。索引边界照抄 Python 版（含 i+3<n 这类
// 差一写法），否则 "\x4" 这种残尾的落点会变。
func unescapeDouble(body string) string {
	var b strings.Builder
	i := 0
	n := len(body)
	for i < n {
		c := body[i]
		if c != '\\' || i+1 >= n {
			b.WriteByte(c)
			i++
			continue
		}
		e := body[i+1]
		if v, ok := doubleEscapes[e]; ok {
			b.WriteString(v)
			i += 2
			continue
		}
		switch {
		case e == 'x' && i+3 < n:
			if v, err := strconv.ParseUint(body[i+2:i+4], 16, 32); err == nil {
				b.WriteRune(rune(v))
				i += 4
				continue
			}
			b.WriteByte(e)
			i += 2
		case e == 'u' && i+5 < n:
			if v, err := strconv.ParseUint(body[i+2:i+6], 16, 32); err == nil {
				b.WriteRune(rune(v))
				i += 6
				continue
			}
			b.WriteByte(e)
			i += 2
		case e == 'U' && i+9 < n:
			if v, err := strconv.ParseUint(body[i+2:i+10], 16, 32); err == nil && v <= utf8.MaxRune {
				b.WriteRune(rune(v))
				i += 10
				continue
			}
			b.WriteByte(e)
			i += 2
		default:
			// Python 追加的是「反斜杠后的那个字符」。按 rune 解码，避免把
			// 多字节字符劈成两半（Python 版 append(e) 是整个码点）。
			if e < utf8.RuneSelf {
				b.WriteByte(e)
				i += 2
			} else {
				r, size := utf8.DecodeRuneInString(body[i+1:])
				if r == utf8.RuneError && size <= 1 {
					b.WriteByte(e)
					i += 2
				} else {
					b.WriteString(body[i+1 : i+1+size])
					i += 1 + size
				}
			}
		}
	}
	return b.String()
}

// ─────────────────────────── 引号扫描 ───────────────────────────

// scanQuoted 从 s[pos] 的引号开始，返回 (内容, 结束后的位置)。
// 跨行拼接由调用方负责（对应 Python 版 _fold_quoted 的用法）。
func scanQuoted(s string, pos int) (string, int, error) {
	q := s[pos]
	i := pos + 1
	n := len(s)
	if q == '\'' {
		var buf strings.Builder
		for i < n {
			c := s[i]
			if c == '\'' {
				if i+1 < n && s[i+1] == '\'' {
					buf.WriteByte('\'')
					i += 2
					continue
				}
				return buf.String(), i + 1, nil
			}
			buf.WriteByte(c)
			i++
		}
		return "", 0, &YamlError{Msg: "单引号未闭合"}
	}
	var buf strings.Builder
	for i < n {
		c := s[i]
		if c == '\\' {
			end := i + 2
			if end > n {
				end = n
			}
			buf.WriteString(s[i:end])
			i += 2
			continue
		}
		if c == '"' {
			return unescapeDouble(buf.String()), i + 1, nil
		}
		buf.WriteByte(c)
		i++
	}
	return "", 0, &YamlError{Msg: "双引号未闭合"}
}

// flowBalanced 对应 _flow_balanced：判断流集合是否已经闭合。
func flowBalanced(s string) bool {
	depth := 0
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		if c == '\'' || c == '"' {
			_, ni, err := scanQuoted(s, i)
			if err != nil {
				return false
			}
			i = ni
			continue
		}
		switch c {
		case '[', '{':
			depth++
		case ']', '}':
			depth--
			if depth == 0 {
				return true
			}
		case '#':
			// 注释：本行剩余丢弃，交给上层；此处视为该行结束
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return depth == 0
			}
		}
		i++
	}
	return depth == 0
}

// stripComment 去掉行尾注释（# 前必须是空白或行首）。
//
// 引号只在「确实构成一个完整引号标量」时才跳过 —— 纯标量里的引号就是普通字符。
// 真踩过：nuclei 模板里的正则 (["']?[\w]+["']?) 含引号，盲目跳过引号会把整行
// 吃掉，结果这条 regex 变成空/错值（假阴性）。
func stripComment(s string) string {
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		if c == '\'' || c == '"' {
			end := -1
			if _, e, err := scanQuoted(s, i); err == nil {
				end = e
			}
			if end >= 0 {
				tail := strings.TrimLeft(s[end:], " \t")
				if tail == "" || strings.IndexByte("#,]}):", tail[0]) >= 0 {
					i = end
					continue
				}
			}
			i++
			continue
		}
		if c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return strings.TrimRightFunc(s[:i], unicode.IsSpace)
		}
		i++
	}
	return s
}

// splitKey 拆 "key: value"，返回 (key, rest, 是否成功)。支持引号键。
func splitKey(s string) (string, string, bool) {
	i := 0
	n := len(s)
	if n > 0 && (s[0] == '\'' || s[0] == '"') {
		key, ni, err := scanQuoted(s, 0)
		if err != nil {
			return "", "", false
		}
		i = ni
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i < n && s[i] == ':' {
			return key, s[i+1:], true
		}
		return "", "", false
	}
	depth := 0
	for i < n {
		c := s[i]
		switch c {
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case ':':
			if depth == 0 && (i+1 >= n || s[i+1] == ' ' || s[i+1] == '\t') {
				return strings.TrimRightFunc(s[:i], unicode.IsSpace), s[i+1:], true
			}
		}
		i++
	}
	return "", "", false
}

// ─────────────────────────── 解析器 ───────────────────────────

type parser struct {
	lines   []string
	i       int
	anchors map[string]any
}

func newParser(text string) *parser {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	return &parser{lines: strings.Split(text, "\n"), anchors: map[string]any{}}
}

func (p *parser) isBlank(line string) bool {
	s := strings.TrimSpace(line)
	return s == "" || strings.HasPrefix(s, "#")
}

func (p *parser) skipBlank() {
	for p.i < len(p.lines) && p.isBlank(p.lines[p.i]) {
		p.i++
	}
}

func (p *parser) indent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// peekIndent 返回下一个非空行的缩进；没有则 -1。
func (p *parser) peekIndent() int {
	j := p.i
	for j < len(p.lines) && p.isBlank(p.lines[j]) {
		j++
	}
	if j >= len(p.lines) {
		return -1
	}
	return p.indent(p.lines[j])
}

func (p *parser) parse() (any, error) {
	// 跳过指令与首个 ---
	for p.i < len(p.lines) {
		s := strings.TrimSpace(p.lines[p.i])
		if strings.HasPrefix(s, "%") {
			p.i++
			continue
		}
		if s == "---" || strings.HasPrefix(s, "--- ") {
			rest := strings.TrimSpace(s[3:])
			if rest != "" {
				p.lines[p.i] = rest
			} else {
				p.i++
			}
			break
		}
		break
	}
	p.skipBlank()
	if p.i >= len(p.lines) {
		return nil, nil
	}
	ind := p.indent(p.lines[p.i])
	return p.parseBlock(ind)
}

func (p *parser) parseBlock(ind int) (any, error) {
	p.skipBlank()
	if p.i >= len(p.lines) {
		return nil, nil
	}
	cur := p.indent(p.lines[p.i])
	if cur < ind {
		return nil, nil
	}
	s := strings.TrimSpace(p.lines[p.i])
	if s == "---" {
		return nil, nil
	}
	if s == "-" || strings.HasPrefix(s, "- ") {
		return p.parseSeq(cur)
	}
	// 先剥注释再判 key —— 否则注释里的 ": " 会把纯标量误判成映射
	if _, _, ok := splitKey(stripComment(s)); ok {
		return p.parseMap(cur)
	}
	return p.parseScalarLine(cur)
}

func (p *parser) parseSeq(ind int) ([]any, error) {
	out := []any{}
	last := -1
	for {
		if p.i == last {
			// 兜底：任何分支没推进游标都会在这里炸，绝不挂死
			return nil, yamlErrorf("序列解析未推进（第 %d 行），拒绝死循环", p.i+1)
		}
		last = p.i
		p.skipBlank()
		if p.i >= len(p.lines) {
			break
		}
		line := p.lines[p.i]
		cur := p.indent(line)
		if cur < ind || cur > ind {
			break
		}
		s := strings.TrimSpace(line)
		if s == "---" {
			break
		}
		if !(s == "-" || strings.HasPrefix(s, "- ")) {
			break
		}
		body := s[1:]
		col := cur + 1 + (len(body) - len(strings.TrimLeft(body, " ")))
		rest := strings.TrimLeft(body, " ")
		if rest == "" || strings.HasPrefix(rest, "#") {
			p.i++
			nxt := p.peekIndent()
			if nxt > cur {
				v, err := p.parseBlock(nxt)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, nil)
			}
			continue
		}
		// 把 "- xxx" 改写成同列缩进的 "xxx"，按块解析
		if rest[0] == '|' || rest[0] == '>' {
			p.i++ // 先吃掉 "- |" 这一行，否则块标量会原地死循环
			v, err := p.parseBlockScalar(rest, cur)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		if rest[0] == '&' {
			tok, tail, _ := strings.Cut(rest, " ")
			tail = strings.TrimSpace(tail)
			if tail != "" && (tail[0] == '|' || tail[0] == '>') {
				p.i++
				v, err := p.parseBlockScalar(tail, cur)
				if err != nil {
					return nil, err
				}
				p.anchors[tok[1:]] = v
				out = append(out, v)
				continue
			}
		}
		p.lines[p.i] = strings.Repeat(" ", col) + rest
		v, err := p.parseBlock(col)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func (p *parser) parseMap(ind int) (map[string]any, error) {
	out := map[string]any{}
	last := -1
	for {
		if p.i == last {
			return nil, yamlErrorf("映射解析未推进（第 %d 行），拒绝死循环", p.i+1)
		}
		last = p.i
		p.skipBlank()
		if p.i >= len(p.lines) {
			break
		}
		line := p.lines[p.i]
		cur := p.indent(line)
		if cur < ind || cur > ind {
			// 更深缩进但没被上一键吃掉：当作上一标量的续行，跳过防止死循环
			break
		}
		s := strings.TrimSpace(line)
		if s == "---" {
			break
		}
		if s == "-" || strings.HasPrefix(s, "- ") {
			break
		}
		key, rest, ok := splitKey(stripComment(s))
		if !ok {
			break
		}
		// Python 版这里是 `_coerce(key) if not isinstance(key, str)`：_split_key
		// 只返回 str，该分支是死代码，故 Go 侧不实现。
		if strings.HasPrefix(key, "? ") {
			key = strings.TrimSpace(key[2:])
		}
		rest = strings.TrimSpace(stripComment(rest))
		p.i++
		val, anchor, err := p.parseValue(rest, ind, true)
		if err != nil {
			return nil, err
		}
		if anchor != "" {
			p.anchors[anchor] = val
		}
		if key == "<<" {
			// 合并键
			srcs := []any{val}
			if l, ok := val.([]any); ok {
				srcs = l
			}
			for _, src := range srcs {
				if m, ok := src.(map[string]any); ok {
					for k, v := range m {
						if _, exists := out[k]; !exists {
							out[k] = v
						}
					}
				}
			}
			continue
		}
		out[key] = val
	}
	return out, nil
}

// parseValue 解析 "key:" 之后（或 "-" 之后）的剩余文本。返回 (值, 锚点名)。
func (p *parser) parseValue(rest string, ind int, allowBlock bool) (any, string, error) {
	anchor := ""
	for strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "!") {
		tok, tail, _ := strings.Cut(rest, " ")
		if strings.HasPrefix(tok, "&") {
			anchor = tok[1:]
		}
		rest = strings.TrimSpace(tail)
	}
	if strings.HasPrefix(rest, "*") {
		name := strings.TrimSpace(rest[1:])
		return p.anchors[name], anchor, nil
	}
	if rest == "" || strings.HasPrefix(rest, "#") {
		nxt := p.peekIndent()
		if nxt > ind {
			v, err := p.parseBlock(nxt)
			return v, anchor, err
		}
		// 序列允许与父键同缩进（YAML 合法）
		j := p.i
		for j < len(p.lines) && p.isBlank(p.lines[j]) {
			j++
		}
		if j < len(p.lines) {
			s := strings.TrimSpace(p.lines[j])
			if (s == "-" || strings.HasPrefix(s, "- ")) && p.indent(p.lines[j]) == ind {
				v, err := p.parseSeq(ind)
				return v, anchor, err
			}
		}
		return nil, anchor, nil
	}
	if rest[0] == '|' || rest[0] == '>' {
		v, err := p.parseBlockScalar(rest, ind)
		return v, anchor, err
	}
	if rest[0] == '[' || rest[0] == '{' {
		text := rest
		for !flowBalanced(text) && p.i < len(p.lines) {
			text += "\n" + p.lines[p.i]
			p.i++
		}
		v, _, err := parseFlow(text, 0)
		return v, anchor, err
	}
	if rest[0] == '\'' || rest[0] == '"' {
		dq := rest[0] == '"'
		text := rest
		for {
			val, _, err := scanQuoted(text, 0)
			if err == nil {
				return val, anchor, nil
			}
			if p.i >= len(p.lines) {
				return nil, anchor, err
			}
			text = foldQuoted(text, p.lines[p.i], dq)
			p.i++
		}
	}
	// plain 标量：可能跨行续写
	parts := []string{rest}
	for {
		j := p.i
		// Python 版此处还有一个 `while ...: break` 的空转循环（j 恒等于 self.i），
		// 等价于不做任何跳过，故 Go 侧直接省掉。
		if j >= len(p.lines) {
			break
		}
		nxtLine := p.lines[j]
		nxtInd := p.indent(nxtLine)
		if nxtInd <= ind || p.isBlank(nxtLine) {
			break
		}
		ns := strings.TrimSpace(nxtLine)
		if _, _, ok := splitKey(ns); ok || ns == "-" || strings.HasPrefix(ns, "- ") ||
			strings.HasPrefix(ns, "---") {
			break
		}
		parts = append(parts, ns)
		p.i++
	}
	return coerce(strings.Join(parts, " ")), anchor, nil
}

func (p *parser) parseScalarLine(ind int) (any, error) {
	line := p.lines[p.i]
	p.i++
	s := strings.TrimSpace(line)
	if s != "" && (s[0] == '\'' || s[0] == '"') {
		text := s
		for {
			val, _, err := scanQuoted(text, 0)
			if err == nil {
				return val, nil
			}
			if p.i >= len(p.lines) {
				return nil, err
			}
			text = foldQuoted(text, p.lines[p.i], s[0] == '"')
			p.i++
		}
	}
	if s != "" && (s[0] == '[' || s[0] == '{') {
		text := s
		for !flowBalanced(text) && p.i < len(p.lines) {
			text += "\n" + p.lines[p.i]
			p.i++
		}
		v, _, err := parseFlow(text, 0)
		return v, err
	}
	s = strings.TrimSpace(stripComment(s))
	return coerce(s), nil
}

// parseBlockScalar 解析 | |- |+ > >- >+ 及缩进指示符。
func (p *parser) parseBlockScalar(header string, ind int) (string, error) {
	style := header[0]
	// 块头后面可以跟注释：`- | # 说明`。注释里出现 '-' 或数字绝不能影响
	// chomp/缩进指示符的解析（真踩过：注释里的 "bj-lazy-load" 被当成 chomp '-'）
	hdr := header
	for _, mark := range []string{" #", "\t#"} {
		if k := strings.Index(hdr, mark); k != -1 {
			hdr = hdr[:k]
			break
		}
	}
	hdr = strings.TrimSpace(hdr)
	var chomp byte
	explicit := -1
	for i := 1; i < len(hdr); i++ {
		c := hdr[i]
		if c == '+' || c == '-' {
			chomp = c
		} else if c >= '0' && c <= '9' && explicit < 0 {
			explicit = int(c - '0')
		} else {
			break
		}
	}
	body := []string{}
	var contentInd int
	if explicit >= 0 {
		contentInd = ind + explicit
	} else {
		found := false
		for j := p.i; j < len(p.lines); j++ {
			if strings.TrimSpace(p.lines[j]) == "" {
				continue
			}
			contentInd = p.indent(p.lines[j])
			found = true
			break
		}
		if !found {
			contentInd = ind + 1
		}
		if contentInd <= ind {
			contentInd = ind + 1
		}
	}
	for p.i < len(p.lines) {
		line := p.lines[p.i]
		if strings.TrimSpace(line) == "" {
			body = append(body, "")
			p.i++
			continue
		}
		if p.indent(line) < contentInd {
			break
		}
		if contentInd <= len(line) {
			body = append(body, line[contentInd:])
		} else {
			body = append(body, "")
		}
		p.i++
	}
	// 去掉尾部空行（按 chomp 处理）
	trailing := 0
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
		trailing++
	}
	var text string
	if style == '|' {
		text = strings.Join(body, "\n")
	} else {
		var b strings.Builder
		for idx, ln := range body {
			switch {
			case idx == 0:
				b.WriteString(ln)
			case ln == "":
				b.WriteString("\n")
			case body[idx-1] == "":
				b.WriteString(ln)
			default:
				b.WriteString(" ")
				b.WriteString(ln)
			}
		}
		text = b.String()
	}
	switch chomp {
	case '-':
		return text, nil
	case '+':
		return text + strings.Repeat("\n", trailing+1), nil
	default:
		if text != "" {
			return text + "\n", nil
		}
		return text, nil
	}
}

// foldQuoted 引号标量跨行折叠（YAML 折叠规则）。
//
//   - 空行 → 真换行
//   - 普通换行 → 一个空格
//   - 双引号内行尾反斜杠 → 直接续接（吃掉反斜杠，不插空格）
//
// 这条规则不是学术洁癖：nuclei 模板里超长 regex 全是这么折行的，
// 不折叠就会把缩进和换行一起塞进正则，匹配必然失败（假阴性）。
func foldQuoted(cur, nxt string, dq bool) string {
	var body string
	if strings.TrimSpace(nxt) == "" {
		body = ""
	} else {
		body = strings.TrimLeft(nxt, " \t")
	}
	if body == "" {
		return strings.TrimRight(cur, " \t") + "\n"
	}
	if dq {
		// 数一下行尾连续反斜杠，奇数才是转义换行
		n := len(cur) - len(strings.TrimRight(cur, `\`))
		if n%2 == 1 {
			return cur[:len(cur)-1] + body
		}
	}
	if strings.HasSuffix(cur, "\n") {
		return cur + body
	}
	return strings.TrimRight(cur, " \t") + " " + body
}

// ─────────────────────────── 流集合 ───────────────────────────

func isFlowSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n'
}

// parseFlow 解析 [..] 或 {..}，返回 (值, 结束位置)。
func parseFlow(s string, pos int) (any, int, error) {
	n := len(s)
	for pos < n && isFlowSpace(s[pos]) {
		pos++
	}
	if pos >= n {
		return nil, pos, nil
	}
	c := s[pos]
	if c == '[' {
		pos++
		out := []any{}
		for pos < n {
			for pos < n && (isFlowSpace(s[pos]) || s[pos] == ',') {
				pos++
			}
			if pos >= n {
				break
			}
			if s[pos] == ']' {
				pos++
				break
			}
			v, np, err := parseFlow(s, pos)
			if err != nil {
				return nil, np, err
			}
			pos = np
			out = append(out, v)
		}
		return out, pos, nil
	}
	if c == '{' {
		pos++
		out := map[string]any{}
		for pos < n {
			for pos < n && (isFlowSpace(s[pos]) || s[pos] == ',') {
				pos++
			}
			if pos >= n {
				break
			}
			if s[pos] == '}' {
				pos++
				break
			}
			k, np, err := parseFlow(s, pos)
			if err != nil {
				return nil, np, err
			}
			pos = np
			for pos < n && isFlowSpace(s[pos]) {
				pos++
			}
			var v any
			if pos < n && s[pos] == ':' {
				pos++
				v, pos, err = parseFlow(s, pos)
				if err != nil {
					return nil, pos, err
				}
			}
			// Python 侧 dict 保留键的原类型；Go map 只能是 string，按 str() 编码。
			out[pyKeyStr(k)] = v
		}
		return out, pos, nil
	}
	if c == '\'' || c == '"' {
		val, np, err := scanQuoted(s, pos)
		if err != nil {
			return nil, np, err
		}
		return val, np, nil
	}
	// plain：到 , ] } 或 : 为止
	start := pos
	for pos < n {
		ch := s[pos]
		if ch == ',' || ch == ']' || ch == '}' {
			break
		}
		if ch == ':' && (pos+1 >= n || isFlowSpace(s[pos+1]) ||
			s[pos+1] == ',' || s[pos+1] == ']' || s[pos+1] == '}') {
			break
		}
		if ch == '#' && pos > start && isFlowSpace(s[pos-1]) {
			break
		}
		pos++
	}
	return coerce(strings.TrimSpace(s[start:pos])), pos, nil
}

// ─────────────────────────── Python 值格式化 ───────────────────────────

// pyKeyStr 把流映射的键按 Python str() 规则编码成 string。
func pyKeyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		return PyFloatStr(x)
	default:
		return PyStr(v)
	}
}

// PyFloatStr 近似 Python 的 repr(float)：整数值补 ".0"，非指数区间用定点。
func PyFloatStr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	if f == 0 {
		if strings.HasPrefix(strconv.FormatFloat(f, 'g', -1, 64), "-") {
			return "-0.0"
		}
		return "0.0"
	}
	abs := f
	if abs < 0 {
		abs = -abs
	}
	var s string
	if abs >= 1e-4 && abs < 1e16 {
		s = strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s
	}
	return strconv.FormatFloat(f, 'e', -1, 64)
}

// PyStr 近似 Python 的 str()，覆盖 YAML 标量能产生的类型。
func PyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	case float64:
		return PyFloatStr(x)
	case Date:
		return x.String()
	case DateTime:
		return x.String()
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(pyRepr(e))
		}
		b.WriteByte(']')
		return b.String()
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortStrings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(pyReprStr(k))
			b.WriteString(": ")
			b.WriteString(pyRepr(x[k]))
		}
		b.WriteByte('}')
		return b.String()
	}
	return fmt.Sprint(v)
}

func pyRepr(v any) string {
	if s, ok := v.(string); ok {
		return pyReprStr(s)
	}
	return PyStr(v)
}

// pyReprStr 近似 Python 的 repr(str)：优先单引号，必要时换双引号。
func pyReprStr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r == rune(quote) {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// sortStrings 是 sort.Strings 的本地副本，避免为两行代码引入 import 语义歧义。
func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// ─────────────────────────── 对外接口 ───────────────────────────

// SafeLoad 解析 YAML 文本。空输入返回 nil。
func SafeLoad(text string) (any, error) {
	return newParser(text).parse()
}

// Loads 是 SafeLoad 的别名（对齐 Python 的 loads = safe_load）。
func Loads(text string) (any, error) { return SafeLoad(text) }

// SafeLoadFile 读文件并解析（UTF-8 容错）。
func SafeLoadFile(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return SafeLoad(strings.ToValidUTF8(string(raw), "\uFFFD"))
}

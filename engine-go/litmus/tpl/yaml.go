package tpl

// yaml.go — yamlite.py 的 Go 移植（纯标准库 YAML 子集解析器）。
//
// tpl.py 的 load_template/load_dir 依赖自带的 yamlite，而不是 PyYAML。
// Go 标准库没有 YAML，所以这里把同一个子集原样移植过来：块映射/块序列、
// 单双引号标量（含跨行折叠）、块标量 | > 带 chomp 与缩进指示符、流集合、
// 注释、多文档取首个、锚点/别名/合并键、YAML 1.1 标量类型推断。
//
// 与原版的唯一差异：日期/时间标量保留为字符串（原版给 datetime.date），
// 模板里这两个类型只会被 str() 拼进描述，输出一致。

import (
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type yamlParser struct {
	lines   []string
	i       int
	anchors map[string]any
}

var (
	reYamlInt   = regexp.MustCompile(`^[-+]?(0b[0-1_]+|0x[0-9a-fA-F_]+|0o?[0-7_]+|[0-9][0-9_]*)$`)
	reYamlFloat = regexp.MustCompile(`^[-+]?(\.[0-9]+|[0-9][0-9_]*(\.[0-9_]*)?)([eE][-+]?[0-9]+)?$`)
)

var (
	yamlNulls = map[string]bool{"": true, "~": true, "null": true, "Null": true, "NULL": true}
	yamlTrue  = map[string]bool{
		"y": true, "Y": true, "yes": true, "Yes": true, "YES": true,
		"true": true, "True": true, "TRUE": true, "on": true, "On": true, "ON": true,
	}
	yamlFalse = map[string]bool{
		"n": true, "N": true, "no": true, "No": true, "NO": true,
		"false": true, "False": true, "FALSE": true, "off": true, "Off": true, "OFF": true,
	}
)

// yamlToInt 解析 YAML 整数。超出 int64 的用 big.Int 兜住（Python 的 int 无上限），
// 否则 14k 个真实模板里那种把十六进制 blob 写成裸整数的字段会被误判成字符串。
func yamlToInt(s string) (any, bool) {
	s2 := strings.ReplaceAll(s, "_", "")
	neg := strings.HasPrefix(s2, "-")
	body := strings.TrimLeft(s2, "+-")
	base := 10
	switch {
	case strings.HasPrefix(body, "0b"):
		base, body = 2, body[2:]
	case strings.HasPrefix(body, "0x"):
		base, body = 16, body[2:]
	case strings.HasPrefix(body, "0o"):
		base, body = 8, body[2:]
	case len(body) > 1 && body[0] == '0' && isAllDigits(body):
		base = 8
	}
	v, err := strconv.ParseInt(body, base, 64)
	if err != nil {
		bi, ok := new(big.Int).SetString(body, base)
		if !ok {
			return nil, false
		}
		if neg {
			bi.Neg(bi)
		}
		return bi, true
	}
	if neg {
		v = -v
	}
	return v, true
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func hasDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

// yamlCoerce 复刻 yamlite._coerce 的 plain 标量类型推断。
func yamlCoerce(s string) any {
	t := strings.TrimSpace(s)
	if yamlNulls[t] {
		return nil
	}
	if yamlTrue[t] {
		return true
	}
	if yamlFalse[t] {
		return false
	}
	if reYamlInt.MatchString(t) {
		if v, ok := yamlToInt(t); ok {
			return v
		}
		return s
	}
	if reYamlFloat.MatchString(t) && hasDigit(t) {
		if f, err := strconv.ParseFloat(strings.ReplaceAll(t, "_", ""), 64); err == nil {
			return f
		}
		return s
	}
	return s
}

// ---------------------------------------------------------------- 扫描工具

// yamlScanQuoted 从 rs[pos] 的引号开始扫描，返回 (内容, 关闭引号后的下标)。
func yamlScanQuoted(rs []rune, pos int) (string, int, bool) {
	if pos >= len(rs) {
		return "", pos, false
	}
	q := rs[pos]
	i := pos + 1
	if q == '\'' {
		var b strings.Builder
		for i < len(rs) {
			if rs[i] == '\'' {
				if i+1 < len(rs) && rs[i+1] == '\'' {
					b.WriteRune('\'')
					i += 2
					continue
				}
				return b.String(), i + 1, true
			}
			b.WriteRune(rs[i])
			i++
		}
		return "", pos, false
	}
	var b strings.Builder
	for i < len(rs) {
		c := rs[i]
		if c == '\\' {
			if i+1 < len(rs) {
				b.WriteRune(c)
				b.WriteRune(rs[i+1])
				i += 2
				continue
			}
			b.WriteRune(c)
			i++
			continue
		}
		if c == '"' {
			return yamlUnescapeDouble(b.String()), i + 1, true
		}
		b.WriteRune(c)
		i++
	}
	return "", pos, false
}

var yamlEscapes = map[rune]string{
	'0': "\x00", 'a': "\a", 'b': "\b", 't': "\t", '\t': "\t", 'n': "\n",
	'v': "\v", 'f': "\f", 'r': "\r", 'e': "\x1b", ' ': " ", '"': "\"",
	'/': "/", '\\': "\\", 'N': "\u0085", '_': "\u00a0", 'L': "\u2028",
	'P': "\u2029",
}

func yamlUnescapeDouble(body string) string {
	rs := []rune(body)
	var b strings.Builder
	i := 0
	for i < len(rs) {
		c := rs[i]
		if c != '\\' || i+1 >= len(rs) {
			b.WriteRune(c)
			i++
			continue
		}
		e := rs[i+1]
		if s, ok := yamlEscapes[e]; ok {
			b.WriteString(s)
			i += 2
			continue
		}
		hexLen := 0
		switch e {
		case 'x':
			hexLen = 2
		case 'u':
			hexLen = 4
		case 'U':
			hexLen = 8
		}
		if hexLen > 0 && i+2+hexLen <= len(rs) {
			if v, err := strconv.ParseUint(string(rs[i+2:i+2+hexLen]), 16, 32); err == nil {
				b.WriteRune(rune(v))
				i += 2 + hexLen
				continue
			}
		}
		b.WriteRune(e)
		i += 2
	}
	return b.String()
}

func yamlFlowBalanced(s string) bool {
	rs := []rune(s)
	depth := 0
	i := 0
	for i < len(rs) {
		c := rs[i]
		if c == '\'' || c == '"' {
			_, end, ok := yamlScanQuoted(rs, i)
			if !ok {
				return false
			}
			i = end
			continue
		}
		if c == '[' || c == '{' {
			depth++
		} else if c == ']' || c == '}' {
			depth--
			if depth == 0 {
				return true
			}
		} else if c == '#' && (i == 0 || rs[i-1] == ' ' || rs[i-1] == '\t') {
			return depth == 0
		}
		i++
	}
	return depth == 0
}

// yamlStripComment 去掉行尾注释（# 前必须是空白或行首）。
// 引号只在「确实构成完整引号标量」时才跳过 —— 正则里的引号是普通字符。
func yamlStripComment(s string) string {
	rs := []rune(s)
	i := 0
	for i < len(rs) {
		c := rs[i]
		if c == '\'' || c == '"' {
			if _, end, ok := yamlScanQuoted(rs, i); ok {
				tail := strings.TrimLeft(string(rs[end:]), " \t")
				if tail == "" || strings.ContainsRune("#,]}):", rune(tail[0])) {
					i = end
					continue
				}
			}
			i++
			continue
		}
		if c == '#' && (i == 0 || rs[i-1] == ' ' || rs[i-1] == '\t') {
			return strings.TrimRight(string(rs[:i]), " \t")
		}
		i++
	}
	return s
}

// yamlSplitKey 拆 "key: value"，支持引号键。返回 (key, rest, ok)。
func yamlSplitKey(s string) (string, string, bool) {
	rs := []rune(s)
	n := len(rs)
	if n > 0 && (rs[0] == '\'' || rs[0] == '"') {
		key, end, ok := yamlScanQuoted(rs, 0)
		if !ok {
			return "", "", false
		}
		i := end
		for i < n && (rs[i] == ' ' || rs[i] == '\t') {
			i++
		}
		if i < n && rs[i] == ':' {
			return key, string(rs[i+1:]), true
		}
		return "", "", false
	}
	depth := 0
	for i := 0; i < n; i++ {
		c := rs[i]
		switch {
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ':' && depth == 0:
			if i+1 >= n || rs[i+1] == ' ' || rs[i+1] == '\t' {
				return strings.TrimRight(string(rs[:i]), " \t"), string(rs[i+1:]), true
			}
		}
	}
	return "", "", false
}

func yamlFoldQuoted(cur, nxt string, dq bool) string {
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
		n := len(cur) - len(strings.TrimRight(cur, "\\"))
		if n%2 == 1 {
			return cur[:len(cur)-1] + body
		}
	}
	if strings.HasSuffix(cur, "\n") {
		return cur + body
	}
	return strings.TrimRight(cur, " \t") + " " + body
}

// ---------------------------------------------------------------- 流集合

func yamlParseFlow(rs []rune, pos int) (any, int, error) {
	n := len(rs)
	for pos < n && (rs[pos] == ' ' || rs[pos] == '\t' || rs[pos] == '\n') {
		pos++
	}
	if pos >= n {
		return nil, pos, nil
	}
	c := rs[pos]
	switch c {
	case '[':
		pos++
		out := []any{}
		for pos < n {
			for pos < n && (rs[pos] == ' ' || rs[pos] == '\t' || rs[pos] == '\n' || rs[pos] == ',') {
				pos++
			}
			if pos >= n {
				break
			}
			if rs[pos] == ']' {
				pos++
				break
			}
			v, np, err := yamlParseFlow(rs, pos)
			if err != nil {
				return nil, pos, err
			}
			out = append(out, v)
			pos = np
		}
		return out, pos, nil
	case '{':
		pos++
		out := map[string]any{}
		for pos < n {
			for pos < n && (rs[pos] == ' ' || rs[pos] == '\t' || rs[pos] == '\n' || rs[pos] == ',') {
				pos++
			}
			if pos >= n {
				break
			}
			if rs[pos] == '}' {
				pos++
				break
			}
			k, np, err := yamlParseFlow(rs, pos)
			if err != nil {
				return nil, pos, err
			}
			pos = np
			for pos < n && (rs[pos] == ' ' || rs[pos] == '\t' || rs[pos] == '\n') {
				pos++
			}
			var v any
			if pos < n && rs[pos] == ':' {
				pos++
				v, pos, err = yamlParseFlow(rs, pos)
				if err != nil {
					return nil, pos, err
				}
			}
			out[pyStr(k)] = v
		}
		return out, pos, nil
	case '\'', '"':
		val, end, ok := yamlScanQuoted(rs, pos)
		if !ok {
			return nil, pos, pyErr("YamlError", "引号未闭合")
		}
		return val, end, nil
	}
	start := pos
	for pos < n {
		ch := rs[pos]
		if ch == ',' || ch == ']' || ch == '}' {
			break
		}
		if ch == ':' && (pos+1 >= n || rs[pos+1] == ' ' || rs[pos+1] == '\t' || rs[pos+1] == '\n' ||
			rs[pos+1] == ',' || rs[pos+1] == ']' || rs[pos+1] == '}') {
			break
		}
		if ch == '#' && pos > start && (rs[pos-1] == ' ' || rs[pos-1] == '\t' || rs[pos-1] == '\n') {
			break
		}
		pos++
	}
	return yamlCoerce(strings.TrimSpace(string(rs[start:pos]))), pos, nil
}

// ---------------------------------------------------------------- 块解析

func yamlIsBlank(line string) bool {
	s := strings.TrimSpace(line)
	return s == "" || strings.HasPrefix(s, "#")
}

func yamlIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func (p *yamlParser) skipBlank() {
	for p.i < len(p.lines) && yamlIsBlank(p.lines[p.i]) {
		p.i++
	}
}

func (p *yamlParser) peekIndent() int {
	j := p.i
	for j < len(p.lines) && yamlIsBlank(p.lines[j]) {
		j++
	}
	if j >= len(p.lines) {
		return -1
	}
	return yamlIndent(p.lines[j])
}

func (p *yamlParser) parse() (any, error) {
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
	ind := yamlIndent(p.lines[p.i])
	return p.parseBlock(ind)
}

func (p *yamlParser) parseBlock(ind int) (any, error) {
	p.skipBlank()
	if p.i >= len(p.lines) {
		return nil, nil
	}
	cur := yamlIndent(p.lines[p.i])
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
	if _, _, ok := yamlSplitKey(yamlStripComment(s)); ok {
		return p.parseMap(cur)
	}
	return p.parseScalarLine()
}

func (p *yamlParser) parseSeq(ind int) (any, error) {
	out := []any{}
	last := -1
	for {
		if p.i == last {
			return nil, pyErr("YamlError", "序列解析未推进（第 %d 行），拒绝死循环", p.i+1)
		}
		last = p.i
		p.skipBlank()
		if p.i >= len(p.lines) {
			break
		}
		line := p.lines[p.i]
		cur := yamlIndent(line)
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
		if rest[0] == '|' || rest[0] == '>' {
			p.i++
			v, err := p.parseBlockScalar(rest, cur)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		if rest[0] == '&' {
			tok, tail := yamlPartition(rest, " ")
			tail = strings.TrimSpace(tail)
			if strings.HasPrefix(tail, "|") || strings.HasPrefix(tail, ">") {
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

func (p *yamlParser) parseMap(ind int) (any, error) {
	out := map[string]any{}
	last := -1
	for {
		if p.i == last {
			return nil, pyErr("YamlError", "映射解析未推进（第 %d 行），拒绝死循环", p.i+1)
		}
		last = p.i
		p.skipBlank()
		if p.i >= len(p.lines) {
			break
		}
		line := p.lines[p.i]
		cur := yamlIndent(line)
		if cur != ind {
			break
		}
		s := strings.TrimSpace(line)
		if s == "---" {
			break
		}
		if s == "-" || strings.HasPrefix(s, "- ") {
			break
		}
		key, rest, ok := yamlSplitKey(yamlStripComment(s))
		if !ok {
			break
		}
		if strings.HasPrefix(key, "? ") {
			key = strings.TrimSpace(key[2:])
		}
		rest = strings.TrimSpace(yamlStripComment(rest))
		p.i++
		val, anchor, err := p.parseValue(rest, ind)
		if err != nil {
			return nil, err
		}
		if anchor != "" {
			p.anchors[anchor] = val
		}
		if key == "<<" {
			srcs := []any{val}
			if l, ok := val.([]any); ok {
				srcs = l
			}
			for _, src := range srcs {
				if d, ok := src.(map[string]any); ok {
					for k, v := range d {
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

func (p *yamlParser) parseValue(rest string, ind int) (any, string, error) {
	anchor := ""
	for strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "!") {
		tok, tail := yamlPartition(rest, " ")
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
		for j < len(p.lines) && yamlIsBlank(p.lines[j]) {
			j++
		}
		if j < len(p.lines) {
			s := strings.TrimSpace(p.lines[j])
			if (s == "-" || strings.HasPrefix(s, "- ")) && yamlIndent(p.lines[j]) == ind {
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
		for !yamlFlowBalanced(text) && p.i < len(p.lines) {
			text += "\n" + p.lines[p.i]
			p.i++
		}
		v, _, err := yamlParseFlow([]rune(text), 0)
		return v, anchor, err
	}
	if rest[0] == '\'' || rest[0] == '"' {
		dq := rest[0] == '"'
		text := rest
		for {
			val, _, ok := yamlScanQuoted([]rune(text), 0)
			if ok {
				return val, anchor, nil
			}
			if p.i >= len(p.lines) {
				return nil, anchor, pyErr("YamlError", "引号未闭合")
			}
			text = yamlFoldQuoted(text, p.lines[p.i], dq)
			p.i++
		}
	}
	// plain 标量：可能跨行续写
	parts := []string{rest}
	for {
		j := p.i
		if j >= len(p.lines) {
			break
		}
		nxt := p.lines[j]
		if yamlIndent(nxt) <= ind || yamlIsBlank(nxt) {
			break
		}
		ns := strings.TrimSpace(nxt)
		if _, _, ok := yamlSplitKey(ns); ok || ns == "-" || strings.HasPrefix(ns, "- ") || strings.HasPrefix(ns, "---") {
			break
		}
		parts = append(parts, ns)
		p.i++
	}
	return yamlCoerce(strings.Join(parts, " ")), anchor, nil
}

func (p *yamlParser) parseScalarLine() (any, error) {
	line := p.lines[p.i]
	p.i++
	s := strings.TrimSpace(line)
	if s != "" && (s[0] == '\'' || s[0] == '"') {
		text := s
		for {
			val, _, ok := yamlScanQuoted([]rune(text), 0)
			if ok {
				return val, nil
			}
			if p.i >= len(p.lines) {
				return nil, pyErr("YamlError", "引号未闭合")
			}
			text = yamlFoldQuoted(text, p.lines[p.i], s[0] == '"')
			p.i++
		}
	}
	if s != "" && (s[0] == '[' || s[0] == '{') {
		text := s
		for !yamlFlowBalanced(text) && p.i < len(p.lines) {
			text += "\n" + p.lines[p.i]
			p.i++
		}
		v, _, err := yamlParseFlow([]rune(text), 0)
		return v, err
	}
	return yamlCoerce(strings.TrimSpace(yamlStripComment(s))), nil
}

func (p *yamlParser) parseBlockScalar(header string, ind int) (any, error) {
	style := header[0]
	hdr := header
	for _, mark := range []string{" #", "\t#"} {
		if k := strings.Index(hdr, mark); k != -1 {
			hdr = hdr[:k]
			break
		}
	}
	hdr = strings.TrimSpace(hdr)
	var chomp rune
	explicit := -1
	for _, c := range hdr[1:] {
		if c == '+' || c == '-' {
			chomp = c
		} else if c >= '0' && c <= '9' && explicit < 0 {
			explicit = int(c - '0')
		} else {
			break
		}
	}
	var body []string
	contentInd := 0
	if explicit >= 0 {
		contentInd = ind + explicit
	} else {
		contentInd = -1
		for j := p.i; j < len(p.lines); j++ {
			if strings.TrimSpace(p.lines[j]) == "" {
				continue
			}
			contentInd = yamlIndent(p.lines[j])
			break
		}
		if contentInd < 0 {
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
		if yamlIndent(line) < contentInd {
			break
		}
		rs := []rune(line)
		if contentInd > len(rs) {
			body = append(body, "")
		} else {
			body = append(body, string(rs[contentInd:]))
		}
		p.i++
	}
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
				b.WriteString(" " + ln)
			}
		}
		text = b.String()
	}
	switch chomp {
	case '-':
		return text, nil
	case '+':
		return text + strings.Repeat("\n", trailing+1), nil
	}
	if text != "" {
		return text + "\n", nil
	}
	return text, nil
}

func yamlPartition(s, sep string) (string, string) {
	if k := strings.Index(s, sep); k >= 0 {
		return s[:k], s[k+len(sep):]
	}
	return s, ""
}

// ---------------------------------------------------------------- 对外接口

// LoadYAML 解析一段 YAML 文本，返回 map[string]any / []any / 标量。
func LoadYAML(text string) (any, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	text = strings.TrimPrefix(text, "\ufeff")
	p := &yamlParser{lines: strings.Split(text, "\n"), anchors: map[string]any{}}
	return p.parse()
}

// LoadYAMLFile 读文件并解析；读取失败按原版 open(..., errors="replace") 处理。
func LoadYAMLFile(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadYAML(utf8DecodeReplace(b))
}

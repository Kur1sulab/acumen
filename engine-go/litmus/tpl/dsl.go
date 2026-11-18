package tpl

// dsl.go — nuclei DSL 的 tokenizer + Pratt 解析器（tpl.py 的 1:1 移植）。
//
// 词法/优先级/结合性都照抄原版 _TOKEN_RE / _BIN_PREC / _Parser，包括：
//   - 不支持短路（|| 和 && 两边都会求值）
//   - 未定义变量是 ValueError，不是"假"
//   - 未知函数是 ValueError
//   - 除零/模零返回 0（`a / b if b else 0`）

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type token struct {
	kind string // num / str / op / ident
	val  any
}

// scanDSLString 从引号开始扫到配对引号（反斜杠转义下一字符）。
func scanDSLString(rs []rune, pos int) (int, bool) {
	quote := rs[pos]
	for i := pos + 1; i < len(rs); i++ {
		switch rs[i] {
		case '\\':
			i++
		case quote:
			return i, true
		}
	}
	return 0, false
}

func isIdentStart(c rune) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c rune) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.'
}

var dslOps = []string{"||", "&&", "==", "!=", "<=", ">=", "!", "<", ">", "+", "-", "*", "/", "%", "(", ")", ","}

func tokenize(expr string) ([]token, error) {
	rs := []rune(expr)
	var toks []token
	pos := 0
	for pos < len(rs) {
		for pos < len(rs) && unicode.IsSpace(rs[pos]) {
			pos++
		}
		if pos >= len(rs) {
			break
		}
		c := rs[pos]
		switch {
		case c >= '0' && c <= '9':
			start := pos
			for pos < len(rs) && rs[pos] >= '0' && rs[pos] <= '9' {
				pos++
			}
			isFloat := false
			if pos+1 < len(rs) && rs[pos] == '.' && rs[pos+1] >= '0' && rs[pos+1] <= '9' {
				isFloat = true
				pos++
				for pos < len(rs) && rs[pos] >= '0' && rs[pos] <= '9' {
					pos++
				}
			}
			text := string(rs[start:pos])
			if isFloat {
				f, err := strconv.ParseFloat(text, 64)
				if err != nil {
					return nil, raiseValue("DSL 数字无法解析: %s", text)
				}
				toks = append(toks, token{"num", f})
			} else {
				n, err := strconv.ParseInt(text, 10, 64)
				if err != nil {
					// 超出 int64：按浮点近似（Python 是大整数，这里是有意的偏差）
					f, _ := strconv.ParseFloat(text, 64)
					toks = append(toks, token{"num", f})
				} else {
					toks = append(toks, token{"num", n})
				}
			}
		case c == '"' || c == '\'':
			end, ok := scanDSLString(rs, pos)
			if !ok {
				return nil, unrecognized(rs, pos)
			}
			raw := string(rs[pos+1 : end])
			raw = strings.ReplaceAll(raw, `\"`, `"`)
			raw = strings.ReplaceAll(raw, `\'`, `'`)
			raw = strings.ReplaceAll(raw, `\n`, "\n")
			raw = strings.ReplaceAll(raw, `\\`, `\`)
			toks = append(toks, token{"str", raw})
			pos = end + 1
		case isIdentStart(c):
			start := pos
			for pos < len(rs) && isIdentChar(rs[pos]) {
				pos++
			}
			toks = append(toks, token{"ident", string(rs[start:pos])})
		default:
			matched := ""
			for _, op := range dslOps {
				if strings.HasPrefix(string(rs[pos:]), op) {
					matched = op
					break
				}
			}
			if matched == "" {
				return nil, unrecognized(rs, pos)
			}
			toks = append(toks, token{"op", matched})
			pos += len([]rune(matched))
		}
	}
	return toks, nil
}

func unrecognized(rs []rune, pos int) error {
	end := pos + 20
	if end > len(rs) {
		end = len(rs)
	}
	return raiseValue("DSL 无法识别的字符: %s", pyStrRepr(string(rs[pos:end])))
}

var binPrec = map[string]int{
	"||": 1, "or": 1,
	"&&": 2, "and": 2,
	"==": 3, "!=": 3, "<": 3, "<=": 3, ">": 3, ">=": 3,
	"+": 4, "-": 4,
	"*": 5, "/": 5, "%": 5,
}

type dslFunc struct {
	pyName  string   // 原版里被调用的函数名，决定 TypeError 文案
	params  []string // 形参名，同样用于文案
	builtin bool     // len 是 Python 内建，报错文案与普通函数不同
	fn      func(args []any) (any, error)
}

type parser struct {
	toks  []token
	i     int
	ctx   map[string]any
	funcs map[string]dslFunc
}

func (p *parser) peek() token {
	if p.i < len(p.toks) {
		return p.toks[p.i]
	}
	return token{}
}

func (p *parser) next() token {
	t := p.peek()
	p.i++
	return t
}

func isOp(t token, op string) bool      { return t.kind == "op" && t.val == op }
func isIdent(t token, name string) bool { return t.kind == "ident" && t.val == name }

func (p *parser) parse(minPrec int) (any, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind != "op" && t.kind != "ident" {
			break
		}
		op := t.val.(string)
		if t.kind == "ident" && op != "and" && op != "or" {
			break
		}
		prec, ok := binPrec[op]
		if !ok || prec < minPrec {
			break
		}
		p.next()
		right, err := p.parse(prec + 1)
		if err != nil {
			return nil, err
		}
		left, err = applyOp(op, left, right)
		if err != nil {
			return nil, err
		}
	}
	return left, nil
}

func (p *parser) unary() (any, error) {
	t := p.peek()
	if isOp(t, "!") || isIdent(t, "not") {
		p.next()
		v, err := p.unary()
		if err != nil {
			return nil, err
		}
		return !truthy(v), nil
	}
	if isOp(t, "-") {
		p.next()
		v, err := p.unary()
		if err != nil {
			return nil, err
		}
		return pyNeg(v)
	}
	return p.postfix()
}

func (p *parser) postfix() (any, error) {
	t := p.peek()
	if isOp(t, "(") {
		p.next()
		v, err := p.parse(0)
		if err != nil {
			return nil, err
		}
		k2 := p.next()
		if !isOp(k2, ")") {
			return nil, raiseValue("DSL 括号不匹配")
		}
		return v, nil
	}
	if t.kind == "num" || t.kind == "str" {
		p.next()
		return t.val, nil
	}
	if t.kind == "ident" {
		p.next()
		name := t.val.(string)
		if isOp(p.peek(), "(") {
			p.next()
			args := []any{}
			if !isOp(p.peek(), ")") {
				for {
					a, err := p.parse(0)
					if err != nil {
						return nil, err
					}
					args = append(args, a)
					if isOp(p.peek(), ",") {
						p.next()
						continue
					}
					break
				}
			}
			k4 := p.next()
			if !isOp(k4, ")") {
				return nil, raiseValue("DSL 函数 %s 参数表未闭合", name)
			}
			fn, ok := p.funcs[name]
			if !ok {
				return nil, raiseValue("DSL 不支持的函数: %s()", name)
			}
			if err := bindArgs(fn, args); err != nil {
				return nil, err
			}
			return fn.fn(args)
		}
		switch name {
		case "true", "True":
			return true, nil
		case "false", "False":
			return false, nil
		}
		if v, ok := p.ctx[name]; ok {
			return v, nil
		}
		return nil, raiseValue("DSL 未定义变量: %s", name)
	}
	return nil, raiseValue("DSL 语法错误，遇到 %s", pyReprTokenVal(t))
}

func pyReprTokenVal(t token) string {
	if t.kind == "" {
		return "None"
	}
	return pyRepr(t.val)
}

func applyOp(op string, a, b any) (any, error) {
	switch op {
	case "||", "or":
		return truthy(a) || truthy(b), nil
	case "&&", "and":
		return truthy(a) && truthy(b), nil
	case "==":
		return pyEq(a, b), nil
	case "!=":
		return !pyEq(a, b), nil
	case "<", "<=", ">", ">=":
		return pyCompare(op, a, b)
	case "+":
		return pyAdd(a, b)
	case "-":
		return pySub(a, b)
	case "*":
		return pyMul(a, b)
	case "/":
		return pyDiv(a, b)
	case "%":
		return pyMod(a, b)
	}
	return nil, raiseValue("DSL 不支持的运算符: %s", op)
}

// ---------------------------------------------------------------- 内置函数

// bindArgs 复刻 CPython 的位置参数绑定报错，连文案一起对齐：
//
//	_f_contains() missing 1 required positional argument: 'needle'
//	_f_contains() takes 2 positional arguments but 3 were given
//	len() takes exactly one argument (0 given)
func bindArgs(f dslFunc, args []any) error {
	if f.builtin {
		if len(args) != 1 {
			return raiseType("%s() takes exactly one argument (%d given)", f.pyName, len(args))
		}
		return nil
	}
	if len(args) < len(f.params) {
		missing := f.params[len(args):]
		var names string
		switch len(missing) {
		case 1:
			names = "'" + missing[0] + "'"
		case 2:
			names = "'" + missing[0] + "' and '" + missing[1] + "'"
		default:
			q := make([]string, len(missing))
			for i, m := range missing {
				q[i] = "'" + m + "'"
			}
			names = strings.Join(q[:len(q)-1], ", ") + ", and " + q[len(q)-1]
		}
		plural := "arguments"
		if len(missing) == 1 {
			plural = "argument"
		}
		return raiseType("%s() missing %d required positional %s: %s", f.pyName, len(missing), plural, names)
	}
	if len(args) > len(f.params) {
		plural := "arguments"
		if len(f.params) == 1 {
			plural = "argument"
		}
		return raiseType("%s() takes %d positional %s but %d were given", f.pyName, len(f.params), plural, len(args))
	}
	return nil
}

func fContains(args []any) (any, error) {
	return strings.Contains(pyStr(args[0]), pyStr(args[1])), nil
}

func fIContains(args []any) (any, error) {
	return strings.Contains(strings.ToLower(pyStr(args[0])), strings.ToLower(pyStr(args[1]))), nil
}

func fRegex(args []any) (any, error) {
	re, err := regexp.Compile("(?s)" + pyStr(args[0]))
	if err != nil {
		return nil, pyErr("error", "invalid regular expression: %v", err)
	}
	return re.MatchString(pyStr(args[1])), nil
}

func fLen(args []any) (any, error) {
	n, err := pyLen(args[0])
	if err != nil {
		return int64(0), nil // 原版 _f_len 吞掉 TypeError 返回 0
	}
	return n, nil
}

func fToLower(args []any) (any, error) {
	return strings.ToLower(pyStr(args[0])), nil
}

func fToUpper(args []any) (any, error) {
	return strings.ToUpper(pyStr(args[0])), nil
}

func fStartsWith(args []any) (any, error) {
	return strings.HasPrefix(pyStr(args[0]), pyStr(args[1])), nil
}

func fEndsWith(args []any) (any, error) {
	return strings.HasSuffix(pyStr(args[0]), pyStr(args[1])), nil
}

func hashFn(alg string, args []any) (any, error) {
	data := []byte(pyStr(args[0]))
	switch alg {
	case "md5":
		sum := md5.Sum(data)
		return hex.EncodeToString(sum[:]), nil
	case "sha1":
		sum := sha1.Sum(data)
		return hex.EncodeToString(sum[:]), nil
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func fInt(args []any) (any, error) {
	return dslInt(args[0]), nil
}

var dslFuncs = map[string]dslFunc{
	"contains":    {"_f_contains", []string{"hay", "needle"}, false, fContains},
	"icontains":   {"_f_icontains", []string{"hay", "needle"}, false, fIContains},
	"regex":       {"_f_regex", []string{"pat", "s"}, false, fRegex},
	"len":         {"len", []string{"x"}, true, fLen},
	"tolower":     {"_f_tolower", []string{"x"}, false, fToLower},
	"toupper":     {"_f_toupper", []string{"x"}, false, fToUpper},
	"starts_with": {"_f_starts_with", []string{"s", "p"}, false, fStartsWith},
	"ends_with":   {"_f_ends_with", []string{"s", "p"}, false, fEndsWith},
	"md5":         {"_f_md5", []string{"x"}, false, func(a []any) (any, error) { return hashFn("md5", a) }},
	"sha1":        {"_f_sha1", []string{"x"}, false, func(a []any) (any, error) { return hashFn("sha1", a) }},
	"sha256":      {"_f_sha256", []string{"x"}, false, func(a []any) (any, error) { return hashFn("sha256", a) }},
	"int":         {"_f_int", []string{"x"}, false, fInt},
}

// EvalDSL 求值一条 DSL 表达式。异常向上抛，由调用方决定如何处理
// （matcher 会把它折成未命中 + evidence，extractor 会跳过该条）。
func EvalDSL(expr string, ctx map[string]any) (any, error) {
	toks, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, raiseValue("DSL 表达式为空")
	}
	p := &parser{toks: toks, ctx: ctx, funcs: dslFuncs}
	v, err := p.parse(0)
	if err != nil {
		return nil, err
	}
	if p.i != len(toks) {
		return nil, raiseValue("DSL 表达式有多余 token: %s", tokensRepr(toks[p.i:]))
	}
	return v, nil
}

func tokensRepr(toks []token) string {
	parts := make([]string, len(toks))
	for i, t := range toks {
		parts[i] = "(" + pyStrRepr(t.kind) + ", " + pyRepr(t.val) + ")"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

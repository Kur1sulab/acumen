package tpl

// value.go — Python 值语义的 Go 实现。
//
// 原版 tpl.py 的 DSL 直接在 Python 动态值上求值，行为细节（真假判定、
// int/float 混比、str() 的形态、负数取模、列表 repr）全部来自 Python。
// 移植时如果直接换成 Go 的 any + 类型断言，`status_code == 200`、
// `len(body) > 100`、evidence 字符串都会悄悄变味。所以这里把 Python
// 的那套语义单独抽出来实现，DSL / matcher / extractor 都只经过这一层。

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// pyError 对应一个 Python 异常的 (type(e).__name__, str(e))。
// evidence 里会拼成 "ValueError: ..." 这种形态，和原版一致。
type pyError struct {
	Kind string
	Msg  string
}

func (e *pyError) Error() string { return e.Kind + ": " + e.Msg }

func pyErr(kind, format string, a ...any) error {
	return &pyError{Kind: kind, Msg: fmt.Sprintf(format, a...)}
}

// raiseType 构造 TypeError。
func raiseType(format string, a ...any) error { return pyErr("TypeError", format, a...) }

// raiseValue 构造 ValueError。
func raiseValue(format string, a ...any) error { return pyErr("ValueError", format, a...) }

// unsupported 对应 tpl.Unsupported：模板用了未实现的特性。
// 它不是普通求值错误，必须一路冒泡到 Engine.Run 记成"未测"。
type unsupported struct{ msg string }

func (e *unsupported) Error() string { return e.msg }

func unsupportedf(format string, a ...any) error {
	return &unsupported{msg: fmt.Sprintf(format, a...)}
}

func isUnsupported(err error) bool {
	_, ok := err.(*unsupported)
	return ok
}

// IsUnsupported 判断错误是否表示"模板用了本引擎未实现的特性"。
// 对应原版抛出的 tpl.Unsupported：上层应记"未测"，不能当成未命中。
func IsUnsupported(err error) bool { return isUnsupported(err) }

// ---------------------------------------------------------------- 类型名

func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int, int64, *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []any:
		return "list"
	case map[string]any:
		return "dict"
	}
	return fmt.Sprintf("%T", v)
}

func isNum(v any) bool {
	switch v.(type) {
	case int, int64, float64, bool:
		return true
	}
	return false
}

func numOf(v any) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	}
	return math.NaN()
}

func isIntKind(v any) bool {
	switch v.(type) {
	case int, int64, bool:
		return true
	}
	return false
}

// intOf 取出 Go 侧的整数，非整数类型返回 ok=false。
func intOf(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// ---------------------------------------------------------------- 真假

// truthy 复刻原版 _truthy：
//
//	str: 不在 ("", "false", "False", "0") 里
//	其余: bool(v)
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != "" && x != "false" && x != "False" && x != "0"
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// boolOf 复刻 Python 的 bool(v)。注意它和 DSL 的 _truthy 不是一个东西：
// bool("false") 是 True，而 _truthy("false") 是 False。模板字段的
// `bool(...)` 和 `x or default` 都必须走这里。
func boolOf(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// orDefault 复刻 `value or def`（Python 的 or 用 bool()，不是 DSL 的 _truthy）。
func orDefault(v, def any) any {
	if boolOf(v) {
		return v
	}
	return def
}

// ---------------------------------------------------------------- str / repr

// pyFloatStr 复刻 Python 3 的 float repr / str。
//
// 关键点：整数值的浮点要带 ".0"（json 提取器把 7.0 写成 "7.0"），
// 大/小指数用 e 记法，阈值和 CPython 一致（|x| < 1e-4 或 >= 1e16）。
func pyFloatStr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	a := math.Abs(f)
	if f != 0 && (a < 1e-4 || a >= 1e16) {
		return strconv.FormatFloat(f, 'e', -1, 64)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// pyStr 复刻 str(v)。
func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *big.Int:
		return x.String()
	case float64:
		return pyFloatStr(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pyRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, pyRepr(k)+": "+pyRepr(x[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(v)
}

// pyStrRepr 复刻 CPython 的 str repr：优先单引号，含单引号且不含双引号时
// 改用双引号，控制字符转义。
func pyStrRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\x00':
			b.WriteString(`\x00`)
		case !unicode.IsPrint(r):
			switch {
			case r <= 0xFF:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r <= 0xFFFF:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// pyRepr 复刻 repr(v)。
func pyRepr(v any) string {
	switch x := v.(type) {
	case string:
		return pyStrRepr(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = pyRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]any:
		return pyStr(x)
	}
	return pyStr(v)
}

// ---------------------------------------------------------------- 比较

// pyEq 复刻 ==。Python 里 True == 1、200 == 200.0，Go 的类型化比较做不到。
func pyEq(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if as, ok := a.(*big.Int); ok {
		bs, ok := b.(*big.Int)
		return ok && as.Cmp(bs) == 0
	}
	if isNum(a) && isNum(b) {
		ai, aok := intOf(a)
		bi, bok := intOf(b)
		if aok && bok {
			return ai == bi
		}
		return numOf(a) == numOf(b)
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEq(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !pyEq(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// pyCompare 复刻 < <= > >=。
func pyCompare(op string, a, b any) (bool, error) {
	if isNum(a) && isNum(b) {
		ai, aok := intOf(a)
		bi, bok := intOf(b)
		var c int
		if aok && bok {
			switch {
			case ai < bi:
				c = -1
			case ai > bi:
				c = 1
			}
		} else {
			af, bf := numOf(a), numOf(b)
			switch {
			case af < bf:
				c = -1
			case af > bf:
				c = 1
			}
		}
		return cmpResult(op, c), nil
	}
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		if !ok {
			return false, raiseType("'%s' not supported between instances of 'str' and '%s'", op, pyTypeName(b))
		}
		return cmpResult(op, strings.Compare(as, bs)), nil
	}
	if al, ok := a.([]any); ok {
		bl, ok := b.([]any)
		if !ok {
			return false, raiseType("'%s' not supported between instances of 'list' and '%s'", op, pyTypeName(b))
		}
		for i := 0; i < len(al) && i < len(bl); i++ {
			if !pyEq(al[i], bl[i]) {
				return pyCompare(op, al[i], bl[i])
			}
		}
		// Python 对列表按长度继续比较
		return cmpResult(op, len(al)-len(bl)), nil
	}
	return false, raiseType("'%s' not supported between instances of '%s' and '%s'", op, pyTypeName(a), pyTypeName(b))
}

func cmpResult(op string, c int) bool {
	switch op {
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	}
	return false
}

// ---------------------------------------------------------------- 算术

func pyAdd(a, b any) (any, error) {
	if _, ok := a.(string); ok {
		return pyStr(a) + pyStr(b), nil
	}
	if _, ok := b.(string); ok {
		return pyStr(a) + pyStr(b), nil
	}
	if al, ok := a.([]any); ok {
		bl, ok := b.([]any)
		if !ok {
			return nil, raiseType("can only concatenate list (not \"%s\") to list", pyTypeName(b))
		}
		out := make([]any, 0, len(al)+len(bl))
		out = append(out, al...)
		out = append(out, bl...)
		return out, nil
	}
	if isIntKind(a) && isIntKind(b) {
		ai, _ := intOf(a)
		bi, _ := intOf(b)
		return ai + bi, nil
	}
	if isNum(a) && isNum(b) {
		return numOf(a) + numOf(b), nil
	}
	return nil, raiseType("unsupported operand type(s) for +: '%s' and '%s'", pyTypeName(a), pyTypeName(b))
}

func pySub(a, b any) (any, error) {
	if isIntKind(a) && isIntKind(b) {
		ai, _ := intOf(a)
		bi, _ := intOf(b)
		return ai - bi, nil
	}
	if isNum(a) && isNum(b) {
		return numOf(a) - numOf(b), nil
	}
	return nil, raiseType("unsupported operand type(s) for -: '%s' and '%s'", pyTypeName(a), pyTypeName(b))
}

func pyMul(a, b any) (any, error) {
	if s, ok := a.(string); ok {
		n, ok := intOf(b)
		if !ok {
			return nil, raiseType("can't multiply sequence by non-int of type '%s'", pyTypeName(b))
		}
		if n <= 0 {
			return "", nil
		}
		return strings.Repeat(s, int(n)), nil
	}
	if s, ok := b.(string); ok {
		n, ok := intOf(a)
		if !ok {
			return nil, raiseType("can't multiply sequence by non-int of type '%s'", pyTypeName(a))
		}
		if n <= 0 {
			return "", nil
		}
		return strings.Repeat(s, int(n)), nil
	}
	if al, ok := a.([]any); ok {
		n, ok := intOf(b)
		if !ok {
			return nil, raiseType("can't multiply sequence by non-int of type '%s'", pyTypeName(b))
		}
		out := make([]any, 0, len(al)*int(max64(n, 0)))
		for i := int64(0); i < n; i++ {
			out = append(out, al...)
		}
		return out, nil
	}
	if isIntKind(a) && isIntKind(b) {
		ai, _ := intOf(a)
		bi, _ := intOf(b)
		return ai * bi, nil
	}
	if isNum(a) && isNum(b) {
		return numOf(a) * numOf(b), nil
	}
	return nil, raiseType("unsupported operand type(s) for *: '%s' and '%s'", pyTypeName(a), pyTypeName(b))
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// pyDiv 复刻 `a / b if b else 0`：除数假值直接给 int 0，否则真除法出浮点。
func pyDiv(a, b any) (any, error) {
	if !truthy(b) {
		return int64(0), nil
	}
	if !isNum(a) || !isNum(b) {
		return nil, raiseType("unsupported operand type(s) for /: '%s' and '%s'", pyTypeName(a), pyTypeName(b))
	}
	return numOf(a) / numOf(b), nil
}

// pyMod 复刻 `a % b if b else 0`。整数取模按 Python 的向下取整语义
// （-7 % 3 == 2），不是 Go 的截断语义（-1）。
func pyMod(a, b any) (any, error) {
	if !truthy(b) {
		return int64(0), nil
	}
	if isIntKind(a) && isIntKind(b) {
		ai, _ := intOf(a)
		bi, _ := intOf(b)
		r := ai % bi
		if r != 0 && (r < 0) != (bi < 0) {
			r += bi
		}
		return r, nil
	}
	if isNum(a) && isNum(b) {
		af, bf := numOf(a), numOf(b)
		r := math.Mod(af, bf)
		if r != 0 && (r < 0) != (bf < 0) {
			r += bf
		}
		return r, nil
	}
	return nil, raiseType("unsupported operand type(s) for %%: '%s' and '%s'", pyTypeName(a), pyTypeName(b))
}

// pyNeg 复刻一元负号。
func pyNeg(v any) (any, error) {
	if i, ok := intOf(v); ok {
		return -i, nil
	}
	if f, ok := v.(float64); ok {
		return -f, nil
	}
	return nil, raiseType("bad operand type for unary -: '%s'", pyTypeName(v))
}

// ---------------------------------------------------------------- 转换

// toFloat 复刻 float(v)：解析失败返回错误。
func toFloat(v any) (float64, error) {
	switch x := v.(type) {
	case int:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case float64:
		return x, nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case string:
		s := strings.TrimSpace(strings.ReplaceAll(x, "_", ""))
		low := strings.ToLower(s)
		switch low {
		case "inf", "+inf", "infinity", "+infinity":
			return math.Inf(1), nil
		case "-inf", "-infinity":
			return math.Inf(-1), nil
		case "nan", "+nan", "-nan":
			return math.NaN(), nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, raiseValue("could not convert string to float: %s", pyStrRepr(x))
		}
		return f, nil
	}
	return 0, raiseType("float() argument must be a string or a real number, not '%s'", pyTypeName(v))
}

// pyToInt 复刻 int(v)（严格版：失败就报错）。
// 注意 int("200.0") 在 Python 里是 ValueError，不是 200。
func pyToInt(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int64:
		return x, nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case float64:
		return int64(x), nil // Go 的转换就是向零截断，和 int() 一致
	case string:
		s := strings.TrimSpace(x)
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			// Python 的 int() 接受下划线分组
			if strings.Contains(s, "_") {
				if n2, err2 := strconv.ParseInt(strings.ReplaceAll(s, "_", ""), 10, 64); err2 == nil {
					return n2, nil
				}
			}
			return 0, raiseValue("invalid literal for int() with base 10: %s", pyStrRepr(x))
		}
		return n, nil
	}
	return 0, raiseType("int() argument must be a string, a bytes-like object or a number, not '%s'", pyTypeName(v))
}

// dslInt 复刻 DSL 里的 int(x)：`int(float(x))`，失败吞成 0。
func dslInt(v any) int64 {
	f, err := toFloat(v)
	if err != nil {
		return 0
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return int64(f)
}

// pyLen 复刻 len(v)；不可取长度时返回错误（DSL 的 len() 会吞成 0）。
func pyLen(v any) (int64, error) {
	switch x := v.(type) {
	case string:
		return int64(utf8.RuneCountInString(x)), nil
	case []any:
		return int64(len(x)), nil
	case map[string]any:
		return int64(len(x)), nil
	}
	return 0, raiseType("object of type '%s' has no len()", pyTypeName(v))
}

// iterate 复刻 for x in v。字符串按字符迭代（原版对 `path: /a` 这种
// 单值写法就是这个行为，会逐字符发请求 —— 这里如实保留）。
func iterate(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case string:
		out := make([]any, 0, len(x))
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([]any, len(keys))
		for i, k := range keys {
			out[i] = k
		}
		return out, nil
	}
	return nil, raiseType("'%s' object is not iterable", pyTypeName(v))
}

// ---------------------------------------------------------------- 编码

// latin1Decode 复刻 bytes.decode("latin-1")：每字节一个码点。
func latin1Decode(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// latin1Encode 复刻 str.encode("latin-1", "replace")：超出 0xFF 的码点变 '?'。
func latin1Encode(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r <= 0xFF {
			out = append(out, byte(r))
		} else {
			out = append(out, '?')
		}
	}
	return out
}

// utf8DecodeReplace 复刻 bytes.decode("utf-8", "replace")：
// 每个非法字节替换成一个 U+FFFD，合法序列原样保留。
func utf8DecodeReplace(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			sb.WriteRune(utf8.RuneError)
			b = b[1:]
			continue
		}
		sb.WriteRune(r)
		b = b[size:]
	}
	return sb.String()
}

// pySplitLines 复刻 str.splitlines()（kval 提取器用）。
func pySplitLines(s string) []string {
	var out []string
	start := 0
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		cut := false
		switch r {
		case '\n', '\v', '\f', '\r', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			cut = true
		}
		if cut {
			out = append(out, string(rs[start:i]))
			if r == '\r' && i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}

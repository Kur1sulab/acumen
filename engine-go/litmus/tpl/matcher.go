package tpl

// matcher.go — Matcher / Extractor / 汇总判定（tpl.py 的 1:1 移植）。
//
// 三条铁律照旧：
//   1. 匹配必须带证据：命中/未命中都返回可读的 evidence；
//   2. DSL 求值失败 = 该 matcher 未命中，异常写进 evidence，不吞掉；
//   3. 模板用了未实现的特性 → Unsupported 一路抛到 Engine.Run，记"未测"。

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Matcher 一个 matcher 规格。
type Matcher struct {
	Spec      map[string]any
	Type      string
	Part      string
	Condition string
	Negative  bool
	Internal  bool
	Name      any // 保留原值（None 就是 nil），与 Python 侧同形
}

// NewMatcher 从 YAML 映射构造。
func NewMatcher(spec map[string]any) *Matcher {
	return &Matcher{
		Spec:      spec,
		Type:      strings.ToLower(pyStr(orDefault(spec["type"], "word"))),
		Part:      strings.ToLower(pyStr(orDefault(spec["part"], "body"))),
		Condition: strings.ToLower(pyStr(orDefault(spec["condition"], "or"))),
		Negative:  boolOf(orDefault(spec["negative"], false)),
		Internal:  boolOf(orDefault(spec["internal"], false)),
		Name:      spec["name"],
	}
}

// partBytes 取 matcher/extractor 作用的响应部分。
func partBytes(resp *Response, part string) ([]byte, error) {
	part = strings.ToLower(part)
	if part == "" {
		part = "body"
	}
	switch part {
	case "body":
		return resp.Body, nil
	case "header":
		return resp.HeaderBytes(), nil
	case "all":
		out := make([]byte, 0, len(resp.HeaderBytes())+2+len(resp.Body))
		out = append(out, resp.HeaderBytes()...)
		out = append(out, '\r', '\n')
		out = append(out, resp.Body...)
		return out, nil
	case "status":
		return []byte(strconv.Itoa(resp.Status)), nil
	}
	if strings.HasPrefix(part, "raw") {
		return resp.RawResponse, nil
	}
	return nil, unsupportedf("matcher.part 不支持: %s", part)
}

// Evaluate 返回 (命中, 证据)。仅 Unsupported 通过 err 返回；
// 其余求值异常折成"未命中 + 异常证据"，与原版一致。
func (m *Matcher) Evaluate(resp *Response, ctx map[string]any) (bool, string, error) {
	hit, ev, err := m.eval(resp, ctx)
	if err != nil {
		if isUnsupported(err) {
			return false, "", err
		}
		return false, fmt.Sprintf("%s matcher 求值异常: %s", m.Type, err.Error()), nil
	}
	if m.Negative {
		hit = !hit
		if ev != "" {
			ev = "[negative] " + ev
		} else {
			ev = "[negative] 反向匹配"
		}
	}
	return hit, ev, nil
}

func (m *Matcher) eval(resp *Response, ctx map[string]any) (bool, string, error) {
	switch m.Type {
	case "status":
		raw, err := iterate(orDefault(m.Spec["status"], []any{}))
		if err != nil {
			return false, "", err
		}
		want := make([]any, 0, len(raw))
		for _, x := range raw {
			n, err := pyToInt(x)
			if err != nil {
				return false, "", err
			}
			want = append(want, n)
		}
		if len(want) == 0 {
			return false, "status matcher 未给状态码", nil
		}
		status := int64(resp.Status)
		ok := false
		for _, w := range want {
			if w == status {
				ok = true
				break
			}
		}
		return ok, fmt.Sprintf("status=%d want=%s", resp.Status, pyRepr(want)), nil

	case "size":
		raw, err := iterate(orDefault(m.Spec["size"], []any{}))
		if err != nil {
			return false, "", err
		}
		want := make([]any, 0, len(raw))
		for _, x := range raw {
			n, err := pyToInt(x)
			if err != nil {
				return false, "", err
			}
			want = append(want, n)
		}
		n := int64(len(resp.Body))
		ok := false
		for _, w := range want {
			if w == n {
				ok = true
				break
			}
		}
		return ok, fmt.Sprintf("body_len=%d want=%s", n, pyRepr(want)), nil

	case "word":
		words, err := iterate(orDefault(m.Spec["words"], []any{}))
		if err != nil {
			return false, "", err
		}
		if len(words) == 0 {
			return false, "word matcher 未给词表", nil
		}
		data, err := partBytes(resp, m.Part)
		if err != nil {
			return false, "", err
		}
		hits := []any{}
		for _, w := range words {
			if bytes.Contains(data, []byte(pyStr(w))) {
				hits = append(hits, w)
			}
		}
		ok := len(hits) > 0
		if m.Condition == "and" {
			ok = len(hits) == len(words)
		}
		return ok, fmt.Sprintf("命中词 %s/%d", pyRepr(head(hits, 5)), len(words)), nil

	case "regex":
		pats, err := iterate(orDefault(m.Spec["regex"], []any{}))
		if err != nil {
			return false, "", err
		}
		if len(pats) == 0 {
			return false, "regex matcher 未给正则", nil
		}
		data, err := partBytes(resp, m.Part)
		if err != nil {
			return false, "", err
		}
		text := latin1Decode(data)
		found := []any{}
		for _, p := range pats {
			re, err := regexp.Compile("(?is)" + pyStr(p))
			if err != nil {
				return false, "", pyErr("error", "%v", err)
			}
			if loc := re.FindStringIndex(text); loc != nil {
				found = append(found, truncRunes(text[loc[0]:loc[1]], 80))
			}
		}
		ok := len(found) > 0
		if m.Condition == "and" {
			ok = len(found) == len(pats)
		}
		return ok, fmt.Sprintf("正则命中 %s", pyRepr(head(found, 3))), nil

	case "binary":
		hexes, err := iterate(orDefault(m.Spec["binary"], []any{}))
		if err != nil {
			return false, "", err
		}
		if len(hexes) == 0 {
			return false, "binary matcher 未给十六进制串", nil
		}
		data, err := partBytes(resp, m.Part)
		if err != nil {
			return false, "", err
		}
		found := []any{}
		for _, h := range hexes {
			clean := stripSpace(pyStr(h))
			b, err := hex.DecodeString(clean)
			if err != nil {
				continue // 原版 bytes.fromhex 失败就跳过，不报错
			}
			if bytes.Contains(data, b) {
				found = append(found, truncRunes(pyStr(h), 32))
			}
		}
		ok := len(found) > 0
		if m.Condition == "and" {
			ok = len(found) == len(hexes)
		}
		return ok, fmt.Sprintf("二进制命中 %s", pyRepr(head(found, 3))), nil

	case "dsl":
		var exprs []any
		if s, ok := m.Spec["dsl"].(string); ok {
			exprs = []any{s}
		} else {
			var err error
			exprs, err = iterate(orDefault(m.Spec["dsl"], []any{}))
			if err != nil {
				return false, "", err
			}
		}
		if len(exprs) == 0 {
			return false, "dsl matcher 未给表达式", nil
		}
		vals := make([]any, 0, len(exprs))
		for _, e := range exprs {
			v, err := EvalDSL(pyStr(e), ctx)
			if err != nil {
				return false, "DSL 失败: " + err.Error(), nil
			}
			vals = append(vals, truthy(v))
		}
		ok := false
		if m.Condition == "and" {
			ok = true
			for _, v := range vals {
				if !truthy(v) {
					ok = false
					break
				}
			}
		} else {
			for _, v := range vals {
				if truthy(v) {
					ok = true
					break
				}
			}
		}
		return ok, fmt.Sprintf("DSL %s → %s", pyRepr(exprs), pyRepr(vals)), nil
	}
	return false, "", unsupportedf("matcher.type 不支持: %s", m.Type)
}

// ---------------------------------------------------------------- 提取器

// Extractor 一个 extractor 规格。
type Extractor struct {
	Spec     map[string]any
	Type     string
	Part     string
	Name     any
	Internal bool
}

// NewExtractor 从 YAML 映射构造。
func NewExtractor(spec map[string]any) *Extractor {
	return &Extractor{
		Spec:     spec,
		Type:     strings.ToLower(pyStr(orDefault(spec["type"], "regex"))),
		Part:     strings.ToLower(pyStr(orDefault(spec["part"], "body"))),
		Name:     spec["name"],
		Internal: boolOf(orDefault(spec["internal"], false)),
	}
}

// Extract 返回提取到的值列表。Unsupported 向上抛，其余异常由调用方吞成警告。
func (e *Extractor) Extract(resp *Response) ([]any, error) {
	data, err := partBytes(resp, e.Part)
	if err != nil {
		return nil, err
	}
	out := []any{}
	switch e.Type {
	case "regex":
		pats, err := iterate(orDefault(e.Spec["regex"], []any{}))
		if err != nil {
			return nil, err
		}
		text := latin1Decode(data)
		for _, p := range pats {
			re, err := regexp.Compile("(?s)" + pyStr(p))
			if err != nil {
				return nil, pyErr("error", "%v", err)
			}
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				if len(m) > 1 {
					out = append(out, m[1])
				} else {
					out = append(out, m[0])
				}
			}
		}
		return out, nil

	case "kval":
		keys, err := iterate(orDefault(e.Spec["kval"], []any{}))
		if err != nil {
			return nil, err
		}
		want := map[string]bool{}
		for _, k := range keys {
			want[strings.ToLower(pyStr(k))] = true
		}
		text := latin1Decode(data)
		for _, line := range pySplitLines(text) {
			k := strings.IndexByte(line, ':')
			if k < 0 {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(line[:k]))
			if want[name] {
				out = append(out, strings.TrimSpace(line[k+1:]))
			}
		}
		return out, nil

	case "json":
		exprs, err := iterate(orDefault(e.Spec["json"], []any{}))
		if err != nil {
			return nil, err
		}
		obj, err := parseJSON(utf8DecodeReplace(data))
		if err != nil {
			return []any{}, nil
		}
		for _, expr := range exprs {
			cur := obj
			found := true
			for _, seg := range strings.Split(pyStr(expr), ".") {
				switch node := cur.(type) {
				case *jsonObject:
					v, ok := node.get(seg)
					if !ok {
						found = false
					} else {
						cur = v
					}
				case []any:
					if isASCIIDigits(seg) {
						idx, _ := strconv.Atoi(seg)
						if idx < len(node) {
							cur = node[idx]
						} else {
							found = false
						}
					} else {
						found = false
					}
				default:
					found = false
				}
				if !found {
					cur = nil
					break
				}
			}
			if !found || cur == nil {
				continue
			}
			if s, ok := cur.(string); ok {
				out = append(out, s)
			} else {
				out = append(out, pyJSONDumps(cur))
			}
		}
		return out, nil

	case "dsl":
		exprs, err := iterate(orDefault(e.Spec["dsl"], []any{}))
		if err != nil {
			return nil, err
		}
		ctx := resp.Ctx()
		for _, expr := range exprs {
			v, err := EvalDSL(pyStr(expr), ctx)
			if err != nil {
				continue // 原版：单条 DSL 失败只跳过这一条
			}
			out = append(out, v)
		}
		return out, nil

	case "xpath":
		return nil, unsupportedf("extractor.type=xpath 需要 XML 解析器，本引擎未实现")
	}
	return nil, unsupportedf("extractor.type 不支持: %s", e.Type)
}

// ---------------------------------------------------------------- 汇总

// EvaluateMatchers 按 condition 汇总所有 matcher，返回 (命中, 证据列表)。
// 空 matcher 列表不算命中（原版就是这么定的，避免"没条件=通过"）。
func EvaluateMatchers(matchers []*Matcher, condition string, resp *Response, ctx map[string]any) (bool, []string, error) {
	if len(matchers) == 0 {
		return false, []string{"模板没有 matcher，不能判定命中"}, nil
	}
	type one struct {
		hit bool
		ev  string
	}
	results := make([]one, 0, len(matchers))
	evs := make([]string, 0, len(matchers))
	for _, m := range matchers {
		hit, ev, err := m.Evaluate(resp, ctx)
		if err != nil {
			return false, nil, err
		}
		prefix := "[" + m.Type
		if boolOf(m.Name) {
			prefix += "/" + pyStr(m.Name)
		}
		prefix += "] "
		results = append(results, one{hit, prefix + ev})
		evs = append(evs, prefix+ev)
	}
	ok := false
	if condition == "and" {
		ok = true
		for _, r := range results {
			if !r.hit {
				ok = false
				break
			}
		}
	} else {
		for _, r := range results {
			if r.hit {
				ok = true
				break
			}
		}
	}
	return ok, evs, nil
}

// ---------------------------------------------------------------- 小工具

func head(v []any, n int) []any {
	if len(v) > n {
		return v[:n]
	}
	return v
}

func truncRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) > n {
		return string(rs[:n])
	}
	return s
}

// stripSpace 对应 bytes.fromhex 前的空白清理（fromhex 会忽略所有 ASCII 空白）。
func stripSpace(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

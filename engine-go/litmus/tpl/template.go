package tpl

// template.go — Template 对象与加载（tpl.py 的 1:1 移植）。
//
// 兼容 nuclei 的两种写法：新式顶层 `http:` 与老式 `requests:`。
// 遇到 dns/tcp/ssl 之类没有 http 段的模板，明确 Unsupported，
// 不静默当"通过"。

import (
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// RequestSpec 单个 http 请求块。
type RequestSpec struct {
	Method            string
	Paths             any // 保留 YAML 原值：列表逐项；单字符串按原版逐字符迭代
	Headers           map[string]string
	Body              []byte
	BodyValue         any // 原始值，非字符串时在发送阶段复刻原版的 TypeError
	Raw               any
	Redirects         bool
	MaxRedirects      int
	Matchers          []*Matcher
	Extractors        []*Extractor
	MatchersCondition string
}

// Template 一个 nuclei 风格模板。
type Template struct {
	Path           string
	ID             string
	Name           string
	Severity       string
	Tags           []string
	Description    string
	Reference      []any
	Classification map[string]any
	Requests       []*RequestSpec
	RawYAML        map[string]any
}

func baseNoExt(path string) string {
	base := path
	if k := strings.LastIndexByte(base, '/'); k >= 0 {
		base = base[k+1:]
	}
	if k := strings.LastIndexByte(base, '.'); k >= 0 {
		base = base[:k]
	}
	return base
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// NewTemplate 从已解析的 YAML 数据构造模板。
// path 仅用于 id 兜底与报错定位，可以为空。
func NewTemplate(data any, path string) (*Template, error) {
	root, ok := asMap(data)
	if !ok {
		return nil, pyErr("ValueError", "模板根节点不是映射")
	}
	t := &Template{Path: path, RawYAML: root}
	t.ID = pyStr(orDefault(root["id"], baseNoExt(path)))

	info, ok := asMap(root["info"])
	if !ok {
		info = map[string]any{}
	}
	t.Name = pyStr(orDefault(info["name"], t.ID))
	t.Severity = strings.ToLower(pyStr(orDefault(info["severity"], "unknown")))
	tagText := pyStr(orDefault(info["tags"], ""))
	t.Tags = []string{}
	for _, part := range strings.Split(tagText, ",") {
		if s := strings.TrimSpace(part); s != "" {
			t.Tags = append(t.Tags, s)
		}
	}
	t.Description = pyStr(orDefault(info["description"], ""))
	refs := orDefault(info["reference"], []any{})
	if list, ok := refs.([]any); ok {
		t.Reference = list
	} else {
		t.Reference = []any{pyStr(refs)}
	}
	if cls, ok := asMap(info["classification"]); ok {
		t.Classification = cls
	} else {
		t.Classification = map[string]any{}
	}

	reqs, present := root["http"]
	if !present || reqs == nil {
		reqs = root["requests"]
	}
	if reqs == nil {
		return nil, unsupportedf("%s: 没有 http/requests 段（可能是 dns/tcp/ssl 模板）", t.ID)
	}
	list := []any{}
	switch v := reqs.(type) {
	case map[string]any:
		list = []any{v}
	case []any:
		list = v
	default:
		return nil, unsupportedf("%s: http 段结构不认识", t.ID)
	}
	for _, item := range list {
		r, ok := asMap(item)
		if !ok {
			continue
		}
		spec, err := newRequestSpec(t.ID, r)
		if err != nil {
			return nil, err
		}
		t.Requests = append(t.Requests, spec)
	}
	if len(t.Requests) == 0 {
		return nil, unsupportedf("%s: http 段为空", t.ID)
	}
	return t, nil
}

func newRequestSpec(tplID string, r map[string]any) (*RequestSpec, error) {
	s := &RequestSpec{
		Method:            strings.ToUpper(pyStr(orDefault(r["method"], "GET"))),
		Paths:             orDefault(r["path"], []any{"/"}),
		Raw:               orDefault(r["raw"], []any{}),
		Redirects:         boolOf(orDefault(r["redirects"], false)),
		MatchersCondition: strings.ToLower(pyStr(orDefault(r["matchers-condition"], "or"))),
	}
	// max-redirects：Python int(r.get("max-redirects") or 3)
	mr, err := pyToInt(orDefault(r["max-redirects"], int64(3)))
	if err != nil {
		return nil, err
	}
	s.MaxRedirects = int(mr)

	s.Headers = map[string]string{}
	if hv := orDefault(r["headers"], map[string]any{}); hv != nil {
		hm, ok := asMap(hv)
		if !ok {
			return nil, pyErr("AttributeError", "'%s' object has no attribute 'items'", pyTypeName(hv))
		}
		for k, v := range hm {
			s.Headers[pyStr(k)] = pyStr(v)
		}
	}
	s.BodyValue = r["body"]
	if bs, ok := r["body"].(string); ok {
		s.Body = []byte(bs)
	}

	if ms := orDefault(r["matchers"], []any{}); boolOf(ms) {
		list, err := iterate(ms)
		if err != nil {
			return nil, err
		}
		for _, m := range list {
			spec, ok := asMap(m)
			if !ok {
				return nil, pyErr("AttributeError", "'%s' object has no attribute 'get'", pyTypeName(m))
			}
			s.Matchers = append(s.Matchers, NewMatcher(spec))
		}
	}
	if es := orDefault(r["extractors"], []any{}); boolOf(es) {
		list, err := iterate(es)
		if err != nil {
			return nil, err
		}
		for _, e := range list {
			spec, ok := asMap(e)
			if !ok {
				return nil, pyErr("AttributeError", "'%s' object has no attribute 'get'", pyTypeName(e))
			}
			s.Extractors = append(s.Extractors, NewExtractor(spec))
		}
	}
	return s, nil
}

// String 对应原版的 __repr__：<Template id sev=high reqs=1>
func (t *Template) String() string {
	return "<Template " + t.ID + " sev=" + t.Severity + " reqs=" + strconv.Itoa(len(t.Requests)) + ">"
}

// LoadTemplate 从文件加载一个模板。
func LoadTemplate(path string) (*Template, error) {
	data, err := LoadYAMLFile(path)
	if err != nil {
		return nil, err
	}
	return NewTemplate(data, path)
}

// LoadTemplateText 从文本加载（测试/内存模板用）。
func LoadTemplateText(text, path string) (*Template, error) {
	data, err := LoadYAML(text)
	if err != nil {
		return nil, err
	}
	return NewTemplate(data, path)
}

// LoadError 单个模板加载失败。
type LoadError struct {
	Path    string
	Message string
}

func (e LoadError) Error() string { return e.Path + ": " + e.Message }

// LoadDir 递归加载目录下所有 yaml，返回 (templates, errors)。
// 单个坏模板不中断整体加载；limit<=0 表示不限制。
func LoadDir(root string, limit int) ([]*Template, []LoadError) {
	var out []*Template
	var errs []LoadError
	n := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 原版 os.walk 对不可读目录也只是跳过
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		t, lerr := LoadTemplate(path)
		switch {
		case lerr == nil:
			out = append(out, t)
		case isUnsupported(lerr):
			errs = append(errs, LoadError{path, "不支持: " + lerr.Error()})
		default:
			errs = append(errs, LoadError{path, errorLabel(lerr)})
		}
		n++
		if limit > 0 && n >= limit {
			return fs.SkipAll
		}
		return nil
	})
	return out, errs
}

// errorLabel 复刻 f"{type(e).__name__}: {e}" 的形态；非 Python 语义错误
// （文件读不了之类）加个 Error: 前缀，避免伪装成 Python 异常。
func errorLabel(err error) string {
	if pe, ok := err.(*pyError); ok {
		return pe.Error()
	}
	return "Error: " + err.Error()
}

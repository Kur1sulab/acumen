// Package tpl 是 litmus2 模板引擎内核（Python 版 tpl.py）的 Go 移植。
//
// 职责与原版一致：加载 nuclei 风格 YAML 模板，按 path 列表或 raw 链发出
// HTTP 请求，用 word/regex/binary/status/size/dsl matcher 判定命中，
// 用 regex/kval/json/dsl extractor 取值，产出带证据的结构化结果。
//
// # 依赖
//
// 只用 Go 标准库。原版依赖自带 yamlite（YAML 子集解析器）与 httpc
// （socket 级 HTTP 客户端），这里分别移植为 yaml.go 与 http.go：
//   - yaml.go   块映射/序列、引号与块标量、流集合、锚点/合并键、类型推断
//   - http.go   net.Dial 级 HTTP/1.1，保留 raw_request / raw_response 原始字节
//
// 所以本包不引入任何 YAML 或 HTTP 第三方库，load_template / load_dir 的
// 行为与 Python 版逐字段对齐（dev/ 下的差分测试验证过整库 14247 个模板）。
//
// # 快速开始
//
//	tp, err := tpl.LoadTemplate("templates/git-config-disclosure.yaml")
//	if err != nil {
//		log.Fatal(err)
//	}
//	res := tpl.NewEngine(8 * time.Second).Run(tp, "https://target.example")
//	if res.Matched {
//		fmt.Println(res.Evidence, res.Extracts)
//	}
//
// # 与原版的对应关系
//
//	tpl.Unsupported        → IsUnsupported 判定（错误带 unsupported 类型）
//	tpl.eval_dsl           → EvalDSL
//	tpl.Matcher            → Matcher / NewMatcher
//	tpl.Extractor          → Extractor / NewExtractor
//	tpl.evaluate_matchers  → EvaluateMatchers
//	tpl.Template           → Template / NewTemplate
//	tpl.load_template      → LoadTemplate
//	tpl.load_dir           → LoadDir
//	tpl.Engine             → Engine / NewEngine
//	tpl.httpc.Response     → Response（含 HeaderBytes / Ctx）
//	tpl.httpc.Pool         → Pool（含 Request / RawExchange）
//
// # 刻意保留的原版行为（不要"顺手修好"）
//
//   - `path` 写成单个字符串时按字符迭代（`path: /hello` 会发 6 个请求）。
//     原版 `for p in rspec["paths"]` 就是这个语义，差分测试把它锁住了。
//   - 请求不带 Content-Length：httpc 不自动补，服务端按 CL 读时 body 为空。
//     模板要发 body 必须自己写 Content-Length（见 engine_test.go）。
//   - headers 不做 {{变量}} 替换（只有 path 和 raw 走 subst）。
//   - matcher 的 regex 带 re.I（大小写不敏感），extractor 的 regex 不带。
//   - 空 matcher 列表不算命中；word matcher 的空词表、status 的空状态码都
//     各有显式证据文案，不静默通过。
//   - extractor 出错只记警告，不否决 matcher 结论；matcher 用了不支持的
//     类型则整个模板记"不支持"，不假装测过。
//
// # 已知差异（不影响模板语义，但要知道）
//
//   - YAML 日期/时间标量保留为原始字符串（原版是 datetime.date/datetime），
//     两者 str() 结果相同。
//   - 超出 int64 的整数用 math/big.Int（原版 Python int 无上限）；DSL 的
//     算术仍是 int64，会溢出回绕，极端数值下与原版不同。
//   - 正则引擎是 RE2：不支持反向引用与 lookaround；用到它们的模板会出现
//     "matcher 求值异常"或 extractor 警告，而不是静默命中。
//   - dict 的迭代顺序不保留（Go map）：str(dict) 与 extracts 的 JSON 键序
//     可能不同；evidence 里的列表顺序不受影响。
//   - 请求超时是整体 deadline（原版是每个 socket 操作单独超时），慢速滴水
//     式服务端下行为略有差别。
//   - matcher/extractor 的 name 不是字符串时用 pyStr 拼接，原版会在
//     `'/' + name` 处抛 TypeError。
//   - 非 Python 语义的错误（文件读不了、连接失败）文案前缀为 "Error:"，
//     Python 侧是 "<异常类型>: <消息>"。
package tpl

// Command yaml_go_dump 用 Go 版 yamlite 解析文件并输出与 Python oracle 同构的
// 规范化 JSON，供差分测试比对。临时工具，不进仓库。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Kur1sulab/kara/engine-go/litmus/yamlite"
)

func canon(v any, depth int) any {
	if depth > 60 {
		return map[string]any{"__deep__": true}
	}
	switch x := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, e := range x {
			m[k] = canon(e, depth+1)
		}
		return map[string]any{"__map__": m}
	case []any:
		l := make([]any, 0, len(x))
		for _, e := range x {
			l = append(l, canon(e, depth+1))
		}
		return map[string]any{"__list__": l}
	case bool:
		return map[string]any{"__bool__": x}
	case int64:
		return map[string]any{"__int__": fmt.Sprintf("%d", x)}
	case int:
		return map[string]any{"__int__": fmt.Sprintf("%d", x)}
	case float64:
		return map[string]any{"__float__": yamlite.PyFloatStr(x)}
	case nil:
		return map[string]any{"__null__": true}
	case yamlite.Date:
		return map[string]any{"__date__": x.ISO()}
	case yamlite.DateTime:
		return map[string]any{"__date__": x.ISO()}
	case string:
		return map[string]any{"__str__": x}
	default:
		return map[string]any{"__str__": fmt.Sprint(x)}
	}
}

func main() {
	paths := os.Args[1:]
	sort.Strings(paths)
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			rec := map[string]any{"path": p, "error": "READ: " + err.Error()}
			b, _ := json.Marshal(rec)
			fmt.Println(string(b))
			continue
		}
		v, err := yamlite.SafeLoad(string(raw))
		rec := map[string]any{"path": p}
		if err != nil {
			rec["error"] = err.Error()
		} else {
			rec["canon"] = canon(v, 0)
		}
		b, _ := json.Marshal(rec)
		fmt.Println(string(b))
	}
}

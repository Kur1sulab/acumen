package authprobe

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/kara/engine-go/litmus/httpc"
	"github.com/Kur1sulab/kara/engine-go/litmus/model"
)

// ================================================================ Elasticsearch
//
// 判据：GET / 回 200 且含 cluster_name，再 GET /_cat/indices 真拿到索引 JSON。
// 只读：两个 GET，没有任何写索引/删数据的动作。

// ProbeElasticsearch 对应 authprobe.probe_elasticsearch。
//
// 这是本包唯一吃 tls 参数的探针（Python 版同样如此）：ES 常直接跑在 9200/9243。
func ProbeElasticsearch(host string, port int, timeout time.Duration, useTLS bool) *model.Finding {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	base := scheme + "://" + host + ":" + strconv.Itoa(port)

	r := httpc.Get(base+"/", httpc.Opts{Timeout: timeout})
	if r == nil || r.Status != 200 || !bytes.Contains(r.Body, []byte("cluster_name")) {
		return nil
	}
	ev := []string{"GET / → " + txt(r.Body, 400)}

	idx := httpc.Get(base+"/_cat/indices?format=json&h=index,docs.count,store.size",
		httpc.Opts{Timeout: timeout})
	docs := 0
	names := []interface{}{}
	if idx != nil && idx.Status == 200 &&
		bytes.HasPrefix(bytes.TrimSpace(idx.Body), []byte("[")) {
		ev = append(ev, "GET /_cat/indices → "+txt(idx.Body, 400))
		var items []map[string]interface{}
		if err := json.Unmarshal(idx.Body, &items); err == nil {
			for _, it := range items {
				names = append(names, it["index"])
				docs += esDocsCount(it["docs.count"])
			}
		}
	}

	level := "L2"
	if len(names) > 0 {
		level = "L3"
	}
	shown := names
	if len(shown) > 20 {
		shown = shown[:20]
	}

	return result{
		check:    "es-unauth",
		name:     "Elasticsearch 未授权访问",
		severity: "high",
		level:    level,
		evidence: strings.Join(ev, "\n"),
		repro:    "curl -s " + base + "/_cat/indices?format=json",
		impact: "可直接读取全部索引（" + strconv.Itoa(len(names)) + " 个索引 / " +
			strconv.Itoa(docs) + " 条文档），常含业务与日志明文。",
		fix: "启用 xpack 安全认证 + 仅监听内网 + 关闭公网暴露的 9200。",
		extra: map[string]interface{}{
			"product": "elasticsearch",
			"indices": shown,
			"docs":    docs,
		},
	}.finding(host, port)
}

// esDocsCount 复刻 int(it.get("docs.count") or 0)：字符串/数字都能吃，
// 解析失败按 0 算（Python 的 except: pass 就是不累加）。
func esDocsCount(v interface{}) int {
	switch x := v.(type) {
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
			return n
		}
	case float64:
		return int(x)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return int(n)
		}
	}
	return 0
}

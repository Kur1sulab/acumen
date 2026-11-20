package replay

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readRec 跑一次 Run 并把产物读回来（测试只走本机回环，不出网）。
func readRec(t *testing.T, url, method, data string, headers []string, noRedirect bool) Record {
	t.Helper()
	dir := t.TempDir()
	if err := Run(url, method, data, headers, 5, !noRedirect, dir); err != nil {
		t.Fatalf("Run(%s) error: %v", url, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("读产物失败: %v", err)
	}
	var rec Record
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("产物不是合法 JSON: %v", err)
	}
	return rec
}

func TestReplayStatusBodyDigest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hello"))
	})
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("server error"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rec := readRec(t, srv.URL+"/ok", "GET", "", nil, false)
	if rec.Kind != "sweep_replay" || rec.Status != 200 || rec.Size != 5 || rec.Body != "hello" {
		t.Fatalf("ok 响应字段不符: %+v", rec)
	}
	// sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	if rec.Digest != "2cf24dba5fb0a30e" {
		t.Fatalf("digest = %q, want 2cf24dba5fb0a30e", rec.Digest)
	}
	if rec.Headers["content-type"] != "text/plain" {
		t.Fatalf("headers 键未小写: %+v", rec.Headers)
	}
	if rec.Error != "" {
		t.Fatalf("成功路径 error 应为空: %q", rec.Error)
	}

	boom := readRec(t, srv.URL+"/boom", "GET", "", nil, false)
	if boom.Status != 500 || boom.Body != "server error" || boom.Error != "" {
		t.Fatalf("500 不是传输错误，应如实记状态: %+v", boom)
	}
}

func TestReplayRedirectToggle(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello")) })
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	follow := readRec(t, srv.URL+"/redir", "GET", "", nil, false)
	if follow.Status != 200 || follow.Redirects != 1 || !strings.HasSuffix(follow.FinalURL, "/ok") {
		t.Fatalf("跟随重定向结果不符: %+v", follow)
	}
	stop := readRec(t, srv.URL+"/redir", "GET", "", nil, true)
	if stop.Status != 302 || stop.Redirects != 0 || stop.FinalURL != srv.URL+"/redir" {
		t.Fatalf("--no-redirect 应停在 302: %+v", stop)
	}
	if loc := stop.Headers["location"]; loc != "/ok" {
		t.Fatalf("302 的 Location 头应保留: %+v", stop.Headers)
	}
}

func TestReplayMethodDataHeaders(t *testing.T) {
	var gotMethod, gotBody, gotHdr, gotUA, gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 64)
		n, _ := r.Body.Read(b)
		gotMethod, gotBody = r.Method, string(b[:n])
		gotHdr = strings.Join(r.Header.Values("X-Multi"), "|")
		gotUA = r.Header.Get("User-Agent")
		gotHost = r.Host
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// 给了 --data 但方法没显式指定：仍是 GET（不自动改 POST）
	readRec(t, srv.URL+"/x", "GET", `{"a":1}`, []string{"X-Multi: one", "X-Multi: two"}, false)
	if gotMethod != "GET" || gotBody != `{"a":1}` {
		t.Fatalf("GET 带体未按原样发送: method=%q body=%q", gotMethod, gotBody)
	}
	if gotHdr != "one|two" {
		t.Fatalf("重复 --header 未按序发送: %q", gotHdr)
	}
	if gotUA == "" {
		t.Fatal("默认 UA 应补上")
	}

	// --header 'User-Agent: ...' 覆盖默认 UA；--header 'Host: ...' 落到 req.Host
	readRec(t, srv.URL+"/x", "post", "", []string{"User-Agent: custom/9", "Host: example.test"}, false)
	if gotMethod != "POST" || gotUA != "custom/9" || gotHost != "example.test" {
		t.Fatalf("覆盖语义不符: method=%q ua=%q host=%q", gotMethod, gotUA, gotHost)
	}
}

func TestReplayBodyTruncateUTF8Safe(t *testing.T) {
	// 5000 字节，前 4095 个是 'a'，第 4096 字节是 0xff（非法 UTF-8），尾部还有多字节字符
	raw := make([]byte, 5000)
	for i := range raw {
		raw[i] = 'a'
	}
	raw[4095] = 0xff
	copy(raw[4096:], "尾巴")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(raw)
	}))
	defer srv.Close()

	rec := readRec(t, srv.URL+"/big", "GET", "", nil, false)
	if rec.Size != 5000 {
		t.Fatalf("size 应是全量 body 字节数: %d", rec.Size)
	}
	if len(rec.Body) > BodyLimit+3 { // 4096 字节内可能带一个 3 字节替换符
		t.Fatalf("body 未截断: %d 字节", len(rec.Body))
	}
	if !strings.HasPrefix(rec.Body, "aaa") || !strings.Contains(rec.Body, "\uFFFD") {
		t.Fatalf("非法字节应替换为 U+FFFD: %q", rec.Body[len(rec.Body)-8:])
	}
}

func TestReplayDialFailIsNotError(t *testing.T) {
	// 先占一个端口再关掉，保证「连不上」稳定复现
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	dir := t.TempDir()
	if err := Run("http://"+addr+"/x", "GET", "", nil, 2, true, dir); err != nil {
		t.Fatalf("传输层失败不该返回 error（CLI 要 exit 0）: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("传输层失败也要写产物: %v", err)
	}
	var rec Record
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Status != 0 || rec.Error == "" || rec.Size != 0 {
		t.Fatalf("连不上应 status=0 + error 非空: %+v", rec)
	}
}

func TestReplayBadArgs(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, url string
		hdr       []string
		timeout   int
	}{
		{"非 http 协议", "ftp://127.0.0.1/x", nil, 5},
		{"缺 scheme", "127.0.0.1:8080/x", nil, 5},
		{"头格式错", "http://127.0.0.1/x", []string{"NoColonHere"}, 5},
		{"超时非正", "http://127.0.0.1/x", nil, 0},
	}
	for _, c := range cases {
		err := Run(c.url, "GET", "", c.hdr, c.timeout, true, dir)
		if !errors.Is(err, ErrBadArgs) {
			t.Fatalf("%s: 应返回 ErrBadArgs，得到 %v", c.name, err)
		}
	}
}

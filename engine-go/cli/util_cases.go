// util_cases.go —— brute / cve 两个命令用的小工具。
package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// serviceDefaultPorts 每个协议在没有 -p 时默认打哪些端口。
var serviceDefaultPorts = map[string][]int{
	"ftp":        {21},
	"telnet":     {23},
	"mysql":      {3306},
	"postgres":   {5432},
	"redis":      {6379},
	"http-basic": {80, 443, 8080, 8443},
}

// hostAndPorts 解析 `-t host[:port]` 与 -p/--service，返回主机与端口列表。
func hostAndPorts(target, ports, service string) (string, []int) {
	host := target
	var list []int
	if h, p, err := net.SplitHostPort(target); err == nil {
		host = h
		if n, err2 := strconv.Atoi(p); err2 == nil {
			list = append(list, n)
		}
	}
	if strings.TrimSpace(ports) != "" {
		for _, part := range strings.Split(ports, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if n, err := strconv.Atoi(part); err == nil && n > 0 && n < 65536 {
				list = append(list, n)
			}
		}
	}
	if len(list) == 0 {
		if svc := strings.TrimSpace(service); svc != "" {
			list = append(list, serviceDefaultPorts[svc]...)
		}
	}
	// 去重保序
	seen := map[int]bool{}
	out := list[:0]
	for _, p := range list {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return host, out
}

// readListFile 读一行一个的列表（忽略空行与 # 注释）。
func readListFile(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[!] 读取 %s 失败: %v\n", path, err)
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// writeJSON 落盘带缩进的 JSON（人工看产物时友好）。
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Package parity：Python 对照桥（已退役）。
//
// Kara 的引擎早期是 Python 实现，Go 侧靠「同一份输入跑两边、逐字节比对」来保证移植正确。
// 现在 Python 实现已不随仓库发布（单一 CLI + Go 内核），对照失去了对照对象，
// 所以这里保留同名入口让既有测试继续可编译，实际执行时直接 skip —— 而不是伪造一份「比对通过」。
package parity

import "testing"

// RunPy 旧签名：跑一段 Python 代码并返回 stdout。现在直接 skip。
func RunPy(t *testing.T, code string, args ...string) string {
	t.Helper()
	t.Skip("Python 对照已退役：仓库内不再有 Python 版引擎可比对")
	return ""
}
